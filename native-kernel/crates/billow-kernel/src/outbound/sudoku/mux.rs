// SPDX-License-Identifier: GPL-3.0-only
//
// Derived from Mihomo `transport/sudoku` (GPL-3.0).
// Upstream: https://github.com/MetaCubeX/mihomo
// Version: v1.19.34
// Commit: 0455d0d28c4526937380505153e65a843d8612e8
// Source paths: transport/sudoku/multiplex/session.go, transport/sudoku/multiplex_dialer.go
//
// This file is a Rust translation of that GPL-3.0 code. The kernel workspace
// therefore carries GPL-3.0 obligations for the sudoku module; see
// native-kernel/THIRD_PARTY_NOTICES.md and native-kernel/COPYING.GPL-3.0.
//
//! Client side of the Sudoku session multiplexer (`multiplex: on`).
//!
//! After the KIP handshake the client sends `KIPTypeStartMux` instead of
//! `KIPTypeOpenTCP`; the record stream then carries mux frames:
//!
//! ```text
//! type(1) | stream id(u32 BE) | payload length(u32 BE) | payload
//! ```
//!
//! `open(1)` carries the SOCKS5-encoded target and creates a stream, `data(2)`
//! carries payload, `close(3)` half-closes the sender, `reset(4)` aborts a
//! stream, and `ping(5)`/`pong(6)` keep the shared session alive. The pinned
//! implementation coalesces small frames for bandwidth; this port writes each
//! frame atomically through one queue (same wire format, no interleaving).
//!
//! One session is shared by every dial with the same configuration and is
//! recreated when it fails, like `MultiplexDialer`.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Notify;

use super::{connect, Handshake, Wakers, SUDOKU_MAX_FRAME};
use crate::outbound::{BoxStream, DialError, Target};
use crate::proxies::SudokuOutbound;

const FRAME_OPEN: u8 = 0x01;
const FRAME_DATA: u8 = 0x02;
const FRAME_CLOSE: u8 = 0x03;
const FRAME_RESET: u8 = 0x04;
const FRAME_PING: u8 = 0x05;
const FRAME_PONG: u8 = 0x06;

const HEADER_SIZE: usize = 9;
/// `maxQueuedBytesPerStream`: a stream that exceeds this is reset.
const MAX_QUEUED_PER_STREAM: usize = 4 * 1024 * 1024;
/// `maxDataPayload` from the pinned session; this port caps writes lower.
const MAX_DATA: usize = 32 * 1024;
/// Bound on bytes waiting to be written by the session writer task.
const MAX_QUEUED_WRITE: usize = 4 * 1024 * 1024;
const KEEPALIVE: Duration = Duration::from_secs(15);

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn frame(kind: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_SIZE + payload.len());
    out.push(kind);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Whole frames waiting for the session writer. Whole-frame queueing is what
/// keeps frames from different streams from interleaving on the wire.
struct WriteQueue {
    frames: Mutex<VecDeque<Vec<u8>>>,
    bytes: AtomicUsize,
    notify: Notify,
    /// Tasks waiting for room; woken when a frame is popped or the queue closes.
    capacity: Wakers,
    closed: AtomicBool,
}

impl WriteQueue {
    fn new() -> WriteQueue {
        WriteQueue {
            frames: Mutex::new(VecDeque::new()),
            bytes: AtomicUsize::new(0),
            notify: Notify::new(),
            capacity: Wakers::new(),
            closed: AtomicBool::new(false),
        }
    }

    fn push(&self, frame: Vec<u8>) -> bool {
        let mut frames = self.frames.lock().expect("sudoku mux queue");
        self.bytes.fetch_add(frame.len(), Ordering::SeqCst);
        frames.push_back(frame);
        drop(frames);
        self.notify.notify_one();
        true
    }

    /// Try to queue a frame without waiting; `false` when the queue is full or
    /// the session is closed (the caller registers a waker and retries).
    fn try_push(&self, frame: Vec<u8>) -> bool {
        if self.closed.load(Ordering::SeqCst) {
            return false;
        }
        let used = self.bytes.load(Ordering::SeqCst);
        if used + frame.len() > MAX_QUEUED_WRITE {
            return false;
        }
        self.push(frame)
    }

    fn pop(&self) -> Option<Vec<u8>> {
        let frame = {
            let mut frames = self.frames.lock().expect("sudoku mux queue");
            frames.pop_front()
        };
        if let Some(frame) = &frame {
            self.bytes.fetch_sub(frame.len(), Ordering::SeqCst);
            // `notify_one` stores a permit when no waiter is registered yet,
            // so a sender that fails `try_push` and has not reached
            // `notified().await` still observes the freed capacity.
            self.notify.notify_one();
            self.capacity.wake_all();
        }
        frame
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.frames.lock().expect("sudoku mux queue").clear();
        self.bytes.store(0, Ordering::SeqCst);
        self.notify.notify_waiters();
        self.capacity.wake_all();
    }

    fn is_empty(&self) -> bool {
        self.frames.lock().expect("sudoku mux queue").is_empty()
    }
}

#[derive(Default)]
struct Inbox {
    bytes: Vec<u8>,
    delivered: usize,
}

struct StreamState {
    inbox: Mutex<Inbox>,
    closed: Mutex<Option<io::Result<()>>>,
    wakers: Wakers,
    local_write_closed: AtomicBool,
    remote_write_closed: AtomicBool,
    queued: AtomicUsize,
}

impl StreamState {
    fn new() -> StreamState {
        StreamState {
            inbox: Mutex::new(Inbox::default()),
            closed: Mutex::new(None),
            wakers: Wakers::new(),
            local_write_closed: AtomicBool::new(false),
            remote_write_closed: AtomicBool::new(false),
            queued: AtomicUsize::new(0),
        }
    }

    fn deliver(&self, payload: &[u8]) -> bool {
        let queued = self.queued.fetch_add(payload.len(), Ordering::SeqCst) + payload.len();
        if queued > MAX_QUEUED_PER_STREAM {
            self.queued.fetch_sub(payload.len(), Ordering::SeqCst);
            return false;
        }
        let mut inbox = self.inbox.lock().expect("sudoku mux inbox");
        if inbox.delivered == inbox.bytes.len() {
            inbox.bytes.clear();
            inbox.delivered = 0;
        }
        inbox.bytes.extend_from_slice(payload);
        drop(inbox);
        self.wakers.wake_all();
        true
    }

    fn fail(&self, error: io::Error) {
        let mut closed = self.closed.lock().expect("sudoku mux closed");
        if closed.is_none() {
            *closed = Some(Err(error));
        }
        drop(closed);
        self.wakers.wake_all();
    }

}

/// The shared mux session.
pub struct MuxClient {
    queue: Arc<WriteQueue>,
    streams: Mutex<HashMap<u32, Arc<StreamState>>>,
    next_id: AtomicU32,
    closed: AtomicBool,
    server: std::net::SocketAddr,
}

impl MuxClient {
    /// Open the mux session: KIP handshake with `KIPTypeStartMux`.
    pub async fn connect(option: &SudokuOutbound) -> Result<Arc<MuxClient>, DialError> {
        let (stream, server) = connect(option, Handshake::StartMux, None).await?;
        MuxClient::connect_stream(stream, server).await
    }

    /// Open the mux session over a stream a `dialer-proxy` hop established.
    pub async fn connect_stream(
        stream: BoxStream,
        server: std::net::SocketAddr,
    ) -> Result<Arc<MuxClient>, DialError> {
        let (mut reader, writer) = tokio::io::split(stream);
        let client = Arc::new(MuxClient {
            queue: Arc::new(WriteQueue::new()),
            streams: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(0),
            closed: AtomicBool::new(false),
            server,
        });

        let writer_client = Arc::clone(&client);
        let queue = Arc::clone(&client.queue);
        tokio::spawn(async move {
            let mut writer = writer;
            loop {
                if queue.closed.load(Ordering::SeqCst) {
                    return;
                }
                let Some(frame) = queue.pop() else {
                    queue.notify.notified().await;
                    continue;
                };
                if writer.write_all(&frame).await.is_err() || writer.flush().await.is_err() {
                    writer_client.close_with("sudoku mux: write failed");
                    return;
                }
            }
        });

        let keepalive_client = Arc::clone(&client);
        tokio::spawn(async move {
            let mut last = now_millis();
            loop {
                tokio::time::sleep(KEEPALIVE).await;
                if keepalive_client.is_closed() {
                    return;
                }
                if now_millis().saturating_sub(last) >= KEEPALIVE.as_millis() as u64 {
                    if let Err(error) = keepalive_client.send(FRAME_PING, 0, &[]).await {
                        keepalive_client.close_with(&format!("sudoku mux: keepalive failed ({error})"));
                        return;
                    }
                    last = now_millis();
                }
            }
        });

        let read_client = Arc::clone(&client);
        tokio::spawn(async move {
            read_client.read_loop(&mut reader).await;
        });
        Ok(client)
    }

    pub fn server(&self) -> std::net::SocketAddr {
        self.server
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn close_with(&self, reason: &str) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.queue.close();
        let reason = reason.to_string();
        let streams = self.streams.lock().expect("sudoku mux streams");
        for state in streams.values() {
            state.fail(io::Error::new(io::ErrorKind::ConnectionAborted, reason.clone()));
        }
    }

    /// Queue one frame and wait until the writer has room for it.
    async fn send(&self, kind: u8, stream_id: u32, payload: &[u8]) -> io::Result<()> {
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "sudoku mux: session is closed",
            ));
        }
        let frame = frame(kind, stream_id, payload);
        // Wait for capacity; the writer task notifies after each pop.
        loop {
            if self.queue.try_push(frame.clone()) {
                return Ok(());
            }
            if self.is_closed() || self.queue.closed.load(Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "sudoku mux: session is closed",
                ));
            }
            self.queue.notify.notified().await;
        }
    }

    fn try_send(&self, kind: u8, stream_id: u32, payload: &[u8]) -> bool {
        if self.is_closed() {
            return false;
        }
        self.queue.try_push(frame(kind, stream_id, payload))
    }

    fn remove_stream(&self, id: u32) {
        self.streams.lock().expect("sudoku mux streams").remove(&id);
    }

    async fn open(self: &Arc<Self>, address: &[u8]) -> io::Result<MuxStream> {
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "sudoku mux: session is closed",
            ));
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
        let id = if id == 0 { 1 } else { id };
        let state = Arc::new(StreamState::new());
        self.streams
            .lock()
            .expect("sudoku mux streams")
            .insert(id, Arc::clone(&state));
        if let Err(error) = self.send(FRAME_OPEN, id, address).await {
            self.remove_stream(id);
            return Err(error);
        }
        Ok(MuxStream {
            client: Arc::clone(self),
            id,
            state,
            pending: Vec::new(),
            pending_len: 0,
            write_closed: false,
            eof_returned: false,
        })
    }

    async fn read_loop<R: AsyncRead + Unpin>(self: Arc<Self>, reader: &mut R) {
        let mut header = [0u8; HEADER_SIZE];
        loop {
            if let Err(error) = reader.read_exact(&mut header).await {
                if !self.is_closed() {
                    self.close_with(&format!("sudoku mux: read failed ({error})"));
                }
                return;
            }
            let kind = header[0];
            let id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
            let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
            if len > SUDOKU_MAX_FRAME {
                self.close_with("sudoku mux: frame too large");
                return;
            }
            let mut payload = vec![0u8; len];
            if len > 0 {
                if let Err(error) = reader.read_exact(&mut payload).await {
                    if !self.is_closed() {
                        self.close_with(&format!("sudoku mux: read failed ({error})"));
                    }
                    return;
                }
            }
            match kind {
                FRAME_PING => {
                    if id != 0 || !payload.is_empty() {
                        self.close_with("sudoku mux: invalid ping");
                        return;
                    }
                    let _ = self.try_send(FRAME_PONG, 0, &[]);
                }
                FRAME_PONG => {}
                FRAME_DATA => {
                    let state = self.streams.lock().expect("sudoku mux streams").get(&id).cloned();
                    let Some(state) = state else { continue };
                    if payload.is_empty() {
                        continue;
                    }
                    if !state.deliver(&payload) {
                        state.fail(io::Error::new(
                            io::ErrorKind::Other,
                            "sudoku mux: stream receive queue full",
                        ));
                        self.remove_stream(id);
                        let _ = self.try_send(FRAME_RESET, id, b"mux receive queue full");
                    }
                }
                FRAME_CLOSE => {
                    let state = self.streams.lock().expect("sudoku mux streams").get(&id).cloned();
                    if let Some(state) = state {
                        state.remote_write_closed.store(true, Ordering::SeqCst);
                        state.wakers.wake_all();
                    }
                }
                FRAME_RESET => {
                    let state = self.streams.lock().expect("sudoku mux streams").get(&id).cloned();
                    if let Some(state) = state {
                        let message = String::from_utf8_lossy(&payload).trim().to_string();
                        let message = if message.is_empty() {
                            "reset".to_string()
                        } else {
                            message
                        };
                        state.fail(io::Error::new(io::ErrorKind::ConnectionAborted, message));
                    }
                    self.remove_stream(id);
                }
                FRAME_OPEN => {
                    let _ = self.try_send(FRAME_RESET, id, b"unexpected open");
                }
                other => {
                    self.close_with(&format!("sudoku mux: unknown frame type {other}"));
                    return;
                }
            }
        }
    }
}

/// One logical stream of a mux session.
pub struct MuxStream {
    client: Arc<MuxClient>,
    id: u32,
    state: Arc<StreamState>,
    pending: Vec<u8>,
    /// Length of the caller buffer represented by a queued `pending` frame.
    pending_len: usize,
    write_closed: bool,
    eof_returned: bool,
}

impl MuxStream {
    fn client(&self) -> &MuxClient {
        &self.client
    }
}

impl MuxStream {
    /// Queue the frame built by the previous `poll_write`. Returns `Ready(Ok(true))`
    /// once it was accepted, `Ready(Ok(false))` when nothing was pending, and
    /// `Pending` while the writer queue is full.
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if self.pending.is_empty() {
            return Poll::Ready(Ok(false));
        }
        let client = Arc::clone(&self.client);
        if client.queue.try_push(std::mem::take(&mut self.pending)) {
            return Poll::Ready(Ok(true));
        }
        client.queue.capacity.register(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // A previously built frame is retried first; the caller's buffer is
        // the same one it passed when the write returned Pending.
        match this.poll_pending(cx) {
            Poll::Ready(Ok(true)) => {
                let len = this.pending_len;
                return Poll::Ready(Ok(len));
            }
            Poll::Ready(Ok(false)) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sudoku mux: stream write half is closed",
            )));
        }
        let len = buf.len().min(MAX_DATA);
        let frame = frame(FRAME_DATA, this.id, &buf[..len]);
        let client = Arc::clone(&this.client);
        let queued = client.queue.try_push(frame.clone());
        if queued {
            return Poll::Ready(Ok(len));
        }
        if client.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "sudoku mux: session is closed",
            )));
        }
        this.pending = frame;
        this.pending_len = len;
        client.queue.capacity.register(cx.waker());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_pending(cx) {
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if this.client.queue.is_empty() {
            return Poll::Ready(Ok(()));
        }
        this.client.queue.capacity.register(cx.waker());
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Ok(()));
        }
        match this.poll_pending(cx) {
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let client = Arc::clone(&this.client);
        if !client.is_closed() && client.queue.try_push(frame(FRAME_CLOSE, this.id, &[])) {
            this.state.local_write_closed.store(true, Ordering::SeqCst);
            this.write_closed = true;
            return Poll::Ready(Ok(()));
        }
        if client.is_closed() {
            this.write_closed = true;
            return Poll::Ready(Ok(()));
        }
        client.queue.capacity.register(cx.waker());
        Poll::Pending
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            this.state.wakers.register(cx.waker());
            {
                let mut inbox = this.state.inbox.lock().expect("sudoku mux inbox");
                if inbox.delivered < inbox.bytes.len() {
                    let remaining = &inbox.bytes[inbox.delivered..];
                    let n = buf.remaining().min(remaining.len());
                    buf.put_slice(&remaining[..n]);
                    inbox.delivered += n;
                    if inbox.delivered == inbox.bytes.len() {
                        inbox.bytes.clear();
                        inbox.delivered = 0;
                    }
                    this.state.queued.fetch_sub(n, Ordering::SeqCst);
                    return Poll::Ready(Ok(()));
                }
                inbox.bytes.clear();
                inbox.delivered = 0;
            }
            if this.eof_returned {
                return Poll::Ready(Ok(()));
            }
            if let Some(result) = this.state.closed.lock().expect("sudoku mux closed").take() {
                this.eof_returned = true;
                return Poll::Ready(result.map(|()| ()));
            }
            if this.state.remote_write_closed.load(Ordering::SeqCst) {
                this.eof_returned = true;
                return Poll::Ready(Ok(()));
            }
            return Poll::Pending;
        }
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        let client = self.client();
        if !self.write_closed && !client.is_closed() {
            // Best effort: tell the peer the stream is gone. The queue is
            // drained by the writer task.
            let _ = client.try_send(FRAME_CLOSE, self.id, &[]);
        }
        self.client.remove_stream(self.id);
    }
}

/// Open a mux stream for one dial, creating or reusing the cached session.
pub async fn dial(
    option: &SudokuOutbound,
    target: &Target,
    cache_key: &str,
) -> Result<(BoxStream, std::net::SocketAddr), DialError> {
    dial_session(option, target, cache_key, None).await
}

/// Parameters for opening a session through a `dialer-proxy` hop chain. The
/// hop connection is opened only when a new session is actually needed, so a
/// cache hit never dials the exit server and closes it again.
struct ChainContext<'a> {
    hops: &'a [&'a crate::proxies::Proxy],
    server: std::net::SocketAddr,
    timeout: std::time::Duration,
    tls: &'a crate::outbound::tls::ClientTls,
}

/// A chained dial: a new session performs the KIP `StartMux` handshake over the
/// hop tunnel; a live cached session is reused without opening a hop
/// connection.
pub async fn dial_chained(
    option: &SudokuOutbound,
    target: &Target,
    cache_key: &str,
    hops: &[&crate::proxies::Proxy],
    server: std::net::SocketAddr,
    timeout: std::time::Duration,
    tls: &crate::outbound::tls::ClientTls,
) -> Result<(BoxStream, std::net::SocketAddr), DialError> {
    dial_session(
        option,
        target,
        cache_key,
        Some(ChainContext {
            hops,
            server,
            timeout,
            tls,
        }),
    )
    .await
}

async fn dial_session(
    option: &SudokuOutbound,
    target: &Target,
    cache_key: &str,
    chain: Option<ChainContext<'_>>,
) -> Result<(BoxStream, std::net::SocketAddr), DialError> {
    let address = crate::outbound::SocksAddr::encode(target);
    for attempt in 0..2 {
        let client = match cached_client(cache_key) {
            Some(client) if !client.is_closed() => client,
            _ => {
                let client = match chain.as_ref() {
                    Some(context) => connect_chained(option, context).await?,
                    None => MuxClient::connect(option).await?,
                };
                store_client(cache_key, Arc::clone(&client));
                client
            }
        };
        match client.open(&address).await {
            Ok(stream) => {
                return Ok((Box::new(stream) as BoxStream, client.server()));
            }
            Err(_error) if attempt == 0 && client.is_closed() => {
                drop_client(cache_key);
            }
            Err(error) => {
                return Err(super::handshake(
                    "sudoku mux",
                    io::Error::new(io::ErrorKind::ConnectionAborted, error.to_string()),
                ))
            }
        }
    }
    Err(super::handshake(
        "sudoku mux",
        io::Error::new(io::ErrorKind::ConnectionAborted, "sudoku mux: session failed twice"),
    ))
}

/// Open a new session through the hop chain: reach the exit server over the
/// hops, run the KIP `StartMux` handshake on that tunnel, then split the mux
/// transport into the client.
async fn connect_chained(
    option: &SudokuOutbound,
    context: &ChainContext<'_>,
) -> Result<Arc<MuxClient>, DialError> {
    let exit_target = Target {
        host: option.server.clone(),
        port: option.port,
    };
    let raw = crate::outbound::connect_via_hops(
        context.hops,
        &exit_target,
        context.timeout,
        context.tls,
    )
    .await?;
    let (stream, server) = super::connect_stream(
        option,
        Handshake::StartMux,
        None,
        raw,
        context.server,
    )
    .await?;
    MuxClient::connect_stream(stream, server).await
}

fn clients() -> &'static Mutex<HashMap<String, Arc<MuxClient>>> {
    static CLIENTS: std::sync::OnceLock<Mutex<HashMap<String, Arc<MuxClient>>>> =
        std::sync::OnceLock::new();
    CLIENTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cached_client(key: &str) -> Option<Arc<MuxClient>> {
    clients().lock().expect("sudoku mux cache").get(key).cloned()
}

fn store_client(key: &str, client: Arc<MuxClient>) {
    let mut cache = clients().lock().expect("sudoku mux cache");
    if cache.len() >= 8 {
        cache.retain(|_, value| !value.is_closed());
    }
    if cache.len() >= 8 {
        cache.clear();
    }
    cache.insert(key.to_string(), client);
}

fn drop_client(key: &str) {
    clients().lock().expect("sudoku mux cache").remove(key);
}

/// Close every cached mux session. The engine calls this when it stops so a
/// restarted engine (same process, same configuration) does not reuse a
/// session whose socket/threads belong to the stopped engine.
pub(crate) fn close_all() {
    let clients = {
        let mut cache = clients().lock().expect("sudoku mux cache");
        std::mem::take(&mut *cache)
    };
    for client in clients.values() {
        client.close_with("sudoku mux: the kernel stopped");
    }
}

/// `trimASCII` of the pinned reset reason (kept for parity in tests).
#[cfg(test)]
fn trim_ascii(bytes: &[u8]) -> String {
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && matches!(bytes[start], b' ' | b'\n' | b'\r' | b'\t') {
        start += 1;
    }
    while end > start && matches!(bytes[end - 1], b' ' | b'\n' | b'\r' | b'\t') {
        end -= 1;
    }
    String::from_utf8_lossy(&bytes[start..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_use_the_pinned_header() {
        let wire = frame(FRAME_OPEN, 7, b"addr");
        assert_eq!(wire[0], FRAME_OPEN);
        assert_eq!(&wire[1..5], &7u32.to_be_bytes());
        assert_eq!(&wire[5..9], &4u32.to_be_bytes());
        assert_eq!(&wire[9..], b"addr");
    }

    #[test]
    fn the_write_queue_is_bounded_and_whole_frame() {
        let queue = WriteQueue::new();
        assert!(queue.try_push(vec![1, 2, 3]));
        assert_eq!(queue.pop(), Some(vec![1, 2, 3]));
        assert_eq!(queue.pop(), None);
        let big = vec![0u8; MAX_QUEUED_WRITE + 1];
        assert!(!queue.try_push(big));
    }

    #[test]
    fn a_stream_receive_queue_overflow_is_rejected() {
        let state = StreamState::new();
        let chunk = vec![0u8; 1024 * 1024];
        for _ in 0..4 {
            assert!(state.deliver(&chunk));
        }
        assert!(!state.deliver(&chunk));
    }

    #[test]
    fn trim_ascii_matches_the_pinned_helper() {
        assert_eq!(trim_ascii(b"  reset \r\n"), "reset");
        assert_eq!(trim_ascii(b"\n\t "), "");
    }

    #[tokio::test]
    async fn frames_are_demultiplexed_and_half_closed() {
        // An in-memory mux pair: the session read loop over a loopback socket
        // pair driven by a hand-written server.
        let (client_side, mut server_side) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(client_side);
        let client = Arc::new(MuxClient {
            queue: Arc::new(WriteQueue::new()),
            streams: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(0),
            closed: AtomicBool::new(false),
            server: "127.0.0.1:0".parse().unwrap(),
        });
        let writer_client = Arc::clone(&client);
        let mut writer = writer;
        let queue = Arc::clone(&client.queue);
        tokio::spawn(async move {
            loop {
                let Some(frame) = queue.pop() else {
                    queue.notify.notified().await;
                    continue;
                };
                if writer.write_all(&frame).await.is_err() {
                    writer_client.close_with("write failed");
                    return;
                }
                let _ = writer.flush().await;
            }
        });
        let client_for_read = Arc::clone(&client);
        let mut reader = reader;
        tokio::spawn(async move {
            client_for_read.read_loop(&mut reader).await;
        });

        let stream = client.open(b"example:443").await.unwrap();
        // The server sees OPEN.
        let mut header = [0u8; HEADER_SIZE];
        server_side.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], FRAME_OPEN);
        let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
        let mut payload = vec![0u8; len];
        server_side.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"example:443");
        let id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);

        // Server sends DATA; the stream reads it.
        server_side
            .write_all(&frame(FRAME_DATA, id, b"hello"))
            .await
            .unwrap();
        let mut stream = stream;
        let mut buffer = [0u8; 5];
        stream.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"hello");

        // Stream shutdown sends CLOSE.
        stream.shutdown().await.unwrap();
        let mut header = [0u8; HEADER_SIZE];
        server_side.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], FRAME_CLOSE);
        assert_eq!(
            u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
            id
        );
    }
}
