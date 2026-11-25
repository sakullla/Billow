//! AnyTLS outbound (Mihomo `adapter/outbound/anytls.go`, protocol version 2).
//!
//! One TLS connection carries a session of multiplexed streams. The client
//! opens with `SHA-256(password) || u16 padding length`, then sends a settings
//! frame (`v=2`, `padding-md5`), one `SYN` and the destination in the server's
//! address serialiser (ATYP 1/4 for IPs, the FQDN form for names, then the
//! port - as `sing`'s SocksaddrSerializer writes it), then `PSH` frames.
//!
//! Frame: `cmd(1) | stream id(4, BE) | length(2, BE) | data`.
//! This client opens one stream per connection and sends no optional padding
//! frames; the initial padding length is 0, which the server accepts.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use ring::digest::{digest, SHA256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{connect_tcp, handshake, tls, BoxStream, DialError, Dialed, Target};
use crate::proxies::AnytlsOutbound;

use super::tls::ClientTls;

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

const HEADER: usize = 7;
const MAX_FRAME: usize = 0xFF_FF;

fn frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + data.len());
    out.push(cmd);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// The destination as `sing`'s SocksaddrSerializer writes it (ATYP, address, port).
pub fn write_destination(target: &Target) -> Vec<u8> {
    let mut out = Vec::with_capacity(target.host.len() + 9);
    if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                out.push(1);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(4);
                out.extend_from_slice(&v6.octets());
            }
        }
    } else {
        out.push(3);
        out.push(target.host.len() as u8);
        out.extend_from_slice(target.host.as_bytes());
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    out
}

/// The first bytes of a session: password hash and the (empty) padding header.
pub fn hello(password: &str) -> Vec<u8> {
    let mut out = digest(&SHA256, password.as_bytes()).as_ref().to_vec();
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

fn settings(client_metadata: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"client=");
    out.extend_from_slice(client_metadata.unwrap_or("").as_bytes());
    out.extend_from_slice(b"\npadding-md5=\nv=2");
    out
}

struct StreamState {
    synack: Mutex<Option<tokio::sync::oneshot::Sender<io::Result<()>>>>,
    recv: Mutex<Option<std::task::Waker>>,
    inbox: Mutex<Vec<u8>>,
    closed: Mutex<Option<io::Result<()>>>,
    fin_sent: AtomicBool,
}

impl StreamState {
    fn fail(&self, error: io::Error) {
        let mut closed = self.closed.lock().expect("anytls closed");
        if closed.is_none() {
            *closed = Some(Err(error));
        }
        drop(closed);
        self.wake();
    }

    fn wake(&self) {
        if let Some(waker) = self.recv.lock().expect("anytls waker").take() {
            waker.wake();
        }
    }
}

struct Session<W> {
    writer: tokio::sync::Mutex<W>,
    streams: Mutex<HashMap<u32, Arc<StreamState>>>,
    next_sid: AtomicU32,
    active: AtomicUsize,
    closed: AtomicBool,
    shutdown: tokio::sync::Notify,
    /// Called (once per transition to zero active streams) by the stream drop
    /// so the outbound's idle-session pool can take the session back.
    idle_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl<W> Session<W> {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Stop the receive loop and fail every open stream. Frames already queued
    /// on the socket are not drained; the peer observes a closed connection.
    fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.shutdown.notify_waiters();
            for state in self.streams.lock().expect("anytls streams").values() {
                state.fail(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "anytls session closed",
                ));
            }
        }
    }
}

impl<W: AsyncWrite + Unpin> Session<W> {
    async fn send(&self, bytes: &[u8]) -> io::Result<()> {
        let mut writer = self.writer.lock().await;
        writer.write_all(bytes).await?;
        writer.flush().await
    }
}

/// Poll a `write` on the shared session writer without blocking the caller:
/// when the mutex is contended the task is woken and tries again.
fn poll_session_write<W: AsyncWrite + Unpin>(
    session: &Session<W>,
    cx: &mut Context<'_>,
    bytes: &[u8],
    flush: bool,
) -> Poll<io::Result<()>> {
    let mut writer = match session.writer.try_lock() {
        Ok(writer) => writer,
        Err(_) => {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
    };
    let mut written = 0;
    while written < bytes.len() {
        match Pin::new(&mut *writer).poll_write(cx, &bytes[written..]) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "anytls session closed",
                )))
            }
            Poll::Ready(Ok(n)) => written += n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
    }
    if flush {
        match Pin::new(&mut *writer).poll_flush(cx) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    } else {
        Poll::Ready(Ok(()))
    }
}

/// The AnyTLS stream handed to the relay.
pub struct AnytlsStream<W: AsyncWrite + Unpin + Send> {
    session: Arc<Session<W>>,
    state: Arc<StreamState>,
    sid: u32,
    /// Bytes of the current inbox chunk already delivered.
    delivered: usize,
}

impl<W: AsyncWrite + Unpin + Send> AsyncWrite for AnytlsStream<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let len = buf.len().min(MAX_FRAME);
        let bytes = frame(CMD_PSH, this.sid, &buf[..len]);
        match poll_session_write(&this.session, cx, &bytes, false) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(len)),
            other => other.map(|r| r.map(|_| 0)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_session_write(&this.session, cx, &[], true)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.state.fin_sent.swap(true, Ordering::SeqCst) {
            let bytes = frame(CMD_FIN, this.sid, &[]);
            match poll_session_write(&this.session, cx, &bytes, false) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.state.fin_sent.store(false, Ordering::SeqCst);
                    return Poll::Pending;
                }
            }
        }
        poll_session_write(&this.session, cx, &[], true)
    }
}

impl<W: AsyncWrite + Unpin + Send> AsyncRead for AnytlsStream<W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            {
                let mut inbox = this.state.inbox.lock().expect("anytls inbox");
                if this.delivered < inbox.len() {
                    let n = buf.remaining().min(inbox.len() - this.delivered);
                    buf.put_slice(&inbox[this.delivered..this.delivered + n]);
                    this.delivered += n;
                    if this.delivered == inbox.len() {
                        inbox.clear();
                        this.delivered = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                inbox.clear();
                this.delivered = 0;
            }
            if let Some(result) = this.state.closed.lock().expect("anytls closed").take() {
                return Poll::Ready(result);
            }
            *this.state.recv.lock().expect("anytls waker") = Some(cx.waker().clone());
            // The receive loop may have queued bytes or a close between the
            // check above and the waker registration. Re-check after the
            // waker is visible so no wakeup is lost; the loop delivers it.
            let ready = {
                let inbox = this.state.inbox.lock().expect("anytls inbox");
                !inbox.is_empty()
            } || this.state.closed.lock().expect("anytls closed").is_some();
            if ready {
                // Drop our waker (the receive loop may already have taken it
                // and woken us, which is harmless) and deliver the state.
                *this.state.recv.lock().expect("anytls waker") = None;
                continue;
            }
            return Poll::Pending;
        }
    }
}

impl<W: AsyncWrite + Unpin + Send> Drop for AnytlsStream<W> {
    fn drop(&mut self) {
        let _ = self
            .session
            .streams
            .lock()
            .expect("anytls streams")
            .remove(&self.sid);
        if self
            .session
            .active
            .fetch_sub(1, Ordering::AcqRel)
            == 1
        {
            let hook = self
                .session
                .idle_hook
                .lock()
                .expect("anytls idle hook")
                .clone();
            if let Some(hook) = hook {
                hook();
            }
        }
    }
}

/// Read frames until the session ends; a stream that is still open then fails.
async fn recv_loop<R, W>(mut reader: R, session: Arc<Session<W>>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut header = [0u8; HEADER];
    'frames: loop {
        let read = tokio::select! {
            _ = session.shutdown.notified() => break 'frames,
            result = reader.read_exact(&mut header) => result,
        };
        if read.is_err() {
            break;
        }
        let cmd = header[0];
        let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let len = u16::from_be_bytes([header[5], header[6]]) as usize;
        let mut data = vec![0u8; len];
        if len > 0 && reader.read_exact(&mut data).await.is_err() {
            break;
        }
        let state = session
            .streams
            .lock()
            .expect("anytls streams")
            .get(&sid)
            .cloned();
        match cmd {
            CMD_PSH => {
                if let Some(state) = &state {
                    state
                        .inbox
                        .lock()
                        .expect("anytls inbox")
                        .extend_from_slice(&data);
                    state.wake();
                }
            }
            CMD_SYNACK => {
                if let Some(state) = &state {
                    if let Some(tx) = state.synack.lock().expect("anytls synack").take() {
                        let result = if data.is_empty() {
                            Ok(())
                        } else {
                            Err(io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                String::from_utf8_lossy(&data).to_string(),
                            ))
                        };
                        let _ = tx.send(result);
                    }
                }
            }
            CMD_FIN => {
                if let Some(state) = &state {
                    *state.closed.lock().expect("anytls closed") = Some(Ok(()));
                    state.wake();
                }
            }
            CMD_ALERT => {
                let message = format!("anytls server alert: {}", String::from_utf8_lossy(&data));
                for state in session.streams.lock().expect("anytls streams").values() {
                    state.fail(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        message.clone(),
                    ));
                }
                break 'frames;
            }
            CMD_HEART_REQUEST => {
                let _ = session.send(&frame(CMD_HEART_RESPONSE, sid, &[])).await;
            }
            CMD_SERVER_SETTINGS | CMD_UPDATE_PADDING | CMD_SETTINGS | CMD_WASTE
            | CMD_HEART_RESPONSE => {}
            _ => {}
        }
    }
    session.closed.store(true, Ordering::Release);
    for state in session.streams.lock().expect("anytls streams").values() {
        state.fail(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "anytls session closed",
        ));
    }
}

/// The concrete writer of a pooled AnyTLS session (both halves come from
/// `tokio::io::split` over the boxed TLS/WebSocket stream).
pub type BoxWriter = tokio::io::WriteHalf<BoxStream>;

/// One AnyTLS stream over a pooled session, as handed to the UDP relay.
pub type AnyUotStream = AnytlsStream<BoxWriter>;

/// One idle session plus the server address it was dialled at.
struct IdleSession {
    session: Arc<Session<BoxWriter>>,
    server: std::net::SocketAddr,
    since: Instant,
}

/// Per-outbound idle-session pool (pinned `anytls/session.Client`).
///
/// `client-metadata` is sent in the settings frame of every new session;
/// `disable-reuse` never pools (a stream's session is closed when it ends);
/// a background ticker sweeps expired sessions every
/// `idle-session-check-interval` (with a lazy sweep on acquire/release as a
/// fallback outside a runtime), and `idle-session-timeout` / `min-idle-session`
/// decide which idle sessions are kept. The pool is runtime state, not part of
/// the configuration, so equality ignores it and dropping it aborts the ticker
/// and closes idle sessions.
#[derive(Default)]
pub struct AnytlsPool {
    idle: Mutex<Vec<IdleSession>>,
    check_interval: u64,
    timeout: u64,
    min_idle: usize,
    /// The pinned background ticker (`util.StartRoutine`). It is started on
    /// the first pooled session, because configuration parsing may run outside
    /// a Tokio runtime, and aborted when the pool is dropped.
    ticker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for AnytlsPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnytlsPool")
            .field("check_interval", &self.check_interval)
            .field("timeout", &self.timeout)
            .field("min_idle", &self.min_idle)
            .finish()
    }
}

impl PartialEq for AnytlsPool {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for AnytlsPool {}

impl AnytlsPool {
    pub fn new(
        check_interval: u64,
        timeout: u64,
        min_idle: usize,
        _disable_reuse: bool,
    ) -> Arc<AnytlsPool> {
        Arc::new(AnytlsPool {
            idle: Mutex::new(Vec::new()),
            check_interval,
            timeout,
            min_idle,
            ticker: Mutex::new(None),
        })
    }

    /// The pinned check interval decides how often the background ticker
    /// sweeps expired sessions.
    pub fn check_interval(&self) -> u64 {
        self.check_interval
    }

    fn sweep(&self) {
        let now = Instant::now();
        let timeout = Duration::from_secs(self.timeout);
        let mut idle = self.idle.lock().expect("anytls pool");
        // The pinned skip list iterates newest-idle first; keep that order so
        // `min-idle-session` retains the most recently returned sessions.
        idle.sort_by(|a, b| b.since.cmp(&a.since));
        let mut kept = Vec::with_capacity(idle.len());
        for (index, session) in idle.drain(..).enumerate() {
            let expired = now.duration_since(session.since) >= timeout;
            if !expired || index < self.min_idle {
                if expired {
                    // The minimum-idle set is refreshed, as the pinned sweep
                    // does, so it is not immediately eligible again.
                    kept.push(IdleSession {
                        since: now,
                        ..session
                    });
                } else {
                    kept.push(session);
                }
            } else {
                session.session.close();
            }
        }
        *idle = kept;
    }

    fn take(&self) -> Option<(Arc<Session<BoxWriter>>, std::net::SocketAddr)> {
        self.sweep();
        let mut idle = self.idle.lock().expect("anytls pool");
        loop {
            if idle.is_empty() {
                return None;
            }
            // Newest idle session first, as the pinned `getIdleSession`.
            let session = idle.remove(0);
            if !session.session.is_closed() {
                return Some((session.session, session.server));
            }
        }
    }

    fn put(self: &Arc<Self>, session: Arc<Session<BoxWriter>>, server: std::net::SocketAddr) {
        if session.is_closed() {
            return;
        }
        self.sweep();
        self.idle
            .lock()
            .expect("anytls pool")
            .push(IdleSession {
                session,
                server,
                since: Instant::now(),
            });
        self.ensure_ticker();
    }

    /// Start the pinned interval sweep once. `idle-session-check-interval` is
    /// otherwise only a stored number; the ticker makes it decide how often
    /// expired sessions are actually closed.
    fn ensure_ticker(self: &Arc<Self>) {
        let mut ticker = self.ticker.lock().expect("anytls ticker");
        if ticker.is_some() {
            return;
        }
        let interval = Duration::from_secs(self.check_interval.max(1));
        let weak = Arc::downgrade(self);
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            // No runtime (configuration parsing/drop outside Tokio): the lazy
            // sweep on acquire/release still applies the timeout.
            return;
        };
        *ticker = Some(handle.spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                match weak.upgrade() {
                    Some(pool) => pool.sweep(),
                    None => break,
                }
            }
        }));
    }
}

impl Drop for AnytlsPool {
    fn drop(&mut self) {
        let handle = self
            .ticker
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(handle) = handle {
            handle.abort();
        }
        let idle = self
            .idle
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for session in idle.drain(..) {
            session.session.close();
        }
    }
}

async fn open_session(
    option: &AnytlsOutbound,
    tls: &ClientTls,
    via: &[&crate::proxies::Proxy],
    timeout: Duration,
) -> Result<(Arc<Session<BoxWriter>>, std::net::SocketAddr), DialError> {
    // `via[0]` is this anytls outbound and `via[1]` the single socks5 hop the
    // `dialer-proxy` chain may carry (validated at load). The server socket is
    // therefore either direct or a hop tunnel, never a silent bypass.
    let (stream, server): (BoxStream, std::net::SocketAddr) = match via.len() {
        0 | 1 => {
            let tcp = connect_tcp(&option.server, option.port).await?;
            let server = tcp.peer_addr().map_err(|e| handshake("anytls", e))?;
            (Box::new(tcp), server)
        }
        _ => (
            super::udp::server_stream(&option.server, option.port, via, timeout, tls).await?,
            super::peer_of(via[0]),
        ),
    };
    let mut stream: BoxStream = match &option.security {
        crate::proxies::TlsSecurity::None => Box::new(
            tls::wrap_stream(stream, &option.server, &option.tls_settings, tls)
                .await
                .map_err(|e| handshake("anytls tls", e))?,
        ),
        crate::proxies::TlsSecurity::ShadowTls { password, version } => {
            // ShadowTLS replaces the TLS layer entirely: the camouflage
            // handshake *is* the TLS session, and the AnyTLS frames then travel
            // inside its plaintext records (pinned `StreamTLSConn` returns the
            // ShadowTLS connection without a second handshake).
            super::shadow_tls::wrap(
                stream,
                &option.server,
                &option.tls_settings,
                tls,
                password.expose(),
                *version,
            )
            .await
            .map_err(|e| handshake("anytls shadow-tls", e))?
        }
        crate::proxies::TlsSecurity::Jls { username, password } => {
            let credentials = super::jls::JlsCredentials {
                username: username.expose().to_string(),
                password: password.expose().to_string(),
            };
            super::tls_io::connect_jls(
                stream,
                &option.server,
                &option.tls_settings,
                tls,
                &credentials,
            )
            .await
            .map_err(|e| handshake("anytls jls", e))?
        }
    };
    let mut opening = hello(option.password.expose());
    opening.extend_from_slice(&frame(
        CMD_SETTINGS,
        0,
        &settings(option.client_metadata.as_deref()),
    ));
    stream
        .write_all(&opening)
        .await
        .map_err(|e| handshake("anytls", e))?;
    stream.flush().await.map_err(|e| handshake("anytls", e))?;
    let (reader, writer) = tokio::io::split(stream);
    let session = Arc::new(Session {
        writer: tokio::sync::Mutex::new(writer),
        streams: Mutex::new(HashMap::new()),
        next_sid: AtomicU32::new(0),
        active: AtomicUsize::new(0),
        closed: AtomicBool::new(false),
        shutdown: tokio::sync::Notify::new(),
        idle_hook: Mutex::new(None),
    });
    tokio::spawn(recv_loop(reader, session.clone()));
    // Install the return/close hook once the session exists.
    let weak_session = Arc::downgrade(&session);
    let hook: Arc<dyn Fn() + Send + Sync> = if option.disable_reuse {
        Arc::new(move || {
            if let Some(session) = weak_session.upgrade() {
                session.close();
            }
        })
    } else {
        let weak_pool = Arc::downgrade(&option.session_pool);
        Arc::new(move || {
            if let (Some(session), Some(pool)) = (weak_session.upgrade(), weak_pool.upgrade()) {
                pool.put(session, server);
            }
        })
    };
    *session.idle_hook.lock().expect("anytls idle hook") = Some(hook);
    Ok((session, server))
}

async fn acquire_session(
    option: &AnytlsOutbound,
    tls: &ClientTls,
    via: &[&crate::proxies::Proxy],
    timeout: Duration,
) -> Result<(Arc<Session<BoxWriter>>, std::net::SocketAddr), DialError> {
    if !option.disable_reuse {
        if let Some((session, server)) = option.session_pool.take() {
            return Ok((session, server));
        }
    }
    open_session(option, tls, via, timeout).await
}

/// Open one stream on `session`, sending the destination first.
async fn open_stream(
    session: Arc<Session<BoxWriter>>,
    target: &Target,
) -> Result<AnytlsStream<BoxWriter>, DialError> {
    let sid = session.next_sid.fetch_add(1, Ordering::AcqRel) + 1;
    // The server's success/failure report for this stream (SYNACK).
    let (syn_tx, _syn_rx) = tokio::sync::oneshot::channel();
    let state = Arc::new(StreamState {
        synack: Mutex::new(Some(syn_tx)),
        recv: Mutex::new(None),
        inbox: Mutex::new(Vec::new()),
        closed: Mutex::new(None),
        fin_sent: AtomicBool::new(false),
    });
    session
        .streams
        .lock()
        .expect("anytls streams")
        .insert(sid, state.clone());
    session.active.fetch_add(1, Ordering::AcqRel);
    let mut opening = frame(CMD_SYN, sid, &[]);
    opening.extend_from_slice(&frame(CMD_PSH, sid, &write_destination(target)));
    if let Err(error) = session.send(&opening).await {
        let _ = session.streams.lock().expect("anytls streams").remove(&sid);
        session.active.fetch_sub(1, Ordering::AcqRel);
        return Err(handshake("anytls", error));
    }
    Ok(AnytlsStream {
        session,
        state,
        sid,
        delivered: 0,
    })
}

pub async fn dial(
    option: &AnytlsOutbound,
    target: &Target,
    tls: &ClientTls,
    timeout: Duration,
) -> Result<Dialed, DialError> {
    let (session, server) = acquire_session(option, tls, &[], timeout).await?;
    let stream = open_stream(session, target).await?;
    Ok(Dialed {
        stream: Box::new(stream),
        server,
    })
}

/// UoT magic destination (`sing/common/uot.RequestDestination(2)`).
pub const UOT_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";

/// Open the AnyTLS stream a UDP association uses: a stream to the UoT magic
/// destination followed by the v2 request (`isConnect=1`, destination).
pub async fn dial_uot(
    option: &AnytlsOutbound,
    target: &Target,
    via: &[&crate::proxies::Proxy],
    timeout: Duration,
    tls: &ClientTls,
) -> Result<(AnytlsStream<BoxWriter>, std::net::SocketAddr), DialError> {
    let (session, server) = acquire_session(option, tls, via, timeout).await?;
    let magic = Target {
        host: UOT_MAGIC.to_string(),
        port: 0,
    };
    let mut stream = open_stream(session, &magic).await?;
    let mut request = Vec::with_capacity(1 + target.host.len() + 9);
    request.push(1); // isConnect
    request.extend_from_slice(&write_destination(target));
    stream
        .write_all(&request)
        .await
        .map_err(|e| handshake("anytls uot", e))?;
    stream
        .flush()
        .await
        .map_err(|e| handshake("anytls uot", e))?;
    Ok((stream, server))
}
