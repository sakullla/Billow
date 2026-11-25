// SPDX-License-Identifier: GPL-3.0-only
//
// Derived from Mihomo `transport/sudoku` (GPL-3.0).
// Upstream: https://github.com/MetaCubeX/mihomo
// Version: v1.19.34
// Commit: 0455d0d28c4526937380505153e65a843d8612e8
// Source paths: transport/sudoku/{address,config,handshake,handshake_kip,kip,table_probe,tables,replay,multiplex}.go,
//               transport/sudoku/crypto/*.go, transport/sudoku/obfs/{sudoku,httpmask}/*.go,
//               adapter/outbound/sudoku.go (option names and defaults)
//
// This file is a Rust translation of that GPL-3.0 code. The kernel workspace
// therefore carries GPL-3.0 obligations for the sudoku module; see
// native-kernel/THIRD_PARTY_NOTICES.md and native-kernel/COPYING.GPL-3.0.
//
//! Sudoku outbound (`adapter/outbound/sudoku.go` + `transport/sudoku` of the
//! pinned source).
//!
//! The protocol is a layered obfuscation tunnel over TCP:
//!
//! 1. an optional legacy HTTP/1.1 request header (the default camouflage);
//! 2. a table-driven obfuscation stream: each plaintext byte becomes four
//!    "hint" bytes of a 4x4 Sudoku puzzle whose table is derived from the key
//!    and the `table-type` layout (`go_rand`, `table`);
//! 3. a record layer: `u16 length | epoch(4) | seq(8) | AEAD(header as nonce
//!    and AAD, plaintext)`, with per-direction keys derived by HMAC-SHA256
//!    from a base key and the epoch;
//! 4. the KIP control plane: a client hello (timestamp, user hash, nonce,
//!    X25519 public key, feature bits, optional table hint), a server hello
//!    echoing the nonce, and a rekey to the X25519/HKDF session keys;
//! 5. `KIPTypeOpenTCP` with the SOCKS5-encoded target, then the raw stream.
//!
//! Implemented: TCP sessions with the `legacy` (default) HTTP mask, the pure
//! and packed downlink codecs, all three record AEAD methods, table rotation
//! with hints, custom byte layouts, the session multiplexer (`multiplex: on`,
//! [`mux`]) and the KIP `StartUoT` packet association (`udp: true`, framed by
//! [`crate::outbound::udp::SudokuUdp`]). Rejected at load time with the reason
//! recorded: the HTTP tunnel modes (`stream`/`poll`/`auto`/`ws`, a mihomo
//! extension over the protocol).

pub mod codec;
pub mod go_rand;
pub mod kip;
pub mod mux;
pub mod record;
pub mod table;

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{connect_tcp, handshake, BoxStream, DialError, Dialed, Target};
use crate::proxies::{SudokuAead, SudokuMultiplex, SudokuOutbound};
use codec::{Downlink, PackedDownlink, PureDownlink};
use record::{AeadMethod, RecordReceiver, RecordSender};
use table::{Encoder, TableSet};

/// How long the client waits for the server hello.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

fn aead_method(aead: SudokuAead) -> AeadMethod {
    match aead {
        SudokuAead::Chacha20Poly1305 => AeadMethod::Chacha20Poly1305,
        SudokuAead::Aes128Gcm => AeadMethod::Aes128Gcm,
        SudokuAead::None => AeadMethod::None,
    }
}

/// Build (and validate) the table rotation a configuration asks for. The
/// canonical AEAD seed is used, as the pinned outbound does.
pub fn build_tables(option: &SudokuOutbound) -> Result<Vec<Arc<TableSet>>, String> {
    build_tables_for(option).map(|tables| tables.as_ref().clone())
}

fn build_tables_for(option: &SudokuOutbound) -> Result<Arc<Vec<Arc<TableSet>>>, String> {
    let seed = crate::keys::sudoku_seed(option.key.expose())?;
    if seed.is_empty() {
        return Err("sudoku: key is empty".to_string());
    }
    let patterns: Vec<Option<&str>> = if option.custom_tables.is_empty() {
        vec![option.custom_table.as_deref()]
    } else {
        option
            .custom_tables
            .iter()
            .map(|pattern| Some(pattern.as_str()))
            .collect()
    };
    let mut tables = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        tables.push(Arc::new(table::build_tables(
            &seed,
            &option.table_type,
            pattern,
        )?));
    }
    Ok(Arc::new(tables))
}

/// Table construction is expensive (a 288-grid shuffle, the 1820 puzzle
/// candidates of every byte value and the hint-set decoder), so it happens
/// once per distinct configuration instead of once per connection. The cache
/// is bounded: configurations beyond the limit evict everything.
fn cached_tables(option: &SudokuOutbound) -> Result<Arc<Vec<Arc<TableSet>>>, String> {
    fn cache() -> &'static Mutex<HashMap<String, Arc<Vec<Arc<TableSet>>>>> {
        static CACHE: OnceLock<Mutex<HashMap<String, Arc<Vec<Arc<TableSet>>>>>> = OnceLock::new();
        CACHE.get_or_init(|| Mutex::new(HashMap::new()))
    }
    let seed = crate::keys::sudoku_seed(option.key.expose())?;
    let key = format!(
        "{}\u{1}{}\u{1}{}\u{1}{}",
        seed,
        option.table_type,
        option.custom_table.as_deref().unwrap_or(""),
        option.custom_tables.join("\u{2}")
    );
    {
        let cache = cache().lock().expect("sudoku table cache");
        if let Some(tables) = cache.get(&key) {
            return Ok(Arc::clone(tables));
        }
    }
    let built = build_tables_for(option)?;
    let mut cache = cache().lock().expect("sudoku table cache");
    if cache.len() >= 16 {
        cache.clear();
    }
    cache.insert(key, Arc::clone(&built));
    Ok(built)
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Decrypted plaintext bytes the read loop delivered and the caller has not
/// read yet.
#[derive(Default)]
struct Inbox {
    bytes: Vec<u8>,
    delivered: usize,
}

/// Waiters for a shared state machine. Unlike polling a `Notify::notified()`
/// future once and dropping it (which unregisters the waker), the wakers stay
/// registered across `Pending`; mutations wake every registered task.
pub(crate) struct Wakers {
    inner: Mutex<Vec<std::task::Waker>>,
}

impl Wakers {
    pub(crate) fn new() -> Wakers {
        Wakers {
            inner: Mutex::new(Vec::new()),
        }
    }

    /// Register the current task, replacing an existing registration of the
    /// same waker (a task polling one stream does not accumulate entries).
    pub(crate) fn register(&self, waker: &std::task::Waker) {
        let mut inner = self.inner.lock().expect("sudoku wakers");
        if inner.iter().any(|existing| existing.will_wake(waker)) {
            return;
        }
        inner.push(waker.clone());
    }

    pub(crate) fn wake_all(&self) {
        let wakers: Vec<std::task::Waker> = {
            let mut inner = self.inner.lock().expect("sudoku wakers");
            std::mem::take(&mut *inner)
        };
        for waker in wakers {
            waker.wake();
        }
    }
}

/// Writer half shared by the stream.
struct Shared {
    writer: tokio::sync::Mutex<SendHalf>,
    inbox: Mutex<Inbox>,
    closed: Mutex<Option<io::Result<()>>>,
    wakers: Wakers,
}

struct SendHalf {
    socket: tokio::io::WriteHalf<BoxStream>,
    obfs: Encoder,
    record: RecordSender,
}

/// Read loop: raw bytes -> obfuscation decode -> record open -> inbox.
async fn read_loop(
    mut socket: tokio::io::ReadHalf<BoxStream>,
    mut downlink: Box<dyn Downlink>,
    mut record: RecordReceiver,
    shared: Arc<Shared>,
    mut plaintext: Vec<u8>,
) {
    if !plaintext.is_empty() {
        let mut inbox = shared.inbox.lock().expect("sudoku inbox");
        inbox.bytes.append(&mut plaintext);
        drop(inbox);
        shared.wakers.wake_all();
    }
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let n = match socket.read(&mut buffer).await {
            Ok(0) => {
                set_closed(&shared, Ok(()));
                return;
            }
            Ok(n) => n,
            Err(error) => {
                set_closed(&shared, Err(error));
                return;
            }
        };
        let mut records = Vec::new();
        if !downlink.push(&buffer[..n], &mut records) {
            set_closed(
                &shared,
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sudoku: downlink stream is not decodable",
                )),
            );
            return;
        }
        let frames = match record.push(&records) {
            Ok(frames) => frames,
            Err(error) => {
                set_closed(&shared, Err(error));
                return;
            }
        };
        if frames.is_empty() {
            continue;
        }
        let mut inbox = shared.inbox.lock().expect("sudoku inbox");
        if inbox.delivered == inbox.bytes.len() {
            inbox.bytes.clear();
            inbox.delivered = 0;
        }
        for frame in frames {
            inbox.bytes.extend_from_slice(&frame);
        }
        drop(inbox);
        shared.wakers.wake_all();
    }
}

fn set_closed(shared: &Arc<Shared>, result: io::Result<()>) {
    let mut closed = shared.closed.lock().expect("sudoku closed");
    if closed.is_none() {
        *closed = Some(result);
    }
    drop(closed);
    shared.wakers.wake_all();
}

/// The proxy connection handed to the relay.
pub struct SudokuStream {
    shared: Arc<Shared>,
    pending: Vec<u8>,
    pending_at: usize,
    shutdown_sent: bool,
    /// A close was already reported, so later reads return EOF instead of
    /// waiting forever.
    eof_returned: bool,
}

impl SudokuStream {
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_at >= self.pending.len() {
            self.pending.clear();
            self.pending_at = 0;
            return Poll::Ready(Ok(()));
        }
        let shared = self.shared.clone();
        let mut writer = match shared.writer.try_lock() {
            Ok(writer) => writer,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        while self.pending_at < self.pending.len() {
            match Pin::new(&mut writer.socket).poll_write(cx, &self.pending[self.pending_at..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "sudoku: peer closed the stream",
                    )))
                }
                Poll::Ready(Ok(n)) => self.pending_at += n,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending.clear();
        self.pending_at = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SudokuStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match this.poll_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let shared = this.shared.clone();
        let mut writer = match shared.writer.try_lock() {
            Ok(writer) => writer,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        let records = match writer.record.seal(buf) {
            Ok(records) => records,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let wire = writer.obfs.encode(&records);
        drop(writer);
        this.pending = wire;
        this.pending_at = 0;
        match this.poll_pending(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            _ => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let shared = this.shared.clone();
        let mut writer = match shared.writer.try_lock() {
            Ok(writer) => writer,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        Pin::new(&mut writer.socket).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let shared = this.shared.clone();
        let mut writer = match shared.writer.try_lock() {
            Ok(writer) => writer,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        if !this.shutdown_sent {
            // Half-close: the peer relays the FIN to the target, and the read
            // side keeps delivering what the target still sends.
            match Pin::new(&mut writer.socket).poll_shutdown(cx) {
                Poll::Ready(Ok(())) => this.shutdown_sent = true,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for SudokuStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // Register before looking at the shared state; the waker stays
            // registered across `Pending`, so a delivery after the check wakes
            // this task.
            this.shared.wakers.register(cx.waker());
            {
                let mut inbox = this.shared.inbox.lock().expect("sudoku inbox");
                if inbox.delivered < inbox.bytes.len() {
                    let remaining = &inbox.bytes[inbox.delivered..];
                    let n = buf.remaining().min(remaining.len());
                    buf.put_slice(&remaining[..n]);
                    inbox.delivered += n;
                    if inbox.delivered == inbox.bytes.len() {
                        inbox.bytes.clear();
                        inbox.delivered = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                inbox.bytes.clear();
                inbox.delivered = 0;
            }
            if this.eof_returned {
                return Poll::Ready(Ok(()));
            }
            if let Some(result) = this.shared.closed.lock().expect("sudoku closed").take() {
                this.eof_returned = true;
                return Poll::Ready(result.map(|()| ()));
            }
            return Poll::Pending;
        }
    }
}

/// The plaintext stream during the handshake: one KIP message at a time.
struct HandshakeIo {
    socket: BoxStream,
    obfs: Encoder,
    record_tx: RecordSender,
    record_rx: RecordReceiver,
    downlink: Box<dyn Downlink>,
    plaintext: Vec<u8>,
    buffer: Vec<u8>,
}

impl HandshakeIo {
    async fn send(&mut self, kind: u8, payload: &[u8]) -> io::Result<()> {
        let message = kip::encode_message(kind, payload)?;
        let records = self.record_tx.seal(&message)?;
        let wire = self.obfs.encode(&records);
        self.socket.write_all(&wire).await
    }

    async fn next_message(&mut self, deadline: Duration) -> io::Result<kip::Message> {
        let deadline = tokio::time::Instant::now() + deadline;
        loop {
            if let Some(message) = kip::parse_message(&self.plaintext)? {
                self.plaintext.drain(..message.total);
                return Ok(message);
            }
            let mut buffer = vec![0u8; 8192];
            let read = tokio::time::timeout_at(deadline, self.socket.read(&mut buffer)).await;
            let n = match read {
                Ok(result) => result?,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "sudoku: no handshake reply",
                    ))
                }
            };
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sudoku: peer closed during the handshake",
                ));
            }
            self.buffer.clear();
            if !self.downlink.push(&buffer[..n], &mut self.buffer) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sudoku: handshake stream is not decodable",
                ));
            }
            for record in self.record_rx.push(&self.buffer)? {
                self.plaintext.extend_from_slice(&record);
            }
        }
    }
}

/// `maxFrameSize` of the pinned mux session.
pub(crate) const SUDOKU_MAX_FRAME: usize = 256 * 1024;

/// Which KIP session kind the handshake asks for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Handshake {
    OpenTcp,
    StartMux,
    StartUot,
}

/// Build the table cache key: every wire-shaping option of the proxy.
fn mux_cache_key(option: &SudokuOutbound) -> String {
    [
        option.server.clone(),
        option.port.to_string(),
        option.key.expose().to_string(),
        format!("{:?}", option.aead_method),
        format!("{}-{}", option.padding_min, option.padding_max),
        option.table_type.clone(),
        option.custom_table.clone().unwrap_or_default(),
        option.custom_tables.join("\u{2}"),
        option.http_mask.to_string(),
        option.path_root.clone().unwrap_or_default(),
        option.enable_pure_downlink.to_string(),
    ]
    .join("\u{1}")
}

/// Perform the Sudoku handshake and the KIP session request; the returned
/// stream is the raw session stream (one target, or the mux transport).
pub(crate) async fn connect(
    option: &SudokuOutbound,
    kind: Handshake,
    target: Option<&Target>,
) -> Result<(BoxStream, std::net::SocketAddr), DialError> {
    let socket = connect_tcp(&option.server, option.port).await?;
    let server = socket.peer_addr().map_err(|e| handshake("sudoku", e))?;
    connect_stream(option, kind, target, Box::new(socket) as BoxStream, server).await
}

/// The same handshake over a connection already established by a
/// `dialer-proxy` hop (the exit's server connection); `server` is the address
/// the hop carried the stream to.
pub(crate) async fn connect_stream(
    option: &SudokuOutbound,
    kind: Handshake,
    target: Option<&Target>,
    socket: BoxStream,
    server: std::net::SocketAddr,
) -> Result<(BoxStream, std::net::SocketAddr), DialError> {
    let tables = cached_tables(option).map_err(DialError::Chain)?;
    if tables.is_empty() {
        return Err(DialError::Chain("sudoku: no table configured".into()));
    }
    // A rotating table set picks one table per connection and always sends the
    // hint, so the probing server resolves it; a single table sends no hint.
    let (chosen, hint) = if tables.len() == 1 {
        (Arc::clone(&tables[0]), None)
    } else {
        let index = (rand::random::<u8>() as usize) % tables.len();
        (Arc::clone(&tables[index]), Some(tables[index].uplink.hint))
    };

    let mut socket = socket;

    if option.http_mask {
        let host = format!("{}:{}", option.server, option.port);
        let header = codec::legacy_header(&host, option.path_root.as_deref().unwrap_or(""));
        socket
            .write_all(&header)
            .await
            .map_err(|e| handshake("sudoku http mask", e))?;
    }

    let seed = crate::keys::sudoku_seed(option.key.expose()).map_err(DialError::Chain)?;
    let method = aead_method(option.aead_method);
    let (psk_c2s, psk_s2c) =
        kip::psk_directional_bases(&seed).map_err(|e| handshake("sudoku", e))?;
    let record_tx =
        RecordSender::new(method, psk_c2s.to_vec()).map_err(|e| handshake("sudoku", e))?;
    let record_rx =
        RecordReceiver::new(method, psk_s2c.to_vec()).map_err(|e| handshake("sudoku", e))?;
    let obfs = codec::uplink_encoder(
        Arc::clone(&chosen.uplink),
        option.padding_min,
        option.padding_max,
    );
    let downlink: Box<dyn Downlink> = if option.enable_pure_downlink {
        Box::new(PureDownlink::new(Arc::clone(&chosen.downlink)))
    } else {
        Box::new(PackedDownlink::new(Arc::clone(&chosen.downlink)))
    };

    let mut io = HandshakeIo {
        socket,
        obfs,
        record_tx,
        record_rx,
        downlink,
        plaintext: Vec::new(),
        buffer: Vec::new(),
    };

    let (client_secret, client_pub) = kip::ephemeral_key();
    let mut nonce = [0u8; kip::NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let features = match kind {
        Handshake::OpenTcp => kip::FEATURE_OPEN_TCP,
        Handshake::StartMux => kip::FEATURE_OPEN_TCP | kip::FEATURE_MUX,
        Handshake::StartUot => kip::FEATURE_OPEN_TCP | kip::FEATURE_UOT,
    };
    let hello = kip::ClientHello {
        timestamp: now_seconds(),
        user_hash: kip::user_hash(option.key.expose()),
        nonce,
        client_pub,
        features,
        table_hint: hint,
    };
    io.send(kip::TYPE_CLIENT_HELLO, &hello.encode())
        .await
        .map_err(|e| handshake("sudoku", e))?;

    let message = io
        .next_message(HANDSHAKE_TIMEOUT)
        .await
        .map_err(|e| handshake("sudoku", e))?;
    if message.kind != kip::TYPE_SERVER_HELLO {
        return Err(handshake(
            "sudoku",
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("sudoku: unexpected handshake message {}", message.kind),
            ),
        ));
    }
    let server_hello =
        kip::decode_server_hello(&message.payload).map_err(|e| handshake("sudoku", e))?;
    if server_hello.nonce != nonce {
        return Err(handshake(
            "sudoku",
            io::Error::new(
                io::ErrorKind::InvalidData,
                "sudoku: server hello nonce mismatch",
            ),
        ));
    }
    let shared = kip::shared_secret(&client_secret, &server_hello.server_pub);
    let (sess_c2s, sess_s2c) = kip::session_directional_bases(&seed, &shared, &nonce)
        .map_err(|e| handshake("sudoku", e))?;
    io.record_tx
        .rekey(sess_c2s.to_vec())
        .map_err(|e| handshake("sudoku", e))?;
    io.record_rx
        .rekey(sess_s2c.to_vec())
        .map_err(|e| handshake("sudoku", e))?;

    match kind {
        Handshake::OpenTcp => {
            let target = target.ok_or_else(|| {
                DialError::Chain("sudoku: a single-session dial needs a target".into())
            })?;
            let address = super::SocksAddr::encode(target);
            io.send(kip::TYPE_OPEN_TCP, &address)
                .await
                .map_err(|e| handshake("sudoku", e))?;
        }
        Handshake::StartMux => {
            io.send(kip::TYPE_START_MUX, &[])
                .await
                .map_err(|e| handshake("sudoku", e))?;
        }
        Handshake::StartUot => {
            io.send(kip::TYPE_START_UOT, &[])
                .await
                .map_err(|e| handshake("sudoku", e))?;
        }
    }

    let HandshakeIo {
        socket,
        obfs,
        record_tx,
        record_rx,
        downlink,
        plaintext,
        ..
    } = io;
    let (read_half, write_half) = tokio::io::split(socket);
    let shared = Arc::new(Shared {
        writer: tokio::sync::Mutex::new(SendHalf {
            socket: write_half,
            obfs,
            record: record_tx,
        }),
        inbox: Mutex::new(Inbox::default()),
        closed: Mutex::new(None),
        wakers: Wakers::new(),
    });
    let stream = SudokuStream {
        shared: Arc::clone(&shared),
        pending: Vec::new(),
        pending_at: 0,
        shutdown_sent: false,
        eof_returned: false,
    };
    tokio::spawn(read_loop(read_half, downlink, record_rx, shared, plaintext));
    Ok((Box::new(stream) as BoxStream, server))
}

pub async fn dial(option: &SudokuOutbound, target: &Target) -> Result<Dialed, DialError> {
    if option.multiplex == SudokuMultiplex::On {
        let key = mux_cache_key(option);
        let (stream, server) = mux::dial(option, target, &key).await?;
        return Ok(Dialed { stream, server });
    }
    let (stream, server) = connect(option, Handshake::OpenTcp, Some(target)).await?;
    Ok(Dialed { stream, server })
}

/// A chained dial: the exit's server connection is tunnelled through `hops`.
/// With `multiplex: on` a live cached session is reused before any hop
/// connection is opened; a new session performs the KIP `StartMux` handshake
/// over the hop tunnel before the mux client is created.
pub async fn dial_chained(
    option: &SudokuOutbound,
    target: &Target,
    hops: &[&crate::proxies::Proxy],
    server: std::net::SocketAddr,
    timeout: std::time::Duration,
    tls: &super::tls::ClientTls,
) -> Result<Dialed, DialError> {
    if option.multiplex == SudokuMultiplex::On {
        let key = mux_cache_key(option) + &chain_suffix(hops);
        let (stream, server) =
            mux::dial_chained(option, target, &key, hops, server, timeout, tls).await?;
        return Ok(Dialed { stream, server });
    }
    let exit_server = Target {
        host: option.server.clone(),
        port: option.port,
    };
    let stream = super::connect_via_hops(hops, &exit_server, timeout, tls).await?;
    let (stream, server) =
        connect_stream(option, Handshake::OpenTcp, Some(target), stream, server).await?;
    Ok(Dialed { stream, server })
}

/// Identity of the hop chain for the mux session cache (name, type and port).
fn chain_suffix(hops: &[&crate::proxies::Proxy]) -> String {
    if hops.is_empty() {
        return String::new();
    }
    let hops = hops
        .iter()
        .map(|proxy| format!("{}:{}:{}", proxy.name, proxy.type_name(), proxy.server().1))
        .collect::<Vec<_>>()
        .join("\u{2}");
    format!("\u{1}chain\u{1}{hops}")
}
