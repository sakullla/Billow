//! mieru TCP outbound (the mieru v3.39.0 stream protocol as reached by the
//! pinned `adapter/outbound/mieru.go`).
//!
//! The module is GPL-3.0, so this is an independent implementation written
//! from the published protocol description
//! (`github.com/enfein/mieru/v3` `docs/protocol.md`) and from wire
//! observations against the pinned Mihomo `listeners: type: mieru`; no mieru
//! source is copied into this repository and no mieru crate is linked.
//!
//! A connection is one underlay stream that hosts one session:
//!
//! - key: `PBKDF2-SHA256(SHA256(password || 0x00 || username), SHA256(BE64(
//!   round(now, 2 min))), 64 iterations, 32 bytes)`; the server tries the
//!   previous, current and next salt, so a clock skew within ±2 minutes works.
//! - AEAD: XChaCha20-Poly1305 with a 24-byte nonce. The first operation in a
//!   direction prepends the nonce; every later operation increments the nonce
//!   as a big-endian 192-bit counter (including the 4-byte user hint suffix
//!   the first nonce carries).
//! - segment: `[nonce] AEAD(metadata 32) [prefix padding] [AEAD(payload)]
//!   [suffix padding]`; the nonce appears only on the first segment of each
//!   direction, and `prefix padding` only exists for data/ack metadata.
//! - session: the client opens it with `openSessionRequest` carrying a SOCKS5
//!   CONNECT request (the first bytes the peer reads), the peer answers with
//!   `openSessionResponse` and its own SOCKS5 reply, then both directions
//!   carry `data*` segments with an increasing sequence number.
//!
//! TCP transport, `transport: TCP` only, one session per underlay. UDP
//! transport, mieru multiplexing (`multiplexing`), `traffic-pattern`
//! (low-entropy and nonce patterns) are rejected at load time with the reason
//! recorded; this is the single-session TCP slice T13 owns.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead as _, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Notify;

use super::{connect_tcp, handshake, BoxStream, DialError, Dialed, Target};
use crate::proxies::{MieruOutbound, MieruTransport};

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const META_LEN: usize = 32;
const MAX_PAYLOAD: usize = 32 * 1024;
/// Upper bound of one encoded segment queued in front of the socket.
const MAX_SEGMENT: usize = MAX_PAYLOAD + META_LEN + NONCE_LEN + TAG_LEN * 2 + 255;

// Protocol types (metadata byte 0).
const OPEN_SESSION_REQUEST: u8 = 2;
const OPEN_SESSION_RESPONSE: u8 = 3;
const CLOSE_SESSION_REQUEST: u8 = 4;
const CLOSE_SESSION_RESPONSE: u8 = 5;
const DATA_CLIENT_TO_SERVER: u8 = 6;
const DATA_SERVER_TO_CLIENT: u8 = 7;
const ACK_CLIENT_TO_SERVER: u8 = 8;
const ACK_SERVER_TO_CLIENT: u8 = 9;
const DATA_CLIENT_TO_SERVER_LOW_ENTROPY: u8 = 10;
const DATA_SERVER_TO_CLIENT_LOW_ENTROPY: u8 = 11;

/// How long the client waits for the peer's session reply. A wrong password
/// is answered with silence (the peer drains the connection), so this bounds
/// the dial instead of waiting for the kernel's own dial timeout.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// mieru `KeyIter`: part of the wire format (v2 used 4096).
const KEY_ITERATIONS: usize = 64;
/// mieru `KeyRefreshInterval`: the salt changes every two minutes.
const KEY_REFRESH_SECONDS: u64 = 120;

type HmacSha256 = Hmac<Sha256>;

/// PBKDF2-HMAC-SHA256, one 32-byte block (the only shape mieru uses).
fn pbkdf2_sha256(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let prf = |key: &[u8], message: &[u8]| -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key");
        mac.update(message);
        mac.finalize().into_bytes().into()
    };
    let mut first = Vec::with_capacity(salt.len() + 4);
    first.extend_from_slice(salt);
    first.extend_from_slice(&1u32.to_be_bytes());
    let mut u = prf(password, &first);
    let mut out = u;
    for _ in 1..KEY_ITERATIONS {
        u = prf(password, &u);
        for (a, b) in out.iter_mut().zip(u.iter()) {
            *a ^= *b;
        }
    }
    out
}

/// `hashedPassword = SHA256(password || 0x00 || username)`.
fn hash_password(password: &str, username: &str) -> [u8; 32] {
    let mut input = Vec::with_capacity(password.len() + 1 + username.len());
    input.extend_from_slice(password.as_bytes());
    input.push(0);
    input.extend_from_slice(username.as_bytes());
    Sha256::digest(&input).into()
}

/// `timeSalt`: `SHA256(BE64(unixSeconds))` of the time rounded to the nearest
/// two minutes. Go rounds half up and its zero time is a whole number of
/// two-minute spans before the epoch, so Unix rounding is identical.
fn time_salt(now: u64) -> [u8; 32] {
    let rounded = (now + KEY_REFRESH_SECONDS / 2) / KEY_REFRESH_SECONDS * KEY_REFRESH_SECONDS;
    Sha256::digest(rounded.to_be_bytes()).into()
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The key the client uses: the current (middle) of the three salts.
fn session_key(password: &str, username: &str) -> [u8; 32] {
    let hashed = hash_password(password, username);
    pbkdf2_sha256(&hashed, &time_salt(now_seconds()))
}

fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

/// One direction of an implicit-nonce cipher: the first operation uses the
/// generated (send) or received (recv) nonce, every later one increments it.
struct Direction {
    cipher: XChaCha20Poly1305,
    nonce: [u8; NONCE_LEN],
    ops: u64,
}

impl Direction {
    fn new(key: &[u8; 32], nonce: [u8; NONCE_LEN]) -> Direction {
        Direction {
            cipher: XChaCha20Poly1305::new_from_slice(key).expect("32-byte key"),
            nonce,
            ops: 0,
        }
    }

    fn next_nonce(&mut self) -> [u8; NONCE_LEN] {
        if self.ops > 0 {
            increment_nonce(&mut self.nonce);
        }
        self.ops += 1;
        self.nonce
    }

    fn seal(&mut self, out: &mut Vec<u8>, plain: &[u8], write_nonce: bool) {
        let nonce = self.next_nonce();
        if write_nonce {
            out.extend_from_slice(&nonce);
        }
        let sealed = self
            .cipher
            .encrypt(XNonce::from_slice(&nonce), plain)
            .expect("XChaCha20-Poly1305 encrypt");
        out.extend_from_slice(&sealed);
    }

    fn open(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = self.next_nonce();
        self.cipher
            .decrypt(XNonce::from_slice(&nonce), ciphertext)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mieru: AEAD open failed"))
    }
}

/// Send the first nonce next to the first segment of the direction.
struct Sender {
    direction: Direction,
    first: bool,
}

impl Sender {
    fn seal(&mut self, out: &mut Vec<u8>, plain: &[u8]) {
        let first = self.first;
        self.first = false;
        self.direction.seal(out, plain, first);
    }
}

struct Receiver {
    direction: Direction,
    first: bool,
}

impl Receiver {
    async fn read_segment<R: AsyncRead + Unpin>(&mut self, reader: &mut R) -> io::Result<Segment> {
        if self.first {
            let mut nonce = [0u8; NONCE_LEN];
            reader.read_exact(&mut nonce).await?;
            self.direction.nonce = nonce;
            self.first = false;
        }
        let mut sealed = [0u8; META_LEN + TAG_LEN];
        reader.read_exact(&mut sealed).await?;
        let meta = self.direction.open(&sealed)?;
        if meta.len() != META_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mieru: metadata is not 32 bytes",
            ));
        }
        let proto = meta[0];
        match proto {
            OPEN_SESSION_REQUEST
            | OPEN_SESSION_RESPONSE
            | CLOSE_SESSION_REQUEST
            | CLOSE_SESSION_RESPONSE => {
                let payload_len = u16::from_be_bytes([meta[15], meta[16]]) as usize;
                let suffix = meta[17] as usize;
                let payload = if payload_len > 0 {
                    let mut sealed = vec![0u8; payload_len + TAG_LEN];
                    reader.read_exact(&mut sealed).await?;
                    self.direction.open(&sealed)?
                } else {
                    Vec::new()
                };
                skip(reader, suffix).await?;
                Ok(Segment {
                    proto,
                    session_id: be32(&meta[6..10]),
                    status: meta[14],
                    payload,
                })
            }
            DATA_CLIENT_TO_SERVER
            | DATA_SERVER_TO_CLIENT
            | ACK_CLIENT_TO_SERVER
            | ACK_SERVER_TO_CLIENT => {
                let prefix = meta[21] as usize;
                let payload_len = u16::from_be_bytes([meta[22], meta[23]]) as usize;
                let suffix = meta[24] as usize;
                skip(reader, prefix).await?;
                let payload = if payload_len > 0 {
                    let mut sealed = vec![0u8; payload_len + TAG_LEN];
                    reader.read_exact(&mut sealed).await?;
                    self.direction.open(&sealed)?
                } else {
                    Vec::new()
                };
                skip(reader, suffix).await?;
                Ok(Segment {
                    proto,
                    session_id: be32(&meta[6..10]),
                    status: 0,
                    payload,
                })
            }
            DATA_CLIENT_TO_SERVER_LOW_ENTROPY | DATA_SERVER_TO_CLIENT_LOW_ENTROPY => {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mieru: low entropy payloads need traffic-pattern, which this kernel rejects",
                ))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("mieru: unknown protocol type {other}"),
            )),
        }
    }
}

async fn skip<R: AsyncRead + Unpin>(reader: &mut R, len: usize) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    let mut buffer = vec![0u8; len];
    reader.read_exact(&mut buffer).await?;
    Ok(())
}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

struct Segment {
    proto: u8,
    session_id: u32,
    status: u8,
    payload: Vec<u8>,
}

/// Plaintext bytes the read loop delivered and the caller has not read yet.
#[derive(Default)]
struct Inbox {
    bytes: Vec<u8>,
    delivered: usize,
}

/// Writer half shared by the stream and the read loop (the read loop only
/// answers close requests).
struct Shared {
    writer: tokio::sync::Mutex<SendHalf>,
    inbox: Mutex<Inbox>,
    closed: Mutex<Option<io::Result<()>>>,
    notify: Notify,
    /// A data segment is being written; the heartbeat must not interleave a
    /// frame inside it.
    pending_active: AtomicBool,
}

struct SendHalf {
    socket: tokio::io::WriteHalf<TcpStream>,
    sender: Sender,
    session_id: u32,
    seq: u32,
    recv_seq: u32,
}

impl SendHalf {
    fn session_meta(&self, proto: u8, seq: u32, status: u8, payload_len: usize) -> [u8; META_LEN] {
        let mut meta = [0u8; META_LEN];
        meta[0] = proto;
        meta[2..6].copy_from_slice(&((now_seconds() / 60) as u32).to_be_bytes());
        meta[6..10].copy_from_slice(&self.session_id.to_be_bytes());
        meta[10..14].copy_from_slice(&seq.to_be_bytes());
        meta[14] = status;
        meta[15..17].copy_from_slice(&(payload_len as u16).to_be_bytes());
        meta
    }

    fn data_meta(&self, seq: u32, payload_len: usize) -> [u8; META_LEN] {
        let mut meta = [0u8; META_LEN];
        meta[0] = DATA_CLIENT_TO_SERVER;
        meta[2..6].copy_from_slice(&((now_seconds() / 60) as u32).to_be_bytes());
        meta[6..10].copy_from_slice(&self.session_id.to_be_bytes());
        meta[10..14].copy_from_slice(&seq.to_be_bytes());
        meta[14..18].copy_from_slice(&self.recv_seq.to_be_bytes());
        // The receive window is reported in segments; the peer only reads it
        // on the packet transport, but a full window keeps the value honest.
        meta[18..20].copy_from_slice(&4096u16.to_be_bytes());
        meta[20] = 0;
        meta[22..24].copy_from_slice(&(payload_len as u16).to_be_bytes());
        meta
    }

    fn encode_session(&mut self, proto: u8, seq: u32, status: u8, payload: &[u8]) -> Vec<u8> {
        let meta = self.session_meta(proto, seq, status, payload.len());
        let mut out = Vec::with_capacity(NONCE_LEN + META_LEN + payload.len() + TAG_LEN * 2);
        self.sender.seal(&mut out, &meta);
        if !payload.is_empty() {
            self.sender.seal(&mut out, payload);
        }
        out
    }

    /// `ackClientToServer` heartbeat: the pinned client sends one after five
    /// seconds without writing, which is what keeps a session outside the
    /// server's injected `tcp-idle-timeout`. The sequence number is the last
    /// data sequence and is not advanced.
    fn encode_heartbeat(&mut self) -> Vec<u8> {
        let meta = self.data_meta(self.seq.wrapping_sub(1), 0);
        let mut meta = meta;
        meta[0] = ACK_CLIENT_TO_SERVER;
        let mut out = Vec::with_capacity(NONCE_LEN + META_LEN + TAG_LEN);
        self.sender.seal(&mut out, &meta);
        out
    }

    fn encode_data(&mut self, payload: &[u8]) -> Vec<u8> {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        let meta = self.data_meta(seq, payload.len());
        let mut out = Vec::with_capacity(NONCE_LEN + META_LEN + payload.len() + TAG_LEN * 2);
        self.sender.seal(&mut out, &meta);
        if !payload.is_empty() {
            self.sender.seal(&mut out, payload);
        }
        out
    }
}

/// Read loop: decode segments and hand payload bytes to the stream.
async fn read_loop(
    mut socket: tokio::io::ReadHalf<TcpStream>,
    shared: Arc<Shared>,
    mut receiver: Receiver,
    session_id: u32,
) {
    loop {
        match receiver.read_segment(&mut socket).await {
            Ok(segment) if segment.session_id != session_id => {
                // A single session per underlay: anything else is a peer
                // mistake for a session that is not ours; ignore it.
                continue;
            }
            Ok(segment) => match segment.proto {
                DATA_SERVER_TO_CLIENT => {
                    if !segment.payload.is_empty() {
                        let mut inbox = shared.inbox.lock().expect("mieru inbox");
                        if inbox.delivered == inbox.bytes.len() {
                            inbox.bytes.clear();
                            inbox.delivered = 0;
                        }
                        inbox.bytes.extend_from_slice(&segment.payload);
                    }
                    shared.notify.notify_waiters();
                }
                CLOSE_SESSION_REQUEST => {
                    let mut writer = shared.writer.lock().await;
                    let seq = writer.seq;
                    writer.seq = writer.seq.wrapping_add(1);
                    let bytes = writer.encode_session(CLOSE_SESSION_RESPONSE, seq, 0, &[]);
                    let _ = writer.socket.write_all(&bytes).await;
                    let _ = writer.socket.flush().await;
                    set_closed(&shared, Ok(()));
                    return;
                }
                CLOSE_SESSION_RESPONSE => {
                    set_closed(&shared, Ok(()));
                    return;
                }
                _ => {}
            },
            Err(error) => {
                let error = if error.kind() == io::ErrorKind::UnexpectedEof {
                    Ok(())
                } else {
                    Err(error)
                };
                set_closed(&shared, error);
                return;
            }
        }
    }
}

/// Send the periodic `ackClientToServer` heartbeat while the session is open.
async fn heartbeat(shared: Arc<Shared>) {
    loop {
        let jitter = Duration::from_millis(rand::thread_rng().next_u32() as u64 % 1000);
        tokio::time::sleep(Duration::from_secs(5) + jitter).await;
        if shared.closed.lock().expect("mieru closed").is_some() {
            return;
        }
        if shared.pending_active.load(Ordering::SeqCst) {
            continue;
        }
        let mut writer = shared.writer.lock().await;
        let bytes = writer.encode_heartbeat();
        // A peer that stopped reading must not hold the writer forever.
        let sent = tokio::time::timeout(Duration::from_secs(5), async {
            writer.socket.write_all(&bytes).await?;
            writer.socket.flush().await
        })
        .await;
        if !matches!(sent, Ok(Ok(()))) {
            return;
        }
    }
}

fn set_closed(shared: &Arc<Shared>, result: io::Result<()>) {
    let mut closed = shared.closed.lock().expect("mieru closed");
    if closed.is_none() {
        *closed = Some(result);
    }
    drop(closed);
    shared.notify.notify_waiters();
}

/// The proxy connection handed to the relay.
pub struct MieruStream {
    shared: Arc<Shared>,
    /// Encoded bytes accepted from the caller but not yet written.
    pending: Vec<u8>,
    pending_at: usize,
    shutdown_sent: bool,
    /// A close was already reported, so later reads return EOF instead of
    /// waiting forever.
    eof_returned: bool,
}

impl MieruStream {
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_at >= self.pending.len() {
            self.pending.clear();
            self.pending_at = 0;
            self.shared.pending_active.store(false, Ordering::SeqCst);
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
                        "mieru: peer closed the stream",
                    )))
                }
                Poll::Ready(Ok(n)) => self.pending_at += n,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending.clear();
        self.pending_at = 0;
        self.shared.pending_active.store(false, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MieruStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Flush the previously accepted segment first: the caller's new buffer
        // is only accepted when nothing is queued in front of it.
        match this.poll_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let len = buf.len().min(MAX_PAYLOAD);
        let shared = this.shared.clone();
        let mut writer = match shared.writer.try_lock() {
            Ok(writer) => writer,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        let bytes = writer.encode_data(&buf[..len]);
        drop(writer);
        if bytes.len() > MAX_SEGMENT {
            return Poll::Ready(Err(io::Error::other("mieru: segment exceeds its bound")));
        }
        this.pending = bytes;
        this.pending_at = 0;
        this.shared.pending_active.store(true, Ordering::SeqCst);
        // If the socket takes the bytes only partially, they stay queued; the
        // caller's buffer was consumed, so the write is reported as accepted.
        match this.poll_pending(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            _ => Poll::Ready(Ok(len)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_pending(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
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
        if !this.shutdown_sent {
            // The peer answers closeSessionResponse and closes its egress
            // connection; the socket itself stays open so the read loop can
            // still deliver what the peer sent before it saw the close.
            let shared = this.shared.clone();
            let mut writer = match shared.writer.try_lock() {
                Ok(writer) => writer,
                Err(_) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            };
            let seq = writer.seq;
            writer.seq = writer.seq.wrapping_add(1);
            this.pending = writer.encode_session(CLOSE_SESSION_REQUEST, seq, 0, &[]);
            this.pending_at = 0;
            drop(writer);
            match this.poll_pending(cx) {
                Poll::Ready(Ok(())) => this.shutdown_sent = true,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
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
}

impl AsyncRead for MieruStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // Register with the notifier before looking at the shared state:
            // `notify_waiters` stores no permit, so a notification between a
            // state check and the registration would otherwise be lost.
            let notified = this.shared.notify.notified();
            tokio::pin!(notified);
            let _ = std::future::Future::poll(notified.as_mut(), cx);
            {
                let mut inbox = this.shared.inbox.lock().expect("mieru inbox");
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
            if let Some(result) = this.shared.closed.lock().expect("mieru closed").take() {
                this.eof_returned = true;
                return Poll::Ready(result.map(|()| ()));
            }
            return Poll::Pending;
        }
    }
}

fn socks_request(target: &Target) -> Vec<u8> {
    let mut out = vec![5u8, 1, 0];
    out.extend_from_slice(&super::SocksAddr::encode(target));
    out
}

/// Parse the peer's SOCKS5 reply; returns the number of bytes it occupied.
fn parse_socks_reply(bytes: &[u8]) -> io::Result<Option<usize>> {
    if bytes.len() < 4 {
        return Ok(None);
    }
    if bytes[0] != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("mieru: SOCKS5 reply version {}", bytes[0]),
        ));
    }
    let len = match bytes[3] {
        1 => 10,
        4 => 22,
        3 => {
            if bytes.len() < 5 {
                return Ok(None);
            }
            5 + bytes[4] as usize + 2
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("mieru: SOCKS5 reply address type {other}"),
            ))
        }
    };
    if bytes.len() < len {
        return Ok(None);
    }
    if bytes[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("mieru: peer refused the request (SOCKS5 reply {})", bytes[1]),
        ));
    }
    Ok(Some(len))
}

async fn dial_port(option: &MieruOutbound, port: u16, target: &Target) -> Result<Dialed, DialError> {
    let socket = connect_tcp(&option.server, port).await?;
    let server = socket
        .peer_addr()
        .map_err(|e| handshake("mieru", e))?;
    let (mut read_half, write_half) = tokio::io::split(socket);
    let key = session_key(option.password.expose(), option.username.expose());
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    // The user hint: the last 4 nonce bytes are the first 4 bytes of
    // SHA256(username || nonce[..16]); it lets the peer find the user before
    // trying every key.
    let mut hint_input = Vec::with_capacity(option.username.expose().len() + 16);
    hint_input.extend_from_slice(option.username.expose().as_bytes());
    hint_input.extend_from_slice(&nonce[..16]);
    let hint = Sha256::digest(&hint_input);
    nonce[NONCE_LEN - 4..].copy_from_slice(&hint[..4]);

    let mut session_id = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut session_id);
    let mut session_id = u32::from_be_bytes(session_id);
    if session_id == 0 {
        session_id = 1;
    }

    let mut writer = SendHalf {
        socket: write_half,
        sender: Sender {
            direction: Direction::new(&key, nonce),
            first: true,
        },
        session_id,
        seq: 0,
        recv_seq: 0,
    };
    let request = socks_request(target);
    let open = writer.encode_session(OPEN_SESSION_REQUEST, 0, 0, &request);
    writer.seq = 1;
    writer
        .socket
        .write_all(&open)
        .await
        .map_err(|e| handshake("mieru", e))?;
    writer
        .socket
        .flush()
        .await
        .map_err(|e| handshake("mieru", e))?;

    let mut receiver = Receiver {
        direction: Direction::new(&key, [0u8; NONCE_LEN]),
        first: true,
    };
    let mut reply = Vec::new();
    let mut reply_len = None;
    // The peer answers a wrong password by staying silent (it drains the
    // connection for up to a minute to look like a dead endpoint), so the
    // client must bound the wait for the session reply itself.
    let read_reply: Result<(), DialError> = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let mut received = 0u32;
        while reply_len.is_none() {
            let segment = receiver
                .read_segment(&mut read_half)
                .await
                .map_err(|e| handshake("mieru", e))?;
            received = received.wrapping_add(1);
            match segment.proto {
                OPEN_SESSION_RESPONSE => {
                    if segment.session_id != session_id {
                        return Err(handshake(
                            "mieru",
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "mieru: open session response for another session",
                            ),
                        ));
                    }
                    if segment.status != 0 {
                        return Err(handshake(
                            "mieru",
                            io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                format!("mieru: peer status {}", segment.status),
                            ),
                        ));
                    }
                }
                DATA_SERVER_TO_CLIENT => {
                    reply.extend_from_slice(&segment.payload);
                    if let Some(len) = parse_socks_reply(&reply).map_err(|e| handshake("mieru", e))?
                    {
                        reply_len = Some(len);
                    }
                }
                CLOSE_SESSION_REQUEST | CLOSE_SESSION_RESPONSE => {
                    return Err(handshake(
                        "mieru",
                        io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            format!("mieru: peer closed the session (protocol {})", segment.proto),
                        ),
                    ))
                }
                _ => {}
            }
        }
        writer.recv_seq = received;
        Ok(())
    })
    .await
    .unwrap_or_else(|_| {
        Err(handshake(
            "mieru",
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("mieru: no session reply within {HANDSHAKE_TIMEOUT:?}"),
            ),
        ))
    });
    read_reply?;

    let consumed = reply_len.expect("reply length is set");
    let leftover = reply.split_off(consumed);
    let shared = Arc::new(Shared {
        writer: tokio::sync::Mutex::new(writer),
        inbox: Mutex::new(Inbox {
            bytes: leftover,
            delivered: 0,
        }),
        closed: Mutex::new(None),
        notify: Notify::new(),
        pending_active: AtomicBool::new(false),
    });
    let stream = MieruStream {
        shared: shared.clone(),
        pending: Vec::new(),
        pending_at: 0,
        shutdown_sent: false,
        eof_returned: false,
    };
    tokio::spawn(read_loop(read_half, Arc::clone(&shared), receiver, session_id));
    tokio::spawn(heartbeat(shared));
    Ok(Dialed {
        stream: Box::new(stream) as BoxStream,
        server,
    })
}

/// Ports to try for one dial: the single `port`, every member of a small
/// `port-range`, or four random members of a larger one (a range is a
/// server-side rotation, so any member is a valid endpoint). Each candidate
/// gets the same bounded session reply wait, so a range never stalls a dial
/// for many multiples of that bound.
fn candidate_ports(option: &MieruOutbound) -> Vec<u16> {
    if let Some(port) = option.port {
        return vec![port];
    }
    let Some((first, last)) = option.port_range else {
        return Vec::new();
    };
    let span = u32::from(last) - u32::from(first) + 1;
    if span <= 4 {
        return (u32::from(first)..=u32::from(last)).map(|port| port as u16).collect();
    }
    let mut picks = Vec::new();
    for _ in 0..4 {
        let offset = rand::thread_rng().next_u32() % span;
        let port = (u32::from(first) + offset) as u16;
        if !picks.contains(&port) {
            picks.push(port);
        }
    }
    picks
}

pub async fn dial(option: &MieruOutbound, target: &Target) -> Result<Dialed, DialError> {
    if option.transport != MieruTransport::Tcp {
        return Err(DialError::Chain(
            "mieru: only the TCP transport is implemented (transport: UDP is rejected at load)".into(),
        ));
    }
    let ports = candidate_ports(option);
    if ports.is_empty() {
        return Err(DialError::Chain("mieru: no port or port-range".into()));
    }
    let mut last: Option<DialError> = None;
    for port in ports {
        match dial_port(option, port, target).await {
            Ok(dialed) => return Ok(dialed),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| DialError::Chain("mieru: no candidate port".into())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors printed by Python's `hashlib` (PBKDF2-HMAC-SHA256) for the
    /// inputs mieru derives: the hashed password is
    /// `SHA256("secret123" 0x00 "alice")` and the salt is
    /// `SHA256(BE64(1749999960))` (the two-minute rounding of 1750000000).
    #[test]
    fn key_derivation_matches_the_pinned_protocol() {
        let hashed = hash_password("secret123", "alice");
        assert_eq!(
            hex(&hashed),
            "81a3876e94d50e07349ac35cef40e56ccc788c9ad7332bfe787274a7290bcd37"
        );
        let salt = time_salt(1_750_000_000);
        assert_eq!(
            hex(&salt),
            "3b6e478d36fbb680ae70f60d83074e506e5d87fc726fa8d6254a8664a445b8b2"
        );
        assert_eq!(
            hex(&pbkdf2_sha256(&hashed, &salt)),
            "e3432a1cd3db257761610aee3fb2f4b5986363edc597c792692126cffa9679c4"
        );
    }

    #[test]
    fn time_salt_rounds_to_the_nearest_two_minutes() {
        // Go's `Time.Round` rounds half away from zero and its zero time is a
        // whole number of two-minute spans before the epoch.
        assert_eq!(time_salt(1_750_000_000), time_salt(1_749_999_960));
        assert_eq!(time_salt(1_750_000_019), time_salt(1_749_999_960));
        // 1_750_000_080 is itself a multiple of two minutes.
        assert_ne!(time_salt(1_750_000_080), time_salt(1_750_000_000));
        assert_eq!(time_salt(1_750_000_060), time_salt(1_750_000_080));
    }

    #[test]
    fn the_nonce_is_a_big_endian_counter() {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[NONCE_LEN - 1] = 0xff;
        increment_nonce(&mut nonce);
        assert_eq!(nonce[NONCE_LEN - 1], 0);
        assert_eq!(nonce[NONCE_LEN - 2], 1);
        let mut all = [0xffu8; NONCE_LEN];
        increment_nonce(&mut all);
        assert_eq!(all, [0u8; NONCE_LEN]);
    }

    #[test]
    fn the_implicit_nonce_is_written_once_per_direction() {
        let key = [7u8; 32];
        let mut sender = Sender {
            direction: Direction::new(&key, [9u8; NONCE_LEN]),
            first: true,
        };
        let mut first = Vec::new();
        sender.seal(&mut first, b"metadata");
        // nonce (24) + sealed metadata (len + tag)
        assert_eq!(first.len(), NONCE_LEN + 8 + TAG_LEN);
        assert_eq!(&first[..NONCE_LEN], &[9u8; NONCE_LEN]);
        let mut second = Vec::new();
        sender.seal(&mut second, b"payload");
        assert_eq!(second.len(), 7 + TAG_LEN, "the nonce is not repeated");
        assert_eq!(sender.direction.nonce[NONCE_LEN - 1], 10);
    }

    fn outbound(port: Option<u16>, range: Option<(u16, u16)>) -> MieruOutbound {
        MieruOutbound {
            server: "127.0.0.1".to_string(),
            port,
            port_range: range,
            transport: MieruTransport::Tcp,
            username: crate::keys::Secret::new("u"),
            password: crate::keys::Secret::new("p"),
            dialer_proxy: None,
        }
    }

    #[test]
    fn candidate_ports_cover_small_ranges_and_bound_large_ones() {
        assert_eq!(candidate_ports(&outbound(Some(2999), None)), vec![2999]);
        assert_eq!(
            candidate_ports(&outbound(None, Some((2090, 2093)))),
            vec![2090, 2091, 2092, 2093]
        );
        let picks = candidate_ports(&outbound(None, Some((20000, 21000))));
        assert!(!picks.is_empty() && picks.len() <= 4);
        assert!(picks.iter().all(|port| (20000..=21000).contains(port)));
        assert!(candidate_ports(&outbound(None, None)).is_empty());
    }

    #[test]
    fn a_socks_reply_is_parsed_for_every_address_type() {
        let ipv4 = [5u8, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90];
        assert_eq!(parse_socks_reply(&ipv4).unwrap(), Some(10));
        let mut ipv6 = vec![5u8, 0, 0, 4];
        ipv6.extend_from_slice(&[0u8; 16]);
        ipv6.extend_from_slice(&[0, 80]);
        assert_eq!(parse_socks_reply(&ipv6).unwrap(), Some(22));
        let mut fqdn = vec![5u8, 0, 0, 3, 3];
        fqdn.extend_from_slice(b"api");
        fqdn.extend_from_slice(&[1, 187]);
        assert_eq!(parse_socks_reply(&fqdn).unwrap(), Some(10));
        assert_eq!(parse_socks_reply(&ipv4[..4]).unwrap(), None);
        let refused = parse_socks_reply(&[5u8, 5, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
