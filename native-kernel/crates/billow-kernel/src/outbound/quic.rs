//! QUIC transport shared by the T10 families (`hysteria`, `hysteria2`, `tuic`,
//! `shadowquic`).
//!
//! `quinn` 0.11 is the QUIC implementation. It is configured from the same
//! `ClientTls` roots and `TlsSettings` as the TCP/TLS outbounds, but a QUIC
//! handshake always uses TLS 1.3 and a non-empty ALPN list. One endpoint (UDP
//! socket) and one connection are created per dial: the pinned clients pool
//! connections, which changes performance and port-hopping behaviour but not
//! the wire protocol, so a pooled client is a later optimisation recorded in
//! `tool/kernel-compat/evidence/rust-mapping.json` rather than a compatibility
//! claim.
//!
//! A bidirectional QUIC stream is exposed as the kernel's normal
//! `AsyncRead + AsyncWrite` stream. The wrapper keeps the `Connection` and
//! `Endpoint` alive for as long as the stream is used.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use quinn::congestion::{Controller, ControllerFactory};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{
    AsyncUdpSocket, ClientConfig, Connection, Endpoint, RecvStream, SendStream, TransportConfig,
    UdpPoller, VarInt,
};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::tls::{self, ClientTls};
use super::DialError;
use crate::proxies::TlsSettings;

/// A bidirectional QUIC stream plus the handles that keep its connection and
/// UDP endpoint alive. Dropping the wrapper closes the connection.
pub struct QuicStream {
    send: SendStream,
    recv: RecvStream,
    connection: Connection,
    endpoint: Endpoint,
    /// Streams that must stay open while this session is used (HTTP/3 control
    /// and QPACK streams for Hysteria2).
    hold: Vec<SendStream>,
}

impl QuicStream {
    pub fn new(
        send: SendStream,
        recv: RecvStream,
        connection: Connection,
        endpoint: Endpoint,
    ) -> QuicStream {
        QuicStream::with_hold(send, recv, connection, endpoint, Vec::new())
    }

    pub fn with_hold(
        send: SendStream,
        recv: RecvStream,
        connection: Connection,
        endpoint: Endpoint,
        hold: Vec<SendStream>,
    ) -> QuicStream {
        QuicStream {
            send,
            recv,
            connection,
            endpoint,
            hold,
        }
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Split into the send/receive halves while keeping the connection alive in
    /// both halves (used by UDP associations).
    pub fn into_halves(
        self,
    ) -> (
        SendStream,
        RecvStream,
        Connection,
        Endpoint,
        Vec<SendStream>,
    ) {
        (
            self.send,
            self.recv,
            self.connection,
            self.endpoint,
            self.hold,
        )
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map(|result| result.map_err(|e| io::Error::other(e.to_string())))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // quinn flushes on every write; there is no separate flush state.
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // `finish` sends the QUIC FIN; the connection stays alive for the
        // peer's response and the wrapper's other direction.
        std::pin::Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

/// QUIC congestion controller selected by a family's `congestion-controller`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionController {
    /// Keep quinn's default (CUBIC).
    #[default]
    Default,
    Cubic,
    NewReno,
    Bbr,
}

/// Knobs a family sets on the QUIC handshake. The pinned clients differ in
/// keep-alive, idle timeout and datagram buffers; only values that change the
/// handshake/transport behaviour are carried here.
#[derive(Debug, Clone)]
pub struct QuicOptions {
    /// ALPN protocols; a QUIC handshake requires at least one.
    pub alpn: Vec<String>,
    /// QUIC idle timeout; `None` keeps quinn's default (30 s).
    pub max_idle_timeout: Option<Duration>,
    /// Keep-alive interval; `None` disables keep-alive.
    pub keep_alive: Option<Duration>,
    /// Advertise and buffer QUIC datagrams (TUIC native UDP, hysteria UDP).
    pub datagrams: bool,
    /// `disable-sni`: send no SNI and accept any certificate (TUIC).
    pub disable_sni: bool,
    /// Per-stream receive window (local flow control, not a wire format).
    pub stream_receive_window: u32,
    /// Per-connection receive window (local flow control).
    pub connection_receive_window: u32,
    /// Send window (local flow control).
    pub send_window: u32,
    /// Inbound stream limits; `None` keeps quinn's defaults.
    pub max_concurrent_uni_streams: Option<u64>,
    pub max_concurrent_bidi_streams: Option<u64>,
    /// DPLPMTUD on/off (`disable-mtu-discovery: true` turns it off).
    pub mtu_discovery: bool,
    /// QUIC datagram buffers when `datagrams` is set.
    pub datagram_receive_buffer: Option<usize>,
    pub datagram_send_buffer: Option<usize>,
    /// Congestion controller (hysteria2 always selects BBR, as the pinned
    /// client does).
    pub congestion_controller: CongestionController,
    /// Initial congestion window in bytes.
    pub initial_congestion_window: Option<u64>,
    /// Hysteria2 `up`: the Brutal sender's TX rate in bytes/second. When set,
    /// the Brutal controller replaces the family's BBR (the pinned client
    /// selects Brutal after authentication).
    pub brutal_bps: Option<u64>,
    /// Hysteria2 `bbr-profile`: `conservative`/`standard`/`aggressive`.
    /// quinn's BBR has no profile selector, so the profile is mapped to the
    /// initial window (a documented approximation, not wire-visible) and takes
    /// precedence over `initial_congestion_window` (`cwnd`).
    pub bbr_profile: Option<BbrProfile>,
    /// Hysteria2 `udp-mtu`: the Hysteria UDP session payload MTU. quinn has no
    /// Hysteria UDP session, so it is applied to the QUIC initial path MTU as
    /// `udp-mtu + 3` (the pinned default 1197 comes from 1200 - 3).
    pub udp_mtu: Option<u16>,
    /// Hysteria2 `obfs`: Salamander's BLAKE2b-256 salt/XOR, and Gecko's
    /// long-header fragmentation on top, applied at the UDP socket boundary.
    pub obfs: Option<Obfs>,
    /// Hysteria2 `ports`/`hop-interval`: destination-port hopping.
    pub hop: Option<HopConfig>,
}

impl QuicOptions {
    pub fn new(alpn: Vec<String>) -> QuicOptions {
        QuicOptions {
            alpn,
            max_idle_timeout: Some(Duration::from_secs(30)),
            keep_alive: None,
            datagrams: false,
            disable_sni: false,
            stream_receive_window: 512 * 1024,
            connection_receive_window: 2 * 1024 * 1024,
            send_window: 2 * 1024 * 1024,
            max_concurrent_uni_streams: None,
            max_concurrent_bidi_streams: None,
            mtu_discovery: true,
            datagram_receive_buffer: None,
            datagram_send_buffer: None,
            congestion_controller: CongestionController::Default,
            initial_congestion_window: None,
            brutal_bps: None,
            bbr_profile: None,
            udp_mtu: None,
            obfs: None,
            hop: None,
        }
    }
}

/// The pinned `bbr-profile` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbrProfile {
    Conservative,
    Standard,
    Aggressive,
}

impl BbrProfile {
    /// Parse the pinned values. Empty is the pinned default and is not a
    /// profile (the caller keeps the default BBR).
    pub fn parse(value: &str) -> Option<BbrProfile> {
        match value {
            "conservative" => Some(BbrProfile::Conservative),
            "standard" => Some(BbrProfile::Standard),
            "aggressive" => Some(BbrProfile::Aggressive),
            _ => None,
        }
    }

    /// The profile's approximation as the BBR initial window in packets. The
    /// pinned sender keeps the initial window at `cwnd` (default 32) and
    /// changes the startup/drain gains instead; quinn exposes only the window,
    /// so the profile is written here and takes precedence over `cwnd`.
    pub fn initial_window_packets(self) -> u64 {
        match self {
            BbrProfile::Conservative => 24,
            BbrProfile::Standard => 32,
            BbrProfile::Aggressive => 40,
        }
    }

    pub fn initial_window(self) -> u64 {
        self.initial_window_packets() * 1200
    }
}

/// The congestion window a BBR transport starts with. A `bbr-profile` maps to
/// its packet count (documented approximation); otherwise the hysteria2 `cwnd`
/// value passes through.
pub fn bbr_initial_window(options: &QuicOptions) -> Option<u64> {
    options
        .bbr_profile
        .map(BbrProfile::initial_window)
        .or(options.initial_congestion_window)
}

/// Hysteria2 Salamander obfuscation (`sing-quic/hysteria2/salamander.go`):
/// `salt[8] || packet XOR BLAKE2b-256(password || salt)`.
#[derive(Clone)]
pub struct Salamander {
    pub password: Vec<u8>,
}

impl std::fmt::Debug for Salamander {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Salamander").finish_non_exhaustive()
    }
}

/// The Hysteria2 packet obfuscators. Gecko is Salamander plus fragmentation of
/// every long-header packet (pinned `NewGeckoConn` wraps `NewSalamanderConn`).
#[derive(Clone)]
pub enum Obfs {
    Salamander(Salamander),
    Gecko(Gecko),
}

impl std::fmt::Debug for Obfs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Obfs::Salamander(salamander) => f.debug_tuple("Salamander").field(salamander).finish(),
            Obfs::Gecko(gecko) => f.debug_tuple("Gecko").field(gecko).finish(),
        }
    }
}

const GECKO_FRAGMENT_FLAG: u8 = 0x80;
const GECKO_HEADER_LEN: usize = 5;
const GECKO_MIN_CHUNKS: usize = 2;
const GECKO_MAX_CHUNKS: usize = 8;
const GECKO_DEFAULT_MIN_PACKET_SIZE: usize = 512;
const GECKO_DEFAULT_MAX_PACKET_SIZE: usize = 1200;
const GECKO_REASSEMBLY_TTL: Duration = Duration::from_secs(8);
const GECKO_MAX_REASSEMBLY: usize = 4096;
const GECKO_MAX_PER_SOURCE: usize = 8;
const SALAMANDER_SALT_LEN: usize = 8;

/// Hysteria2 Gecko obfuscation (`sing-quic/hysteria2/gecko.go`): Salamander on
/// every datagram, and every packet whose first byte is a QUIC long header is
/// split into 2..8 padded chunks:
///
/// ```text
/// 0x80 | message id | (chunk index << 4 | total chunks) | pad length (u16) | pad | chunk
/// ```
///
/// The whole frame is then Salamander-obfuscated, so each fragment carries its
/// own 8-byte salt. Replies are reassembled with the pinned TTL, per-source and
/// global caps.
#[derive(Clone)]
pub struct Gecko {
    password: Vec<u8>,
    min_packet_size: usize,
    max_packet_size: usize,
    state: Arc<Mutex<GeckoState>>,
}

impl std::fmt::Debug for Gecko {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gecko")
            .field("min_packet_size", &self.min_packet_size)
            .field("max_packet_size", &self.max_packet_size)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct GeckoState {
    msg_id: u32,
    reassembly: HashMap<(SocketAddr, u8), GeckoEntry>,
    per_source: HashMap<SocketAddr, usize>,
    last_sweep: Option<Instant>,
}

struct GeckoEntry {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    total: u8,
    deadline: Instant,
}

impl Gecko {
    /// `min`/`max` are the pinned packet sizes; zero selects the pinned
    /// defaults. The caller validates the range when the block is parsed.
    pub fn new(password: Vec<u8>, min_packet_size: usize, max_packet_size: usize) -> Gecko {
        Gecko {
            password,
            min_packet_size: if min_packet_size == 0 {
                GECKO_DEFAULT_MIN_PACKET_SIZE
            } else {
                min_packet_size
            },
            max_packet_size: if max_packet_size == 0 {
                GECKO_DEFAULT_MAX_PACKET_SIZE
            } else {
                max_packet_size
            },
            state: Arc::new(Mutex::new(GeckoState::default())),
        }
    }

    fn random_pad_len(&self, chunk_len: usize) -> usize {
        let base = SALAMANDER_SALT_LEN + GECKO_HEADER_LEN + chunk_len;
        let low = self.min_packet_size.max(base);
        if low > self.max_packet_size {
            return 0;
        }
        low - base + (rand::random::<u32>() as usize) % (self.max_packet_size - low + 1)
    }

    /// One on-wire datagram per QUIC segment. A short-header packet is only
    /// Salamander-obfuscated; a long-header packet is fragmented first.
    fn frames(&self, packet: &[u8]) -> Vec<Vec<u8>> {
        if packet.is_empty() {
            return Vec::new();
        }
        if packet[0] & GECKO_FRAGMENT_FLAG == 0 {
            return vec![salamander_frame(&self.password, packet)];
        }
        let chunks = GECKO_MIN_CHUNKS
            + (rand::random::<u32>() as usize) % (GECKO_MAX_CHUNKS - GECKO_MIN_CHUNKS + 1);
        let chunk_size = packet.len() / chunks;
        if chunk_size == 0 {
            return vec![salamander_frame(&self.password, packet)];
        }
        let msg_id = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let id = state.msg_id.wrapping_add(1);
            state.msg_id = id;
            (id & 0xff) as u8
        };
        let mut frames = Vec::with_capacity(chunks);
        for index in 0..chunks {
            let start = index * chunk_size;
            let end = if index < chunks - 1 {
                start + chunk_size
            } else {
                packet.len()
            };
            let chunk = &packet[start..end];
            let pad_len = self.random_pad_len(chunk.len());
            let mut frame = Vec::with_capacity(GECKO_HEADER_LEN + pad_len + chunk.len());
            frame.push(GECKO_FRAGMENT_FLAG);
            frame.push(msg_id);
            frame.push(((index as u8) << 4) | (chunks as u8 & 0x0f));
            frame.extend_from_slice(&(pad_len as u16).to_be_bytes());
            if pad_len > 0 {
                let mut pad = vec![0u8; pad_len];
                rand::thread_rng().fill_bytes(&mut pad);
                frame.extend_from_slice(&pad);
            }
            frame.extend_from_slice(chunk);
            frames.push(salamander_frame(&self.password, &frame));
        }
        frames
    }

    /// Feed one de-Salamandered datagram. `Some(message)` once the last chunk
    /// of a message is present; `None` when it was buffered.
    fn accept(&self, from: SocketAddr, body: &[u8]) -> Option<Vec<u8>> {
        if body.len() < GECKO_HEADER_LEN {
            return None;
        }
        if body[0] & GECKO_FRAGMENT_FLAG == 0 {
            return Some(body.to_vec());
        }
        let msg_id = body[1];
        let chunk_index = body[2] >> 4;
        let total = body[2] & 0x0f;
        let pad_len = usize::from(u16::from_be_bytes([body[3], body[4]]));
        if !(GECKO_MIN_CHUNKS as u8..=GECKO_MAX_CHUNKS as u8).contains(&total)
            || chunk_index >= total
        {
            return None;
        }
        let payload_start = GECKO_HEADER_LEN + pad_len;
        if payload_start > body.len() {
            return None;
        }
        let payload = &body[payload_start..];

        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state
            .last_sweep
            .map(|last| now.duration_since(last) >= GECKO_REASSEMBLY_TTL / 2)
            .unwrap_or(true)
        {
            sweep_expired(&mut state, now);
        }
        let key = (from, msg_id);
        if !state.reassembly.contains_key(&key) {
            if state.per_source.get(&from).copied().unwrap_or(0) >= GECKO_MAX_PER_SOURCE {
                return None;
            }
            if state.reassembly.len() >= GECKO_MAX_REASSEMBLY {
                evict_oldest(&mut state);
            }
            state.reassembly.insert(
                key,
                GeckoEntry {
                    chunks: vec![None; usize::from(total)],
                    received: 0,
                    total,
                    deadline: now + GECKO_REASSEMBLY_TTL,
                },
            );
            *state.per_source.entry(from).or_insert(0) += 1;
        }
        let entry = state.reassembly.get_mut(&key)?;
        if entry.total != total {
            return None;
        }
        let slot = entry.chunks.get_mut(usize::from(chunk_index))?;
        if slot.is_some() {
            return None;
        }
        *slot = Some(payload.to_vec());
        entry.received += 1;
        if entry.received < usize::from(entry.total) {
            return None;
        }
        let entry = state.reassembly.remove(&key)?;
        drop_entry_source(&mut state, from);
        let mut out = Vec::new();
        for chunk in entry.chunks {
            out.extend_from_slice(&chunk?);
        }
        Some(out)
    }
}

fn sweep_expired(state: &mut GeckoState, now: Instant) {
    let expired: Vec<(SocketAddr, u8)> = state
        .reassembly
        .iter()
        .filter(|(_, entry)| now > entry.deadline)
        .map(|(key, _)| *key)
        .collect();
    for key in expired {
        if state.reassembly.remove(&key).is_some() {
            drop_entry_source(state, key.0);
        }
    }
    state.last_sweep = Some(now);
}

fn evict_oldest(state: &mut GeckoState) {
    let oldest = state
        .reassembly
        .iter()
        .min_by_key(|(_, entry)| entry.deadline)
        .map(|(key, _)| *key);
    if let Some(key) = oldest {
        if state.reassembly.remove(&key).is_some() {
            drop_entry_source(state, key.0);
        }
    }
}

fn drop_entry_source(state: &mut GeckoState, from: SocketAddr) {
    if let Some(count) = state.per_source.get_mut(&from) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            state.per_source.remove(&from);
        }
    }
}

/// `salt[8] || packet XOR BLAKE2b-256(password || salt)`.
fn salamander_frame(password: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; SALAMANDER_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(password);
    hasher.update(salt);
    let key = hasher.finalize();
    let mut out = Vec::with_capacity(SALAMANDER_SALT_LEN + plain.len());
    out.extend_from_slice(&salt);
    for (index, byte) in plain.iter().enumerate() {
        out.push(byte ^ key[index % key.len()]);
    }
    out
}

/// Strip one Salamander salt in place; returns the plain length.
fn salamander_unframe(password: &[u8], buffer: &mut [u8]) -> usize {
    if buffer.len() <= SALAMANDER_SALT_LEN {
        return 0;
    }
    let salt: [u8; SALAMANDER_SALT_LEN] = buffer[..SALAMANDER_SALT_LEN]
        .try_into()
        .expect("salt slice");
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(password);
    hasher.update(salt);
    let key = hasher.finalize();
    let len = buffer.len() - SALAMANDER_SALT_LEN;
    for index in 0..len {
        buffer[index] = buffer[SALAMANDER_SALT_LEN + index] ^ key[index % key.len()];
    }
    len
}

/// Hysteria2 port hopping: every `interval` the next datagram is sent to a
/// random port from `ports`. Replies from that port are mapped back to the
/// configured base address so quinn (which drops packets from an unrecognised
/// remote address for client connections) keeps the single connection alive.
#[derive(Clone, Debug)]
pub struct HopConfig {
    pub ports: Vec<u16>,
    pub interval: Duration,
    pub interval_max: Duration,
}

impl HopConfig {
    fn next_interval(&self) -> Duration {
        if self.interval_max <= self.interval {
            return self.interval;
        }
        let spread = (self.interval_max - self.interval).as_millis() as u64;
        let extra = if spread == 0 {
            0
        } else {
            rand::random::<u64>() % (spread + 1)
        };
        self.interval + Duration::from_millis(extra)
    }
}

#[derive(Debug)]
struct HopState {
    port: AtomicU16,
}

impl HopState {
    fn next(&self, ports: &[u16]) {
        if ports.is_empty() {
            return;
        }
        let index = (rand::random::<u32>() as usize) % ports.len();
        self.port.store(ports[index], Ordering::Relaxed);
    }
}

/// A UDP socket wrapper that applies the Hysteria2 obfuscator and port hop
/// before/after the runtime socket. The layer is transparent to quinn's
/// connection state: hopping only rewrites the destination port, and replies
/// are reported from the configured base address.
struct LayeredSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    base: SocketAddr,
    obfs: Option<Obfs>,
    hop: Option<Arc<HopState>>,
}

impl std::fmt::Debug for LayeredSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LayeredSocket")
            .field("base", &self.base)
            .field("obfs", &self.obfs.is_some())
            .field("hop", &self.hop.is_some())
            .finish()
    }
}

impl LayeredSocket {
    fn destination(&self, original: SocketAddr) -> SocketAddr {
        match &self.hop {
            Some(hop) => SocketAddr::new(original.ip(), hop.port.load(Ordering::Relaxed)),
            None => original,
        }
    }

    fn salamander(&self) -> Option<&Salamander> {
        match &self.obfs {
            Some(Obfs::Salamander(salamander)) => Some(salamander),
            _ => None,
        }
    }

    /// One datagram (or each GRO segment) gets an independent salt.
    fn obfuscate(&self, contents: &[u8], segment_size: Option<usize>) -> (Vec<u8>, Option<usize>) {
        let Some(obfs) = self.salamander() else {
            return (contents.to_vec(), segment_size);
        };
        let stride = segment_size.unwrap_or(contents.len());
        if stride == 0 {
            return (Vec::new(), segment_size);
        }
        let segments = contents.len().div_ceil(stride);
        let mut out = Vec::with_capacity(contents.len() + segments * 8);
        let mut offset = 0;
        while offset < contents.len() {
            let end = (offset + stride).min(contents.len());
            let mut salt = [0u8; 8];
            rand::thread_rng().fill_bytes(&mut salt);
            let mut hasher = Blake2b::<U32>::new();
            hasher.update(&obfs.password);
            hasher.update(&salt);
            let key = hasher.finalize();
            out.extend_from_slice(&salt);
            for (index, byte) in contents[offset..end].iter().enumerate() {
                out.push(byte ^ key[index % key.len()]);
            }
            offset = end;
        }
        (out, segment_size.map(|size| size + 8))
    }

    /// Remove one salt per GRO segment in place and compact the buffer.
    fn deobfuscate(&self, buffer: &mut [u8], meta: &mut RecvMeta) {
        let Some(obfs) = self.salamander() else {
            return;
        };
        let stride = if meta.stride == 0 {
            meta.len
        } else {
            meta.stride
        };
        if stride == 0 {
            return;
        }
        let mut read = 0usize;
        let mut write = 0usize;
        while read < meta.len {
            let end = (read + stride).min(meta.len);
            if end - read > 8 {
                let salt: [u8; 8] = buffer[read..read + 8].try_into().expect("salt slice");
                let mut hasher = Blake2b::<U32>::new();
                hasher.update(&obfs.password);
                hasher.update(&salt);
                let key = hasher.finalize();
                for index in 0..end - read - 8 {
                    buffer[write + index] = buffer[read + 8 + index] ^ key[index % key.len()];
                }
                write += end - read - 8;
            }
            read = end;
        }
        meta.len = write;
        meta.stride = stride.saturating_sub(8).max(1);
    }

    /// Gecko reads may consume several fragments before one message is
    /// complete. The inner poll is invoked with a single buffer (see
    /// `max_receive_segments`), so a reassembled message never needs to
    /// straddle quinn's receive array.
    fn poll_recv_gecko(
        &self,
        gecko: &Gecko,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            let read = {
                let mut single_bufs = [io::IoSliceMut::new(&mut bufs[0])];
                let mut single_meta = [RecvMeta::default()];
                match self.inner.poll_recv(cx, &mut single_bufs, &mut single_meta) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(0)) => continue,
                    Poll::Ready(Ok(_)) => {
                        meta[0] = single_meta[0];
                        meta[0].len
                    }
                }
            };
            let from = meta[0].addr;
            let plain_len = {
                let buffer = &mut bufs[0][..read];
                salamander_unframe(&gecko.password, buffer)
            };
            let message = {
                let buffer = &bufs[0][..plain_len];
                gecko.accept(from, buffer)
            };
            let Some(message) = message else {
                continue;
            };
            if message.len() > bufs[0].len() {
                // A reassembled message too large for quinn's buffer is
                // dropped, exactly like a truncated inner read.
                continue;
            }
            bufs[0][..message.len()].copy_from_slice(&message);
            meta[0].len = message.len();
            meta[0].stride = message.len();
            if self.hop.is_some() {
                meta[0].addr = self.base;
            }
            return Poll::Ready(Ok(1));
        }
    }
}

impl AsyncUdpSocket for LayeredSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let destination = self.destination(transmit.destination);
        if let Some(Obfs::Gecko(gecko)) = &self.obfs {
            let stride = transmit.segment_size.unwrap_or(transmit.contents.len());
            if stride == 0 {
                return Ok(());
            }
            for segment in transmit.contents.chunks(stride) {
                for frame in gecko.frames(segment) {
                    let transmit = Transmit {
                        destination,
                        ecn: transmit.ecn,
                        contents: &frame,
                        segment_size: None,
                        src_ip: transmit.src_ip,
                    };
                    self.inner.try_send(&transmit)?;
                }
            }
            return Ok(());
        }
        if self.obfs.is_none() {
            let transmit = Transmit {
                destination,
                ..*transmit
            };
            return self.inner.try_send(&transmit);
        }
        let (contents, segment_size) = self.obfuscate(transmit.contents, transmit.segment_size);
        let transmit = Transmit {
            destination,
            ecn: transmit.ecn,
            contents: &contents,
            segment_size,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if let Some(Obfs::Gecko(gecko)) = &self.obfs {
            return self.poll_recv_gecko(gecko, cx, bufs, meta);
        }
        match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(count)) => {
                for index in 0..count.min(bufs.len()).min(meta.len()) {
                    let buffer = &mut bufs[index];
                    let buffer = &mut buffer[..meta[index].len];
                    self.deobfuscate(buffer, &mut meta[index]);
                    if self.hop.is_some() {
                        meta[index].addr = self.base;
                    }
                }
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        if matches!(self.obfs, Some(Obfs::Gecko(_))) {
            1
        } else {
            self.inner.max_receive_segments()
        }
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// Brutal: the pinned Hysteria2 sender's congestion window. quinn exposes the
/// window but no pacing hook, so the TX rate is enforced through the window
/// (`bps * smoothed_rtt * 2 / ack_rate`) while the ACK-rate adjustment follows
/// `transport/hysteria2/congestion/brutal.go`. Without a BBR profile or an
/// initial RTT the 10 KiB initial window is exactly the pinned value.
#[derive(Debug, Clone)]
struct Brutal {
    bps: f64,
    max_datagram_size: u64,
    smoothed_rtt: Option<Duration>,
    ack_rate: f64,
    slots: [(i64, u64, u64); 5],
    epoch: std::time::Instant,
}

impl Brutal {
    fn new(bps: u64, mtu: u16, epoch: std::time::Instant) -> Brutal {
        Brutal {
            bps: bps as f64,
            max_datagram_size: u64::from(mtu.max(1200)),
            smoothed_rtt: None,
            ack_rate: 1.0,
            slots: [(0, 0, 0); 5],
            epoch,
        }
    }

    fn record(&mut self, now: std::time::Instant, acked: u64, lost: u64) {
        let second = now.saturating_duration_since(self.epoch).as_secs() as i64;
        let slot = (second % 5) as usize;
        if self.slots[slot].0 == second {
            self.slots[slot].1 += acked;
            self.slots[slot].2 += lost;
        } else {
            self.slots[slot] = (second, acked, lost);
        }
        let min = second - 4;
        let (mut ack, mut loss) = (0u64, 0u64);
        for (timestamp, ack_count, loss_count) in self.slots {
            if timestamp >= min {
                ack += ack_count;
                loss += loss_count;
            }
        }
        if ack + loss >= 50 {
            let rate = ack as f64 / (ack + loss) as f64;
            self.ack_rate = rate.max(0.8);
        } else {
            self.ack_rate = 1.0;
        }
    }

    fn window(&self) -> u64 {
        match self.smoothed_rtt {
            Some(rtt) if !rtt.is_zero() => {
                let window = self.bps * rtt.as_secs_f64() * 2.0 / self.ack_rate;
                (window as u64).max(self.max_datagram_size)
            }
            _ => 10240,
        }
    }
}

impl Controller for Brutal {
    fn on_ack(
        &mut self,
        now: std::time::Instant,
        _sent: std::time::Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &quinn_proto::RttEstimator,
    ) {
        self.smoothed_rtt = Some(rtt.get());
        self.record(now, 1, 0);
    }

    fn on_congestion_event(
        &mut self,
        now: std::time::Instant,
        _sent: std::time::Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.record(now, 0, u64::from(lost_bytes > 0));
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.max_datagram_size = u64::from(new_mtu.max(1200));
    }

    fn window(&self) -> u64 {
        self.window()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

/// Factory for [`Brutal`].
#[derive(Debug, Clone)]
pub struct BrutalConfig {
    pub bps: u64,
}

impl ControllerFactory for BrutalConfig {
    fn build(
        self: Arc<Self>,
        now: std::time::Instant,
        current_mtu: u16,
    ) -> Box<dyn Controller> {
        Box::new(Brutal::new(self.bps, current_mtu, now))
    }
}

/// Establish one QUIC connection to `server:port`.
///
/// `address` is the host actually dialled (`tuic`'s `ip` option overrides the
/// configured server while the certificate name stays `server`/`sni`).
pub async fn connect(
    server: &str,
    address: &str,
    port: u16,
    settings: &TlsSettings,
    tls: &ClientTls,
    options: &QuicOptions,
    timeout: Duration,
) -> Result<(Connection, Endpoint), DialError> {
    if options.alpn.is_empty() {
        return Err(DialError::Handshake {
            protocol: "quic",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "a QUIC handshake needs at least one ALPN protocol",
            ),
        });
    }
    let rustls_config = tls::quic_client_config(settings, tls, &options.alpn, !options.disable_sni)
        .map_err(|source| DialError::Handshake {
            protocol: "quic tls",
            source,
        })?;
    let quic_crypto =
        QuicClientConfig::try_from(rustls_config).map_err(|e| DialError::Handshake {
            protocol: "quic tls",
            source: io::Error::new(io::ErrorKind::InvalidInput, e.to_string()),
        })?;
    connect_with_crypto(
        server,
        address,
        port,
        settings,
        options,
        timeout,
        Arc::new(quic_crypto),
    )
    .await
}

/// Establish one QUIC connection with a caller-built TLS client configuration
/// (the MASQUE WARP path needs the generated client certificate and the
/// endpoint-key pin, which the shared `TlsSettings` surface cannot express).
pub async fn connect_with_tls_config(
    server: &str,
    address: &str,
    port: u16,
    options: &QuicOptions,
    client_config: Arc<rustls::ClientConfig>,
    timeout: Duration,
) -> Result<(Connection, Endpoint), DialError> {
    if options.alpn.is_empty() {
        return Err(DialError::Handshake {
            protocol: "quic",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "a QUIC handshake needs at least one ALPN protocol",
            ),
        });
    }
    let quic_crypto =
        QuicClientConfig::try_from(client_config).map_err(|e| DialError::Handshake {
            protocol: "quic tls",
            source: io::Error::new(io::ErrorKind::InvalidInput, e.to_string()),
        })?;
    let settings = TlsSettings {
        sni: None,
        skip_cert_verify: false,
        alpn: Vec::new(),
        ..Default::default()
    };
    connect_with_crypto(
        server,
        address,
        port,
        &settings,
        options,
        timeout,
        Arc::new(quic_crypto),
    )
    .await
}

/// Establish one ShadowQUIC QUIC connection: the same transport as
/// [`connect`], but with the JLS-sealing TLS session and the JLS-aware
/// certificate verifier.
pub async fn connect_jls(
    server: &str,
    address: &str,
    port: u16,
    settings: &TlsSettings,
    tls: &ClientTls,
    options: &QuicOptions,
    timeout: Duration,
    credentials: &super::jls::JlsCredentials,
) -> Result<(Connection, Endpoint), DialError> {
    if options.alpn.is_empty() {
        return Err(DialError::Handshake {
            protocol: "quic",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "a QUIC handshake needs at least one ALPN protocol",
            ),
        });
    }
    let state = Arc::new(super::jls::JlsState::new());
    let rustls_config = tls::jls_quic_client_config(tls, &options.alpn, state.clone()).map_err(
        |source| DialError::Handshake {
            protocol: "shadowquic tls",
            source,
        },
    )?;
    let quic_crypto =
        QuicClientConfig::try_from(rustls_config).map_err(|e| DialError::Handshake {
            protocol: "shadowquic tls",
            source: io::Error::new(io::ErrorKind::InvalidInput, e.to_string()),
        })?;
    let crypto = super::jls::JlsClientConfig::new(quic_crypto, credentials.clone(), state);
    connect_with_crypto(
        server,
        address,
        port,
        settings,
        options,
        timeout,
        Arc::new(crypto),
    )
    .await
}

async fn connect_with_crypto(
    server: &str,
    address: &str,
    port: u16,
    settings: &TlsSettings,
    options: &QuicOptions,
    timeout: Duration,
    crypto: Arc<dyn quinn::crypto::ClientConfig>,
) -> Result<(Connection, Endpoint), DialError> {
    let target = super::resolve(address, port).await?;
    let bind: SocketAddr = if target.is_ipv4() {
        SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0)
    } else {
        SocketAddr::new(IpAddr::from([0u16; 8]), 0)
    };
    // The endpoint owns the UDP socket; create it here so interface-name and
    // routing-mark are applied before QUIC sends anything.
    let dialer_options = super::current_dialer().unwrap_or_default();
    let socket = super::udp_socket_std(bind, &dialer_options).map_err(|source| DialError::Connect {
        addr: bind.to_string(),
        source,
    })?;
    connect_with_socket(socket, target, server, settings, options, timeout, crypto).await
}

/// Establish one QUIC connection over an already bound UDP socket (the realm
/// rendezvous punches on one socket and runs the handshake on it).
pub async fn connect_over_socket(
    socket: std::net::UdpSocket,
    target: SocketAddr,
    server: &str,
    settings: &TlsSettings,
    tls: &ClientTls,
    options: &QuicOptions,
    timeout: Duration,
) -> Result<(Connection, Endpoint), DialError> {
    if options.alpn.is_empty() {
        return Err(DialError::Handshake {
            protocol: "quic",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "a QUIC handshake needs at least one ALPN protocol",
            ),
        });
    }
    let rustls_config = tls::quic_client_config(settings, tls, &options.alpn, !options.disable_sni)
        .map_err(|source| DialError::Handshake {
            protocol: "quic tls",
            source,
        })?;
    let crypto = QuicClientConfig::try_from(rustls_config).map_err(|e| DialError::Handshake {
        protocol: "quic tls",
        source: io::Error::new(io::ErrorKind::InvalidInput, e.to_string()),
    })?;
    connect_with_socket(
        socket,
        target,
        server,
        settings,
        options,
        timeout,
        Arc::new(crypto),
    )
    .await
}

async fn connect_with_socket(
    socket: std::net::UdpSocket,
    target: SocketAddr,
    server: &str,
    settings: &TlsSettings,
    options: &QuicOptions,
    timeout: Duration,
    crypto: Arc<dyn quinn::crypto::ClientConfig>,
) -> Result<(Connection, Endpoint), DialError> {
    let bind = socket
        .local_addr()
        .map(|address| address.to_string())
        .unwrap_or_else(|_| target.to_string());
    let runtime = quinn::default_runtime().ok_or_else(|| DialError::Connect {
        addr: bind.clone(),
        source: io::Error::other("quinn has no default async runtime"),
    })?;
    let abstract_socket = runtime
        .wrap_udp_socket(socket)
        .map_err(|source| DialError::Connect {
            addr: bind.clone(),
            source,
        })?;
    let hop_state = options.hop.as_ref().map(|hop| {
        Arc::new(HopState {
            port: AtomicU16::new(hop.ports[0]),
        })
    });
    let socket: Arc<dyn AsyncUdpSocket> =
        if options.obfs.is_some() || hop_state.is_some() {
            Arc::new(LayeredSocket {
                inner: abstract_socket,
                base: target,
                obfs: options.obfs.clone(),
                hop: hop_state.clone(),
            })
        } else {
            abstract_socket
        };
    let endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket,
        runtime,
    )
    .map_err(|source| DialError::Connect {
        addr: bind.clone(),
        source,
    })?;

    let mut client_config = ClientConfig::new(crypto);
    let mut transport = TransportConfig::default();
    // T7's 40 MB iOS budget: the quinn defaults are 1.25 MB per stream
    // receive window, a 10 MB send window and an unbounded connection receive
    // window. Those defaults are for a desktop proxy, not a Network Extension;
    // cap them here and record the numbers in evidence/t10-feasibility.json.
    // Window sizes are local flow-control choices and do not change the wire
    // protocol.
    transport.stream_receive_window(VarInt::from_u32(options.stream_receive_window));
    transport.receive_window(VarInt::from_u32(options.connection_receive_window));
    transport.send_window(options.send_window as u64);
    if let Some(streams) = options.max_concurrent_uni_streams {
        transport.max_concurrent_uni_streams(VarInt::from_u64(streams).unwrap_or(VarInt::MAX));
    }
    if let Some(streams) = options.max_concurrent_bidi_streams {
        transport.max_concurrent_bidi_streams(VarInt::from_u64(streams).unwrap_or(VarInt::MAX));
    }
    if !options.mtu_discovery {
        transport.mtu_discovery_config(None);
    }
    if let Some(idle) = options.max_idle_timeout {
        let idle = quinn::IdleTimeout::try_from(idle).map_err(|_| DialError::Handshake {
            protocol: "quic",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC idle timeout out of range",
            ),
        })?;
        transport.max_idle_timeout(Some(idle));
    }
    transport.keep_alive_interval(options.keep_alive);
    if let Some(mtu) = options.udp_mtu {
        // `udp-mtu` is the Hysteria UDP payload size; the pinned default 1197
        // comes from quic-go's 1200-byte max datagram minus a 3-byte frame.
        let initial = mtu.saturating_add(3).clamp(1200, 1452);
        transport.initial_mtu(initial);
    }
    if options.datagrams {
        transport.datagram_receive_buffer_size(Some(
            options.datagram_receive_buffer.unwrap_or(64 * 1024).max(1200),
        ));
        transport.datagram_send_buffer_size(
            options.datagram_send_buffer.unwrap_or(64 * 1024).max(1200),
        );
    }
    if let Some(bps) = options.brutal_bps.filter(|bps| *bps > 0) {
        transport.congestion_controller_factory(Arc::new(BrutalConfig { bps }));
    } else {
    match options.congestion_controller {
        CongestionController::Default => {
            // quinn's default is CUBIC; only an explicit initial window needs
            // a factory.
            if let Some(window) = options.initial_congestion_window {
                let mut config = quinn::congestion::CubicConfig::default();
                config.initial_window(window);
                transport.congestion_controller_factory(Arc::new(config));
            }
        }
        CongestionController::Cubic => {
            let mut config = quinn::congestion::CubicConfig::default();
            if let Some(window) = options.initial_congestion_window {
                config.initial_window(window);
            }
            transport.congestion_controller_factory(Arc::new(config));
        }
        CongestionController::NewReno => {
            let mut config = quinn::congestion::NewRenoConfig::default();
            if let Some(window) = options.initial_congestion_window {
                config.initial_window(window);
            }
            transport.congestion_controller_factory(Arc::new(config));
        }
        CongestionController::Bbr => {
            let mut config = quinn::congestion::BbrConfig::default();
            if let Some(window) = bbr_initial_window(options) {
                config.initial_window(window);
            }
            transport.congestion_controller_factory(Arc::new(config));
        }
    }
    }
    client_config.transport_config(Arc::new(transport));

    // The certificate name is `sni` when set, else the configured server (never
    // the `ip` override: that is only the address that is dialled).
    let server_name = settings.sni.as_deref().unwrap_or(server).to_string();
    let connecting = endpoint
        .connect_with(client_config, target, &server_name)
        .map_err(|e| DialError::Connect {
            addr: target.to_string(),
            source: io::Error::other(e.to_string()),
        })?;
    let connection = tokio::time::timeout(timeout, connecting)
        .await
        .map_err(|_| DialError::Timeout(timeout))?
        .map_err(|e| DialError::Handshake {
            protocol: "quic",
            source: io::Error::other(e.to_string()),
        })?;
    if let (Some(hop), Some(state)) = (&options.hop, hop_state) {
        let ports = hop.ports.clone();
        let hop = hop.clone();
        let connection = connection.clone();
        tokio::spawn(async move {
            loop {
                let delay = hop.next_interval();
                tokio::select! {
                    _ = tokio::time::sleep(delay) => state.next(&ports),
                    _ = connection.closed() => break,
                }
            }
        });
    }
    Ok((connection, endpoint))
}

/// Export TLS keying material (TUIC v5 token). `label`/`context` are the exact
/// bytes the pinned `GenToken` passes to `ExportKeyingMaterial`.
pub fn export_keying_material(
    connection: &Connection,
    output: &mut [u8],
    label: &[u8],
    context: &[u8],
) -> Result<(), DialError> {
    connection
        .export_keying_material(output, label, context)
        .map_err(|e| DialError::Handshake {
            protocol: "quic exporter",
            source: io::Error::other(format!("TLS exporter failed: {e:?}")),
        })
}

/// Error code helper for QUIC application close codes.
pub fn varint(value: u64) -> VarInt {
    VarInt::from_u64(value).unwrap_or(VarInt::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::IoSliceMut;

    #[test]
    fn varint_never_panics_on_out_of_range_values() {
        assert_eq!(varint(0).into_inner(), 0);
        assert_eq!(varint(u64::MAX), VarInt::MAX);
    }

    fn salamander_bytes(password: &[u8], salt: &[u8; 8], plain: &[u8]) -> Vec<u8> {
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(password);
        hasher.update(salt);
        let key = hasher.finalize();
        let mut out = salt.to_vec();
        for (index, byte) in plain.iter().enumerate() {
            out.push(byte ^ key[index % key.len()]);
        }
        out
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn layered_socket_obfuscates_and_rewrites_the_hop_port() {
        let password = b"hysteria2-obfs-secret".to_vec();
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let base = SocketAddr::new(server_addr.ip(), server_addr.port().wrapping_add(1).max(1));
        let local = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let runtime = quinn::default_runtime().unwrap();
        let inner = runtime.wrap_udp_socket(local).unwrap();
        let hop = Arc::new(HopState {
            port: AtomicU16::new(server_addr.port()),
        });
        let socket = Arc::new(LayeredSocket {
            inner,
            base,
            obfs: Some(Obfs::Salamander(Salamander {
                password: password.clone(),
            })),
            hop: Some(hop),
        });

        let plain = b"quic-initial";
        let transmit = Transmit {
            destination: base,
            ecn: None,
            contents: plain,
            segment_size: None,
            src_ip: None,
        };
        let mut poller = socket.clone().create_io_poller();
        std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();
        socket.try_send(&transmit).unwrap();

        let mut buffer = [0u8; 128];
        // The datagram arrived at the hop port even though quinn passed the
        // base address (which is not bound anywhere).
        let (read, from) = server.recv_from(&mut buffer).unwrap();
        assert!(read > 8);
        let salt: [u8; 8] = buffer[..8].try_into().unwrap();
        let decoded = salamander_bytes(&password, &salt, &buffer[8..read]);
        assert_eq!(&decoded[8..], plain);

        // The server replies from the hop port; the layer must decode it and
        // report the configured base address so quinn keeps one connection.
        let reply = salamander_bytes(&password, &[9u8; 8], b"server-reply");
        server.send_to(&reply, from).unwrap();
        let mut received = [0u8; 128];
        let mut bufs = [IoSliceMut::new(&mut received)];
        let mut meta = [RecvMeta::default()];
        let count = std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(meta[0].addr, base);
        assert_eq!(&received[..meta[0].len], b"server-reply");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hop_interval_is_clamped_and_randomised() {
        let hop = HopConfig {
            ports: vec![1, 2],
            interval: Duration::from_secs(5),
            interval_max: Duration::from_secs(7),
        };
        for _ in 0..50 {
            let next = hop.next_interval();
            assert!(next >= Duration::from_secs(5));
            assert!(next <= Duration::from_secs(7));
        }
    }

    #[test]
    fn bbr_profile_selects_the_initial_window() {
        let mut options = QuicOptions::new(vec!["h3".to_string()]);
        options.congestion_controller = CongestionController::Bbr;
        options.initial_congestion_window = Some(48 * 1200);
        assert_eq!(bbr_initial_window(&options), Some(48 * 1200));
        options.bbr_profile = Some(BbrProfile::Conservative);
        assert_eq!(bbr_initial_window(&options), Some(24 * 1200));
        options.bbr_profile = Some(BbrProfile::Standard);
        assert_eq!(bbr_initial_window(&options), Some(32 * 1200));
        options.bbr_profile = Some(BbrProfile::Aggressive);
        assert_eq!(bbr_initial_window(&options), Some(40 * 1200));
        // The same value reaches quinn's controller factory, so the profile is
        // observable beyond the helper.
        let mut config = quinn::congestion::BbrConfig::default();
        config.initial_window(bbr_initial_window(&options).unwrap());
        let controller =
            Arc::new(config).build(std::time::Instant::now(), 1200);
        assert_eq!(controller.initial_window(), 40 * 1200);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gecko_fragments_long_headers_and_reassembles_them() {
        let password = b"hysteria2-gecko-secret".to_vec();
        let gecko = Gecko::new(password.clone(), 512, 1200);
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let local = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let runtime = quinn::default_runtime().unwrap();
        let inner = runtime.wrap_udp_socket(local).unwrap();
        let socket = Arc::new(LayeredSocket {
            inner,
            base: server_addr,
            obfs: Some(Obfs::Gecko(gecko.clone())),
            hop: None,
        });
        let mut plain = vec![0u8; 900];
        rand::thread_rng().fill_bytes(&mut plain);
        plain[0] = 0xc0;
        let transmit = Transmit {
            destination: server_addr,
            ecn: None,
            contents: &plain,
            segment_size: None,
            src_ip: None,
        };
        let mut poller = socket.clone().create_io_poller();
        std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();
        socket.try_send(&transmit).unwrap();

        // Every long-header packet is split into 2..8 padded frames, each one
        // Salamander-obfuscated and in the configured on-wire range.
        let mut chunks: Vec<Option<Vec<u8>>> = Vec::new();
        let mut total = 0u8;
        let mut frames = 0;
        let mut buffer = [0u8; 2048];
        let mut from = None;
        loop {
            let Ok((read, source)) = server.recv_from(&mut buffer) else {
                break;
            };
            from = Some(source);
            frames += 1;
            let plain_len = salamander_unframe(&password, &mut buffer[..read]);
            let body = &buffer[..plain_len];
            assert!(
                body[0] & GECKO_FRAGMENT_FLAG != 0,
                "long header was not fragmented"
            );
            assert!(
                (512..=1200).contains(&read),
                "on-wire frame {read} outside range"
            );
            let index = usize::from(body[2] >> 4);
            let count = body[2] & 0x0f;
            total = count;
            let pad = usize::from(u16::from_be_bytes([body[3], body[4]]));
            if chunks.len() < usize::from(count) {
                chunks.resize(usize::from(count), None);
            }
            chunks[index] = Some(body[GECKO_HEADER_LEN + pad..].to_vec());
        }
        assert!((2..=8).contains(&frames), "{frames} gecko frames");
        assert!((2..=8).contains(&total));
        let reassembled: Vec<u8> = chunks
            .into_iter()
            .map(|chunk| chunk.expect("every chunk arrived"))
            .flatten()
            .collect();
        assert_eq!(reassembled, plain);

        // The server fragments a reply the same way; the layer reassembles it
        // before quinn sees it.
        let mut reply = vec![0u8; 400];
        rand::thread_rng().fill_bytes(&mut reply);
        reply[0] = 0x80;
        for frame in gecko.frames(&reply) {
            server.send_to(&frame, from.unwrap()).unwrap();
        }
        let mut received = [0u8; 2048];
        let mut bufs = [IoSliceMut::new(&mut received)];
        let mut meta = [RecvMeta::default()];
        let count = std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(&received[..meta[0].len], &reply[..]);
    }
}
