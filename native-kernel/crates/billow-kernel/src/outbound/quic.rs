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

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

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
    /// initial window (a documented approximation, not wire-visible).
    pub bbr_profile: Option<BbrProfile>,
    /// Hysteria2 `udp-mtu`: the Hysteria UDP session payload MTU. quinn has no
    /// Hysteria UDP session, so it is applied to the QUIC initial path MTU as
    /// `udp-mtu + 3` (the pinned default 1197 comes from 1200 - 3).
    pub udp_mtu: Option<u16>,
    /// Hysteria2 `obfs: salamander`: BLAKE2b-256 salt/XOR packet obfuscation
    /// applied at the UDP socket boundary.
    pub obfs: Option<Salamander>,
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
    obfs: Option<Salamander>,
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

    /// One datagram (or each GRO segment) gets an independent salt.
    fn obfuscate(&self, contents: &[u8], segment_size: Option<usize>) -> (Vec<u8>, Option<usize>) {
        let Some(obfs) = &self.obfs else {
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
        let Some(obfs) = &self.obfs else {
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
}

impl AsyncUdpSocket for LayeredSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let destination = self.destination(transmit.destination);
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
        self.inner.max_receive_segments()
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
    let runtime = quinn::default_runtime().ok_or_else(|| DialError::Connect {
        addr: bind.to_string(),
        source: io::Error::other("quinn has no default async runtime"),
    })?;
    let abstract_socket = runtime
        .wrap_udp_socket(socket)
        .map_err(|source| DialError::Connect {
            addr: bind.to_string(),
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
        addr: bind.to_string(),
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
            if let Some(window) = options.initial_congestion_window {
                config.initial_window(window);
            } else if let Some(profile) = options.bbr_profile {
                // quinn's BBR has no upstream profile selector; the gain
                // difference is approximated with the initial window.
                let packets = match profile {
                    BbrProfile::Conservative => 24,
                    BbrProfile::Standard => 32,
                    BbrProfile::Aggressive => 40,
                };
                config.initial_window(packets * 1200);
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
            obfs: Some(Salamander {
                password: password.clone(),
            }),
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
}
