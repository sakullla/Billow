//! TUIC outbound (`adapter/outbound/tuic.go`, `transport/tuic/v4` and `v5`).
//!
//! One QUIC connection (TLS 1.3, ALPN `h3` by default) carries every session:
//!
//! - v5 (`uuid`/`password`): a unidirectional stream writes
//!   `0x05 0x00 || uuid[16] || token[32]`, where `token` is the TLS exporter
//!   output with the raw 16 UUID bytes as label and the password as context
//!   (`GenToken`);
//! - v4 (`token`): a unidirectional stream writes `0x04 0x00 || BLAKE3(token)`
//!   (`GenTKN`), and every Connect stream is answered with
//!   `0xff || rep[1]` (v5 has no connect response).
//!
//! Each TCP session opens a bidirectional stream and writes
//! `version, 0x01, address`, then the raw byte stream. UDP uses the same
//! connection: `udp-relay-mode: native` carries one Packet per QUIC datagram,
//! `udp-relay-mode: quic` carries one Packet per unidirectional stream.
//! `udp-over-stream` instead opens a stream to the pinned
//! `sp[.v2].udp-over-tcp.arpa` destination and frames `u16 length || payload`
//! (v1 prepends the destination to each frame, v2 sends it in the request).
//!
//! A new QUIC connection is established per dial. The pinned client pools one
//! connection and re-authenticates once; pooling changes latency and
//! connection count, not the wire format. `reduce-rtt` (the pinned `DialEarly`)
//! is a named residual: quinn needs a session-ticket cache and a pooled
//! connection to send 0-RTT data, and neither exists here.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

use super::quic::{self, BbrProfile, CongestionController, QuicOptions};
pub use super::quic::QuicStream;
use super::tls::ClientTls;
use super::{DialError, Dialed, Target};

use crate::proxies::{TuicOutbound, TuicRelayMode};

const COMMAND_AUTHENTICATE: u8 = 0x00;
const COMMAND_CONNECT: u8 = 0x01;
const COMMAND_PACKET: u8 = 0x02;
const VERSION_V4: u8 = 0x04;
const VERSION_V5: u8 = 0x05;
const COMMAND_RESPONSE: u8 = 0xff;

/// Largest UDP payload the pinned clients accept (uint16 length field).
const MAX_UDP_PAYLOAD: usize = 0xffff;

pub const UOT_MAGIC_V1: &str = "sp.udp-over-tcp.arpa";
pub const UOT_MAGIC_V2: &str = "sp.v2.udp-over-tcp.arpa";

/// Encode one target in TUIC's address form: `type` 0 = domain (length byte +
/// name), 1 = IPv4, 2 = IPv6, then the big-endian port.
pub fn encode_address(target: &Target) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(target.host.len() + 19);
    if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                out.push(1);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(2);
                out.extend_from_slice(&v6.octets());
            }
        }
    } else {
        let name = target.host.as_bytes();
        if name.is_empty() || name.len() > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("TUIC domain name length {} is out of range", name.len()),
            ));
        }
        out.push(0);
        out.push(name.len() as u8);
        out.extend_from_slice(name);
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(out)
}

/// Read one TUIC address (used by the loopback peer and the tests).
pub fn read_address(bytes: &[u8], offset: usize) -> Option<(Target, usize)> {
    let kind = *bytes.get(offset)?;
    let mut cursor = offset + 1;
    let host = match kind {
        0 => {
            let len = *bytes.get(cursor)? as usize;
            cursor += 1;
            let name = bytes.get(cursor..cursor + len)?;
            cursor += len;
            String::from_utf8(name.to_vec()).ok()?
        }
        1 => {
            let addr = bytes.get(cursor..cursor + 4)?;
            cursor += 4;
            std::net::Ipv4Addr::from(<[u8; 4]>::try_from(addr).ok()?).to_string()
        }
        2 => {
            let addr = bytes.get(cursor..cursor + 16)?;
            cursor += 16;
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(addr).ok()?).to_string()
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*bytes.get(cursor)?, *bytes.get(cursor + 1)?]);
    cursor += 2;
    Some((Target { host, port }, cursor - offset))
}

/// `PacketOverHead` of the pinned protocol: an IPv6 unspecified address
/// (`2 | 16 bytes | port`), the two-byte command head and the fixed fields.
pub fn packet_overhead(version: u8) -> usize {
    let address = 19;
    match version {
        VERSION_V4 => 2 + 4 + 2 + address,
        _ => 2 + 2 + 2 + 1 + 1 + 2 + address,
    }
}

fn timeout_error(timeout: Duration) -> DialError {
    DialError::Timeout(timeout)
}

/// QUIC congestion tuning for TUIC/masque. The pinned `SetCongestionController`
/// accepts `cubic`, `new_reno` and `bbr`; only the BBR branch consumes `cwnd`
/// (default 32 packets), while `cwnd` without a controller and with the other
/// controllers is accepted and left to the library default.
///
/// `packet_size` is the QUIC `InitialPacketSize` the pinned client configures:
/// quic-go defaults to 1280 for TUIC, while masque sets 1242 explicitly. The
/// BBR sender multiplies the packet count by that size, so the initial window
/// differs per family.
pub(crate) fn congestion_tuning(
    name: Option<&str>,
    cwnd: u32,
    packet_size: u64,
) -> (CongestionController, Option<u64>) {
    let controller = match name {
        Some("cubic") => CongestionController::Cubic,
        Some("new_reno") => CongestionController::NewReno,
        // Pinned `congestion.SetCongestionController`: `bbr_meta_v2` is a
        // fallthrough alias of `bbr` (both use the v2 BBR sender).
        Some("bbr") | Some("bbr_meta_v2") => CongestionController::Bbr,
        _ => CongestionController::Default,
    };
    let initial = if matches!(name, Some("bbr") | Some("bbr_meta_v2")) {
        let packets = if cwnd == 0 { 32 } else { cwnd };
        Some(u64::from(packets) * packet_size)
    } else {
        None
    };
    (controller, initial)
}

/// BBR with `bbr-profile`. The pinned v2 BBR sender keeps the initial window
/// at `cwnd` and changes its gains instead; quinn exposes only the window, so
/// the profile maps to 24/32/40 packets (the same approximation as T31's
/// hysteria2 `bbr-profile`) and takes precedence over `cwnd`.
pub(crate) fn congestion_tuning_profile(
    name: Option<&str>,
    cwnd: u32,
    profile: Option<&str>,
    packet_size: u64,
) -> (CongestionController, Option<u64>) {
    let (controller, initial) = congestion_tuning(name, cwnd, packet_size);
    if !matches!(name, Some("bbr") | Some("bbr_meta_v2")) {
        return (controller, initial);
    }
    let parsed = match profile {
        Some(value) => BbrProfile::parse(value),
        None => None,
    };
    match parsed {
        Some(profile) => (controller, Some(profile.initial_window_packets() * packet_size)),
        None => (controller, initial),
    }
}

/// One v5/v4 UDP packet (the relay payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuicPacket {
    pub assoc_id: u32,
    pub packet_id: u16,
    pub fragment_total: u8,
    pub fragment_id: u8,
    pub target: Target,
    pub data: Vec<u8>,
}

impl TuicPacket {
    pub fn encode(&self, version: u8) -> io::Result<Vec<u8>> {
        let address = encode_address(&self.target)?;
        let mut out = Vec::with_capacity(16 + address.len() + self.data.len());
        out.push(version);
        out.push(COMMAND_PACKET);
        if version == VERSION_V4 {
            out.extend_from_slice(&self.assoc_id.to_be_bytes());
            out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        } else {
            out.extend_from_slice(&(self.assoc_id as u16).to_be_bytes());
            out.extend_from_slice(&self.packet_id.to_be_bytes());
            out.push(self.fragment_total);
            out.push(self.fragment_id);
            out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
            // The pinned `fragWriteNative` writes `AtypNone` (255) instead of
            // the address on every fragment after the first; the server's
            // address reader stops immediately for it.
            if self.fragment_total > 1 && self.fragment_id > 0 {
                out.push(0xff);
                out.extend_from_slice(&self.data);
                return Ok(out);
            }
        }
        out.extend_from_slice(&address);
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    pub fn decode(version: u8, bytes: &[u8]) -> Option<TuicPacket> {
        if bytes.len() < 3 || bytes[0] != version || bytes[1] != COMMAND_PACKET {
            return None;
        }
        let mut cursor = 2;
        let (assoc_id, packet_id, fragment_total, fragment_id, size): (u32, u16, u8, u8, usize) =
            if version == VERSION_V4 {
                let assoc = u32::from_be_bytes(bytes.get(cursor..cursor + 4)?.try_into().ok()?);
                cursor += 4;
                let size = u16::from_be_bytes(bytes.get(cursor..cursor + 2)?.try_into().ok()?) as usize;
                cursor += 2;
                (assoc, 0, 1, 0, size)
            } else {
                let assoc = u16::from_be_bytes(bytes.get(cursor..cursor + 2)?.try_into().ok()?) as u32;
                cursor += 2;
                let packet_id = u16::from_be_bytes(bytes.get(cursor..cursor + 2)?.try_into().ok()?);
                cursor += 2;
                let fragment_total = *bytes.get(cursor)?;
                cursor += 1;
                let fragment_id = *bytes.get(cursor)?;
                cursor += 1;
                let size = u16::from_be_bytes(bytes.get(cursor..cursor + 2)?.try_into().ok()?) as usize;
                cursor += 2;
                (assoc, packet_id, fragment_total, fragment_id, size)
            };
        let (target, used) = if version != VERSION_V4 && *bytes.get(cursor)? == 0xff {
            // `AtypNone`: a non-first v5 fragment carries no address.
            (Target { host: String::new(), port: 0 }, 1)
        } else {
            read_address(bytes, cursor)?
        };
        cursor += used;
        let data = bytes.get(cursor..cursor + size)?.to_vec();
        Some(TuicPacket {
            assoc_id,
            packet_id,
            fragment_total,
            fragment_id,
            target,
            data,
        })
    }
}

/// A bidirectional TUIC stream whose first v4 Connect response is read lazily
/// (`fast-open`): the pinned `NewEarlyConn` hands the stream to the caller and
/// replays the server's verdict on the first read.
struct EarlyResponse<S> {
    inner: S,
    pending: Option<[u8; 3]>,
    filled: usize,
}

impl<S> EarlyResponse<S> {
    fn new(inner: S) -> EarlyResponse<S> {
        EarlyResponse {
            inner,
            pending: Some([0u8; 3]),
            filled: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for EarlyResponse<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(pending) = &mut this.pending {
            while this.filled < 3 {
                let mut slot = [0u8; 3];
                let available = 3 - this.filled;
                let mut read = ReadBuf::new(&mut slot[..available]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                    Poll::Ready(Ok(())) => {
                        let count = read.filled().len();
                        if count == 0 {
                            this.pending = None;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "tuic: the connection closed before the connect response",
                            )));
                        }
                        pending[this.filled..this.filled + count]
                            .copy_from_slice(&read.filled()[..count]);
                        this.filled += count;
                    }
                    Poll::Ready(Err(error)) => {
                        this.pending = None;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            // The v4 Response is `0x04 0xff rep` (the command head plus the
            // reply byte); `rep != 0` is a rejection.
            if pending[1] != 0xff || pending[2] != 0x00 {
                this.pending = None;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "tuic: the server rejected the connect request",
                )));
            }
            this.pending = None;
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for EarlyResponse<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Authenticate one QUIC connection and open the Connect stream for `target`.
async fn connect_and_open(
    option: &TuicOutbound,
    target: &Target,
    tls: &ClientTls,
    timeout: Duration,
) -> Result<(QuicStream, std::net::SocketAddr), DialError> {
    let version = if option.token.is_some() {
        VERSION_V4
    } else {
        VERSION_V5
    };
    let address = option.ip.as_deref().unwrap_or(&option.server);
    let alpn = if option.alpn.is_empty() {
        vec!["h3".to_string()]
    } else {
        option.alpn.clone()
    };
    let mut quic_options = QuicOptions::new(alpn);
    quic_options.keep_alive = Some(Duration::from_millis(option.heartbeat_interval.max(1)));
    quic_options.datagrams = true;
    quic_options.disable_sni = option.disable_sni;
    quic_options.mtu_discovery = !option.disable_mtu_discovery;
    // `max-datagram-frame-size` bounds one TUIC frame, not quinn's queue: a
    // fragmented message sends several frames back to back, so the socket
    // buffers stay at the Hysteria2 64 KiB default.
    quic_options.datagram_receive_buffer = Some(64 * 1024);
    quic_options.datagram_send_buffer = Some(64 * 1024);
    if let Some(window) = option.stream_receive_window {
        quic_options.stream_receive_window = window;
    }
    if let Some(window) = option.connection_receive_window {
        quic_options.connection_receive_window = window;
    }
    if option.congestion_controller.is_some()
        || option.cwnd != 0
        || option.bbr_profile.is_some()
    {
        // quic-go's default InitialPacketSize for TUIC.
        let (controller, initial) = congestion_tuning_profile(
            option.congestion_controller.as_deref(),
            option.cwnd,
            option.bbr_profile.as_deref(),
            1280,
        );
        quic_options.congestion_controller = controller;
        quic_options.initial_congestion_window = initial;
    }
    let (connection, endpoint) = quic::connect(
        &option.server,
        address,
        option.port,
        &option.tls_settings,
        tls,
        &quic_options,
        timeout,
    )
    .await?;

    // `request-timeout` bounds each TUIC request operation (the auth stream
    // and the Connect stream). The pinned client uses the value for reading
    // the v4 connect response; the auth write has no response.
    let request_timeout = Duration::from_millis(option.request_timeout.max(1));

    // Authentication: one unidirectional stream per connection.
    authenticate(option, &connection).await?;

    // One bidirectional stream per TCP session.
    let (mut send, recv) = tokio::time::timeout(request_timeout, connection.open_bi())
        .await
        .map_err(|_| timeout_error(request_timeout))?
        .map_err(|e| DialError::Handshake {
            protocol: "tuic",
            source: io::Error::other(format!("open stream: {e}")),
        })?;
    let mut header = Vec::with_capacity(2 + target.host.len() + 19);
    header.push(version);
    header.push(COMMAND_CONNECT);
    header.extend_from_slice(
        &encode_address(target).map_err(|source| DialError::Handshake {
            protocol: "tuic",
            source,
        })?,
    );
    tokio::time::timeout(request_timeout, send.write_all(&header))
        .await
        .map_err(|_| timeout_error(request_timeout))?
        .map_err(|e| DialError::Handshake {
            protocol: "tuic",
            source: io::Error::other(format!("connect request: {e}")),
        })?;

    let server = connection.remote_address();
    let stream = QuicStream::new(send, recv, connection, endpoint);
    Ok((stream, server))
}

/// Read the v4 Connect response (`0x04 0xff rep`) and refuse a non-zero rep.
async fn read_v4_response<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(), DialError> {
    let mut response = [0u8; 3];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|e| DialError::Handshake {
            protocol: "tuic",
            source: io::Error::other(format!("connect response: {e}")),
        })?;
    if response[1] != COMMAND_RESPONSE || response[2] != 0x00 {
        return Err(DialError::Handshake {
            protocol: "tuic",
            source: io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("tuic: the server rejected the connect request ({response:02x?})"),
            ),
        });
    }
    Ok(())
}

/// Dial `target` through a TUIC server.
pub async fn dial(
    option: &TuicOutbound,
    target: &Target,
    tls: &ClientTls,
    timeout: Duration,
) -> Result<Dialed, DialError> {
    let (mut stream, server) = connect_and_open(option, target, tls, timeout).await?;
    if option.token.is_some() {
        if option.fast_open {
            return Ok(Dialed {
                stream: Box::new(EarlyResponse::new(stream)),
                server,
            });
        }
        let request_timeout = Duration::from_millis(option.request_timeout.max(1));
        tokio::time::timeout(request_timeout, read_v4_response(&mut stream))
            .await
            .map_err(|_| timeout_error(request_timeout))??;
    }
    Ok(Dialed {
        stream: Box::new(stream),
        server,
    })
}

/// Open the UDP-over-stream association for one destination. Version 2 writes
/// the pinned `uot.Request` (`isConnect = 1`, destination) on the stream;
/// version 1 carries the destination in every frame instead.
pub async fn dial_uot(
    option: &TuicOutbound,
    target: &Target,
    tls: &ClientTls,
    timeout: Duration,
) -> Result<(QuicStream, std::net::SocketAddr, u8), DialError> {
    let magic = Target {
        host: match option.udp_over_stream_version {
            1 => UOT_MAGIC_V1.to_string(),
            _ => UOT_MAGIC_V2.to_string(),
        },
        port: 0,
    };
    let (mut stream, server) = connect_and_open(option, &magic, tls, timeout).await?;
    if option.token.is_some() {
        read_v4_response(&mut stream).await?;
    }
    if option.udp_over_stream_version >= 2 {
        let mut request = Vec::with_capacity(1 + target.host.len() + 9);
        request.push(1); // isConnect
        request.extend_from_slice(&uot_address(target));
        stream
            .write_all(&request)
            .await
            .map_err(|e| DialError::Handshake {
                protocol: "tuic uot",
                source: io::Error::other(format!("request: {e}")),
            })?;
        stream.flush().await.map_err(|e| DialError::Handshake {
            protocol: "tuic uot",
            source: io::Error::other(format!("request flush: {e}")),
        })?;
    }
    Ok((stream, server, option.udp_over_stream_version))
}

/// UoT `AddrParser` (the `sing/common/uot` form: family 0 IPv4, 1 IPv6,
/// 2 FQDN, then the address and the port).
pub fn uot_address(target: &Target) -> Vec<u8> {
    let mut out = Vec::with_capacity(target.host.len() + 9);
    if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                out.push(0);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(1);
                out.extend_from_slice(&v6.octets());
            }
        }
    } else {
        out.push(2);
        out.push(target.host.len().min(255) as u8);
        out.extend_from_slice(&target.host.as_bytes()[..target.host.len().min(255)]);
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    out
}

pub fn parse_uot_address(bytes: &[u8], offset: usize) -> Option<(Target, usize)> {
    let family = *bytes.get(offset)?;
    let mut cursor = offset + 1;
    let host = match family {
        0 => {
            let octets = bytes.get(cursor..cursor + 4)?;
            cursor += 4;
            std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]).to_string()
        }
        1 => {
            let octets = bytes.get(cursor..cursor + 16)?;
            cursor += 16;
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(octets).ok()?).to_string()
        }
        2 => {
            let len = *bytes.get(cursor)? as usize;
            cursor += 1;
            let name = bytes.get(cursor..cursor + len)?;
            cursor += len;
            String::from_utf8_lossy(name).to_string()
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*bytes.get(cursor)?, *bytes.get(cursor + 1)?]);
    Some((Target { host, port }, cursor + 2 - offset))
}

/// Reassembles v5 fragmented UDP packets by packet id.
#[derive(Default)]
pub struct TuicFragments {
    pending: HashMap<u16, Pending>,
}

struct Pending {
    total: u8,
    target: Option<Target>,
    parts: HashMap<u8, Vec<u8>>,
    started: Instant,
}

impl TuicFragments {
    const MAX_AGE: Duration = Duration::from_secs(10);

    pub fn feed(&mut self, packet: TuicPacket) -> Option<(Target, Vec<u8>)> {
        self.expire(Instant::now());
        if packet.fragment_total <= 1 {
            return Some((packet.target, packet.data));
        }
        let entry = self.pending.entry(packet.packet_id).or_insert_with(|| Pending {
            total: packet.fragment_total,
            target: None,
            parts: HashMap::new(),
            started: Instant::now(),
        });
        if entry.total != packet.fragment_total {
            self.pending.remove(&packet.packet_id);
            return None;
        }
        if packet.fragment_id == 0 && !packet.target.host.is_empty() {
            entry.target = Some(packet.target);
        }
        entry.parts.insert(packet.fragment_id, packet.data);
        if entry.parts.len() != entry.total as usize {
            return None;
        }
        let entry = self.pending.remove(&packet.packet_id)?;
        let target = entry.target?;
        let mut data = Vec::new();
        for index in 0..entry.total {
            data.extend_from_slice(entry.parts.get(&index)?);
        }
        Some((target, data))
    }

    fn expire(&mut self, now: Instant) {
        self.pending
            .retain(|_, entry| now.duration_since(entry.started) <= Self::MAX_AGE);
    }
}

/// One TUIC UDP association over a shared QUIC connection.
pub struct TuicUdp {
    connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
    version: u8,
    mode: TuicRelayMode,
    assoc_id: u32,
    packet_id: u16,
    max_udp: usize,
    max_frame: usize,
    fragments: TuicFragments,
    /// `udp-relay-mode: quic` replies arrive on server-initiated uni streams;
    /// a background task decodes them into this queue.
    inbound: Option<mpsc::Receiver<(Target, Vec<u8>)>>,
}

impl TuicUdp {
    /// Open the UDP association. A `dialer-proxy` chain is refused by name:
    /// a QUIC socket cannot ride a SOCKS5 UDP hop in this kernel. The
    /// configuration itself still loads.
    pub async fn connect(
        option: &TuicOutbound,
        via: &[&crate::proxies::Proxy],
        tls: &ClientTls,
        timeout: Duration,
    ) -> Result<TuicUdp, DialError> {
        if via.len() > 1 {
            return Err(DialError::Chain(format!(
                "tuic udp through {} is not implemented: a QUIC socket cannot be carried through a SOCKS5 UDP hop; the association is never dialled around the chain",
                via[1].name
            )));
        }
        if option.udp_over_stream {
            return Err(DialError::Chain(
                "tuic udp-over-stream is handled by the per-target UoT association, not by the shared datagram association".into(),
            ));
        }
        let version = if option.token.is_some() {
            VERSION_V4
        } else {
            VERSION_V5
        };
        let address = option.ip.as_deref().unwrap_or(&option.server);
        let alpn = if option.alpn.is_empty() {
            vec!["h3".to_string()]
        } else {
            option.alpn.clone()
        };
        let mut quic_options = QuicOptions::new(alpn);
        quic_options.keep_alive = Some(Duration::from_millis(option.heartbeat_interval.max(1)));
        quic_options.datagrams = true;
        quic_options.disable_sni = option.disable_sni;
        quic_options.mtu_discovery = !option.disable_mtu_discovery;
        quic_options.datagram_receive_buffer = Some(64 * 1024);
        quic_options.datagram_send_buffer = Some(64 * 1024);
        if let Some(window) = option.stream_receive_window {
            quic_options.stream_receive_window = window;
        }
        if let Some(window) = option.connection_receive_window {
            quic_options.connection_receive_window = window;
        }
        if option.congestion_controller.is_some()
            || option.cwnd != 0
            || option.bbr_profile.is_some()
        {
            let (controller, initial) = congestion_tuning_profile(
                option.congestion_controller.as_deref(),
                option.cwnd,
                option.bbr_profile.as_deref(),
                1280,
            );
            quic_options.congestion_controller = controller;
            quic_options.initial_congestion_window = initial;
        }
        let (connection, endpoint) = quic::connect(
            &option.server,
            address,
            option.port,
            &option.tls_settings,
            tls,
            &quic_options,
            timeout,
        )
        .await?;
        // Authenticate exactly like the TCP path.
        authenticate(option, &connection).await?;
        let assoc_id = if version == VERSION_V4 {
            rand::random::<u32>()
        } else {
            u32::from(rand::random::<u16>())
        };
        let inbound = if option.udp_relay_mode == TuicRelayMode::Quic {
            let (tx, rx) = mpsc::channel(32);
            let streams = connection.clone();
            tokio::spawn(async move {
                loop {
                    let mut stream = match streams.accept_uni().await {
                        Ok(stream) => stream,
                        Err(_) => return,
                    };
                    let mut buffer = vec![0u8; MAX_UDP_PAYLOAD + 64];
                    let read = match stream.read(&mut buffer).await {
                        Ok(Some(read)) if read > 0 => read,
                        _ => continue,
                    };
                    if let Some(packet) = TuicPacket::decode(version, &buffer[..read]) {
                        if tx.send((packet.target, packet.data)).await.is_err() {
                            return;
                        }
                    }
                }
            });
            Some(rx)
        } else {
            None
        };
        Ok(TuicUdp {
            connection,
            _endpoint: endpoint,
            version,
            mode: option.udp_relay_mode,
            assoc_id,
            packet_id: 0,
            max_udp: option.max_udp_relay_packet_size,
            max_frame: option.max_datagram_frame_size,
            fragments: TuicFragments::default(),
            inbound,
        })
    }

    pub async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_UDP_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tuic: UDP payload exceeds 65535 bytes",
            ));
        }
        // The pinned v4 native client refuses a payload above
        // `max-udp-relay-packet-size`; v5 fragments instead, and the quic
        // carrier is a stream (bounded only by the u16 length field).
        if self.version == VERSION_V4
            && self.mode == TuicRelayMode::Native
            && payload.len() > self.max_udp
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "tuic v4: UDP payload {} exceeds max-udp-relay-packet-size {}",
                    payload.len(),
                    self.max_udp
                ),
            ));
        }
        self.packet_id = self.packet_id.wrapping_add(1);
        let packet_id = self.packet_id;
        let address = encode_address(target)?;
        let overhead = packet_overhead(self.version);
        let (chunk, total) = match self.mode {
            TuicRelayMode::Quic => (payload.len().max(1), 1usize),
            TuicRelayMode::Native if self.version == VERSION_V4 => (payload.len().max(1), 1usize),
            TuicRelayMode::Native => {
                // The pinned v5 `fragWriteNative` splits on
                // `max-udp-relay-packet-size`, not on the datagram frame, to
                // stay under the 1200-byte path MTU. quinn reports the exact
                // payload budget, which is a little smaller than the pinned
                // 1168-byte margin, so use the smaller of the two.
                let fixed = overhead - 19; // command + assoc/packet/frag/size
                let path_limit = self
                    .connection
                    .max_datagram_size()
                    .unwrap_or(self.max_udp + address.len() + fixed);
                let chunk = self
                    .max_udp
                    .min(path_limit.saturating_sub(fixed + address.len()))
                    .max(1);
                (chunk, payload.len().div_ceil(chunk).max(1))
            }
        };
        if total > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tuic: a datagram needs more than 255 fragments",
            ));
        }
        let mut offset = 0;
        for index in 0..total {
            let end = (offset + chunk).min(payload.len());
            let packet = TuicPacket {
                assoc_id: self.assoc_id,
                packet_id,
                fragment_total: total as u8,
                fragment_id: index as u8,
                target: target.clone(),
                data: payload[offset..end].to_vec(),
            };
            offset = end;
            let encoded = packet.encode(self.version)?;
            match self.mode {
                TuicRelayMode::Native => {
                    if encoded.len() > self.max_frame {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "tuic: datagram frame {} exceeds max-datagram-frame-size {}",
                                encoded.len(),
                                self.max_frame
                            ),
                        ));
                    }
                    self.connection
                        .send_datagram(Bytes::from(encoded))
                        .map_err(|e| io::Error::other(e.to_string()))?;
                }
                TuicRelayMode::Quic => {
                    let mut stream = self
                        .connection
                        .open_uni()
                        .await
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    stream
                        .write_all(&encoded)
                        .await
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    stream
                        .finish()
                        .map_err(|e| io::Error::other(e.to_string()))?;
                }
            }
        }
        Ok(())
    }

    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        loop {
            let (target, payload) = match self.mode {
                TuicRelayMode::Native => {
                    let datagram = match self.connection.read_datagram().await {
                        Ok(datagram) => datagram,
                        Err(_) => return Ok(None),
                    };
                    match TuicPacket::decode(self.version, &datagram) {
                        Some(packet) => match self.fragments.feed(packet) {
                            Some(message) => message,
                            None => continue,
                        },
                        None => continue,
                    }
                }
                TuicRelayMode::Quic => {
                    let Some(inbound) = self.inbound.as_mut() else {
                        return Ok(None);
                    };
                    match inbound.recv().await {
                        Some(message) => message,
                        None => return Ok(None),
                    }
                }
            };
            if payload.len() > buffer.len() {
                continue;
            }
            buffer[..payload.len()].copy_from_slice(&payload);
            return Ok(Some((target, payload.len())));
        }
    }
}

/// Perform the authentication stream write on an already connected QUIC
/// connection (shared by the TCP and UDP paths).
pub(crate) async fn authenticate(
    option: &TuicOutbound,
    connection: &quinn::Connection,
) -> Result<(), DialError> {
    let request_timeout = Duration::from_millis(option.request_timeout.max(1));
    let auth = match &option.token {
        Some(token) => {
            let mut auth = Vec::with_capacity(2 + 32);
            auth.push(VERSION_V4);
            auth.push(COMMAND_AUTHENTICATE);
            auth.extend_from_slice(&super::blake3::hash32(token.expose().as_bytes()));
            auth
        }
        None => {
            let mut token = [0u8; 32];
            quic::export_keying_material(
                connection,
                &mut token,
                &option.uuid,
                option.password.expose().as_bytes(),
            )?;
            let mut auth = Vec::with_capacity(2 + 16 + 32);
            auth.push(VERSION_V5);
            auth.push(COMMAND_AUTHENTICATE);
            auth.extend_from_slice(&option.uuid);
            auth.extend_from_slice(&token);
            auth
        }
    };
    let mut stream = tokio::time::timeout(request_timeout, connection.open_uni())
        .await
        .map_err(|_| timeout_error(request_timeout))?
        .map_err(|e| DialError::Handshake {
            protocol: "tuic",
            source: io::Error::other(format!("open unidirectional stream: {e}")),
        })?;
    tokio::time::timeout(request_timeout, stream.write_all(&auth))
        .await
        .map_err(|_| timeout_error(request_timeout))?
        .map_err(|e| DialError::Handshake {
            protocol: "tuic",
            source: io::Error::other(format!("authentication: {e}")),
        })?;
    stream.finish().map_err(|e| DialError::Handshake {
        protocol: "tuic",
        source: io::Error::other(format!("authentication finish: {e}")),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_encoding_uses_tuic_type_numbers() {
        let v4 = encode_address(&Target {
            host: "127.0.0.1".into(),
            port: 443,
        })
        .unwrap();
        assert_eq!(v4, vec![1, 127, 0, 0, 1, 1, 187]);
        let v6 = encode_address(&Target {
            host: "::1".into(),
            port: 1,
        })
        .unwrap();
        assert_eq!(v6[0], 2);
        assert_eq!(v6.len(), 19);
        let name = encode_address(&Target {
            host: "example.org".into(),
            port: 80,
        })
        .unwrap();
        assert_eq!(&name[..2], &[0, 11]);
        assert_eq!(&name[2..13], b"example.org");
        assert_eq!(&name[13..], &[0, 80]);
        let (target, used) = read_address(&name, 0).unwrap();
        assert_eq!(target.host, "example.org");
        assert_eq!(target.port, 80);
        assert_eq!(used, name.len());
    }

    #[test]
    fn empty_domain_is_rejected() {
        assert!(encode_address(&Target {
            host: String::new(),
            port: 1
        })
        .is_err());
    }

    #[test]
    fn cwnd_only_applies_to_bbr() {
        // TUIC uses quic-go's default InitialPacketSize (1280); masque sets
        // 1242, so the same `cwnd` yields different byte windows per family.
        assert_eq!(
            congestion_tuning(Some("bbr"), 64, 1280),
            (CongestionController::Bbr, Some(64 * 1280))
        );
        assert_eq!(
            congestion_tuning(Some("bbr"), 0, 1280),
            (CongestionController::Bbr, Some(32 * 1280))
        );
        assert_eq!(
            congestion_tuning(Some("bbr"), 64, 1242),
            (CongestionController::Bbr, Some(64 * 1242))
        );
        // Pinned `common.SetCongestionController`: "bbr_meta_v2" shares the
        // `bbr` branch (and the cwnd-derived initial window).
        assert_eq!(
            congestion_tuning(Some("bbr_meta_v2"), 64, 1280),
            (CongestionController::Bbr, Some(64 * 1280))
        );
        assert_eq!(
            congestion_tuning(Some("bbr_meta_v2"), 0, 1242),
            (CongestionController::Bbr, Some(32 * 1242))
        );
        assert_eq!(
            congestion_tuning(Some("cubic"), 64, 1280),
            (CongestionController::Cubic, None)
        );
        assert_eq!(
            congestion_tuning(Some("new_reno"), 64, 1280),
            (CongestionController::NewReno, None)
        );
        assert_eq!(
            congestion_tuning(None, 64, 1280),
            (CongestionController::Default, None)
        );
    }

    #[test]
    fn bbr_profile_maps_to_the_initial_window() {
        assert_eq!(
            congestion_tuning_profile(Some("bbr"), 64, Some("standard"), 1280),
            (CongestionController::Bbr, Some(32 * 1280))
        );
        assert_eq!(
            congestion_tuning_profile(Some("bbr"), 64, Some("conservative"), 1280),
            (CongestionController::Bbr, Some(24 * 1280))
        );
        assert_eq!(
            congestion_tuning_profile(Some("bbr"), 64, Some("aggressive"), 1280),
            (CongestionController::Bbr, Some(40 * 1280))
        );
        // The profile only reaches the BBR branch.
        assert_eq!(
            congestion_tuning_profile(Some("cubic"), 64, Some("aggressive"), 1280),
            (CongestionController::Cubic, None)
        );
    }

    #[test]
    fn v5_packet_round_trips_with_the_pinned_layout() {
        let target = Target {
            host: "1.2.3.4".into(),
            port: 53,
        };
        let packet = TuicPacket {
            assoc_id: 0x0102,
            packet_id: 0x0304,
            fragment_total: 2,
            fragment_id: 0,
            target: target.clone(),
            data: b"hello".to_vec(),
        };
        let bytes = packet.encode(VERSION_V5).unwrap();
        // head(2) assoc(2) packet(2) total(1) frag(1) size(2) addr(7) data(5)
        assert_eq!(bytes.len(), 2 + 2 + 2 + 1 + 1 + 2 + 7 + 5);
        assert_eq!(&bytes[..2], &[VERSION_V5, COMMAND_PACKET]);
        assert_eq!(TuicPacket::decode(VERSION_V5, &bytes), Some(packet));
        // A non-first fragment carries `AtypNone` (255) with no address/port.
        let later = TuicPacket {
            assoc_id: 0x0102,
            packet_id: 0x0304,
            fragment_total: 2,
            fragment_id: 1,
            target: target.clone(),
            data: b"hello".to_vec(),
        }
        .encode(VERSION_V5)
        .unwrap();
        assert_eq!(later.len(), 2 + 2 + 2 + 1 + 1 + 2 + 1 + 5);
        let decoded = TuicPacket::decode(VERSION_V5, &later).expect("non-first fragment");
        assert_eq!(decoded.fragment_id, 1);
        assert_eq!(decoded.target.host, "");
        assert_eq!(decoded.data, b"hello");
        assert_eq!(packet_overhead(VERSION_V5), 2 + 2 + 2 + 1 + 1 + 2 + 19);
    }

    #[test]
    fn v4_packet_round_trips_and_uses_u32_assoc_and_u16_length() {
        let target = Target {
            host: "example.org".into(),
            port: 443,
        };
        let packet = TuicPacket {
            assoc_id: 0x0102_0304,
            packet_id: 0,
            fragment_total: 1,
            fragment_id: 0,
            target: target.clone(),
            data: b"hi".to_vec(),
        };
        let bytes = packet.encode(VERSION_V4).unwrap();
        assert_eq!(&bytes[..2], &[VERSION_V4, COMMAND_PACKET]);
        assert_eq!(bytes.len(), 2 + 4 + 2 + 15 + 2);
        let decoded = TuicPacket::decode(VERSION_V4, &bytes).unwrap();
        assert_eq!(decoded.assoc_id, 0x0102_0304);
        assert_eq!(decoded.fragment_total, 1);
        assert_eq!(decoded.target, target);
        assert_eq!(decoded.data, b"hi");
        assert_eq!(packet_overhead(VERSION_V4), 2 + 4 + 2 + 19);
    }

    #[test]
    fn fragments_reassemble_and_expire() {
        let target = Target {
            host: "1.2.3.4".into(),
            port: 53,
        };
        let mut fragments = TuicFragments::default();
        assert!(fragments
            .feed(TuicPacket {
                assoc_id: 1,
                packet_id: 7,
                fragment_total: 2,
                fragment_id: 1,
                target: target.clone(),
                data: b"world".to_vec(),
            })
            .is_none());
        let (from, payload) = fragments
            .feed(TuicPacket {
                assoc_id: 1,
                packet_id: 7,
                fragment_total: 2,
                fragment_id: 0,
                target: target.clone(),
                data: b"hello ".to_vec(),
            })
            .expect("complete");
        assert_eq!(from, target);
        assert_eq!(payload, b"hello world");
    }

    #[test]
    fn uot_address_round_trips() {
        for target in [
            Target {
                host: "1.2.3.4".into(),
                port: 53,
            },
            Target {
                host: "::1".into(),
                port: 443,
            },
            Target {
                host: "example.org".into(),
                port: 80,
            },
        ] {
            let bytes = uot_address(&target);
            let (read, used) = parse_uot_address(&bytes, 0).unwrap();
            assert_eq!(read, target);
            assert_eq!(used, bytes.len());
        }
    }
}
