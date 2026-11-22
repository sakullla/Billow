//! MASQUE CONNECT-IP (RFC 9484) over the in-tree HTTP/3 client.
//!
//! This is the pinned `masque` adapter's shape: a Cloudflare WARP client that
//! presents a generated client certificate, pins the endpoint public key,
//! opens one extended-CONNECT request with `:protocol cf-connect-ip` and then
//! exchanges **whole IP packets** with the proxy. The kernel's own minimal
//! IP stack ([`super::ipstack`]) parses and builds those packets; this module
//! carries them and implements the tunnel's control plane:
//!
//! 1. one QUIC connection (`ALPN h3`), QUIC datagrams enabled, the HTTP/3
//!    control stream advertising `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08),
//!    `SETTINGS_H3_DATAGRAM` (0x33) and the draft-00 identifier (0x276) the
//!    pinned adapter also sends. The peer must advertise extended CONNECT and
//!    HTTP Datagrams; CONNECT-IP without datagrams has no data path, so that
//!    is a named handshake failure instead of a silent fallback.
//! 2. one request stream: `:method CONNECT`, `:protocol cf-connect-ip`
//!    (RFC 9484 registers `connect-ip`; the pinned WARP adapter sends the
//!    Cloudflare spelling and its endpoint requires it), `:scheme https`,
//!    `:authority`/`:path` from `uri` (default `https://cloudflareaccess.com`)
//!    and `capsule-protocol: ?1`. A `2xx` response with `capsule-protocol: ?1`
//!    starts the capsule stream.
//! 3. control capsules on the request stream (RFC 9484 §5): the client sends
//!    `ROUTE_ADVERTISEMENT` (0x03) for `0.0.0.0`–`255.255.255.255` and `::`–the
//!    all-ones address with IP protocol 0, exactly as the pinned adapter does,
//!    and reads the peer's `ADDRESS_ASSIGN` (0x01) and `ROUTE_ADVERTISEMENT`.
//!    `ADDRESS_REQUEST` (0x02) asks the client to assign addresses to the peer;
//!    there is no address-assignment policy here, so it fails the association
//!    by name (the pinned client also errors).
//! 4. IP packets as HTTP Datagrams (RFC 9297 §2.1): a QUIC DATAGRAM frame
//!    carrying the quarter stream ID, Context ID 0 and the packet. Inbound
//!    `DATAGRAM` capsules (type 0x00) are accepted too, since they are the
//!    stream form of the same HTTP Datagram payload; outbound packets always
//!    use datagram frames (what the pinned adapter sends).
//!
//! UDP is the only terminated transport: a UDP socket table maps each
//! destination to a local source port, so replies are matched back to the
//! SOCKS5 association. TCP would need a full TCP state machine (the pinned
//! adapter uses mipstack or gVisor); `masque::dial` refuses it by name.
//!
//! Memory: the association owns one QUIC connection with the T10 windows
//! (512 KiB stream / 2 MiB connection receive, 2 MiB send), 64 KiB datagram
//! receive and send buffers, one request stream with a bounded capsule buffer,
//! and at most [`MAX_CONCURRENT_DESTINATIONS`] UDP flows. The packet buffers
//! are MTU-bounded (`mtu`, pinned default 1280) and the inbound channel holds
//! at most [`INBOUND_QUEUE`] packets; worst-case totals are in
//! `tool/kernel-compat/evidence/t18-feasibility.json`.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn::SendStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tracing::debug;

use super::h3::{self, Session};
use super::ipstack::{self, IpPrefix};
use super::quic::{self, QuicOptions};
use super::tcp::{TcpConfig, TcpConnection};
use super::tls::ClientTls;
use super::warp;
use super::{DialError, Target};
use crate::proxies::MasqueOutbound;

/// Capsule `ADDRESS_ASSIGN` (RFC 9484 §5.1).
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
/// Capsule `ADDRESS_REQUEST` (RFC 9484 §5.2).
pub const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;
/// Capsule `ROUTE_ADVERTISEMENT` (RFC 9484 §5.3).
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;
/// Capsule `DATAGRAM` (RFC 9297 §2.2): one HTTP Datagram in the stream form.
const CAPSULE_DATAGRAM: u64 = 0x00;

/// One capsule body. A control capsule is small (the pinned adapter advertises
/// two full-address ranges and a WARP endpoint assigns a handful of prefixes);
/// a `DATAGRAM` capsule carries one IP packet, so 1536 bytes covers an
/// MTU-sized packet (default 1280) plus its context ID. A larger capsule is
/// refused instead of being buffered.
const MAX_CAPSULE_VALUE: usize = 1536;

/// One HTTP/3 DATA frame read from the request stream. A control capsule is a
/// few bytes and one datagram capsule carries at most one IP packet (the
/// tunnel MTU), so 2 KiB covers every frame this client asked for; a larger
/// frame fails the association (local bound, recorded in evidence).
const MAX_DATA_FRAME: usize = 2048;

/// Bounded capsule buffer while a capsule spans DATA frames.
const MAX_PENDING_CAPSULES: usize = 2 * MAX_CAPSULE_VALUE;

/// Inbound IP packets waiting for the UDP association. A peer that floods
/// faster than the association drains is shed here (QUIC datagram buffers and
/// flow control already bound the connection) instead of growing without
/// limit.
const INBOUND_QUEUE: usize = 4;

/// Datagrams received during a tunnel-DNS lookup that were not the answer are
/// held for the application (bounded, oldest dropped first).
const MAX_PENDING_DATAGRAMS: usize = 8;

/// UDP flows per association; the same bound as CONNECT-UDP, so one hostile
/// association cannot pin unbounded per-destination state.
pub const MAX_CONCURRENT_DESTINATIONS: usize = 32;

/// IPv4 TTL / IPv6 hop limit of built packets. The tunnel is a single hop; the
/// peer's stack handles the rest.
const HOP_LIMIT: u8 = 64;

/// DNS over the tunnel: one query gets one datagram answer; the pinned
/// resolver has its own timeouts, this one only bounds one query.
const DNS_TIMEOUT: Duration = Duration::from_secs(3);

/// One IP route the peer advertised (or we advertised to it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRoute {
    pub start: IpAddr,
    pub end: IpAddr,
    /// Internet Protocol Number the route carries; 0 means every protocol.
    pub protocol: u8,
}

/// One `ADDRESS_ASSIGN` entry: the peer assigns `prefix` to this client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressAssignment {
    pub request_id: u64,
    pub prefix: IpPrefix,
}

/// Encode one capsule: type, length, value.
fn encode_capsule(kind: u64, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 16);
    h3::encode_varint(kind, &mut out);
    h3::encode_varint(value.len() as u64, &mut out);
    out.extend_from_slice(value);
    out
}

/// The body of one `ROUTE_ADVERTISEMENT` capsule.
pub fn route_advertisement_value(routes: &[IpRoute]) -> Vec<u8> {
    let mut value = Vec::new();
    for route in routes {
        match (route.start, route.end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                value.push(4);
                value.extend_from_slice(&start.octets());
                value.extend_from_slice(&end.octets());
            }
            (IpAddr::V6(start), IpAddr::V6(end)) => {
                value.push(6);
                value.extend_from_slice(&start.octets());
                value.extend_from_slice(&end.octets());
            }
            _ => continue,
        }
        value.push(route.protocol);
    }
    value
}

/// The body of one `ADDRESS_ASSIGN` capsule.
pub fn address_assign_value(assignments: &[AddressAssignment]) -> Vec<u8> {
    let mut value = Vec::new();
    for assignment in assignments {
        h3::encode_varint(assignment.request_id, &mut value);
        match assignment.prefix.addr {
            IpAddr::V4(addr) => {
                value.push(4);
                value.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                value.push(6);
                value.extend_from_slice(&addr.octets());
            }
        }
        value.push(assignment.prefix.bits);
    }
    value
}

fn decode_value(bytes: &[u8], pos: &mut usize, length: usize) -> Option<Vec<u8>> {
    let end = pos.checked_add(length)?;
    let value = bytes.get(*pos..end)?.to_vec();
    *pos = end;
    Some(value)
}

/// Parse an `ADDRESS_ASSIGN` body. RFC 9484 §5.1: a sequence of
/// `Request ID (varint) | IP Version (4 or 6) | IP Address | IP Prefix Length`.
pub fn parse_address_assign(value: &[u8]) -> Result<Vec<AddressAssignment>, String> {
    let mut assignments = Vec::new();
    let mut pos = 0;
    while pos < value.len() {
        let request_id = h3::decode_varint(value, &mut pos)
            .ok_or_else(|| "truncated ADDRESS_ASSIGN request ID".to_string())?;
        let version = *value
            .get(pos)
            .ok_or_else(|| "truncated ADDRESS_ASSIGN IP version".to_string())?;
        pos += 1;
        let width = match version {
            4 => 4,
            6 => 16,
            other => return Err(format!("ADDRESS_ASSIGN IP version {other}")),
        };
        let address = decode_value(value, &mut pos, width)
            .ok_or_else(|| "truncated ADDRESS_ASSIGN address".to_string())?;
        let bits = *value
            .get(pos)
            .ok_or_else(|| "truncated ADDRESS_ASSIGN prefix length".to_string())?;
        pos += 1;
        let addr = match width {
            4 => {
                IpAddr::from(<[u8; 4]>::try_from(address.as_slice()).map_err(|_| "4".to_string())?)
            }
            _ => IpAddr::from(
                <[u8; 16]>::try_from(address.as_slice()).map_err(|_| "16".to_string())?,
            ),
        };
        if u16::from(bits) > if width == 4 { 32u16 } else { 128u16 } {
            return Err(format!("ADDRESS_ASSIGN prefix length {bits}"));
        }
        let prefix = IpPrefix { addr, bits };
        if prefix.network() != addr {
            return Err("ADDRESS_ASSIGN prefix has host bits set".to_string());
        }
        assignments.push(AddressAssignment { request_id, prefix });
    }
    Ok(assignments)
}

/// Parse a `ROUTE_ADVERTISEMENT` body. RFC 9484 §5.3: a sequence of
/// `IP Version | Start IP | End IP | IP Protocol`.
pub fn parse_route_advertisement(value: &[u8]) -> Result<Vec<IpRoute>, String> {
    let mut routes = Vec::new();
    let mut pos = 0;
    while pos < value.len() {
        let version = *value
            .get(pos)
            .ok_or_else(|| "truncated ROUTE_ADVERTISEMENT IP version".to_string())?;
        pos += 1;
        let width = match version {
            4 => 4,
            6 => 16,
            other => return Err(format!("ROUTE_ADVERTISEMENT IP version {other}")),
        };
        let start = decode_value(value, &mut pos, width)
            .ok_or_else(|| "truncated ROUTE_ADVERTISEMENT start address".to_string())?;
        let end = decode_value(value, &mut pos, width)
            .ok_or_else(|| "truncated ROUTE_ADVERTISEMENT end address".to_string())?;
        let protocol = *value
            .get(pos)
            .ok_or_else(|| "truncated ROUTE_ADVERTISEMENT protocol".to_string())?;
        pos += 1;
        let (start, end) = match width {
            4 => (
                IpAddr::from(<[u8; 4]>::try_from(start.as_slice()).map_err(|_| "4".to_string())?),
                IpAddr::from(<[u8; 4]>::try_from(end.as_slice()).map_err(|_| "4".to_string())?),
            ),
            _ => (
                IpAddr::from(<[u8; 16]>::try_from(start.as_slice()).map_err(|_| "16".to_string())?),
                IpAddr::from(<[u8; 16]>::try_from(end.as_slice()).map_err(|_| "16".to_string())?),
            ),
        };
        if ip_compare(start, end).is_gt() {
            return Err("ROUTE_ADVERTISEMENT start address is after its end".to_string());
        }
        routes.push(IpRoute {
            start,
            end,
            protocol,
        });
    }
    Ok(routes)
}

fn ip_compare(left: IpAddr, right: IpAddr) -> std::cmp::Ordering {
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => left.cmp(&right),
        (IpAddr::V6(left), IpAddr::V6(right)) => left.cmp(&right),
        (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Less,
        (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Greater,
    }
}

/// Parse `uri` (the pinned `uri` option, default `https://cloudflareaccess.com`)
/// into the request's `:authority` and `:path`. RFC 9484 §3.1 builds the
/// request from the proxy URI; the pinned adapter refuses a URI template with
/// variables ("IP flow forwarding not supported"), which is refused here too.
pub fn parse_connect_uri(uri: &str) -> Result<(String, String), String> {
    if uri.contains('{') || uri.contains('}') {
        return Err(format!(
            "option 'uri' value '{uri}' uses a URI template variable: IP flow forwarding (RFC 9484 §8.2) is not implemented"
        ));
    }
    let rest = uri
        .strip_prefix("https://")
        .ok_or_else(|| format!("option 'uri' value '{uri}' must be an absolute https URI"))?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(format!("option 'uri' value '{uri}' has no authority"));
    }
    if authority.contains('@') || authority.contains('?') || authority.contains('#') {
        return Err(format!(
            "option 'uri' value '{uri}' has userinfo, a query or a fragment where only an authority is expected"
        ));
    }
    let path = if path.starts_with('/') { path } else { "/" };
    Ok((authority.to_string(), path.to_string()))
}

/// One inbound IP packet (or the reader's terminal error).
type InboundItem = Result<Vec<u8>, String>;

/// One live UDP flow: the local source address/port a reply is addressed to.
struct Flow {
    local: IpAddr,
    port: u16,
    last_used: Instant,
}

/// One CONNECT-IP tunnel: the QUIC/HTTP3 session, its request stream, the
/// local addresses and the inbound IP-packet queue. Both data paths (UDP for
/// the SOCKS5 relay, TCP for a `dial`) share it, so the handshake, the
/// capsules and the datagram framing exist once.
pub struct ConnectIpSession {
    session: Session,
    /// Quarter stream ID of the request stream (RFC 9297 §2.1).
    quarter_stream_id: u64,
    /// The request stream's send half; kept open for the association's
    /// lifetime (closing it ends the tunnel).
    send: SendStream,
    /// Local addresses from `ip`/`ipv6`; the first of the matching family is
    /// the source address of a built packet.
    local: Vec<IpPrefix>,
    mtu: usize,
    /// Prefixes the peer assigned via `ADDRESS_ASSIGN`.
    assigned: Arc<Mutex<Vec<IpPrefix>>>,
    /// Routes the peer advertised as reachable.
    routes: Arc<Mutex<Vec<IpRoute>>>,
    timeout: Duration,
    inbound: mpsc::Receiver<InboundItem>,
}

impl ConnectIpSession {
    /// Open the QUIC connection, the HTTP/3 session and the CONNECT-IP request.
    pub async fn open(
        option: &MasqueOutbound,
        timeout: Duration,
    ) -> Result<ConnectIpSession, DialError> {
        let Some(warp) = &option.connect_ip else {
            return Err(handshake(
                io::ErrorKind::InvalidInput,
                "CONNECT-IP needs the WARP shape (private-key/public-key and ip/ipv6)",
            ));
        };
        let identity = warp::parse_private_key(warp.private_key.expose())
            .map_err(|error| handshake(io::ErrorKind::InvalidInput, format!("masque {error}")))?;
        let pin = if option.tls_settings.skip_cert_verify {
            None
        } else {
            Some(warp.public_key_der.clone())
        };
        let alpn = vec!["h3".to_string()];
        let client_config = warp::client_config(pin, &identity, &alpn, true)
            .map_err(|error| handshake(io::ErrorKind::Other, format!("masque TLS: {error}")))?;
        let handshake_timeout = if option.handshake_timeout == 0 {
            timeout
        } else {
            Duration::from_secs(option.handshake_timeout)
        };
        let mut quic_options = QuicOptions::new(alpn.clone());
        quic_options.keep_alive = Some(Duration::from_secs(30));
        quic_options.datagrams = true;
        quic_options.datagram_receive_buffer = Some(64 * 1024);
        quic_options.datagram_send_buffer = Some(64 * 1024);
        // The pinned adapter's SNI default; the certificate name is not
        // verified either way (the endpoint is authenticated by the pin).
        let server_name = option
            .tls_settings
            .sni
            .clone()
            .unwrap_or_else(|| DEFAULT_WARP_SNI.to_string());
        let (connection, endpoint) = quic::connect_with_tls_config(
            &server_name,
            &option.server,
            option.port,
            &quic_options,
            client_config,
            handshake_timeout,
        )
        .await?;
        // SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_H3_DATAGRAM and the
        // draft-00 datagram identifier; the pinned adapter sends all three.
        let settings = &[(0x08, 1), (0x33, 1), (0x276, 1)];
        let session = match tokio::time::timeout(
            handshake_timeout,
            Session::open_with_settings(connection, endpoint, settings),
        )
        .await
        {
            Ok(Ok(session)) => session,
            Ok(Err(source)) => {
                return Err(DialError::Handshake {
                    protocol: "masque",
                    source,
                })
            }
            Err(_) => return Err(DialError::Timeout(handshake_timeout)),
        };
        match session.settings() {
            Some(settings) if settings.enable_connect_protocol => {}
            Some(_) => {
                return Err(handshake(
                    io::ErrorKind::Unsupported,
                    "HTTP/3 peer did not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220 extended CONNECT)",
                ))
            }
            None => {
                return Err(handshake(
                    io::ErrorKind::Unsupported,
                    "HTTP/3 peer settings were not read; CONNECT-IP needs extended CONNECT and HTTP Datagrams",
                ))
            }
        }
        if !session.settings().map(|s| s.h3_datagram).unwrap_or(false) {
            return Err(handshake(
                io::ErrorKind::Unsupported,
                "CONNECT-IP needs HTTP Datagrams (SETTINGS_H3_DATAGRAM 0x33 or 0x276) and the peer did not advertise them",
            ));
        }
        let headers: [(&str, &str); 7] = [
            (":method", "CONNECT"),
            (":protocol", "cf-connect-ip"),
            (":scheme", "https"),
            (":authority", warp.uri_authority.as_str()),
            (":path", warp.uri_path.as_str()),
            ("capsule-protocol", "?1"),
            ("user-agent", ""),
        ];
        let (mut send, mut recv) =
            match tokio::time::timeout(handshake_timeout, session.open_request(&headers)).await {
                Ok(Ok(pair)) => pair,
                Ok(Err(source)) => {
                    return Err(DialError::Handshake {
                        protocol: "masque",
                        source,
                    })
                }
                Err(_) => return Err(DialError::Timeout(handshake_timeout)),
            };
        let quarter_stream_id = send.id().index();
        let response =
            match tokio::time::timeout(handshake_timeout, h3::read_response(&mut recv)).await {
                Ok(Ok(response)) => response,
                Ok(Err(source)) => {
                    return Err(DialError::Handshake {
                        protocol: "masque",
                        source,
                    })
                }
                Err(_) => return Err(DialError::Timeout(handshake_timeout)),
            };
        if !(200..300).contains(&response.status) {
            return Err(DialError::Handshake {
                protocol: "masque",
                source: io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "CONNECT-IP request to {} was refused with status {}",
                        warp.uri_authority, response.status
                    ),
                ),
            });
        }
        match response.get("capsule-protocol") {
            Some(value) if value.trim() == "?1" => {}
            _ => return Err(handshake(
                io::ErrorKind::Unsupported,
                "CONNECT-IP response did not select the capsule protocol (Capsule-Protocol: ?1)",
            )),
        }
        // The pinned adapter advertises every IPv4 and IPv6 destination with
        // protocol 0 before checking the response status.
        let routes = vec![
            IpRoute {
                start: IpAddr::from([0, 0, 0, 0]),
                end: IpAddr::from([255, 255, 255, 255]),
                protocol: 0,
            },
            IpRoute {
                start: IpAddr::from([0u16; 8]),
                end: IpAddr::from([u16::MAX; 8]),
                protocol: 0,
            },
        ];
        let mut advertisement = Vec::new();
        h3::encode_varint(0x00, &mut advertisement); // DATA
        let value = route_advertisement_value(&routes);
        let capsule = encode_capsule(CAPSULE_ROUTE_ADVERTISEMENT, &value);
        h3::encode_varint(capsule.len() as u64, &mut advertisement);
        advertisement.extend_from_slice(&capsule);
        send.write_all(&advertisement)
            .await
            .map_err(|source| DialError::Handshake {
                protocol: "masque",
                source: io::Error::other(format!("ROUTE_ADVERTISEMENT: {source}")),
            })?;

        let assigned = Arc::new(Mutex::new(Vec::new()));
        let routes_seen = Arc::new(Mutex::new(Vec::new()));
        let (inbound_tx, inbound) = mpsc::channel(INBOUND_QUEUE);
        // Datagram reader: every IP packet the peer sends arrives here.
        let connection = session.connection().clone();
        let datagram_tx = inbound_tx.clone();
        tokio::spawn(async move {
            loop {
                match connection.read_datagram().await {
                    Ok(datagram) => {
                        if let Some(packet) = datagram_payload(&datagram, quarter_stream_id) {
                            if datagram_tx.send(Ok(packet)).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        let _ = datagram_tx
                            .send(Err(format!("QUIC datagram read ended: {error}")))
                            .await;
                        return;
                    }
                }
            }
        });
        // Capsule reader: control capsules update the shared state, datagram
        // capsules feed the same inbound queue as QUIC datagram frames.
        let capsule_tx = inbound_tx.clone();
        let assigned_seen = assigned.clone();
        let routes_state = routes_seen.clone();
        tokio::spawn(async move {
            let mut pending = Vec::new();
            loop {
                let frame = match h3::read_frame_limited(&mut recv, MAX_DATA_FRAME as u64).await {
                    Ok(Some(frame)) => frame,
                    Ok(None) => {
                        let _ = capsule_tx
                            .send(Err("CONNECT-IP request stream ended".to_string()))
                            .await;
                        return;
                    }
                    Err(error) => {
                        let _ = capsule_tx
                            .send(Err(format!("CONNECT-IP request stream: {error}")))
                            .await;
                        return;
                    }
                };
                if frame.0 != 0x00 {
                    continue;
                }
                pending.extend_from_slice(&frame.1);
                loop {
                    let (kind, value) = match next_capsule(&mut pending) {
                        Ok(Some(capsule)) => capsule,
                        Ok(None) => break,
                        Err(error) => {
                            let _ = capsule_tx
                                .send(Err(format!("CONNECT-IP capsule: {error}")))
                                .await;
                            return;
                        }
                    };
                    match kind {
                        CAPSULE_ADDRESS_ASSIGN => match parse_address_assign(&value) {
                            Ok(assignments) => {
                                let prefixes: Vec<IpPrefix> =
                                    assignments.iter().map(|entry| entry.prefix).collect();
                                *assigned_seen.lock().unwrap() = prefixes;
                            }
                            Err(error) => {
                                let _ = capsule_tx
                                    .send(Err(format!("ADDRESS_ASSIGN: {error}")))
                                    .await;
                                return;
                            }
                        },
                        CAPSULE_ADDRESS_REQUEST => {
                            let _ = capsule_tx
                                .send(Err("the peer sent ADDRESS_REQUEST: assigning addresses to the peer needs an address-assignment policy this kernel does not implement".to_string()))
                                .await;
                            return;
                        }
                        CAPSULE_ROUTE_ADVERTISEMENT => match parse_route_advertisement(&value) {
                            Ok(routes) => *routes_state.lock().unwrap() = routes,
                            Err(error) => {
                                let _ = capsule_tx
                                    .send(Err(format!("ROUTE_ADVERTISEMENT: {error}")))
                                    .await;
                                return;
                            }
                        },
                        CAPSULE_DATAGRAM => match capsule_datagram_payload(&value) {
                            Some(packet) => {
                                if capsule_tx.send(Ok(packet)).await.is_err() {
                                    return;
                                }
                            }
                            None => debug!(
                                "masque CONNECT-IP datagram capsule has a non-zero context ID"
                            ),
                        },
                        // RFC 9297 §3.3: unknown capsule types are ignored.
                        _ => {}
                    }
                }
                if pending.len() > MAX_PENDING_CAPSULES {
                    let _ = capsule_tx
                        .send(Err(format!(
                            "CONNECT-IP capsule buffer exceeded {MAX_PENDING_CAPSULES} bytes"
                        )))
                        .await;
                    return;
                }
            }
        });

        Ok(ConnectIpSession {
            session,
            quarter_stream_id,
            send,
            local: warp.local.clone(),
            mtu: usize::from(warp.mtu),
            assigned,
            routes: routes_seen,
            timeout,
            inbound,
        })
    }

    /// Prefixes the peer assigned; empty until an `ADDRESS_ASSIGN` capsule
    /// arrives.
    pub fn assigned_prefixes(&self) -> Vec<IpPrefix> {
        self.assigned
            .lock()
            .map(|state| state.clone())
            .unwrap_or_default()
    }

    /// Routes the peer advertised as reachable.
    pub fn advertised_routes(&self) -> Vec<IpRoute> {
        self.routes
            .lock()
            .map(|state| state.clone())
            .unwrap_or_default()
    }

    /// The local addresses the configured `ip`/`ipv6` values select.
    pub fn local_prefixes(&self) -> &[IpPrefix] {
        &self.local
    }

    /// The configured `mtu`, the bound for one built packet.
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// The handshake/dial timeout the association was opened with.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Source address for a packet to `destination` (the first configured
    /// prefix of the same family), or `None` when that family is not
    /// configured.
    pub fn local_address(&self, destination: IpAddr) -> Option<IpAddr> {
        self.local
            .iter()
            .find(|prefix| prefix.addr.is_ipv4() == destination.is_ipv4())
            .map(|prefix| prefix.addr)
    }

    /// Send one IP packet as an HTTP Datagram (quarter stream ID, context 0).
    pub fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
        let mut datagram = Vec::with_capacity(packet.len() + 12);
        h3::encode_varint(self.quarter_stream_id, &mut datagram);
        h3::encode_varint(0, &mut datagram);
        datagram.extend_from_slice(packet);
        self.session
            .connection()
            .send_datagram(Bytes::from(datagram))
            .map_err(|error| match error {
                quinn::SendDatagramError::TooLarge => io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "masque CONNECT-IP: an IP packet of {} bytes exceeds the QUIC datagram limit of this connection (path MTU minus overhead); lower 'mtu'",
                        packet.len()
                    ),
                ),
                other => io::Error::other(format!("masque CONNECT-IP datagram: {other}")),
            })
    }

    /// Next inbound IP packet (a QUIC datagram frame or a DATAGRAM capsule).
    pub async fn recv_packet(&mut self) -> io::Result<Vec<u8>> {
        match self.inbound.recv().await {
            Some(Ok(packet)) => Ok(packet),
            Some(Err(error)) => Err(io::Error::other(error)),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "masque CONNECT-IP association closed",
            )),
        }
    }
}

impl Drop for ConnectIpSession {
    fn drop(&mut self) {
        // Closing the connection ends both reader tasks (their channel sends
        // fail and they return) instead of leaving them until the peer's idle
        // timeout.
        let _ = self.send.finish();
        self.session
            .close(0, "masque CONNECT-IP association closed");
    }
}

/// The UDP association of a CONNECT-IP tunnel (SOCKS5 UDP relay).
pub struct MasqueIp {
    session: ConnectIpSession,
    flows: HashMap<Target, Flow>,
    by_port: HashMap<u16, (Target, IpAddr, IpAddr)>,
    next_port: u16,
    pending: VecDeque<(Target, Vec<u8>)>,
    /// Name servers of `remote-dns-resolve`; `None` resolves locally.
    dns: Option<Vec<SocketAddr>>,
}

impl MasqueIp {
    /// Open the tunnel for the SOCKS5 UDP association.
    pub async fn connect(
        option: &MasqueOutbound,
        _tls: &ClientTls,
        timeout: Duration,
    ) -> Result<MasqueIp, DialError> {
        let session = ConnectIpSession::open(option, timeout).await?;
        let dns = match &option.connect_ip {
            Some(warp) if warp.remote_dns_resolve && !warp.dns.is_empty() => Some(warp.dns.clone()),
            _ => None,
        };
        Ok(MasqueIp {
            session,
            flows: HashMap::new(),
            by_port: HashMap::new(),
            next_port: FIRST_LOCAL_PORT,
            pending: VecDeque::new(),
            dns,
        })
    }

    /// Prefixes the peer assigned; empty until an `ADDRESS_ASSIGN` capsule
    /// arrives.
    pub fn assigned_prefixes(&self) -> Vec<IpPrefix> {
        self.session.assigned_prefixes()
    }

    /// Routes the peer advertised as reachable.
    pub fn advertised_routes(&self) -> Vec<IpRoute> {
        self.session.advertised_routes()
    }

    /// The local addresses the configured `ip`/`ipv6` values select.
    pub fn local_prefixes(&self) -> &[IpPrefix] {
        self.session.local_prefixes()
    }

    /// Send one UDP payload to `target` through the tunnel, opening a flow
    /// (a local source port) when this destination has none yet.
    pub async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        let destination = self.resolve(target).await?;
        self.send_ip(target, destination, payload).await
    }

    async fn send_ip(
        &mut self,
        target: &Target,
        destination: IpAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        let family_overhead = if destination.is_ipv4() {
            ipstack::IPV4_UDP_OVERHEAD
        } else {
            ipstack::IPV6_UDP_OVERHEAD
        };
        let mtu = self.session.mtu;
        if payload.len() > mtu.saturating_sub(family_overhead) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "masque CONNECT-IP datagram is {} bytes; the configured mtu {} allows at most {} payload bytes",
                    payload.len(),
                    mtu,
                    mtu.saturating_sub(family_overhead)
                ),
            ));
        }
        let local = self.session.local_address(destination).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "masque CONNECT-IP has no local {} address: set the 'ip'/'ipv6' option",
                    if destination.is_ipv4() {
                        "IPv4"
                    } else {
                        "IPv6"
                    }
                ),
            )
        })?;
        let port = self.flow_port(target, local, destination);
        let packet =
            ipstack::build_udp_packet(local, destination, port, target.port, payload, HOP_LIMIT)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        self.session.send_packet(&packet)
    }

    /// Receive one UDP payload; returns the destination it belongs to.
    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        loop {
            let (target, payload) = self.next_udp(None).await?;
            if payload.len() > buffer.len() {
                debug!(
                    bytes = payload.len(),
                    "masque CONNECT-IP datagram exceeds the receive buffer; dropped"
                );
                continue;
            }
            buffer[..payload.len()].copy_from_slice(&payload);
            return Ok(Some((target, payload.len())));
        }
    }

    /// Next inbound UDP datagram (from the pending queue or the tunnel).
    async fn next_udp(&mut self, deadline: Option<Instant>) -> io::Result<(Target, Vec<u8>)> {
        loop {
            if let Some((target, payload)) = self.pending.pop_front() {
                return Ok((target, payload));
            }
            let received = match deadline {
                Some(deadline) => {
                    let deadline = tokio::time::Instant::from_std(deadline);
                    match tokio::time::timeout_at(deadline, self.session.recv_packet()).await {
                        Ok(result) => result,
                        Err(_) => {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "masque CONNECT-IP receive timed out",
                            ))
                        }
                    }
                }
                None => self.session.recv_packet().await,
            };
            let packet = received?;
            let parsed = match ipstack::parse_ip_packet(&packet) {
                Ok(parsed) => parsed,
                Err(error) => {
                    debug!(%error, "masque CONNECT-IP inbound packet dropped");
                    continue;
                }
            };
            let udp = match ipstack::parse_udp(&parsed) {
                Ok(udp) => udp,
                Err(error) => {
                    debug!(%error, "masque CONNECT-IP inbound packet dropped");
                    continue;
                }
            };
            let Some((target, local, remote)) = self.by_port.get(&udp.dst_port) else {
                debug!(
                    port = udp.dst_port,
                    "masque CONNECT-IP inbound datagram for an unknown flow; dropped"
                );
                continue;
            };
            if udp.dst != *local || udp.src != *remote {
                debug!(
                    dst = %udp.dst,
                    src = %udp.src,
                    "masque CONNECT-IP inbound datagram does not match its flow; dropped"
                );
                continue;
            }
            let (target, payload) = (target.clone(), udp.payload.to_vec());
            return Ok((target, payload));
        }
    }

    /// The local port of the flow to `target`, reusing the existing flow or
    /// opening one. At the bound, the least recently used destination is
    /// evicted (UDP is connectionless; the next datagram reopens it).
    fn flow_port(&mut self, target: &Target, local: IpAddr, remote: IpAddr) -> u16 {
        let now = Instant::now();
        if let Some(flow) = self.flows.get_mut(target) {
            if flow.local == local {
                flow.last_used = now;
                let port = flow.port;
                self.by_port.insert(port, (target.clone(), local, remote));
                return port;
            }
            let previous = flow.port;
            self.by_port.remove(&previous);
        }
        if self.flows.len() >= MAX_CONCURRENT_DESTINATIONS {
            if let Some(oldest) = self
                .flows
                .iter()
                .min_by_key(|(_, flow)| flow.last_used)
                .map(|(target, _)| target.clone())
            {
                if let Some(flow) = self.flows.remove(&oldest) {
                    self.by_port.remove(&flow.port);
                }
                debug!("masque CONNECT-IP flow table full; evicted the oldest destination");
            }
        }
        let port = self.allocate_port();
        self.flows.insert(
            target.clone(),
            Flow {
                local,
                port,
                last_used: now,
            },
        );
        self.by_port.insert(port, (target.clone(), local, remote));
        port
    }

    fn allocate_port(&mut self) -> u16 {
        loop {
            let candidate = self.next_port;
            self.next_port = if candidate >= u16::MAX - 1 {
                FIRST_LOCAL_PORT
            } else {
                candidate + 1
            };
            if candidate >= FIRST_LOCAL_PORT && !self.by_port.contains_key(&candidate) {
                return candidate;
            }
        }
    }

    /// Resolve a target host to the tunnel's destination address: a literal is
    /// used as is, `remote-dns-resolve` queries the configured name servers
    /// through the tunnel itself, and otherwise the host resolves locally
    /// (the pinned adapter's default resolver).
    async fn resolve(&mut self, target: &Target) -> io::Result<IpAddr> {
        if let Ok(ip) = target.host.parse::<IpAddr>() {
            return Ok(ip);
        }
        let Some(servers) = self.dns.clone() else {
            let addr = super::resolve(&target.host, target.port)
                .await
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("resolve {}: {error}", target.host),
                    )
                })?;
            return Ok(addr.ip());
        };
        let mut last_error = None;
        for server in servers {
            for qtype in [1u16, 28u16] {
                match self.query_dns(server, &target.host, qtype).await {
                    Ok(answers) => {
                        if let Some(ip) = answers
                            .into_iter()
                            .find(|ip| self.session.local_address(*ip).is_some())
                        {
                            return Ok(ip);
                        }
                    }
                    Err(error) => last_error = Some(error),
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "masque CONNECT-IP DNS returned no address for '{}'",
                    target.host
                ),
            )
        }))
    }

    /// Query one tunnel name server for `qtype` and return its answer records.
    async fn query_dns(
        &mut self,
        server: SocketAddr,
        host: &str,
        qtype: u16,
    ) -> io::Result<Vec<IpAddr>> {
        let id = rand::random::<u16>();
        let query = dns_query(id, host, qtype)?;
        let dns_target = Target {
            host: server.ip().to_string(),
            port: server.port(),
        };
        self.send_ip(&dns_target, server.ip(), &query).await?;
        let deadline = Instant::now() + DNS_TIMEOUT.min(self.session.timeout());
        loop {
            let (target, payload) = match self.next_udp(Some(deadline)).await {
                Ok(pair) => pair,
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("masque CONNECT-IP DNS query to {server} timed out"),
                    ))
                }
                Err(error) => return Err(error),
            };
            if target != dns_target {
                // Only a payload that could still fit the tunnel MTU is worth
                // holding; a larger one could never be delivered anyway.
                if self.pending.len() < MAX_PENDING_DATAGRAMS && payload.len() <= self.session.mtu {
                    self.pending.push_back((target, payload));
                } else {
                    debug!("masque CONNECT-IP pending datagram dropped while resolving DNS");
                }
                continue;
            }
            return dns_answers(id, host, qtype, &payload);
        }
    }
}

// ---------------------------------------------------------------------------
// TCP over CONNECT-IP (T21).
//
// CONNECT-IP carries IP packets, so a TCP target is served by the in-tree
// minimal client in `outbound::tcp`: one tunnel and one TCP connection per
// `dial` (no pooling, like the other QUIC families). The two halves meet in an
// actor that owns the tunnel and the state machine: application bytes arrive
// on a channel, inbound IP packets on the other, and every timer/transmission
// decision belongs to the state machine.
// ---------------------------------------------------------------------------

/// Application commands for one tunnel TCP connection.
enum TcpCommand {
    Data(Vec<u8>),
    Shutdown,
}

type ReserveFuture = Pin<
    Box<
        dyn Future<Output = Result<mpsc::OwnedPermit<TcpCommand>, mpsc::error::SendError<()>>>
            + Send
            + 'static,
    >,
>;

/// An established TCP stream over a CONNECT-IP tunnel.
///
/// Reads yield the peer's bytes in order and end (EOF) when the peer's FIN
/// arrives; writes are queued and bounded by the TCP send buffer (64 KiB), and
/// `poll_shutdown` half-closes the connection with a FIN. Dropping the stream
/// closes the tunnel after the pending data has been acknowledged or the
/// connection times out.
pub struct MasqueTcpStream {
    to_network: mpsc::Sender<TcpCommand>,
    from_network: mpsc::Receiver<io::Result<Vec<u8>>>,
    read_buffer: Vec<u8>,
    read_offset: usize,
    write_reserve: Option<ReserveFuture>,
    shutdown_reserve: Option<ReserveFuture>,
    shutdown_sent: bool,
    eof: bool,
}

impl MasqueTcpStream {
    /// Open a tunnel and an active TCP connection to `target`.
    pub async fn connect(
        option: &MasqueOutbound,
        target: &Target,
        _tls: &ClientTls,
        timeout: Duration,
    ) -> Result<MasqueTcpStream, DialError> {
        let warp = option.connect_ip.as_ref().ok_or_else(|| {
            handshake(
                io::ErrorKind::Unsupported,
                "TCP over masque needs the CONNECT-IP (WARP) shape: the RFC 9298 CONNECT-UDP subset carries UDP only",
            )
        })?;
        let mut session = ConnectIpSession::open(option, timeout).await?;
        let remote = resolve_tcp(&mut session, warp, target, timeout).await?;
        let local = session.local_address(remote).ok_or_else(|| {
            handshake(
                io::ErrorKind::NotFound,
                format!(
                    "masque CONNECT-IP has no local {} address for TCP: set the 'ip'/'ipv6' option",
                    if remote.is_ipv4() { "IPv4" } else { "IPv6" }
                ),
            )
        })?;
        let overhead = if remote.is_ipv4() {
            ipstack::IPV4_UDP_OVERHEAD
        } else {
            ipstack::IPV6_UDP_OVERHEAD
        };
        let mss = session.mtu().saturating_sub(overhead).clamp(64, 65_495) as u16;
        let connect_deadline = Instant::now() + timeout;
        let config = TcpConfig {
            local,
            remote,
            local_port: random_local_port(),
            remote_port: target.port,
            mss,
            initial_seq: rand::random::<u32>(),
            connect_deadline,
            hop_limit: HOP_LIMIT,
        };
        let mut connection = TcpConnection::new(config, Instant::now());
        // Drive the handshake inline so a refusal or a timeout is a dial
        // failure (the caller answers 502), not a stream that fails later.
        loop {
            loop {
                let Some(packet) = connection.poll_transmit(Instant::now()) else {
                    break;
                };
                if packet.is_empty() {
                    continue;
                }
                session
                    .send_packet(&packet)
                    .map_err(|source| DialError::Handshake {
                        protocol: "masque tcp",
                        source,
                    })?;
            }
            if connection.established() {
                break;
            }
            if let Some(error) = connection.failure() {
                return Err(DialError::Handshake {
                    protocol: "masque tcp",
                    source: io::Error::new(error.kind(), error.to_string()),
                });
            }
            let now = Instant::now();
            if now >= connect_deadline {
                return Err(DialError::Timeout(timeout));
            }
            let timer = connection.next_timer();
            let sleep = async {
                match timer {
                    Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = sleep => connection.on_timer(Instant::now()),
                packet = session.recv_packet() => match packet {
                    Ok(packet) => connection.on_packet(&packet, Instant::now()),
                    Err(source) => return Err(DialError::Handshake { protocol: "masque tcp", source }),
                },
            }
        }
        let (to_network, commands) = mpsc::channel(4);
        let (out, from_network) = mpsc::channel(4);
        tokio::spawn(run_tcp(session, connection, commands, out));
        Ok(MasqueTcpStream {
            to_network,
            from_network,
            read_buffer: Vec::new(),
            read_offset: 0,
            write_reserve: None,
            shutdown_reserve: None,
            shutdown_sent: false,
            eof: false,
        })
    }
}

impl AsyncRead for MasqueTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.read_offset < this.read_buffer.len() {
                let available = &this.read_buffer[this.read_offset..];
                let count = available.len().min(buf.remaining());
                buf.put_slice(&available[..count]);
                this.read_offset += count;
                if this.read_offset == this.read_buffer.len() {
                    this.read_buffer.clear();
                    this.read_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match this.from_network.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(data))) => {
                    this.read_buffer = data;
                    this.read_offset = 0;
                }
                Poll::Ready(Some(Err(error))) => {
                    this.eof = true;
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(None) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for MasqueTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.shutdown_sent {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "masque TCP stream was shut down",
            )));
        }
        // Bound one accepted write: the channel and the state machine's
        // buffers then stay inside the recorded per-connection memory.
        let take = buf.len().min(MAX_TCP_WRITE_CHUNK);
        let buf = &buf[..take];
        loop {
            if this.write_reserve.is_none() {
                this.write_reserve = Some(Box::pin(this.to_network.clone().reserve_owned()));
            }
            let future = this.write_reserve.as_mut().expect("set above");
            match future.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(permit)) => {
                    this.write_reserve = None;
                    permit.send(TcpCommand::Data(buf.to_vec()));
                    return Poll::Ready(Ok(take));
                }
                Poll::Ready(Err(_)) => {
                    this.write_reserve = None;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "masque TCP connection is closed",
                    )));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Every accepted write is already queued in order; the TCP actor
        // sends it as the window allows.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.shutdown_sent {
            return Poll::Ready(Ok(()));
        }
        if this.shutdown_reserve.is_none() {
            this.shutdown_reserve = Some(Box::pin(this.to_network.clone().reserve_owned()));
        }
        let future = this.shutdown_reserve.as_mut().expect("set above");
        match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(permit)) => {
                this.shutdown_reserve = None;
                this.shutdown_sent = true;
                permit.send(TcpCommand::Shutdown);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => {
                this.shutdown_reserve = None;
                this.shutdown_sent = true;
                Poll::Ready(Ok(()))
            }
        }
    }
}

/// Drive one TCP connection over its tunnel until both directions end.
async fn run_tcp(
    mut session: ConnectIpSession,
    mut connection: TcpConnection,
    mut commands: mpsc::Receiver<TcpCommand>,
    out: mpsc::Sender<io::Result<Vec<u8>>>,
) {
    let mut out = Some(out);
    let mut deferred: Option<Vec<u8>> = None;
    loop {
        // Transmissions (data, ACKs, retransmissions, FIN).
        loop {
            let Some(packet) = connection.poll_transmit(Instant::now()) else {
                break;
            };
            if packet.is_empty() {
                continue;
            }
            if let Err(error) = session.send_packet(&packet) {
                if let Some(out) = out.as_ref() {
                    let _ = out.send(Err(error)).await;
                }
                return;
            }
        }
        // In-order payload for the application.
        if let Some(out) = out.as_ref() {
            while let Some(data) = connection.take_received() {
                if out.send(Ok(data)).await.is_err() {
                    return;
                }
            }
        } else {
            let _ = connection.take_received();
        }
        if let Some(error) = connection.failure() {
            if let Some(out) = out.as_ref() {
                let _ = out
                    .send(Err(io::Error::new(error.kind(), error.to_string())))
                    .await;
            }
            return;
        }
        // The peer's FIN ends the inbound direction: deliver the buffered data
        // (above) and then close the reader while writes may continue.
        if connection.peer_closed() && connection.received_empty() {
            out = None;
        }
        if connection.finished() {
            return;
        }
        if let Some(data) = deferred.take() {
            let accepted = connection.enqueue(&data);
            if accepted < data.len() {
                deferred = Some(data[accepted..].to_vec());
            }
        }
        let timer = connection.next_timer();
        let can_read = deferred.is_none() && connection.can_accept();
        let sleep = async {
            match timer {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            biased;
            _ = sleep => connection.on_timer(Instant::now()),
            command = commands.recv(), if can_read => {
                match command {
                Some(TcpCommand::Data(data)) => {
                    let accepted = connection.enqueue(&data);
                    if accepted < data.len() {
                        deferred = Some(data[accepted..].to_vec());
                    }
                }
                Some(TcpCommand::Shutdown) | None => connection.shutdown(),
                }
            },
            packet = session.recv_packet() => match packet {
                Ok(packet) => connection.on_packet(&packet, Instant::now()),
                Err(error) => {
                    // The tunnel ended before both directions closed: report
                    // it to the reader instead of a clean EOF.
                    if let Some(out) = out.as_ref() {
                        let _ = out.send(Err(error)).await;
                    }
                    return;
                }
            },
        }
    }
}

/// A local port for one tunnel TCP connection. The tunnel is dedicated, so
/// collisions only matter against the peer's notion of the same connection.
fn random_local_port() -> u16 {
    let span = u16::MAX - FIRST_LOCAL_PORT;
    FIRST_LOCAL_PORT + (rand::random::<u16>() % span.max(1))
}

/// Resolve a TCP target: a literal is used as is, `remote-dns-resolve` asks
/// the configured name servers through the tunnel, otherwise the host resolves
/// locally (the pinned adapter's default resolver).
async fn resolve_tcp(
    session: &mut ConnectIpSession,
    warp: &crate::proxies::MasqueConnectIp,
    target: &Target,
    timeout: Duration,
) -> Result<IpAddr, DialError> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        return Ok(ip);
    }
    if warp.remote_dns_resolve && !warp.dns.is_empty() {
        let deadline = Instant::now() + timeout;
        let mut last_error = None;
        for server in &warp.dns {
            for qtype in [1u16, 28u16] {
                match dns_over_tunnel(session, *server, &target.host, qtype, deadline).await {
                    Ok(answers) => {
                        if let Some(ip) = answers
                            .into_iter()
                            .find(|ip| session.local_address(*ip).is_some())
                        {
                            return Ok(ip);
                        }
                    }
                    Err(error) => last_error = Some(error),
                }
            }
        }
        return Err(DialError::Resolve {
            host: target.host.clone(),
            source: last_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "masque CONNECT-IP DNS returned no address",
                )
            }),
        });
    }
    let address = super::resolve(&target.host, target.port).await?;
    Ok(address.ip())
}

/// One DNS query carried as a UDP packet through the tunnel.
async fn dns_over_tunnel(
    session: &mut ConnectIpSession,
    server: SocketAddr,
    host: &str,
    qtype: u16,
    deadline: Instant,
) -> io::Result<Vec<IpAddr>> {
    let local = session.local_address(server.ip()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "no local {} address for the tunnel DNS server {server}",
                if server.is_ipv4() { "IPv4" } else { "IPv6" }
            ),
        )
    })?;
    let port = random_local_port();
    let id = rand::random::<u16>();
    let query = dns_query(id, host, qtype)?;
    let packet =
        ipstack::build_udp_packet(local, server.ip(), port, server.port(), &query, HOP_LIMIT)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    session.send_packet(&packet)?;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("masque CONNECT-IP DNS query to {server} timed out"),
            ));
        }
        let remaining = deadline.saturating_duration_since(now);
        let received = tokio::time::timeout(remaining, session.recv_packet()).await;
        let packet = match received {
            Ok(Ok(packet)) => packet,
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("masque CONNECT-IP DNS query to {server} timed out"),
                ))
            }
        };
        let parsed = match ipstack::parse_ip_packet(&packet) {
            Ok(parsed) => parsed,
            Err(_) => continue,
        };
        let udp = match ipstack::parse_udp(&parsed) {
            Ok(udp) => udp,
            Err(_) => continue,
        };
        if udp.src != server.ip() || udp.src_port != server.port() || udp.dst_port != port {
            continue;
        }
        return dns_answers(id, host, qtype, udp.payload);
    }
}

/// The pinned adapter's `ConnectSNI` (`transport/masque/masque.go`).
pub const DEFAULT_WARP_SNI: &str = "consumer-masque.cloudflareclient.com";

/// The pinned adapter's `ConnectURI` default.
pub const DEFAULT_WARP_URI: &str = "https://cloudflareaccess.com";

/// First local UDP port assigned to a tunnel flow. IANA's dynamic range
/// starts at 49152; using 40000–59999 keeps clear of the kernel's inbound
/// listeners and of the harness ports (24000–31999) the tests use.
const FIRST_LOCAL_PORT: u16 = 40_000;

/// One accepted application write. The engine's relay buffers 32 KiB per
/// direction; clamping here keeps one command bounded even for a caller that
/// writes a much larger slice (the write returns a short count, which is a
/// normal `AsyncWrite` outcome).
const MAX_TCP_WRITE_CHUNK: usize = 32 * 1024;

/// One `DATAGRAM` capsule body (RFC 9297 §2.2): Context ID then payload. The
/// capsule form carries no quarter stream ID (the stream identifies it).
fn capsule_datagram_payload(value: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    let context = h3::decode_varint(value, &mut pos)?;
    if context != 0 {
        return None;
    }
    Some(value[pos..].to_vec())
}

/// Check and strip the HTTP Datagram framing (RFC 9297 §2.1): quarter stream
/// ID, Context ID 0, then the payload. Datagrams for another quarter stream
/// ID or another context belong to the QUIC connection's other users and are
/// skipped (`None`).
fn datagram_payload(datagram: &[u8], quarter_stream_id: u64) -> Option<Vec<u8>> {
    let mut pos = 0;
    let quarter = h3::decode_varint(datagram, &mut pos)?;
    if quarter != quarter_stream_id {
        return None;
    }
    let context = h3::decode_varint(datagram, &mut pos)?;
    if context != 0 {
        return None;
    }
    Some(datagram[pos..].to_vec())
}

/// Take one complete capsule off `buffer`, leaving the remainder in place.
/// `Ok(None)` means the bytes so far are not a complete capsule yet; a capsule
/// body larger than [`MAX_CAPSULE_VALUE`] is an error (no control capsule this
/// client asked for is that large, so nothing is buffered).
fn next_capsule(buffer: &mut Vec<u8>) -> Result<Option<(u64, Vec<u8>)>, String> {
    let mut pos = 0;
    let Some(kind) = h3::decode_varint(buffer, &mut pos) else {
        return Ok(None);
    };
    let Some(length) = h3::decode_varint(buffer, &mut pos) else {
        return Ok(None);
    };
    let length = length as usize;
    if length > MAX_CAPSULE_VALUE {
        return Err(format!(
            "capsule of {length} bytes exceeds the {MAX_CAPSULE_VALUE}-byte bound"
        ));
    }
    let Some(end) = pos.checked_add(length) else {
        return Err("capsule length overflow".to_string());
    };
    if buffer.len() < end {
        return Ok(None);
    }
    let value = buffer[pos..end].to_vec();
    buffer.drain(..end);
    Ok(Some((kind, value)))
}

// ---------------------------------------------------------------------------
// Minimal DNS client (one question, UDP answers) for `remote-dns-resolve`.
// ---------------------------------------------------------------------------

/// A/AAAA answer records of a DNS response.
fn dns_answers(id: u16, host: &str, qtype: u16, response: &[u8]) -> io::Result<Vec<IpAddr>> {
    let malformed = |what: &str| io::Error::new(io::ErrorKind::InvalidData, format!("DNS: {what}"));
    if response.len() < 12 {
        return Err(malformed("response shorter than its header"));
    }
    let response_id = u16::from_be_bytes([response[0], response[1]]);
    if response_id != id {
        return Err(malformed("response ID does not match the query"));
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 {
        return Err(malformed("response is not marked as a response"));
    }
    if flags & 0x0200 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "DNS response is truncated (TC): TCP DNS needs a TCP stack, which the CONNECT-IP tunnel does not implement",
        ));
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("DNS server returned rcode {rcode} for '{host}'"),
        ));
    }
    let questions = u16::from_be_bytes([response[4], response[5]]);
    let answers = u16::from_be_bytes([response[6], response[7]]);
    let mut pos = 12;
    for _ in 0..questions {
        skip_dns_name(response, &mut pos).ok_or_else(|| malformed("truncated question name"))?;
        if response.len() < pos + 4 {
            return Err(malformed("truncated question"));
        }
        pos += 4;
    }
    let mut addresses = Vec::new();
    for _ in 0..answers {
        skip_dns_name(response, &mut pos).ok_or_else(|| malformed("truncated answer name"))?;
        let record = response
            .get(pos..pos + 10)
            .ok_or_else(|| malformed("truncated answer header"))?;
        let record_type = u16::from_be_bytes([record[0], record[1]]);
        let class = u16::from_be_bytes([record[2], record[3]]);
        let data_length = usize::from(u16::from_be_bytes([record[8], record[9]]));
        pos += 10;
        let data = response
            .get(pos..pos + data_length)
            .ok_or_else(|| malformed("truncated answer data"))?;
        pos += data_length;
        if class != 1 || record_type != qtype {
            continue;
        }
        match (record_type, data.len()) {
            (1, 4) => addresses.push(IpAddr::from(<[u8; 4]>::try_from(data).unwrap())),
            (28, 16) => addresses.push(IpAddr::from(<[u8; 16]>::try_from(data).unwrap())),
            _ => {}
        }
    }
    Ok(addresses)
}

fn skip_dns_name(response: &[u8], pos: &mut usize) -> Option<()> {
    loop {
        let length = *response.get(*pos)?;
        match length & 0xc0 {
            0xc0 => {
                // Compression pointer: two bytes, the target is not followed
                // here (only the record layout matters).
                *pos += 2;
                return Some(());
            }
            0 => {
                *pos += 1;
                if length == 0 {
                    return Some(());
                }
                *pos += usize::from(length);
            }
            _ => return None,
        }
    }
}

/// Encode one DNS query (header, one question, no EDNS).
pub fn dns_query(id: u16, host: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("DNS name '{host}' is not a valid query name (ASCII/Punycode only; this resolver does not apply IDNA)"),
        ));
    }
    let mut out = Vec::with_capacity(host.len() + 18);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    out.extend_from_slice(&1u16.to_be_bytes()); // questions
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // answers, authority, additional
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("DNS label in '{host}' is empty or longer than 63 bytes"),
            ));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    Ok(out)
}

fn handshake(kind: io::ErrorKind, message: impl std::fmt::Display) -> DialError {
    DialError::Handshake {
        protocol: "masque",
        source: io::Error::new(kind, message.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_advertisement_matches_the_pinned_capsule() {
        let routes = [
            IpRoute {
                start: IpAddr::from([0, 0, 0, 0]),
                end: IpAddr::from([255, 255, 255, 255]),
                protocol: 0,
            },
            IpRoute {
                start: IpAddr::from([0u16; 8]),
                end: IpAddr::from([u16::MAX; 8]),
                protocol: 0,
            },
        ];
        let value = route_advertisement_value(&routes);
        // 4 | start (4) | end (4) | protocol, then the IPv6 form.
        assert_eq!(value.len(), 1 + 4 + 4 + 1 + 1 + 16 + 16 + 1);
        assert_eq!(value[0], 4);
        assert_eq!(&value[1..5], &[0, 0, 0, 0]);
        assert_eq!(&value[5..9], &[255, 255, 255, 255]);
        assert_eq!(value[9], 0);
        assert_eq!(value[10], 6);
        assert_eq!(parse_route_advertisement(&value).unwrap(), routes);
    }

    #[test]
    fn address_assign_round_trip_and_validation() {
        let assignments = [
            AddressAssignment {
                request_id: 0,
                prefix: IpPrefix::parse("172.16.0.2/32").unwrap(),
            },
            AddressAssignment {
                request_id: 7,
                prefix: IpPrefix::parse("fd00::2/128").unwrap(),
            },
        ];
        let value = address_assign_value(&assignments);
        assert_eq!(parse_address_assign(&value).unwrap(), assignments);

        // Host bits under the prefix length are refused, as connect-ip-go does.
        let mut bad = Vec::new();
        h3::encode_varint(0, &mut bad);
        bad.push(4);
        bad.extend_from_slice(&[192, 0, 2, 7]);
        bad.push(24);
        assert!(parse_address_assign(&bad).is_err());

        let mut unknown_version = vec![0, 5];
        unknown_version.extend_from_slice(&[0; 18]);
        assert!(parse_address_assign(&unknown_version).is_err());
        assert!(parse_address_assign(&[0]).is_err());
    }

    #[test]
    fn connect_uri_defaults_and_templates() {
        assert_eq!(
            parse_connect_uri("https://cloudflareaccess.com").unwrap(),
            ("cloudflareaccess.com".to_string(), "/".to_string())
        );
        assert_eq!(
            parse_connect_uri("https://example.org/tunnel?x=1").unwrap(),
            ("example.org".to_string(), "/tunnel?x=1".to_string())
        );
        assert!(parse_connect_uri("http://example.org").is_err());
        assert!(parse_connect_uri("https://").is_err());
        assert!(parse_connect_uri("https://example.org/{target}").is_err());
        assert!(parse_connect_uri("https://user@example.org").is_err());
    }

    #[test]
    fn datagram_framing_carries_quarter_stream_and_context() {
        let mut datagram = Vec::new();
        h3::encode_varint(3, &mut datagram);
        h3::encode_varint(0, &mut datagram);
        datagram.extend_from_slice(b"packet");
        assert_eq!(datagram_payload(&datagram, 3).unwrap(), b"packet");
        assert!(datagram_payload(&datagram, 4).is_none());

        let mut other_context = Vec::new();
        h3::encode_varint(3, &mut other_context);
        h3::encode_varint(1, &mut other_context);
        other_context.extend_from_slice(b"packet");
        assert!(datagram_payload(&other_context, 3).is_none());
        assert!(datagram_payload(&[], 0).is_none());
    }

    #[test]
    fn capsules_are_framed_with_varint_type_and_length() {
        let value = address_assign_value(&[AddressAssignment {
            request_id: 0,
            prefix: IpPrefix::parse("172.16.0.2/32").unwrap(),
        }]);
        let capsule = encode_capsule(CAPSULE_ADDRESS_ASSIGN, &value);
        let mut buffer = capsule.clone();
        let (kind, parsed) = next_capsule(&mut buffer).unwrap().unwrap();
        assert_eq!(kind, CAPSULE_ADDRESS_ASSIGN);
        assert_eq!(parsed, value);
        assert!(buffer.is_empty());

        // A partial capsule is not consumed.
        let mut partial = capsule;
        partial.truncate(partial.len() - 1);
        assert!(next_capsule(&mut partial).unwrap().is_none());
        assert!(!partial.is_empty());

        // An oversized capsule is refused, not buffered.
        let mut oversized = Vec::new();
        h3::encode_varint(CAPSULE_ROUTE_ADVERTISEMENT, &mut oversized);
        h3::encode_varint(MAX_CAPSULE_VALUE as u64 + 1, &mut oversized);
        assert!(next_capsule(&mut oversized).is_err());
    }

    #[test]
    fn dns_query_and_answers() {
        let query = dns_query(0x1234, "dns-target.test", 1).unwrap();
        assert_eq!(&query[..2], &[0x12, 0x34]);
        assert_eq!(&query[4..6], &[0, 1]);
        assert_eq!(&query[12..13], &[10]);
        assert_eq!(&query[13..23], b"dns-target");
        assert_eq!(&query[query.len() - 4..query.len() - 2], &[0, 1]);

        // Build a response with one A record for the same question.
        let mut response = Vec::new();
        response.extend_from_slice(&[0x12, 0x34]);
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0, 0, 0, 0]);
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c]); // pointer to the question name
        response.extend_from_slice(&[0, 1, 0, 1]);
        response.extend_from_slice(&[0, 0, 0, 60]);
        response.extend_from_slice(&[0, 4]);
        response.extend_from_slice(&[198, 51, 100, 7]);
        let answers = dns_answers(0x1234, "dns-target.test", 1, &response).unwrap();
        assert_eq!(answers, vec![IpAddr::from([198, 51, 100, 7])]);

        assert!(dns_query(1, "dns-target.test", 1).is_ok());
        assert!(dns_query(1, "dnß-target.test", 1).is_err());
        assert!(dns_answers(0x1235, "dns-target.test", 1, &response).is_err());
        let mut truncated = response.clone();
        truncated[2] = 0x83; // TC set
        assert_eq!(
            dns_answers(0x1234, "dns-target.test", 1, &truncated)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        let mut nxdomain = response;
        nxdomain[3] = 0x03; // rcode 3
        assert_eq!(
            dns_answers(0x1234, "dns-target.test", 1, &nxdomain)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }
}
