//! MASQUE outbound: HTTP/3 CONNECT-UDP (RFC 9298) over the in-tree minimal
//! HTTP/3 client.
//!
//! The pinned Mihomo `masque` outbound (`adapter/outbound/masque.go`,
//! `transport/masque`) is a Cloudflare WARP client: it pins the endpoint's
//! ECDSA public key, presents a generated client certificate, sends
//! `:protocol cf-connect-ip` and terminates the returned IP packets in a
//! userspace IP stack (`connect-ip-go`), which is how it serves both TCP and
//! UDP. That shape is implemented here as CONNECT-IP over the kernel's own
//! minimal IP stack ([`super::masque_ip`], [`super::ipstack`]) for UDP; TCP
//! needs a TCP state machine and is refused by name.
//!
//! Two shapes share this module:
//!
//! * [`MasqueUdp`] — the RFC 9298 CONNECT-UDP subset below (a plain server);
//! * [`super::masque_ip::MasqueIp`] — CONNECT-IP (RFC 9484) for the WARP
//!   configuration; [`MasqueUdpAssociation`] picks one for the UDP
//!   association.
//!
//! Implemented here is the RFC 9298 CONNECT-UDP subset on top of the same QUIC
//! dependency profile as T10 (`quinn` 0.11, TLS 1.3, ALPN `h3`):
//!
//! 1. one QUIC connection per UDP association, HTTP/3 control streams with
//!    `SETTINGS_ENABLE_CONNECT_PROTOCOL`, and the peer's SETTINGS read before
//!    the first request (extended CONNECT is only usable when advertised);
//! 2. per destination, one request stream:
//!    `:method CONNECT`, `:protocol connect-udp`, `:scheme https`,
//!    `:authority <proxy authority>`,
//!    `:path /.well-known/masque/udp/<target_host>/<target_port>/`,
//!    `capsule-protocol: ?1` (RFC 9298 §3.4: `:authority` is the proxy's,
//!    the target is carried in the expanded path);
//! 3. a successful (`2xx`, `capsule-protocol: ?1`) response turns the stream
//!    into a capsule stream: each UDP payload travels in a `DATAGRAM` capsule
//!    (type 0x00) with context ID 0, and the peer's `DATAGRAM` capsules are
//!    handed back to the SOCKS5 UDP association.
//!
//! Capsule types other than `DATAGRAM` are ignored as RFC 9297 requires; a
//! non-zero context ID, a truncated capsule, a capsule larger than one UDP
//! datagram (65,535 payload bytes plus the context ID) or a non-`?1`/non-2xx
//! response is reported as an error and the flow is not used. Each flow holds
//! at most `FLOW_QUEUE * 65,535` queued payloads and
//! `MAX_CAPSULE + MAX_DATA_FRAME` bytes of unparsed capsule data, and at most
//! `MAX_CONCURRENT_DESTINATIONS` flows are open per association; the worst-case
//! totals are in `tool/kernel-compat/evidence/t14-feasibility.json`. HTTP
//! Datagrams (QUIC datagram frames) are not advertised, so the peer must use
//! capsules; server push, the WebTransport capsule protocol and 0-RTT are not
//! implemented.
//!
//! TCP over masque needs a TCP/IP stack on top of CONNECT-IP (RFC 9484), and
//! the pinned `h2`/`h3-l4proxy` modes are Cloudflare specific; both are
//! refused with a named error rather than silently dropped.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::debug;

use super::h3::{self, Session};
use super::masque_ip::MasqueIp;
use super::quic::{self, QuicOptions};
use super::tls::ClientTls;
use super::{DialError, Dialed, Target};
use crate::proxies::MasqueOutbound;

/// Capsule type `DATAGRAM` (RFC 9297 §3.5, used by RFC 9298 for UDP payloads).
pub const CAPSULE_DATAGRAM: u64 = 0x00;

/// One UDP payload is at most 65,535 bytes (the IPv4/IPv6 UDP length limit).
const MAX_UDP_PAYLOAD: usize = 65_535;

/// Upper bound for one capsule *value*: a UDP payload plus the context ID
/// varint (at most 8 bytes for a 62-bit value). A larger capsule cannot be a
/// UDP datagram and is refused instead of being buffered.
const MAX_CAPSULE: usize = MAX_UDP_PAYLOAD + 8;

/// Upper bound for one HTTP/3 DATA frame read from a CONNECT-UDP stream: one
/// maximal capsule plus its type/length varints. Bounding the frame (not just
/// the capsule) keeps the reader's buffer from allocating quinn's 1 MiB frame
/// limit before the capsule check can run.
const MAX_DATA_FRAME: usize = MAX_CAPSULE + 16;

/// One request stream (flow) per destination. The association refuses new
/// destinations beyond this bound so a hostile rule set cannot open unbounded
/// QUIC streams on one connection. Memory is bounded by this cap: each flow
/// holds at most `FLOW_QUEUE * 65,535` queued outbound payloads and
/// `MAX_CAPSULE + MAX_DATA_FRAME` bytes of unparsed inbound capsule data (see
/// `tool/kernel-compat/evidence/t14-feasibility.json`).
pub const MAX_CONCURRENT_DESTINATIONS: usize = 32;

/// Queued datagrams per flow in each direction. Two slots keep the worst-case
/// per-flow buffer at ~128 KiB; a full queue applies backpressure to the
/// association instead of growing without bound.
const FLOW_QUEUE: usize = 2;

/// One received UDP payload and the destination it was sent to.
struct Inbound {
    target: Target,
    payload: Vec<u8>,
}

/// The write half of one CONNECT-UDP flow plus its liveness marker. The reader
/// task clears `alive` when the peer ends the request stream or the capsule
/// stream becomes unusable; the association then prunes the entry instead of
/// letting closed flows exhaust `MAX_CONCURRENT_DESTINATIONS`.
struct Flow {
    outgoing: mpsc::Sender<Vec<u8>>,
    alive: Arc<AtomicBool>,
}

impl Flow {
    fn is_dead(&self) -> bool {
        !self.alive.load(Ordering::Acquire) || self.outgoing.is_closed()
    }
}

/// Clears the flow's liveness marker on every exit path of the reader task,
/// including early `return`s and panics.
struct DeadOnDrop(Arc<AtomicBool>);

impl Drop for DeadOnDrop {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// A live RFC 9298 CONNECT-UDP association for the SOCKS5 UDP relay.
pub struct MasqueUdp {
    session: Session,
    /// `:authority` of every CONNECT-UDP request: the proxy's authority
    /// (RFC 9298 §3.4), from the configured server and port.
    authority: String,
    timeout: Duration,
    inbound: mpsc::Receiver<Inbound>,
    inbound_tx: mpsc::Sender<Inbound>,
    flows: HashMap<Target, Flow>,
}

impl MasqueUdp {
    /// Open the QUIC connection and the HTTP/3 session. `option.udp` must be
    /// true: this kernel has no CONNECT-IP/IP-stack path for TCP.
    pub async fn connect(
        option: &MasqueOutbound,
        tls: &ClientTls,
        timeout: Duration,
    ) -> Result<MasqueUdp, DialError> {
        if !option.udp {
            return Err(handshake(
                io::ErrorKind::Unsupported,
                "masque has no supported mode with 'udp: false': TCP needs a TCP/IP stack over CONNECT-IP; set 'udp: true' to use CONNECT-UDP",
            ));
        }
        let handshake_timeout = if option.handshake_timeout == 0 {
            timeout
        } else {
            Duration::from_secs(option.handshake_timeout)
        };
        let mut quic_options = QuicOptions::new(vec!["h3".to_string()]);
        quic_options.keep_alive = Some(Duration::from_secs(30));
        let (connection, endpoint) = quic::connect(
            &option.server,
            &option.server,
            option.port,
            &option.tls_settings,
            tls,
            &quic_options,
            handshake_timeout,
        )
        .await?;
        // SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08) is what an HTTP/3 client
        // advertises for extended CONNECT; the peer must advertise it too.
        let session = match tokio::time::timeout(
            handshake_timeout,
            Session::open_with_settings(connection, endpoint, &[(0x08, 1)]),
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
        if !session
            .settings()
            .map(|settings| settings.enable_connect_protocol)
            .unwrap_or(false)
        {
            return Err(handshake(
                io::ErrorKind::Unsupported,
                "HTTP/3 peer did not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220 extended CONNECT)",
            ));
        }
        let (inbound_tx, inbound) = mpsc::channel(FLOW_QUEUE);
        Ok(MasqueUdp {
            session,
            authority: proxy_authority(&option.server, option.port),
            timeout,
            inbound,
            inbound_tx,
            flows: HashMap::new(),
        })
    }

    /// Open one CONNECT-UDP request stream for `target` and start its reader.
    async fn open_flow(&self, target: &Target) -> Result<Flow, DialError> {
        let path = connect_udp_path(target);
        let headers: [(&str, &str); 7] = [
            (":method", "CONNECT"),
            (":protocol", "connect-udp"),
            (":scheme", "https"),
            (":authority", self.authority.as_str()),
            (":path", path.as_str()),
            ("capsule-protocol", "?1"),
            ("user-agent", ""),
        ];
        let (send, mut recv) =
            match tokio::time::timeout(self.timeout, self.session.open_request(&headers)).await {
                Ok(Ok(pair)) => pair,
                Ok(Err(source)) => {
                    return Err(DialError::Handshake {
                        protocol: "masque",
                        source,
                    })
                }
                Err(_) => return Err(DialError::Timeout(self.timeout)),
            };
        let response = match tokio::time::timeout(self.timeout, h3::read_response(&mut recv)).await
        {
            Ok(Ok(response)) => response,
            Ok(Err(source)) => {
                return Err(DialError::Handshake {
                    protocol: "masque",
                    source,
                })
            }
            Err(_) => return Err(DialError::Timeout(self.timeout)),
        };
        if !(200..300).contains(&response.status) {
            return Err(DialError::Handshake {
                protocol: "masque",
                source: io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "CONNECT-UDP for {} was refused with status {}",
                        target.authority(),
                        response.status
                    ),
                ),
            });
        }
        match response.get("capsule-protocol") {
            Some(value) if value.trim() == "?1" => {}
            _ => return Err(handshake(
                io::ErrorKind::Unsupported,
                "CONNECT-UDP response did not select the capsule protocol (Capsule-Protocol: ?1)",
            )),
        }
        let (outgoing, mut queue) = mpsc::channel::<Vec<u8>>(FLOW_QUEUE);
        let inbound = self.inbound_tx.clone();
        let reader_target = target.clone();
        let alive = Arc::new(AtomicBool::new(true));
        // Writer: one capsule per payload, then a graceful FIN when the flow is
        // dropped. A failed write ends the task, which closes the queue so the
        // association reopens the flow on the next datagram.
        tokio::spawn(async move {
            let mut send = send;
            while let Some(payload) = queue.recv().await {
                if send.write_all(&datagram_frame(&payload)).await.is_err() {
                    return;
                }
            }
            let _ = send.finish();
        });
        // Reader: DATA frames carry the capsule byte stream; capsules may span
        // DATA frames, so the bytes are buffered until a whole capsule is here.
        let reader_alive = alive.clone();
        tokio::spawn(async move {
            // Every exit path (peer FIN, malformed capsule, oversized frame)
            // marks the flow dead so `flow_sender` can reclaim it.
            let _dead = DeadOnDrop(reader_alive);
            let mut recv = recv;
            let mut pending: Vec<u8> = Vec::new();
            while let Ok(Some((frame_type, data))) =
                h3::read_frame_limited(&mut recv, MAX_DATA_FRAME as u64).await
            {
                if frame_type != 0x00 {
                    continue;
                }
                pending.extend_from_slice(&data);
                loop {
                    match next_capsule(&mut pending) {
                        Ok(None) => break,
                        Ok(Some((CAPSULE_DATAGRAM, value))) => {
                            let Some(payload) = datagram_payload(&value) else {
                                debug!("masque DATAGRAM capsule has a non-zero context ID; flow closed");
                                return;
                            };
                            if inbound
                                .send(Inbound {
                                    target: reader_target.clone(),
                                    payload,
                                })
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        // Unknown capsule types are ignored (RFC 9297 §3.3).
                        Ok(Some(_)) => {}
                        Err(_) => {
                            debug!("masque capsule stream is malformed; flow closed");
                            return;
                        }
                    }
                }
                if pending.len() > MAX_CAPSULE + MAX_DATA_FRAME {
                    debug!(
                        "masque capsule buffer exceeded {} bytes; flow closed",
                        MAX_CAPSULE + MAX_DATA_FRAME
                    );
                    return;
                }
            }
        });
        Ok(Flow { outgoing, alive })
    }

    /// Get a live sender for `target`, opening a request stream when needed.
    /// Closed flows (peer FIN, reader protocol error, writer failure) are
    /// pruned for *every* destination before the cap is checked, so a peer
    /// that ends streams cannot pin the association at `MAX_CONCURRENT_DESTINATIONS`.
    async fn flow_sender(&mut self, target: &Target) -> io::Result<mpsc::Sender<Vec<u8>>> {
        self.flows.retain(|_, flow| !flow.is_dead());
        if let Some(flow) = self.flows.get(target) {
            return Ok(flow.outgoing.clone());
        }
        if self.flows.len() >= MAX_CONCURRENT_DESTINATIONS {
            return Err(io::Error::other(format!(
                "masque: at most {MAX_CONCURRENT_DESTINATIONS} concurrent CONNECT-UDP destinations per association"
            )));
        }
        let flow = self.open_flow(target).await.map_err(io::Error::other)?;
        let sender = flow.outgoing.clone();
        self.flows.insert(target.clone(), flow);
        Ok(sender)
    }

    /// Send one UDP payload to `target`, opening the CONNECT-UDP flow when this
    /// is the first datagram for that destination.
    pub async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_UDP_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("masque datagram is larger than the {MAX_UDP_PAYLOAD}-byte UDP limit"),
            ));
        }
        let sender = self.flow_sender(target).await?;
        // A full queue waits for the writer; bound that wait so a peer that
        // stops reading cannot stall the whole UDP association indefinitely.
        match tokio::time::timeout(self.timeout, sender.send(payload.to_vec())).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) | Err(_) => {
                // The flow was closed by the peer or its writer failed (or the
                // writer did not drain in time); open a new request stream for
                // the same destination since UDP is connectionless.
                self.flows.remove(target);
                let reopened = self.flow_sender(target).await?;
                match tokio::time::timeout(self.timeout, reopened.send(payload.to_vec())).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) => Err(io::Error::other("masque CONNECT-UDP flow closed")),
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "masque CONNECT-UDP flow did not drain",
                    )),
                }
            }
        }
    }

    /// Receive one UDP payload; returns the destination it belongs to. A
    /// datagram larger than the relay buffer is dropped and logged, like a
    /// malformed datagram in the other UDP associations.
    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        loop {
            let Some(Inbound { target, payload }) = self.inbound.recv().await else {
                return Ok(None);
            };
            if payload.len() > buffer.len() {
                debug!(
                    bytes = payload.len(),
                    "masque datagram exceeds the receive buffer; dropped"
                );
                continue;
            }
            buffer[..payload.len()].copy_from_slice(&payload);
            return Ok(Some((target, payload.len())));
        }
    }
}

impl Drop for MasqueUdp {
    fn drop(&mut self) {
        // Request-stream tasks hold their own stream handles; closing the
        // connection here makes them end with the association instead of
        // lingering until the peer times them out.
        self.session.close(0, "masque association closed");
    }
}

/// TCP through masque: CONNECT-UDP cannot carry it, and CONNECT-IP carries
/// whole IP packets that this kernel terminates for UDP only (no TCP state
/// machine), so the dial fails with the reason instead of bypassing the proxy.
pub async fn dial(
    option: &MasqueOutbound,
    _target: &Target,
    _tls: &ClientTls,
    _timeout: Duration,
) -> Result<Dialed, DialError> {
    let reason = if option.connect_ip.is_some() {
        "TCP over masque is not implemented: the CONNECT-IP (RFC 9484) tunnel carries IP packets and serving TCP needs a TCP state machine (the pinned adapter uses mipstack/gVisor); this kernel terminates UDP over the tunnel only"
    } else {
        "TCP over masque is not implemented: the RFC 9298 CONNECT-UDP subset carries UDP only, and the pinned CONNECT-IP shape needs 'private-key'/'public-key' plus 'ip'/'ipv6' and a TCP stack this kernel does not have"
    };
    Err(handshake(io::ErrorKind::Unsupported, reason))
}

/// The UDP association of a `masque` outbound: RFC 9298 CONNECT-UDP for a
/// plain server, RFC 9484 CONNECT-IP for the WARP configuration.
pub enum MasqueUdpAssociation {
    ConnectUdp(MasqueUdp),
    ConnectIp(MasqueIp),
}

impl MasqueUdpAssociation {
    /// Open the association the configuration selects.
    pub async fn connect(
        option: &MasqueOutbound,
        tls: &ClientTls,
        timeout: Duration,
    ) -> Result<MasqueUdpAssociation, DialError> {
        if option.connect_ip.is_some() {
            Ok(MasqueUdpAssociation::ConnectIp(
                MasqueIp::connect(option, tls, timeout).await?,
            ))
        } else {
            Ok(MasqueUdpAssociation::ConnectUdp(
                MasqueUdp::connect(option, tls, timeout).await?,
            ))
        }
    }

    pub async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        match self {
            MasqueUdpAssociation::ConnectUdp(association) => association.send(target, payload).await,
            MasqueUdpAssociation::ConnectIp(association) => association.send(target, payload).await,
        }
    }

    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        match self {
            MasqueUdpAssociation::ConnectUdp(association) => association.recv(buffer).await,
            MasqueUdpAssociation::ConnectIp(association) => association.recv(buffer).await,
        }
    }
}

/// The RFC 9298 request path for `target`:
/// `/.well-known/masque/udp/<target_host>/<target_port>/`. IPv6 literals are
/// bare addresses with their colons percent-encoded (RFC 9298 §3), and the
/// port is the decimal destination port.
pub fn connect_udp_path(target: &Target) -> String {
    format!(
        "/.well-known/masque/udp/{}/{}/",
        encode_target_host(&target.host),
        target.port
    )
}

/// The proxy authority used as `:authority` (RFC 9298 §3.4): the configured
/// server, bracketed for IPv6, with the port unless it is the https default.
pub fn proxy_authority(server: &str, port: u16) -> String {
    let host = if server.contains(':') {
        format!("[{server}]")
    } else {
        server.to_string()
    };
    if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    }
}

/// One `DATAGRAM` capsule inside an HTTP/3 DATA frame: the capsule protocol's
/// byte stream runs in DATA frames, so a payload is `DATA || DATAGRAM(0) ||
/// length || context 0 || payload`.
fn datagram_frame(payload: &[u8]) -> Vec<u8> {
    let mut capsule = Vec::with_capacity(payload.len() + 10);
    h3::encode_varint(CAPSULE_DATAGRAM, &mut capsule);
    h3::encode_varint((1 + payload.len()) as u64, &mut capsule);
    h3::encode_varint(0, &mut capsule); // context ID 0
    capsule.extend_from_slice(payload);
    let mut frame = Vec::with_capacity(capsule.len() + 10);
    h3::encode_varint(0x00, &mut frame); // DATA
    h3::encode_varint(capsule.len() as u64, &mut frame);
    frame.extend_from_slice(&capsule);
    frame
}

/// Parse the value of a `DATAGRAM` capsule: `context ID (varint) || payload`.
/// Only context ID 0 is the default flow (RFC 9298 §4.4); another ID is a
/// protocol error this client refuses instead of guessing.
fn datagram_payload(value: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    let context = h3::decode_varint(value, &mut pos)?;
    if context != 0 {
        return None;
    }
    Some(value[pos..].to_vec())
}

/// Take one complete capsule off `buffer`, leaving the remainder in place.
/// `Ok(None)` means the bytes so far are not a complete capsule yet.
fn next_capsule(buffer: &mut Vec<u8>) -> Result<Option<(u64, Vec<u8>)>, ()> {
    let mut pos = 0;
    let Some(capsule_type) = h3::decode_varint(buffer, &mut pos) else {
        return Ok(None);
    };
    let Some(length) = h3::decode_varint(buffer, &mut pos) else {
        return Ok(None);
    };
    let length = length as usize;
    if length > MAX_CAPSULE {
        return Err(());
    }
    let Some(end) = pos.checked_add(length) else {
        return Err(());
    };
    if buffer.len() < end {
        return Ok(None);
    }
    let value = buffer[pos..end].to_vec();
    buffer.drain(..end);
    Ok(Some((capsule_type, value)))
}

/// Percent-encode a `target_host` variable (RFC 3986 `reg-name`: `unreserved`
/// or `sub-delims`). IPv6 literals therefore lose their colons to `%3A` and
/// are not bracketed, as RFC 9298 §3 requires.
fn encode_target_host(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        let keep = matches!(
            byte,
            b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'-'
                | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
        );
        if keep {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
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

    fn target(host: &str, port: u16) -> Target {
        Target {
            host: host.to_string(),
            port,
        }
    }

    #[test]
    fn connect_udp_path_follows_rfc9298() {
        assert_eq!(
            connect_udp_path(&target("example.com", 443)),
            "/.well-known/masque/udp/example.com/443/"
        );
        assert_eq!(
            connect_udp_path(&target("192.0.2.6", 53)),
            "/.well-known/masque/udp/192.0.2.6/53/"
        );
        // RFC 9298 §3: an IPv6 literal is a bare address with its colons
        // percent-encoded, no brackets.
        assert_eq!(
            connect_udp_path(&target("2001:db8::42", 443)),
            "/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/"
        );
        // A byte outside reg-name is escaped, never split.
        assert_eq!(
            connect_udp_path(&target("a b@c", 1)),
            "/.well-known/masque/udp/a%20b%40c/1/"
        );
    }

    #[test]
    fn authority_is_the_proxy_not_the_target() {
        assert_eq!(proxy_authority("example.org", 443), "example.org");
        assert_eq!(proxy_authority("example.org", 8443), "example.org:8443");
        assert_eq!(proxy_authority("2001:db8::1", 443), "[2001:db8::1]");
    }

    #[test]
    fn datagram_is_a_capsule_inside_a_data_frame() {
        let frame = datagram_frame(b"ping");
        let mut pos = 0;
        assert_eq!(h3::decode_varint(&frame, &mut pos), Some(0x00)); // DATA
        let length = h3::decode_varint(&frame, &mut pos).unwrap();
        let mut capsules = frame[pos..pos + length as usize].to_vec();
        assert_eq!(frame.len(), pos + length as usize);
        let (kind, value) = next_capsule(&mut capsules).unwrap().unwrap();
        assert_eq!(kind, CAPSULE_DATAGRAM);
        assert_eq!(datagram_payload(&value).unwrap(), b"ping");
        assert!(capsules.is_empty());
    }

    #[test]
    fn partial_capsules_are_buffered_until_complete() {
        let mut buffer = Vec::new();
        h3::encode_varint(CAPSULE_DATAGRAM, &mut buffer);
        h3::encode_varint(3, &mut buffer);
        assert!(next_capsule(&mut buffer).unwrap().is_none());
        buffer.extend_from_slice(&[0x00, b'o']);
        assert!(next_capsule(&mut buffer).unwrap().is_none());
        buffer.push(b'k');
        let (_, value) = next_capsule(&mut buffer).unwrap().unwrap();
        assert_eq!(datagram_payload(&value).unwrap(), b"ok");
        assert!(buffer.is_empty());
    }

    #[test]
    fn unknown_capsules_are_skipped_and_bad_context_is_refused() {
        let mut buffer = Vec::new();
        h3::encode_varint(0x26, &mut buffer); // keep-alive
        h3::encode_varint(0, &mut buffer);
        h3::encode_varint(CAPSULE_DATAGRAM, &mut buffer);
        h3::encode_varint(2, &mut buffer);
        h3::encode_varint(0, &mut buffer);
        buffer.push(b'x');
        mapped_next(&mut buffer);
        assert_eq!(
            next_capsule(&mut buffer).unwrap().unwrap().0,
            CAPSULE_DATAGRAM
        );

        // A non-zero context ID is not the default flow.
        let mut other = Vec::new();
        h3::encode_varint(CAPSULE_DATAGRAM, &mut other);
        h3::encode_varint(2, &mut other);
        h3::encode_varint(7, &mut other);
        h3::encode_varint(7, &mut other);
        let (_, value) = next_capsule(&mut other).unwrap().unwrap();
        assert!(datagram_payload(&value).is_none());
    }

    fn mapped_next(buffer: &mut Vec<u8>) {
        let (kind, _) = next_capsule(buffer).unwrap().unwrap();
        assert_eq!(kind, 0x26);
    }

    #[test]
    fn a_capsule_longer_than_the_cap_is_refused() {
        let mut buffer = Vec::new();
        h3::encode_varint(CAPSULE_DATAGRAM, &mut buffer);
        h3::encode_varint(MAX_CAPSULE as u64 + 1, &mut buffer);
        assert!(next_capsule(&mut buffer).is_err());
    }

    #[test]
    fn a_full_udp_datagram_fits_the_capsule_cap() {
        let payload = vec![0xAB; MAX_UDP_PAYLOAD];
        let frame = datagram_frame(&payload);
        let mut pos = 0;
        assert_eq!(h3::decode_varint(&frame, &mut pos), Some(0x00)); // DATA
        let length = h3::decode_varint(&frame, &mut pos).unwrap();
        let mut capsules = frame[pos..pos + length as usize].to_vec();
        let (kind, value) = next_capsule(&mut capsules).unwrap().unwrap();
        assert_eq!(kind, CAPSULE_DATAGRAM);
        assert_eq!(datagram_payload(&value).unwrap().len(), MAX_UDP_PAYLOAD);
        assert!(capsules.is_empty());
    }

    #[test]
    fn closed_flows_are_visible_for_reclamation() {
        // A live flow is not pruned; a reader exit (DeadOnDrop), a dropped
        // writer receiver, or an explicit shutdown all mark it dead.
        let alive = Arc::new(AtomicBool::new(true));
        let (outgoing, _receiver) = mpsc::channel::<Vec<u8>>(1);
        let flow = Flow {
            outgoing,
            alive: alive.clone(),
        };
        assert!(!flow.is_dead());
        drop(flow);

        let (outgoing, _receiver) = mpsc::channel::<Vec<u8>>(1);
        let flow = Flow {
            outgoing,
            alive: alive.clone(),
        };
        assert!(!flow.is_dead());
        {
            let _dead = DeadOnDrop(alive.clone());
        }
        assert!(flow.is_dead(), "a reader exit must mark the flow dead");

        let receiver_gone = Arc::new(AtomicBool::new(true));
        let (outgoing, receiver) = mpsc::channel::<Vec<u8>>(1);
        drop(receiver);
        let flow = Flow {
            outgoing,
            alive: receiver_gone,
        };
        assert!(flow.is_dead(), "a failed writer must mark the flow dead");
    }
}
