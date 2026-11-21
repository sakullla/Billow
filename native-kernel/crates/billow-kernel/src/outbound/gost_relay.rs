//! Gost relay v2 outbound (`transport/gost/relay.go`).
//!
//! The client opens a TCP connection (optionally wrapped in TLS and in an smux
//! session), writes one version-1 request header with up to three features -
//! user authentication, target address and network - and then reads the
//! four-byte response header. After a `status ok` the connection is the relayed
//! byte stream. `forward: true` omits the address feature so the relay server
//! uses its own forward target, which is how the pinned relay dialer treats
//! `forward`.
//!
//! The UDP association is the same request with `command = CONNECT|0x80` and
//! the `udp` network feature: the address feature then names the one target the
//! association is bound to, and each datagram is `length(u16 BE) payload` in
//! both directions (`relayPacketConn`).
//!
//! The wire format is small and fully specified by the pinned source; the
//! unit vectors below are copied from it and the controlled peer in
//! `tool/kernel-compat/peers/gost-relay-server` is an independent server-side
//! implementation used by `tool/kernel-compat/family-peers.sh`.

use std::io;
use std::net::IpAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{connect_tcp, handshake, smux, tls, BoxStream, DialError, Dialed, Target};
use super::tls::ClientTls;
use crate::proxies::GostRelayOutbound;

const RELAY_VERSION: u8 = 0x01;
const CMD_CONNECT: u8 = 0x01;
const FLAG_UDP: u8 = 0x80;

const FEATURE_USER_AUTH: u8 = 0x01;
const FEATURE_ADDR: u8 = 0x02;
const FEATURE_NETWORK: u8 = 0x04;

const ADDR_IPV4: u8 = 0x01;
const ADDR_DOMAIN: u8 = 0x03;
const ADDR_IPV6: u8 = 0x04;

const NETWORK_TCP: u16 = 0x0000;
const NETWORK_UDP: u16 = 0x0001;

const STATUS_OK: u8 = 0x00;

const MAX_FEATURE_LIST: usize = 0xFFFF;

pub async fn dial(
    option: &GostRelayOutbound,
    target: &Target,
    tls: &ClientTls,
) -> Result<Dialed, DialError> {
    let (mut stream, server) = connect_stream(option, tls).await?;
    let request = request_header(option, target).map_err(|e| handshake("gost-relay", e))?;
    stream
        .write_all(&request)
        .await
        .map_err(|e| handshake("gost-relay", e))?;
    stream.flush().await.map_err(|e| handshake("gost-relay", e))?;
    read_connect_response(&mut stream)
        .await
        .map_err(|e| handshake("gost-relay", e))?;
    Ok(Dialed { stream, server })
}

/// One UDP association, bound to `target` exactly like the pinned
/// `relayPacketConn` (a datagram for another address is refused).
pub struct GostRelayUdp {
    stream: BoxStream,
    read_buf: Vec<u8>,
    target: Target,
}

impl GostRelayUdp {
    pub async fn connect(
        option: &GostRelayOutbound,
        target: &Target,
        tls: &ClientTls,
    ) -> Result<GostRelayUdp, DialError> {
        debug_assert!(option.udp);
        let (mut stream, _) = connect_stream(option, tls).await?;
        let request = request_header_for(option, Some(target), true)
            .map_err(|e| handshake("gost-relay", e))?;
        stream
            .write_all(&request)
            .await
            .map_err(|e| handshake("gost-relay", e))?;
        stream.flush().await.map_err(|e| handshake("gost-relay", e))?;
        read_connect_response(&mut stream)
            .await
            .map_err(|e| handshake("gost-relay", e))?;
        Ok(GostRelayUdp {
            stream,
            read_buf: Vec::new(),
            target: target.clone(),
        })
    }

    pub fn target(&self) -> &Target {
        &self.target
    }

    pub async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > 0xFFFF {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gost relay udp packet too large",
            ));
        }
        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        self.stream.write_all(&frame).await?;
        self.stream.flush().await
    }

    /// One reply datagram; a datagram larger than `buffer` is truncated, as the
    /// pinned `ReadFrom` does.
    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        loop {
            if self.read_buf.len() >= 2 {
                let length = u16::from_be_bytes([self.read_buf[0], self.read_buf[1]]) as usize;
                if self.read_buf.len() >= 2 + length {
                    let payload = &self.read_buf[2..2 + length];
                    let copied = payload.len().min(buffer.len());
                    buffer[..copied].copy_from_slice(&payload[..copied]);
                    self.read_buf.drain(..2 + length);
                    return Ok(Some(copied));
                }
            }
            let mut chunk = [0u8; 4096];
            let read = self.stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(None);
            }
            self.read_buf.extend_from_slice(&chunk[..read]);
            if self.read_buf.len() > 4 * 65_535 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "gost relay udp frame buffer exceeded",
                ));
            }
        }
    }
}

/// Open the relay server connection: TCP, optional TLS and optional smux.
async fn connect_stream(
    option: &GostRelayOutbound,
    tls: &ClientTls,
) -> Result<(BoxStream, std::net::SocketAddr), DialError> {
    let tcp = connect_tcp(&option.server, option.port).await?;
    let server = tcp.peer_addr().map_err(|e| handshake("gost-relay", e))?;
    let mut stream: BoxStream = if option.tls {
        Box::new(
            tls::wrap(tcp, &option.server, &option.tls_settings, tls)
                .await
                .map_err(|e| handshake("gost-relay tls", e))?,
        )
    } else {
        Box::new(tcp)
    };
    if option.mux {
        let session = smux::open(stream)
            .await
            .map_err(|e| handshake("gost-relay smux", e))?;
        stream = Box::new(session);
    }
    Ok((stream, server))
}

/// Encode the version-1 request: `[version, command, len_hi, len_lo]` followed
/// by the feature list. `forward` drops the address feature.
fn request_header(option: &GostRelayOutbound, target: &Target) -> io::Result<Vec<u8>> {
    request_header_for(option, Some(target), false)
}

fn request_header_for(
    option: &GostRelayOutbound,
    target: Option<&Target>,
    udp: bool,
) -> io::Result<Vec<u8>> {
    let mut features = Vec::new();
    let username = option.username.as_ref().map(|s| s.expose()).unwrap_or("");
    let password = option.password.as_ref().map(|s| s.expose()).unwrap_or("");
    if !username.is_empty() || !password.is_empty() {
        if username.len() > 0xFF || password.len() > 0xFF {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gost relay username or password too long",
            ));
        }
        let mut payload = Vec::with_capacity(2 + username.len() + password.len());
        payload.push(username.len() as u8);
        payload.extend_from_slice(username.as_bytes());
        payload.push(password.len() as u8);
        payload.extend_from_slice(password.as_bytes());
        features.extend_from_slice(&encode_feature(FEATURE_USER_AUTH, &payload)?);
    }
    if !option.forward {
        if let Some(target) = target {
            let address = encode_address(&target.host, target.port)?;
            features.extend_from_slice(&encode_feature(FEATURE_ADDR, &address)?);
        }
    }
    let network = if udp { NETWORK_UDP } else { NETWORK_TCP };
    features.extend_from_slice(&encode_feature(FEATURE_NETWORK, &network.to_be_bytes())?);
    if features.len() > MAX_FEATURE_LIST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "gost relay feature list too large",
        ));
    }
    let command = if udp { CMD_CONNECT | FLAG_UDP } else { CMD_CONNECT };
    let mut out = Vec::with_capacity(4 + features.len());
    out.push(RELAY_VERSION);
    out.push(command);
    out.extend_from_slice(&(features.len() as u16).to_be_bytes());
    out.extend_from_slice(&features);
    Ok(out)
}

fn encode_feature(kind: u8, payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.len() > MAX_FEATURE_LIST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "gost relay feature payload too large",
        ));
    }
    let mut out = Vec::with_capacity(3 + payload.len());
    out.push(kind);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// `type|address|port`, with the same type tags as the pinned encoder.
fn encode_address(host: &str, port: u16) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + 1 + host.len() + 2);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            out.push(ADDR_IPV4);
            out.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            out.push(ADDR_IPV6);
            out.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            if host.len() > 0xFF {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "gost relay target host too long",
                ));
            }
            out.push(ADDR_DOMAIN);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

async fn read_connect_response<S>(stream: &mut S) -> io::Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != RELAY_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("gost relay bad version: {}", header[0]),
        ));
    }
    if header[1] != STATUS_OK {
        let kind = match header[1] {
            0x02 => io::ErrorKind::PermissionDenied,
            0x04 => io::ErrorKind::TimedOut,
            0x06 | 0x07 => io::ErrorKind::AddrNotAvailable,
            _ => io::ErrorKind::ConnectionRefused,
        };
        return Err(io::Error::new(
            kind,
            format!(
                "gost relay connect failed with status 0x{:02x} ({})",
                header[1],
                status_text(header[1])
            ),
        ));
    }
    let feature_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if feature_len > 0 {
        let mut discard = vec![0u8; feature_len];
        stream.read_exact(&mut discard).await?;
    }
    Ok(())
}

fn status_text(status: u8) -> &'static str {
    match status {
        0x00 => "ok",
        0x01 => "bad request",
        0x02 => "unauthorized",
        0x03 => "forbidden",
        0x04 => "timeout",
        0x05 => "service unavailable",
        0x06 => "host unreachable",
        0x07 => "network unreachable",
        0x08 => "internal server error",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Secret;

    fn option(forward: bool, user: Option<&str>, pass: Option<&str>) -> GostRelayOutbound {
        GostRelayOutbound {
            server: "127.0.0.1".into(),
            port: 9000,
            forward,
            tls: false,
            tls_settings: Default::default(),
            mux: false,
            udp: false,
            username: user.map(Secret::new),
            password: pass.map(Secret::new),
            dialer_proxy: None,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn ipv4_request_layout_matches_the_pinned_encoder() {
        let target = Target {
            host: "1.2.3.4".into(),
            port: 80,
        };
        let request = request_header(&option(false, None, None), &target).unwrap();
        // version, connect, feature length 15; addr feature: type/len, 1.2.3.4:80;
        // network feature: type/len, 0x0000.
        assert_eq!(hex(&request), "0101000f020007010102030400500400020000");
    }

    #[test]
    fn domain_and_auth_features_follow_the_pinned_order() {
        let target = Target {
            host: "a.example".into(),
            port: 443,
        };
        let request = request_header(&option(false, Some("u"), Some("p")), &target).unwrap();
        // auth (type 1), address (type 2), network (type 4).
        assert_eq!(
            hex(&request),
            "0101001c0100040175017002000d0309612e6578616d706c6501bb0400020000"
        );
    }

    #[test]
    fn udp_request_sets_the_flag_and_the_udp_network() {
        let target = Target {
            host: "1.2.3.4".into(),
            port: 53,
        };
        let request = request_header_for(&option(false, None, None), Some(&target), true).unwrap();
        // command 0x81, then the address feature and the udp network feature.
        assert_eq!(hex(&request), "0181000f020007010102030400350400020001");
    }

    #[test]
    fn forward_omits_the_address_feature() {
        let target = Target {
            host: "a.example".into(),
            port: 443,
        };
        let request = request_header(&option(true, None, None), &target).unwrap();
        assert_eq!(hex(&request), "010100050400020000");
    }

    #[test]
    fn ipv6_address_uses_type_four() {
        let target = Target {
            host: "::1".into(),
            port: 1,
        };
        let request = request_header(&option(false, None, None), &target).unwrap();
        // addr feature payload: 1 + 16 + 2 = 19 bytes.
        assert_eq!(&request[4..7], &[0x02, 0x00, 0x13]);
        assert_eq!(request[7], 0x04);
        assert_eq!(&request[24..26], &[0x00, 0x01]);
    }

    #[test]
    fn overlong_credentials_are_refused_at_dial_encoding() {
        let long = "x".repeat(256);
        let target = Target {
            host: "1.2.3.4".into(),
            port: 80,
        };
        let error = request_header(&option(false, Some(&long), None), &target).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn status_names_match_the_pinned_table() {
        assert_eq!(status_text(0x00), "ok");
        assert_eq!(status_text(0x02), "unauthorized");
        assert_eq!(status_text(0x08), "internal server error");
        assert_eq!(status_text(0x7f), "unknown");
    }
}
