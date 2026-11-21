//! UDP forwarding used by the mixed inbound's SOCKS5 `UDP ASSOCIATE`.
//!
//! The client sends datagrams to the relay socket the kernel reports; each
//! datagram starts with a SOCKS5 address header (`RSV RSV FRAG ATYP ADDR PORT`)
//! as RFC 1928 defines it. The relay evaluates the same rule set as TCP, then
//! forwards through:
//!
//! - `DIRECT`: an unconnected UDP socket, so every destination shares one
//!   socket and replies keep their source address;
//! - `ss` with `udp: true`: AEAD-2017 datagrams to the Shadowsocks server
//!   (`salt || sealed(addr || payload)`), one socket per association;
//! - `trojan` with `udp: true`: the server's UDP command framing over the TLS
//!   stream (`addr | length | CRLF | payload`), one stream per association.
//!
//! Families whose pinned outbound has no UDP association this kernel can
//! express (socks5, http, vless without `packet-addr`, anytls without UoT) drop
//! the datagram and log it; that is a recorded capability gap, never a silent
//! success. Fragmented datagrams (`FRAG != 0`) are dropped as well.

use std::io;
use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use super::tls::ClientTls;
use super::{connect_tcp, handshake, BoxStream, DialError, SocksAddr, Target};
use crate::keys::trojan_password_key;
use crate::proxies::{ShadowsocksOutbound, TrojanOutbound};

/// Upper bound for one UDP datagram (the IPv4/IPv6 payload limit).
pub const MAX_DATAGRAM: usize = 65_535;

/// One SOCKS5 UDP request: the destination and where its payload starts.
pub struct Datagram {
    pub target: Target,
    pub offset: usize,
}

/// Parse the SOCKS5 UDP request header. `None` when the datagram is malformed
/// or fragmented (this kernel does not reassemble fragments).
pub fn parse_datagram(bytes: &[u8]) -> Option<Datagram> {
    if bytes.len() < 4 || bytes[2] != 0 {
        return None;
    }
    let atyp = bytes[3];
    let mut offset = 4;
    let host = match atyp {
        0x01 => {
            let addr = bytes.get(offset..offset + 4)?;
            offset += 4;
            IpAddr::from(<[u8; 4]>::try_from(addr).ok()?).to_string()
        }
        0x04 => {
            let addr = bytes.get(offset..offset + 16)?;
            offset += 16;
            IpAddr::from(<[u8; 16]>::try_from(addr).ok()?).to_string()
        }
        0x03 => {
            let len = *bytes.get(offset)? as usize;
            offset += 1;
            let name = bytes.get(offset..offset + len)?;
            offset += len;
            String::from_utf8_lossy(name).to_ascii_lowercase()
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*bytes.get(offset)?, *bytes.get(offset + 1)?]);
    offset += 2;
    if port == 0 || offset > bytes.len() {
        return None;
    }
    Some(Datagram {
        target: Target { host, port },
        offset,
    })
}

/// Header bytes (SOCKS5 form) for a target; the ss and trojan framings carry
/// exactly this form.
pub fn address_header(target: &Target) -> Vec<u8> {
    SocksAddr::encode(target)
}

/// The full SOCKS5 UDP reply header: `RSV(2) FRAG(1)` then the source address.
pub fn reply_header(target: &Target) -> Vec<u8> {
    let mut header = vec![0u8, 0u8, 0u8];
    header.extend_from_slice(&address_header(target));
    header
}

/// Parse a SOCKS5 address at `bytes[offset..]`; returns the target and the
/// number of bytes it occupied.
pub fn parse_address(bytes: &[u8], offset: usize) -> Option<(Target, usize)> {
    let atyp = *bytes.get(offset)?;
    let mut cursor = offset + 1;
    let host = match atyp {
        0x01 => {
            let addr = bytes.get(cursor..cursor + 4)?;
            cursor += 4;
            IpAddr::from(<[u8; 4]>::try_from(addr).ok()?).to_string()
        }
        0x04 => {
            let addr = bytes.get(cursor..cursor + 16)?;
            cursor += 16;
            IpAddr::from(<[u8; 16]>::try_from(addr).ok()?).to_string()
        }
        0x03 => {
            let len = *bytes.get(cursor)? as usize;
            cursor += 1;
            let name = bytes.get(cursor..cursor + len)?;
            cursor += len;
            String::from_utf8_lossy(name).to_ascii_lowercase()
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*bytes.get(cursor)?, *bytes.get(cursor + 1)?]);
    Some((Target { host, port }, cursor + 2 - offset))
}

/// Whether a relayed source address is one the proxy server name resolved to.
/// The hop reports an IP, so a non-IP header cannot be validated and is
/// dropped rather than trusted.
fn target_matches(from: &Target, server_addrs: &[SocketAddr]) -> bool {
    match from.host.parse::<IpAddr>() {
        Ok(ip) => server_addrs
            .iter()
            .any(|server| *server == SocketAddr::new(ip, from.port)),
        Err(_) => false,
    }
}

/// Every address a UDP destination resolves to, IPv4 first (the system
/// resolver answers; there is no in-kernel DNS before T5).
pub async fn resolve_all(target: &Target) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, target.port)]);
    }
    let mut addrs = tokio::net::lookup_host((target.host.as_str(), target.port))
        .await?
        .collect::<Vec<_>>();
    addrs.sort_by_key(|addr| if addr.is_ipv4() { 0 } else { 1 });
    addrs.dedup();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "destination resolved to no address",
        ));
    }
    Ok(addrs)
}

/// Resolve a UDP destination: names use the system resolver (there is no
/// in-kernel DNS before T5), literals are used as they are.
pub async fn resolve(target: &Target) -> io::Result<SocketAddr> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, target.port));
    }
    let mut addrs = tokio::net::lookup_host((target.host.as_str(), target.port)).await?;
    addrs
        .find(|addr| addr.is_ipv4())
        .or_else(|| addrs.next())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "destination resolved to no address"))
}

/// How a proxy server connection is reached for datagrams: directly, or
/// through the first `dialer-proxy` hop (a SOCKS5 UDP association), matching
/// Mihomo's `proxydialer.ListenPacket`.
enum PacketTransport {
    Direct {
        socket: UdpSocket,
        server: SocketAddr,
    },
    Socks5 {
        association: super::socks5::Socks5Udp,
        /// Every address the server name resolves to: the hop reports the IP it
        /// actually dialled in the reply header, and a multi-A record (or NAT)
        /// may pick a different one than the first. A reply is accepted when
        /// its source is one of these, never from an arbitrary address.
        server_addrs: Vec<SocketAddr>,
    },
}

impl PacketTransport {
    async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        match self {
            PacketTransport::Direct { socket, server } => {
                socket.send_to(payload, *server).await.map(|_| ())
            }
            PacketTransport::Socks5 {
                association,
                server_addrs,
            } => {
                let server = server_addrs
                    .first()
                    .copied()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "server resolved to no address"))?;
                let target = Target {
                    host: server.ip().to_string(),
                    port: server.port(),
                };
                association.send(&target, payload).await
            }
        }
    }

    async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        match self {
            PacketTransport::Direct { socket, server } => {
                let (read, from) = socket.recv_from(buffer).await?;
                // Only the configured server may answer this association.
                if from != *server {
                    return Ok(None);
                }
                Ok(Some(read))
            }
            PacketTransport::Socks5 {
                association,
                server_addrs,
            } => {
                match association.recv(buffer).await? {
                    // Compare against the resolved set, not the configured name:
                    // a `server: example.org` configuration still receives
                    // replies whose header carries the IP the hop dialled, even
                    // when a multi-A record sends it to another address.
                    Some((from, len)) if target_matches(&from, server_addrs) => Ok(Some(len)),
                    _ => Ok(None),
                }
            }
        }
    }
}

/// Shadowsocks AEAD-2017 datagrams for one association.
pub struct SsUdp {
    transport: PacketTransport,
    codec: super::shadowsocks::SsDatagram,
}

impl SsUdp {
    /// `via` is the `dialer-proxy` chain of the matched proxy (first element
    /// is the proxy itself). A single socks5 hop carries the datagrams; any
    /// other chain is refused here and was already refused at load time.
    pub async fn connect(
        option: &ShadowsocksOutbound,
        via: &[&crate::proxies::Proxy],
        timeout: std::time::Duration,
        tls: &super::tls::ClientTls,
    ) -> Result<SsUdp, DialError> {
        debug_assert!(option.udp);
        let server = Target {
            host: option.server.clone(),
            port: option.port,
        };
        // Resolve once: the Direct socket needs the address, and the SOCKS5
        // hop reports the address it saw (an IP) in its reply header. The whole
        // set is kept so a multi-A server answering from another address is
        // still accepted.
        let resolved = resolve_all(&server)
            .await
            .map_err(|source| DialError::Resolve {
                host: server.host.clone(),
                source,
            })?;
        let transport = match via.len() {
            1 => {
                let bind = if resolved[0].is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                let socket = UdpSocket::bind(bind)
                    .await
                    .map_err(|source| DialError::Connect {
                        addr: bind.to_string(),
                        source,
                    })?;
                PacketTransport::Direct {
                    socket,
                    server: resolved[0],
                }
            }
            2 => match &via[1].protocol {
                crate::proxies::Protocol::Socks5(hop) => PacketTransport::Socks5 {
                    association: super::socks5::Socks5Udp::connect(hop, timeout, tls).await?,
                    server_addrs: resolved,
                },
                other => {
                    return Err(DialError::Chain(format!(
                        "udp through {}({}): only a socks5 hop can carry a UDP association",
                        via[1].name,
                        other_type(other)
                    )))
                }
            },
            _ => {
                return Err(DialError::Chain(format!(
                    "udp with a multi-hop dialer-proxy chain ({} hops) is not implemented (at most one socks5 hop)",
                    via.len() - 1
                )))
            }
        };
        Ok(SsUdp {
            transport,
            codec: super::shadowsocks::SsDatagram {
                cipher: option.cipher,
                password: option.password.expose().to_string(),
            },
        })
    }

    /// Seal `target || payload` into one datagram and send it.
    pub async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        let mut plain = address_header(target);
        plain.extend_from_slice(payload);
        let packet = self.codec.encode(&plain);
        self.transport.send(&packet).await
    }

    /// Receive and open one datagram; returns the sender and the payload.
    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        let Some(read) = self.transport.recv(buffer).await? else {
            return Ok(None);
        };
        let plain = match self.codec.decode(&buffer[..read]) {
            Ok(plain) => plain,
            // A datagram from the wrong key (or a tampered one) is dropped.
            Err(_) => return Ok(None),
        };
        let Some((target, header)) = parse_address(&plain, 0) else {
            return Ok(None);
        };
        let payload = &plain[header..];
        buffer[..payload.len()].copy_from_slice(payload);
        Ok(Some((target, payload.len())))
    }
}

fn other_type(protocol: &crate::proxies::Protocol) -> &'static str {
    match protocol {
        crate::proxies::Protocol::Socks5(_) => "socks5",
        crate::proxies::Protocol::Http(_) => "http",
        crate::proxies::Protocol::Shadowsocks(_) => "ss",
        crate::proxies::Protocol::Trojan(_) => "trojan",
        crate::proxies::Protocol::Vless(_) => "vless",
        crate::proxies::Protocol::Anytls(_) => "anytls",
    }
}

/// Trojan UDP association: one TLS stream carrying `cmd = 3` and frames of
/// `addr | length(2) | CRLF | payload` in both directions.
pub struct TrojanUdp {
    stream: BoxStream,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl TrojanUdp {
    /// `via` is the `dialer-proxy` chain of the matched proxy. The server
    /// connection is TCP, so it is established exactly like the TCP path (a
    /// socks5 hop carries it) and then carries the UDP frames.
    pub async fn connect(
        option: &TrojanOutbound,
        via: &[&crate::proxies::Proxy],
        timeout: std::time::Duration,
        tls: &ClientTls,
    ) -> Result<TrojanUdp, DialError> {
        let server_stream: BoxStream = match via.len() {
            1 => Box::new(connect_tcp(&option.server, option.port).await?),
            2 => match &via[1].protocol {
                crate::proxies::Protocol::Socks5(hop) => {
                    let (read, write) = super::socks5::tunnel(
                        hop,
                        &option.server,
                        option.port,
                        &[],
                        timeout,
                        tls,
                    )
                    .await?;
                    super::joined(read, write)
                }
                other => {
                    return Err(DialError::Chain(format!(
                        "udp through {}({}): only a socks5 hop can carry a UDP association",
                        via[1].name,
                        other_type(other)
                    )))
                }
            },
            _ => {
                return Err(DialError::Chain(format!(
                    "udp with a multi-hop dialer-proxy chain ({} hops) is not implemented (at most one socks5 hop)",
                    via.len() - 1
                )))
            }
        };
        let stream = super::tls::wrap_stream(server_stream, &option.server, &option.tls_settings, tls)
            .await
            .map_err(|e| handshake("trojan-udp tls", e))?;
        let mut stream: BoxStream = match &option.network {
            crate::proxies::TrojanNetwork::Tcp => Box::new(stream),
            crate::proxies::TrojanNetwork::Ws(ws_settings) => {
                let host = option
                    .tls_settings
                    .sni
                    .clone()
                    .unwrap_or_else(|| option.server.clone());
                let tunnel = super::ws::connect(
                    stream,
                    &host,
                    &ws_settings.path,
                    &ws_settings.headers,
                    ws_settings.v2ray_http_upgrade,
                )
                .await
                .map_err(|e| handshake("trojan-udp ws", e))?;
                Box::new(tunnel)
            }
        };
        // The pinned server reads a command, an address and a CRLF even for the
        // UDP command; the frames carry the real destinations.
        let dummy = Target {
            host: "0.0.0.0".to_string(),
            port: 0,
        };
        let mut header = trojan_password_key(option.password.expose());
        header.extend_from_slice(b"\r\n");
        header.push(3);
        header.extend_from_slice(&address_header(&dummy));
        header.extend_from_slice(b"\r\n");
        stream
            .write_all(&header)
            .await
            .map_err(|e| handshake("trojan-udp", e))?;
        stream
            .flush()
            .await
            .map_err(|e| handshake("trojan-udp", e))?;
        Ok(TrojanUdp {
            stream,
            read_buf: Vec::new(),
            read_pos: 0,
        })
    }

    pub async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        let mut frame = address_header(target);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(b"\r\n");
        frame.extend_from_slice(payload);
        self.stream.write_all(&frame).await?;
        self.stream.flush().await
    }

    /// Read one reply frame (skipping partial reads with the retained buffer).
    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        loop {
            if let Some((target, header)) = parse_address(&self.read_buf, self.read_pos) {
                let after_addr = self.read_pos + header;
                if self.read_buf.len() >= after_addr + 4 {
                    let length =
                        u16::from_be_bytes([self.read_buf[after_addr], self.read_buf[after_addr + 1]])
                            as usize;
                    if length > MAX_DATAGRAM - 2 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "trojan UDP frame length out of range",
                        ));
                    }
                    let start = after_addr + 4;
                    if self.read_buf.len() >= start + length {
                        let payload = &self.read_buf[start..start + length];
                        let len = payload.len();
                        buffer[..len].copy_from_slice(payload);
                        self.read_buf.drain(..start + length);
                        self.read_pos = 0;
                        return Ok(Some((target, len)));
                    }
                }
            }
            let mut chunk = [0u8; 4096];
            let read = self.stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(None);
            }
            self.read_buf.extend_from_slice(&chunk[..read]);
            if self.read_buf.len() > 4 * MAX_DATAGRAM {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "trojan UDP frame buffer exceeded",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(host: &str, port: u16) -> SocketAddr {
        SocketAddr::new(host.parse().expect("ip"), port)
    }

    #[test]
    fn a_reply_is_accepted_from_any_resolved_address_only() {
        // A multi-A server name resolves to several addresses; the hop reports
        // whichever one it dialled, so all of them are accepted.
        let resolved = vec![addr("127.0.0.1", 443), addr("::1", 443)];
        let from_v4 = Target {
            host: "127.0.0.1".into(),
            port: 443,
        };
        let from_v6 = Target {
            host: "::1".into(),
            port: 443,
        };
        assert!(target_matches(&from_v4, &resolved));
        assert!(target_matches(&from_v6, &resolved));
        // Another address on the same port, another port, and a name are all
        // dropped: an association never accepts an arbitrary sender.
        assert!(!target_matches(
            &Target {
                host: "203.0.113.9".into(),
                port: 443,
            },
            &resolved
        ));
        assert!(!target_matches(
            &Target {
                host: "127.0.0.1".into(),
                port: 444,
            },
            &resolved
        ));
        assert!(!target_matches(
            &Target {
                host: "example.org".into(),
                port: 443,
            },
            &resolved
        ));
    }

    #[test]
    fn resolve_all_keeps_a_literal_address_as_a_single_entry() {
        let target = Target {
            host: "127.0.0.1".into(),
            port: 53,
        };
        let addrs = futures_block_on(resolve_all(&target)).expect("literal resolves");
        assert_eq!(addrs, vec![addr("127.0.0.1", 53)]);
    }

    /// A tiny block_on so the unit tests do not need a tokio test runtime.
    fn futures_block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(future)
    }
}
