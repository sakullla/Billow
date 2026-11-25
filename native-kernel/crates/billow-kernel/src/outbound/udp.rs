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
//!   stream (`addr | length | CRLF | payload`), one stream per association;
//! - `hysteria2`: the pinned QUIC datagram session (`session id | packet id |
//!   fragment id/count | varint address | host:port | data`), one association
//!   serving every destination, with `udp-mtu` fragmentation and packet-id
//!   reassembly (see [`Hysteria2Udp`]).
//!
//! Families whose pinned outbound has no UDP association this kernel can
//! express (http, tuic, hysteria v1, mieru, sudoku, snell, ssh, trusttunnel,
//! vless without `packet-addr`, anytls without UoT) drop the datagram and log
//! it; that is a recorded capability gap, never a silent success. Fragmented
//! SOCKS5 datagrams (`FRAG != 0`) are dropped as well.

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

/// Every address a UDP destination (the proxy server of an `ss`/`ssr`
/// association) resolves to. The shared resolver applies the in-scope
/// `ip-version` and `proxy-server-nameserver` (`outbound::with_proxy_dns`), so
/// a proxy server name is never resolved by the OS resolver while DNS is on.
/// `IPv4 first` is only the `dual` default of that shared ordering.
pub async fn resolve_all(target: &Target) -> io::Result<Vec<SocketAddr>> {
    // The shared resolver applies `ip-version` (including for a literal) and
    // `proxy-server-nameserver`; `IPv4 first` is only its `dual` default.
    super::resolve_all(&target.host, target.port)
        .await
        .map_err(dial_to_io)
}

/// Keep the transport error shape: a resolution failure surfaces its source
/// instead of a printed `DialError`.
fn dial_to_io(error: DialError) -> io::Error {
    match error {
        DialError::Resolve { source, .. } => source,
        other => io::Error::other(other.to_string()),
    }
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
                let socket = super::bind_udp_str(bind)
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
                    // The socket that actually leaves this host is the one to
                    // the hop (`chain.last()`, as in `dial_chain`), so the
                    // hop's BasicOption knobs own it, not the exit's.
                    association: super::with_dialer(
                        via[1].dialer.clone(),
                        super::socks5::Socks5Udp::connect(hop, timeout, tls),
                    )
                    .await?,
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

/// ShadowsocksR datagrams for one association (`ssr.cipher.PacketConn` then
/// `ssr.protocol.PacketConn` in the pinned outbound): each datagram is
/// `IV || cipher(protocol packet)` and the protocol packet carries the SOCKS5
/// address plus the payload. The obfs layer is not used on the UDP path.
pub struct SsrUdp {
    transport: PacketTransport,
    cipher: crate::proxies::SsrCipher,
    key: Vec<u8>,
    protocol: Box<dyn super::ssr::protocol::Protocol>,
}

impl SsrUdp {
    pub async fn connect(
        option: &crate::proxies::SsrOutbound,
        via: &[&crate::proxies::Proxy],
        timeout: std::time::Duration,
        tls: &super::tls::ClientTls,
    ) -> Result<SsrUdp, DialError> {
        debug_assert!(option.udp);
        let server = Target {
            host: option.server.clone(),
            port: option.port,
        };
        let resolved = resolve_all(&server)
            .await
            .map_err(|source| DialError::Resolve {
                host: server.host.clone(),
                source,
            })?;
        let transport = match via.len() {
            1 => {
                let bind = if resolved[0].is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                let socket = super::bind_udp_str(bind)
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
                    // The socket that actually leaves this host is the one to
                    // the hop (`chain.last()`, as in `dial_chain`), so the
                    // hop's BasicOption knobs own it, not the exit's.
                    association: super::with_dialer(
                        via[1].dialer.clone(),
                        super::socks5::Socks5Udp::connect(hop, timeout, tls),
                    )
                    .await?,
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
        let key = crate::keys::evp_bytes_to_key(
            option.password.expose().as_bytes(),
            option.cipher.key_len(),
        );
        let overhead = option.obfs.overhead() + option.protocol.overhead();
        let protocol = super::ssr::protocol::build(option, key.clone(), Vec::new(), overhead);
        Ok(SsrUdp {
            transport,
            cipher: option.cipher,
            key,
            protocol,
        })
    }

    pub async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        let mut plain = address_header(target);
        plain.extend_from_slice(payload);
        let mut packet = Vec::new();
        self.protocol.encode_packet(&plain, &mut packet)?;
        let datagram = super::ssr::pack_datagram(self.cipher, &self.key, &packet);
        self.transport.send(&datagram).await
    }

    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        let Some(read) = self.transport.recv(buffer).await? else {
            return Ok(None);
        };
        let packet = match super::ssr::unpack_datagram(self.cipher, &self.key, &buffer[..read]) {
            Ok(packet) => packet,
            Err(_) => return Ok(None),
        };
        let plain = match self.protocol.decode_packet(&packet) {
            Ok(plain) => plain,
            Err(_) => return Ok(None),
        };
        let Some((target, header)) = parse_address(&plain, 0) else {
            return Ok(None);
        };
        let payload = &plain[header..];
        if payload.len() > buffer.len() {
            return Ok(None);
        }
        buffer[..payload.len()].copy_from_slice(payload);
        Ok(Some((target, payload.len())))
    }
}

fn other_type(protocol: &crate::proxies::Protocol) -> &'static str {    match protocol {
        crate::proxies::Protocol::Socks5(_) => "socks5",
        crate::proxies::Protocol::Http(_) => "http",
        crate::proxies::Protocol::Shadowsocks(_) => "ss",
        crate::proxies::Protocol::Trojan(_) => "trojan",
        crate::proxies::Protocol::Vless(_) => "vless",
        crate::proxies::Protocol::Anytls(_) => "anytls",
        crate::proxies::Protocol::Vmess(_) => "vmess",
        crate::proxies::Protocol::Snell(_) => "snell",
        crate::proxies::Protocol::TrustTunnel(_) => "trusttunnel",
        crate::proxies::Protocol::GostRelay(_) => "gost-relay",
        crate::proxies::Protocol::Ssh(_) => "ssh",
        crate::proxies::Protocol::Ssr(_) => "ssr",
        crate::proxies::Protocol::Tuic(_) => "tuic",
        crate::proxies::Protocol::Hysteria(_) => "hysteria",
        crate::proxies::Protocol::Hysteria2(_) => "hysteria2",
        crate::proxies::Protocol::Mieru(_) => "mieru",
        crate::proxies::Protocol::Sudoku(_) => "sudoku",
        crate::proxies::Protocol::Masque(_) => "masque",
        crate::proxies::Protocol::ShadowQuic(_) => "shadowquic",
        crate::proxies::Protocol::Wireguard(_) => "wireguard (no UDP association)",
        crate::proxies::Protocol::OpenVpn(_) => "openvpn (no UDP association)",
        crate::proxies::Protocol::Tailscale(_) => "tailscale (no UDP association)",
        crate::proxies::Protocol::Zerotier(_) => "zerotier (no UDP association)",
        crate::proxies::Protocol::Easytier(_) => "easytier (no UDP association)",
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
                    // The hop is the locally dialled socket, so its own
                    // BasicOption knobs own it (as `dial_chain` uses
                    // `chain.last()`), not the exit's.
                    let (read, write) = super::with_dialer(
                        via[1].dialer.clone(),
                        super::socks5::tunnel(
                            hop,
                            &option.server,
                            option.port,
                            &[],
                            timeout,
                            tls,
                        ),
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
        let stream: BoxStream = match &option.network {
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
        let mut stream = super::trojan::wrap_ss(stream, option).await?;
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

/// One dedicated TCP stream toward the proxy server, honouring the
/// `dialer-proxy` chain exactly like the TCP dial path: direct, or through one
/// socks5 hop's CONNECT tunnel.
pub(crate) async fn server_stream(
    server: &str,
    port: u16,
    via: &[&crate::proxies::Proxy],
    timeout: std::time::Duration,
    tls: &ClientTls,
) -> Result<BoxStream, DialError> {
    match via.len() {
        1 => Ok(Box::new(connect_tcp(server, port).await?)),
        2 => match &via[1].protocol {
            crate::proxies::Protocol::Socks5(hop) => {
                let (read, write) = super::with_dialer(
                    via[1].dialer.clone(),
                    super::socks5::tunnel(hop, server, port, &[], timeout, tls),
                )
                .await?;
                Ok(super::joined(read, write))
            }
            other => Err(DialError::Chain(format!(
                "udp through {}({}): only a socks5 hop can carry a UDP association",
                via[1].name,
                other_type(other)
            ))),
        },
        _ => Err(DialError::Chain(format!(
            "udp with a multi-hop dialer-proxy chain ({} hops) is not implemented (at most one socks5 hop)",
            via.len() - 1
        ))),
    }
}

/// VLESS UDP association. The pinned outbound never uses the bare UDP command:
/// `packet-encoding: packetaddr|packet` selects packet-addr, and the default
/// (no packet-addr) selects XUDP, so the kernel speaks exactly those two
/// framings. XUDP frames are the mux frames (`len | sid | status | option |
/// network | address | u16 len | data`); packet-addr frames are the 2-byte
/// length records of the vless `PacketConn` with the destination inside the
/// payload.
pub struct VlessUdp {
    stream: BoxStream,
    mode: VlessUdpMode,
    sid: u16,
    first: bool,
    bound: Option<Target>,
    /// The VLESS response header (`version || addon length || addon`) arrives
    /// with the first server write; the pinned client consumes it lazily on its
    /// first read, so the association does the same.
    response_pending: bool,
}

enum VlessUdpMode {
    Xudp,
    PacketAddr,
}

impl VlessUdp {
    pub async fn connect(
        option: &crate::proxies::VlessOutbound,
        via: &[&crate::proxies::Proxy],
        timeout: std::time::Duration,
        tls: &ClientTls,
    ) -> Result<VlessUdp, DialError> {
        debug_assert!(option.udp);
        let stream = server_stream(&option.server, option.port, via, timeout, tls).await?;
        let stream: BoxStream = if option.tls {
            Box::new(
                super::tls::wrap_stream(stream, &option.server, &option.tls_settings, tls)
                    .await
                    .map_err(|e| handshake("vless-udp tls", e))?,
            )
        } else {
            stream
        };
        let mut stream: BoxStream = match &option.network {
            crate::proxies::VlessNetwork::Tcp => stream,
            crate::proxies::VlessNetwork::Ws(ws) => {
                let host = option
                    .tls_settings
                    .sni
                    .clone()
                    .unwrap_or_else(|| option.server.clone());
                Box::new(
                    super::ws::connect(
                        stream,
                        &host,
                        &ws.path,
                        &ws.headers,
                        ws.v2ray_http_upgrade,
                    )
                    .await
                    .map_err(|e| handshake("vless-udp ws", e))?,
                )
            }
        };
        let mode = if option.xudp {
            let header = super::vless::request_header_command(&option.uuid, None, super::vless::CMD_MUX);
            stream
                .write_all(&header)
                .await
                .map_err(|e| handshake("vless-udp", e))?;
            VlessUdpMode::Xudp
        } else {
            let magic = Target {
                host: PACKETADDR_MAGIC.to_string(),
                port: 443,
            };
            let header = super::vless::request_header_command(
                &option.uuid,
                Some(&magic),
                super::vless::CMD_UDP,
            );
            stream
                .write_all(&header)
                .await
                .map_err(|e| handshake("vless-udp", e))?;
            VlessUdpMode::PacketAddr
        };
        stream
            .flush()
            .await
            .map_err(|e| handshake("vless-udp", e))?;
        Ok(VlessUdp {
            stream,
            mode,
            sid: 1,
            first: true,
            bound: None,
            response_pending: true,
        })
    }

    pub async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        match self.mode {
            VlessUdpMode::Xudp => {
                let addr = vmess_address(target);
                let mut frame = Vec::with_capacity(2 + 5 + addr.len() + 2 + payload.len());
                frame.extend_from_slice(&((5 + addr.len()) as u16).to_be_bytes());
                frame.extend_from_slice(&self.sid.to_be_bytes());
                frame.push(if self.first { 1 } else { 2 }); // new | keep
                frame.push(1); // option data
                frame.push(2); // network UDP
                frame.extend_from_slice(&addr);
                frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                frame.extend_from_slice(payload);
                self.first = false;
                self.stream.write_all(&frame).await?;
                self.stream.flush().await
            }
            VlessUdpMode::PacketAddr => {
                // Packet-addr carries only IP destinations; resolve a name the
                // way the pinned `ResolveUDP` does before framing.
                let addr = match resolve(target).await {
                    Ok(addr) => addr,
                    Err(error) => return Err(error),
                };
                let mut plain = packet_addr_bytes(addr.ip(), addr.port());
                plain.extend_from_slice(payload);
                let mut frame = Vec::with_capacity(2 + plain.len());
                frame.extend_from_slice(&(plain.len() as u16).to_be_bytes());
                frame.extend_from_slice(&plain);
                self.stream.write_all(&frame).await?;
                self.stream.flush().await
            }
        }
    }

    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        if self.response_pending {
            let mut header = [0u8; 2];
            if self.stream.read_exact(&mut header).await.is_err() {
                return Ok(None);
            }
            if header[0] != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected vless response version",
                ));
            }
            if header[1] > 0 {
                let mut addon = vec![0u8; header[1] as usize];
                if self.stream.read_exact(&mut addon).await.is_err() {
                    return Ok(None);
                }
            }
            self.response_pending = false;
        }
        match self.mode {
            VlessUdpMode::PacketAddr => {
                let mut length = [0u8; 2];
                if self.stream.read_exact(&mut length).await.is_err() {
                    return Ok(None);
                }
                let length = u16::from_be_bytes(length) as usize;
                if length > MAX_DATAGRAM {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vless packet-addr record too long",
                    ));
                }
                let mut plain = vec![0u8; length];
                if self.stream.read_exact(&mut plain).await.is_err() {
                    return Ok(None);
                }
                let Some((target, header)) = parse_packet_address(&plain, 0) else {
                    return Ok(None);
                };
                let payload = &plain[header..];
                if payload.len() > buffer.len() {
                    return Ok(None);
                }
                buffer[..payload.len()].copy_from_slice(payload);
                Ok(Some((target, payload.len())))
            }
            VlessUdpMode::Xudp => loop {
                let mut header = [0u8; 6];
                if self.stream.read_exact(&mut header).await.is_err() {
                    return Ok(None);
                }
                let length = u16::from_be_bytes([header[0], header[1]]) as usize;
                let status = header[4];
                let option = header[5];
                let mut target: Option<Target> = None;
                if length > 4 {
                    let mut extra = vec![0u8; length - 4];
                    if self.stream.read_exact(&mut extra).await.is_err() {
                        return Ok(None);
                    }
                    // extra = network(1) + vmess address (port first).
                    if extra[0] == 2 {
                        target = parse_vmess_address(&extra[1..]);
                    }
                }
                if status == 3 {
                    return Ok(None);
                }
                if status != 2 || option & 1 == 0 {
                    continue;
                }
                let mut length_bytes = [0u8; 2];
                if self.stream.read_exact(&mut length_bytes).await.is_err() {
                    return Ok(None);
                }
                let length = u16::from_be_bytes(length_bytes) as usize;
                if length > buffer.len() {
                    return Ok(None);
                }
                self.stream.read_exact(&mut buffer[..length]).await.map_err(|_| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "vless xudp frame cut")
                })?;
                let target = target.or_else(|| self.bound.clone()).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "vless xudp reply without a destination")
                })?;
                if self.bound.is_none() {
                    self.bound = Some(target.clone());
                }
                return Ok(Some((target, length)));
            },
        }
    }
}

const PACKETADDR_MAGIC: &str = "sp.packet-addr.v2fly.arpa";

/// vlESS request destination is the vmess `AddressSerializer` order: port
/// first, then ATYP 1/2/3 (v4, fqdn, v6).
pub(crate) fn vmess_address(target: &Target) -> Vec<u8> {
    let mut out = Vec::with_capacity(target.host.len() + 9);
    out.extend_from_slice(&target.port.to_be_bytes());
    if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                out.push(1);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(3);
                out.extend_from_slice(&v6.octets());
            }
        }
    } else {
        out.push(2);
        out.push(target.host.len() as u8);
        out.extend_from_slice(target.host.as_bytes());
    }
    out
}

/// UoT `AddrParser` (`sing/common/uot`): family byte 0 IPv4, 1 IPv6, 2 FQDN,
/// then the address and the port (different from SOCKS5's 1/4/3).
fn uot_address(target: &Target) -> Vec<u8> {
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

fn parse_uot_address(bytes: &[u8], offset: usize) -> Option<(Target, usize)> {
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

/// Packet-addr serializer (`sing-vmess/packetaddr`): ATYP 1 IPv4, 2 IPv6,/// then the address and port. No domain form exists, so the caller resolves.
fn packet_addr_bytes(ip: IpAddr, port: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(19);
    match ip {
        IpAddr::V4(v4) => {
            out.push(1);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(2);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out
}

fn parse_packet_address(bytes: &[u8], offset: usize) -> Option<(Target, usize)> {
    let atyp = *bytes.get(offset)?;
    let mut cursor = offset + 1;
    let host = match atyp {
        1 => {
            let octets = bytes.get(cursor..cursor + 4)?;
            cursor += 4;
            std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]).to_string()
        }
        2 => {
            let octets = bytes.get(cursor..cursor + 16)?;
            cursor += 16;
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(octets).ok()?).to_string()
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*bytes.get(cursor)?, *bytes.get(cursor + 1)?]);
    Some((Target { host, port }, cursor + 2 - offset))
}

fn parse_vmess_address(bytes: &[u8]) -> Option<Target> {    if bytes.len() < 3 {
        return None;
    }
    let port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let atyp = bytes[2];
    let mut pos = 3;
    let host = match atyp {
        1 => {
            let octets = bytes.get(pos..pos + 4)?;
            pos += 4;
            std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]).to_string()
        }
        3 => {
            let octets = bytes.get(pos..pos + 16)?;
            pos += 16;
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(octets).ok()?).to_string()
        }
        2 => {
            let len = *bytes.get(pos)? as usize;
            pos += 1;
            let name = bytes.get(pos..pos + len)?;
            String::from_utf8_lossy(name).to_string()
        }
        _ => return None,
    };
    Some(Target { host, port })
}

/// AnyTLS UoT association: a dedicated AnyTLS stream to the UoT magic
/// destination, then `u16 length || payload` in both directions. The pinned
/// outbound opens one such stream per destination (`ListenPacketContext`), so
/// the engine owns one association per target and this type can be split into
/// independent halves.
pub struct AnytlsUot {
    stream: super::anytls::AnyUotStream,
    bound: Target,
}

impl AnytlsUot {
    pub async fn connect(
        option: &crate::proxies::AnytlsOutbound,
        target: &Target,
        via: &[&crate::proxies::Proxy],
        timeout: std::time::Duration,
        tls: &ClientTls,
    ) -> Result<AnytlsUot, DialError> {
        debug_assert!(option.udp);
        let (stream, _server) = super::anytls::dial_uot(option, target, via, timeout, tls).await?;
        Ok(AnytlsUot {
            stream,
            bound: target.clone(),
        })
    }

    /// Split into a read half (server → client) and a write half (client →
    /// server) so one target's replies do not block another target's sends.
    pub fn into_halves(self) -> (AnyUotReader, AnyUotWriter) {
        let (read, write) = tokio::io::split(self.stream);
        (
            AnyUotReader {
                read,
                bound: self.bound,
            },
            AnyUotWriter { write },
        )
    }
}

/// Read half of one destination-bound AnyTLS UoT stream.
pub struct AnyUotReader {
    read: tokio::io::ReadHalf<super::anytls::AnyUotStream>,
    bound: Target,
}

impl AnyUotReader {
    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        let mut length = [0u8; 2];
        if self.read.read_exact(&mut length).await.is_err() {
            return Ok(None);
        }
        let length = u16::from_be_bytes(length) as usize;
        if length > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "anytls UoT datagram larger than the buffer",
            ));
        }
        if self.read.read_exact(&mut buffer[..length]).await.is_err() {
            return Ok(None);
        }
        Ok(Some((self.bound.clone(), length)))
    }
}

/// Write half of one destination-bound AnyTLS UoT stream.
pub struct AnyUotWriter {
    write: tokio::io::WriteHalf<super::anytls::AnyUotStream>,
}

impl AnyUotWriter {
    pub async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        self.write.write_all(&frame).await?;
        self.write.flush().await
    }
}

/// VMess UDP association: XUDP (mux frames), packet-addr (magic destination
/// plus the ip:port inside the record) or plain `command 2` bound to one
/// destination, matching the pinned `NewVmess` resolution.
pub struct VmessUdp {
    packet: super::vmess::VmessPacket,
    mode: VmessUdpMode,
    bound: Target,
    sid: u16,
    first: bool,
    read_buf: Vec<u8>,
}

enum VmessUdpMode {
    Xudp,
    PacketAddr,
    Plain,
}

impl VmessUdp {
    pub async fn connect(
        option: &crate::proxies::VmessOutbound,
        target: &Target,
        via: &[&crate::proxies::Proxy],
        timeout: std::time::Duration,
        tls: &ClientTls,
    ) -> Result<VmessUdp, DialError> {
        debug_assert!(option.udp);
        let mode = if option.xudp {
            VmessUdpMode::Xudp
        } else if option.packet_addr {
            VmessUdpMode::PacketAddr
        } else {
            VmessUdpMode::Plain
        };
        let packet = match mode {
            VmessUdpMode::Xudp => {
                // The mux command carries no destination in the request.
                let ignored = Target {
                    host: "0.0.0.0".to_string(),
                    port: 0,
                };
                super::vmess::dial_mux(option, &ignored, via, timeout, tls).await?
            }
            VmessUdpMode::PacketAddr => {
                let magic = Target {
                    host: PACKETADDR_MAGIC.to_string(),
                    port: 443,
                };
                super::vmess::dial_packet(option, &magic, via, timeout, tls).await?
            }
            VmessUdpMode::Plain => {
                super::vmess::dial_packet(option, target, via, timeout, tls).await?
            }
        };
        Ok(VmessUdp {
            packet,
            mode,
            bound: target.clone(),
            sid: 1,
            first: true,
            read_buf: Vec::new(),
        })
    }

    /// Split a plain (`command 2`) association into independent halves, one
    /// per destination in the engine's map.
    pub fn into_plain_halves(self) -> (super::vmess::VmessPacketReader, super::vmess::VmessPacketWriter) {
        debug_assert!(matches!(self.mode, VmessUdpMode::Plain));
        self.packet.into_halves()
    }

    pub async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        match self.mode {
            VmessUdpMode::Xudp => {
                let addr = vmess_address(target);
                let mut frame = Vec::with_capacity(2 + 5 + addr.len() + 2 + payload.len());
                frame.extend_from_slice(&((5 + addr.len()) as u16).to_be_bytes());
                frame.extend_from_slice(&self.sid.to_be_bytes());
                frame.push(if self.first { 1 } else { 2 });
                frame.push(1);
                frame.push(2);
                frame.extend_from_slice(&addr);
                frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                frame.extend_from_slice(payload);
                self.first = false;
                self.packet.send(&frame).await
            }
            VmessUdpMode::PacketAddr => {
                let addr = resolve(target).await?;
                let mut plain = packet_addr_bytes(addr.ip(), addr.port());
                plain.extend_from_slice(payload);
                self.packet.send(&plain).await
            }
            VmessUdpMode::Plain => {
                if target != &self.bound {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "vmess plain UDP is bound to its first destination",
                    ));
                }
                self.packet.send(payload).await
            }
        }
    }

    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        match self.mode {
            VmessUdpMode::Plain => {
                return self
                    .packet
                    .recv(buffer)
                    .await
                    .map(|read| read.map(|len| (self.bound.clone(), len)))
            }
            VmessUdpMode::PacketAddr => {
                let mut record = vec![0u8; MAX_DATAGRAM];
                let Some(read) = self.packet.recv(&mut record).await? else {
                    return Ok(None);
                };
                let Some((target, header)) = parse_packet_address(&record[..read], 0) else {
                    return Ok(None);
                };
                let payload = &record[header..read];
                buffer[..payload.len()].copy_from_slice(payload);
                return Ok(Some((target, payload.len())));
            }
            VmessUdpMode::Xudp => loop {
                if let Some(result) = self.take_xudp_frame(buffer)? {
                    return Ok(Some(result));
                }
                let mut record = vec![0u8; MAX_DATAGRAM];
                let Some(read) = self.packet.recv(&mut record).await? else {
                    return Ok(None);
                };
                self.read_buf.extend_from_slice(&record[..read]);
                if self.read_buf.len() > 8 * MAX_DATAGRAM {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vmess xudp frame buffer exceeded",
                    ));
                }
            },
        }
    }

    fn take_xudp_frame(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        loop {
            if self.read_buf.len() < 6 {
                return Ok(None);
            }
            let length = u16::from_be_bytes([self.read_buf[0], self.read_buf[1]]) as usize;
            let status = self.read_buf[4];
            let option = self.read_buf[5];
            let extras = length.saturating_sub(4);
            let mut cursor = 6 + extras;
            if cursor + 2 > self.read_buf.len() {
                return Ok(None);
            }
            if status == 3 {
                self.read_buf.clear();
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "vmess xudp stream ended",
                ));
            }
            let data_len =
                u16::from_be_bytes([self.read_buf[cursor], self.read_buf[cursor + 1]]) as usize;
            cursor += 2;
            if cursor + data_len > self.read_buf.len() {
                return Ok(None);
            }
            let target = if extras > 1 {
                parse_vmess_address(&self.read_buf[7..6 + extras])
            } else {
                None
            };
            let payload = self.read_buf[cursor..cursor + data_len].to_vec();
            self.read_buf.drain(..cursor + data_len);
            if status != 2 || option & 1 == 0 {
                continue;
            }
            let target = target.or_else(|| Some(self.bound.clone())).unwrap();
            let len = payload.len().min(buffer.len());
            buffer[..len].copy_from_slice(&payload[..len]);
            return Ok(Some((target, len)));
        }
    }
}


/// UoT magic destination, then v2 (`u16 length`) or legacy v1 (address +
/// `u16 length`) frames.
pub struct SsUot {
    stream: super::shadowsocks::SsStream<BoxStream>,
    version: u8,
    bound: Target,
}

impl SsUot {
    pub async fn connect(
        option: &crate::proxies::ShadowsocksOutbound,
        target: &Target,
        via: &[&crate::proxies::Proxy],
        timeout: std::time::Duration,
        tls: &ClientTls,
    ) -> Result<SsUot, DialError> {
        debug_assert!(option.udp_over_tcp);
        let server = server_stream(&option.server, option.port, via, timeout, tls).await?;
        let magic = Target {
            host: if option.udp_over_tcp_version == 1 {
                "sp.udp-over-tcp.arpa".to_string()
            } else {
                "sp.v2.udp-over-tcp.arpa".to_string()
            },
            port: 0,
        };
        let mut stream = super::shadowsocks::connect(
            server,
            option.cipher,
            option.password.expose(),
            &SocksAddr::encode(&magic),
        )
        .await
        .map_err(|e| handshake("ss-uot", e))?;
        if option.udp_over_tcp_version != 1 {
            // v2 request: isConnect=1 plus the bound destination.
            let mut request = vec![1u8];
            request.extend_from_slice(&SocksAddr::encode(target));
            stream
                .write_all(&request)
                .await
                .map_err(|e| handshake("ss-uot", e))?;
            stream.flush().await.map_err(|e| handshake("ss-uot", e))?;
        }
        Ok(SsUot {
            stream,
            version: option.udp_over_tcp_version,
            bound: target.clone(),
        })
    }

    /// Split into independent read/write halves. The engine keeps one
    /// association per destination (v2 is bound; v1 still sends each
    /// destination in its frame, so per-target is correct and simpler).
    pub fn into_halves(self) -> (SsUotReader, SsUotWriter) {
        let (read, write) = tokio::io::split(self.stream);
        (
            SsUotReader {
                read,
                version: self.version,
                bound: self.bound.clone(),
            },
            SsUotWriter {
                write,
                version: self.version,
                bound: self.bound,
            },
        )
    }
}

/// Read half of one destination-bound ss UoT association.
pub struct SsUotReader {
    read: tokio::io::ReadHalf<super::shadowsocks::SsStream<BoxStream>>,
    version: u8,
    bound: Target,
}

impl SsUotReader {
    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        let mut target = self.bound.clone();
        // v1 frames start with the UoT `AddrParser` source address.
        if self.version == 1 {
            let mut family = [0u8; 1];
            if self.read.read_exact(&mut family).await.is_err() {
                return Ok(None);
            }
            let mut address = vec![family[0]];
            match family[0] {
                0 => {
                    let mut rest = [0u8; 6];
                    if self.read.read_exact(&mut rest).await.is_err() {
                        return Ok(None);
                    }
                    address.extend_from_slice(&rest);
                }
                1 => {
                    let mut rest = [0u8; 18];
                    if self.read.read_exact(&mut rest).await.is_err() {
                        return Ok(None);
                    }
                    address.extend_from_slice(&rest);
                }
                2 => {
                    let mut length = [0u8; 1];
                    if self.read.read_exact(&mut length).await.is_err() {
                        return Ok(None);
                    }
                    address.push(length[0]);
                    let mut rest = vec![0u8; length[0] as usize + 2];
                    if self.read.read_exact(&mut rest).await.is_err() {
                        return Ok(None);
                    }
                    address.extend_from_slice(&rest);
                }
                _ => return Ok(None),
            }
            match parse_uot_address(&address, 0) {
                Some((parsed, _)) => target = parsed,
                None => return Ok(None),
            }
        }
        let mut length = [0u8; 2];
        if self.read.read_exact(&mut length).await.is_err() {
            return Ok(None);
        }
        let length = u16::from_be_bytes(length) as usize;
        if length > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ss UoT datagram larger than the buffer",
            ));
        }
        if self.read.read_exact(&mut buffer[..length]).await.is_err() {
            return Ok(None);
        }
        Ok(Some((target, length)))
    }
}

/// Write half of one destination-bound ss UoT association.
pub struct SsUotWriter {
    write: tokio::io::WriteHalf<super::shadowsocks::SsStream<BoxStream>>,
    version: u8,
    bound: Target,
}

impl SsUotWriter {
    pub async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut frame = Vec::with_capacity(self.bound.host.len() + 4 + payload.len());
        if self.version == 1 {
            frame.extend_from_slice(&uot_address(&self.bound));
        }
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        self.write.write_all(&frame).await?;
        self.write.flush().await
    }
}

/// Identity of one destination-bound association: the selected proxy plus the
/// destination. The pinned outbound opens a packet conn / UoT stream per
/// destination; the engine reuses that association for every datagram to the
/// same target and proxy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UotKey {
    pub proxy: String,
    pub target: Target,
}

/// TUIC `udp-over-stream` association: a TUIC Connect stream to the pinned
/// `sp[.v2].udp-over-tcp.arpa` destination. Version 1 carries the destination
/// in every frame; version 2 sends one UoT request and then bare
/// `u16 length || payload` frames.
pub struct TuicUot {
    stream: super::tuic::QuicStream,
    bound: Target,
    version: u8,
}

impl TuicUot {
    pub async fn connect(
        option: &crate::proxies::TuicOutbound,
        target: &Target,
        via: &[&crate::proxies::Proxy],
        timeout: std::time::Duration,
        tls: &ClientTls,
    ) -> Result<TuicUot, DialError> {
        debug_assert!(option.udp_over_stream);
        // `TuicUdp` refuses a chain by name; the UoT stream must do the same
        // instead of dialling the TUIC server directly and bypassing the hops.
        if via.len() > 1 {
            return Err(DialError::Chain(format!(
                "tuic udp-over-stream through {} is not implemented: a QUIC stream cannot be carried through a SOCKS5/UoT hop; the association is never dialled around the chain",
                via[1].name
            )));
        }
        let (stream, _server, version) =
            super::tuic::dial_uot(option, target, tls, timeout).await?;
        Ok(TuicUot {
            stream,
            bound: target.clone(),
            version,
        })
    }

    pub fn into_halves(self) -> (TuicUotReader, TuicUotWriter) {
        let (read, write) = tokio::io::split(self.stream);
        (
            TuicUotReader {
                read,
                bound: self.bound.clone(),
                version: self.version,
            },
            TuicUotWriter {
                write,
                bound: self.bound,
                version: self.version,
            },
        )
    }
}

pub struct TuicUotReader {
    read: tokio::io::ReadHalf<super::tuic::QuicStream>,
    bound: Target,
    version: u8,
}

impl TuicUotReader {
    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        let mut target = self.bound.clone();
        if self.version == 1 {
            let address = match read_uot_address(&mut self.read).await {
                Ok(address) => address,
                Err(_) => return Ok(None),
            };
            target = address;
        }
        let mut length = [0u8; 2];
        if self.read.read_exact(&mut length).await.is_err() {
            return Ok(None);
        }
        let length = u16::from_be_bytes(length) as usize;
        if length > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tuic UoT datagram larger than the buffer",
            ));
        }
        if self.read.read_exact(&mut buffer[..length]).await.is_err() {
            return Ok(None);
        }
        Ok(Some((target, length)))
    }
}

pub struct TuicUotWriter {
    write: tokio::io::WriteHalf<super::tuic::QuicStream>,
    bound: Target,
    version: u8,
}

impl TuicUotWriter {
    pub async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut frame = Vec::with_capacity(self.bound.host.len() + 4 + payload.len());
        if self.version == 1 {
            frame.extend_from_slice(&super::tuic::uot_address(&self.bound));
        }
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        self.write.write_all(&frame).await?;
        self.write.flush().await
    }
}

async fn read_uot_address<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> io::Result<Target> {
    let family = reader.read_u8().await?;
    let host = match family {
        0 => {
            let mut raw = [0u8; 4];
            reader.read_exact(&mut raw).await?;
            std::net::Ipv4Addr::from(raw).to_string()
        }
        1 => {
            let mut raw = [0u8; 16];
            reader.read_exact(&mut raw).await?;
            std::net::Ipv6Addr::from(raw).to_string()
        }
        2 => {
            let len = reader.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            reader.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).to_string()
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("tuic UoT address family {other} is invalid"),
            ))
        }
    };
    let port = reader.read_u16().await?;
    Ok(Target { host, port })
}

/// Events from a per-target association reader task back to the relay.
pub enum UotEvent {
    Datagram { from: Target, payload: Vec<u8> },
    Closed { key: UotKey, id: u64 },
}

/// Write half of a per-target association, dispatched across the three
/// families whose pinned outbound binds one packet conn per destination.
pub enum UotWriter {
    Anytls(AnyUotWriter),
    SsUot(SsUotWriter),
    Tuic(TuicUotWriter),
    Vmess(super::vmess::VmessPacketWriter),
}

impl UotWriter {
    pub async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        match self {
            UotWriter::Anytls(writer) => writer.send(payload).await,
            UotWriter::SsUot(writer) => writer.send(payload).await,
            UotWriter::Tuic(writer) => writer.send(payload).await,
            UotWriter::Vmess(writer) => writer.send(payload).await,
        }
    }
}

/// Read half of a per-target association.
pub enum UotReader {
    Anytls(AnyUotReader),
    SsUot(SsUotReader),
    Tuic(TuicUotReader),
    Vmess {
        reader: super::vmess::VmessPacketReader,
        /// Plain `command 2` carries no source address on replies; the pinned
        /// packet conn is bound to its destination, so the engine reports that
        /// destination.
        bound: Target,
    },
}

impl UotReader {
    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        match self {
            UotReader::Anytls(reader) => reader.recv(buffer).await,
            UotReader::SsUot(reader) => reader.recv(buffer).await,
            UotReader::Tuic(reader) => reader.recv(buffer).await,
            UotReader::Vmess { reader, bound } => reader
                .recv(buffer)
                .await
                .map(|read| read.map(|length| (bound.clone(), length))),
        }
    }
}

/// Spawn a reader task for one per-target association. Replies are forwarded
/// to the relay through `events`; a closed stream sends `Closed` so the engine
/// can retire the writer instead of silently losing datagrams.
pub fn spawn_uot_reader(
    reader: UotReader,
    key: UotKey,
    id: u64,
    events: tokio::sync::mpsc::UnboundedSender<UotEvent>,
) -> tokio::task::AbortHandle {
    let handle = tokio::spawn(async move {
        let mut reader = reader;
        let mut buffer = vec![0u8; MAX_DATAGRAM];
        loop {
            match reader.recv(&mut buffer).await {
                Ok(Some((from, length))) => {
                    let payload = buffer[..length].to_vec();
                    if events.send(UotEvent::Datagram { from, payload }).is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
        let _ = events.send(UotEvent::Closed { key, id });
    });
    handle.abort_handle()
}

/// Hysteria v1 UDP association (`transport/hysteria/core/client.go`). The
/// pinned `DialUDP` opens one bidirectional stream with `udp=1`, reads the
/// server-assigned session id, and carries every datagram on the QUIC
/// connection:
///
/// ```text
/// session id (u32 BE) | host length (u16 BE) | host | port (u16 BE) |
/// msg id (u16 BE) | fragment id (u8) | fragment count (u8) |
/// data length (u16 BE) | data
/// ```
///
/// One association serves every destination; the server keys sessions by the
/// id and destinations by the address in each datagram. A message larger than
/// the QUIC payload limit is split by `msg id` (never 0 when fragmented).
pub struct HysteriaUdp {
    session: super::hysteria::HysteriaUdpSession,
    msg_id: u16,
    fragments: HysteriaDefragger,
}

impl HysteriaUdp {
    /// `via` is the `dialer-proxy` chain. A QUIC socket cannot ride a SOCKS5
    /// UDP hop here, so any hop is refused by name before the handshake.
    pub async fn connect(
        option: &crate::proxies::HysteriaOutbound,
        via: &[&crate::proxies::Proxy],
        timeout: std::time::Duration,
        tls: &ClientTls,
    ) -> Result<HysteriaUdp, DialError> {
        if via.len() > 1 {
            return Err(DialError::Chain(format!(
                "hysteria udp through {} is not implemented: a QUIC socket cannot be carried through a SOCKS5 UDP hop; the association is never dialled around the chain",
                via[1].name
            )));
        }
        let session = super::hysteria::dial_udp(option, tls, timeout).await?;
        Ok(HysteriaUdp {
            session,
            msg_id: 0,
            fragments: HysteriaDefragger::default(),
        })
    }

    pub async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        if payload.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria: UDP payload exceeds the u16 data-length field",
            ));
        }
        let Some(max) = self.session.connection.max_datagram_size() else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "hysteria: the QUIC peer disabled datagrams",
            ));
        };
        let header = 14 + target.host.len();
        if max <= header {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "hysteria: the QUIC datagram limit {max} cannot carry the {header}-byte header of a {}:{} message",
                    target.host, target.port
                ),
            ));
        }
        let chunk = max - header;
        let total = payload.len().div_ceil(chunk).max(1);
        let total = u8::try_from(total).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria: a datagram needs more than 255 fragments",
            )
        })?;
        if total <= 1 {
            return self.send_message(0, 0, 1, target, payload).await;
        }
        self.msg_id = self.msg_id.wrapping_add(1);
        if self.msg_id == 0 {
            self.msg_id = 1;
        }
        let msg_id = self.msg_id;
        for (index, part) in payload.chunks(chunk).enumerate() {
            self.send_message(msg_id, index as u8, total, target, part)
                .await?;
        }
        Ok(())
    }

    async fn send_message(
        &self,
        msg_id: u16,
        fragment: u8,
        total: u8,
        target: &Target,
        payload: &[u8],
    ) -> io::Result<()> {
        let mut message = Vec::with_capacity(14 + target.host.len() + payload.len());
        message.extend_from_slice(&self.session.session_id.to_be_bytes());
        message.extend_from_slice(&(target.host.len() as u16).to_be_bytes());
        message.extend_from_slice(target.host.as_bytes());
        message.extend_from_slice(&target.port.to_be_bytes());
        message.extend_from_slice(&msg_id.to_be_bytes());
        message.push(fragment);
        message.push(total);
        message.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        message.extend_from_slice(payload);
        self.session
            .connection
            .send_datagram(bytes::Bytes::from(message))
            .map_err(|error| {
                io::Error::new(io::ErrorKind::Other, format!("hysteria: send UDP datagram: {error}"))
            })
    }

    /// Receive one reassembled datagram. `Ok(None)` when the connection ended.
    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        loop {
            let datagram = match self.session.connection.read_datagram().await {
                Ok(datagram) => datagram,
                Err(_) => return Ok(None),
            };
            let Some(message) = decode_hysteria_message(&datagram) else {
                continue;
            };
            if message.session != self.session.session_id {
                continue;
            }
            let Some((target, payload)) = self.fragments.feed(message) else {
                continue;
            };
            if payload.len() > buffer.len() {
                continue;
            }
            buffer[..payload.len()].copy_from_slice(&payload);
            return Ok(Some((target, payload.len())));
        }
    }
}

/// One decoded Hysteria v1 UDP datagram.
struct HysteriaMessage {
    session: u32,
    host: String,
    port: u16,
    msg_id: u16,
    fragment: u8,
    total: u8,
    data: Vec<u8>,
}

fn decode_hysteria_message(datagram: &[u8]) -> Option<HysteriaMessage> {
    let mut cursor = 0usize;
    let session = u32::from_be_bytes(datagram.get(cursor..cursor + 4)?.try_into().ok()?);
    cursor += 4;
    let host_len = u16::from_be_bytes(datagram.get(cursor..cursor + 2)?.try_into().ok()?) as usize;
    cursor += 2;
    let host = String::from_utf8(datagram.get(cursor..cursor + host_len)?.to_vec()).ok()?;
    cursor += host_len;
    let port = u16::from_be_bytes(datagram.get(cursor..cursor + 2)?.try_into().ok()?);
    cursor += 2;
    let msg_id = u16::from_be_bytes(datagram.get(cursor..cursor + 2)?.try_into().ok()?);
    cursor += 2;
    let fragment = *datagram.get(cursor)?;
    cursor += 1;
    let total = *datagram.get(cursor)?;
    cursor += 1;
    let data_len = u16::from_be_bytes(datagram.get(cursor..cursor + 2)?.try_into().ok()?) as usize;
    cursor += 2;
    let data = datagram.get(cursor..cursor + data_len)?.to_vec();
    if cursor + data_len != datagram.len() {
        return None;
    }
    Some(HysteriaMessage {
        session,
        host,
        port,
        msg_id,
        fragment,
        total,
        data,
    })
}

/// Reassembles fragmented Hysteria v1 datagrams by `msg id` (the pinned
/// `defragger` resets when a new message id arrives).
#[derive(Default)]
struct HysteriaDefragger {
    msg_id: u16,
    host: String,
    port: u16,
    frags: Vec<Option<Vec<u8>>>,
    count: u8,
}

impl HysteriaDefragger {
    fn feed(&mut self, message: HysteriaMessage) -> Option<(Target, Vec<u8>)> {
        if message.total <= 1 {
            return Some((
                Target {
                    host: message.host,
                    port: message.port,
                },
                message.data,
            ));
        }
        if message.fragment >= message.total {
            return None;
        }
        if message.msg_id != self.msg_id {
            self.msg_id = message.msg_id;
            self.host = message.host.clone();
            self.port = message.port;
            self.frags = vec![None; message.total as usize];
            self.count = 0;
        } else if self.frags.len() != message.total as usize {
            return None;
        }
        match self.frags.get_mut(message.fragment as usize) {
            Some(slot @ None) => {
                *slot = Some(message.data);
                self.count += 1;
            }
            _ => return None,
        }
        if self.count as usize != self.frags.len() {
            return None;
        }
        let mut payload = Vec::new();
        for fragment in self.frags.drain(..).flatten() {
            payload.extend_from_slice(&fragment);
        }
        self.count = 0;
        Some((
            Target {
                host: std::mem::take(&mut self.host),
                port: self.port,
            },
            payload,
        ))
    }
}

/// Largest UDP payload the Hysteria2 session carries (`protocol.MaxUDPSize`).
const HYSTERIA2_MAX_UDP: usize = 4096;

/// Hysteria2 UDP association over QUIC datagrams (`sing-quic/hysteria2`).
///
/// The pinned client does not use the legacy `0x403` stream-based session: a
/// `ListenPacket` allocates one session id per QUIC connection and every
/// datagram is
///
/// ```text
/// session id (u32 BE) | packet id (u16 BE) | fragment id (u8) |
/// fragment count (u8) | address length (QUIC varint) | address |
/// data...
/// ```
///
/// where `address` is the textual target (`host:port`, `[v6]:port`). The server
/// creates one packet conn per session id on the first message and routes each
/// message by its own destination, so one association serves every target.
/// Payloads larger than `udp-mtu` (pinned default 1197) are split into
/// `fragment count` datagrams that the peer reassembles by `packet id`.
pub struct Hysteria2Udp {
    connection: quinn::Connection,
    /// Kept alive while the association is open (dropping the endpoint closes
    /// the QUIC connection); the HTTP/3 control streams must stay open too.
    _endpoint: quinn::Endpoint,
    _hold: Vec<quinn::SendStream>,
    session_id: u32,
    packet_id: u16,
    udp_mtu: usize,
    fragments: Hysteria2Fragments,
}

impl Hysteria2Udp {
    /// `via` is the `dialer-proxy` chain of the matched proxy. A QUIC socket
    /// cannot be carried through a SOCKS5 UDP hop here, so any hop is refused
    /// by name before the QUIC handshake; the configuration itself still loads
    /// (the pinned client accepts it).
    pub async fn connect(
        option: &crate::proxies::Hysteria2Outbound,
        via: &[&crate::proxies::Proxy],
        timeout: std::time::Duration,
        tls: &ClientTls,
    ) -> Result<Hysteria2Udp, DialError> {
        if via.len() > 1 {
            return Err(DialError::Chain(format!(
                "hysteria2 udp through {} is not implemented: a QUIC socket cannot be carried through a SOCKS5 UDP hop; the association is never dialled around the chain",
                via[1].name
            )));
        }
        let authenticated = super::hysteria2::connect_authenticated(option, tls, timeout).await?;
        let udp_mtu = super::hysteria2::udp_session_mtu(option);
        Ok(Hysteria2Udp {
            connection: authenticated.connection,
            _endpoint: authenticated.endpoint,
            _hold: authenticated.hold,
            // The pinned client starts each connection's session ids at 0; one
            // connection carries exactly one association here.
            session_id: 0,
            packet_id: 0,
            udp_mtu,
            fragments: Hysteria2Fragments::default(),
        })
    }

    /// Split `target || payload` into datagrams and send them.
    pub async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        if payload.len() > HYSTERIA2_MAX_UDP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "hysteria2: UDP payload of {} bytes exceeds the session maximum of {HYSTERIA2_MAX_UDP} bytes",
                    payload.len()
                ),
            ));
        }
        let address = target.authority();
        let header = hysteria2_header_size(&address);
        // The configured `udp-mtu` bounds the message; the QUIC path MTU can be
        // smaller, so the effective limit is the smaller of the two.
        let path_limit = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "hysteria2: QUIC peer disabled datagrams"))?;
        let limit = self.udp_mtu.min(path_limit);
        if limit <= header {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "hysteria2: udp-mtu {limit} cannot carry the {header}-byte header of a {address} datagram"
                ),
            ));
        }
        let chunk = limit - header;
        self.packet_id = self.packet_id.wrapping_add(1);
        let packet_id = self.packet_id;
        let total = payload.len().div_ceil(chunk);
        if total > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria2: a datagram needs more than 255 fragments",
            ));
        }
        if total <= 1 {
            self.send_fragment(packet_id, 0, 1, &address, payload)
                .await
        } else {
            for (index, part) in payload.chunks(chunk).enumerate() {
                self.send_fragment(packet_id, index as u8, total as u8, &address, part)
                    .await?;
            }
            Ok(())
        }
    }

    async fn send_fragment(
        &self,
        packet_id: u16,
        fragment_id: u8,
        fragment_total: u8,
        address: &str,
        payload: &[u8],
    ) -> io::Result<()> {
        let mut message = Vec::with_capacity(8 + address.len() + 3 + payload.len());
        message.extend_from_slice(&self.session_id.to_be_bytes());
        message.extend_from_slice(&packet_id.to_be_bytes());
        message.push(fragment_id);
        message.push(fragment_total);
        super::h3::encode_varint(address.len() as u64, &mut message);
        message.extend_from_slice(address.as_bytes());
        message.extend_from_slice(payload);
        self.connection
            .send_datagram(bytes::Bytes::from(message))
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("hysteria2: send UDP datagram: {error}"),
                )
            })
    }

    /// Receive one reassembled datagram. `Ok(None)` when the QUIC connection
    /// ended.
    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        loop {
            let datagram = match self.connection.read_datagram().await {
                Ok(datagram) => datagram,
                Err(_) => return Ok(None),
            };
            let Some(message) = decode_hysteria2_datagram(&datagram) else {
                continue;
            };
            if message.session != self.session_id {
                continue;
            }
            let Some((address, payload)) = self.fragments.feed(
                message.packet,
                message.fragment,
                message.total,
                message.address,
                message.data,
            ) else {
                continue;
            };
            let Some(target) = parse_authority(&address) else {
                continue;
            };
            if payload.len() > buffer.len() {
                continue;
            }
            buffer[..payload.len()].copy_from_slice(&payload);
            return Ok(Some((target, payload.len())));
        }
    }
}

/// One decoded Hysteria2 UDP datagram.
struct Hysteria2Message {
    session: u32,
    packet: u16,
    fragment: u8,
    total: u8,
    address: String,
    data: Vec<u8>,
}

/// Header bytes before the payload: session, packet, two fragment bytes and
/// the varint-prefixed address.
fn hysteria2_header_size(address: &str) -> usize {
    8 + hysteria2_varint_len(address.len() as u64) + address.len()
}

fn hysteria2_varint_len(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16383 => 2,
        16384..=1_073_741_823 => 4,
        _ => 8,
    }
}

fn decode_hysteria2_datagram(bytes: &[u8]) -> Option<Hysteria2Message> {
    if bytes.len() < 8 {
        return None;
    }
    let session = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let packet = u16::from_be_bytes([bytes[4], bytes[5]]);
    let fragment = bytes[6];
    let total = bytes[7];
    let (length, prefix) = read_quic_varint(bytes, 8)?;
    let start = 8 + prefix;
    let end = start.checked_add(usize::try_from(length).ok()?)?;
    if end > bytes.len() {
        return None;
    }
    let address = String::from_utf8(bytes[start..end].to_vec()).ok()?;
    Some(Hysteria2Message {
        session,
        packet,
        fragment,
        total,
        address,
        data: bytes[end..].to_vec(),
    })
}

/// Read one QUIC varint (RFC 9000 §16) at `offset`.
fn read_quic_varint(bytes: &[u8], offset: usize) -> Option<(u64, usize)> {
    let first = *bytes.get(offset)?;
    let (length, mask) = match first >> 6 {
        0 => (1, 0x3f),
        1 => (2, 0x3f),
        2 => (4, 0x3f),
        _ => (8, 0x3f),
    };
    let slice = bytes.get(offset..offset + length)?;
    let mut value = u64::from(slice[0] & mask);
    for byte in &slice[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, length))
}

/// `host:port` / `[v6]:port` as the Hysteria2 address field carries it.
fn parse_authority(authority: &str) -> Option<Target> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some(Target {
            host: host.to_string(),
            port: port.parse().ok()?,
        });
    }
    let (host, port) = authority.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    Some(Target {
        host: host.to_string(),
        port: port.parse().ok()?,
    })
}

/// Reassembly buffers for fragmented datagrams, bounded so a peer cannot grow
/// memory without limit.
#[derive(Default)]
struct Hysteria2Fragments {
    pending: std::collections::HashMap<u16, Hysteria2Pending>,
    order: std::collections::VecDeque<u16>,
}

struct Hysteria2Pending {
    total: u8,
    address: String,
    parts: Vec<Option<Vec<u8>>>,
    received: u8,
    /// Monotonic time of the last fragment, so an incomplete message ages out
    /// like the pinned `newUDPDefragger` (a 10-second LRU refreshed on get).
    last_seen: std::time::Instant,
}

impl Hysteria2Fragments {
    const MAX_PENDING: usize = 64;
    /// The pinned `newUDPDefragger` drops an entry after 10 s without a
    /// fragment; without an age an abandoned message would live until 64 newer
    /// packet ids evicted it.
    const MAX_AGE: std::time::Duration = std::time::Duration::from_secs(10);

    /// Feed one datagram; returns the address and payload once complete.
    fn feed(
        &mut self,
        packet: u16,
        fragment: u8,
        total: u8,
        address: String,
        data: Vec<u8>,
    ) -> Option<(String, Vec<u8>)> {
        self.feed_at(std::time::Instant::now(), packet, fragment, total, address, data)
    }

    fn feed_at(
        &mut self,
        now: std::time::Instant,
        packet: u16,
        fragment: u8,
        total: u8,
        address: String,
        data: Vec<u8>,
    ) -> Option<(String, Vec<u8>)> {
        if total <= 1 {
            return Some((address, data));
        }
        if fragment >= total {
            return None;
        }
        self.expire(now);
        let entry = match self.pending.get_mut(&packet) {
            Some(entry) if entry.total == total => entry,
            _ => {
                if !self.pending.contains_key(&packet) {
                    self.order.push_back(packet);
                    while self.order.len() > Self::MAX_PENDING {
                        if let Some(oldest) = self.order.pop_front() {
                            self.pending.remove(&oldest);
                        }
                    }
                }
                self.pending.insert(
                    packet,
                    Hysteria2Pending {
                        total,
                        address: address.clone(),
                        parts: vec![None; usize::from(total)],
                        received: 0,
                        last_seen: now,
                    },
                );
                self.pending.get_mut(&packet).expect("inserted above")
            }
        };
        entry.last_seen = now;
        let slot = entry.parts.get_mut(usize::from(fragment))?;
        if slot.is_some() {
            return None;
        }
        *slot = Some(data);
        entry.received += 1;
        if entry.received != entry.total {
            return None;
        }
        let entry = self.pending.remove(&packet)?;
        self.order.retain(|id| *id != packet);
        let mut payload = Vec::new();
        for part in entry.parts {
            payload.extend_from_slice(&part?);
        }
        Some((entry.address, payload))
    }

    /// Drop incomplete messages that no fragment refreshed within `MAX_AGE`.
    fn expire(&mut self, now: std::time::Instant) {
        if self.pending.is_empty() {
            return;
        }
        self.pending.retain(|_, pending| {
            now.saturating_duration_since(pending.last_seen) < Self::MAX_AGE
        });
        self.order.retain(|id| self.pending.contains_key(id));
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

    #[test]
    fn resolve_all_applies_the_scoped_ip_version_to_a_literal() {
        // `ip-version` is a BasicOption filter, not only a resolver hint: the
        // pinned dialer refuses an address of the other family.
        let target = Target {
            host: "::1".into(),
            port: 53,
        };
        let options = crate::proxies::DialerOptions {
            ip_version: crate::proxies::IpVersion::V4Only,
            ..Default::default()
        };
        let result = futures_block_on(super::super::with_dialer(options, resolve_all(&target)));
        assert!(result.is_err(), "ipv4 must reject an IPv6 literal");
        let options = crate::proxies::DialerOptions {
            ip_version: crate::proxies::IpVersion::V6Only,
            ..Default::default()
        };
        let result = futures_block_on(super::super::with_dialer(options, resolve_all(&target)));
        assert_eq!(result.expect("ipv6 accepts ::1"), vec![addr("::1", 53)]);
    }

    #[test]
    fn hysteria2_datagram_layout_matches_the_pinned_udpmessage() {
        // session 0x01020304, packet 0x0506, fragment 1/3, "1.2.3.4:53", "hi":
        // the pinned `UDPMessage.Serialize` writes 4+2+1+1 big-endian bytes, a
        // QUIC varint address length and the address text.
        let address = "1.2.3.4:53";
        let header = hysteria2_header_size(address);
        assert_eq!(header, 8 + 1 + address.len());
        let mut message = Vec::new();
        message.extend_from_slice(&0x0102_0304u32.to_be_bytes());
        message.extend_from_slice(&0x0506u16.to_be_bytes());
        message.push(1);
        message.push(3);
        super::super::h3::encode_varint(address.len() as u64, &mut message);
        message.extend_from_slice(address.as_bytes());
        message.extend_from_slice(b"hi");
        let decoded = decode_hysteria2_datagram(&message).expect("decode");
        assert_eq!(decoded.session, 0x0102_0304);
        assert_eq!(decoded.packet, 0x0506);
        assert_eq!(decoded.fragment, 1);
        assert_eq!(decoded.total, 3);
        assert_eq!(decoded.address, address);
        assert_eq!(decoded.data, b"hi");
    }

    #[test]
    fn hysteria2_fragments_reassemble_by_packet_id() {
        let mut fragments = Hysteria2Fragments::default();
        // Out of order: fragment 1 arrives before fragment 0.
        assert!(fragments
            .feed(7, 1, 2, "1.2.3.4:53".into(), b"world".to_vec())
            .is_none());
        let (address, payload) = fragments
            .feed(7, 0, 2, "1.2.3.4:53".into(), b"hello ".to_vec())
            .expect("complete");
        assert_eq!(address, "1.2.3.4:53");
        assert_eq!(payload, b"hello world");
        // A duplicate after completion starts no new message.
        assert!(fragments
            .feed(7, 0, 2, "1.2.3.4:53".into(), b"hello ".to_vec())
            .is_none());
    }

    #[test]
    fn hysteria2_authority_round_trips_ipv4_and_ipv6() {
        let v4 = parse_authority("1.2.3.4:53").expect("v4");
        assert_eq!(v4.host, "1.2.3.4");
        assert_eq!(v4.port, 53);
        let v6 = Target {
            host: "::1".into(),
            port: 5353,
        };
        let parsed = parse_authority(&v6.authority()).expect("v6");
        assert_eq!(parsed, v6);
        let name = parse_authority("example.org:443").expect("name");
        assert_eq!(name.host, "example.org");
        assert_eq!(name.port, 443);
        assert!(parse_authority("no-port").is_none());
    }

    #[test]
    fn hysteria2_fragments_expire_incomplete_messages_like_the_pinned_lru() {
        let mut fragments = Hysteria2Fragments::default();
        let start = std::time::Instant::now();
        assert!(fragments
            .feed_at(start, 9, 0, 2, "1.2.3.4:53".into(), b"hello ".to_vec())
            .is_none());
        // A fragment within the 10 s age completes the message.
        let (_, payload) = fragments
            .feed_at(
                start + std::time::Duration::from_secs(9),
                9,
                1,
                2,
                "1.2.3.4:53".into(),
                b"world".to_vec(),
            )
            .expect("completes inside the age");
        assert_eq!(payload, b"hello world");
        // An abandoned message is dropped after 10 s: the late fragment must
        // start a new message instead of completing the old one.
        assert!(fragments
            .feed_at(start, 10, 0, 2, "1.2.3.4:53".into(), b"first".to_vec())
            .is_none());
        fragments.expire(start + Hysteria2Fragments::MAX_AGE + std::time::Duration::from_secs(1));
        assert!(fragments.pending.is_empty(), "the expired entry was reaped");
        assert!(fragments
            .feed_at(
                start + Hysteria2Fragments::MAX_AGE + std::time::Duration::from_secs(1),
                10,
                1,
                2,
                "1.2.3.4:53".into(),
                b"second".to_vec(),
            )
            .is_none());
        assert_eq!(
            fragments.pending.get(&10).map(|pending| pending.received),
            Some(1),
            "the stale fragment did not complete the expired message"
        );
    }

    #[test]
    fn hysteria2_udp_through_a_hop_is_a_named_chain_error() {
        // The point of the load-time exemption: the config loads, but the
        // association itself refuses the hop by name before any QUIC dial.
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "proxies:\n  - {name: q, type: hysteria2, server: 127.0.0.1, port: 8443, password: p, dialer-proxy: hop}\n  - {name: hop, type: socks5, server: 127.0.0.1, port: 1081}\n",
        )
        .expect("yaml");
        let proxies = crate::proxies::parse_proxies(yaml.get("proxies").expect("proxies"))
            .expect("a hysteria2 chain still loads");
        let option = match &proxies[0].protocol {
            crate::proxies::Protocol::Hysteria2(option) => option,
            other => panic!("expected hysteria2, got {other:?}"),
        };
        let via: Vec<&crate::proxies::Proxy> = proxies.iter().collect();
        let error = match futures_block_on(Hysteria2Udp::connect(
            option,
            &via,
            std::time::Duration::from_secs(1),
            &crate::outbound::tls::ClientTls::new(&[]),
        )) {
            Ok(_) => panic!("a chain must be refused"),
            Err(error) => error,
        };
        let text = error.to_string();
        assert!(text.contains("hysteria2 udp through hop"), "{text}");
    }

    #[test]
    fn hysteria_udp_through_a_hop_is_a_named_chain_error() {
        // T32-A3: `validate_udp_chains` exempts Hysteria v1 exactly like
        // Hysteria2, so a legal pinned file loads; the association refuses the
        // hop by name before any QUIC dial and never reaches the server
        // directly. Both the reviewer's shapes are covered: a non-socks5 hop
        // and a multi-hop chain.
        for (label, hops) in [
            (
                "non-socks5 hop",
                "  - {name: hop, type: vless, server: 127.0.0.1, port: 2, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true}\n",
            ),
            (
                "multi-hop",
                "  - {name: hop, type: socks5, server: 127.0.0.1, port: 1081, dialer-proxy: hop2}\n  - {name: hop2, type: socks5, server: 127.0.0.1, port: 1082}\n",
            ),
        ] {
            let yaml: serde_yaml::Value = serde_yaml::from_str(&format!(
                "proxies:\n  - {{name: q, type: hysteria, server: 127.0.0.1, port: 443, up: 50 Mbps, down: 50 Mbps, auth-str: p, dialer-proxy: hop}}\n{hops}"
            ))
            .expect("yaml");
            let proxies = crate::proxies::parse_proxies(yaml.get("proxies").expect("proxies"))
                .unwrap_or_else(|e| panic!("a hysteria chain ({label}) still loads: {e}"));
            let option = match &proxies[0].protocol {
                crate::proxies::Protocol::Hysteria(option) => option,
                other => panic!("expected hysteria, got {other:?}"),
            };
            let via: Vec<&crate::proxies::Proxy> = proxies.iter().collect();
            let error = match futures_block_on(HysteriaUdp::connect(
                option,
                &via,
                std::time::Duration::from_secs(1),
                &crate::outbound::tls::ClientTls::new(&[]),
            )) {
                Ok(_) => panic!("a chain must be refused ({label})"),
                Err(error) => error,
            };
            assert!(
                matches!(error, crate::outbound::DialError::Chain(_)),
                "{label}: {error:?}"
            );
            let text = error.to_string();
            assert!(text.contains("hysteria udp through hop"), "{label}: {text}");
        }
    }

    #[test]
    fn hysteria_tcp_through_a_hop_still_refuses_the_exit_at_dial_time() {
        // Before T32 enabled Hysteria v1 UDP the chained file loaded and TCP
        // was refused by `dial_chain` when the rule selected the proxy; the
        // load-time exemption must not change that, and must not let TCP dial
        // the server directly around the hop.
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "proxies:\n  - {name: q, type: hysteria, server: 127.0.0.1, port: 443, up: 50 Mbps, down: 50 Mbps, auth-str: p, dialer-proxy: hop}\n  - {name: hop, type: vless, server: 127.0.0.1, port: 2, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true}\n",
        )
        .expect("yaml");
        let proxies = crate::proxies::parse_proxies(yaml.get("proxies").expect("proxies"))
            .expect("a hysteria chain still loads");
        let chain: Vec<&crate::proxies::Proxy> = proxies.iter().collect();
        let target = Target {
            host: "example.org".into(),
            port: 443,
        };
        let error = match futures_block_on(crate::outbound::dial_chain(
            &chain,
            &target,
            std::time::Duration::from_secs(1),
            &crate::outbound::tls::ClientTls::new(&[]),
        )) {
            Ok(_) => panic!("the TCP exit must be refused"),
            Err(error) => error,
        };
        assert!(
            matches!(error, crate::outbound::DialError::Chain(_)),
            "{error:?}"
        );
        let text = error.to_string();
        assert!(
            text.contains("dialer-proxy exit q(hysteria) is not supported"),
            "{text}"
        );
    }

    #[test]
    fn tuic_uot_through_a_hop_is_a_named_chain_error() {
        // `TuicUdp` refuses a chain; the per-destination UoT stream must not
        // dial the TUIC server directly and bypass the hop.
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "proxies:\n  - {name: q, type: tuic, server: 127.0.0.1, port: 8443, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, password: p, udp-over-stream: true, dialer-proxy: hop}\n  - {name: hop, type: socks5, server: 127.0.0.1, port: 1081}\n",
        )
        .expect("yaml");
        let proxies = crate::proxies::parse_proxies(yaml.get("proxies").expect("proxies"))
            .expect("a TUIC UoT chain still loads");
        let option = match &proxies[0].protocol {
            crate::proxies::Protocol::Tuic(option) => option,
            other => panic!("expected tuic, got {other:?}"),
        };
        let via: Vec<&crate::proxies::Proxy> = proxies.iter().collect();
        let target = Target {
            host: "127.0.0.1".into(),
            port: 9,
        };
        let error = match futures_block_on(TuicUot::connect(
            option,
            &target,
            &via,
            std::time::Duration::from_secs(1),
            &crate::outbound::tls::ClientTls::new(&[]),
        )) {
            Ok(_) => panic!("a chain must be refused"),
            Err(error) => error,
        };
        let text = error.to_string();
        assert!(text.contains("tuic udp-over-stream through hop"), "{text}");
    }

    #[test]
    fn hysteria_udp_fragments_reassemble_by_message_id() {
        let encode = |msg_id: u16, fragment: u8, total: u8, data: &[u8]| {
            let mut message = Vec::new();
            message.extend_from_slice(&7u32.to_be_bytes());
            message.extend_from_slice(&9u16.to_be_bytes());
            message.extend_from_slice(b"127.0.0.1");
            message.extend_from_slice(&53u16.to_be_bytes());
            message.extend_from_slice(&msg_id.to_be_bytes());
            message.push(fragment);
            message.push(total);
            message.extend_from_slice(&(data.len() as u16).to_be_bytes());
            message.extend_from_slice(data);
            message
        };
        let mut defragger = HysteriaDefragger::default();
        let second = decode_hysteria_message(&encode(9, 1, 2, b"world")).expect("decode");
        assert_eq!(second.session, 7);
        assert!(defragger.feed(second).is_none(), "the first half is missing");
        let first = decode_hysteria_message(&encode(9, 0, 2, b"hello ")).expect("decode");
        let (target, payload) = defragger.feed(first).expect("both halves now");
        assert_eq!(target.host, "127.0.0.1");
        assert_eq!(target.port, 53);
        assert_eq!(payload, b"hello world");
        // A new message id discards an incomplete one instead of joining it.
        let stale = decode_hysteria_message(&encode(10, 1, 2, b"b")).expect("decode");
        assert!(defragger.feed(stale).is_none());
        let fresh = decode_hysteria_message(&encode(11, 0, 2, b"a")).expect("decode");
        assert!(defragger.feed(fresh).is_none());
        let other_half = decode_hysteria_message(&encode(11, 1, 2, b"c")).expect("decode");
        let (_, payload) = defragger.feed(other_half).expect("fresh message completes");
        assert_eq!(payload, b"ac");
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
