//! SOCKS5 outbound (RFC 1928 + RFC 1929 username/password), optionally over TLS.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use super::{connect_hop, handshake, tls, BoxStream, DialError, Dialed, SocksAddr, Target};
use crate::proxies::{Proxy, Socks5Outbound};

use super::tls::ClientTls;

pub async fn dial(
    option: &Socks5Outbound,
    target: &Target,
    via: &[&Proxy],
    _timeout: Duration,
    tls: &ClientTls,
) -> Result<Dialed, DialError> {
    if !via.is_empty() {
        // `tunnel()` is how dial_with_rest reaches a hop that itself carries a
        // chain; calling `dial` directly for such a hop would bypass it.
        return Err(DialError::Chain(format!(
            "socks5 '{}' reached through a dialer-proxy chain: internal dispatch reached dial() instead of tunnel()",
            option.server
        )));
    }
    let (tcp, server) = connect_hop(&option.server, option.port).await?;
    let stream: BoxStream = if option.tls {
        let mut stream = tls::wrap(tcp, &option.server, &option.tls_settings, tls)
            .await
            .map_err(|e| handshake("socks5 tls", e))?;
        negotiate(&mut stream, option, target)
            .await
            .map_err(|e| handshake("socks5", e))?;
        Box::new(stream)
    } else {
        let mut stream = tcp;
        negotiate(&mut stream, option, target)
            .await
            .map_err(|e| handshake("socks5", e))?;
        Box::new(stream)
    };
    Ok(Dialed { stream, server })
}

/// Tunnel a destination through this SOCKS5 proxy (used when this proxy is
/// the `dialer-proxy` of another hop), returning the split stream.
pub async fn tunnel(
    option: &Socks5Outbound,
    target: &str,
    port: u16,
    via: &[&Proxy],
    timeout: Duration,
    tls: &ClientTls,
) -> Result<(ReadHalf<BoxStream>, WriteHalf<BoxStream>), DialError> {
    let request = Target {
        host: target.to_string(),
        port,
    };
    let dialed = dial(option, &request, via, timeout, tls).await?;
    Ok(dialed.into_parts())
}

/// SOCKS5 negotiation over an existing stream (a hop reached through a
/// `dialer-proxy`); TLS is not re-applied here because the transport already
/// belongs to the previous hop.
pub async fn negotiate_stream(
    mut stream: BoxStream,
    option: &Socks5Outbound,
    target: &Target,
) -> std::io::Result<BoxStream> {
    if option.tls {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a socks5 hop reached through a dialer-proxy cannot use tls: true (the transport is owned by the previous hop)",
        ));
    }
    negotiate(&mut stream, option, target).await?;
    Ok(stream)
}

async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    option: &Socks5Outbound,
    target: &Target,
) -> io::Result<()> {
    authenticate(stream, option).await?;
    request(stream, 0x01, target).await.map(|_| ())
}

/// RFC 1928 method negotiation plus RFC 1929 authentication.
async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    option: &Socks5Outbound,
) -> io::Result<()> {
    if option.username.is_some() {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection).await?;
    if selection[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a SOCKS5 server",
        ));
    }
    match selection[1] {
        0x00 => {}
        0x02 => {
            let Some(username) = &option.username else {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS5 server requires username/password but none was configured",
                ));
            };
            let password = option.password.as_ref().map(|p| p.expose()).unwrap_or("");
            let mut auth = vec![0x01, username.expose().len() as u8];
            auth.extend_from_slice(username.expose().as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            stream.write_all(&auth).await?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await?;
            if status[1] != 0x00 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS5 username/password authentication failed",
                ));
            }
        }
        0xFF => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 server accepted none of the offered methods",
            ));
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("SOCKS5 server selected unoffered method {other:#x}"),
            ));
        }
    }
    Ok(())
}

/// Send one CONNECT/UDP-ASSOCIATE request and return the server's bound address.
async fn request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    command: u8,
    target: &Target,
) -> io::Result<SocketAddr> {
    let mut request = Vec::with_capacity(3 + 3 + target.host.len());
    request.extend_from_slice(&[0x05, command, 0x00]);
    request.extend_from_slice(&SocksAddr::encode(target));
    stream.write_all(&request).await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad SOCKS5 reply version",
        ));
    }
    if reply[1] != 0x00 {
        let reason = match reply[1] {
            0x01 => "general failure",
            0x02 => "not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown",
        };
        let command = if command == 0x03 { "UDP ASSOCIATE" } else { "CONNECT" };
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 {command} failed: {reason} ({:#04x})", reply[1]),
        ));
    }
    // BND.ADDR/BND.PORT: the relay the client must use for UDP.
    let host = match reply[3] {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            IpAddr::from(addr)
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            IpAddr::from(addr)
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            match String::from_utf8_lossy(&name).parse::<IpAddr>() {
                Ok(ip) => ip,
                // A named relay is unusual; resolve it through the system.
                Err(_) => {
                    let name = String::from_utf8_lossy(&name).to_string();
                    let mut port = [0u8; 2];
                    stream.read_exact(&mut port).await?;
                    let addrs = tokio::net::lookup_host((name.as_str(), u16::from_be_bytes(port)))
                        .await?;
                    return addrs.into_iter().next().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "relay name resolved to nothing")
                    });
                }
            }
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("SOCKS5 reply address type {other}"),
            ))
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(SocketAddr::new(host, u16::from_be_bytes(port)))
}

/// Client side of SOCKS5 `UDP ASSOCIATE`: the control connection stays open for
/// the lifetime of the association and each datagram is sent to the relay the
/// server named, wrapped in the RFC 1928 UDP request header.
pub struct Socks5Udp {
    socket: tokio::net::UdpSocket,
    relay: SocketAddr,
    _control: BoxStream,
}

impl Socks5Udp {
    pub async fn connect(
        option: &Socks5Outbound,
        timeout: Duration,
        tls: &ClientTls,
    ) -> Result<Socks5Udp, DialError> {
        let (tcp, _) = connect_hop(&option.server, option.port).await?;
        let mut control: BoxStream = if option.tls {
            let stream = tls::wrap(tcp, &option.server, &option.tls_settings, tls)
                .await
                .map_err(|e| handshake("socks5-udp tls", e))?;
            Box::new(stream)
        } else {
            Box::new(tcp)
        };
        let inner = async {
            authenticate(&mut control, option).await?;
            let any = Target {
                host: "0.0.0.0".to_string(),
                port: 0,
            };
            request(&mut control, 0x03, &any).await
        };
        let relay = match tokio::time::timeout(timeout, inner).await {
            Ok(Ok(relay)) => relay,
            Ok(Err(e)) => return Err(handshake("socks5-udp", e)),
            Err(_) => return Err(DialError::Timeout(timeout)),
        };
        // The relay may be reported as 0.0.0.0 when the server does not know its
        // external address; use the server's address in that case.
        let relay = if relay.ip().is_unspecified() {
            let ip = if let Ok(ip) = option.server.parse::<IpAddr>() {
                ip
            } else {
                super::resolve(&option.server, option.port)
                    .await
                    .map(|addr| addr.ip())
                    .map_err(|e| handshake("socks5-udp relay", io::Error::other(format!("{e}"))))?
            };
            SocketAddr::new(ip, relay.port())
        } else {
            relay
        };
        let bind = if relay.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = tokio::net::UdpSocket::bind(bind)
            .await
            .map_err(|source| DialError::Connect {
                addr: bind.to_string(),
                source,
            })?;
        Ok(Socks5Udp {
            socket,
            relay,
            _control: control,
        })
    }

    pub fn relay(&self) -> SocketAddr {
        self.relay
    }

    /// Send one payload to `target` through the relay.
    pub async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        let mut packet = vec![0u8, 0u8, 0u8];
        packet.extend_from_slice(&SocksAddr::encode(target));
        packet.extend_from_slice(payload);
        self.socket.send_to(&packet, self.relay).await.map(|_| ())
    }

    /// Receive one relayed datagram; `None` when it is not from the relay.
    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        let (read, from) = self.socket.recv_from(buffer).await?;
        if from != self.relay {
            return Ok(None);
        }
        let Some(datagram) = super::udp::parse_datagram(&buffer[..read]) else {
            return Ok(None);
        };
        let payload = &buffer[datagram.offset..read];
        let len = payload.len();
        buffer.copy_within(datagram.offset..read, 0);
        Ok(Some((datagram.target, len)))
    }
}
