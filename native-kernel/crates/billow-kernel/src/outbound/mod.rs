//! Protocol outbounds: dial one configured proxy to reach a destination.
//!
//! Every variant establishes a real TCP connection to the configured server
//! (optionally TLS / WebSocket), performs the protocol handshake and hands
//! back a byte stream. Boundaries are explicit:
//!
//! - `udp` on the rule path is accepted only where a UDP transport exists
//!   (ss and trojan associations); the inbound still refuses UDP ASSOCIATE,
//!   so no rule traffic reaches those paths yet (see `CAPABILITY.md`).
//! - Any failed handshake, TLS verification or authentication aborts the
//!   session; the client sees the inbound failure reply.

pub mod anytls;
pub mod http;
pub mod shadowsocks;
pub mod socks5;
pub mod tls;
pub mod trojan;
pub mod vless;
pub mod ws;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::proxies::{Protocol, Proxy};

/// Boxed duplex stream with half-close support (plain TCP, TLS, TLS+WS, ...).
pub type BoxStream = Box<dyn Stream>;

pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

/// One dial target as requested by the inbound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// SOCKS5 address encoding used by SOCKS5 requests, Shadowsocks and Trojan.
pub enum SocksAddr {}

impl SocksAddr {
    pub fn encode(target: &Target) -> Vec<u8> {
        let mut out = Vec::with_capacity(target.host.len() + 20);
        if let Ok(ip) = target.host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => {
                    out.push(0x01);
                    out.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    out.push(0x04);
                    out.extend_from_slice(&v6.octets());
                }
            }
        } else {
            out.push(0x03);
            out.push(target.host.len().min(255) as u8);
            out.extend_from_slice(&target.host.as_bytes()[..target.host.len().min(255)]);
        }
        out.extend_from_slice(&target.port.to_be_bytes());
        out
    }
}

/// Failure of one outbound attempt; `err` is logged, the session fails.
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    #[error("resolve {host}: {source}")]
    Resolve { host: String, source: io::Error },
    #[error("connect {addr}: {source}")]
    Connect {
        addr: String,
        #[source]
        source: io::Error,
    },
    #[error("{protocol} handshake: {source}")]
    Handshake {
        protocol: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("timed out after {0:?}")]
    Timeout(Duration),
    #[error("dialer-proxy chain: {0}")]
    Chain(String),
}

/// An established outbound session before the inbound success reply.
pub struct Dialed {
    pub stream: BoxStream,
    /// Where the protocol server was reached (logged as the session exit).
    pub server: SocketAddr,
}

impl Dialed {
    pub(crate) fn into_parts(
        self,
    ) -> (
        tokio::io::ReadHalf<BoxStream>,
        tokio::io::WriteHalf<BoxStream>,
    ) {
        tokio::io::split(self.stream)
    }
}

/// Best-effort peer address for a hop reached through a chain (its server may
/// be a name the first hop resolved).
pub fn peer_of(proxy: &Proxy) -> SocketAddr {
    let (host, port) = proxy.server();
    match host.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, port),
        Err(_) => SocketAddr::from(([0, 0, 0, 0], port)),
    }
}

/// Dial `target` through `proxy`.
pub async fn dial(proxy: &Proxy, target: &Target, timeout: Duration) -> Result<Dialed, DialError> {
    match tokio::time::timeout(timeout, dial_inner(&proxy.protocol, target, &[], timeout)).await {
        Ok(result) => result,
        Err(_) => Err(DialError::Timeout(timeout)),
    }
}

/// Dial `target` through the `dialer-proxy` chain that starts at `chain[0]`;
/// `chain[i].dialer_proxy == chain[i+1].name` (validated at configuration
/// load). Every hop except the last dials the next hop's `server:port` as its
/// own destination, so the servers after the first hop are resolved and
/// reached by the previous hop, never locally. Each hop is bounded by the same
/// timeout; the total is bounded by the caller's own timeout.
pub async fn dial_chain(
    chain: &[&Proxy],
    target: &Target,
    timeout: Duration,
) -> Result<Dialed, DialError> {
    // The matched proxy may itself be reached through `dialer-proxy`; the
    // effective chain starts at the first hop without one.
    let head = chain
        .iter()
        .position(|proxy| proxy.dialer_proxy().is_none())
        .ok_or_else(|| DialError::Chain(format!("no chain head without a dialer-proxy in [{}]", chain.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", "))))?;
    let chain = &chain[head..];
    let Some((first, rest)) = chain.split_first() else {
        return Err(DialError::Chain("empty dialer-proxy chain".to_string()));
    };
    let hop_target = match rest.first() {
        Some(next) => Target {
            host: next.server().0.to_string(),
            port: next.server().1,
        },
        None => target.clone(),
    };
    let inner = dial_with_rest(first, &hop_target, rest, timeout);
    match tokio::time::timeout(timeout, inner).await {
        Ok(result) => result,
        Err(_) => Err(DialError::Timeout(timeout)),
    }
}

async fn dial_with_rest(
    first: &Proxy,
    target: &Target,
    rest: &[&Proxy],
    timeout: Duration,
) -> Result<Dialed, DialError> {
    let (next, tail) = match rest.split_first() {
        Some(pair) => pair,
        None => return dial_inner(&first.protocol, target, &[], timeout).await,
    };
    match (&first.protocol, &next.protocol) {
        (Protocol::Socks5(option), _) => {
            // The next hop's server connection is a SOCKS5 tunnel through this hop.
            let (host, port) = next.server();
            let (read, write) = socks5::tunnel(option, host, port, tail, timeout).await?;
            let stream: BoxStream = Box::new(Joined { read, write });
            dial_over(next, stream, target, tail, timeout).await
        }
        (_, Protocol::Socks5(_)) => Err(DialError::Chain(format!(
            "dialer-proxy chain {}({}) -> {}(socks5): a socks5 hop over a non-socks5 hop is not supported",
            first.name,
            first.type_name(),
            next.name
        ))),
        _ => Err(DialError::Chain(format!(
            "dialer-proxy chain {}({}) -> {}({}) is not supported: only a socks5 hop can carry another hop",
            first.name,
            first.type_name(),
            next.name,
            next.type_name()
        ))),
    }
}

/// A stream built from a generic reader/writer pair.
struct Joined {
    read: tokio::io::ReadHalf<BoxStream>,
    write: tokio::io::WriteHalf<BoxStream>,
}

impl tokio::io::AsyncRead for Joined {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.read).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Joined {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.write).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.write).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.write).poll_shutdown(cx)
    }
}

/// Run the protocol of `proxy` over an already established stream (a hop
/// reached through its `dialer-proxy` chain).
async fn dial_over(
    proxy: &Proxy,
    stream: BoxStream,
    target: &Target,
    tail: &[&Proxy],
    timeout: Duration,
) -> Result<Dialed, DialError> {
    match &proxy.protocol {
        Protocol::Socks5(option) => {
            let stream = socks5::negotiate_stream(stream, option, target)
                .await
                .map_err(|e| handshake("socks5", e))?;
            Ok(Dialed {
                stream,
                server: super::outbound::peer_of(proxy),
            })
        }
        _other => {
            let _ = (tail, timeout);
            Err(DialError::Chain(format!(
                "hop {} ({}) reached through a dialer-proxy is not supported",
                proxy.name,
                proxy.type_name()
            )))
        }
    }
}

/// Dispatch one hop's protocol over its server connection; `via` is that
/// hop's own `dialer-proxy` chain (empty for a direct server connection).
async fn dial_inner(
    protocol: &Protocol,
    target: &Target,
    via: &[&Proxy],
    timeout: Duration,
) -> Result<Dialed, DialError> {
    match protocol {
        Protocol::Socks5(p) => socks5::dial(p, target, via, timeout).await,
        Protocol::Http(p) => {
            refuse_chain(via, "http")?;
            http::dial(p, target).await
        }
        Protocol::Shadowsocks(p) => {
            refuse_chain(via, "ss")?;
            shadowsocks::dial(p, target).await
        }
        Protocol::Trojan(p) => {
            refuse_chain(via, "trojan")?;
            trojan::dial(p, target).await
        }
        Protocol::Vless(p) => {
            refuse_chain(via, "vless")?;
            vless::dial(p, target).await
        }
        Protocol::Anytls(p) => {
            refuse_chain(via, "anytls")?;
            anytls::dial(p, target).await
        }
    }
}

/// Only a socks5 hop can be entered through a previous hop (its handshake is
/// plain bytes over a stream); the TLS-bearing protocols need their own server
/// socket, so they are refused as later hops instead of silently bypassing the
/// previous hop.
fn refuse_chain(via: &[&Proxy], kind: &'static str) -> Result<(), DialError> {
    match via.first() {
        None => Ok(()),
        Some(previous) => Err(DialError::Chain(format!(
            "{kind} hop reached through {}({}) is not supported: only a socks5 hop can be reached through a dialer-proxy chain",
            previous.name,
            previous.type_name()
        ))),
    }
}

/// Open a hop's server connection locally (no `dialer-proxy` in this tree:
/// only the first hop of a chain is dialled locally, later hops arrive as
/// tunnels of the previous hop).
pub(crate) async fn connect_hop(
    server: &str,
    port: u16,
) -> Result<(TcpStream, SocketAddr), DialError> {
    let stream = connect_tcp(server, port).await?;
    let peer = stream.peer_addr().map_err(|e| handshake("connect", e))?;
    Ok((stream, peer))
}

/// Resolve the server name once, preferring addresses of the given family order.
pub(crate) async fn resolve(server: &str, port: u16) -> Result<SocketAddr, DialError> {
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs = tokio::net::lookup_host((server, port))
        .await
        .map_err(|source| DialError::Resolve {
            host: server.to_string(),
            source,
        })?
        .collect::<Vec<_>>();
    // Deterministic order: IPv4 first, then IPv6.
    addrs.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
    addrs.into_iter().next().ok_or_else(|| DialError::Resolve {
        host: server.to_string(),
        source: io::Error::new(io::ErrorKind::NotFound, "resolved to no address"),
    })
}

pub(crate) async fn connect_tcp(server: &str, port: u16) -> Result<TcpStream, DialError> {
    let addr = resolve(server, port).await?;
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|source| DialError::Connect {
            addr: addr.to_string(),
            source,
        })?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

pub(crate) fn handshake(protocol: &'static str, source: io::Error) -> DialError {
    DialError::Handshake { protocol, source }
}

/// `base64(user:pass)` for HTTP Proxy-Authorization.
/// `base64` for the HTTP and WebSocket handshakes (public for the fixtures).
pub fn http_pub_base64(input: &[u8]) -> String {
    base64(input)
}

pub(crate) fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(triple >> 18) as usize & 63] as char);
        out.push(TABLE[(triple >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(triple >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[triple as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648() {
        for (raw, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("user:pa ss", "dXNlcjpwYSBzcw=="),
        ] {
            assert_eq!(base64(raw.as_bytes()), encoded);
        }
    }

    #[test]
    fn socks_address_forms() {
        assert_eq!(
            SocksAddr::encode(&Target {
                host: "1.2.3.4".into(),
                port: 80
            }),
            vec![1, 1, 2, 3, 4, 0, 80]
        );
        assert_eq!(
            SocksAddr::encode(&Target {
                host: "a.example".into(),
                port: 443
            }),
            vec![3, 9, b'a', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', 1, 187]
        );
        let v6 = SocksAddr::encode(&Target {
            host: "::1".into(),
            port: 1,
        });
        assert_eq!(v6[0], 4);
        assert_eq!(v6.len(), 19);
    }
}
