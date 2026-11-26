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
pub mod blake3;
pub mod easytier;
pub mod gost_relay;
pub mod h3;
pub mod http;
pub mod hysteria;
pub mod hysteria2;
pub mod hysteria2_realm;
pub mod ipstack;
pub mod jls;
pub mod masque;
pub mod masque_ip;
pub mod mekya;
pub mod mieru;
pub mod mkcp;
pub mod openvpn;
pub mod shadowsocks;
pub mod tailscale;
pub mod tcp;
pub mod zerotier;
pub mod shadowquic;
pub mod shadow_tls;
pub mod snell;
pub mod socks5;
pub mod smux;
pub mod sudoku;
pub mod ssh;
pub mod ssr;
pub mod quic;
pub mod tls;
pub mod tls_io;
pub mod tlsmirror;
pub mod trojan;
pub mod trusttunnel;
pub mod tuic;
pub mod udp;
pub mod vless;
pub mod vmess;
pub mod warp;
pub mod wireguard;
pub mod ws;

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::proxies::{DialerOptions, IpVersion, Protocol, Proxy};

use self::tls::ClientTls;

/// Boxed duplex stream with half-close support (plain TCP, TLS, TLS+WS, ...).
pub type BoxStream = Box<dyn Stream>;

pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

/// One dial target as requested by the inbound.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
pub async fn dial(
    proxy: &Proxy,
    target: &Target,
    timeout: Duration,
    tls: &ClientTls,
) -> Result<Dialed, DialError> {
    let inner = tokio::time::timeout(
        timeout,
        dial_inner(&proxy.protocol, target, &[], timeout, tls),
    );
    match with_dialer(proxy.dialer.clone(), inner).await {
        Ok(result) => result,
        Err(_) => Err(DialError::Timeout(timeout)),
    }
}

/// Dial `target` through the `dialer-proxy` chain that starts at `chain[0]`;
/// `chain[i].dialer_proxy == chain[i+1].name` (validated at configuration
/// load). `chain[0]` is the exit the rule selected; the exit is never dropped:
/// its server connection is tunnelled through `chain[1..]` (the last hop is
/// dialled locally, every earlier hop is entered through the hop after it),
/// then the exit protocol runs over that stream toward `target`. The total is
/// bounded by the caller's timeout.
pub async fn dial_chain(
    chain: &[&Proxy],
    target: &Target,
    timeout: Duration,
    tls: &ClientTls,
) -> Result<Dialed, DialError> {
    let Some((exit, hops)) = chain.split_first() else {
        return Err(DialError::Chain("empty dialer-proxy chain".to_string()));
    };
    let inner = dial_through(exit, hops, target, timeout, tls);
    // The last hop is the only one dialled locally; its BasicOption knobs own
    // the socket. A chain with no hops is the exit itself.
    let local = chain.last().copied().unwrap_or(exit);
    match with_dialer(local.dialer.clone(), tokio::time::timeout(timeout, inner)).await {
        Ok(result) => result,
        Err(_) => Err(DialError::Timeout(timeout)),
    }
}

/// Establish `exit` over `hops`, then run the exit protocol toward `target`.
async fn dial_through(
    exit: &Proxy,
    hops: &[&Proxy],
    target: &Target,
    timeout: Duration,
    tls: &ClientTls,
) -> Result<Dialed, DialError> {
    if hops.is_empty() {
        return dial_inner(&exit.protocol, target, &[], timeout, tls).await;
    }
    if let Protocol::Sudoku(option) = &exit.protocol {
        // Sudoku owns the hop stream: with `multiplex: on` a cached session is
        // reused before any hop connection is opened, and a new session needs
        // the KIP `StartMux` handshake over the hop tunnel.
        return sudoku::dial_chained(
            option,
            target,
            hops,
            peer_of(exit),
            timeout,
            tls,
        )
        .await;
    }
    if !matches!(exit.protocol, Protocol::Socks5(_)) {
        return Err(exit_over_stream_error(exit));
    }
    // The exit's own server is the destination of its dialer hop.
    let exit_server = server_target(exit);
    let stream = connect_via_hops(hops, &exit_server, timeout, tls).await?;
    dial_over(exit, stream, target).await
}

/// Only protocols whose handshake can run over a stream someone else produced
/// can be an exit with a `dialer-proxy`; the exit is never dropped or bypassed.
fn exit_over_stream_error(exit: &Proxy) -> DialError {
    DialError::Chain(format!(
        "dialer-proxy exit {}({}) is not supported: its protocol cannot run over a connection established through a hop (only socks5 and sudoku exits can); the exit is never bypassed",
        exit.name,
        exit.type_name()
    ))
}

/// A stream connected to `destination`, tunnelled through `hops`: `hops[0]`
/// carries the connection, and when there are more hops its own server is
/// reached through them (`hops[0]`'s server is `hops[1]`'s destination).
pub(crate) async fn connect_via_hops(
    hops: &[&Proxy],
    destination: &Target,
    timeout: Duration,
    tls: &ClientTls,
) -> Result<BoxStream, DialError> {
    if hops.is_empty() {
        return Err(DialError::Chain("empty dialer-proxy hop list".to_string()));
    }
    // Only a SOCKS5 hop can be entered through the previous hop, so every hop
    // must be SOCKS5 before any connection is made.
    let mut layers = Vec::with_capacity(hops.len());
    for hop in hops {
        let Protocol::Socks5(option) = &hop.protocol else {
            return Err(DialError::Chain(format!(
                "dialer-proxy hop {}({}) cannot carry the next server connection: only a socks5 hop can be entered through a previous hop",
                hop.name,
                hop.type_name()
            )));
        };
        layers.push((*hop, option));
    }
    let last = layers.len() - 1;
    let (read, write) = if last == 0 {
        // One hop: dial it locally and ask it for `destination`.
        socks5::tunnel(layers[0].1, &destination.host, destination.port, &[], timeout, tls)
            .await?
    } else {
        // The deepest hop is dialled locally and asked for the server of the
        // hop above it; then each hop above is negotiated over that stream.
        let below = server_target(layers[last - 1].0);
        socks5::tunnel(layers[last].1, &below.host, below.port, &[], timeout, tls).await?
    };
    let mut stream: BoxStream = Box::new(Joined { read, write });
    if last > 0 {
        for index in (0..last).rev() {
            let target = if index == 0 {
                destination.clone()
            } else {
                server_target(layers[index - 1].0)
            };
            stream = socks5::negotiate_stream(stream, layers[index].1, &target)
                .await
                .map_err(|e| handshake("socks5", e))?;
        }
    }
    Ok(stream)
}

/// `server:port` of a proxy as a dial destination.
fn server_target(proxy: &Proxy) -> Target {
    let (host, port) = proxy.server();
    Target {
        host: host.to_string(),
        port,
    }
}

/// Join the two halves of a tunnel into one stream (used when a protocol
/// connection itself is established through a `dialer-proxy` chain).
pub(crate) fn joined(read: tokio::io::ReadHalf<BoxStream>, write: tokio::io::WriteHalf<BoxStream>) -> BoxStream {
    Box::new(Joined { read, write })
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

/// Run a SOCKS5 exit's negotiation over a stream its hop chain produced.
async fn dial_over(
    proxy: &Proxy,
    stream: BoxStream,
    target: &Target,
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
        _other => Err(exit_over_stream_error(proxy)),
    }
}

/// Dispatch one hop's protocol over its server connection; `via` is that
/// hop's own `dialer-proxy` chain (empty for a direct server connection).
async fn dial_inner(
    protocol: &Protocol,
    target: &Target,
    via: &[&Proxy],
    timeout: Duration,
    tls: &ClientTls,
) -> Result<Dialed, DialError> {
    match protocol {
        Protocol::Socks5(p) => socks5::dial(p, target, via, timeout, tls).await,
        Protocol::Http(p) => {
            refuse_chain(via, "http")?;
            http::dial(p, target, tls).await
        }
        Protocol::Shadowsocks(p) => {
            refuse_chain(via, "ss")?;
            shadowsocks::dial(p, target).await
        }
        Protocol::Trojan(p) => {
            refuse_chain(via, "trojan")?;
            trojan::dial(p, target, tls).await
        }
        Protocol::Vless(p) => {
            refuse_chain(via, "vless")?;
            vless::dial(p, target, tls).await
        }
        Protocol::Anytls(p) => {
            refuse_chain(via, "anytls")?;
            anytls::dial(p, target, tls, timeout).await
        }
        Protocol::Vmess(p) => {
            refuse_chain(via, "vmess")?;
            vmess::dial(p, target, via, timeout, tls).await
        }
        Protocol::Snell(p) => {
            refuse_chain(via, "snell")?;
            snell::dial(p, target).await
        }
        Protocol::TrustTunnel(p) => {
            refuse_chain(via, "trusttunnel")?;
            trusttunnel::dial(p, target, tls).await
        }
        Protocol::GostRelay(p) => {
            refuse_chain(via, "gost-relay")?;
            gost_relay::dial(p, target, tls).await
        }
        Protocol::Ssh(p) => {
            refuse_chain(via, "ssh")?;
            ssh::dial(p, target).await
        }
        Protocol::Ssr(p) => {
            refuse_chain(via, "ssr")?;
            ssr::dial(p, target).await
        }
        Protocol::Tuic(p) => {
            refuse_chain(via, "tuic")?;
            tuic::dial(p, target, tls, timeout).await
        }
        Protocol::Hysteria(p) => {
            refuse_chain(via, "hysteria")?;
            hysteria::dial(p, target, tls, timeout).await
        }
        Protocol::Hysteria2(p) => {
            refuse_chain(via, "hysteria2")?;
            hysteria2::dial(p, target, tls, timeout).await
        }
        Protocol::Mieru(p) => {
            refuse_chain(via, "mieru")?;
            mieru::dial(p, target).await
        }
        Protocol::Sudoku(p) => {
            refuse_chain(via, "sudoku")?;
            sudoku::dial(p, target).await
        }
        Protocol::Masque(p) => {
            refuse_chain(via, "masque")?;
            masque::dial(p, target, tls, timeout).await
        }
        Protocol::ShadowQuic(p) => {
            refuse_chain(via, "shadowquic")?;
            shadowquic::dial(p, target, tls, timeout).await
        }
        Protocol::OpenVpn(_) => {
            refuse_chain(via, "openvpn")?;
            Err(handshake(
                "openvpn",
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the control channel, TLS authentication and AEAD data channel are implemented, but IP packets through the tunnel need the userspace IP stack and TUN device owned by T6/T7 (use outbound::openvpn::OpenVpnTunnel for the data channel)",
                ),
            ))
        }
        Protocol::Tailscale(_) => {
            refuse_chain(via, "tailscale")?;
            Err(handshake(
                "tailscale",
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the control-plane Noise transport, HTTP/2 control request and DERP frame codec are implemented in outbound/tailscale.rs, but TCP/UDP through the tunnel needs the userspace IP stack and TUN device owned by T6/T7",
                ),
            ))
        }
        Protocol::Easytier(_) => {
            refuse_chain(via, "easytier")?;
            Err(handshake(
                "easytier",
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the LGPL-3.0-derived cleartext host/discovery frame, HandshakeRequest, PeerManagerHeader and PingPong are implemented in outbound/easytier.rs, but TCP/UDP through the network needs the userspace IP stack and TUN device owned by T6/T7; the secure-datagram path is available to the T6/T7 layer",
                ),
            ))
        }
        Protocol::Zerotier(_) => {
            refuse_chain(via, "zerotier")?;
            Err(handshake(
                "zerotier",
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the identity, planet, VL1 armor/HELLO/OK and VL2 frame layers are implemented in outbound/zerotier.rs, but TCP/UDP through the network needs the userspace IP stack and TUN device owned by T6/T7",
                ),
            ))
        }
        Protocol::Wireguard(_) => {
            refuse_chain(via, "wireguard")?;
            // The packet transport is implemented in `wireguard.rs` and
            // verified against a controlled locked-source peer, but turning an
            // IP packet stream into the TCP stream this function returns needs
            // the userspace IP stack and TUN device owned by the T6/T7 device
            // layer. Refusing names that gap; it never pretends a dial worked.
            Err(handshake(
                "wireguard",
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the Noise IK handshake and transport are implemented, but TCP/UDP through the tunnel needs the userspace IP stack and TUN device owned by T6/T7 (use outbound::wireguard::WireguardTunnel for the packet transport)",
                ),
            ))
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

tokio::task_local! {
    /// BasicOption socket knobs of the proxy whose server is dialled locally.
    static DIALER: DialerOptions;
}

/// Run `future` with `options` as the socket knobs for locally dialled
/// proxy-server connections.
pub(crate) async fn with_dialer<F: Future>(options: DialerOptions, future: F) -> F::Output {
    DIALER.scope(options, future).await
}

tokio::task_local! {
    /// Proxy-server resolver installed for a session or health probe: the
    /// pinned engine resolves proxy `server` names through
    /// `proxy-server-nameserver` (`resolver.ProxyServerHostResolver`), not
    /// through the OS resolver.
    static PROXY_DNS: Arc<crate::dns::DnsService>;
}

/// Run `future` with `dns` as the resolver for proxy server names.
pub(crate) async fn with_proxy_dns<F: Future>(dns: Arc<crate::dns::DnsService>, future: F) -> F::Output {
    PROXY_DNS.scope(dns, future).await
}

/// The `ip-version` of the dial currently in progress (`dual` when none is
/// scoped, e.g. a direct/health path).
fn current_dialer() -> Option<DialerOptions> {
    DIALER.try_with(|options| options.clone()).ok()
}

fn default_interface_slot() -> &'static Mutex<Option<String>> {
    static SLOT: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// Physical interface kernel-originated sockets must leave through. A desktop
/// TUN with `auto-detect-interface` installs the detected default interface so
/// proxy-server dials, DIRECT TCP/UDP and DNS queries cannot be captured by the
/// TUN again. `None` clears it (tunnel stop).
pub fn set_default_interface(name: Option<String>) {
    let mut slot = default_interface_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *slot = name.filter(|name| !name.is_empty());
}

/// The process-wide physical interface, when one is installed.
pub fn default_interface() -> Option<String> {
    default_interface_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Fill `interface-name` from the process-wide physical binding when the proxy
/// did not configure one itself.
pub(crate) fn merge_default_interface(options: &DialerOptions) -> DialerOptions {
    let mut merged = options.clone();
    if merged.interface_name.is_none() {
        merged.interface_name = default_interface();
    }
    merged
}

/// Sort (and, for `ipv4`/`ipv6`, filter) addresses the way the pinned
/// `dialer.WithPreferIPv4`/`WithOnlySingleStack` options do.
pub(crate) fn order_addresses(addrs: &mut Vec<SocketAddr>, ip_version: IpVersion) {
    match ip_version {
        IpVersion::V4Only => addrs.retain(SocketAddr::is_ipv4),
        IpVersion::V6Only => addrs.retain(SocketAddr::is_ipv6),
        IpVersion::Dual | IpVersion::V4Prefer => {
            addrs.sort_by_key(|addr| if addr.is_ipv4() { 0 } else { 1 })
        }
        IpVersion::V6Prefer => addrs.sort_by_key(|addr| if addr.is_ipv6() { 0 } else { 1 }),
    }
}

/// Every address a proxy `server` name resolves to, with the in-scope
/// `ip-version` applied (filter for `ipv4`/`ipv6`, order for the prefer
/// values). Proxy server names go through `proxy-server-nameserver` when the
/// caller scoped [`with_proxy_dns`], exactly like [`resolve`]; the OS resolver
/// is only the fallback when DNS is off.
pub(crate) async fn resolve_all(
    server: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, DialError> {
    let ip_version = current_dialer().map(|options| options.ip_version).unwrap_or_default();
    if let Ok(ip) = server.parse::<IpAddr>() {
        if ip_version == IpVersion::V4Only && !ip.is_ipv4()
            || ip_version == IpVersion::V6Only && !ip.is_ipv6()
        {
            return Err(DialError::Resolve {
                host: server.to_string(),
                source: io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("address does not match ip-version {}", ip_version.as_str()),
                ),
            });
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let dns = PROXY_DNS.try_with(|dns| dns.clone()).ok();
    let mut addrs = if let Some(dns) = dns {
        dns.resolve_proxy_server(server)
            .await
            .map_err(|error| DialError::Resolve {
                host: server.to_string(),
                source: io::Error::other(error.to_string()),
            })?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect::<Vec<_>>()
    } else {
        tokio::net::lookup_host((server, port))
            .await
            .map_err(|source| DialError::Resolve {
                host: server.to_string(),
                source,
            })?
            .collect::<Vec<_>>()
    };
    order_addresses(&mut addrs, ip_version);
    addrs.dedup();
    if addrs.is_empty() {
        return Err(DialError::Resolve {
            host: server.to_string(),
            source: io::Error::new(io::ErrorKind::NotFound, "resolved to no address"),
        });
    }
    Ok(addrs)
}

/// Resolve the server name once, applying the in-scope `ip-version`.
pub(crate) async fn resolve(server: &str, port: u16) -> Result<SocketAddr, DialError> {
    resolve_all(server, port)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| DialError::Resolve {
            host: server.to_string(),
            source: io::Error::new(io::ErrorKind::NotFound, "resolved to no address"),
        })
}

pub(crate) async fn connect_tcp(server: &str, port: u16) -> Result<TcpStream, DialError> {
    let addr = resolve(server, port).await?;
    let options = current_dialer().unwrap_or_default();
    let stream = connect_resolved(addr, &options)
        .await
        .map_err(|source| DialError::Connect {
            addr: addr.to_string(),
            source,
        })?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Connect with the BasicOption socket knobs. With no options set this is
/// tokio's own connect; otherwise the socket is created through `socket2`, the
/// options are applied and the non-blocking connect is awaited by tokio.
async fn connect_resolved(
    addr: SocketAddr,
    options: &DialerOptions,
) -> io::Result<TcpStream> {
    let options = merge_default_interface(options);
    if options == DialerOptions::default() {
        return TcpStream::connect(addr).await;
    }
    let socket = dial_socket(addr, &options)?;
    let stream = socket.connect(addr).await?;
    Ok(stream)
}

/// DIRECT TCP dial that honours the process-wide physical-interface binding
/// (the TUN anti-loop path).
pub(crate) async fn connect_bound(addr: SocketAddr) -> io::Result<TcpStream> {
    connect_resolved(addr, &DialerOptions::default()).await
}

/// [`connect_bound`] for a name or literal address.
pub(crate) async fn connect_bound_str(host: &str, port: u16) -> io::Result<TcpStream> {
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return connect_bound(addr).await;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return connect_bound(SocketAddr::new(ip, port)).await;
    }
    let mut addrs = tokio::net::lookup_host((host, port)).await?;
    let mut last = io::Error::new(io::ErrorKind::NotFound, format!("{host} resolved to no address"));
    for addr in addrs.by_ref() {
        match connect_bound(addr).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = error,
        }
    }
    Err(last)
}

/// Bind a UDP socket with the in-scope BasicOption knobs (interface-name and
/// routing-mark; tfo/mptcp are TCP-only).
pub(crate) async fn bind_udp(addr: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    let options = merge_default_interface(&current_dialer().unwrap_or_default());
    if options == DialerOptions::default() {
        return tokio::net::UdpSocket::bind(addr).await;
    }
    let socket = udp_socket_std(addr, &options)?;
    tokio::net::UdpSocket::from_std(socket)
}

/// [`bind_udp`] for the `"0.0.0.0:0"` / `"[::]:0"` literals the outbounds use.
pub(crate) async fn bind_udp_str(bind: &str) -> io::Result<tokio::net::UdpSocket> {
    let addr: SocketAddr = bind.parse().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("invalid bind address '{bind}'"))
    })?;
    bind_udp(addr).await
}

/// The raw bound socket for QUIC endpoints, which need to own the socket.
pub(crate) fn udp_socket_std(addr: SocketAddr, options: &DialerOptions) -> io::Result<std::net::UdpSocket> {
    let socket = build_udp_socket(addr, options)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

/// A bound UDP socket that stays in blocking mode (mKCP's packet loop uses
/// `set_read_timeout` + blocking reads).
pub(crate) fn udp_socket_std_blocking(
    addr: SocketAddr,
    options: &DialerOptions,
) -> io::Result<std::net::UdpSocket> {
    let socket = build_udp_socket(addr, options)?;
    Ok(socket.into())
}

fn build_udp_socket(addr: SocketAddr, options: &DialerOptions) -> io::Result<socket2::Socket> {
    let options = merge_default_interface(options);
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    apply_interface(&socket, addr, options.interface_name.as_deref())?;
    apply_routing_mark(&socket, options.routing_mark)?;
    socket.bind(&addr.into())?;
    Ok(socket)
}

/// A blocking TCP connection with the process-wide interface binding (provider
/// downloads and other synchronous kernel-originated requests).
pub(crate) fn tcp_stream_std_blocking(
    addr: SocketAddr,
    timeout: Duration,
) -> io::Result<std::net::TcpStream> {
    let options = merge_default_interface(&DialerOptions::default());
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    apply_interface(&socket, addr, options.interface_name.as_deref())?;
    apply_routing_mark(&socket, options.routing_mark)?;
    socket.connect_timeout(&addr.into(), timeout)?;
    Ok(socket.into())
}

/// Create a non-blocking TCP socket and apply tfo/mptcp/interface-name/
/// routing-mark before connecting.
fn dial_socket(addr: SocketAddr, options: &DialerOptions) -> io::Result<tokio::net::TcpSocket> {
    let options = merge_default_interface(options);
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let protocol = mptcp_protocol(options.mptcp);
    let socket = match socket2::Socket::new(domain, socket2::Type::STREAM, Some(protocol)) {
        Ok(socket) => socket,
        Err(error) if options.mptcp => {
            // Go's net package falls back to TCP when the MPTCP protocol is
            // not available; keep the configuration usable the same way.
            tracing::warn!("mptcp: socket creation failed ({error}); falling back to TCP");
            socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?
        }
        Err(error) => return Err(error),
    };
    apply_interface(&socket, addr, options.interface_name.as_deref())?;
    apply_routing_mark(&socket, options.routing_mark)?;
    apply_tfo(&socket, options.tfo)?;
    socket.set_nonblocking(true)?;
    let std_stream: std::net::TcpStream = socket.into();
    Ok(tokio::net::TcpSocket::from_std_stream(std_stream))
}

fn mptcp_protocol(enabled: bool) -> socket2::Protocol {
    if !enabled {
        return socket2::Protocol::TCP;
    }
    #[cfg(target_os = "linux")]
    {
        // `IPPROTO_MPTCP`; the kernel falls back to TCP when the stack does
        // not implement it.
        socket2::Protocol::from(262)
    }
    #[cfg(not(target_os = "linux"))]
    {
        warn_once(
            "mptcp",
            "multipath TCP is not available on this platform; the connection uses TCP",
        );
        socket2::Protocol::TCP
    }
}

#[cfg(target_os = "linux")]
fn apply_interface(
    socket: &socket2::Socket,
    _addr: SocketAddr,
    name: Option<&str>,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let Some(name) = name else {
        return Ok(());
    };
    let bytes = name.as_bytes();
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            bytes.as_ptr().cast(),
            bytes.len() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_interface(
    socket: &socket2::Socket,
    addr: SocketAddr,
    name: Option<&str>,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let Some(name) = name else {
        return Ok(());
    };
    let c_name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name has a NUL"))?;
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    // Darwin binds sockets with IP_BOUND_IF / IPV6_BOUND_IF rather than
    // SO_BINDTODEVICE.
    const IP_BOUND_IF: libc::c_int = 25;
    const IPV6_BOUND_IF: libc::c_int = 125;
    let (level, option) = if addr.is_ipv4() {
        (libc::IPPROTO_IP, IP_BOUND_IF)
    } else {
        (libc::IPPROTO_IPV6, IPV6_BOUND_IF)
    };
    let index = index as libc::c_int;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&index as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn apply_interface(
    socket: &socket2::Socket,
    addr: SocketAddr,
    name: Option<&str>,
) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    let Some(name) = name else {
        return Ok(());
    };
    // Winsock `IP_UNICAST_IF` takes the interface index in network byte order
    // for IPv4 and host byte order for IPv6.
    const IPPROTO_IP: i32 = 0;
    const IPPROTO_IPV6: i32 = 41;
    const IP_UNICAST_IF: i32 = 31;
    const IPV6_UNICAST_IF: i32 = 31;

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn if_nametoindex(name: *const i8) -> u32;
    }
    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn setsockopt(
            socket: usize,
            level: i32,
            option: i32,
            value: *const i8,
            length: i32,
        ) -> i32;
    }

    let c_name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name has a NUL"))?;
    let index = unsafe { if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    let (level, option, value) = if addr.is_ipv4() {
        (IPPROTO_IP, IP_UNICAST_IF, index.to_be())
    } else {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, index)
    };
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            level,
            option,
            (&value as *const u32).cast(),
            std::mem::size_of::<u32>() as i32,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn apply_interface(
    _socket: &socket2::Socket,
    _addr: SocketAddr,
    name: Option<&str>,
) -> io::Result<()> {
    match name {
        None => Ok(()),
        Some(name) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "interface-name '{name}' is not implemented on this platform (Linux SO_BINDTODEVICE, macOS IP_BOUND_IF and Windows IP_UNICAST_IF are the implemented bindings)"
            ),
        )),
    }
}

#[cfg(target_os = "linux")]
fn apply_routing_mark(socket: &socket2::Socket, mark: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    if mark == 0 {
        return Ok(());
    }
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const u32).cast(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_routing_mark(_socket: &socket2::Socket, mark: u32) -> io::Result<()> {
    if mark != 0 {
        warn_once(
            "routing-mark",
            "routing mark on sockets is not supported on this platform (the pinned dialer also only logs this)",
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_tfo(socket: &socket2::Socket, enabled: bool) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    if !enabled {
        return Ok(());
    }
    const TCP_FASTOPEN_CONNECT: libc::c_int = 30;
    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_FASTOPEN_CONNECT,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result != 0 {
        // tfo-go falls back to a normal connect when the option is rejected.
        tracing::debug!("tfo: TCP_FASTOPEN_CONNECT rejected: {}", io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_tfo(socket: &socket2::Socket, enabled: bool) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    if !enabled {
        return Ok(());
    }
    const TCP_FASTOPEN: libc::c_int = 0x105;
    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_FASTOPEN,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result != 0 {
        tracing::debug!("tfo: TCP_FASTOPEN rejected: {}", io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn apply_tfo(_socket: &socket2::Socket, enabled: bool) -> io::Result<()> {
    if enabled {
        // Never a silent success: a configuration that asks for TFO on a
        // platform this dialer cannot express it on is logged once and uses a
        // normal connect, the same fallback tfo-go uses.
        warn_once(
            "tfo",
            "TCP fast open is not available on this platform; the connection uses a normal connect",
        );
    }
    Ok(())
}

/// Upstream logs an unsupported platform knob once; do the same instead of
/// rejecting a configuration the pinned engine accepts.
fn warn_once(key: &'static str, message: &str) {
    static WARNED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<&'static str>>> =
        std::sync::OnceLock::new();
    let warned = WARNED.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    let mut guard = warned
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.insert(key) {
        tracing::warn!("{message}");
    }
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

    #[test]
    fn default_interface_can_be_installed_and_cleared() {
        set_default_interface(Some("lo0".to_string()));
        assert_eq!(default_interface().as_deref(), Some("lo0"));
        let merged = merge_default_interface(&DialerOptions::default());
        assert_eq!(merged.interface_name.as_deref(), Some("lo0"));
        // A per-proxy value wins over the process default.
        let configured = DialerOptions {
            interface_name: Some("en0".to_string()),
            ..DialerOptions::default()
        };
        assert_eq!(
            merge_default_interface(&configured).interface_name.as_deref(),
            Some("en0")
        );
        set_default_interface(None);
        assert!(default_interface().is_none());
    }

    /// The TUN anti-loop branch really binds the socket to the interface.
    /// `IP_BOUND_IF` is available unprivileged on macOS; Linux/Windows policy is
    /// covered by the cfg implementation and remains platform-acceptance work.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn direct_dial_uses_the_process_interface() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        set_default_interface(Some("lo0".to_string()));
        let dialed = connect_bound(addr).await;
        set_default_interface(None);
        accept.await.unwrap();
        assert!(dialed.is_ok(), "{dialed:?}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn blocking_udp_helper_stays_blocking_and_binds_the_interface() {
        set_default_interface(Some("lo0".to_string()));
        let socket = udp_socket_std_blocking(
            "0.0.0.0:0".parse().unwrap(),
            &DialerOptions::default(),
        );
        set_default_interface(None);
        let socket = socket.expect("blocking UDP bind with the interface");
        use std::os::fd::AsRawFd;
        let flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(flags & libc::O_NONBLOCK, 0, "mKCP needs blocking reads");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn blocking_tcp_helper_connects_on_the_process_interface() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = std::thread::spawn(move || {
            let _ = listener.accept();
        });
        set_default_interface(Some("lo0".to_string()));
        let stream = tcp_stream_std_blocking(addr, Duration::from_secs(2));
        set_default_interface(None);
        accept.join().unwrap();
        assert!(stream.is_ok(), "{stream:?}");
    }
}
