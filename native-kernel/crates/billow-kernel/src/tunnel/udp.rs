//! UDP egress shared by the desktop and mobile packet tunnels.
//!
//! The device sends UDP datagrams as IP packets; each one is routed through
//! the engine (rule -> group -> outbound) exactly like a SOCKS5 `UDP
//! ASSOCIATE` datagram. The transports are the same association types the
//! mixed listener uses (`socks5`, `ss` including UoT, `anytls`, `vless`,
//! `vmess`, `snell`, `trojan`, `sudoku`, `trusttunnel`,
//! `ssr`, `masque`, `shadowquic`, `hysteria`, `hysteria2`, `tuic` including
//! `udp-over-stream`), plus `DIRECT`. `wireguard` and `openvpn` use the shared
//! userspace L3 stack (`outbound::l3`): one unconnected smoltcp UDP socket per
//! association carries every destination of the flow. A family without a UDP
//! association in this kernel is refused by name instead of being sent the
//! wrong way. The mesh families `tailscale`/`zerotier`/`easytier` and
//! `gost-relay` still have no TUN transport; that is registered in the
//! evidence rather than silently accepted.
//!
//! Memory is bounded: at most [`MAX_ASSOCIATIONS`] live proxy associations and
//! at most [`crate::tunnel::TunnelOptions::max_udp_flows`] tracked device
//! flows. Each flow owns its DIRECT socket or proxy association so replies are
//! delivered by the exact `(device src, device dst)` key; each task keeps one
//! 64 KiB receive buffer. Expired flows abort their socket reader and drop the
//! association channel.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::outbound::{
    self,
    l3::L3UdpSocket,
    masque::MasqueUdpAssociation,
    shadowquic::ShadowQuicUdp,
    snell_v6::SnellUdp,
    tls::ClientTls,
    trusttunnel::TrustTunnelUdp,
    udp::{
        AnytlsUot, Hysteria2Udp, HysteriaUdp, SsUdp, SsUot, SsrUdp, SudokuUdp, TrojanUdp,
        TuicUot, UotReader, UotWriter, VlessUdp, VlessUdpReader, VlessUdpWriter,
        VmessUdp, VmessUdpReader, VmessUdpWriter, MAX_DATAGRAM,
    },
};
use crate::proxies::{Protocol, Proxy};

use crate::tunnel::Inner;

/// A framed UDP stream cannot cancel a partial read when another datagram
/// arrives. Keep one reader per device flow and send replies straight to the
/// bounded device queue. The writer owns the reader's lifetime.
struct StreamAssociation {
    target: outbound::Target,
    writer: StreamWriter,
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for StreamAssociation {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

enum StreamReader {
    Bound(UotReader),
    Vless(VlessUdpReader),
    Vmess(VmessUdpReader),
}

impl StreamReader {
    async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(outbound::Target, usize)>> {
        match self {
            Self::Bound(reader) => reader.recv(buffer).await,
            Self::Vless(reader) => reader.recv(buffer).await,
            Self::Vmess(reader) => reader.recv(buffer).await,
        }
    }
}

enum StreamWriter {
    Bound(UotWriter),
    Vless(VlessUdpWriter),
    Vmess(VmessUdpWriter),
}

impl StreamWriter {
    async fn send(&mut self, target: &outbound::Target, payload: &[u8]) -> io::Result<()> {
        match self {
            Self::Bound(writer) => writer.send(payload).await,
            Self::Vless(writer) => writer.send(target, payload).await,
            Self::Vmess(writer) => writer.send(target, payload).await,
        }
    }
}

fn stream_udp(protocol: &Protocol) -> bool {
    match protocol {
        Protocol::Anytls(option) => option.udp,
        Protocol::Vless(option) => option.udp,
        Protocol::Vmess(option) => option.udp,
        Protocol::Shadowsocks(option) => option.udp && option.udp_over_tcp,
        Protocol::Tuic(option) => option.udp_over_stream,
        _ => false,
    }
}

async fn connect_stream(
    proxy: &Proxy,
    target: &outbound::Target,
    hops: &[&Proxy],
    timeout: std::time::Duration,
    tls: &ClientTls,
) -> Result<(StreamReader, StreamWriter), outbound::DialError> {
    let pair = match &proxy.protocol {
        Protocol::Anytls(option) => {
            let (reader, writer) = AnytlsUot::connect(option, target, hops, timeout, tls).await?.into_halves();
            (StreamReader::Bound(UotReader::Anytls(reader)), StreamWriter::Bound(UotWriter::Anytls(writer)))
        }
        Protocol::Shadowsocks(option) => {
            let (reader, writer) = SsUot::connect(option, target, hops, timeout, tls).await?.into_halves();
            (StreamReader::Bound(UotReader::SsUot(reader)), StreamWriter::Bound(UotWriter::SsUot(writer)))
        }
        Protocol::Tuic(option) => {
            let (reader, writer) = TuicUot::connect(option, target, hops, timeout, tls).await?.into_halves();
            (StreamReader::Bound(UotReader::Tuic(reader)), StreamWriter::Bound(UotWriter::Tuic(writer)))
        }
        Protocol::Vless(option) => {
            let (reader, writer) = VlessUdp::connect(option, hops, timeout, tls).await?.into_halves();
            (StreamReader::Vless(reader), StreamWriter::Vless(writer))
        }
        Protocol::Vmess(option) => {
            let (reader, writer) = VmessUdp::connect(option, target, hops, timeout, tls).await?.into_halves();
            (StreamReader::Vmess(reader), StreamWriter::Vmess(writer))
        }
        _ => unreachable!("stream_udp checked before dispatch"),
    };
    Ok(pair)
}

async fn stream_association_task(
    inner: &Inner,
    session: &crate::engine::SessionContext,
    proxy: &Proxy,
    flow: UdpFlowKey,
    mut commands: mpsc::Receiver<AssocCommand>,
    replies: mpsc::Sender<UdpReply>,
) {
    let mut association: Option<StreamAssociation> = None;
    let hops = crate::engine::chain_for(&session.runtime.config, proxy);
    let timeout = session.limits.dial_timeout;
    let ip_only = match &proxy.protocol {
        Protocol::Vless(option) => option.packet_addr && !option.xudp,
        Protocol::Vmess(option) => option.packet_addr && !option.xudp,
        _ => false,
    };
    let mut resolved = None;
    while let Some(AssocCommand::Send { mut target, payload }) = commands.recv().await {
        if ip_only && target.host.parse::<IpAddr>().is_err() {
            // All datagrams from this device flow target the same destination.
            // Reuse its resolved address for the lifetime of the association.
            let cached: Option<&(outbound::Target, outbound::Target)> = resolved.as_ref();
            let address = match cached {
                Some((original, address)) if original == &target => address.clone(),
                _ => match resolve_ip_only_target(session, proxy, target.clone()).await {
                    Ok(address) => {
                        resolved = Some((target.clone(), address.clone()));
                        address
                    }
                    Err(error) => {
                        inner.note_udp_association_error(&proxy.name, &error.to_string());
                        continue;
                    }
                },
            };
            target = address;
        }
        if association.as_ref().is_none_or(|stream| stream.target != target || stream.reader.is_finished()) {
            drop(association.take());
            let connect = outbound::with_dialer(
                proxy.dialer.clone(),
                connect_stream(proxy, &target, &hops, timeout, &session.runtime.tls),
            );
            let connect = async {
                match &session.runtime.dns {
                    Some(dns) => outbound::with_proxy_dns(dns.clone(), connect).await,
                    None => connect.await,
                }
            };
            let (mut reader, writer) = match tokio::time::timeout(timeout, connect).await {
                Ok(Ok(pair)) => pair,
                Ok(Err(error)) => {
                    inner.note_udp_association_error(&proxy.name, &error.to_string());
                    break;
                }
                Err(_) => {
                    inner.note_udp_association_error(&proxy.name, "UDP stream connect timed out");
                    break;
                }
            };
            let reply_tx = replies.clone();
            let destination = target.clone();
            let reader = tokio::spawn(async move {
                let mut buffer = vec![0; MAX_DATAGRAM];
                while let Ok(Some((from, length))) = reader.recv(&mut buffer).await {
                    let from = if from.port == destination.port
                        && from.host.eq_ignore_ascii_case(&destination.host)
                    {
                        // A destination-bound stream may report a hostname
                        // or a resolved IP behind the app's Fake-IP address.
                        flow.1
                    } else if let Ok(ip) = from.host.parse() {
                        SocketAddr::new(ip, from.port)
                    } else {
                        continue;
                    };
                    // Reserve before copying. A saturated device queue drops
                    // a UDP reply without allocating or waking another task.
                    match reply_tx.try_reserve() {
                        Ok(slot) => slot.send(UdpReply { flow, from, payload: buffer[..length].to_vec() }),
                        Err(mpsc::error::TrySendError::Full(())) => {}
                        Err(mpsc::error::TrySendError::Closed(())) => break,
                    }
                }
            });
            association = Some(StreamAssociation { target: target.clone(), writer, reader });
            inner.note_udp_association_ready(&proxy.name);
        }
        let Some(stream) = &mut association else { continue };
        match tokio::time::timeout(timeout, stream.writer.send(&target, &payload)).await {
            Ok(Ok(())) => {}
            result => {
                let error = match result {
                    Ok(Err(error)) => error.to_string(),
                    Err(_) => "UDP stream write timed out".to_string(),
                    Ok(Ok(())) => unreachable!(),
                };
                inner.note_udp_association_error(&proxy.name, &error);
                association = None;
            }
        }
    }
    inner.note_udp_association_closed(&proxy.name);
}

/// One UDP association terminated by the shared userspace IP stack
/// (`wireguard`/`openvpn`). The smoltcp socket is unconnected, so one
/// association carries every destination of its flow.
pub(crate) struct L3Association {
    socket: L3UdpSocket,
    protocol: &'static str,
}

impl L3Association {
    fn new(socket: L3UdpSocket, protocol: &'static str) -> L3Association {
        L3Association { socket, protocol }
    }

    async fn send(&mut self, target: &outbound::Target, payload: &[u8]) -> io::Result<()> {
        let ip: IpAddr = target.host.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} UDP association needs a resolved IP destination, got '{}'",
                    self.protocol, target.host
                ),
            )
        })?;
        self.socket.send(SocketAddr::new(ip, target.port), payload).await
    }

    async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(SocketAddr, usize)>> {
        self.socket.recv(buffer).await.map(Some)
    }
}

/// One association per device UDP flow (see [`UdpReply::flow`]); a
/// configuration with more concurrently active UDP flows than this drops the
/// excess by name. Bounded, never unbounded.
pub(crate) const MAX_ASSOCIATIONS: usize = 32;

/// Device 4-tuple of one UDP flow.
pub(crate) type UdpFlowKey = (SocketAddr, SocketAddr);

/// A datagram that a transport received. `flow` is the device 4-tuple the
/// reply belongs to, so two device sockets that reach the same remote never
/// receive each other's datagrams (the direct reader and the proxied
/// association both tag every reply with their own flow).
pub(crate) struct UdpReply {
    pub flow: UdpFlowKey,
    pub from: SocketAddr,
    pub payload: Vec<u8>,
}

/// Outgoing work for one association task.
pub(crate) enum AssocCommand {
    Send {
        target: outbound::Target,
        payload: Vec<u8>,
    },
}

enum Transport {
    Socks5(crate::outbound::socks5::Socks5Udp),
    Ss(SsUdp),
    Trojan(TrojanUdp),
    Sudoku(SudokuUdp),
    Snell(SnellUdp),
    TrustTunnel(TrustTunnelUdp),
    Ssr(SsrUdp),
    Masque(MasqueUdpAssociation),
    ShadowQuic(ShadowQuicUdp),
    Hysteria(HysteriaUdp),
    Hysteria2(Hysteria2Udp),
    Tuic(crate::outbound::tuic::TuicUdp),
    L3(L3Association),
}

impl Transport {
    async fn send(&mut self, target: &outbound::Target, payload: &[u8]) -> io::Result<()> {
        match self {
            Transport::Socks5(transport) => transport.send(target, payload).await,
            Transport::Ss(transport) => transport.send(target, payload).await,
            Transport::Trojan(transport) => transport.send(target, payload).await,
            Transport::Sudoku(transport) => transport.send(target, payload).await,
            Transport::Snell(transport) => transport.send(target, payload).await,
            Transport::TrustTunnel(transport) => transport.send(target, payload).await,
            Transport::Ssr(transport) => transport.send(target, payload).await,
            Transport::Masque(transport) => transport.send(target, payload).await,
            Transport::ShadowQuic(transport) => transport.send(target, payload).await,
            Transport::Hysteria(transport) => transport.send(target, payload).await,
            Transport::Hysteria2(transport) => transport.send(target, payload).await,
            Transport::Tuic(transport) => transport.send(target, payload).await,
            Transport::L3(transport) => transport.send(target, payload).await,
        }
    }

    /// One reply, already mapped to the remote address. `None` on EOF.
    async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(SocketAddr, usize)>> {
        let result = match self {
            // A SOCKS5 relay datagram that is not from the relay or is
            // malformed is ignored (the mixed inbound does the same); only a
            // real transport error ends the association.
            Transport::Socks5(transport) => loop {
                match transport.recv(buffer).await {
                    Ok(Some(reply)) => break Ok(Some(reply)),
                    Ok(None) => continue,
                    Err(error) => break Err(error),
                }
            },
            Transport::Ss(transport) => transport.recv(buffer).await,
            Transport::Trojan(transport) => transport.recv(buffer).await,
            Transport::Sudoku(transport) => transport.recv(buffer).await,
            Transport::Snell(transport) => transport.recv(buffer).await,
            Transport::TrustTunnel(transport) => transport.recv(buffer).await,
            Transport::Ssr(transport) => transport.recv(buffer).await,
            Transport::Masque(transport) => transport.recv(buffer).await,
            Transport::ShadowQuic(transport) => transport.recv(buffer).await,
            Transport::Hysteria(transport) => transport.recv(buffer).await,
            Transport::Hysteria2(transport) => transport.recv(buffer).await,
            Transport::Tuic(transport) => transport.recv(buffer).await,
            // The smoltcp socket reports the remote of every datagram, the
            // same shape the UoT reader uses.
            Transport::L3(transport) => return transport.recv(buffer).await,
        };
        match result? {
            Some((target, read)) => match target.host.parse::<IpAddr>() {
                Ok(ip) => Ok(Some((SocketAddr::new(ip, target.port), read))),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "UDP reply from '{}' is not an IP address; the tunnel cannot map it to a device flow",
                        target.host
                    ),
                )),
            },
            None => Ok(None),
        }
    }
}

/// IP-only packet formats (`trusttunnel`'s `_udp2`) need a resolved
/// destination. The mixed inbound resolves before dispatch; the TUN path can
/// still carry a fake-ip-mapped name in `target.host`, so resolve it through
/// the session resolver (pinned `Base.ResolveUDP`).
async fn resolve_ip_only_target(
    session: &crate::engine::SessionContext,
    proxy: &Proxy,
    target: outbound::Target,
) -> Result<outbound::Target, io::Error> {
    if target.host.parse::<IpAddr>().is_ok() {
        return Ok(target);
    }
    let address = crate::engine::proxy_udp_destination(
        session,
        proxy.dialer.ip_version,
        &target.host,
        None,
        target.port,
    )
    .await?;
    Ok(outbound::Target {
        host: address.ip().to_string(),
        port: address.port(),
    })
}

/// The one association task: connect once, then multiplex every destination
/// of that proxy over it (the pinned association is destination-agnostic).
pub(crate) async fn association_task(
    inner: Arc<Inner>,
    name: String,
    proxy: std::sync::Arc<Proxy>,
    flow: UdpFlowKey,
    mut commands: mpsc::Receiver<AssocCommand>,
    replies: mpsc::Sender<UdpReply>,
) {
    let Some(session) = inner.session() else {
        return;
    };
    if stream_udp(&proxy.protocol) {
        stream_association_task(&inner, &session, &proxy, flow, commands, replies).await;
        return;
    }
    let timeout = session.limits.dial_timeout;
    let tls = session.runtime.tls.clone();
    // The engine scopes `proxy-server-nameserver` around its dials; a spawned
    // association is a fresh task and does not inherit a task-local scope, so
    // the scope is re-entered here. Without this an `ss`/`ssr`/`socks5` server
    // name would go to the OS resolver while DNS is configured.
    let proxy_dns = session.runtime.dns.clone();
    let hops = crate::engine::chain_for(&session.runtime.config, &proxy);
    let family = proxy.type_name();
    let supported = match &proxy.protocol {
        Protocol::Socks5(option) => option.udp,
        Protocol::Shadowsocks(option) => option.udp,
        Protocol::Trojan(option) => option.udp,
        Protocol::TrustTunnel(option) => option.udp,
        Protocol::Sudoku(option) => option.udp,
        Protocol::Snell(option) => option.udp,
        Protocol::Ssr(option) => option.udp,
        Protocol::Masque(option) => option.udp,
        Protocol::ShadowQuic(_) => true,
        // Hysteria v1, Hysteria2 and TUIC always enable UDP in the pinned
        // outbound. Hysteria v1 uses the `udp=1` session with QUIC datagrams;
        // TUIC `udp-over-stream` opens one stream per destination below.
        Protocol::Hysteria(_) | Protocol::Hysteria2(_) | Protocol::Tuic(_) => true,
        // WireGuard states the UDP capability with `udp`; OpenVPN always
        // carries UDP in the pinned outbound.
        Protocol::Wireguard(option) => option.udp,
        Protocol::OpenVpn(_) => true,
        _ => false,
    };
    if !supported {
        inner.note_udp_unsupported(&name, family);
        return;
    }
    let connect = outbound::with_dialer(proxy.dialer.clone(), async {
        match &proxy.protocol {
            Protocol::Socks5(option) => {
                crate::outbound::socks5::Socks5Udp::connect(option, timeout, &tls)
                    .await
                    .map(Transport::Socks5)
            }
            Protocol::Shadowsocks(option) => {
                SsUdp::connect(option, &hops, timeout, &tls)
                    .await
                    .map(Transport::Ss)
            }
            Protocol::Trojan(option) => {
                TrojanUdp::connect(option, &hops, timeout, &tls)
                    .await
                    .map(Transport::Trojan)
            }
            Protocol::TrustTunnel(option) => {
                TrustTunnelUdp::connect(option, &hops, timeout, &tls)
                    .await
                    .map(Transport::TrustTunnel)
            }
            Protocol::Snell(option) => tokio::time::timeout(timeout, SnellUdp::connect(option))
                .await
                .map_err(|error| outbound::handshake("Snell v6 UDP", io::Error::new(io::ErrorKind::TimedOut, error)))?
                .map(Transport::Snell),
            Protocol::Sudoku(option) => {
                SudokuUdp::connect(option, &hops, timeout, &tls)
                    .await
                    .map(Transport::Sudoku)
            }
            Protocol::Ssr(option) => {
                SsrUdp::connect(option, &hops, timeout, &tls)
                    .await
                    .map(Transport::Ssr)
            }
            Protocol::Masque(option) => {
                MasqueUdpAssociation::connect(option, &tls, timeout)
                    .await
                    .map(Transport::Masque)
            }
            Protocol::ShadowQuic(option) => ShadowQuicUdp::connect(option, &tls, timeout)
                .await
                .map(Transport::ShadowQuic),
            Protocol::Hysteria(option) => HysteriaUdp::connect(option, &hops, timeout, &tls)
                .await
                .map(Transport::Hysteria),
            Protocol::Hysteria2(option) => Hysteria2Udp::connect(option, &hops, timeout, &tls)
                .await
                .map(Transport::Hysteria2),
            Protocol::Tuic(option) => crate::outbound::tuic::TuicUdp::connect(
                option, &hops, &tls, timeout,
            )
            .await
            .map(Transport::Tuic),
            Protocol::Wireguard(option) => {
                let stack = crate::outbound::wireguard::connect_stack(option, timeout)
                    .await
                    .map_err(|error| crate::outbound::DialError::Handshake {
                        protocol: "wireguard",
                        source: io::Error::other(error.to_string()),
                    })?;
                stack
                    .udp_socket()
                    .map(|socket| Transport::L3(L3Association::new(socket, "wireguard")))
                    .map_err(|source| crate::outbound::DialError::Handshake {
                        protocol: "wireguard",
                        source,
                    })
            }
            Protocol::OpenVpn(option) => {
                let stack = crate::outbound::openvpn::connect_stack(option, timeout)
                    .await
                    .map_err(|error| crate::outbound::DialError::Handshake {
                        protocol: "openvpn",
                        source: io::Error::other(error.to_string()),
                    })?;
                stack
                    .udp_socket()
                    .map(|socket| Transport::L3(L3Association::new(socket, "openvpn")))
                    .map_err(|source| crate::outbound::DialError::Handshake {
                        protocol: "openvpn",
                        source,
                    })
            }
            _ => unreachable!("supported was checked above"),
        }
    });
    let transport = match proxy_dns {
        Some(dns) => outbound::with_proxy_dns(dns, connect).await,
        None => connect.await,
    };
    let mut transport = match transport {
        Ok(transport) => transport,
        Err(error) => {
            inner.note_udp_association_error(&name, &error.to_string());
            return;
        }
    };
    inner.note_udp_association_ready(&name);
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    let idle_limit = inner.udp_idle();
    let mut idle = tokio::time::Instant::now() + idle_limit;
    loop {
        tokio::select! {
            biased;
            reply = transport.recv(&mut buffer) => match reply {
                Ok(Some((from, read))) => {
                    idle = tokio::time::Instant::now() + idle_limit;
                    let _ = replies.try_send(UdpReply {
                        flow,
                        from,
                        payload: buffer[..read].to_vec(),
                    });
                }
                Ok(None) => break,
                Err(error) => {
                    inner.note_udp_association_error(&name, &error.to_string());
                    break;
                }
            },
            command = commands.recv() => match command {
                Some(AssocCommand::Send { target, payload }) => {
                    idle = tokio::time::Instant::now() + idle_limit;
                    let target = match &transport {
                        Transport::TrustTunnel(_) | Transport::L3(_) => {
                            match resolve_ip_only_target(&session, &proxy, target).await {
                                Ok(target) => target,
                                Err(error) => {
                                    inner.note_udp_association_error(&name, &error.to_string());
                                    break;
                                }
                            }
                        }
                        _ => target,
                    };
                    if let Err(error) = transport.send(&target, &payload).await {
                        inner.note_udp_association_error(&name, &error.to_string());
                        break;
                    }
                }
                None => break,
            },
            _ = tokio::time::sleep_until(idle) => break,
        }
    }
    inner.note_udp_association_closed(&name);
}

/// One DIRECT UDP socket per device flow (the socket is connected to the
/// flow's remote, so the kernel only delivers packets from that remote). The
/// reader tags every datagram with the owning flow.
pub(crate) async fn direct_reader(
    socket: std::sync::Arc<tokio::net::UdpSocket>,
    flow: UdpFlowKey,
    replies: mpsc::Sender<UdpReply>,
) {
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    loop {
        match socket.recv(&mut buffer).await {
            Ok(read) => {
                if replies
                    .try_send(UdpReply {
                        flow,
                        from: flow.1,
                        payload: buffer[..read].to_vec(),
                    })
                    .is_err()
                    && replies.is_closed()
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}
