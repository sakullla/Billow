//! UDP egress for the packet tunnel (feature `ios-vpn`).
//!
//! The device sends UDP datagrams as IP packets; each one is routed through
//! the engine (rule -> group -> outbound) exactly like a SOCKS5 `UDP
//! ASSOCIATE` datagram. The transports are the same association types the
//! mixed listener uses (`socks5`, `ss`, `trojan`, `ssr`, `masque`,
//! `shadowquic`, `hysteria`, `hysteria2`, `tuic` including
//! `udp-over-stream`), plus `DIRECT`. A family without a UDP association in
//! this kernel is refused by name instead of being sent the wrong way. The mesh
//! families (`wireguard`/`openvpn`/`tailscale`/`zerotier`/`easytier`) and
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
    masque::MasqueUdpAssociation,
    shadowquic::ShadowQuicUdp,
    tls::ClientTls,
    udp::{
        spawn_uot_reader, Hysteria2Udp, HysteriaUdp, SsUdp, SsrUdp, TrojanUdp, TuicUot,
        UotKey, UotReader, UotWriter, MAX_DATAGRAM,
    },
};
use crate::proxies::{Protocol, Proxy};

use crate::tunnel::Inner;

/// Per-destination TUIC `udp-over-stream` associations for one device UDP flow.
///
/// The pinned UoT carriers bind a stream to a destination, so the device
/// association (one transport per flow) opens one UoT stream per target and
/// multiplexes commands and replies over them. This mirrors the mixed inbound's
/// UoT map while keeping the TUN path's flow tagging.
struct TuicUotAssociation {
    proxy: Arc<Proxy>,
    config: Arc<crate::config::Config>,
    tls: Arc<ClientTls>,
    timeout: std::time::Duration,
    associations:
        std::collections::HashMap<outbound::Target, (u64, UotWriter, tokio::task::AbortHandle)>,
    events: mpsc::UnboundedReceiver<crate::outbound::udp::UotEvent>,
    event_tx: mpsc::UnboundedSender<crate::outbound::udp::UotEvent>,
    next_id: u64,
}

impl TuicUotAssociation {
    fn new(
        proxy: Arc<Proxy>,
        config: Arc<crate::config::Config>,
        tls: Arc<ClientTls>,
        timeout: std::time::Duration,
    ) -> TuicUotAssociation {
        let (event_tx, events) = mpsc::unbounded_channel();
        TuicUotAssociation {
            proxy,
            config,
            tls,
            timeout,
            associations: std::collections::HashMap::new(),
            events,
            event_tx,
            next_id: 0,
        }
    }

    async fn send(&mut self, target: &outbound::Target, payload: &[u8]) -> io::Result<()> {
        if !self.associations.contains_key(target) {
            let Protocol::Tuic(option) = &self.proxy.protocol else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "tuic UoT association without a TUIC proxy",
                ));
            };
            let hops = crate::engine::chain_for(&self.config, &self.proxy);
            let association = TuicUot::connect(option, target, &hops, self.timeout, &self.tls)
                .await
                .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
            let (reader, writer) = association.into_halves();
            let key = UotKey {
                proxy: self.proxy.name.clone(),
                target: target.clone(),
            };
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            let abort = spawn_uot_reader(
                UotReader::Tuic(reader),
                key,
                id,
                self.event_tx.clone(),
            );
            self.associations
                .insert(target.clone(), (id, UotWriter::Tuic(writer), abort));
        }
        let result = match self.associations.get_mut(target) {
            Some((_, writer, _)) => writer.send(payload).await,
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "tuic UoT association missing after install",
            )),
        };
        if result.is_err() {
            if let Some((_, _, abort)) = self.associations.remove(target) {
                abort.abort();
            }
        }
        result
    }

    async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(SocketAddr, usize)>> {
        loop {
            match self.events.recv().await {
                Some(crate::outbound::udp::UotEvent::Datagram { from, payload }) => {
                    if payload.len() > buffer.len() {
                        continue;
                    }
                    let host = match from.host.parse::<IpAddr>() {
                        Ok(ip) => ip,
                        Err(_) => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "TUIC UoT reply from '{}' is not an IP address; the tunnel cannot map it to a device flow",
                                    from.host
                                ),
                            ))
                        }
                    };
                    buffer[..payload.len()].copy_from_slice(&payload);
                    return Ok(Some((SocketAddr::new(host, from.port), payload.len())));
                }
                Some(crate::outbound::udp::UotEvent::Closed { key, id }) => {
                    // The reader ended (stream closed or error); retire the
                    // writer so the next datagram reconnects instead of
                    // silently writing to a dead stream. A stale reader must
                    // not retire a newer association for the same target.
                    if self
                        .associations
                        .get(&key.target)
                        .is_some_and(|(known, _, _)| *known == id)
                    {
                        if let Some((_, _, abort)) = self.associations.remove(&key.target) {
                            abort.abort();
                        }
                    }
                }
                None => return Ok(None),
            }
        }
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
    Ssr(SsrUdp),
    Masque(MasqueUdpAssociation),
    ShadowQuic(ShadowQuicUdp),
    Hysteria(HysteriaUdp),
    Hysteria2(Hysteria2Udp),
    Tuic(crate::outbound::tuic::TuicUdp),
    TuicUot(TuicUotAssociation),
}

impl Transport {
    async fn send(&mut self, target: &outbound::Target, payload: &[u8]) -> io::Result<()> {
        match self {
            Transport::Socks5(transport) => transport.send(target, payload).await,
            Transport::Ss(transport) => transport.send(target, payload).await,
            Transport::Trojan(transport) => transport.send(target, payload).await,
            Transport::Ssr(transport) => transport.send(target, payload).await,
            Transport::Masque(transport) => transport.send(target, payload).await,
            Transport::ShadowQuic(transport) => transport.send(target, payload).await,
            Transport::Hysteria(transport) => transport.send(target, payload).await,
            Transport::Hysteria2(transport) => transport.send(target, payload).await,
            Transport::Tuic(transport) => transport.send(target, payload).await,
            Transport::TuicUot(transport) => transport.send(target, payload).await,
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
            Transport::Ssr(transport) => transport.recv(buffer).await,
            Transport::Masque(transport) => transport.recv(buffer).await,
            Transport::ShadowQuic(transport) => transport.recv(buffer).await,
            Transport::Hysteria(transport) => transport.recv(buffer).await,
            Transport::Hysteria2(transport) => transport.recv(buffer).await,
            Transport::Tuic(transport) => transport.recv(buffer).await,
            // Replies already carry an `IpAddr`; returning `None` here would
            // skip the target mapping below.
            Transport::TuicUot(transport) => return transport.recv(buffer).await,
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
        Protocol::Ssr(option) => option.udp,
        Protocol::Masque(option) => option.udp,
        Protocol::ShadowQuic(_) => true,
        // Hysteria v1, Hysteria2 and TUIC always enable UDP in the pinned
        // outbound. Hysteria v1 uses the `udp=1` session with QUIC datagrams;
        // TUIC `udp-over-stream` opens one stream per destination below.
        Protocol::Hysteria(_) | Protocol::Hysteria2(_) | Protocol::Tuic(_) => true,
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
            Protocol::Tuic(option) if option.udp_over_stream => Ok(Transport::TuicUot(
                TuicUotAssociation::new(
                    proxy.clone(),
                    session.runtime.config.clone(),
                    tls.clone(),
                    timeout,
                ),
            )),
            Protocol::Tuic(option) => crate::outbound::tuic::TuicUdp::connect(
                option, &hops, &tls, timeout,
            )
            .await
            .map(Transport::Tuic),
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
        match socket.recv_from(&mut buffer).await {
            Ok((read, from)) => {
                if replies
                    .try_send(UdpReply {
                        flow,
                        from,
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
