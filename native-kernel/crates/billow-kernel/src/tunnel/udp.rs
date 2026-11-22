//! UDP egress for the packet tunnel (feature `ios-vpn`).
//!
//! The device sends UDP datagrams as IP packets; each one is routed through
//! the engine (rule -> group -> outbound) exactly like a SOCKS5 `UDP
//! ASSOCIATE` datagram. The transports are the same association types the
//! mixed listener uses (`ss`, `trojan`, `ssr`, `masque`, `shadowquic`), plus
//! `DIRECT`. A family without a UDP association in this kernel is refused by
//! name instead of being sent the wrong way.
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
    udp::{SsUdp, SsrUdp, TrojanUdp, MAX_DATAGRAM},
};
use crate::proxies::{Protocol, Proxy};

use crate::tunnel::Inner;

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
    Ss(SsUdp),
    Trojan(TrojanUdp),
    Ssr(SsrUdp),
    Masque(MasqueUdpAssociation),
    ShadowQuic(ShadowQuicUdp),
}

impl Transport {
    async fn send(&mut self, target: &outbound::Target, payload: &[u8]) -> io::Result<()> {
        match self {
            Transport::Ss(transport) => transport.send(target, payload).await,
            Transport::Trojan(transport) => transport.send(target, payload).await,
            Transport::Ssr(transport) => transport.send(target, payload).await,
            Transport::Masque(transport) => transport.send(target, payload).await,
            Transport::ShadowQuic(transport) => transport.send(target, payload).await,
        }
    }

    /// One reply, already mapped to the remote address. `None` on EOF.
    async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(SocketAddr, usize)>> {
        let result = match self {
            Transport::Ss(transport) => transport.recv(buffer).await,
            Transport::Trojan(transport) => transport.recv(buffer).await,
            Transport::Ssr(transport) => transport.recv(buffer).await,
            Transport::Masque(transport) => transport.recv(buffer).await,
            Transport::ShadowQuic(transport) => transport.recv(buffer).await,
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
    let hops = crate::engine::chain_for(&session.runtime.config, &proxy);
    let family = proxy.type_name();
    let transport = match &proxy.protocol {
        Protocol::Shadowsocks(option) if option.udp => SsUdp::connect(option, &hops, timeout, &tls)
            .await
            .map(Transport::Ss),
        Protocol::Trojan(option) if option.udp => TrojanUdp::connect(option, &hops, timeout, &tls)
            .await
            .map(Transport::Trojan),
        Protocol::Ssr(option) if option.udp => SsrUdp::connect(option, &hops, timeout, &tls)
            .await
            .map(Transport::Ssr),
        Protocol::Masque(option) if option.udp => {
            MasqueUdpAssociation::connect(option, &tls, timeout)
                .await
                .map(Transport::Masque)
        }
        Protocol::ShadowQuic(option) => ShadowQuicUdp::connect(option, &tls, timeout)
            .await
            .map(Transport::ShadowQuic),
        _ => {
            inner.note_udp_unsupported(&name, family);
            return;
        }
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
