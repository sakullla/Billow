//! Userspace IP data plane for device tunnels (feature `ios-vpn`).
//!
//! The iOS Packet Tunnel (`src-tauri/gen/apple/network-extension/RustExtension`)
//! hands whole IP packets to this module and expects IP packets back. The
//! module terminates the device's TCP and UDP flows in userspace, routes every
//! flow through the engine (rules, proxy groups, outbound dialling, DNS) and
//! emits the replies as IP packets. It is deliberately independent of
//! Tauri/NetworkExtension so a host can drive it in tests; the C ABI in
//! `ios_vpn` is a thin wrapper.
//!
//! Layout:
//! * [`tcp_server`] — the passive-open TCP endpoint (device -> kernel);
//! * [`udp`] — UDP associations (the same transports the mixed listener uses);
//! * [`route`] — rule/group/outbound decisions shared with the listener path.
//!
//! Bounds (R3/R4): one task per TCP flow up to [`TunnelOptions::max_tcp_flows`],
//! at most [`TunnelOptions::max_udp_flows`] UDP flows, an inbound queue per flow
//! and one datagram queue, a bounded egress queue (drain mode) and a fixed
//! number of UDP associations. Every drop is counted and named; nothing is
//! buffered without a limit.

mod route;
pub mod tcp_server;
pub mod udp;

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::config::NetworkKind;
use crate::engine::{Kernel, KernelOptions, Limits, SessionContext};
use crate::outbound::ipstack;
use crate::outbound::tcp::{build_segment, parse_segment, FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN};
use crate::tunnel::tcp_server::{ServerConfig, ServerTcp};
use crate::tunnel::udp::{direct_reader, AssocCommand, UdpReply, MAX_ASSOCIATIONS};

/// Default tunnel MTU: the extension configures 9000 for the Mihomo (gVisor)
/// stack, but this stack advertises a conservative Ethernet-sized MSS so the
/// kernel never builds a segment larger than a normal network path.
pub const DEFAULT_MTU: usize = 1500;
/// Fixed hop limit of emitted packets (nothing routes them further).
const HOP_LIMIT: u8 = 64;
/// DNS queries answered concurrently (each is one UDP packet in flight).
const DNS_SLOTS: usize = 32;

/// Tunables of one tunnel. The defaults are the values the iOS extension
/// starts with; tests shrink them.
#[derive(Debug, Clone, Copy)]
pub struct TunnelOptions {
    /// Tunnel MTU used for the advertised TCP MSS (never for receiving).
    pub mtu: usize,
    /// TCP flows alive at once; a new SYN beyond this is refused with RST.
    pub max_tcp_flows: usize,
    /// UDP flows (device 4-tuples) tracked at once.
    pub max_udp_flows: usize,
    /// Packets held for a polling host when no egress callback is installed.
    pub packet_queue: usize,
    /// Packets queued per flow before the device side is dropped (bounded).
    pub inbound_queue: usize,
    /// Datagrams queued for the UDP task before they are dropped.
    pub datagram_queue: usize,
    /// An idle UDP flow is released after this long.
    pub udp_idle: Duration,
    /// An idle TCP flow is closed after this long.
    pub tcp_idle: Duration,
    /// Answer `:53` queries from the configured DNS instead of forwarding.
    pub hijack_dns: bool,
    /// Per-direction relay buffer.
    pub buffer_size: usize,
    /// Engine limits (dial timeouts, UDP association idle) for this host.
    pub limits: Limits,
}

impl Default for TunnelOptions {
    fn default() -> Self {
        TunnelOptions {
            mtu: DEFAULT_MTU,
            max_tcp_flows: 128,
            max_udp_flows: 256,
            packet_queue: 128,
            inbound_queue: 32,
            datagram_queue: 256,
            udp_idle: Duration::from_secs(60),
            tcp_idle: Duration::from_secs(300),
            hijack_dns: true,
            buffer_size: 16 * 1024,
            limits: Limits {
                // The extension relays whole packets; a 16 KiB copy buffer per
                // direction matches the engine default and keeps R3 in reach.
                buffer_size: 16 * 1024,
                max_sessions: 256,
                ..Limits::default()
            },
        }
    }
}

/// Where emitted packets go. The iOS extension installs a callback that writes
/// to `packetFlow`; tests and polling hosts leave it unset and drain.
pub trait PacketSink: Send + Sync {
    /// Deliver one IP packet; the slice is only valid during the call.
    /// `false` means the host refused it (counted as a drop).
    fn emit(&self, packet: &[u8]) -> bool;
}

/// Why an inbound packet did not start or continue a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ingest {
    Accepted,
    /// A named rejection: malformed packet, unsupported protocol, refused flow.
    Dropped(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FlowKey {
    pub proto: u8,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

/// One device UDP datagram on its way through the engine.
struct UdpIn {
    src: SocketAddr,
    dst: SocketAddr,
    payload: Vec<u8>,
}

/// Control message of the UDP task (a reload drops every association so the
/// previous generation's transports and rules are released).
enum UdpCommand {
    Datagram(UdpIn),
    Reload,
}

#[derive(Default)]
pub(crate) struct Stats {
    in_packets: AtomicU64,
    in_bytes: AtomicU64,
    out_packets: AtomicU64,
    out_bytes: AtomicU64,
    tcp_opened: AtomicU64,
    tcp_closed: AtomicU64,
    tcp_rejected: AtomicU64,
    udp_datagrams: AtomicU64,
    udp_replies: AtomicU64,
    udp_flow_high: AtomicUsize,
    dns_queries: AtomicU64,
    dns_failures: AtomicU64,
    invalid_packets: AtomicU64,
    fragments: AtomicU64,
    unsupported_protocols: AtomicU64,
    icmp_dropped: AtomicU64,
    dropped_inbound: AtomicU64,
    dropped_egress: AtomicU64,
    queue_high: AtomicUsize,
    tcp_flow_high: AtomicUsize,
    reloads: AtomicU64,
    generation: AtomicU64,
}

/// A point-in-time copy, printed by `billow_ios_vpn_stats`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelStats {
    pub in_packets: u64,
    pub in_bytes: u64,
    pub out_packets: u64,
    pub out_bytes: u64,
    pub tcp_opened: u64,
    pub tcp_closed: u64,
    pub tcp_rejected: u64,
    pub udp_datagrams: u64,
    pub udp_replies: u64,
    pub dns_queries: u64,
    pub dns_failures: u64,
    pub invalid_packets: u64,
    pub fragments: u64,
    pub unsupported_protocols: u64,
    pub icmp_dropped: u64,
    pub dropped_inbound: u64,
    pub dropped_egress: u64,
    pub queue_high: u64,
    pub tcp_flow_high: u64,
    pub udp_flow_high: u64,
    pub reloads: u64,
    pub generation: u64,
    /// Live TCP flows and queued packets at the moment of the snapshot.
    pub tcp_flows: u64,
    pub udp_flows: u64,
    pub queued_packets: u64,
}

pub(crate) struct Inner {
    kernel: Mutex<Option<Kernel>>,
    config_path: PathBuf,
    options: TunnelOptions,
    sink: Option<Arc<dyn PacketSink>>,
    queue: Mutex<VecDeque<Vec<u8>>>,
    tcp: Mutex<HashMap<FlowKey, mpsc::Sender<Vec<u8>>>>,
    udp: Mutex<Option<mpsc::Sender<UdpCommand>>>,
    udp_flows: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), tokio::time::Instant>>>,
    associations: Mutex<HashMap<String, mpsc::Sender<AssocCommand>>>,
    dns_slots: Arc<tokio::sync::Semaphore>,
    stats: Stats,
    closed: AtomicBool,
    runtime: Mutex<Option<tokio::runtime::Handle>>,
}

impl Inner {
    pub(crate) fn session(&self) -> Option<Arc<SessionContext>> {
        self.kernel
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|kernel| kernel.packet_session())
    }

    pub(crate) fn udp_idle(&self) -> Duration {
        self.options.udp_idle
    }

    pub(crate) fn note_udp_unsupported(&self, proxy: &str, family: &'static str) {
        self.stats
            .unsupported_protocols
            .fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            proxy,
            family,
            "UDP datagram dropped: no UDP association for this proxy type"
        );
    }

    pub(crate) fn note_udp_association_error(&self, proxy: &str, error: &str) {
        self.stats.dropped_inbound.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(proxy, error, "UDP association failed");
    }

    pub(crate) fn note_udp_association_ready(&self, proxy: &str) {
        tracing::debug!(proxy, "UDP association established");
    }

    pub(crate) fn note_udp_association_closed(&self, proxy: &str) {
        tracing::debug!(proxy, "UDP association closed");
    }

    /// Emit one packet: the host callback when installed, the bounded queue
    /// otherwise.
    fn emit(&self, packet: Vec<u8>) {
        if packet.is_empty() {
            return;
        }
        let bytes = packet.len() as u64;
        match &self.sink {
            Some(sink) => {
                if sink.emit(&packet) {
                    self.stats.out_packets.fetch_add(1, Ordering::Relaxed);
                    self.stats.out_bytes.fetch_add(bytes, Ordering::Relaxed);
                } else {
                    self.stats.dropped_egress.fetch_add(1, Ordering::Relaxed);
                }
            }
            None => {
                let mut queue = self
                    .queue
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if queue.len() >= self.options.packet_queue {
                    self.stats.dropped_egress.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                queue.push_back(packet);
                let len = queue.len();
                self.stats.queue_high.fetch_max(len, Ordering::Relaxed);
                self.stats.out_packets.fetch_add(1, Ordering::Relaxed);
                self.stats.out_bytes.fetch_add(bytes, Ordering::Relaxed);
            }
        }
    }

    fn spawn<F>(&self, future: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        if let Some(handle) = self
            .runtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .cloned()
        {
            handle.spawn(future);
        }
    }
}

/// One running tunnel: the engine plus the device data plane.
pub struct Tunnel {
    pub(crate) inner: Arc<Inner>,
    /// Taken by [`Tunnel::stop`] so the shutdown can wait for the flow tasks.
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
}

impl Tunnel {
    /// Load `config_yaml` (already the effictive configuration) from
    /// `base_dir`, start the engine and the data plane.
    pub fn start(
        config_yaml: &str,
        base_dir: PathBuf,
        options: TunnelOptions,
        sink: Option<Arc<dyn PacketSink>>,
    ) -> Result<Tunnel, String> {
        let config_path = base_dir.join("config.yaml");
        let loaded = crate::config::load_config(config_yaml, &config_path.display().to_string())
            .map_err(|error| format!("configuration: {error}"))?;
        let (kernel, warnings) = Kernel::start_with_options(
            &loaded,
            Some(base_dir.clone()),
            base_dir.clone(),
            options.limits,
            &KernelOptions {
                cache_dir: Some(base_dir.clone()),
                log_bus: None,
            },
        )
        .map_err(|error| format!("kernel start: {error}"))?;
        for warning in &warnings {
            tracing::warn!(warning, "kernel configuration warning");
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("billow-tunnel")
            .enable_all()
            .build()
            .map_err(|error| format!("tunnel runtime: {error}"))?;
        let inner = Arc::new(Inner {
            kernel: Mutex::new(Some(kernel)),
            config_path,
            options,
            sink,
            queue: Mutex::new(VecDeque::new()),
            tcp: Mutex::new(HashMap::new()),
            udp: Mutex::new(None),
            udp_flows: Arc::new(Mutex::new(HashMap::new())),
            associations: Mutex::new(HashMap::new()),
            dns_slots: Arc::new(tokio::sync::Semaphore::new(DNS_SLOTS)),
            stats: Stats::default(),
            closed: AtomicBool::new(false),
            runtime: Mutex::new(Some(runtime.handle().clone())),
        });
        let (udp_tx, udp_rx) = mpsc::channel::<UdpCommand>(options.datagram_queue.max(1));
        *inner
            .udp
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(udp_tx);
        let (reply_tx, reply_rx) = mpsc::channel::<UdpReply>(options.datagram_queue.max(1));
        let task_inner = inner.clone();
        runtime.spawn(udp_task(task_inner, udp_rx, reply_rx, reply_tx));
        tracing::info!(
            listen = %inner
                .session()
                .map(|session| session.listen_port().to_string())
                .unwrap_or_else(|| "?".to_string()),
            mtu = options.mtu,
            "tunnel data plane started"
        );
        Ok(Tunnel {
            inner,
            runtime: Mutex::new(Some(runtime)),
        })
    }

    /// Feed one IP packet from the device. Never blocks: work is queued to the
    /// flow tasks and a full queue is a counted drop.
    pub fn ingest(&self, packet: &[u8]) -> Ingest {
        let stats = &self.inner.stats;
        stats.in_packets.fetch_add(1, Ordering::Relaxed);
        stats
            .in_bytes
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        if self.inner.closed.load(Ordering::Relaxed) {
            return Ingest::Dropped("tunnel stopped");
        }
        let parsed = match ipstack::parse_ip_packet(packet) {
            Ok(parsed) => parsed,
            Err(error) => {
                match &error {
                    ipstack::IpError::Unsupported(what) => {
                        if what.contains("fragment") {
                            stats.fragments.fetch_add(1, Ordering::Relaxed);
                        } else {
                            stats.unsupported_protocols.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    ipstack::IpError::Malformed(_) => {
                        stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
                    }
                }
                tracing::debug!(error = %error, "device packet dropped");
                return Ingest::Dropped("unsupported or malformed IP packet");
            }
        };
        match parsed.protocol {
            ipstack::IPPROTO_TCP => self.ingest_tcp(packet, &parsed),
            ipstack::IPPROTO_UDP => self.ingest_udp(&parsed),
            // ICMP is not answered by this stack (the pinned adapter answers
            // ping through gVisor); it is counted and dropped by name.
            1 | 58 => {
                stats.icmp_dropped.fetch_add(1, Ordering::Relaxed);
                Ingest::Dropped("ICMP")
            }
            other => {
                stats.unsupported_protocols.fetch_add(1, Ordering::Relaxed);
                if let Some(reply) = build_icmp_unreachable(packet, 2) {
                    self.inner.emit(reply);
                }
                tracing::debug!(protocol = other, "device packet dropped: no handler");
                Ingest::Dropped("unsupported IP protocol")
            }
        }
    }

    fn ingest_tcp(&self, packet: &[u8], parsed: &ipstack::IpPacket<'_>) -> Ingest {
        let segment = match parse_segment(packet) {
            Ok(segment) => segment,
            Err(error) => {
                self.inner
                    .stats
                    .invalid_packets
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!(error, "TCP segment dropped");
                return Ingest::Dropped("malformed TCP segment");
            }
        };
        let key = FlowKey {
            proto: ipstack::IPPROTO_TCP,
            src: SocketAddr::new(parsed.src, segment.src_port),
            dst: SocketAddr::new(parsed.dst, segment.dst_port),
        };
        {
            let map = self
                .inner
                .tcp
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(sender) = map.get(&key) {
                if sender.try_send(packet.to_vec()).is_err() {
                    self.inner
                        .stats
                        .dropped_inbound
                        .fetch_add(1, Ordering::Relaxed);
                    return Ingest::Dropped("flow queue full");
                }
                return Ingest::Accepted;
            }
        }
        if segment.flags & FLAG_SYN == 0 || segment.flags & FLAG_ACK != 0 {
            // Not a connection attempt and no flow knows the segment: answer a
            // RST the way a closed port does, so the device fails fast.
            if let Some(reply) = reset_for(&segment, parsed) {
                self.inner.emit(reply);
            }
            self.inner
                .stats
                .tcp_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Ingest::Dropped("no such TCP flow");
        }
        let mut map = self
            .inner
            .tcp
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if map.len() >= self.inner.options.max_tcp_flows {
            drop(map);
            if let Some(reply) = reset_for(&segment, parsed) {
                self.inner.emit(reply);
            }
            self.inner
                .stats
                .tcp_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Ingest::Dropped("TCP flow limit");
        }
        let config = ServerConfig {
            local: parsed.dst,
            remote: parsed.src,
            local_port: segment.dst_port,
            remote_port: segment.src_port,
            mss: self.inner.mss(parsed.dst),
            initial_seq: rand::random::<u32>(),
            hop_limit: HOP_LIMIT,
        };
        let tcp = ServerTcp::accept(config, &segment);
        let (sender, receiver) = mpsc::channel(self.inner.options.inbound_queue.max(1));
        map.insert(key, sender);
        let len = map.len();
        drop(map);
        self.inner
            .stats
            .tcp_flow_high
            .fetch_max(len, Ordering::Relaxed);
        self.inner.stats.tcp_opened.fetch_add(1, Ordering::Relaxed);
        let inner = self.inner.clone();
        self.inner.spawn(tcp_flow(inner, key, tcp, receiver));
        Ingest::Accepted
    }

    fn ingest_udp(&self, parsed: &ipstack::IpPacket<'_>) -> Ingest {
        let datagram = match ipstack::parse_udp(parsed) {
            Ok(datagram) => datagram,
            Err(error) => {
                self.inner
                    .stats
                    .invalid_packets
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!(error = %error, "UDP datagram dropped");
                return Ingest::Dropped("malformed UDP datagram");
            }
        };
        let src = SocketAddr::new(datagram.src, datagram.src_port);
        let dst = SocketAddr::new(datagram.dst, datagram.dst_port);
        if self.inner.options.hijack_dns && datagram.dst_port == 53 {
            if let Some(session) = self.inner.session() {
                if let Some(dns) = session.runtime.dns.clone() {
                    let Ok(slot) = self.inner.dns_slots.clone().try_acquire_owned() else {
                        self.inner
                            .stats
                            .dropped_inbound
                            .fetch_add(1, Ordering::Relaxed);
                        return Ingest::Dropped("DNS concurrency limit");
                    };
                    let payload = datagram.payload.to_vec();
                    let query = payload.clone();
                    let inner = self.inner.clone();
                    self.inner.spawn(async move {
                        let _slot = slot;
                        inner.stats.dns_queries.fetch_add(1, Ordering::Relaxed);
                        let answer = dns.answer_query(&query).await;
                        if answer.is_empty() {
                            inner.stats.dns_failures.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                        match ipstack::build_udp_packet(
                            dst.ip(),
                            src.ip(),
                            dst.port(),
                            src.port(),
                            &answer,
                            HOP_LIMIT,
                        ) {
                            Ok(reply) => inner.emit(reply),
                            Err(error) => {
                                tracing::debug!(error = %error, "DNS reply could not be built");
                                inner.stats.dns_failures.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    });
                    return Ingest::Accepted;
                }
            }
        }
        self.inner
            .stats
            .udp_datagrams
            .fetch_add(1, Ordering::Relaxed);
        let command = UdpCommand::Datagram(UdpIn {
            src,
            dst,
            payload: datagram.payload.to_vec(),
        });
        let sender = self
            .inner
            .udp
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        match sender {
            Some(sender) => {
                if sender.try_send(command).is_err() {
                    self.inner
                        .stats
                        .dropped_inbound
                        .fetch_add(1, Ordering::Relaxed);
                    Ingest::Dropped("UDP queue full")
                } else {
                    Ingest::Accepted
                }
            }
            None => Ingest::Dropped("UDP task stopped"),
        }
    }

    /// Packets waiting for a polling host, as `[4-byte big-endian
    /// length][packet]` records. Returns the number of records copied; a
    /// record that does not fit is left in the queue.
    pub fn drain_into(&self, out: &mut [u8], max_count: usize) -> usize {
        let mut queue = self
            .inner
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut count = 0;
        let mut offset = 0;
        while count < max_count {
            let Some(front) = queue.front() else {
                break;
            };
            let needed = 4 + front.len();
            if offset + needed > out.len() {
                break;
            }
            out[offset..offset + 4].copy_from_slice(&(front.len() as u32).to_be_bytes());
            out[offset + 4..offset + needed].copy_from_slice(front);
            offset += needed;
            count += 1;
            queue.pop_front();
        }
        count
    }

    /// Queued packets waiting for [`Tunnel::drain_into`].
    pub fn queued(&self) -> usize {
        self.inner
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Reload the same configuration file. A rejected reload keeps the running
    /// generation; an accepted one closes every flow and association so the
    /// previous generation's rules/providers are released (R4).
    pub fn reload(&self) -> Result<Vec<String>, String> {
        let yaml = std::fs::read_to_string(&self.inner.config_path)
            .map_err(|error| format!("read {}: {error}", self.inner.config_path.display()))?;
        let warnings = {
            let mut guard = self
                .inner
                .kernel
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let kernel = guard.as_mut().ok_or_else(|| "kernel stopped".to_string())?;
            kernel.reload(&yaml).map_err(|error| error.to_string())?
        };
        self.inner.stats.reloads.fetch_add(1, Ordering::Relaxed);
        self.inner.stats.generation.fetch_add(1, Ordering::Relaxed);
        self.reset_flows();
        Ok(warnings)
    }

    /// Close every flow and association (a reload, or a host request).
    pub fn reset_flows(&self) {
        self.inner
            .tcp
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.inner
            .associations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        if let Some(sender) = self
            .inner
            .udp
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
        {
            let _ = sender.try_send(UdpCommand::Reload);
        }
        let mut queue = self
            .inner
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        queue.clear();
    }

    /// Live counters for the extension (`billow_ios_vpn_stats`).
    pub fn stats(&self) -> TunnelStats {
        let stats = &self.inner.stats;
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        TunnelStats {
            in_packets: load(&stats.in_packets),
            in_bytes: load(&stats.in_bytes),
            out_packets: load(&stats.out_packets),
            out_bytes: load(&stats.out_bytes),
            tcp_opened: load(&stats.tcp_opened),
            tcp_closed: load(&stats.tcp_closed),
            tcp_rejected: load(&stats.tcp_rejected),
            udp_datagrams: load(&stats.udp_datagrams),
            udp_replies: load(&stats.udp_replies),
            dns_queries: load(&stats.dns_queries),
            dns_failures: load(&stats.dns_failures),
            invalid_packets: load(&stats.invalid_packets),
            fragments: load(&stats.fragments),
            unsupported_protocols: load(&stats.unsupported_protocols),
            icmp_dropped: load(&stats.icmp_dropped),
            dropped_inbound: load(&stats.dropped_inbound),
            dropped_egress: load(&stats.dropped_egress),
            queue_high: stats.queue_high.load(Ordering::Relaxed) as u64,
            tcp_flow_high: stats.tcp_flow_high.load(Ordering::Relaxed) as u64,
            udp_flow_high: stats.udp_flow_high.load(Ordering::Relaxed) as u64,
            reloads: load(&stats.reloads),
            generation: load(&stats.generation),
            tcp_flows: self
                .inner
                .tcp
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len() as u64,
            udp_flows: self
                .inner
                .udp_flows
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len() as u64,
            queued_packets: self.queued() as u64,
        }
    }

    /// Stop the data plane and the engine; every buffer, flow and socket is
    /// released before this returns.
    pub fn stop(&self) {
        self.inner.closed.store(true, Ordering::Relaxed);
        self.inner
            .tcp
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.inner
            .associations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        *self
            .inner
            .udp
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        *self
            .inner
            .runtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        if let Some(runtime) = self
            .runtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            // `shutdown_background` is safe from an async context (a host may
            // call stop from its own runtime); the tasks observe the closed
            // channels first.
            runtime.shutdown_background();
        }
        // Take the kernel out of the lock first: stopping it joins its
        // supervisor thread, and a tunnel task may still be asking for a
        // session snapshot.
        let kernel = self
            .inner
            .kernel
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(mut kernel) = kernel {
            let _ = kernel.stop();
        }
        self.inner
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        tracing::info!("tunnel data plane stopped");
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // `stop` consumes the tunnel; dropping it is the same teardown minus
        // the shutdown wait the explicit path performs.
        self.inner.closed.store(true, Ordering::Relaxed);
        self.inner
            .tcp
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.inner
            .udp
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let kernel = self
            .inner
            .kernel
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(mut kernel) = kernel {
            let _ = kernel.stop();
        }
    }
}

impl Inner {
    fn mss(&self, dst: IpAddr) -> u16 {
        let overhead = if dst.is_ipv4() {
            ipstack::IPV4_TCP_OVERHEAD
        } else {
            ipstack::IPV6_TCP_OVERHEAD
        };
        self.options.mtu.saturating_sub(overhead).clamp(536, 65_495) as u16
    }
}

fn build_icmp_unreachable(original: &[u8], code: u8) -> Option<Vec<u8>> {
    // Only IPv4 is answered: an ICMP error quotes the original IP header plus
    // 8 bytes (RFC 792), and IPv6 has no equivalent shape here.
    if original.first().map(|byte| byte >> 4) != Some(4) || original.len() < 20 {
        return None;
    }
    let header_len = usize::from(original[0] & 0x0f) * 4;
    if header_len < 20 || header_len > original.len() {
        return None;
    }
    let quote_end = (header_len + 8).min(original.len());
    let mut icmp = vec![3u8, code, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&original[..quote_end]);
    let checksum = ipstack::checksum16(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    let src = IpAddr::V4(std::net::Ipv4Addr::new(
        original[16],
        original[17],
        original[18],
        original[19],
    ));
    let dst = IpAddr::V4(std::net::Ipv4Addr::new(
        original[12],
        original[13],
        original[14],
        original[15],
    ));
    ipstack::build_packet(src, dst, 1, &icmp, 64).ok()
}

/// A RST for a segment that no flow accepts.
fn reset_for(
    segment: &crate::outbound::tcp::TcpSegment<'_>,
    parsed: &ipstack::IpPacket<'_>,
) -> Option<Vec<u8>> {
    let mut ack = segment.seq.wrapping_add(segment.payload.len() as u32);
    if segment.flags & FLAG_SYN != 0 || segment.flags & FLAG_FIN != 0 {
        ack = ack.wrapping_add(1);
    }
    let seq = if segment.flags & FLAG_ACK != 0 {
        segment.ack
    } else {
        0
    };
    let flags = if segment.flags & FLAG_ACK != 0 {
        FLAG_RST
    } else {
        FLAG_RST | FLAG_ACK
    };
    let segment = build_segment(
        parsed.dst,
        parsed.src,
        segment.dst_port,
        segment.src_port,
        seq,
        ack,
        flags,
        0,
        None,
        &[],
    );
    ipstack::build_packet(
        parsed.dst,
        parsed.src,
        ipstack::IPPROTO_TCP,
        &segment,
        HOP_LIMIT,
    )
    .ok()
}

fn flush(inner: &Inner, tcp: &mut ServerTcp) {
    while let Some(packet) = tcp.poll_transmit(Instant::now()) {
        inner.emit(packet);
    }
}

/// One device TCP flow: answer the handshake, route the connection through the
/// engine and splice the byte stream to the outbound socket.
async fn tcp_flow(
    inner: Arc<Inner>,
    key: FlowKey,
    mut tcp: ServerTcp,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    let Some(session) = inner.session() else {
        tcp.reset();
        flush(&inner, &mut tcp);
        return;
    };
    // The SYN-ACK goes out before any dial so the device does not retransmit
    // while the outbound is being established.
    flush(&inner, &mut tcp);
    let idle_limit = inner.options.tcp_idle;
    let mut idle = Instant::now() + idle_limit;

    let target = match route::destination(
        &session,
        key.dst.ip(),
        key.dst.port(),
        NetworkKind::Tcp,
        key.src,
    )
    .await
    {
        Ok(target) => target,
        Err(reason) => {
            tracing::warn!(dst = %key.dst, reason, "tunnel destination mapping failed");
            tcp.reset();
            flush(&inner, &mut tcp);
            inner.stats.tcp_rejected.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let dns = session.runtime.dns.clone();
    if inner.options.hijack_dns && key.dst.port() == 53 && dns.is_some() {
        dns_tcp_flow(inner, tcp, rx, dns.expect("checked above"), idle_limit).await;
        return;
    }

    // 1. Route the flow (rule -> group -> outbound).
    let mut target = target;
    let (route, decision) = match route::decide(&session, &mut target, false).await {
        Ok(pair) => pair,
        Err(failure) => {
            tracing::info!(dst = %key.dst, reason = %failure.reason, "tunnel TCP flow refused");
            tcp.reset();
            flush(&inner, &mut tcp);
            inner.stats.tcp_rejected.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let host = target.host.clone();
    let ip = target.ip;

    // 2. Dial while the device packets keep arriving (they are buffered in the
    //    connection's bounded send path and acknowledged).
    let timeout = session.limits.dial_timeout;
    let dial = route::dial_tcp(
        &session,
        route,
        &decision,
        &target,
        host.clone(),
        ip,
        timeout,
    );
    tokio::pin!(dial);
    let routed = loop {
        tokio::select! {
            biased;
            result = &mut dial => break result,
            packet = rx.recv() => match packet {
                Some(packet) => {
                    tcp.on_packet(&packet, Instant::now());
                    flush(&inner, &mut tcp);
                    if tcp.failure().is_some() {
                        return;
                    }
                }
                None => {
                    tcp.reset();
                    flush(&inner, &mut tcp);
                    return;
                }
            },
            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                tcp.on_timer(Instant::now());
                flush(&inner, &mut tcp);
                if Instant::now() >= idle {
                    tcp.reset();
                    flush(&inner, &mut tcp);
                    return;
                }
            },
        }
    };
    let routed = match routed {
        Ok(routed) => routed,
        Err(failure) => {
            tracing::warn!(dst = %key.dst, reason = %failure.reason, "tunnel TCP dial failed");
            tcp.reset();
            flush(&inner, &mut tcp);
            return;
        }
    };
    tracing::info!(
        dst = %key.dst,
        rule = %routed.rule,
        outbound = %routed.outbound,
        "tunnel TCP flow established"
    );
    idle = Instant::now() + idle_limit;

    // 3. Register the flow for the control API (`/connections`).
    let upload = Arc::new(AtomicU64::new(0));
    let download = Arc::new(AtomicU64::new(0));
    let closed = Arc::new(tokio::sync::Notify::new());
    let connection_id = uuid::Uuid::new_v4().to_string();
    let _registration = session.connections.register(crate::engine::OpenConnection {
        id: connection_id,
        host: routed.host.clone(),
        destination_ip: routed.ip,
        destination_port: key.dst.port(),
        source_ip: key.src.ip(),
        source_port: key.src.port(),
        kind: "Tun",
        network: "tcp",
        inbound_port: session.listen_port(),
        chains: routed.chains.clone(),
        rule: routed.rule_kind.clone(),
        rule_payload: routed.rule_payload.clone(),
        start: std::time::SystemTime::now(),
        upload: upload.clone(),
        download: download.clone(),
        close: closed.clone(),
    });

    // 4. Relay.
    let (mut read_half, mut write_half) = tokio::io::split(routed.stream);
    let mut buffer = vec![0u8; inner.options.buffer_size.max(1)];
    let mut upstream_half_closed = false;
    loop {
        flush(&inner, &mut tcp);
        if tcp.finished() {
            break;
        }
        if let Some(error) = tcp.failure() {
            tracing::debug!(dst = %key.dst, error = %error, "tunnel TCP flow failed");
            break;
        }
        if tcp.write_side_closed() && !upstream_half_closed {
            upstream_half_closed = true;
            let _ = write_half.shutdown().await;
        }
        while let Some(data) = tcp.take_received() {
            idle = Instant::now() + idle_limit;
            if write_half.write_all(&data).await.is_err() {
                tcp.reset();
                flush(&inner, &mut tcp);
                break;
            }
            upload.fetch_add(data.len() as u64, Ordering::Relaxed);
        }
        if tcp.finished() {
            break;
        }
        let timer = tcp
            .next_timer()
            .map(tokio::time::Instant::from_std)
            .unwrap_or_else(|| tokio::time::Instant::now() + idle_limit);
        tokio::select! {
            biased;
            packet = rx.recv() => match packet {
                Some(packet) => {
                    idle = Instant::now() + idle_limit;
                    tcp.on_packet(&packet, Instant::now());
                }
                None => {
                    tcp.reset();
                    flush(&inner, &mut tcp);
                    break;
                }
            },
            read = read_half.read(&mut buffer), if tcp.can_accept() => match read {
                Ok(0) => tcp.shutdown(),
                Ok(read) => {
                    idle = Instant::now() + idle_limit;
                    download.fetch_add(read as u64, Ordering::Relaxed);
                    let accepted = tcp.enqueue(&buffer[..read]);
                    if accepted < read {
                        // The device is not reading: close instead of growing
                        // an unbounded buffer.
                        tracing::debug!(dst = %key.dst, "tunnel TCP send buffer full; closing");
                        tcp.reset();
                        flush(&inner, &mut tcp);
                        break;
                    }
                }
                Err(_) => {
                    tcp.shutdown();
                }
            },
            _ = tokio::time::sleep_until(timer) => tcp.on_timer(Instant::now()),
            _ = closed.notified() => {
                tcp.reset();
                flush(&inner, &mut tcp);
                break;
            },
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(idle)) => {
                tracing::debug!(dst = %key.dst, "tunnel TCP flow idle timeout");
                tcp.reset();
                flush(&inner, &mut tcp);
                break;
            },
        }
    }
    // Best effort FIN/RST already emitted; release the flow index so a reload
    // or a new connection is not blocked by a stale entry.
    inner
        .tcp
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&key);
    inner.stats.tcp_closed.fetch_add(1, Ordering::Relaxed);
}

/// DNS over the tunnel's own TCP listener (`:53` hijack): read length-prefixed
/// queries, answer from the configured resolver, never dial.
async fn dns_tcp_flow(
    inner: Arc<Inner>,
    mut tcp: ServerTcp,
    mut rx: mpsc::Receiver<Vec<u8>>,
    dns: Arc<crate::dns::DnsService>,
    idle_limit: Duration,
) {
    let mut pending = Vec::new();
    let mut idle = Instant::now() + idle_limit;
    loop {
        flush(&inner, &mut tcp);
        if tcp.finished() || tcp.failure().is_some() {
            break;
        }
        if tcp.write_side_closed() {
            // Queries already answered; nothing else arrives.
            break;
        }
        while let Some(data) = tcp.take_received() {
            pending.extend_from_slice(&data);
        }
        // Each query is a 2-byte length prefix plus a DNS message.
        while pending.len() >= 2 {
            let length = usize::from(u16::from_be_bytes([pending[0], pending[1]]));
            if length == 0 || pending.len() < 2 + length {
                break;
            }
            let query = pending[2..2 + length].to_vec();
            pending.drain(..2 + length);
            inner.stats.dns_queries.fetch_add(1, Ordering::Relaxed);
            let answer = dns.answer_query(&query).await;
            if answer.is_empty() {
                inner.stats.dns_failures.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let mut framed = Vec::with_capacity(2 + answer.len());
            framed.extend_from_slice(&(answer.len() as u16).to_be_bytes());
            framed.extend_from_slice(&answer);
            if tcp.enqueue(&framed) < framed.len() {
                inner.stats.dns_failures.fetch_add(1, Ordering::Relaxed);
                break;
            }
            flush(&inner, &mut tcp);
        }
        let timer = tcp
            .next_timer()
            .map(tokio::time::Instant::from_std)
            .unwrap_or_else(|| tokio::time::Instant::now() + idle_limit);
        tokio::select! {
            biased;
            packet = rx.recv() => match packet {
                Some(packet) => {
                    idle = Instant::now() + idle_limit;
                    tcp.on_packet(&packet, Instant::now());
                }
                None => {
                    tcp.reset();
                    flush(&inner, &mut tcp);
                    break;
                }
            },
            _ = tokio::time::sleep_until(timer) => tcp.on_timer(Instant::now()),
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(idle)) => {
                tcp.reset();
                flush(&inner, &mut tcp);
                break;
            },
        }
    }
    inner.stats.tcp_closed.fetch_add(1, Ordering::Relaxed);
}

/// The UDP data plane: one task owns the DIRECT sockets, the associations and
/// the flow index, so replies map back to device flows without locks.
async fn udp_task(
    inner: Arc<Inner>,
    mut rx: mpsc::Receiver<UdpCommand>,
    mut replies: mpsc::Receiver<UdpReply>,
    reply_tx: mpsc::Sender<UdpReply>,
) {
    let Some(mut session) = inner.session() else {
        return;
    };
    // The flow index is shared with `Tunnel::stats`, so the high-water values
    // a host samples are the ones this task keeps.
    let flows: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), tokio::time::Instant>>> =
        inner.udp_flows.clone();
    let mut direct4: Option<Arc<tokio::net::UdpSocket>> = None;
    let mut direct6: Option<Arc<tokio::net::UdpSocket>> = None;
    let mut associations: HashMap<String, mpsc::Sender<AssocCommand>> = HashMap::new();
    loop {
        let next_expiry = {
            let guard = flows
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.values().copied().min()
        };
        let timer = match next_expiry {
            Some(at) => at,
            None => tokio::time::Instant::now() + Duration::from_secs(3600),
        };
        tokio::select! {
            biased;
            command = rx.recv() => match command {
                Some(UdpCommand::Datagram(datagram)) => {
                    handle_datagram(
                        &inner,
                        &session,
                        datagram,
                        &flows,
                        &mut direct4,
                        &mut direct6,
                        &mut associations,
                        &reply_tx,
                    ).await;
                }
                Some(UdpCommand::Reload) => {
                    // Release the previous generation's transports and flows.
                    associations.clear();
                    flows.lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clear();
                    direct4 = None;
                    direct6 = None;
                    if let Some(refreshed) = inner.session() {
                        session = refreshed;
                    }
                }
                None => return,
            },
            reply = replies.recv() => match reply {
                Some(reply) => {
                    emit_udp_reply(&inner, &flows, &reply);
                }
                None => return,
            },
            _ = tokio::time::sleep_until(timer) => {
                let now = tokio::time::Instant::now();
                flows
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .retain(|_, deadline| *deadline > now);
            },
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_datagram(
    inner: &Arc<Inner>,
    session: &SessionContext,
    datagram: UdpIn,
    flows: &Arc<Mutex<HashMap<(SocketAddr, SocketAddr), tokio::time::Instant>>>,
    direct4: &mut Option<Arc<tokio::net::UdpSocket>>,
    direct6: &mut Option<Arc<tokio::net::UdpSocket>>,
    associations: &mut HashMap<String, mpsc::Sender<AssocCommand>>,
    reply_tx: &mpsc::Sender<UdpReply>,
) {
    let key = (datagram.src, datagram.dst);
    let deadline = tokio::time::Instant::now() + inner.udp_idle();
    {
        let mut guard = flows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !guard.contains_key(&key) && guard.len() >= inner.options.max_udp_flows {
            drop(guard);
            inner.stats.dropped_inbound.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(dst = %datagram.dst, "UDP flow limit reached");
            return;
        }
        guard.insert(key, deadline);
        let len = guard.len();
        inner.stats.udp_flow_high.fetch_max(len, Ordering::Relaxed);
    }

    let target = match route::destination(
        session,
        datagram.dst.ip(),
        datagram.dst.port(),
        NetworkKind::Udp,
        datagram.src,
    )
    .await
    {
        Ok(target) => target,
        Err(reason) => {
            tracing::warn!(dst = %datagram.dst, reason, "tunnel UDP destination mapping failed");
            inner.stats.dropped_inbound.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let mut target = target;
    let (route, _decision) = match route::decide(session, &mut target, true).await {
        Ok(pair) => pair,
        Err(failure) => {
            tracing::info!(dst = %datagram.dst, reason = %failure.reason, "tunnel UDP refused");
            inner.stats.dropped_inbound.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    match route {
        route::Route::Direct => {
            let ipv4 = datagram.dst.is_ipv4();
            let slot = if ipv4 { direct4 } else { direct6 };
            if slot.is_none() {
                let bind = if ipv4 { "0.0.0.0:0" } else { "[::]:0" };
                match tokio::net::UdpSocket::bind(bind).await {
                    Ok(socket) => {
                        let socket = Arc::new(socket);
                        tokio::spawn(direct_reader(socket.clone(), reply_tx.clone()));
                        *slot = Some(socket);
                    }
                    Err(error) => {
                        tracing::warn!(%error, "UDP DIRECT bind failed");
                        inner.stats.dropped_inbound.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                }
            }
            let socket = slot.as_ref().expect("bound above");
            if let Err(error) = socket.send_to(&datagram.payload, datagram.dst).await {
                tracing::debug!(dst = %datagram.dst, %error, "UDP DIRECT send failed");
                inner.stats.dropped_inbound.fetch_add(1, Ordering::Relaxed);
            }
        }
        route::Route::Proxy { proxy, .. } => {
            let name = proxy.name.clone();
            let sender = match associations.get(&name) {
                Some(sender) => sender.clone(),
                None => {
                    if associations.len() >= MAX_ASSOCIATIONS {
                        inner
                            .stats
                            .unsupported_protocols
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(proxy = %name, "UDP association limit reached");
                        return;
                    }
                    let (sender, receiver) = mpsc::channel::<AssocCommand>(32);
                    let task_inner = inner.clone();
                    let task_name = name.clone();
                    tokio::spawn(udp::association_task(
                        task_inner,
                        task_name,
                        proxy.clone(),
                        receiver,
                        reply_tx.clone(),
                    ));
                    associations.insert(name.clone(), sender.clone());
                    sender
                }
            };
            let outgoing = crate::outbound::Target {
                host: if target.host.is_empty() {
                    target
                        .ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| datagram.dst.ip().to_string())
                } else {
                    target.host.clone()
                },
                port: datagram.dst.port(),
            };
            if sender
                .try_send(AssocCommand::Send {
                    target: outgoing,
                    payload: datagram.payload,
                })
                .is_err()
            {
                inner.stats.dropped_inbound.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn emit_udp_reply(
    inner: &Inner,
    flows: &Arc<Mutex<HashMap<(SocketAddr, SocketAddr), tokio::time::Instant>>>,
    reply: &UdpReply,
) {
    let mut matched = false;
    let guard = flows
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for (src, dst) in guard.keys() {
        if *dst != reply.from {
            continue;
        }
        matched = true;
        match ipstack::build_udp_packet(
            reply.from.ip(),
            src.ip(),
            reply.from.port(),
            src.port(),
            &reply.payload,
            HOP_LIMIT,
        ) {
            Ok(packet) => inner.emit(packet),
            Err(error) => {
                tracing::debug!(error = %error, "UDP reply could not be built");
            }
        }
    }
    drop(guard);
    if matched {
        inner.stats.udp_replies.fetch_add(1, Ordering::Relaxed);
    } else {
        tracing::debug!(from = %reply.from, "UDP reply without a matching device flow dropped");
    }
}

#[cfg(test)]
mod tests;
