//! Shared userspace L3 stack: `smoltcp` over a bounded IP-packet device.
//!
//! One [`Stack`] belongs to one proxy configuration (the registry key is a
//! fingerprint of that configuration). A carrier module (WireGuard, OpenVPN or
//! a test) feeds received IP packets with [`Stack::push_rx_packet`] and drains
//! [`Stack::take_tx_packet`]; the stack itself terminates TCP and UDP.
//!
//! Every operation is bounded and every refusal is named:
//!
//! * at most [`TCP_SOCKETS`] TCP sockets, each with [`TCP_BUFFER_BYTES`] per
//!   direction;
//! * at most [`UDP_SOCKETS`] UDP sockets, each with [`UDP_QUEUE_PACKETS`]
//!   packets of [`UDP_PACKET_BYTES`];
//! * the carrier queues in [`super::device`] are bounded too;
//! * a stack that stays unused for [`IDLE_RECLAIM`] and owns no socket stops
//!   its poller and is removed from the registry (the registry only holds
//!   `Weak` references, so the last stream drop frees it as well).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::socket::udp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use super::device::MemDevice;
use crate::outbound::BoxStream;

/// TCP sockets one stack may own.
pub const TCP_SOCKETS: usize = 16;
/// UDP sockets one stack may own.
pub const UDP_SOCKETS: usize = 32;
/// Bytes buffered per TCP direction.
pub const TCP_BUFFER_BYTES: usize = 32 * 1024;
/// Datagrams one UDP socket may queue in each direction.
pub const UDP_QUEUE_PACKETS: usize = 32;
/// Payload capacity of one queued UDP datagram.
pub const UDP_PACKET_BYTES: usize = 2048;
/// A stack with no socket and no traffic for this long is reclaimed.
pub const IDLE_RECLAIM: Duration = Duration::from_secs(60);
/// Poll cadence of the stack actor. The carriers wake it on ingress with
/// [`Stack::push_rx_packet`]; this is the fallback for timers and egress.
const POLL_INTERVAL: Duration = Duration::from_millis(2);
/// How long a closed TCP socket may stay in the set for FIN/RST delivery.
const ZOMBIE_LIFETIME: Duration = Duration::from_secs(5);

/// Named refusals of stack construction and socket creation.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum StackError {
    #[error("no local IPv4 or IPv6 address for the userspace IP stack (set 'ip' and/or 'ipv6', or the tunnel-provided ifconfig)")]
    NoLocalAddress,
    #[error("no route to remote address {0}")]
    NoRoute(IpAddr),
    #[error("the userspace IP stack has no local {0} address")]
    NoFamily(&'static str),
    #[error("the userspace IP stack already owns the maximum of {0} sockets")]
    TooManySockets(usize),
    #[error("the userspace IP stack datagram queue is full")]
    QueueFull,
    #[error("the userspace IP stack failed: {0}")]
    Failed(String),
}

impl StackError {
    pub fn to_io(&self) -> io::Error {
        match self {
            StackError::TooManySockets(_) | StackError::QueueFull => {
                io::Error::new(io::ErrorKind::OutOfMemory, self.to_string())
            }
            StackError::NoLocalAddress
            | StackError::NoRoute(_)
            | StackError::NoFamily(_) => {
                io::Error::new(io::ErrorKind::Unsupported, self.to_string())
            }
            StackError::Failed(_) => io::Error::other(self.to_string()),
        }
    }
}

/// Everything one stack needs to build its interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackConfig {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub mtu: usize,
    /// Registry key: equal fingerprints share one stack.
    pub fingerprint: String,
}

impl StackConfig {
    pub fn new(
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
        mtu: usize,
        fingerprint: impl Into<String>,
    ) -> StackConfig {
        StackConfig {
            ipv4,
            ipv6,
            mtu: mtu.clamp(68, 65535),
            fingerprint: fingerprint.into(),
        }
    }
}

struct Core {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: MemDevice,
    /// Local port -> socket handle for live TCP connections.
    tcp: HashMap<u16, SocketHandle>,
    /// Local port -> socket handle for UDP associations.
    udp: HashMap<u16, SocketHandle>,
    /// Handles whose owner dropped them; kept until FIN/RST is delivered.
    zombies: Vec<(SocketHandle, u16, Instant)>,
    wakers: Vec<Waker>,
    fatal: Option<String>,
    next_port: u16,
}

/// One shared userspace stack.
pub struct Stack {
    core: Mutex<Core>,
    config: StackConfig,
    /// Wakes `dial_tcp`/`udp recv` waiters after every poll.
    change: Notify,
    /// Wakes the stack poller when a carrier queues a received packet.
    ingress: Notify,
    poller_running: AtomicBool,
    last_used: AtomicU64,
}

impl std::fmt::Debug for Stack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stack")
            .field("ipv4", &self.config.ipv4)
            .field("ipv6", &self.config.ipv6)
            .field("mtu", &self.config.mtu)
            .finish_non_exhaustive()
    }
}

fn monotonic_millis() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

fn smoltcp_now() -> SmolInstant {
    SmolInstant::from_millis(monotonic_millis() as i64)
}

fn make_endpoint(addr: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(IpAddress::from(addr.ip()), addr.port())
}

fn from_smoltcp(endpoint: IpEndpoint) -> SocketAddr {
    let ip: IpAddr = endpoint.addr.into();
    SocketAddr::new(ip, endpoint.port)
}

impl Stack {
    /// Build the interface and start its poller. At least one local address is
    /// required: without it smoltcp cannot pick a source address.
    pub fn new(config: StackConfig) -> Result<Arc<Stack>, StackError> {
        if config.ipv4.is_none() && config.ipv6.is_none() {
            return Err(StackError::NoLocalAddress);
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(StackError::Failed(
                "the stack poller needs a tokio runtime".to_string(),
            ));
        }
        for addr in [config.ipv4.map(IpAddr::V4), config.ipv6.map(IpAddr::V6)]
            .into_iter()
            .flatten()
        {
            if addr.is_unspecified() {
                return Err(StackError::NoLocalAddress);
            }
        }
        let mut device = MemDevice::new(config.mtu);
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(0x9e37_79b9_7f4a_7c15)
            ^ (std::process::id() as u64) << 32;
        let mut iface_config = Config::new(HardwareAddress::Ip);
        iface_config.random_seed = seed;
        let mut iface = Interface::new(iface_config, &mut device, smoltcp_now());
        let ipv4 = config.ipv4;
        let ipv6 = config.ipv6;
        iface.update_ip_addrs(|addrs| {
            if let Some(addr) = ipv4 {
                // A host prefix forces the default route to carry every
                // destination; the tunnel does not need on-link subnets.
                let _ = addrs.push(IpCidr::new(IpAddress::from(addr), 32));
            }
            if let Some(addr) = ipv6 {
                let _ = addrs.push(IpCidr::new(IpAddress::from(addr), 128));
            }
        });
        if let Some(addr) = ipv4 {
            // Medium::Ip has no neighbour discovery; the gateway only has to
            // exist so the route lookup succeeds. The interface's own address
            // is the documented choice for that.
            iface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::from(addr))
                .map_err(|_| StackError::NoRoute(IpAddr::V4(addr)))?;
        }
        if let Some(addr) = ipv6 {
            iface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Address::from(addr))
                .map_err(|_| StackError::NoRoute(IpAddr::V6(addr)))?;
        }
        let start_port = 49152 + (seed % 16384) as u16;
        let stack = Arc::new(Stack {
            core: Mutex::new(Core {
                iface,
                sockets: SocketSet::new(Vec::new()),
                device,
                tcp: HashMap::new(),
                udp: HashMap::new(),
                zombies: Vec::new(),
                wakers: Vec::new(),
                fatal: None,
                next_port: start_port,
            }),
            config,
            change: Notify::new(),
            ingress: Notify::new(),
            poller_running: AtomicBool::new(false),
            last_used: AtomicU64::new(monotonic_millis()),
        });
        stack.ensure_poller();
        Ok(stack)
    }

    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.config.ipv4
    }

    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        self.config.ipv6
    }

    pub fn mtu(&self) -> usize {
        self.config.mtu
    }

    pub fn fingerprint(&self) -> &str {
        &self.config.fingerprint
    }

    fn touch(&self) {
        self.last_used
            .store(monotonic_millis(), Ordering::Relaxed);
    }

    fn idle(&self) -> bool {
        monotonic_millis().saturating_sub(self.last_used.load(Ordering::Relaxed))
            >= IDLE_RECLAIM.as_millis() as u64
    }

    /// Live TCP and UDP socket counts (zombies still count: their port is
    /// reserved until FIN/RST delivery finishes).
    pub fn socket_counts(&self) -> (usize, usize) {
        let core = self.lock();
        (core.tcp.len(), core.udp.len())
    }

    /// Number of packets waiting for the carrier.
    pub fn pending_tx(&self) -> usize {
        self.lock().device.tx_len()
    }

    /// Local port of one live TCP socket, for diagnostics/tests.
    pub fn tcp_local_ports(&self) -> Vec<u16> {
        self.lock().tcp.keys().copied().collect()
    }

    /// A named fatal error from the carrier (authentication failure, peer
    /// unreachable after handshake). Streams report it instead of stalling.
    pub fn fail(&self, message: impl Into<String>) {
        let mut core = self.lock();
        if core.fatal.is_none() {
            core.fatal = Some(message.into());
        }
        for waker in std::mem::take(&mut core.wakers) {
            waker.wake();
        }
        drop(core);
        self.change.notify_waiters();
        self.touch();
    }

    pub fn fatal_error(&self) -> Option<String> {
        self.lock().fatal.clone()
    }

    /// Queue one IP packet received by the carrier.
    pub fn push_rx_packet(&self, packet: &[u8]) -> bool {
        let accepted = {
            let mut core = self.lock();
            let accepted = core.device.push_rx(packet);
            accepted
        };
        if accepted {
            self.touch();
            self.ingress.notify_one();
        }
        accepted
    }

    /// Next IP packet smoltcp wants the carrier to send.
    pub fn take_tx_packet(&self) -> Option<Vec<u8>> {
        self.lock().device.pop_tx()
    }

    pub fn has_tx_packets(&self) -> bool {
        self.lock().device.has_tx()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Core> {
        self.core
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn ensure_poller(self: &Arc<Stack>) {
        if self.poller_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(POLL_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let Some(stack) = weak.upgrade() else {
                    return;
                };
                stack.poll_once();
                if stack.idle() && stack.socket_counts() == (0, 0) && !stack.has_tx_packets() {
                    // Let the registry (Weak only) and every stream drop the
                    // stack; a later dial starts a fresh one.
                    stack.poller_running.store(false, Ordering::SeqCst);
                    return;
                }
            }
        });
    }

    fn poll_once(&self) {
        let mut core = self.lock();
        if core.fatal.is_some() {
            let wakers = std::mem::take(&mut core.wakers);
            drop(core);
            for waker in wakers {
                waker.wake();
            }
            self.change.notify_waiters();
            return;
        }
        let now = smoltcp_now();
        let this = &mut *core;
        let mut changed = this.iface.poll(now, &mut this.device, &mut this.sockets);
        // Retire dropped sockets once their FIN/RST is no longer owed.
        let mut index = 0;
        while index < core.zombies.len() {
            let (handle, _port, since) = core.zombies[index];
            let state = core.sockets.get::<tcp::Socket>(handle).state();
            let finished = matches!(state, tcp::State::Closed | tcp::State::TimeWait)
                || since.elapsed() >= ZOMBIE_LIFETIME;
            if finished {
                let (_, port, _) = core.zombies.swap_remove(index);
                core.sockets.get_mut::<tcp::Socket>(handle).abort();
                core.sockets.remove(handle);
                core.tcp.remove(&port);
                changed = true;
            } else {
                index += 1;
            }
        }
        let wakers = std::mem::take(&mut core.wakers);
        drop(core);
        // Readiness can change without `poll` returning true (a reader waiting
        // for data that arrived without a state transition), so every tick
        // wakes the registered waiters. The set is only populated by socket
        // poll methods that returned Pending.
        let _ = changed;
        for waker in wakers {
            waker.wake();
        }
        self.change.notify_waiters();
    }

    fn allocate_port(core: &mut Core) -> Option<u16> {
        for _ in 0..=u16::MAX {
            let port = core.next_port;
            core.next_port = if port >= 65534 { 49152 } else { port + 1 };
            if port >= 49152 && !core.tcp.contains_key(&port) && !core.udp.contains_key(&port) {
                return Some(port);
            }
        }
        None
    }

    fn family_supported(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(_) => self.config.ipv4.is_some(),
            IpAddr::V6(_) => self.config.ipv6.is_some(),
        }
    }

    /// Dial one TCP connection through the tunnel. The returned stream
    /// implements half-close: `poll_shutdown` sends a FIN, and a remote FIN is
    /// reported as EOF.
    pub async fn dial_tcp(
        self: &Arc<Stack>,
        remote: SocketAddr,
        timeout: Duration,
    ) -> io::Result<BoxStream> {
        if !self.family_supported(remote.ip()) {
            return Err(StackError::NoFamily(if remote.is_ipv4() { "IPv4" } else { "IPv6" })
                .to_io());
        }
        let (handle, local_port) = self.create_tcp(remote)?;
        let stream = L3TcpStream {
            stack: self.clone(),
            handle,
            local_port,
            active: true,
        };
        match tokio::time::timeout(timeout, self.wait_established(handle, local_port)).await {
            Ok(Ok(())) => {
                self.touch();
                Ok(Box::new(stream))
            }
            Ok(Err(error)) => {
                stream.release();
                Err(error)
            }
            Err(_) => {
                stream.release();
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("userspace TCP connect to {remote} timed out after {timeout:?}"),
                ))
            }
        }
    }

    fn create_tcp(&self, remote: SocketAddr) -> io::Result<(SocketHandle, u16)> {
        let mut core = self.lock();
        if core.tcp.len() >= TCP_SOCKETS {
            return Err(StackError::TooManySockets(TCP_SOCKETS).to_io());
        }
        let local_port = Self::allocate_port(&mut core)
            .ok_or_else(|| StackError::TooManySockets(u16::MAX as usize).to_io())?;
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_BYTES]),
            tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_BYTES]),
        );
        socket.set_nagle_enabled(false);
        let handle = core.sockets.add(socket);
        let endpoint = IpListenEndpoint {
            addr: None,
            port: local_port,
        };
        let result = {
            let this = &mut *core;
            let context = this.iface.context();
            let socket = this.sockets.get_mut::<tcp::Socket>(handle);
            socket.connect(context, make_endpoint(remote), endpoint)
        };
        if let Err(error) = result {
            core.sockets.remove(handle);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("userspace TCP connect to {remote}: {error}"),
            ));
        }
        core.tcp.insert(local_port, handle);
        self.touch();
        self.ingress.notify_one();
        Ok((handle, local_port))
    }

    async fn wait_established(&self, _handle: SocketHandle, port: u16) -> io::Result<()> {
        loop {
            let notified = self.change.notified();
            {
                let mut core = self.lock();
                if let Some(fatal) = &core.fatal {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        fatal.clone(),
                    ));
                }
                let Some(socket) = core.tcp.get(&port).copied() else {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "userspace TCP socket disappeared during connect",
                    ));
                };
                let socket = core.sockets.get_mut::<tcp::Socket>(socket);
                match socket.state() {
                    tcp::State::Established | tcp::State::CloseWait | tcp::State::FinWait1
                    | tcp::State::FinWait2 => return Ok(()),
                    tcp::State::Closed | tcp::State::TimeWait => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "userspace TCP connection was refused or reset",
                        ));
                    }
                    _ => {
                        // `notified()` was registered before this check, so a
                        // wake cannot be lost; no per-socket waker is needed.
                    }
                }
            }
            notified.await;
        }
    }

    fn release_tcp(&self, handle: SocketHandle, port: u16) {
        let mut core = self.lock();
        core.sockets.get_mut::<tcp::Socket>(handle).abort();
        core.sockets.remove(handle);
        core.tcp.remove(&port);
        core.zombies.retain(|(known, _, _)| *known != handle);
    }

    /// Open a UDP association bound to one ephemeral local port. The socket is
    /// unconnected: one association carries every destination of its flow.
    pub fn udp_socket(self: &Arc<Stack>) -> io::Result<L3UdpSocket> {
        let mut core = self.lock();
        if core.udp.len() >= UDP_SOCKETS {
            return Err(StackError::TooManySockets(UDP_SOCKETS).to_io());
        }
        let local_port = Self::allocate_port(&mut core)
            .ok_or_else(|| StackError::TooManySockets(u16::MAX as usize).to_io())?;
        let packet_bytes = UDP_PACKET_BYTES.max(self.config.mtu + 16);
        let rx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_QUEUE_PACKETS],
            vec![0u8; packet_bytes * UDP_QUEUE_PACKETS],
        );
        let tx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_QUEUE_PACKETS],
            vec![0u8; packet_bytes * UDP_QUEUE_PACKETS],
        );
        let mut socket = udp::Socket::new(rx, tx);
        socket
            .bind(local_port)
            .map_err(|error| io::Error::new(io::ErrorKind::AddrInUse, error.to_string()))?;
        let handle = core.sockets.add(socket);
        core.udp.insert(local_port, handle);
        self.touch();
        self.ingress.notify_one();
        Ok(L3UdpSocket {
            stack: self.clone(),
            handle,
            local_port,
        })
    }

    fn release_udp(&self, handle: SocketHandle, port: u16) {
        let mut core = self.lock();
        core.sockets.remove(handle);
        core.udp.remove(&port);
    }
}

// ---------------------------------------------------------------------------
// TCP stream
// ---------------------------------------------------------------------------

/// One TCP connection terminated by the shared stack.
pub struct L3TcpStream {
    stack: Arc<Stack>,
    handle: SocketHandle,
    local_port: u16,
    active: bool,
}

impl std::fmt::Debug for L3TcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("L3TcpStream")
            .field("local_port", &self.local_port)
            .finish_non_exhaustive()
    }
}

impl L3TcpStream {
    fn release(&self) {
        if self.active {
            self.stack.release_tcp(self.handle, self.local_port);
        }
    }

    fn fatal(core: &Core) -> Option<io::Error> {
        core.fatal.as_ref().map(|message| {
            io::Error::new(io::ErrorKind::ConnectionAborted, message.clone())
        })
    }
}

impl Drop for L3TcpStream {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut core = self.stack.lock();
        // A dropped stream half-closes like a socket close; the poller keeps
        // the socket until FIN (or RST) is delivered, then frees the port.
        if let Some(handle) = core.tcp.get(&self.local_port).copied() {
            let socket = core.sockets.get_mut::<tcp::Socket>(handle);
            if socket.is_open() {
                socket.close();
            }
            core.zombies
                .push((handle, self.local_port, Instant::now()));
        }
        self.active = false;
    }
}

impl AsyncRead for L3TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut core = this.stack.lock();
        if let Some(error) = Self::fatal(&core) {
            return Poll::Ready(Err(error));
        }
        let Some(handle) = core.tcp.get(&this.local_port).copied() else {
            return Poll::Ready(Ok(()));
        };
        let socket = core.sockets.get_mut::<tcp::Socket>(handle);
        match socket.recv_slice(buf.initialize_unfilled()) {
            Ok(0) => {
                core.wakers.push(cx.waker().clone());
                Poll::Pending
            }
            Ok(read) => {
                buf.advance(read);
                Poll::Ready(Ok(()))
            }
            Err(tcp::RecvError::Finished) => Poll::Ready(Ok(())),
            Err(tcp::RecvError::InvalidState) => {
                if matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "userspace TCP connection was reset",
                    )))
                } else {
                    core.wakers.push(cx.waker().clone());
                    Poll::Pending
                }
            }
        }
    }
}

impl AsyncWrite for L3TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        let mut core = this.stack.lock();
        if let Some(error) = Self::fatal(&core) {
            return Poll::Ready(Err(error));
        }
        let Some(handle) = core.tcp.get(&this.local_port).copied() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "userspace TCP socket is closed",
            )));
        };
        let socket = core.sockets.get_mut::<tcp::Socket>(handle);
        if !socket.may_send() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "userspace TCP connection is not writable (FIN or RST already sent)",
            )));
        }
        match socket.send_slice(buf) {
            Ok(0) => {
                core.wakers.push(cx.waker().clone());
                Poll::Pending
            }
            Ok(written) => Poll::Ready(Ok(written)),
            Err(tcp::SendError::InvalidState) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "userspace TCP connection closed while writing",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // smoltcp owns the transmit queue; the poller drains it.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut core = this.stack.lock();
        if let Some(handle) = core.tcp.get(&this.local_port).copied() {
            let socket = core.sockets.get_mut::<tcp::Socket>(handle);
            if socket.may_send() {
                socket.close();
            }
        }
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// UDP association
// ---------------------------------------------------------------------------

/// One UDP association of the shared stack. Unconnected by design: a SOCKS5
/// association sends to many destinations over the same local port.
pub struct L3UdpSocket {
    stack: Arc<Stack>,
    handle: SocketHandle,
    local_port: u16,
}

impl std::fmt::Debug for L3UdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("L3UdpSocket")
            .field("local_port", &self.local_port)
            .finish_non_exhaustive()
    }
}

impl L3UdpSocket {
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Queue one datagram toward `remote`.
    pub async fn send(&self, remote: SocketAddr, payload: &[u8]) -> io::Result<()> {
        if !self.stack.family_supported(remote.ip()) {
            return Err(StackError::NoFamily(if remote.is_ipv4() { "IPv4" } else { "IPv6" })
                .to_io());
        }
        let overhead = if remote.is_ipv4() { 28 } else { 48 };
        if payload.len() + overhead > self.stack.mtu() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "UDP datagram of {} bytes does not fit the tunnel MTU {}",
                    payload.len(),
                    self.stack.mtu()
                ),
            ));
        }
        let result = {
            let mut core = self.stack.lock();
            if let Some(fatal) = &core.fatal {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    fatal.clone(),
                ));
            }
            match core.sockets.get_mut::<udp::Socket>(self.handle).send_slice(
                payload,
                IpEndpoint::new(IpAddress::from(remote.ip()), remote.port()),
            ) {
                Ok(()) => Ok(()),
                Err(udp::SendError::BufferFull) => Err(StackError::QueueFull.to_io()),
                Err(error) => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    error.to_string(),
                )),
            }
        };
        if result.is_ok() {
            self.stack.touch();
            self.stack.ingress.notify_one();
        }
        result
    }

    /// Receive one datagram and the remote it came from. Waits on the stack's
    /// change notification; the poller guarantees progress every tick.
    pub async fn recv(&self, buffer: &mut [u8]) -> io::Result<(SocketAddr, usize)> {
        loop {
            let notified = self.stack.change.notified();
            {
                let mut core = self.stack.lock();
                if let Some(fatal) = &core.fatal {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        fatal.clone(),
                    ));
                }
                let socket = core.sockets.get_mut::<udp::Socket>(self.handle);
                match socket.recv_slice(buffer) {
                    Ok((read, metadata)) => {
                        self.stack.touch();
                        return Ok((from_smoltcp(metadata.endpoint), read));
                    }
                    Err(udp::RecvError::Exhausted) => {}
                    Err(udp::RecvError::Truncated) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "UDP datagram was truncated by the receive buffer",
                        ));
                    }
                }
            }
            notified.await;
        }
    }
}

impl Drop for L3UdpSocket {
    fn drop(&mut self) {
        self.stack.release_udp(self.handle, self.local_port);
    }
}

/// Placeholder removed; the stack change notification wakes every waiter.

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

fn registry() -> &'static Mutex<HashMap<String, Weak<Stack>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Weak<Stack>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Serialises "look up or create" so two concurrent dials of the same proxy
/// do not build two stacks (one carrier would be orphaned).
pub fn registry_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// The live stack for `fingerprint`, if one is still alive and not idle with
/// no sockets.
pub fn lookup(fingerprint: &str) -> Option<Arc<Stack>> {
    let mut map = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let stack = map.get(fingerprint)?.upgrade()?;
    if stack.idle() && stack.socket_counts() == (0, 0) {
        map.remove(fingerprint);
        return None;
    }
    Some(stack)
}

/// Publish a new stack. Dead entries are pruned first.
pub fn publish(fingerprint: impl Into<String>, stack: &Arc<Stack>) {
    let mut map = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    map.retain(|_, weak| weak.strong_count() > 0);
    map.insert(fingerprint.into(), Arc::downgrade(stack));
}

/// Remove one entry (the caller found it unusable).
pub fn forget(fingerprint: &str) {
    let mut map = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    map.remove(fingerprint);
}

/// Stable registry key for a set of configuration fields. The input may hold
/// secret material; the digest never prints it.
pub fn fingerprint(prefix: &str, parts: &[&str]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    for part in parts {
        hasher.update(b"\0");
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(prefix.len() + 1 + digest.len() * 2);
    out.push_str(prefix);
    out.push(':');
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_config_rejects_a_stack_without_addresses() {
        let config = StackConfig::new(None, None, 1408, "test");
        assert_eq!(Stack::new(config).unwrap_err(), StackError::NoLocalAddress);
    }

    #[tokio::test]
    async fn registry_shares_one_stack_per_fingerprint_and_drops_it() {
        let config = StackConfig::new(
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            None,
            1408,
            "registry-test",
        );
        let stack = Stack::new(config).expect("stack");
        publish("registry-test", &stack);
        let same = lookup("registry-test").expect("same stack");
        assert!(Arc::ptr_eq(&stack, &same));
        drop(same);
        drop(stack);
        // The entry is Weak: it cannot keep the stack alive.
        assert!(lookup("registry-test").is_none());
    }

    #[test]
    fn fingerprint_changes_with_secret_material_and_never_prints_it() {
        let first = fingerprint("wg", &["private-a", "10.0.0.2"]);
        let second = fingerprint("wg", &["private-b", "10.0.0.2"]);
        assert_ne!(first, second);
        assert!(!first.contains("private-a"));
        assert_eq!(first, fingerprint("wg", &["private-a", "10.0.0.2"]));
    }
}
