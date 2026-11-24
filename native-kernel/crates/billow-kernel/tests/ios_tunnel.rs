//! End-to-end tests of the iOS packet data plane (`feature = "ios-vpn"`).
//!
//! A `Tunnel` is started with the same engine configuration the extension
//! uses, a local peer plays the device (it builds IP packets and reads the
//! packets the kernel emits) and the assertions cover the two directions the
//! extension must bridge: TCP (handshake, data, half-close) and UDP, all
//! through the rule/outbound path. DNS hijack is exercised against a local
//! upstream server.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use billow_kernel::outbound::ipstack;
use billow_kernel::outbound::tcp::{
    parse_segment, TcpSegment, FLAG_ACK, FLAG_FIN, FLAG_PSH, FLAG_SYN,
};
use billow_kernel::tunnel::{Ingest, PacketSink, Tunnel, TunnelOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// Device address used by every test client.
const DEVICE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2));

/// One TCP segment inside an IPv4 packet, as the device would emit it (the
/// crate's own builder is `pub(crate)`, so the test carries the 20-byte header
/// construction and lets `ipstack::transport_checksum` fill the checksum).
#[allow(clippy::too_many_arguments)]
fn tcp_packet(
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut segment = Vec::with_capacity(20 + payload.len());
    segment.extend_from_slice(&src_port.to_be_bytes());
    segment.extend_from_slice(&dst_port.to_be_bytes());
    segment.extend_from_slice(&seq.to_be_bytes());
    segment.extend_from_slice(&ack.to_be_bytes());
    segment.push(5 << 4);
    segment.push(flags);
    segment.extend_from_slice(&65_535u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);
    let checksum = ipstack::transport_checksum(src, dst, ipstack::IPPROTO_TCP, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    ipstack::build_packet(src, dst, ipstack::IPPROTO_TCP, &segment, 64).expect("packet")
}

struct Collector {
    packets: Mutex<Vec<Vec<u8>>>,
    notify: tokio::sync::Notify,
}

impl Collector {
    fn new() -> Arc<Collector> {
        Arc::new(Collector {
            packets: Mutex::new(Vec::new()),
            notify: tokio::sync::Notify::new(),
        })
    }

    fn take(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.packets.lock().unwrap())
    }

    async fn wait_for(&self, mut predicate: impl FnMut(&[Vec<u8>]) -> bool) -> Vec<Vec<u8>> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            {
                let packets = self.packets.lock().unwrap();
                if predicate(&packets) {
                    drop(packets);
                    return self.take();
                }
            }
            if Instant::now() > deadline {
                let packets = self.take();
                panic!(
                    "timed out waiting for a packet; got {} packets",
                    packets.len()
                );
            }
            let _ = tokio::time::timeout(Duration::from_millis(50), self.notify.notified()).await;
        }
    }
}

impl PacketSink for Collector {
    fn emit(&self, packet: &[u8]) -> bool {
        self.packets.lock().unwrap().push(packet.to_vec());
        self.notify.notify_waiters();
        true
    }
}

/// A tiny UDP DNS server that answers every A query with 127.0.0.1. The TUN
/// association task is spawned, so this proves the task-local
/// `proxy-server-nameserver` scope is re-entered inside the spawned task.
fn spawn_a_record_dns() -> (u16, Arc<std::sync::atomic::AtomicU64>) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("dns bind");
    socket.set_nonblocking(true).expect("nonblocking dns");
    let port = socket.local_addr().unwrap().port();
    let queries = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter = queries.clone();
    tokio::spawn(async move {
        let socket = UdpSocket::from_std(socket).expect("dns socket");
        let mut buffer = vec![0u8; 2048];
        loop {
            let Ok((read, peer)) = socket.recv_from(&mut buffer).await else {
                continue;
            };
            counter.fetch_add(1, Ordering::Relaxed);
            let query = &buffer[..read];
            if query.len() < 12 {
                continue;
            }
            let mut offset = 12usize;
            while offset < query.len() && query[offset] != 0 {
                offset += 1 + query[offset] as usize;
            }
            offset += 1;
            if offset + 4 > query.len() {
                continue;
            }
            let qtype = u16::from_be_bytes([query[offset], query[offset + 1]]);
            let question_end = offset + 4;
            let mut reply = Vec::new();
            reply.extend_from_slice(&query[..2]);
            reply.extend_from_slice(&[0x81, 0x80]);
            reply.extend_from_slice(&1u16.to_be_bytes());
            let answers = if qtype == 1 { 1u16 } else { 0 };
            reply.extend_from_slice(&answers.to_be_bytes());
            reply.extend_from_slice(&0u16.to_be_bytes());
            reply.extend_from_slice(&0u16.to_be_bytes());
            reply.extend_from_slice(&query[12..question_end]);
            if answers == 1 {
                reply.extend_from_slice(&[0xc0, 0x0c]);
                reply.extend_from_slice(&1u16.to_be_bytes());
                reply.extend_from_slice(&1u16.to_be_bytes());
                reply.extend_from_slice(&60u32.to_be_bytes());
                reply.extend_from_slice(&4u16.to_be_bytes());
                reply.extend_from_slice(&[127, 0, 0, 1]);
            }
            let _ = socket.send_to(&reply, peer).await;
        }
    });
    (port, queries)
}

struct Device {
    tunnel: Tunnel,
    sink: Arc<Collector>,
    next_port: AtomicU16,
}

impl Device {
    fn start(config: &str, options: TunnelOptions) -> Device {
        let sink = Collector::new();
        let tunnel = Tunnel::start(
            config,
            PathBuf::from("."),
            options,
            Some(sink.clone() as Arc<dyn PacketSink>),
        )
        .expect("tunnel starts");
        Device {
            tunnel,
            sink,
            next_port: AtomicU16::new(50_000),
        }
    }

    fn next_port(&self) -> u16 {
        self.next_port.fetch_add(1, Ordering::Relaxed)
    }

    fn send(&self, packet: &[u8]) {
        assert_eq!(self.tunnel.ingest(packet), Ingest::Accepted);
    }

    fn send_tcp(
        &self,
        src_port: u16,
        dst: SocketAddr,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) {
        self.send(&tcp_packet(
            DEVICE_IP,
            dst.ip(),
            src_port,
            dst.port(),
            seq,
            ack,
            flags,
            payload,
        ));
    }

    async fn tcp_packets(&self) -> Vec<Vec<u8>> {
        self.sink
            .wait_for(|packets| {
                packets.iter().any(|packet| {
                    ipstack::parse_ip_packet(packet).map(|p| p.protocol) == Ok(ipstack::IPPROTO_TCP)
                })
            })
            .await
    }

    /// Wait until a segment with `flags` for `device_port`/`target` arrives.
    async fn wait_tcp(&self, device_port: u16, target: SocketAddr, flags: u8) -> Vec<Vec<u8>> {
        self.sink
            .wait_for(|packets| packet_for(packets, device_port, target, flags).is_some())
            .await
    }
}

/// The engine always binds its mixed listener, so every test gets a free
/// loopback port for it.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

fn direct_config() -> String {
    format!("mixed-port: {}\nrules:\n  - MATCH,DIRECT\n", free_port())
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_stream_crosses_the_tunnel_in_both_directions() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 64];
        let read = socket.read(&mut buffer).await.unwrap();
        socket.write_all(&buffer[..read]).await.unwrap();
        // The device half-closes; the server answers with its own FIN.
        let _ = socket.shutdown().await;
        read
    });

    let device = Device::start(&direct_config(), TunnelOptions::default());
    let port = device.next_port();
    device.send_tcp(port, target, 1000, 0, FLAG_SYN, &[]);
    let packets = device.tcp_packets().await;
    let syn_ack = packet_for(&packets, port, target, FLAG_SYN | FLAG_ACK).expect("SYN-ACK");
    let our_iss = syn_ack.seq;
    // The SYN-ACK acknowledges the device's SYN (seq 1000).
    assert_eq!(syn_ack.ack, 1001);
    assert_eq!(syn_ack.dst, DEVICE_IP);
    assert_eq!(syn_ack.dst_port, port);
    let device_next = 1001u32;

    // Third ACK plus the first data segment (acknowledging the SYN-ACK).
    device.send_tcp(
        port,
        target,
        device_next,
        our_iss.wrapping_add(1),
        FLAG_ACK | FLAG_PSH,
        b"ping",
    );
    // The echo comes back as payload in a segment towards the device.
    let packets = device
        .sink
        .wait_for(|packets| {
            packets.iter().any(|packet| {
                parse_segment(packet)
                    .map(|segment| segment.payload == b"ping")
                    .unwrap_or(false)
            })
        })
        .await;
    let echo = packets
        .iter()
        .filter_map(|packet| parse_segment(packet).ok())
        .find(|segment| segment.payload == b"ping")
        .expect("echo");
    assert_eq!(echo.dst, DEVICE_IP);
    assert_eq!(echo.dst_port, port);
    assert_eq!(echo.src_port, target.port());
    // Acknowledge the echo so the kernel can release the segment.
    device.send_tcp(
        port,
        target,
        device_next.wrapping_add(4),
        echo.seq.wrapping_add(4),
        FLAG_ACK,
        &[],
    );

    // Device half-close: the kernel forwards the FIN upstream.
    device.send_tcp(
        port,
        target,
        device_next.wrapping_add(4),
        echo.seq.wrapping_add(4),
        FLAG_FIN | FLAG_ACK,
        &[],
    );
    let read = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server finishes")
        .unwrap();
    assert_eq!(read, 4);

    let stats = device.tunnel.stats();
    assert_eq!(stats.tcp_opened, 1, "{stats:?}");
    assert!(stats.out_packets >= 3, "{stats:?}");
    device.tunnel.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_datagrams_cross_the_tunnel_in_both_directions() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 128];
        let (read, from) = server.recv_from(&mut buffer).await.unwrap();
        server.send_to(&buffer[..read], from).await.unwrap();
    });

    let device = Device::start(&direct_config(), TunnelOptions::default());
    let port = device.next_port();
    let query = ipstack::build_udp_packet(DEVICE_IP, target.ip(), port, target.port(), b"pong", 64)
        .unwrap();
    device.send(&query);
    let packets = device
        .sink
        .wait_for(|packets| {
            packets.iter().any(|packet| {
                ipstack::parse_ip_packet(packet).map(|p| p.protocol) == Ok(ipstack::IPPROTO_UDP)
            })
        })
        .await;
    let reply = packets
        .iter()
        .find_map(|packet| ipstack::parse_ip_packet(packet).ok())
        .expect("UDP reply");
    assert_eq!(reply.protocol, ipstack::IPPROTO_UDP);
    assert_eq!(reply.src, target.ip());
    assert_eq!(reply.dst, DEVICE_IP);
    let udp = ipstack::parse_udp(&reply).expect("UDP datagram");
    assert_eq!(udp.payload, b"pong");
    assert_eq!(udp.dst_port, port);
    assert_eq!(udp.src_port, target.port());
    // The high-water interface a host samples counts the live flow.
    let stats = device.tunnel.stats();
    assert_eq!(stats.udp_flows, 1, "{stats:?}");
    assert_eq!(stats.udp_flow_high, 1, "{stats:?}");
    assert_eq!(stats.udp_replies, 1, "{stats:?}");
    device.tunnel.stop();
}

/// A minimal SOCKS5 server with a UDP relay: RFC 1928 method negotiation,
/// `UDP ASSOCIATE`, and one datagram round-trip per client packet. It proves
/// the TUN data plane really uses `Socks5Udp`, not a DIRECT fallback.
async fn socks5_udp_peer() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        loop {
            let Ok((read, from)) = relay.recv_from(&mut buffer).await else {
                return;
            };
            let Some(datagram) = billow_kernel::outbound::udp::parse_datagram(&buffer[..read])
            else {
                continue;
            };
            let payload = buffer[datagram.offset..read].to_vec();
            let Ok(ip) = datagram.target.host.parse::<IpAddr>() else {
                continue;
            };
            let target = SocketAddr::new(ip, datagram.target.port);
            let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let _ = peer.send_to(&payload, target).await;
            let mut reply = vec![0u8; 65_535];
            let Ok(Ok((n, source))) =
                tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut reply)).await
            else {
                continue;
            };
            let origin = billow_kernel::outbound::Target {
                host: source.ip().to_string(),
                port: source.port(),
            };
            let mut packet = vec![0u8, 0u8, 0u8];
            packet.extend_from_slice(&billow_kernel::outbound::udp::address_header(&origin));
            packet.extend_from_slice(&reply[..n]);
            let _ = relay.send_to(&packet, from).await;
        }
    });

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let relay_addr = relay_addr;
            tokio::spawn(async move {
                let mut greeting = [0u8; 2];
                if stream.read_exact(&mut greeting).await.is_err() {
                    return;
                }
                let mut methods = vec![0u8; greeting[1] as usize];
                if stream.read_exact(&mut methods).await.is_err() {
                    return;
                }
                if stream.write_all(&[0x05, 0x00]).await.is_err() {
                    return;
                }
                let mut request = [0u8; 4];
                if stream.read_exact(&mut request).await.is_err() {
                    return;
                }
                let skip = match request[3] {
                    0x01 => 4,
                    0x04 => 16,
                    0x03 => {
                        let mut len = [0u8; 1];
                        if stream.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        1 + len[0] as usize
                    }
                    _ => return,
                };
                let mut rest = vec![0u8; skip + 2];
                if stream.read_exact(&mut rest).await.is_err() {
                    return;
                }
                let mut reply = vec![0x05, 0x00, 0x00, 0x01];
                reply.extend_from_slice(&[127, 0, 0, 1]);
                reply.extend_from_slice(&relay_addr.port().to_be_bytes());
                if stream.write_all(&reply).await.is_err() {
                    return;
                }
                // Keep the control connection alive: the association ends with
                // it, and the kernel keeps it open while a flow is live.
                let mut scratch = [0u8; 64];
                while stream.read(&mut scratch).await.unwrap_or(0) > 0 {}
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread")]
async fn socks5_udp_datagrams_cross_the_tunnel_in_both_directions() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 128];
        if let Ok((read, from)) = echo.recv_from(&mut buffer).await {
            let _ = echo.send_to(&buffer[..read], from).await;
        }
    });
    let peer = socks5_udp_peer().await;
    let config = format!(
        "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: s5, type: socks5, server: 127.0.0.1, port: {peer}, udp: true}}\nrules:\n  - 'MATCH,s5'\n",
        free_port()
    );
    let device = Device::start(&config, TunnelOptions::default());
    let port = device.next_port();
    let query = ipstack::build_udp_packet(
        DEVICE_IP,
        echo_addr.ip(),
        port,
        echo_addr.port(),
        b"tun-socks5",
        64,
    )
    .unwrap();
    device.send(&query);
    let packets = device
        .sink
        .wait_for(|packets| {
            packets.iter().any(|packet| {
                ipstack::parse_ip_packet(packet).map(|p| p.protocol) == Ok(ipstack::IPPROTO_UDP)
            })
        })
        .await;
    let reply = packets
        .iter()
        .find_map(|packet| ipstack::parse_ip_packet(packet).ok())
        .expect("UDP reply");
    assert_eq!(reply.protocol, ipstack::IPPROTO_UDP);
    assert_eq!(reply.src, echo_addr.ip());
    assert_eq!(reply.dst, DEVICE_IP);
    let udp = ipstack::parse_udp(&reply).expect("UDP datagram");
    assert_eq!(udp.payload, b"tun-socks5");
    assert_eq!(udp.dst_port, port);
    assert_eq!(udp.src_port, echo_addr.port());
    let stats = device.tunnel.stats();
    assert_eq!(stats.udp_replies, 1, "{stats:?}");
    assert_eq!(stats.unsupported_protocols, 0, "{stats:?}");
    device.tunnel.stop();
}

/// A TUN UDP association is spawned as its own task; it must re-enter the
/// engine's `proxy-server-nameserver` scope. The proxy server name exists only
/// in the test DNS server, so the data plane cannot reach the peer otherwise.
#[tokio::test(flavor = "multi_thread")]
async fn spawned_tun_udp_association_uses_proxy_server_nameserver() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 128];
        if let Ok((read, from)) = echo.recv_from(&mut buffer).await {
            let _ = echo.send_to(&buffer[..read], from).await;
        }
    });
    let peer = socks5_udp_peer().await;
    let (dns_port, queries) = spawn_a_record_dns();
    let dead = free_port();
    let config = format!(
        "mixed-port: {}\nlog-level: warn\ndns:\n  enable: true\n  ipv6: false\n  nameserver: ['udp://127.0.0.1:{dead}']\n  proxy-server-nameserver: ['udp://127.0.0.1:{dns_port}']\nproxies:\n  - {{name: s5, type: socks5, server: s5.pool.test, port: {peer}, udp: true, ip-version: ipv4}}\nrules:\n  - 'MATCH,s5'\n",
        free_port()
    );
    let device = Device::start(&config, TunnelOptions::default());
    let port = device.next_port();
    let query = ipstack::build_udp_packet(
        DEVICE_IP,
        echo_addr.ip(),
        port,
        echo_addr.port(),
        b"tun-pool-dns",
        64,
    )
    .unwrap();
    device.send(&query);
    let packets = device
        .sink
        .wait_for(|packets| {
            packets.iter().any(|packet| {
                ipstack::parse_ip_packet(packet).map(|p| p.protocol) == Ok(ipstack::IPPROTO_UDP)
            })
        })
        .await;
    let reply = packets
        .iter()
        .find_map(|packet| ipstack::parse_ip_packet(packet).ok())
        .expect("UDP reply");
    let udp = ipstack::parse_udp(&reply).expect("UDP datagram");
    assert_eq!(udp.payload, b"tun-pool-dns");
    assert!(
        queries.load(Ordering::Relaxed) > 0,
        "the spawned association must query proxy-server-nameserver"
    );
    device.tunnel.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_device_sockets_to_one_remote_keep_their_replies() {
    // Two device sockets (different source ports) reach the same remote at
    // the same time. The shared-socket design would broadcast each reply to
    // both sockets; the per-flow NAT key must deliver each payload exactly to
    // the socket that sent it.
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 128];
        loop {
            let Ok((read, from)) = server.recv_from(&mut buffer).await else {
                return;
            };
            let payload = buffer[..read].to_vec();
            if server.send_to(&payload, from).await.is_err() {
                return;
            }
        }
    });

    let device = Device::start(&direct_config(), TunnelOptions::default());
    let first = device.next_port();
    let second = device.next_port();
    for (port, payload) in [(first, b"first".as_slice()), (second, b"second".as_slice())] {
        let packet = ipstack::build_udp_packet(
            DEVICE_IP,
            target.ip(),
            port,
            target.port(),
            payload,
            64,
        )
        .unwrap();
        device.send(&packet);
    }
    let packets = device
        .sink
        .wait_for(|packets| {
            let mut replies = 0;
            for packet in packets {
                if let Ok(parsed) = ipstack::parse_ip_packet(packet) {
                    if parsed.protocol == ipstack::IPPROTO_UDP {
                        replies += 1;
                    }
                }
            }
            replies >= 2
        })
        .await;
    let mut by_port = std::collections::HashMap::new();
    for packet in &packets {
        let Ok(parsed) = ipstack::parse_ip_packet(packet) else {
            continue;
        };
        if parsed.protocol != ipstack::IPPROTO_UDP {
            continue;
        }
        let udp = ipstack::parse_udp(&parsed).expect("UDP reply");
        by_port.insert(udp.dst_port, udp.payload.to_vec());
    }
    assert_eq!(by_port.get(&first).map(Vec::as_slice), Some(b"first".as_slice()));
    assert_eq!(by_port.get(&second).map(Vec::as_slice), Some(b"second".as_slice()));
    let stats = device.tunnel.stats();
    assert_eq!(stats.udp_flows, 2, "{stats:?}");
    assert_eq!(stats.udp_replies, 2, "{stats:?}");
    device.tunnel.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_queries_are_answered_from_the_configured_resolver() {
    // A fake upstream resolver: answers every query with NXDOMAIN-shaped
    // header flags so the test only asserts routing, not DNS semantics.
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        while let Ok((read, from)) = upstream.recv_from(&mut buffer).await {
            let mut answer = buffer[..read].to_vec();
            answer[2] |= 0x80; // QR
            answer[3] = (answer[3] & 0xf0) | 3; // NXDOMAIN
            let _ = upstream.send_to(&answer, from).await;
        }
    });
    let config = format!(
        "mixed-port: {}\ndns:\n  enable: true\n  nameserver:\n    - '{}'\nrules:\n  - MATCH,DIRECT\n",
        free_port(),
        upstream_addr
    );
    let device = Device::start(&config, TunnelOptions::default());
    let port = device.next_port();
    // A minimal query for "example.com" A.
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
    query.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
    query.extend_from_slice(&[0, 1, 0, 1]);
    let dns_addr = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));
    let packet = ipstack::build_udp_packet(DEVICE_IP, dns_addr, port, 53, &query, 64).unwrap();
    device.send(&packet);
    let packets = device
        .sink
        .wait_for(|packets| {
            packets.iter().any(|packet| {
                ipstack::parse_ip_packet(packet)
                    .map(|parsed| parsed.protocol == ipstack::IPPROTO_UDP && parsed.src == dns_addr)
                    .unwrap_or(false)
            })
        })
        .await;
    let reply = packets
        .iter()
        .filter_map(|packet| ipstack::parse_ip_packet(packet).ok())
        .find(|parsed| parsed.protocol == ipstack::IPPROTO_UDP && parsed.src == dns_addr)
        .expect("DNS reply");
    let udp = ipstack::parse_udp(&reply).expect("DNS datagram");
    assert_eq!(udp.dst_port, port);
    assert_eq!(udp.src_port, 53);
    assert!(!udp.payload.is_empty());
    assert_eq!(
        &udp.payload[..2],
        &[0x12, 0x34],
        "the transaction id is echoed"
    );
    let stats = device.tunnel.stats();
    assert_eq!(stats.dns_queries, 1, "{stats:?}");
    device.tunnel.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_rule_closes_the_flow_with_reset() {
    let config = format!(
        "mixed-port: {}\nrules:\n  - IP-CIDR,93.184.216.0/24,REJECT\n  - MATCH,DIRECT\n",
        free_port()
    );
    let device = Device::start(&config, TunnelOptions::default());
    let port = device.next_port();
    let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
    device.send_tcp(port, target, 7, 0, FLAG_SYN, &[]);
    let packets = device
        .sink
        .wait_for(|packets| {
            packets
                .iter()
                .filter_map(|packet| parse_segment(packet).ok())
                .any(|segment| segment.flags & 0x04 != 0)
        })
        .await;
    let reset = packets
        .iter()
        .filter_map(|packet| parse_segment(packet).ok())
        .find(|segment| segment.flags & 0x04 != 0)
        .expect("RST");
    assert_eq!(reset.dst_port, port);
    assert_eq!(device.tunnel.stats().tcp_rejected, 1);
    device.tunnel.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn reload_closes_flows_and_keeps_forwarding() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 32];
                if let Ok(read) = socket.read(&mut buffer).await {
                    let _ = socket.write_all(&buffer[..read]).await;
                }
            });
        }
    });
    let root = std::env::temp_dir().join(format!("billow-t7-reload-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let yaml = direct_config();
    std::fs::write(root.join("config.yaml"), &yaml).unwrap();
    let sink = Collector::new();
    let tunnel = Tunnel::start(
        &yaml,
        root.clone(),
        TunnelOptions::default(),
        Some(sink.clone() as Arc<dyn PacketSink>),
    )
    .expect("tunnel starts");
    let device = Device {
        tunnel,
        sink,
        next_port: AtomicU16::new(51_000),
    };
    let port = device.next_port();
    device.send_tcp(port, target, 1, 0, FLAG_SYN, &[]);
    let _ = device.tcp_packets().await;
    assert_eq!(device.tunnel.stats().tcp_flows, 1);
    let warnings = device.tunnel.reload().expect("reload");
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(
        device.tunnel.stats().tcp_flows,
        0,
        "the flow index is released"
    );
    // A new connection is served by the new generation.
    let port = device.next_port();
    device.send_tcp(port, target, 1, 0, FLAG_SYN, &[]);
    let packets = device.wait_tcp(port, target, FLAG_SYN | FLAG_ACK).await;
    assert!(packet_for(&packets, port, target, FLAG_SYN | FLAG_ACK).is_some());
    device.tunnel.stop();
    let _ = std::fs::remove_dir_all(&root);
}

fn packet_for<'a>(
    packets: &'a [Vec<u8>],
    device_port: u16,
    target: SocketAddr,
    flags: u8,
) -> Option<TcpSegment<'a>> {
    packets
        .iter()
        .filter_map(|packet| parse_segment(packet).ok())
        .find(|segment| {
            segment.flags & flags == flags
                && segment.dst_port == device_port
                && segment.src_port == target.port()
                && segment.dst == DEVICE_IP
        })
}
