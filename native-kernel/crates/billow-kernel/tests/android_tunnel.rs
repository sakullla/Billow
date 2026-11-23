//! End-to-end tests of the Android VpnService data plane (`feature = "android-vpn"`).
//!
//! A `UnixDatagram` pair plays the boundary the VpnService crosses: one end is
//! the TUN fd handed to [`AndroidVpn`] (many kernels implement a TUN as a
//! packet-oriented descriptor; a datagram socket preserves packet boundaries
//! the same way), the other end is the device. The tests write whole IP
//! packets and read the packets the engine emits, so the fd plumbing, the
//! bounded writer queue and the shared T7 TCP/UDP/DNS paths are all exercised
//! without an Android device.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::os::fd::{IntoRawFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use billow_kernel::android_vpn::{AndroidVpn, AndroidVpnOptions};
use billow_kernel::outbound::ipstack;
use billow_kernel::outbound::tcp::{
    parse_segment, TcpSegment, FLAG_ACK, FLAG_FIN, FLAG_PSH, FLAG_SYN,
};
use billow_kernel::tunnel::TunnelOptions;

/// Device address the VpnService builder assigns to the app side.
const DEVICE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1));

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

fn direct_config() -> String {
    format!("mixed-port: {}\nrules:\n  - MATCH,DIRECT\n", free_port())
}

fn test_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "billow-android-vpn-{}-{tag}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

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

/// The VpnService side of the fd plus the device socket.
struct Device {
    vpn: AndroidVpn,
    /// The raw number handed to `AndroidVpn` (it owns and closes it).
    fd: RawFd,
    peer: std::os::unix::net::UnixDatagram,
    dir: PathBuf,
    next_port: AtomicU16,
}

impl Device {
    fn start(config: &str, options: TunnelOptions) -> Device {
        let dir = test_dir("tunnel");
        std::fs::write(dir.join("config.yaml"), config).expect("config.yaml");
        let (host, peer) = std::os::unix::net::UnixDatagram::pair().expect("socketpair");
        peer.set_read_timeout(Some(Duration::from_millis(200)))
            .expect("read timeout");
        let fd = host.into_raw_fd();
        let vpn = AndroidVpn::start(
            fd,
            config,
            dir.clone(),
            AndroidVpnOptions {
                tunnel: options,
                ..AndroidVpnOptions::default()
            },
        )
        .expect("android tunnel starts");
        Device {
            vpn,
            fd,
            peer,
            dir,
            next_port: AtomicU16::new(40_000),
        }
    }

    fn next_port(&self) -> u16 {
        self.next_port.fetch_add(1, Ordering::Relaxed)
    }

    fn send(&self, packet: &[u8]) {
        self.peer.send(packet).expect("device packet written");
    }

    /// Closes the VpnService side of the descriptor, as a revoke does.
    fn revoke(&mut self) {
        // `Device` implements `Drop`, so the peer is swapped out instead of
        // moved; the old socket closes when the replacement is dropped.
        let (replacement, _) = std::os::unix::net::UnixDatagram::pair().expect("socketpair");
        let _ = std::mem::replace(&mut self.peer, replacement);
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

    fn tcp_packets(&self) -> Vec<Vec<u8>> {
        self.wait_for(|packets| {
            packets.iter().any(|packet| {
                ipstack::parse_ip_packet(packet).map(|parsed| parsed.protocol)
                    == Ok(ipstack::IPPROTO_TCP)
            })
        })
    }

    fn wait_tcp(&self, device_port: u16, target: SocketAddr, flags: u8) -> Vec<Vec<u8>> {
        self.wait_for(|packets| packet_for(packets, device_port, target, flags).is_some())
    }

    /// Collects emitted packets until `predicate` accepts the set.
    fn wait_for(&self, predicate: impl Fn(&[Vec<u8>]) -> bool) -> Vec<Vec<u8>> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut packets: Vec<Vec<u8>> = Vec::new();
        loop {
            if predicate(&packets) {
                return packets;
            }
            if Instant::now() > deadline {
                panic!(
                    "timed out waiting for an emitted packet; got {} packets",
                    packets.len()
                );
            }
            let mut buffer = vec![0u8; 65_535];
            match self.peer.recv(&mut buffer) {
                Ok(length) => packets.push(buffer[..length].to_vec()),
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue
                }
                Err(error) => panic!("device read failed: {error}"),
            }
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        self.vpn.stop();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
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

#[test]
fn tcp_stream_crosses_the_fd_in_both_directions() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let target = listener.local_addr().expect("addr");
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        let mut buffer = [0u8; 64];
        let read = socket.read(&mut buffer).expect("read");
        socket.write_all(&buffer[..read]).expect("write");
        let _ = socket.shutdown(std::net::Shutdown::Write);
        read
    });

    let device = Device::start(&direct_config(), TunnelOptions::default());
    let port = device.next_port();
    device.send_tcp(port, target, 1000, 0, FLAG_SYN, &[]);
    let packets = device.tcp_packets();
    let syn_ack = packet_for(&packets, port, target, FLAG_SYN | FLAG_ACK).expect("SYN-ACK");
    let our_iss = syn_ack.seq;
    assert_eq!(syn_ack.ack, 1001);
    assert_eq!(syn_ack.dst, DEVICE_IP);
    assert_eq!(syn_ack.dst_port, port);
    let device_next = 1001u32;

    device.send_tcp(
        port,
        target,
        device_next,
        our_iss.wrapping_add(1),
        FLAG_ACK | FLAG_PSH,
        b"ping",
    );
    let packets = device.wait_for(|packets| {
        packets.iter().any(|packet| {
            parse_segment(packet)
                .map(|segment| segment.payload == b"ping")
                .unwrap_or(false)
        })
    });
    let echo = packets
        .iter()
        .filter_map(|packet| parse_segment(packet).ok())
        .find(|segment| segment.payload == b"ping")
        .expect("echo crosses the fd");
    assert_eq!(echo.dst, DEVICE_IP);
    assert_eq!(echo.dst_port, port);
    assert_eq!(echo.src_port, target.port());

    device.send_tcp(
        port,
        target,
        device_next.wrapping_add(4),
        echo.seq.wrapping_add(4),
        FLAG_ACK,
        &[],
    );
    device.send_tcp(
        port,
        target,
        device_next.wrapping_add(4),
        echo.seq.wrapping_add(4),
        FLAG_FIN | FLAG_ACK,
        &[],
    );
    let read = server.join().expect("server finishes");
    assert_eq!(read, 4);

    let stats = device.vpn.stats();
    assert_eq!(stats.tunnel.tcp_opened, 1, "{stats:?}");
    assert!(stats.tunnel.out_packets >= 3, "{stats:?}");
    // The SYN and the data segment must have crossed the fd; later ACK/FIN
    // packets may still be in flight when the echo returns.
    assert!(stats.fd.reads >= 2, "{stats:?}");
    assert!(stats.fd.written >= 3, "{stats:?}");
    assert_eq!(stats.fd.dropped, 0, "{stats:?}");
}

#[test]
fn udp_datagrams_cross_the_fd_in_both_directions() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let target = server.local_addr().expect("addr");
    let echo = std::thread::spawn(move || {
        let mut buffer = [0u8; 128];
        let (read, from) = server.recv_from(&mut buffer).expect("recv");
        server.send_to(&buffer[..read], from).expect("send");
        read
    });

    let device = Device::start(&direct_config(), TunnelOptions::default());
    let port = device.next_port();
    let query = ipstack::build_udp_packet(DEVICE_IP, target.ip(), port, target.port(), b"pong", 64)
        .expect("packet");
    device.send(&query);
    let packets = device.wait_for(|packets| {
        packets.iter().any(|packet| {
            ipstack::parse_ip_packet(packet).map(|parsed| parsed.protocol)
                == Ok(ipstack::IPPROTO_UDP)
        })
    });
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
    assert_eq!(echo.join().expect("echo"), 4);

    let stats = device.vpn.stats();
    assert_eq!(stats.tunnel.udp_flows, 1, "{stats:?}");
    assert_eq!(stats.tunnel.udp_replies, 1, "{stats:?}");
    assert_eq!(stats.fd.dropped, 0, "{stats:?}");
}

#[test]
fn dns_queries_are_hijacked_and_answered_through_the_fd() {
    let upstream = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let upstream_addr = upstream.local_addr().expect("addr");
    let resolver = std::thread::spawn(move || {
        let mut buffer = [0u8; 512];
        let (read, from) = upstream.recv_from(&mut buffer).expect("recv");
        let mut answer = buffer[..read].to_vec();
        answer[2] |= 0x80; // QR
        answer[3] = (answer[3] & 0xf0) | 3; // NXDOMAIN
        upstream.send_to(&answer, from).expect("send");
    });
    let config = format!(
        "mixed-port: {}\ndns:\n  enable: true\n  nameserver:\n    - '{}'\nrules:\n  - MATCH,DIRECT\n",
        free_port(),
        upstream_addr
    );
    let device = Device::start(&config, TunnelOptions::default());
    let port = device.next_port();
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
    query.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
    query.extend_from_slice(&[0, 1, 0, 1]);
    // The VpnService builder configures 172.19.0.2 as the device resolver.
    let dns_addr = IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2));
    let packet =
        ipstack::build_udp_packet(DEVICE_IP, dns_addr, port, 53, &query, 64).expect("packet");
    device.send(&packet);
    let packets = device.wait_for(|packets| {
        packets.iter().any(|packet| {
            ipstack::parse_ip_packet(packet)
                .map(|parsed| parsed.protocol == ipstack::IPPROTO_UDP && parsed.src == dns_addr)
                .unwrap_or(false)
        })
    });
    let reply = packets
        .iter()
        .filter_map(|packet| ipstack::parse_ip_packet(packet).ok())
        .find(|parsed| parsed.protocol == ipstack::IPPROTO_UDP && parsed.src == dns_addr)
        .expect("DNS reply");
    let udp = ipstack::parse_udp(&reply).expect("DNS datagram");
    assert_eq!(udp.dst_port, port);
    assert_eq!(udp.src_port, 53);
    assert_eq!(&udp.payload[..2], &[0x12, 0x34]);
    resolver.join().expect("resolver finishes");
    let stats = device.vpn.stats();
    assert_eq!(stats.tunnel.dns_queries, 1, "{stats:?}");
}

#[test]
fn stop_releases_the_fd_and_every_flow() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let target = listener.local_addr().expect("addr");
    let server = std::thread::spawn(move || {
        let _ = listener.accept();
    });
    let device = Device::start(&direct_config(), TunnelOptions::default());
    let port = device.next_port();
    device.send_tcp(port, target, 1, 0, FLAG_SYN, &[]);
    let _ = device.wait_tcp(port, target, FLAG_SYN | FLAG_ACK);
    assert_eq!(device.vpn.stats().tunnel.tcp_flows, 1);

    let fd = device.fd;
    device.vpn.stop();
    assert!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0,
        "the owned TUN fd must be closed by stop"
    );
    let stats = device.vpn.stats();
    assert!(!stats.running);
    assert_eq!(stats.tunnel.tcp_flows, 0, "flows are released: {stats:?}");
    // Idempotent: a host that stops twice (disconnect then drop) is safe.
    device.vpn.stop();
    let _ = server.join();
}

#[test]
fn reload_closes_flows_and_keeps_pumping() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let target = listener.local_addr().expect("addr");
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let Ok((mut socket, _)) = listener.accept() else {
                return;
            };
            std::thread::spawn(move || {
                let mut buffer = [0u8; 32];
                if let Ok(read) = socket.read(&mut buffer) {
                    let _ = socket.write_all(&buffer[..read]);
                }
            });
        }
    });
    let device = Device::start(&direct_config(), TunnelOptions::default());
    let port = device.next_port();
    device.send_tcp(port, target, 1, 0, FLAG_SYN, &[]);
    let _ = device.wait_tcp(port, target, FLAG_SYN | FLAG_ACK);
    assert_eq!(device.vpn.stats().tunnel.tcp_flows, 1);
    let warnings = device.vpn.reload().expect("reload");
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(device.vpn.stats().tunnel.tcp_flows, 0);

    let port = device.next_port();
    device.send_tcp(port, target, 1, 0, FLAG_SYN, &[]);
    let packets = device.wait_tcp(port, target, FLAG_SYN | FLAG_ACK);
    assert!(packet_for(&packets, port, target, FLAG_SYN | FLAG_ACK).is_some());
    let _ = server.join();
}

#[test]
fn a_user_tun_block_is_staged_away_instead_of_rejected() {
    let dir = test_dir("staged");
    let yaml = format!(
        "mixed-port: {}\ntun:\n  enable: true\n  stack: gvisor\nsniffer:\n  enable: true\nrules:\n  - MATCH,DIRECT\n",
        free_port()
    );
    std::fs::write(dir.join("config.yaml"), &yaml).expect("config.yaml");
    let (host, peer) = std::os::unix::net::UnixDatagram::pair().expect("socketpair");
    peer.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("read timeout");
    let fd = host.into_raw_fd();
    let vpn = AndroidVpn::start(
        fd,
        &yaml,
        dir.clone(),
        AndroidVpnOptions {
            tunnel: TunnelOptions::default(),
            ..AndroidVpnOptions::default()
        },
    )
    .expect("a user tun block is staged away, not a config rejection");
    let staged = std::fs::read_to_string(dir.join("config.rust.yaml")).expect("staged file");
    let value: serde_yaml::Value = serde_yaml::from_str(&staged).expect("staged YAML");
    assert!(value.get("tun").is_none(), "{staged}");
    assert!(value.get("sniffer").is_none(), "{staged}");
    vpn.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_invalid_fd_is_refused_before_anything_starts() {
    let dir = test_dir("bad-fd");
    let yaml = direct_config();
    let error = match AndroidVpn::start(-1, &yaml, dir.clone(), AndroidVpnOptions::default()) {
        Ok(vpn) => {
            vpn.stop();
            panic!("a negative fd must be refused");
        }
        Err(error) => error,
    };
    assert!(error.contains("invalid TUN fd"), "{error}");

    // No process can hold this number (above any RLIMIT_NOFILE), so it is a
    // deterministic EBADF even when another test thread opens descriptors.
    let closed = i32::MAX;
    let error = match AndroidVpn::start(closed, &yaml, dir.clone(), AndroidVpnOptions::default()) {
        Ok(vpn) => {
            vpn.stop();
            panic!("a closed fd must be refused");
        }
        Err(error) => error,
    };
    assert!(error.contains("not open"), "{error}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_revoked_device_fd_stops_the_pump_and_is_visible_to_the_host() {
    let mut device = Device::start(&direct_config(), TunnelOptions::default());
    assert!(device.vpn.stats().running);
    // The VpnService side closing the descriptor (a revoke) ends the pump; a
    // host that only samples process liveness must still be able to notice.
    device.revoke();
    let deadline = Instant::now() + Duration::from_secs(5);
    while device.vpn.stats().running && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !device.vpn.stats().running,
        "a closed peer must stop the fd pump instead of polling forever"
    );
}

#[test]
fn a_failed_start_leaves_the_descriptor_open_for_the_caller() {
    let dir = test_dir("failed-ownership");
    let (host, _peer) = std::os::unix::net::UnixDatagram::pair().expect("socketpair");
    let fd = host.into_raw_fd();
    let error = match AndroidVpn::start(fd, "not: [valid yaml", dir.clone(), AndroidVpnOptions::default()) {
        Ok(vpn) => {
            vpn.stop();
            panic!("invalid YAML must be refused");
        }
        Err(error) => error,
    };
    assert!(!error.is_empty());
    // The documented ownership rule: a failed start hands the fd back, so the
    // caller closes it exactly once and a later double close cannot happen.
    assert!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0,
        "a failed start must not close the caller's descriptor"
    );
    unsafe { libc::close(fd) };
    let _ = std::fs::remove_dir_all(&dir);
}
