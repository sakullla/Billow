//! Desktop TUN data plane tests (`feature = "desktop-tun"`).
//!
//! These cover the parts that do not need root/administrator rights:
//! configuration strictness, utun framing, the fd pump over a `UnixDatagram`
//! pair, DNS-hijack targeting, route/DNS command planning (including pinned
//! auto-route and set-difference semantics) and rollback. A real utun creation
//! is `#[ignore]`d because this environment has no TUN authorization.

#![cfg(feature = "desktop-tun")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
#[cfg(unix)]
use std::os::fd::IntoRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use billow_kernel::config::{load_config, TunConfig, TunDnsMode};
use billow_kernel::desktop_tun::apply_plan;
use billow_kernel::desktop_tun::framing::{strip_utun_header, with_utun_header, UtunError};
use billow_kernel::desktop_tun::pump::Pump;
use billow_kernel::desktop_tun::route_plan::{self, DefaultRoute, DeviceAddresses, Platform};
use billow_kernel::desktop_tun::{device::Framing, DesktopTun, DesktopTunOptions};
use billow_kernel::outbound::ipstack;
use billow_kernel::outbound::tcp::{parse_segment, FLAG_ACK, FLAG_PSH, FLAG_SYN};
use billow_kernel::tunnel::{Tunnel, TunnelOptions};

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

fn test_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "billow-desktop-tun-{}-{tag}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn addresses() -> DeviceAddresses {
    DeviceAddresses {
        v4: "198.18.0.1/30".parse().unwrap(),
        v6: vec!["fdfe:dcba:9876::1/126".parse().unwrap()],
    }
}

fn physical() -> DefaultRoute {
    DefaultRoute {
        interface: "en0".to_string(),
        gateway: Some("192.168.1.1".parse().unwrap()),
    }
}

#[test]
fn tun_config_accepts_the_billow_desktop_shape_and_rejects_by_name() {
    let yaml = format!(
        "mixed-port: {}\ntun:\n  enable: true\n  device: utun9\n  stack: gvisor\n  mtu: 1400\n  auto-route: true\n  auto-detect-interface: true\n  strict-route: false\n  dns-hijack: [any:53, udp://1.1.1.1:53, '[::]:53']\n  dns-mode: native\n  inet6-address: ['fdfe:dcba:9876::1/126']\n  iproute2-table-index: 3033\n  iproute2-rule-index: 9100\n  route-address: [10.0.0.0/8]\n  route-exclude-address: [192.168.0.0/16]\nrules: ['MATCH,DIRECT']\n",
        free_port()
    );
    let loaded = load_config(&yaml, "desktop-tun").expect("Billow desktop shape loads");
    let tun = loaded.config.tun;
    assert!(tun.enable);
    assert_eq!(tun.device, "utun9");
    assert_eq!(tun.stack, "gvisor");
    assert_eq!(tun.mtu, 1400);
    assert!(tun.auto_route && tun.auto_detect_interface && !tun.strict_route);
    assert_eq!(tun.dns_mode, TunDnsMode::Native);
    assert_eq!(
        tun.dns_hijack,
        vec![
            "0.0.0.0:53".parse().unwrap(),
            "1.1.1.1:53".parse().unwrap(),
            "[::]:53".parse().unwrap(),
        ]
    );
    assert_eq!(tun.inet6_address, ["fdfe:dcba:9876::1/126"]);
    assert_eq!(tun.iproute2_table_index, 3033);
    assert_eq!(tun.iproute2_rule_index, 9100);
    assert_eq!(tun.route_address, ["10.0.0.0/8"]);
    assert_eq!(tun.route_exclude_address, ["192.168.0.0/16"]);

    for stack in ["mips", "mixed", "gvisor"] {
        let yaml = format!("mixed-port: 1\ntun: {{enable: true, stack: {stack}}}\n");
        assert!(load_config(&yaml, "t").is_ok(), "{stack} must load");
    }
    let tag = |yaml: &str| load_config(yaml, "t").unwrap_err().tag().to_string();
    assert_eq!(tag("tun: {enable: true, stack: system}\n"), "unsupported");
    assert_eq!(tag("tun: {enable: true, stack: ebpf}\n"), "unsupported");
    assert_eq!(tag("tun: {enable: true, gso: true}\n"), "unsupported");
    assert_eq!(tag("tun: {enable: true, file-descriptor: 4}\n"), "unsupported");
    assert_eq!(tag("tun: {enable: true, dns-mode: dnsmasq}\n"), "unsupported");
    assert_eq!(tag("tun: {enable: true, mtu: 70000}\n"), "invalid_value");
    assert_eq!(tag("tun: {enable: true, route-address: ['10.0.0.1']}\n"), "invalid_value");
    assert!(tag("tun: {enable: true, inet6-address: ['10.0.0.0/8']}\n").starts_with("invalid"));
    assert!(tag("tun: {enable: true, iproute2-table-index: 0}\n").starts_with("invalid"));
    assert!(tag("tun: {enable: true, iproute2-table-index: 254}\n").starts_with("invalid"));
    assert!(tag("tun: {enable: true, iproute2-rule-index: 0}\n").starts_with("invalid"));
    // A non-53 DNS entry is named instead of becoming a global hijack.
    assert_eq!(
        tag("tun: {enable: true, dns-hijack: ['tls://1.1.1.1:853']}\n"),
        "unsupported"
    );
    assert_eq!(
        tag("tun: {enable: true, dns-hijack: ['1.1.1.1']}\n"),
        "invalid_value"
    );
    // Empty hijack list is accepted and means "never hijack".
    let loaded = load_config("mixed-port: 1\ntun: {enable: true, dns-hijack: []}\n", "t").unwrap();
    assert!(loaded.config.tun.dns_hijack.is_empty());
    // Pinned defaults: dns-mode disabled and the default IPv6 device address.
    let loaded = load_config("mixed-port: 1\ntun: {enable: true}\n", "t").unwrap();
    assert_eq!(loaded.config.tun.dns_mode, TunDnsMode::Disabled);
    assert_eq!(loaded.config.tun.inet6_address, ["fdfe:dcba:9876::1/126"]);
    let loaded = load_config(
        "mixed-port: 1\ntun: {enable: true, strict-route: true}\n",
        "t",
    )
    .unwrap();
    assert!(
        loaded.warnings.iter().any(|warning| warning.contains("strict-route")),
        "{:?}",
        loaded.warnings
    );
}

#[test]
fn dns_hijack_matching_is_exact_or_unspecified() {
    let exact = TunnelOptions {
        dns_hijack: vec!["1.1.1.1:53".parse().unwrap()],
        ..TunnelOptions::default()
    };
    assert!(exact.should_hijack_dns("1.1.1.1:53".parse().unwrap()));
    assert!(!exact.should_hijack_dns("192.0.2.53:53".parse().unwrap()));
    let wildcard = TunnelOptions {
        dns_hijack: vec!["0.0.0.0:53".parse().unwrap(), "[::]:53".parse().unwrap()],
        ..TunnelOptions::default()
    };
    assert!(wildcard.should_hijack_dns("192.0.2.53:53".parse().unwrap()));
    assert!(wildcard.should_hijack_dns("[2001:db8::1]:53".parse().unwrap()));
    assert!(!wildcard.should_hijack_dns("192.0.2.53:54".parse().unwrap()));
    let empty = TunnelOptions {
        dns_hijack: Vec::new(),
        ..TunnelOptions::default()
    };
    assert!(!empty.should_hijack_dns("192.0.2.53:53".parse().unwrap()));
}

#[test]
fn utun_framing_matches_darwin_address_families() {
    let v4 = ipstack::build_packet(
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
        ipstack::IPPROTO_UDP,
        &[0u8; 8],
        64,
    )
    .unwrap();
    let framed = with_utun_header(&v4).unwrap();
    assert_eq!(&framed[..4], &[0, 0, 0, 2], "AF_INET is 2");
    assert_eq!(strip_utun_header(&framed).unwrap(), v4.as_slice());

    let mut v6 = vec![0u8; 40];
    v6[0] = 0x60;
    v6[6] = 17;
    v6[7] = 64;
    let framed = with_utun_header(&v6).unwrap();
    assert_eq!(&framed[..4], &[0, 0, 0, 30], "AF_INET6 is 30");
    assert_eq!(strip_utun_header(&framed).unwrap(), v6.as_slice());

    assert_eq!(
        strip_utun_header(&[0, 0, 0, 7, 0x45]),
        Err(UtunError::UnsupportedFamily(7))
    );
    assert_eq!(
        strip_utun_header(&[0, 0, 0, 2, 0x60]),
        Err(UtunError::FamilyMismatch { af: 2, version: 6 })
    );
}

#[cfg(unix)]
#[test]
fn fd_pump_carries_udp_ip_packets_both_ways() {
    let dir = test_dir("pump");
    let config = format!(
        "mixed-port: {}\ntun: {{enable: true, auto-route: false, auto-detect-interface: false, dns-hijack: []}}\nrules: ['MATCH,DIRECT']\n",
        free_port()
    );
    let (host, peer) = std::os::unix::net::UnixDatagram::pair().expect("socketpair");
    peer.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("read timeout");
    let fd = host.into_raw_fd();
    let device = std::sync::Arc::new(
        billow_kernel::desktop_tun::device::FdDevice::from_owned(fd, "test-tun", Framing::Raw)
            .expect("fd device"),
    );
    let tunnel = std::sync::Arc::new(
        Tunnel::start(&config, dir.clone(), TunnelOptions::default(), None).expect("tunnel"),
    );
    let mut pump = Pump::start(tunnel.clone(), device, 256).expect("pump");
    let deadline = Instant::now() + Duration::from_secs(5);
    while tunnel.identity().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }

    let echo = UdpSocket::bind("127.0.0.1:0").expect("echo bind");
    let echo_addr = echo.local_addr().unwrap();
    let echo_thread = std::thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        let (read, peer) = echo.recv_from(&mut buffer).expect("echo recv");
        echo.send_to(&buffer[..read], peer).expect("echo send");
    });

    let device_ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2));
    let datagram = ipstack::build_udp_packet(
        device_ip,
        echo_addr.ip(),
        40_000,
        echo_addr.port(),
        b"desktop-tun",
        64,
    )
    .expect("udp packet");
    peer.send(&datagram).expect("device packet");

    let mut buffer = vec![0u8; 65_535];
    let deadline = Instant::now() + Duration::from_secs(10);
    let reply = loop {
        if Instant::now() > deadline {
            panic!("timed out waiting for the UDP reply");
        }
        match peer.recv(&mut buffer) {
            Ok(length) => {
                let parsed = ipstack::parse_ip_packet(&buffer[..length]).expect("reply IP");
                if parsed.protocol == ipstack::IPPROTO_UDP {
                    if let Ok(udp) = ipstack::parse_udp(&parsed) {
                        if udp.payload == b"desktop-tun" {
                            break udp.payload.to_vec();
                        }
                    }
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => panic!("device read failed: {error}"),
        }
    };
    assert_eq!(reply, b"desktop-tun");
    echo_thread.join().unwrap();
    let pump_stats = pump.stats();
    pump.stop();
    let tunnel_stats = tunnel.stats();
    assert!(tunnel_stats.udp_replies >= 1, "{tunnel_stats:?}");
    assert!(pump_stats.reads >= 1, "{pump_stats:?}");
    assert!(pump_stats.written >= 1, "{pump_stats:?}");
    tunnel.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

fn dns_query() -> Vec<u8> {
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
    query.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
    query.extend_from_slice(&[0, 1, 0, 1]);
    query
}

fn dns_upstream() -> (SocketAddr, std::thread::JoinHandle<()>) {
    let upstream = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let addr = upstream.local_addr().expect("addr");
    let thread = std::thread::spawn(move || {
        let mut buffer = [0u8; 512];
        let (read, from) = upstream.recv_from(&mut buffer).expect("recv");
        let mut answer = buffer[..read].to_vec();
        answer[2] |= 0x80;
        answer[3] = (answer[3] & 0xf0) | 3;
        upstream.send_to(&answer, from).expect("send");
    });
    (addr, thread)
}

fn dns_config(upstream: SocketAddr, hijack: &str) -> String {
    format!(
        "mixed-port: {}\ndns:\n  enable: true\n  nameserver: ['{}']\ntun: {{enable: true, auto-route: false, auto-detect-interface: false, dns-hijack: [{hijack}]}}\nrules: ['MATCH,DIRECT']\n",
        free_port(),
        upstream
    )
}

fn native_dns_config(upstream: SocketAddr, hijack: &str) -> String {
    format!(
        "mixed-port: {}\ndns:\n  enable: true\n  nameserver: ['{}']\ntun: {{enable: true, auto-route: false, auto-detect-interface: false, dns-mode: native, dns-hijack: [{hijack}]}}\nrules: ['MATCH,DIRECT']\n",
        free_port(),
        upstream
    )
}

fn start_tunnel_with_config(config: &str, dir: &std::path::Path) -> Tunnel {
    let loaded = load_config(config, "desktop-tunnel").expect("config");
    let addresses = DeviceAddresses::from_config(&loaded.config);
    let options = TunnelOptions {
        dns_hijack: billow_kernel::desktop_tun::effective_dns_hijack(
            &loaded.config.tun,
            &addresses,
        ),
        ..TunnelOptions::default()
    };
    Tunnel::start(config, dir.to_path_buf(), options, None).expect("tunnel")
}

fn drain(tunnel: &Tunnel) -> Vec<Vec<u8>> {
    let mut buffer = vec![0u8; 70_000];
    let count = tunnel.drain_into(&mut buffer, 16);
    let mut packets = Vec::new();
    let mut offset = 0;
    for _ in 0..count {
        let length = u32::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]) as usize;
        packets.push(buffer[offset + 4..offset + 4 + length].to_vec());
        offset += 4 + length;
    }
    packets
}

#[test]
fn a_listed_dns_target_is_hijacked_and_an_unlisted_one_is_not() {
    // `dns-hijack: ['1.1.1.1:53']` must not answer 192.0.2.53.
    let (upstream, upstream_thread) = dns_upstream();
    let dir = test_dir("dns-miss");
    let config = dns_config(upstream, "'1.1.1.1:53'");
    let tunnel = start_tunnel_with_config(&config, &dir);
    let packet = ipstack::build_udp_packet(
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
        40_000,
        53,
        &dns_query(),
        64,
    )
    .unwrap();
    assert!(matches!(
        tunnel.ingest(&packet),
        billow_kernel::tunnel::Ingest::Accepted
    ));
    std::thread::sleep(Duration::from_millis(300));
    let stats = tunnel.stats();
    assert_eq!(stats.dns_queries, 0, "unlisted target must not be answered: {stats:?}");
    assert!(stats.udp_datagrams >= 1, "{stats:?}");
    tunnel.stop();
    let _ = std::fs::remove_dir_all(&dir);
    // The upstream never saw a query; the thread is left blocked. Detach it.
    drop(upstream_thread);
}

#[test]
fn an_unspecified_dns_hijack_entry_answers_any_port_53_target() {
    let (upstream, upstream_thread) = dns_upstream();
    let dir = test_dir("dns-hit");
    let config = dns_config(upstream, "'any:53'");
    let tunnel = start_tunnel_with_config(&config, &dir);
    let packet = ipstack::build_udp_packet(
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
        40_000,
        53,
        &dns_query(),
        64,
    )
    .unwrap();
    tunnel.ingest(&packet);
    let deadline = Instant::now() + Duration::from_secs(5);
    let reply = loop {
        let packets = drain(&tunnel);
        if let Some(packet) = packets.into_iter().find(|packet| {
            ipstack::parse_ip_packet(packet)
                .map(|parsed| parsed.protocol == ipstack::IPPROTO_UDP)
                .unwrap_or(false)
        }) {
            break packet;
        }
        assert!(Instant::now() < deadline, "no DNS reply");
        std::thread::sleep(Duration::from_millis(20));
    };
    let parsed = ipstack::parse_ip_packet(&reply).unwrap();
    let udp = ipstack::parse_udp(&parsed).unwrap();
    assert_eq!(udp.src_port, 53);
    assert_eq!(udp.dst_port, 40_000);
    assert_eq!(udp.payload[2] & 0x80, 0x80, "QR bit set by the upstream");
    upstream_thread.join().unwrap();
    assert!(tunnel.stats().dns_queries >= 1);
    tunnel.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// With `dns-mode: native` and an empty `dns-hijack`, pinned still appends the
/// device DNS address, so a query to tun4+1:53 is answered locally.
#[test]
fn native_dns_mode_appends_the_device_dns_address_to_an_empty_hijack_set() {
    let (upstream, upstream_thread) = dns_upstream();
    let dir = test_dir("dns-native");
    let config = native_dns_config(upstream, "");
    let loaded = load_config(&config, "desktop-tunnel").unwrap();
    assert!(loaded.config.tun.dns_hijack.is_empty());
    assert_eq!(loaded.config.tun.dns_mode, TunDnsMode::Native);
    let addresses = DeviceAddresses::from_config(&loaded.config);
    let effective = billow_kernel::desktop_tun::effective_dns_hijack(&loaded.config.tun, &addresses);
    assert!(effective.contains(&"198.18.0.2:53".parse().unwrap()));
    assert!(effective.contains(&"[fdfe:dcba:9876::2]:53".parse().unwrap()));
    let tunnel = start_tunnel_with_config(&config, &dir);
    let packet = ipstack::build_udp_packet(
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)),
        40_000,
        53,
        &dns_query(),
        64,
    )
    .unwrap();
    tunnel.ingest(&packet);
    let deadline = Instant::now() + Duration::from_secs(5);
    let reply = loop {
        if let Some(packet) = drain(&tunnel).into_iter().find(|packet| {
            ipstack::parse_ip_packet(packet)
                .map(|parsed| parsed.protocol == ipstack::IPPROTO_UDP)
                .unwrap_or(false)
        }) {
            break packet;
        }
        assert!(Instant::now() < deadline, "no device-DNS reply");
        std::thread::sleep(Duration::from_millis(20));
    };
    let parsed = ipstack::parse_ip_packet(&reply).unwrap();
    let udp = ipstack::parse_udp(&parsed).unwrap();
    assert_eq!(udp.dst_port, 40_000);
    assert_eq!(udp.payload[2] & 0x80, 0x80);
    upstream_thread.join().unwrap();
    assert!(tunnel.stats().dns_queries >= 1);
    tunnel.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// TCP DNS hijack: the same target set drives the passive TCP endpoint. A
/// narrow `dns-hijack` list plus `dns-mode: native` still matches the device
/// DNS address (pinned appends tun4+1:53).
#[test]
fn a_tcp_dns_query_is_hijacked_only_for_a_matching_target() {
    let (upstream, upstream_thread) = dns_upstream();
    let dir = test_dir("dns-tcp");
    let config = native_dns_config(upstream, "'1.1.1.1:53'");
    let tunnel = start_tunnel_with_config(&config, &dir);
    let device_ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2));
    let target = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2));
    let port = 40_000u16;
    let syn = tcp_packet(device_ip, target, port, 53, 1000, 0, FLAG_SYN, &[]);
    tunnel.ingest(&syn);
    let deadline = Instant::now() + Duration::from_secs(5);
    let our_iss = loop {
        if let Some(seq) = drain(&tunnel)
            .iter()
            .filter_map(|packet| parse_segment(packet).ok())
            .find(|segment| segment.flags & (FLAG_SYN | FLAG_ACK) == FLAG_SYN | FLAG_ACK)
            .map(|segment| segment.seq)
        {
            break seq;
        }
        assert!(Instant::now() < deadline, "no SYN-ACK");
        std::thread::sleep(Duration::from_millis(10));
    };
    let query = dns_query();
    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&query);
    let data = tcp_packet(
        device_ip,
        target,
        port,
        53,
        1001,
        our_iss.wrapping_add(1),
        FLAG_ACK | FLAG_PSH,
        &framed,
    );
    tunnel.ingest(&data);
    let deadline = Instant::now() + Duration::from_secs(5);
    let reply = loop {
        let payload = drain(&tunnel)
            .iter()
            .filter_map(|packet| parse_segment(packet).ok())
            .find(|segment| segment.payload.len() >= 4 && segment.payload[4] & 0x80 == 0x80)
            .map(|segment| segment.payload.to_vec());
        if let Some(payload) = payload {
            break payload;
        }
        assert!(Instant::now() < deadline, "no TCP DNS reply");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(u16::from_be_bytes([reply[0], reply[1]]) as usize, reply.len() - 2);
    upstream_thread.join().unwrap();
    assert!(tunnel.stats().dns_queries >= 1);
    tunnel.stop();
    let _ = std::fs::remove_dir_all(&dir);
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

#[test]
fn route_plan_follows_pinned_auto_route_and_exclusion() {
    let mut tun = TunConfig {
        enable: true,
        auto_detect_interface: true,
        ..TunConfig::default()
    };
    let addresses = addresses();
    let mac = route_plan::plan(Platform::Macos, "utun7", &tun, &addresses, Some(&physical()), 1400).unwrap();
    let up: Vec<String> = mac.up.iter().map(|command| command.render()).collect();
    assert!(up.contains(&"/sbin/route -n add -inet 1.0.0.0/8 -interface utun7".to_string()), "{up:?}");
    assert!(up.contains(&"/sbin/route -n add -inet 128.0.0.0/1 -interface utun7".to_string()));
    assert!(!up.iter().any(|line| line.contains("0.0.0.0/1 ")), "{up:?}");

    // route-address replaces the auto ranges; macOS adds the device subnet.
    tun.route_address = vec!["10.0.0.0/8".to_string()];
    let scoped = route_plan::plan(Platform::Macos, "utun7", &tun, &addresses, Some(&physical()), 1500).unwrap();
    let up: Vec<String> = scoped.up.iter().map(|command| command.render()).collect();
    assert!(up.contains(&"/sbin/route -n add -inet 10.0.0.0/8 -interface utun7".to_string()));
    assert!(up.contains(&"/sbin/route -n add -inet 198.18.0.0/30 -interface utun7".to_string()));
    assert!(!up.iter().any(|line| line.contains("1.0.0.0/8")), "{up:?}");
    let linux = route_plan::plan(Platform::Linux, "billow0", &tun, &addresses, Some(&physical()), 1500).unwrap();
    assert_eq!(
        linux.up.iter().map(|command| command.render()).collect::<Vec<_>>(),
        vec![
            "ip route add 10.0.0.0/8 dev billow0 table 2022",
            "ip -6 route add ::/0 dev billow0 table 2022",
            "ip rule add priority 9000 lookup 2022",
            "ip -6 rule add priority 9000 lookup 2022",
        ]
    );

    // Exclusions are a set difference: no `via gateway` route remains.
    tun.route_exclude_address = vec!["192.168.0.0/16".to_string()];
    let excluded = route_plan::plan(Platform::Linux, "billow0", &tun, &addresses, Some(&physical()), 1500).unwrap();
    let up: Vec<String> = excluded.up.iter().map(|command| command.render()).collect();
    assert!(!up.iter().any(|line| line.contains("192.168.0.0/16 ")), "{up:?}");
    assert!(!up.iter().any(|line| line.contains("via ")), "{up:?}");
}

#[test]
fn ipv6_false_and_custom_inet6_addresses_change_the_plan() {
    let yaml = format!(
        "mixed-port: {}\nipv6: false\ntun: {{enable: true, route-address: ['10.0.0.0/8']}}\nrules: ['MATCH,DIRECT']\n",
        free_port()
    );
    let loaded = load_config(&yaml, "t").unwrap();
    let addresses = DeviceAddresses::from_config(&loaded.config);
    assert!(addresses.v6.is_empty());
    assert!(addresses.dns_servers().1.is_none());
    let plan = route_plan::plan(
        Platform::Linux,
        "billow0",
        &loaded.config.tun,
        &addresses,
        Some(&physical()),
        1500,
    )
    .unwrap();
    let rendered: Vec<String> = plan.address.iter().map(|command| command.render()).collect();
    assert!(rendered.iter().all(|line| !line.contains("-6")), "{rendered:?}");
    assert!(plan
        .up
        .iter()
        .map(|command| command.render())
        .all(|line| !line.contains("::/0")));

    let yaml = format!(
        "mixed-port: {}\ntun: {{enable: true, inet6-address: ['2001:db8::1/126'], route-address: ['10.0.0.0/8', '2001:db8:1::/48']}}\nrules: ['MATCH,DIRECT']\n",
        free_port()
    );
    let loaded = load_config(&yaml, "t").unwrap();
    let addresses = DeviceAddresses::from_config(&loaded.config);
    assert_eq!(addresses.v6[0].to_string(), "2001:db8::1/126");
    let plan = route_plan::plan(
        Platform::Linux,
        "billow0",
        &loaded.config.tun,
        &addresses,
        Some(&physical()),
        1500,
    )
    .unwrap();
    let up: Vec<String> = plan.up.iter().map(|command| command.render()).collect();
    assert!(up.contains(&"ip -6 route add 2001:db8:1::/48 dev billow0 table 2022".to_string()), "{up:?}");
    assert!(plan
        .address
        .iter()
        .map(|command| command.render())
        .any(|line| line.contains("2001:db8::1/126")));
}

#[test]
fn device_address_comes_from_fake_ip_range() {
    let yaml = format!(
        "mixed-port: {}\ndns: {{fake-ip-range: '10.1.2.3/8'}}\ntun: {{enable: true}}\nrules: ['MATCH,DIRECT']\n",
        free_port()
    );
    let loaded = load_config(&yaml, "t").unwrap();
    let addresses = DeviceAddresses::from_config(&loaded.config);
    assert_eq!(addresses.v4.to_string(), "10.1.2.3/30");
}

#[test]
fn dns_plans_construct_and_restore() {
    let v4 = Some("198.18.0.2".parse().unwrap());
    let v6 = Some("fdfe:dcba:9876::2".parse().unwrap());
    let linux = route_plan::plan_dns_linux("billow0", v4, v6);
    let up: Vec<String> = linux.up.iter().map(|command| command.render()).collect();
    assert_eq!(
        up,
        vec![
            "resolvectl dns billow0 198.18.0.2 fdfe:dcba:9876::2",
            "resolvectl domain billow0 ~.",
            "resolvectl default-route billow0 true",
        ]
    );
    assert_eq!(
        linux.down.iter().map(|command| command.render()).collect::<Vec<_>>(),
        vec!["resolvectl revert billow0"]
    );
    let mac = route_plan::plan_dns_macos("Wi-Fi", &[], v4, v6);
    assert_eq!(
        mac.down.iter().map(|command| command.render()).collect::<Vec<_>>(),
        vec!["networksetup -setdnsservers Wi-Fi Empty"]
    );
    let restored = route_plan::plan_dns_macos("Wi-Fi", &["1.1.1.1".to_string()], v4, None);
    assert_eq!(
        restored.down.iter().map(|command| command.render()).collect::<Vec<_>>(),
        vec!["networksetup -setdnsservers Wi-Fi 1.1.1.1"]
    );
    let windows = route_plan::plan_dns_windows("Billow", &[], &["2001:db8::53".to_string()], v4, v6);
    assert!(windows
        .down
        .iter()
        .map(|command| command.render())
        .any(|line| line.contains("dhcp")));
    assert!(windows
        .down
        .iter()
        .map(|command| command.render())
        .any(|line| line.contains("2001:db8::53")));
}

#[test]
fn default_route_and_dns_probes_parse_each_platform() {
    let mac = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n";
    assert_eq!(
        route_plan::parse_macos_default(mac),
        Some(DefaultRoute {
            interface: "en0".to_string(),
            gateway: Some("192.168.1.1".parse().unwrap())
        })
    );
    assert_eq!(
        route_plan::parse_linux_default("default via 192.168.1.1 dev en0 proto dhcp metric 100\n"),
        Some(DefaultRoute {
            interface: "en0".to_string(),
            gateway: Some("192.168.1.1".parse().unwrap())
        })
    );
    assert_eq!(
        route_plan::parse_windows_default("Wi-Fi|192.168.1.1\r\n"),
        Some(DefaultRoute {
            interface: "Wi-Fi".to_string(),
            gateway: Some("192.168.1.1".parse().unwrap())
        })
    );
    let order = "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n(2) USB\n(Hardware Port: USB, Device: en5)\n";
    assert_eq!(route_plan::parse_macos_service_order(order, "en5").as_deref(), Some("USB"));
    assert_eq!(
        route_plan::parse_macos_dns_servers("There aren't any DNS Servers set on Wi-Fi.\n"),
        Vec::<String>::new()
    );
    let netsh = "    Statically Configured DNS Servers: 1.1.1.1\n                                          8.8.8.8\n    Register with which suffix: Primary only\n";
    assert_eq!(
        route_plan::parse_windows_dns_servers(netsh),
        vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
    );
}

#[test]
fn a_failed_route_command_rolls_the_plan_back() {
    let tun = TunConfig {
        enable: true,
        ..TunConfig::default()
    };
    let plan = route_plan::plan(
        Platform::Linux,
        "billow0",
        &tun,
        &addresses(),
        Some(&physical()),
        1500,
    )
    .unwrap();
    let mut seen = Vec::new();
    let mut calls = 0usize;
    let result = apply_plan(&plan, &mut |command| {
        seen.push(command.render());
        calls += 1;
        if calls == 2 {
            return Err("simulated failure".to_string());
        }
        Ok(())
    });
    let error = result.unwrap_err();
    assert!(error.contains("simulated failure"), "{error}");
    for command in &plan.down {
        assert!(
            seen.contains(&command.render()),
            "rollback did not run {}; saw {seen:?}",
            command.render()
        );
    }
}

#[test]
fn start_with_tun_disabled_fails_before_creating_a_device() {
    let dir = test_dir("disabled");
    let config = format!("mixed-port: {}\ntun: {{enable: false}}\n", free_port());
    let error = DesktopTun::start(&config, dir.clone(), DesktopTunOptions::default())
        .err()
        .expect("disabled tun must not start");
    assert!(error.contains("tun.enable is false"), "{error}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Requires root/TunGrant; not run in this environment.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires root or the TunGrant setuid authorization to create a utun"]
fn real_utun_can_be_created_and_closed() {
    let dir = test_dir("utun");
    let config = format!(
        "mixed-port: {}\ntun: {{enable: true, auto-route: false, auto-detect-interface: false, dns-hijack: []}}\nrules: ['MATCH,DIRECT']\n",
        free_port()
    );
    let tun = DesktopTun::start(&config, dir.clone(), DesktopTunOptions::default())
        .expect("real utun needs authorization");
    assert!(tun.device_name().starts_with("utun"));
    tun.stop();
    let _ = std::fs::remove_dir_all(&dir);
}
