//! Unit tests of the packet data plane that do not need a network peer.
//!
//! The end-to-end cases (TCP/UDP/DNS through a real listener) live in
//! `tests/ios_tunnel.rs`, because they start a kernel and real sockets.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::outbound::ipstack;

/// A free loopback port for the kernel's mixed listener. Every test gets its
/// own so the cases can run in parallel.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

fn config() -> String {
    format!("mixed-port: {}\nrules:\n  - MATCH,DIRECT\n", free_port())
}

/// A private directory with a `config.yaml`, so `reload` reads the same file
/// the tunnel started from.
fn test_dir() -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "billow-tunnel-test-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn test_tunnel(options: TunnelOptions) -> Tunnel {
    let dir = test_dir();
    let yaml = config();
    std::fs::write(dir.join("config.yaml"), &yaml).expect("config.yaml");
    Tunnel::start(&yaml, dir, options, None).expect("tunnel starts")
}

fn ipv4(src: [u8; 4], dst: [u8; 4], protocol: u8, payload: &[u8]) -> Vec<u8> {
    ipstack::build_packet(IpAddr::from(src), IpAddr::from(dst), protocol, payload, 64)
        .expect("packet builds")
}

/// An IPv4 header with a non-zero fragment offset (the stack refuses it).
fn fragment() -> Vec<u8> {
    let mut packet = ipv4(
        [198, 18, 0, 2],
        [93, 184, 216, 34],
        ipstack::IPPROTO_UDP,
        &[0u8; 8],
    );
    packet[6] = 0x20; // fragment offset 4 (non-zero) -> refused
    packet
}

#[test]
fn unsupported_ipv4_protocol_is_answered_with_icmp_protocol_unreachable() {
    let tunnel = test_tunnel(TunnelOptions::default());
    // Protocol 47 (GRE) has no handler in this stack.
    let packet = ipv4([198, 18, 0, 2], [93, 184, 216, 34], 47, &[0u8; 8]);
    assert_eq!(
        tunnel.ingest(&packet),
        Ingest::Dropped("unsupported IP protocol")
    );
    assert_eq!(tunnel.stats().unsupported_protocols, 1);
    let mut out = vec![0u8; 4096];
    let count = tunnel.drain_into(&mut out, 8);
    assert_eq!(count, 1, "one ICMP error is owed");
    let length = u32::from_be_bytes([out[0], out[1], out[2], out[3]]) as usize;
    let reply = &out[4..4 + length];
    let parsed = ipstack::parse_ip_packet(reply).expect("ICMP packet");
    assert_eq!(parsed.protocol, 1);
    assert_eq!(
        (parsed.src, parsed.dst),
        (
            IpAddr::from([93, 184, 216, 34]),
            IpAddr::from([198, 18, 0, 2])
        )
    );
    assert_eq!(parsed.payload[0], 3, "ICMP destination unreachable");
    assert_eq!(parsed.payload[1], 2, "protocol unreachable");
    tunnel.stop();
}

#[test]
fn fragments_are_refused_by_name_and_counted() {
    let tunnel = test_tunnel(TunnelOptions::default());
    assert_eq!(
        tunnel.ingest(&fragment()),
        Ingest::Dropped("unsupported or malformed IP packet")
    );
    let stats = tunnel.stats();
    assert_eq!(stats.fragments, 1);
    assert_eq!(stats.invalid_packets, 0);
    assert_eq!(tunnel.queued(), 0);
    tunnel.stop();
}

#[test]
fn icmp_is_counted_and_dropped() {
    let tunnel = test_tunnel(TunnelOptions::default());
    let packet = ipv4(
        [198, 18, 0, 2],
        [198, 18, 0, 1],
        1,
        &[8, 0, 0, 0, 0, 0, 0, 0],
    );
    assert_eq!(tunnel.ingest(&packet), Ingest::Dropped("ICMP"));
    assert_eq!(tunnel.stats().icmp_dropped, 1);
    tunnel.stop();
}

#[test]
fn malformed_packet_is_counted_and_dropped() {
    let tunnel = test_tunnel(TunnelOptions::default());
    assert_eq!(
        tunnel.ingest(&[0x45, 0x00, 0x00]),
        Ingest::Dropped("unsupported or malformed IP packet")
    );
    assert_eq!(tunnel.stats().invalid_packets, 1);
    tunnel.stop();
}

#[test]
fn stray_tcp_segment_gets_a_reset() {
    let tunnel = test_tunnel(TunnelOptions::default());
    let segment = build_segment(
        IpAddr::from([198, 18, 0, 2]),
        IpAddr::from([93, 184, 216, 34]),
        51_000,
        443,
        100,
        0,
        FLAG_ACK,
        65_535,
        None,
        b"stray",
    );
    let packet = ipv4(
        [198, 18, 0, 2],
        [93, 184, 216, 34],
        ipstack::IPPROTO_TCP,
        &segment,
    );
    assert_eq!(tunnel.ingest(&packet), Ingest::Dropped("no such TCP flow"));
    let mut out = vec![0u8; 4096];
    assert_eq!(tunnel.drain_into(&mut out, 8), 1, "one RST is owed");
    let length = u32::from_be_bytes([out[0], out[1], out[2], out[3]]) as usize;
    let parsed = ipstack::parse_ip_packet(&out[4..4 + length]).expect("RST packet");
    let segment = crate::outbound::tcp::parse_segment(&out[4..4 + length]).expect("RST segment");
    assert_eq!(segment.flags & FLAG_RST, FLAG_RST);
    assert_eq!(
        (parsed.src, parsed.dst),
        (
            IpAddr::from([93, 184, 216, 34]),
            IpAddr::from([198, 18, 0, 2])
        )
    );
    assert_eq!(tunnel.stats().tcp_rejected, 1);
    tunnel.stop();
}

#[test]
fn drain_frames_records_and_leaves_the_rest_queued() {
    let tunnel = test_tunnel(TunnelOptions::default());
    for protocol in [47u8, 48u8, 50u8] {
        let packet = ipv4([198, 18, 0, 2], [93, 184, 216, 34], protocol, &[0u8; 8]);
        assert_eq!(
            tunnel.ingest(&packet),
            Ingest::Dropped("unsupported IP protocol")
        );
    }
    let mut out = vec![0u8; 4096];
    assert_eq!(tunnel.drain_into(&mut out, 2), 2);
    assert_eq!(tunnel.queued(), 1);
    assert_eq!(tunnel.drain_into(&mut out, 8), 1);
    assert_eq!(tunnel.queued(), 0);
    // A buffer that cannot hold the record leaves it queued.
    let packet = ipv4([198, 18, 0, 2], [93, 184, 216, 34], 47, &[0u8; 8]);
    let _ = tunnel.ingest(&packet);
    let mut tiny = [0u8; 8];
    assert_eq!(tunnel.drain_into(&mut tiny, 8), 0);
    assert_eq!(tunnel.queued(), 1);
    tunnel.stop();
}

#[test]
fn egress_queue_is_bounded() {
    let options = TunnelOptions {
        packet_queue: 2,
        ..TunnelOptions::default()
    };
    let tunnel = test_tunnel(options);
    for protocol in [47u8, 48u8, 50u8] {
        let packet = ipv4([198, 18, 0, 2], [93, 184, 216, 34], protocol, &[0u8; 8]);
        let _ = tunnel.ingest(&packet);
    }
    let stats = tunnel.stats();
    assert_eq!(stats.queued_packets, 2);
    assert_eq!(stats.dropped_egress, 1);
    tunnel.stop();
}

#[test]
fn reload_keeps_the_engine_running_and_resets_flows() {
    let tunnel = test_tunnel(TunnelOptions::default());
    let warnings = tunnel.reload().expect("reload from the same file");
    assert!(warnings.is_empty(), "{warnings:?}");
    let stats = tunnel.stats();
    assert_eq!(stats.reloads, 1);
    assert_eq!(stats.generation, 1);
    assert_eq!(stats.tcp_flows, 0);
    assert_eq!(stats.udp_flows, 0);
    // The tunnel still answers after the reload.
    let packet = ipv4([198, 18, 0, 2], [93, 184, 216, 34], 47, &[0u8; 8]);
    assert_eq!(
        tunnel.ingest(&packet),
        Ingest::Dropped("unsupported IP protocol")
    );
    tunnel.stop();
}

#[test]
fn stats_are_serialisable_and_count_the_basics() {
    let tunnel = test_tunnel(TunnelOptions::default());
    let packet = ipv4([198, 18, 0, 2], [93, 184, 216, 34], 47, &[0u8; 8]);
    let _ = tunnel.ingest(&packet);
    let stats = tunnel.stats();
    assert_eq!(stats.in_packets, 1);
    assert_eq!(stats.in_bytes, packet.len() as u64);
    assert_eq!(stats.out_packets, 1);
    assert!(stats.queue_high >= 1);
    tunnel.stop();
}

#[test]
fn tcp_mss_follows_the_tunnel_mtu() {
    let tunnel = test_tunnel(TunnelOptions {
        mtu: 1400,
        ..TunnelOptions::default()
    });
    assert_eq!(tunnel.inner.mss(IpAddr::from([1, 2, 3, 4])), 1360);
    assert_eq!(
        tunnel.inner.mss(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
        1340
    );
    tunnel.stop();
}

#[test]
fn udp_flow_limit_drops_new_flows() {
    let options = TunnelOptions {
        max_udp_flows: 0,
        ..TunnelOptions::default()
    };
    let tunnel = test_tunnel(options);
    let datagram = ipstack::build_udp_packet(
        IpAddr::from([198, 18, 0, 2]),
        IpAddr::from([93, 184, 216, 34]),
        51_000,
        53,
        b"query",
        64,
    )
    .expect("datagram builds");
    // DNS hijack is off here (`dns.enable` is false), so it reaches the UDP
    // task and is refused by the flow limit.
    assert_eq!(tunnel.ingest(&datagram), Ingest::Accepted);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let stats = tunnel.stats();
        if stats.dropped_inbound >= 1 || std::time::Instant::now() > deadline {
            assert!(stats.dropped_inbound >= 1, "{stats:?}");
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    tunnel.stop();
}

#[test]
fn egress_callback_receives_packets() {
    struct Collector(Mutex<Vec<Vec<u8>>>);
    impl PacketSink for Collector {
        fn emit(&self, packet: &[u8]) -> bool {
            self.0.lock().unwrap().push(packet.to_vec());
            true
        }
    }
    let sink = Arc::new(Collector(Mutex::new(Vec::new())));
    let tunnel = Tunnel::start(
        &config(),
        PathBuf::from("."),
        TunnelOptions::default(),
        Some(sink.clone()),
    )
    .expect("tunnel starts");
    let packet = ipv4([198, 18, 0, 2], [93, 184, 216, 34], 47, &[0u8; 8]);
    let _ = tunnel.ingest(&packet);
    assert_eq!(sink.0.lock().unwrap().len(), 1);
    assert_eq!(tunnel.queued(), 0, "the callback path does not queue");
    assert_eq!(tunnel.stats().out_packets, 1);
    tunnel.stop();
}

#[test]
fn device_source_addresses_are_kept() {
    // A closed-port RST echoes the device 4-tuple, not a placeholder.
    let tunnel = test_tunnel(TunnelOptions::default());
    let segment = build_segment(
        IpAddr::from([198, 18, 0, 9]),
        IpAddr::from([93, 184, 216, 34]),
        12_345,
        8080,
        7,
        0,
        FLAG_ACK,
        65_535,
        None,
        b"",
    );
    let packet = ipv4(
        [198, 18, 0, 9],
        [93, 184, 216, 34],
        ipstack::IPPROTO_TCP,
        &segment,
    );
    let _ = tunnel.ingest(&packet);
    let mut out = vec![0u8; 4096];
    assert_eq!(tunnel.drain_into(&mut out, 8), 1);
    let length = u32::from_be_bytes([out[0], out[1], out[2], out[3]]) as usize;
    let segment = crate::outbound::tcp::parse_segment(&out[4..4 + length]).expect("RST segment");
    assert_eq!(segment.src, IpAddr::from([93, 184, 216, 34]));
    assert_eq!(segment.src_port, 8080);
    assert_eq!(segment.dst, IpAddr::from([198, 18, 0, 9]));
    assert_eq!(segment.dst_port, 12_345);
    let _ = SocketAddr::from(([198, 18, 0, 9], 12_345));
    tunnel.stop();
}
