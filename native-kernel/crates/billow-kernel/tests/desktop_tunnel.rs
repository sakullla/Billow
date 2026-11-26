//! Desktop TUN data plane tests (`feature = "desktop-tun"`).
//!
//! These cover the parts that do not need root/administrator rights:
//! configuration strictness, utun framing, the fd pump over a `UnixDatagram`
//! pair (whole IP packets both ways), route/interface command planning, the
//! default-route parsers and rollback on a failed command. A real utun creation
//! is `#[ignore]`d because this environment has no TUN authorization; the
//! Linux/Windows device code is compile-only here and is registered as such in
//! the evidence.

#![cfg(feature = "desktop-tun")]

use std::net::{IpAddr, Ipv4Addr, TcpListener, UdpSocket};
#[cfg(unix)]
use std::os::fd::IntoRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use billow_kernel::config::{load_config, TunConfig};
use billow_kernel::desktop_tun::apply_plan;
use billow_kernel::desktop_tun::framing::{strip_utun_header, with_utun_header, UtunError};
use billow_kernel::desktop_tun::pump::Pump;
use billow_kernel::desktop_tun::route_plan::{self, DefaultRoute, Platform};
use billow_kernel::desktop_tun::{device::Framing, DesktopTun, DesktopTunOptions};
use billow_kernel::outbound::ipstack;
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

#[test]
fn tun_config_accepts_the_billow_desktop_shape_and_rejects_by_name() {
    let yaml = format!(
        "mixed-port: {}\ntun:\n  enable: true\n  device: utun9\n  stack: gvisor\n  mtu: 1400\n  auto-route: true\n  auto-detect-interface: true\n  strict-route: false\n  dns-hijack: [any:53]\n  route-address: [10.0.0.0/8]\n  route-exclude-address: [192.168.0.0/16]\nrules: ['MATCH,DIRECT']\n",
        free_port()
    );
    let loaded = load_config(&yaml, "desktop-tun").expect("Billow desktop shape loads");
    let tun = loaded.config.tun;
    assert!(tun.enable);
    assert_eq!(tun.device, "utun9");
    assert_eq!(tun.stack, "gvisor");
    assert_eq!(tun.mtu, 1400);
    assert!(tun.auto_route && tun.auto_detect_interface && !tun.strict_route);
    assert_eq!(tun.dns_hijack, ["any:53"]);
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
    assert_eq!(tag("tun: {enable: true, mtu: 70000}\n"), "invalid_value");
    assert_eq!(tag("tun: {enable: true, route-address: ['10.0.0.1']}\n"), "invalid_value");
    assert!(tag("tun: {enable: true, route-address: ['10.0.0.0/33']}\n").starts_with("invalid"));
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
    // The engine starts before the sink is installed; wait until it listens.
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
    assert!(tunnel_stats.out_packets >= 1, "{tunnel_stats:?}");
    assert!(pump_stats.reads >= 1, "{pump_stats:?}");
    assert!(pump_stats.written >= 1, "{pump_stats:?}");
    tunnel.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn macos_linux_windows_route_plans_use_split_defaults() {
    let tun = TunConfig {
        enable: true,
        route_address: vec!["10.0.0.0/8".to_string()],
        route_exclude_address: vec!["192.168.0.0/16".to_string()],
        ..TunConfig::default()
    };
    let physical = DefaultRoute {
        interface: "en0".to_string(),
        gateway: Some("192.168.1.1".parse().unwrap()),
    };
    for platform in [Platform::Macos, Platform::Linux, Platform::Windows] {
        let plan = route_plan::plan(platform, "billow0", &tun, Some(&physical), 1400).unwrap();
        let up: Vec<String> = plan.up.iter().map(|command| command.render()).collect();
        let joined = up.join("\n");
        assert!(joined.contains("0.0.0.0/1"), "{platform:?}: {joined}");
        assert!(joined.contains("128.0.0.0/1"), "{platform:?}: {joined}");
        assert!(joined.contains("::/1"), "{platform:?}: {joined}");
        assert!(joined.contains("8000::/1"), "{platform:?}: {joined}");
        assert!(joined.contains("10.0.0.0/8"), "{platform:?}: {joined}");
        assert!(joined.contains("192.168.0.0/16"), "{platform:?}: {joined}");
        assert!(joined.contains("192.168.1.1"), "{platform:?}: {joined}");
        assert!(!plan.down.is_empty());
    }
    let mut off = tun.clone();
    off.auto_route = false;
    let plan = route_plan::plan(Platform::Linux, "billow0", &off, Some(&physical), 1500).unwrap();
    assert!(plan.up.iter().all(|command| {
        let rendered = command.render();
        !rendered.contains("0.0.0.0/1") && !rendered.contains("128.0.0.0/1") && !rendered.contains("8000::/1")
    }));
}

#[test]
fn default_route_probes_parse_each_platform() {
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
        route_plan::parse_windows_default("Wi-Fi\r\n192.168.1.1\r\n"),
        Some(DefaultRoute {
            interface: "Wi-Fi".to_string(),
            gateway: Some("192.168.1.1".parse().unwrap())
        })
    );
}

#[test]
fn a_failed_route_command_rolls_the_plan_back() {
    let tun = TunConfig {
        enable: true,
        route_exclude_address: Vec::new(),
        ..TunConfig::default()
    };
    let physical = DefaultRoute {
        interface: "en0".to_string(),
        gateway: Some("192.168.1.1".parse().unwrap()),
    };
    let plan = route_plan::plan(Platform::Linux, "billow0", &tun, Some(&physical), 1500).unwrap();
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
    let error = DesktopTun::start(
        &config,
        dir.clone(),
        DesktopTunOptions::default(),
    )
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
