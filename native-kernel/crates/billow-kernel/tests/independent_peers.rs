//! Independent SSR server interop.
//!
//! The default suite's SSR peer shares the Rust `SsrStream` implementation with
//! the client, so it proves framing only. This ignored test uses the Go server
//! in `tool/kernel-compat/peers/ssr-server`, which is written against the
//! pinned `transport/shadowsocks/shadowstream` package, to verify IV exchange,
//! the encrypted SOCKS address and the relay with an independent implementation.
//!
//! Controlled entry point (builds the Go server first):
//!
//! ```sh
//! tool/kernel-compat/family-peers.sh
//! ```
//!
//! Without `KC_SSR_PEER_BIN` the cases print SKIP and never pass.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use billow_kernel::{Kernel, Limits};

struct SsrPeer {
    child: Child,
    addr: SocketAddr,
}

impl Drop for SsrPeer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut buffer = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buffer) {
                    if n == 0 || stream.write_all(&buffer[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

fn start_peer(cipher: &str, password: &str) -> SsrPeer {
    let bin = std::env::var_os("KC_SSR_PEER_BIN").expect("KC_SSR_PEER_BIN");
    let port = free_port();
    let mut child = Command::new(bin)
        .args([
            "-listen",
            &format!("127.0.0.1:{port}"),
            "-cipher",
            cipher,
            "-password",
            password,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ssr peer");
    let stdout = child.stdout.take().expect("peer stdout");
    let mut lines = BufReader::new(stdout).lines();
    let ready = lines.next().expect("peer READY line").expect("peer READY");
    assert!(ready.starts_with("READY "), "peer said: {ready}");
    SsrPeer {
        child,
        addr: format!("127.0.0.1:{port}").parse().unwrap(),
    }
}

fn start_kernel(peer_port: u16, cipher: &str, password: &str) -> (Kernel, SocketAddr) {
    let port = free_port();
    let yaml = format!(
        "mixed-port: {port}\nlog-level: warn\nproxies:\n  - {{name: p, type: ssr, server: 127.0.0.1, port: {peer_port}, cipher: {cipher}, password: {password}, protocol: origin, obfs: plain}}\nrules:\n  - 'MATCH,p'\n"
    );
    let (kernel, _) = Kernel::start_from_yaml(&yaml, None, Limits::default()).unwrap();
    let listen = kernel.listen_addr();
    (kernel, listen)
}

fn connect(proxy: SocketAddr, target: &str, marker: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(proxy)?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        head.push(byte[0]);
    }
    let status = String::from_utf8_lossy(&head)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    if !status.starts_with("HTTP/1.1 200") {
        return Err(std::io::Error::other(status));
    }
    stream.write_all(marker)?;
    let mut back = vec![0u8; marker.len()];
    stream.read_exact(&mut back)?;
    Ok(back)
}

#[test]
#[ignore = "needs the Go SSR server: run tool/kernel-compat/family-peers.sh"]
fn ssr_go_server_relays_the_client_frames() {
    let Some(_) = std::env::var_os("KC_SSR_PEER_BIN") else {
        eprintln!("SKIP ssr_go_server_relays_the_client_frames (set KC_SSR_PEER_BIN; run tool/kernel-compat/family-peers.sh)");
        return;
    };
    let echo = spawn_echo();
    let peer = start_peer("aes-256-cfb", "ssr-go-pass");
    let (mut kernel, proxy) = start_kernel(peer.addr.port(), "aes-256-cfb", "ssr-go-pass");
    let back = connect(proxy, &format!("127.0.0.1:{echo}"), b"independent-ssr-go")
        .expect("tunnel through the Go SSR server");
    assert_eq!(back, b"independent-ssr-go".to_vec());
    kernel.stop().unwrap();
}

#[test]
#[ignore = "needs the Go SSR server: run tool/kernel-compat/family-peers.sh"]
fn ssr_go_server_rejects_a_wrong_password() {
    let Some(_) = std::env::var_os("KC_SSR_PEER_BIN") else {
        eprintln!("SKIP ssr_go_server_rejects_a_wrong_password (set KC_SSR_PEER_BIN; run tool/kernel-compat/family-peers.sh)");
        return;
    };
    let echo = spawn_echo();
    let peer = start_peer("aes-256-cfb", "right-password");
    let (mut kernel, proxy) = start_kernel(peer.addr.port(), "aes-256-cfb", "wrong-password");
    let error = connect(proxy, &format!("127.0.0.1:{echo}"), b"must-not-arrive");
    assert!(error.is_err(), "wrong password must not relay: {error:?}");
    kernel.stop().unwrap();
}


// ---------------------------------------------------------------------------
// SSR plugin layers: the Go peer above (`tool/kernel-compat/peers/ssr-plugins`)
// is the server side of the pinned `protocol/*` and `obfs/*` wire formats. That
// program also runs the *pinned* client packages against itself
// (`-client`), so a case here checks the Rust framing against a peer whose
// framing is checked against the locked implementation, not against a second
// Rust implementation.
// ---------------------------------------------------------------------------

struct PluginPeer {
    child: Child,
    addr: SocketAddr,
}

impl Drop for PluginPeer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn plugin_bin() -> Option<std::ffi::OsString> {
    std::env::var_os("KC_SSR_PLUGINS_BIN")
}

fn start_plugin_peer(
    protocol: &str,
    protocol_param: Option<&str>,
    obfs: &str,
    cipher: &str,
    password: &str,
    udp: bool,
) -> PluginPeer {
    let bin = plugin_bin().expect("KC_SSR_PLUGINS_BIN");
    let port = free_port();
    let mut args = vec![
        "-listen".to_string(),
        format!("127.0.0.1:{port}"),
        "-cipher".to_string(),
        cipher.to_string(),
        "-password".to_string(),
        password.to_string(),
        "-protocol".to_string(),
        protocol.to_string(),
        "-obfs".to_string(),
        obfs.to_string(),
    ];
    if std::env::var_os("KC_SSR_PEER_DEBUG").is_some() {
        args.insert(0, "-debug".to_string());
    }
    if let Some(param) = protocol_param {
        args.push("-protocol-param".to_string());
        args.push(param.to_string());
    }
    if udp {
        args.push("-udp".to_string());
    }
    let mut child = Command::new(bin)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn ssr plugin peer");
    let stdout = child.stdout.take().expect("peer stdout");
    let mut lines = BufReader::new(stdout).lines();
    let ready = lines.next().expect("peer READY line").expect("peer READY");
    assert!(ready.starts_with("READY "), "peer said: {ready}");
    PluginPeer {
        child,
        addr: format!("127.0.0.1:{port}").parse().unwrap(),
    }
}

fn start_plugin_kernel(
    peer_port: u16,
    cipher: &str,
    password: &str,
    protocol: &str,
    protocol_param: Option<&str>,
    obfs: &str,
    obfs_param: Option<&str>,
    udp: bool,
) -> (Kernel, SocketAddr) {
    let port = free_port();
    let mut proxy = format!(
        "{{name: p, type: ssr, server: 127.0.0.1, port: {peer_port}, cipher: {cipher}, password: {password}, protocol: {protocol}, obfs: {obfs}"
    );
    if let Some(param) = protocol_param {
        proxy.push_str(&format!(", protocol-param: '{param}'"));
    }
    if let Some(param) = obfs_param {
        proxy.push_str(&format!(", obfs-param: '{param}'"));
    }
    if udp {
        proxy.push_str(", udp: true");
    }
    proxy.push('}');
    let yaml = format!(
        "mixed-port: {port}\nlog-level: warn\nproxies:\n  - {proxy}\nrules:\n  - 'MATCH,p'\n"
    );
    let (kernel, _) = Kernel::start_from_yaml(&yaml, None, Limits::default()).unwrap();
    let listen = kernel.listen_addr();
    (kernel, listen)
}

#[test]
#[ignore = "needs the Go SSR plugin peer: run tool/kernel-compat/family-peers.sh"]
fn ssr_plugin_matrix_relays_with_every_protocol_and_obfs() {
    let Some(_) = plugin_bin() else {
        eprintln!("SKIP ssr_plugin_matrix (set KC_SSR_PLUGINS_BIN; run tool/kernel-compat/family-peers.sh)");
        return;
    };
    let echo = spawn_echo();
    let protocols = [
        "origin",
        "auth_sha1_v4",
        "auth_aes128_md5",
        "auth_aes128_sha1",
        "auth_chain_a",
        "auth_chain_b",
    ];
    let obfs_list = [
        "plain",
        "http_simple",
        "http_post",
        "random_head",
        "tls1.2_ticket_auth",
        "tls1.2_ticket_fastauth",
    ];
    let only = std::env::var("KC_SSR_ONLY").ok();
    for protocol in protocols {
        for obfs in obfs_list {
            if let Some(only) = &only {
                if only != &format!("{protocol}/{obfs}") {
                    continue;
                }
            }
            let peer = start_plugin_peer(protocol, None, obfs, "aes-256-cfb", "ssr-plugin-pass", false);
            let (mut kernel, proxy) = start_plugin_kernel(
                peer.addr.port(),
                "aes-256-cfb",
                "ssr-plugin-pass",
                protocol,
                None,
                obfs,
                None,
                false,
            );
            let marker = format!("ssr-{protocol}-{obfs}").into_bytes();
            let back = connect(proxy, &format!("127.0.0.1:{echo}"), &marker)
                .unwrap_or_else(|e| panic!("{protocol}/{obfs}: {e}"));
            assert_eq!(back, marker, "{protocol}/{obfs}");
            kernel.stop().unwrap();
        }
    }
}

#[test]
#[ignore = "needs the Go SSR plugin peer: run tool/kernel-compat/family-peers.sh"]
fn ssr_plugin_wrong_password_never_relays() {
    let Some(_) = plugin_bin() else {
        eprintln!("SKIP ssr_plugin_wrong_password (set KC_SSR_PLUGINS_BIN; run tool/kernel-compat/family-peers.sh)");
        return;
    };
    let echo = spawn_echo();
    for protocol in [
        "auth_sha1_v4",
        "auth_aes128_md5",
        "auth_aes128_sha1",
        "auth_chain_a",
        "auth_chain_b",
    ] {
        for obfs in ["plain", "tls1.2_ticket_auth"] {
            let peer = start_plugin_peer(protocol, None, obfs, "aes-256-cfb", "right-password", false);
            let (mut kernel, proxy) = start_plugin_kernel(
                peer.addr.port(),
                "aes-256-cfb",
                "wrong-password",
                protocol,
                None,
                obfs,
                None,
                false,
            );
            let error = connect(proxy, &format!("127.0.0.1:{echo}"), b"must-not-arrive");
            assert!(
                error.is_err(),
                "{protocol}/{obfs}: a wrong password must not relay: {error:?}"
            );
            kernel.stop().unwrap();
        }
    }
}

#[test]
#[ignore = "needs the Go SSR plugin peer: run tool/kernel-compat/family-peers.sh"]
fn ssr_plugin_protocol_param_and_large_payloads() {
    let Some(_) = plugin_bin() else {
        eprintln!("SKIP ssr_plugin_protocol_param (set KC_SSR_PLUGINS_BIN; run tool/kernel-compat/family-peers.sh)");
        return;
    };
    let echo = spawn_echo();
    // A user id / key parameter selects the derived user key; a payload larger
    // than the per-record chunk (8100 for auth_aes128, 2800 for auth_chain)
    // forces several records in one write.
    for (protocol, chunk) in [
        ("auth_aes128_sha1", 8100),
        ("auth_chain_a", 2800),
        ("auth_chain_b", 2800),
    ] {
        let peer = start_plugin_peer(
            protocol,
            Some("1234:user-key"),
            "http_simple",
            "aes-256-cfb",
            "param-pass",
            false,
        );
        let (mut kernel, proxy) = start_plugin_kernel(
            peer.addr.port(),
            "aes-256-cfb",
            "param-pass",
            protocol,
            Some("1234:user-key"),
            "http_simple",
            None,
            false,
        );
        let mut marker = b"ssr-large-".to_vec();
        marker.extend(std::iter::repeat(b'x').take(chunk * 2 + 7));
        let back = connect(proxy, &format!("127.0.0.1:{echo}"), &marker)
            .unwrap_or_else(|e| panic!("{protocol}: {e}"));
        assert_eq!(back, marker, "{protocol}");
        kernel.stop().unwrap();
    }
}


// ---------------------------------------------------------------------------
// SSR UDP: the pinned outbound builds `cipher.PacketConn` then
// `protocol.PacketConn`, so a datagram is `IV || cipher(protocol packet)` with
// the SOCKS5 address inside and no obfs layer. The Go peer decrypts it with the
// pinned cipher and the mirrored protocol packet codec.
// ---------------------------------------------------------------------------

fn udp_echo() -> (u16, Arc<AtomicU64>) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let seen = Arc::new(AtomicU64::new(0));
    let counter = seen.clone();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 65535];
        while let Ok((read, from)) = socket.recv_from(&mut buffer) {
            counter.fetch_add(read as u64, Ordering::Relaxed);
            let _ = socket.send_to(&buffer[..read], from);
        }
    });
    (port, seen)
}

fn udp_associate(proxy: SocketAddr) -> (std::net::TcpStream, SocketAddr) {
    let mut control =
        TcpStream::connect_timeout(&proxy, Duration::from_secs(5)).expect("control");
    control
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    control.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut selection = [0u8; 2];
    control.read_exact(&mut selection).unwrap();
    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0, "UDP associate refused: {reply:02x?}");
    let ip = std::net::Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
    let port = u16::from_be_bytes([reply[8], reply[9]]);
    (control, SocketAddr::from((ip, port)))
}

fn udp_roundtrip(relay: SocketAddr, target: SocketAddr, payload: &[u8], wait: Duration) -> Option<Vec<u8>> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut packet = vec![0u8, 0u8, 0u8, 0x01];
    match target.ip() {
        std::net::IpAddr::V4(v4) => packet.extend_from_slice(&v4.octets()),
        _ => return None,
    }
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    socket.send_to(&packet, relay).ok()?;
    socket.set_read_timeout(Some(wait)).ok()?;
    let mut buffer = [0u8; 65535];
    let (read, _) = socket.recv_from(&mut buffer).ok()?;
    assert!(read > 10, "reply too short: {read}");
    assert_eq!(buffer[3], 0x01, "reply header: {:02x?}", &buffer[..read]);
    Some(buffer[10..read].to_vec())
}

#[test]
#[ignore = "needs the Go SSR plugin peer: run tool/kernel-compat/family-peers.sh"]
fn ssr_udp_reaches_the_echo_for_every_protocol() {
    let Some(_) = plugin_bin() else {
        eprintln!("SKIP ssr_udp (set KC_SSR_PLUGINS_BIN; run tool/kernel-compat/family-peers.sh)");
        return;
    };
    let (echo_port, received) = udp_echo();
    let only = std::env::var("KC_SSR_ONLY").ok();
    for protocol in [
        "origin",
        "auth_sha1_v4",
        "auth_aes128_md5",
        "auth_aes128_sha1",
        "auth_chain_a",
        "auth_chain_b",
    ] {
        if let Some(only) = &only {
            if only != protocol {
                continue;
            }
        }
        // UDP has no obfs layer in the pinned outbound.
        let peer = start_plugin_peer(protocol, None, "plain", "aes-256-cfb", "ssr-udp-pass", true);
        let (mut kernel, proxy) = start_plugin_kernel(
            peer.addr.port(),
            "aes-256-cfb",
            "ssr-udp-pass",
            protocol,
            None,
            "plain",
            None,
            true,
        );
        let (control, relay) = udp_associate(proxy);
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().unwrap();
        let payload = format!("ssr-udp-{protocol}").into_bytes();
        let reply = udp_roundtrip(relay, target, &payload, Duration::from_secs(5))
            .unwrap_or_else(|| panic!("{protocol}: no UDP reply"));
        assert_eq!(reply, payload, "{protocol}");
        drop(control);
        kernel.stop().unwrap();
    }
    assert!(received.load(Ordering::Relaxed) > 0);
}

#[test]
#[ignore = "needs the Go SSR plugin peer: run tool/kernel-compat/family-peers.sh"]
fn ssr_udp_wrong_password_never_reaches_the_echo() {
    let Some(_) = plugin_bin() else {
        eprintln!("SKIP ssr_udp_wrong_password (set KC_SSR_PLUGINS_BIN; run tool/kernel-compat/family-peers.sh)");
        return;
    };
    let (echo_port, received) = udp_echo();
    let peer = start_plugin_peer("auth_chain_a", None, "plain", "aes-256-cfb", "right-udp", true);
    let (mut kernel, proxy) = start_plugin_kernel(
        peer.addr.port(),
        "aes-256-cfb",
        "wrong-udp",
        "auth_chain_a",
        None,
        "plain",
        None,
        true,
    );
    let (control, relay) = udp_associate(proxy);
    let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().unwrap();
    assert!(
        udp_roundtrip(relay, target, b"must-not-arrive", Duration::from_millis(800)).is_none(),
        "a wrong UDP password must not produce a reply"
    );
    assert_eq!(received.load(Ordering::Relaxed), 0);
    drop(control);
    kernel.stop().unwrap();
}
