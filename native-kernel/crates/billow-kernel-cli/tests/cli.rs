//! Drives the real `billow-kernel` process: start, forward via HTTP CONNECT and
//! SOCKS5, reject, stop with SIGINT and start again on the same port.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    // Kernel listener ports come from a range the OS does not use for
    // ephemeral binds (macOS and Linux pick `bind(0)` ports above 32,000), so a
    // peer's `bind(0)` cannot grab a just-released port before the kernel
    // binds it. The registry keeps the number unique within this process; a
    // busy slot is skipped.
    static PORTS: std::sync::Mutex<Option<std::collections::BTreeSet<u16>>> =
        std::sync::Mutex::new(None);
    static NEXT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(24_000);
    loop {
        let slot = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let port = 24_000 + slot.wrapping_sub(24_000) % 8_000;
        let mut ports = PORTS.lock().unwrap_or_else(|p| p.into_inner());
        let ports = ports.get_or_insert_with(std::collections::BTreeSet::new);
        if !ports.contains(&port) && TcpListener::bind(("127.0.0.1", port)).is_ok() {
            ports.insert(port);
            return port;
        }
    }
}

/// Loopback echo server in a background thread; returns its port.
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

/// Minimal SOCKS5 server for the CLI test: it dials the requested target and
/// relays bytes, recording the target it accepted. The CLI process is the
/// client here, so a tunnel through it proves the protocol outbound works in
/// the shipped entry point, not just in the library.
fn spawn_socks5_peer() -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use std::sync::{Arc, Mutex};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let log = log.clone();
            std::thread::spawn(move || {
                let mut stream = stream;
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut head = [0u8; 2];
                if stream.read_exact(&mut head).is_err() || head[0] != 0x05 {
                    return;
                }
                let mut methods = vec![0u8; head[1] as usize];
                if stream.read_exact(&mut methods).is_err() {
                    return;
                }
                if stream.write_all(&[0x05, 0x00]).is_err() {
                    return;
                }
                let mut request = [0u8; 4];
                if stream.read_exact(&mut request).is_err() || request[1] != 0x01 {
                    return;
                }
                let host = match request[3] {
                    0x01 => {
                        let mut addr = [0u8; 4];
                        stream.read_exact(&mut addr).unwrap();
                        std::net::Ipv4Addr::from(addr).to_string()
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        stream.read_exact(&mut len).unwrap();
                        let mut name = vec![0u8; len[0] as usize];
                        stream.read_exact(&mut name).unwrap();
                        String::from_utf8_lossy(&name).to_string()
                    }
                    _ => return,
                };
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).unwrap();
                let port = u16::from_be_bytes(port);
                log.lock().unwrap().push(format!("{host}:{port}"));
                let Ok(mut upstream) = TcpStream::connect((host.as_str(), port)) else {
                    let _ = stream.write_all(&[0x05, 0x05, 0, 1, 0, 0, 0, 0, 0, 0]);
                    return;
                };
                if stream
                    .write_all(&[0x05, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .is_err()
                {
                    return;
                }
                let (mut up_r, mut stream_w) =
                    (upstream.try_clone().unwrap(), stream.try_clone().unwrap());
                let back = std::thread::spawn(move || {
                    let _ = std::io::copy(&mut stream, &mut upstream);
                });
                let _ = std::io::copy(&mut up_r, &mut stream_w);
                let _ = back.join();
            });
        }
    });
    (port, seen)
}

struct KernelProcess {
    child: Child,
    config: PathBuf,
}

impl KernelProcess {
    fn start(rules: &[&str], port: u16) -> KernelProcess {
        let body = rules
            .iter()
            .map(|r| format!("  - '{r}'\n"))
            .collect::<String>();
        KernelProcess::start_body(&format!("rules:\n{body}"), port)
    }

    /// Start the process from the part of the YAML below the listener line.
    fn start_body(body: &str, port: u16) -> KernelProcess {
        let dir = std::env::temp_dir().join(format!("billow-cli-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.yaml");
        std::fs::write(
            &config,
            format!("mixed-port: {port}\nlog-level: info\n{body}"),
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_billow-kernel"))
            .arg(&config)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn billow-kernel");
        wait_for_port(port, &mut child);
        KernelProcess { child, config }
    }

    fn sigint(&mut self) -> std::process::Output {
        #[cfg(unix)]
        {
            unsafe {
                extern "C" {
                    fn kill(pid: i32, sig: i32) -> i32;
                }
                assert_eq!(kill(self.child.id() as i32, 2), 0, "send SIGINT");
            }
            wait_with_timeout(&mut self.child, Duration::from_secs(10))
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.kill();
            wait_with_timeout(&mut self.child, Duration::from_secs(10))
        }
    }
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> std::process::Output {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let mut stdout = String::new();
            let mut stderr = String::new();
            if let Some(mut out) = child.stdout.take() {
                let _ = out.read_to_string(&mut stdout);
            }
            if let Some(mut err) = child.stderr.take() {
                let _ = err.read_to_string(&mut stderr);
            }
            return std::process::Output {
                status,
                stdout: stdout.into_bytes(),
                stderr: stderr.into_bytes(),
            };
        }
        assert!(
            Instant::now() < deadline,
            "kernel did not exit within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_port(port: u16, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("wait for billow-kernel") {
            // The process has exited, so draining the pipes cannot block.
            let mut stdout = String::new();
            let mut stderr = String::new();
            if let Some(mut out) = child.stdout.take() {
                let _ = out.read_to_string(&mut stdout);
            }
            if let Some(mut err) = child.stderr.take() {
                let _ = err.read_to_string(&mut stderr);
            }
            panic!(
                "kernel exited with {status} before listening on {port}: {stdout}
{stderr}"
            );
        }
        if kernel_ready(port) {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("kernel never listened on {port}");
}

/// A bare TCP connect only proves *some* listener owns the port; the mixed
/// inbound's SOCKS5 method negotiation proves the kernel itself is serving.
/// The read timeout keeps a foreign listener from stalling the probe.
fn kernel_ready(port: u16) -> bool {
    let address: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(250)) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .is_err()
    {
        return false;
    }
    if stream.write_all(&[0x05, 0x01, 0x00]).is_err() {
        return false;
    }
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).is_ok() && reply == [0x05, 0x00]
}

/// Connect to the kernel's listener, retrying a refused connection for a short
/// while (the listener can be up a moment after the readiness probe under load;
/// a kernel that is gone still fails within the deadline).
fn connect_retry(proxy: SocketAddr) -> std::io::Result<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match TcpStream::connect_timeout(&proxy, Duration::from_secs(1)) {
            Ok(stream) => return Ok(stream),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                if Instant::now() >= deadline {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error),
        }
    }
}

fn http_connect(proxy: SocketAddr, authority: &str) -> std::io::Result<(TcpStream, String)> {
    let mut stream = connect_retry(proxy)?;
    stream.write_all(
        format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
    )?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let status = text.lines().next().unwrap_or_default().to_string();
    Ok((stream, status))
}

fn socks5_connect(proxy: SocketAddr, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut stream = connect_retry(proxy)?;
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection)?;
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request)?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply)?;
    if reply[1] != 0 {
        return Err(std::io::Error::other(format!(
            "socks reply 0x{:02x}",
            reply[1]
        )));
    }
    let mut rest = [0u8; 6];
    stream.read_exact(&mut rest)?;
    Ok(stream)
}

fn roundtrip(stream: &mut TcpStream, payload: &[u8]) -> Vec<u8> {
    stream.write_all(payload).unwrap();
    let mut got = vec![0u8; payload.len()];
    stream.read_exact(&mut got).unwrap();
    got
}

fn identity_line(stdout: &[u8]) -> String {
    String::from_utf8_lossy(stdout)
        .lines()
        .find(|line| line.starts_with("instance="))
        .unwrap_or_default()
        .to_string()
}

#[test]
fn process_forwards_both_protocols_rejects_and_restarts() {
    let echo_port = spawn_echo();
    let port = free_port();
    let rules = ["DOMAIN-SUFFIX,blocked.test,REJECT", "MATCH,DIRECT"];

    for round in 0..2 {
        let mut kernel = KernelProcess::start(&rules, port);
        let proxy: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        // HTTP CONNECT to the echo endpoint.
        let (mut tunnel, status) = http_connect(proxy, &format!("127.0.0.1:{echo_port}")).unwrap();
        assert_eq!(
            status, "HTTP/1.1 200 Connection Established",
            "round {round}"
        );
        assert_eq!(roundtrip(&mut tunnel, b"http-payload"), b"http-payload");
        drop(tunnel);

        // SOCKS5 to the same endpoint on the same port.
        let mut tunnel = socks5_connect(proxy, "127.0.0.1", echo_port).unwrap();
        assert_eq!(roundtrip(&mut tunnel, b"socks-payload"), b"socks-payload");
        drop(tunnel);

        // A REJECT rule blocks the request.
        let (_tunnel, status) = http_connect(proxy, &format!("blocked.test:{echo_port}")).unwrap();
        assert_eq!(status, "HTTP/1.1 403 Forbidden");

        let output = kernel.sigint();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        assert!(
            output.status.success(),
            "round {round} exit: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let identity = identity_line(&output.stdout);
        assert!(
            identity.contains(&format!("listen=127.0.0.1:{port}")),
            "{identity}"
        );
        assert!(identity.contains("version="), "{identity}");
        assert!(identity.contains("pid="), "{identity}");
        assert!(stdout.contains("completed="), "{stdout}");
        // The port is free again, so the next round can bind it.
        assert!(
            TcpListener::bind(("127.0.0.1", port)).is_ok(),
            "round {round}: port released after SIGINT"
        );
        let _ = std::fs::remove_file(&kernel.config);
    }
}

#[test]
fn process_rejects_unimplemented_config_and_exits_non_zero() {
    let dir = std::env::temp_dir().join(format!("billow-cli-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("bad.yaml");
    std::fs::write(
        &config,
        "mixed-port: 1\ndns:\n  enable: true\nrules:\n  - 'MATCH,DIRECT'\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_billow-kernel"))
        .arg(&config)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("[unsupported]"), "{stderr}");
    assert!(stderr.contains("'dns'"), "{stderr}");

    std::fs::write(&config, "mixed-port: 1\nrules:\n  - 'DSCP,4,DIRECT'\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_billow-kernel"))
        .arg(&config)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("rule type 'DSCP'"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_rejects_a_provider_path_outside_the_configuration_root() {
    let dir = std::env::temp_dir().join(format!("billow-cli-paths-{}", std::process::id()));
    let config_dir = dir.join("config");
    std::fs::create_dir_all(config_dir.join("providers")).unwrap();
    std::fs::write(config_dir.join("providers/domain.txt"), "+.inside.example\n").unwrap();
    std::fs::write(dir.join("outside.txt"), "+.outside.example\n").unwrap();
    let config = config_dir.join("config.yaml");
    let port = free_port();
    std::fs::write(
        &config,
        format!(
            "mixed-port: {port}\nrule-providers:\n  r:\n    type: file\n    behavior: domain\n    format: text\n    path: ../outside.txt\nrules: ['RULE-SET,r,REJECT', 'MATCH,DIRECT']\n"
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_billow-kernel"))
        .arg(&config)
        .arg("--check")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not a subpath"), "{stderr}");

    // The legal relative path resolves against the config directory and
    // passes --check.
    std::fs::write(
        &config,
        format!(
            "mixed-port: {port}\nrule-providers:\n  r:\n    type: file\n    behavior: domain\n    format: text\n    path: providers/domain.txt\nrules: ['RULE-SET,r,REJECT', 'MATCH,DIRECT']\n"
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_billow-kernel"))
        .arg(&config)
        .arg("--check")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("configuration accepted"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn process_forwards_through_a_protocol_outbound() {
    let (peer_port, seen) = spawn_socks5_peer();
    let echo_port = spawn_echo();
    let port = free_port();
    let kernel = KernelProcess::start_body(
        &format!(
            "proxies:\n  - {{name: p0, type: socks5, server: 127.0.0.1, port: {peer_port}}}\nrules:\n  - 'MATCH,p0'\n"
        ),
        port,
    );
    let proxy: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (mut tunnel, status) = http_connect(proxy, &format!("127.0.0.1:{echo_port}")).unwrap();
    assert_eq!(status, "HTTP/1.1 200 Connection Established");
    assert_eq!(
        roundtrip(&mut tunnel, b"cli-through-socks5"),
        b"cli-through-socks5"
    );
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        [format!("127.0.0.1:{echo_port}")]
    );
    drop(tunnel);
    let mut kernel = kernel;
    let output = kernel.sigint();
    assert!(output.status.success());
}

/// T9 families in the shipped process: the CLI loads VMess, Snell and
/// TrustTunnel outbounds, names them in its identity line, and a tunnel routed
/// to the first one fails with the inbound failure reply when the server is
/// absent (it never falls back to DIRECT). The successful path through each
/// family is exercised against the pinned Mihomo listener in
/// `mihomo_peers.rs`.
#[test]
fn process_loads_t9_outbounds() {
    let vmess_port = free_port();
    let snell_port = free_port();
    let port = free_port();
    let kernel = KernelProcess::start_body(
        &format!(
            "proxies:\n  - {{name: vm, type: vmess, server: 127.0.0.1, port: {vmess_port}, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, alterId: 0, cipher: auto}}\n  - {{name: sn, type: snell, server: 127.0.0.1, port: {snell_port}, psk: p, version: 2}}\n  - {{name: tt, type: trusttunnel, server: 127.0.0.1, port: {snell_port}, username: u, password: p}}\n  - {{name: gr, type: gost-relay, server: 127.0.0.1, port: {snell_port}, forward: true, username: u, password: p}}\n  - {{name: sh, type: ssh, server: 127.0.0.1, port: {snell_port}, username: u, password: p}}\n  - {{name: sr, type: ssr, server: 127.0.0.1, port: {snell_port}, cipher: aes-256-cfb, password: p, protocol: origin, obfs: plain}}\nrules:\n  - 'MATCH,vm'\n"
        ),
        port,
    );
    let proxy: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (mut tunnel, status) = http_connect(proxy, "127.0.0.1:9").unwrap();
    assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
    let _ = tunnel.write_all(b"unused");
    drop(tunnel);
    let mut kernel = kernel;
    let output = kernel.sigint();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("vm=vmess"), "{stdout}");
    assert!(stdout.contains("sn=snell"), "{stdout}");
    assert!(stdout.contains("tt=trusttunnel"), "{stdout}");
    assert!(stdout.contains("gr=gost-relay"), "{stdout}");
    assert!(stdout.contains("sh=ssh"), "{stdout}");
    assert!(stdout.contains("sr=ssr"), "{stdout}");
}

/// T13 families in the shipped process: mieru and sudoku load from the same
/// configuration surface as the library, appear in the identity line, and a
/// tunnel routed to them fails with the inbound reply when the server port is
/// closed (they never fall back to DIRECT). The successful paths run against
/// the pinned Mihomo listeners in `mihomo_peers.rs`.
#[test]
fn process_loads_t13_outbounds() {
    let mieru_port = free_port();
    let sudoku_port = free_port();
    let port = free_port();
    let kernel = KernelProcess::start_body(
        &format!(
            "proxies:\n  - {{name: mi, type: mieru, server: 127.0.0.1, port: {mieru_port}, transport: TCP, username: u, password: p}}\n  - {{name: su, type: sudoku, server: 127.0.0.1, port: {sudoku_port}, key: \"cli-key\"}}\nrules:\n  - 'MATCH,mi'\n"
        ),
        port,
    );
    let proxy: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (mut tunnel, status) = http_connect(proxy, "127.0.0.1:9").unwrap();
    assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
    let _ = tunnel.write_all(b"unused");
    drop(tunnel);
    let mut kernel = kernel;
    let output = kernel.sigint();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("mi=mieru"), "{stdout}");
    assert!(stdout.contains("su=sudoku"), "{stdout}");
}

/// T14 family in the shipped process: a masque CONNECT-UDP outbound loads from
/// the same configuration surface as the library and appears in the identity
/// line. A TCP tunnel routed to it is refused by name (CONNECT-IP needs an IP
/// stack), and the process stays up; the UDP path is exercised in
/// `tests/quic_peers.rs` against the controlled HTTP/3 peer.
#[test]
fn process_loads_t15_shadowquic() {
    let port = free_port();
    let mut kernel = KernelProcess::start_body(
        "proxies:\n  - {name: sq, type: shadowquic, server: 127.0.0.1, port: 1, username: alice, password: secret, sni: localhost, udp-over-stream: false}\nrules:\n  - 'MATCH,sq'\n",
        port,
    );
    let output = kernel.sigint();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("sq=shadowquic"), "{stdout}");
}

/// T18/T21: the pinned Cloudflare WARP CONNECT-IP shape loads in the shipped
/// process (keys, local addresses, URI, MTU, resolver options); a TCP tunnel
/// with no reachable CONNECT-IP endpoint fails as a 502 and the process stays
/// up. The UDP and TCP data paths are exercised against CONNECT-IP peers in
/// `tests/family_cli.rs` and `tests/quic_peers.rs`.
#[test]
fn process_loads_t18_masque_connect_ip() {
    // Throwaway P-256 SEC1 key and endpoint SPKI (base64), as the pinned
    // adapter's x509 parsers read them.
    let key = "MHcCAQEEIDKh56LbUI7PTfKO5ojiPkNrK2H8jcLrmfdlhv3TsqRzoAoGCCqGSM49AwEHoUQDQgAEMAUkhPqJXQGTsDj6a3yC7F2zxIWXs6UJCc/Mwr6wL3GWgqbrP6tvB52ZUbnalrJXSxMwUFXDTHNqxPhpzzUawA==";
    let endpoint_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMAUkhPqJXQGTsDj6a3yC7F2zxIWXs6UJCc/Mwr6wL3GWgqbrP6tvB52ZUbnalrJXSxMwUFXDTHNqxPhpzzUawA==";
    let masque_port = free_port();
    let port = free_port();
    let kernel = KernelProcess::start_body(
        &format!(
            "proxies:\n  - {{name: mq, type: masque, server: 127.0.0.1, port: {masque_port}, udp: true, private-key: '{key}', public-key: '{endpoint_key}', ip: 172.16.0.2, ipv6: fd00::2, uri: https://cloudflareaccess.com, mtu: 1280, ip-stack: {{mode: auto}}, remote-dns-resolve: true, dns: [1.1.1.1]}}\nrules:\n  - 'MATCH,mq'\n"
        ),
        port,
    );
    let proxy: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (mut tunnel, status) = http_connect(proxy, "127.0.0.1:9").unwrap();
    assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
    let _ = tunnel.write_all(b"unused");
    drop(tunnel);
    let mut kernel = kernel;
    let output = kernel.sigint();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("mq=masque"), "{stdout}");
}

/// T16/T19/T20 mesh adapters in the shipped process: every control-plane
/// adapter loads from the same configuration surface as the library and
/// appears in the identity line. Their `dial()` needs the T6/T7 device layer,
/// so no tunnel is started here; the protocol layers are exercised against
/// pinned/controlled peers in `mesh_peers.rs`, `wireguard_peer.rs` and
/// `openvpn_peer.rs`.
#[test]
fn process_loads_mesh_adapters() {
    let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let ca = "-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----";
    let port = free_port();
    let kernel = KernelProcess::start_body(
        &format!(
            "proxies:\n  - {{name: wg, type: wireguard, private-key: {key}, ip: 10.13.13.2, peers: [{{server: 127.0.0.1, port: 51820, public-key: {key}, allowed-ips: [0.0.0.0/0]}}]}}\n  - {{name: ov, type: openvpn, server: 127.0.0.1, port: 1194, ca: \"{ca}\"}}\n  - {{name: ts, type: tailscale, server: 127.0.0.1, port: 1}}\n  - {{name: zt, type: zerotier, network: 8056c2e21c000001}}\n  - {{name: et, type: easytier, network-name: billow-test, network-secret: s, peers: ['udp://127.0.0.1:11010']}}\nrules:\n  - 'MATCH,wg'\n"
        ),
        port,
    );
    let mut kernel = kernel;
    let output = kernel.sigint();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for name in ["wg=wireguard", "ov=openvpn", "ts=tailscale", "zt=zerotier", "et=easytier"] {
        assert!(stdout.contains(name), "{name}: {stdout}");
    }
}

#[test]
fn process_loads_t14_masque() {
    let masque_port = free_port();
    let port = free_port();
    let kernel = KernelProcess::start_body(
        &format!(
            "proxies:\n  - {{name: mq, type: masque, server: 127.0.0.1, port: {masque_port}, udp: true, skip-cert-verify: true}}\nrules:\n  - 'MATCH,mq'\n"
        ),
        port,
    );
    let proxy: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (mut tunnel, status) = http_connect(proxy, "127.0.0.1:9").unwrap();
    assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
    let _ = tunnel.write_all(b"unused");
    drop(tunnel);
    let mut kernel = kernel;
    let output = kernel.sigint();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("mq=masque"), "{stdout}");
}
