//! Routable OpenVPN peer for the T35 payload test.
//!
//! This is the **real payload** counterpart of `openvpn_peer.rs` (whose
//! `--dev null` server can only prove the control channel and AEAD keys):
//!
//! * Docker runs Ubuntu 22.04 OpenVPN as a real `--dev tun0` server, so
//!   `10.8.0.1` is routable inside the tunnel;
//! * socat echoes TCP on `10.8.0.1:7777` and UDP on `10.8.0.1:7778`;
//! * the Rust client loads an `OpenVpnOutbound` with `proto: tcp`, builds
//!   `openvpn::connect_stack`, dials a TCP stream and sends a UDP datagram
//!   through the shared L3 stack.
//!
//! Default-skipped (like the other controlled peers). Opt in with
//! `KC_OPENVPN_DOCKER=1`; without Docker/OpenSSL or without the opt-in the test
//! prints SKIP and does not count as a pass.
//!
//! ```sh
//! KC_OPENVPN_DOCKER=1 cargo test \
//!   --manifest-path native-kernel/Cargo.toml --locked \
//!   --test openvpn_docker -- --ignored --nocapture --test-threads=1
//! ```

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use billow_kernel::config::load_config;
use billow_kernel::outbound::openvpn;
use billow_kernel::proxies::Protocol;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const IMAGE: &str = "billow-openvpn-docker-t35:local";

fn docker(args: &[&str]) -> std::process::Output {
    Command::new("docker")
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("docker CLI is not available: {error}"))
}

fn docker_ok(args: &[&str]) -> bool {
    docker(args).status.success()
}

fn run_openssl(args: &[&str], directory: &Path) {
    let output = Command::new("openssl")
        .args(args)
        .current_dir(directory)
        .output()
        .expect("run openssl");
    assert!(
        output.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_file(path: &Path, contents: &[u8]) {
    let mut file = std::fs::File::create(path).expect("create certificate file");
    file.write_all(contents).expect("write certificate file");
}

fn make_ca(directory: &Path) {
    run_openssl(
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.crt",
            "-days",
            "2",
            "-subj",
            "/CN=Billow T35 OpenVPN CA",
        ],
        directory,
    );
}

fn make_leaf(directory: &Path, name: &str, server: bool) {
    run_openssl(
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.csr"),
            "-subj",
            &format!("/CN={name}"),
        ],
        directory,
    );
    // rustls rejects a certificate for an IP address unless the SAN contains
    // that IP; the client connects to 127.0.0.1.
    let extension = if server {
        "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"
    } else {
        "extendedKeyUsage=clientAuth\n"
    };
    write_file(&directory.join(format!("{name}.ext")), extension.as_bytes());
    run_openssl(
        &[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            "ca.crt",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            &format!("{name}.crt"),
            "-days",
            "2",
            "-extfile",
            &format!("{name}.ext"),
        ],
        directory,
    );
}

fn certificates(directory: &Path) {
    make_ca(directory);
    make_leaf(directory, "server", true);
    make_leaf(directory, "client", false);
}

fn free_host_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

struct Cleanup {
    name: String,
    directory: PathBuf,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn container_logs(name: &str) -> String {
    let output = docker(&["logs", name]);
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn wait_for_ready(name: &str, port: u16) {
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        let logs = container_logs(name);
        if logs.contains("READY") {
            break;
        }
        let running = docker(&["inspect", "-f", "{{.State.Running}}", name]);
        if String::from_utf8_lossy(&running.stdout).trim() != "true"
            || logs.contains("OPENVPN_EXITED")
            || logs.contains("TUN_NOT_READY")
        {
            panic!("openvpn container failed before READY:\n{logs}");
        }
        if Instant::now() >= deadline {
            panic!("openvpn container did not reach READY in 40s:\n{logs}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // READY is printed after socat binds, but the host proxy can lag slightly.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().expect("host addr"),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("host port {port} never accepted a connection");
}

fn indent(pem: &str, spaces: usize) -> String {
    let prefix = " ".repeat(spaces);
    pem.lines()
        .map(|line| format!("{prefix}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn openvpn_tun_payload_tcp_and_udp_echo() {
    const CASE: &str = "openvpn_tun_payload_tcp_and_udp_echo";
    if std::env::var("KC_OPENVPN_DOCKER").as_deref() != Ok("1") {
        // This case is `#[ignore]` in the normal suite. If it is explicitly
        // selected with `--ignored` but the opt-in is absent, fail instead of
        // reporting a pass without the real payload.
        panic!("{CASE}: set KC_OPENVPN_DOCKER=1 to run the Docker TUN payload case");
    }
    if !Command::new("openssl")
        .arg("version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
    {
        panic!("{CASE}: openssl is not available");
    }
    if !docker_ok(&["version"]) {
        panic!("{CASE}: docker daemon is not available");
    }

    let context = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tool/kernel-compat/peers/openvpn-docker");
    assert!(
        context.join("Dockerfile").is_file(),
        "missing Dockerfile at {}",
        context.display()
    );
    let build = Command::new("docker")
        .args([
            "build",
            "-q",
            "-t",
            IMAGE,
            "-f",
            &context.join("Dockerfile").display().to_string(),
            &context.display().to_string(),
        ])
        .output()
        .expect("run docker build");
    assert!(
        build.status.success(),
        "docker build failed:\n{}{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );

    // The daemon may not expose /dev/net/tun (or the image may run on a host
    // without it); that is an environment limitation and the case is skipped.
    let tun = docker(&[
        "run",
        "--rm",
        "--device",
        "/dev/net/tun",
        "--entrypoint",
        "/bin/sh",
        IMAGE,
        "-c",
        "test -c /dev/net/tun",
    ]);
    if !tun.status.success() {
        panic!(
            "{CASE}: /dev/net/tun is not available to the daemon: {}",
            String::from_utf8_lossy(&tun.stderr).trim()
        );
    }

    let port = free_host_port();
    let name = format!(
        "billow-ovpn-t35-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    let directory = std::env::temp_dir()
        .join("opencode")
        .join(format!("{name}-certs"));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("certificate directory");
    let cleanup = Cleanup {
        name: name.clone(),
        directory: directory.clone(),
    };
    certificates(&directory);

    let _ = Command::new("docker")
        .args(["rm", "-f", &name])
        .output();
    let created = Command::new("docker")
        .args([
            "create",
            "--name",
            &name,
            "--cap-add",
            "NET_ADMIN",
            "--device",
            "/dev/net/tun",
            "-p",
            &format!("127.0.0.1:{port}:1194"),
            IMAGE,
        ])
        .output()
        .expect("run docker create");
    if !created.status.success() {
        let _ = std::fs::remove_dir_all(&directory);
        panic!(
            "docker create failed:\n{}{}",
            String::from_utf8_lossy(&created.stdout),
            String::from_utf8_lossy(&created.stderr)
        );
    }
    // Copy the generated certificates into the created container instead of a
    // host bind mount: Docker Desktop's file sharing does not cover every
    // temporary directory, while `docker cp` is independent of it.
    let copied = Command::new("docker")
        .args([
            "cp",
            &format!("{}/.", directory.display()),
            &format!("{name}:/certs"),
        ])
        .output()
        .expect("run docker cp");
    assert!(
        copied.status.success(),
        "docker cp certificates failed:\n{}{}",
        String::from_utf8_lossy(&copied.stdout),
        String::from_utf8_lossy(&copied.stderr)
    );
    let started = Command::new("docker")
        .args(["start", &name])
        .output()
        .expect("run docker start");
    assert!(
        started.status.success(),
        "docker start failed:\n{}{}",
        String::from_utf8_lossy(&started.stdout),
        String::from_utf8_lossy(&started.stderr)
    );
    wait_for_ready(&name, port);

    let ca = std::fs::read_to_string(directory.join("ca.crt")).expect("ca");
    let cert = std::fs::read_to_string(directory.join("client.crt")).expect("client cert");
    let key = std::fs::read_to_string(directory.join("client.key")).expect("client key");
    let yaml = format!(
        "mixed-port: 1\nproxies:\n  - name: ov\n    type: openvpn\n    server: 127.0.0.1\n    port: {port}\n    proto: tcp\n    cipher: AES-256-GCM\n    auth: SHA256\n    ca: |\n{}\n    cert: |\n{}\n    key: |\n{}\nrules:\n  - 'MATCH,ov'\n",
        indent(&ca, 6),
        indent(&cert, 6),
        indent(&key, 6)
    );
    let loaded = load_config(&yaml, "openvpn-docker.yaml").expect("configuration loads");
    let option = loaded
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.name == "ov")
        .and_then(|proxy| match &proxy.protocol {
            Protocol::OpenVpn(option) => Some(option.clone()),
            _ => None,
        })
        .expect("openvpn outbound");

    let stack = tokio::time::timeout(
        Duration::from_secs(20),
        openvpn::connect_stack(&option, Duration::from_secs(15)),
    )
    .await
    .expect("connect_stack within 20s")
    .expect("connect_stack");
    assert_eq!(
        stack.ipv4(),
        Some(std::net::Ipv4Addr::new(10, 8, 0, 2)),
        "server pool must assign 10.8.0.2"
    );
    assert!(stack.ipv6().is_none());
    eprintln!("OPENVPN_DOCKER_LOCAL v4={:?} v6={:?}", stack.ipv4(), stack.ipv6());

    let tcp_target = "10.8.0.1:7777".parse().expect("tcp target");
    let mut tcp = tokio::time::timeout(
        Duration::from_secs(10),
        stack.dial_tcp(tcp_target, Duration::from_secs(10)),
    )
    .await
    .expect("TCP dial within 10s")
    .expect("TCP dial");
    tcp.write_all(b"hello-ovpn").await.expect("TCP write");
    let mut tcp_echo = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(10), tcp.read_exact(&mut tcp_echo))
        .await
        .expect("TCP echo within 10s")
        .expect("TCP echo");
    assert_eq!(&tcp_echo, b"hello-ovpn");
    eprintln!("OPENVPN_DOCKER_TCP_OK payload=hello-ovpn");

    let udp = stack.udp_socket().expect("UDP association");
    let udp_target = "10.8.0.1:7778".parse().expect("udp target");
    udp.send(udp_target, b"udp-ovpn").await.expect("UDP send");
    let mut udp_echo = [0u8; 64];
    let (from, read) = tokio::time::timeout(Duration::from_secs(10), udp.recv(&mut udp_echo))
        .await
        .expect("UDP echo within 10s")
        .expect("UDP echo");
    assert_eq!(from, udp_target);
    assert_eq!(&udp_echo[..read], b"udp-ovpn");
    eprintln!("OPENVPN_DOCKER_UDP_OK from={from} payload=udp-ovpn");

    drop(cleanup);
}
