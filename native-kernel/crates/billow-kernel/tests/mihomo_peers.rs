//! Real-peer interoperability against the pinned Mihomo v1.19.34 binary.
//!
//! The kernel (Rust) is the client: its mixed inbound gets a tagged request,
//! a rule selects one configured proxy, and that proxy *is* a Mihomo listener
//! (`listeners:` socks / http / shadowsocks / trojan / vless / anytls) which
//! forwards to a controlled sink. Each test reads what the sink actually
//! received and the negative cases (wrong credentials, untrusted certificate,
//! protocol mismatch) must not reach it.
//!
//! Requirements: the pinned Mihomo executable (`KC_MIHOMO_BIN`) and the openssl
//! CLI (or `KC_CERT_DIR` with `cert.pem`/`key.pem`). The cases are `#[ignore]`d
//! by default so the default suite neither fails nor implies interop it did not
//! run; the controlled command is
//!
//! ```sh
//! KC_MIHOMO_BIN=tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
//!   cargo test --manifest-path native-kernel/Cargo.toml --locked \
//!   --test mihomo_peers -- --ignored --test-threads=1
//! ```
//!
//! Without the binary an explicitly requested run prints a SKIP line and
//! returns; a skip is never a pass.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use billow_kernel::{Kernel, Limits};

#[allow(dead_code)]
mod common;

/// Set `KC_KERNEL_LOG=1` to see the kernel's own warnings (an outbound dial
/// failure is logged there, which is what a failing case needs).
fn install_kernel_log() {
    let level = match std::env::var("KC_KERNEL_LOG").ok().as_deref() {
        None => return,
        Some("debug") => tracing::Level::DEBUG,
        Some(_) => tracing::Level::WARN,
    };
    struct Printer {
        level: tracing::Level,
    }
    struct Fields(String);
    impl tracing::field::Visit for Fields {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, " {}={:?}", field.name(), value);
        }
    }
    impl tracing::Subscriber for Printer {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            *metadata.level() <= self.level
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if !self.enabled(event.metadata()) {
                return;
            }
            let mut fields = Fields(String::new());
            event.record(&mut fields);
            eprintln!("[kernel {} {}]{}", event.metadata().level(), event.metadata().target(), fields.0);
        }
    }
    let _ = tracing::subscriber::set_global_default(Printer { level });
}

// Credentials shared with the differential fixtures (fixed, local only).
const SS_PASSWORD: &str = "vlmpIPSyHH6f4S8WVPdRIHIlzmB+GIRfoH3aNJ/t9Gg=";
const TROJAN_PASSWORD: &str = "9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68";
const ANYTLS_PASSWORD: &str = "9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68";
const UUID: &str = "9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68";
const SOCKS_USER: &str = "alice";
const SOCKS_PASSWORD: &str = "vlmpIPSyHH6f4S8WVPdRIHIlzmB+GIRfoH3aNJ/t9Gg=";

fn mihomo_bin() -> Option<PathBuf> {
    std::env::var_os("KC_MIHOMO_BIN").map(PathBuf::from)
}

fn free_port() -> u16 {
    common::free_port()
}

/// `cert.pem`/`key.pem` for the TLS listeners, from `KC_CERT_DIR` or openssl.
/// Serialised because the suite starts its Mihomo instances in parallel and
/// concurrent `openssl` runs into one directory produce a truncated pair.
fn cert_dir() -> Option<PathBuf> {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(dir) = std::env::var_os("KC_CERT_DIR") {
        let dir = PathBuf::from(dir);
        if dir.join("cert.pem").is_file() && dir.join("key.pem").is_file() {
            return Some(dir);
        }
    }
    let dir = std::env::temp_dir().join(format!("billow-peers-cert-{}", std::process::id()));
    if dir.join("cert.pem").is_file() && dir.join("key.pem").is_file() {
        return Some(dir);
    }
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).ok()?;
    let status = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes"])
        .arg("-keyout")
        .arg(dir.join("key.pem"))
        .arg("-out")
        .arg(dir.join("cert.pem"))
        .args(["-days", "1", "-subj", "/CN=billow-peers"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    (status.success() && dir.join("cert.pem").is_file() && dir.join("key.pem").is_file())
        .then_some(dir)
}

struct Mihomo {
    child: Child,
    dir: PathBuf,
    config: String,
}

impl Mihomo {
    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("mihomo.log")).unwrap_or_default()
    }
}

impl Drop for Mihomo {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Start Mihomo with `listeners` (YAML lines; `CERT`/`KEY` become the PEM
/// names copied next to the config) forwarding to a sink through a local HTTP
/// proxy, and wait until every listener accepts a connection.
fn start_mihomo(
    bin: PathBuf,
    certs: PathBuf,
    sink_port: u16,
    listeners: &str,
    rule: &str,
    socks_port: Option<u16>,
) -> Option<Mihomo> {
    let dir = std::env::temp_dir().join(format!(
        "billow-peers-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).ok()?;
    std::fs::copy(certs.join("cert.pem"), dir.join("cert.pem")).ok()?;
    std::fs::copy(certs.join("key.pem"), dir.join("key.pem")).ok()?;
    let listeners = listeners
        .replace("CERT", "cert.pem")
        .replace("KEY", "key.pem");
    let socks_line = socks_port
        .map(|port| format!("socks-port: {port}\n"))
        .unwrap_or_default();
    let config = format!(
        "mixed-port: {}\n{socks_line}log-level: debug\nproxies:\n  - {{name: sink-http, type: http, server: 127.0.0.1, port: {sink_port}}}\n  - {{name: sink-direct, type: direct}}\nrules:\n  - {rule}\nlisteners:\n{listeners}",
        free_port()
    );
    std::fs::write(dir.join("config.yaml"), &config).ok()?;
    // The peer's own output is kept next to its config; a failing case prints
    // it, so a mismatch is diagnosed from the peer's view instead of guessing.
    let stdout = std::fs::File::create(dir.join("mihomo.log")).ok()?;
    let stderr = stdout.try_clone().ok()?;
    let child = Command::new(bin)
        .arg("-d")
        .arg(&dir)
        .arg("-f")
        .arg(dir.join("config.yaml"))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .ok()?;
    let mihomo = Mihomo {
        child,
        dir,
        config: config.clone(),
    };
    let expected = listener_ports(listeners.as_str());
    for _ in 0..200 {
        if expected
            .iter()
            .all(|port| TcpStream::connect(("127.0.0.1", *port)).is_ok())
        {
            return Some(mihomo);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    None
}

/// Ports of `listeners:` lines, each line carries exactly one `port: N`.
fn listener_ports(listeners: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    let mut rest = listeners;
    while let Some(at) = rest.find("port: ") {
        let tail = &rest[at + 6..];
        let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(port) = digits.parse() {
            ports.push(port);
        }
        rest = &tail[digits.len()..];
    }
    ports
}

/// What a controlled sink saw on one connection (the sink answers proxies'
/// CONNECT with 200 and keeps reading).
struct Sink {
    port: u16,
    log: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    accepted: Arc<std::sync::atomic::AtomicUsize>,
}

impl Sink {
    fn start() -> Sink {
        let listener = common::bind_loopback();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (log_task, stop_task) = (log.clone(), stop.clone());
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted_task = accepted.clone();
        let port_for_log = port;
        std::thread::spawn(move || {
            while !stop_task.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if std::env::var_os("KC_SINK_LOG").is_some() {
                            eprintln!(
                                "SINK port {} accept from {:?}",
                                port_for_log,
                                stream.peer_addr()
                            );
                        }
                        accepted_task.fetch_add(1, Ordering::Relaxed);
                        let log = log_task.clone();
                        std::thread::spawn(move || {
                            let slot = {
                                let mut log = log.lock().unwrap();
                                log.push(Vec::new());
                                log.len() - 1
                            };
                            let mut stream = stream;
                            stream
                                .set_read_timeout(Some(Duration::from_millis(200)))
                                .ok();
                            let mut collected = Vec::new();
                            let deadline = Instant::now() + Duration::from_secs(4);
                            while Instant::now() < deadline {
                                let mut buffer = vec![0u8; 4096];
                                match stream.read(&mut buffer) {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        collected.extend_from_slice(&buffer[..n]);
                                        log.lock().unwrap()[slot] = collected.clone();
                                        if collected.windows(4).any(|w| w == b"\r\n\r\n") {
                                            let _ = stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nsink-ack");
                                        }
                                    }
                                    Err(_) => {}
                                }
                            }
                        });
                    }
                    Err(e) => {
                        if std::env::var_os("KC_SINK_LOG").is_some() && e.kind() != std::io::ErrorKind::WouldBlock {
                            eprintln!("SINK accept error: {e}");
                        }
                        std::thread::sleep(Duration::from_millis(5))
                    }
                }
            }
        });
        if std::env::var_os("KC_SINK_LOG").is_some() {
            eprintln!("SINK port {port} listening");
        }
        Sink {
            port,
            log,
            stop,
            accepted,
        }
    }

    /// Concatenation of everything every connection sent.
    fn received(&self) -> String {
        let log = self.log.lock().unwrap();
        log.iter()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn wait_marker(&self, marker: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.received().contains(marker) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

struct Running {
    kernel: Option<Kernel>,
    proxy: SocketAddr,
}

impl Running {
    fn kernel(&self) -> &Kernel {
        self.kernel.as_ref().unwrap()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut kernel) = self.kernel.take() {
            let _ = kernel.stop();
        }
    }
}

/// Kernel with one rule: `MATCH,<proxy name>` (the proxy is the first entry).
fn start_kernel(proxies: &str) -> (Running, String) {
    let port = free_port();
    let yaml =
        format!("mixed-port: {port}\nlog-level: warn\nproxies:\n{proxies}rules:\n  - 'MATCH,p0'\n");
    let (kernel, _) =
        Kernel::start_from_yaml(&yaml, None, Limits::default()).expect("kernel starts");
    let proxy = kernel.listen_addr();
    (
        Running {
            kernel: Some(kernel),
            proxy,
        },
        yaml,
    )
}

/// HTTP CONNECT through the kernel; returns (status line, bytes read back).
fn connect(proxy: SocketAddr, target: &str, payload: &[u8]) -> (String, Vec<u8>) {
    let (status, back, stream) = connect_keep(proxy, target, payload);
    if let Some(stream) = stream {
        close_gracefully(stream);
    }
    (status, back)
}

/// Like `connect`, but keeps the client socket alive for the whole closure
/// (`hold`) so the tunnel is not half-closed before the sink has replied.
fn connect_while<F: FnOnce()>(proxy: SocketAddr, target: &str, payload: &[u8], hold: F) -> String {
    let (status, _, stream) = connect_keep(proxy, target, payload);
    hold();
    if let Some(stream) = stream {
        close_gracefully(stream);
    }
    status
}

/// Close the client side without leaving unread bytes behind: an abrupt close
/// of a socket with queued receive data sends an RST, which can discard bytes
/// the kernel has not read yet (the tagged payload) and make a positive case
/// look like a failure. Half-close, drain, then drop.
fn close_gracefully(mut stream: TcpStream) {
    let _ = stream.shutdown(std::net::Shutdown::Write);
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    let mut scratch = [0u8; 1024];
    loop {
        match stream.read(&mut scratch) {
            Ok(0) | Err(_) => break,
            Ok(_) => continue,
        }
    }
    drop(stream);
}

fn connect_keep(
    proxy: SocketAddr,
    target: &str,
    payload: &[u8],
) -> (String, Vec<u8>, Option<TcpStream>) {
    let mut stream = match TcpStream::connect_timeout(&proxy, Duration::from_secs(5)) {
        Ok(stream) => stream,
        Err(e) => return (format!("connect error: {e}"), Vec::new(), None),
    };
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let _ =
        stream.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes());
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) => head.push(byte[0]),
        }
    }
    let status = String::from_utf8_lossy(&head)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    if !status.starts_with("HTTP/1.1 200") {
        // A refusal is worth seeing next to a missing marker: the marker can
        // only arrive when the kernel established the tunnel.
        eprintln!("CONNECT {target} -> {status:?}");
    }
    let mut back = Vec::new();
    if status.starts_with("HTTP/1.1 200") {
        let _ = stream.write_all(payload);
        let mut buffer = [0u8; 64];
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
        if let Ok(n) = stream.read(&mut buffer) {
            back.extend_from_slice(&buffer[..n]);
        }
    }
    (status, back, Some(stream))
}

fn skip(test: &str, reason: &str) {
    eprintln!(
        "SKIP {test} (not verified): {reason}; a skipped peer case is not a pass"
    );
}

/// Run `body` with a Mihomo instance and the kernel; skips when the peer
/// cannot be provided.
fn with_peer<F>(test: &str, listeners: &str, body: F)
where
    F: FnOnce(&Sink, &Mihomo, &[u16]),
{
    // Each case starts its own kernel and its own Mihomo process. Run one at
    // a time: with several in flight the host starves a just-accepted session
    // for seconds, which shows up as "the sink never saw the marker" and is a
    // scheduling artefact of the test host, not a protocol result.
    static SERIAL: Mutex<()> = Mutex::new(());
    let _serial = SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    install_kernel_log();
    // Without the pinned peer these cases cannot run. They are reported as
    // skipped (never as passed) and the default suite stays green; the T4
    // evidence in tool/kernel-compat/ records the runs that did have it.
    let Some(bin) = mihomo_bin() else {
        skip(test, "set KC_MIHOMO_BIN to the pinned Mihomo binary");
        return;
    };
    let Some(certs) = cert_dir() else {
        skip(
            test,
            "provide the openssl CLI or KC_CERT_DIR with cert.pem/key.pem",
        );
        return;
    };
    let sink = Sink::start();
    let Some(mihomo) = start_mihomo(
        bin,
        certs,
        sink.port,
        listeners,
        "MATCH,sink-http",
        None,
    ) else {
        panic!("{test}: Mihomo did not start its listeners");
    };
    let ports = listener_ports(
        &listeners
            .replace("CERT", "cert.pem")
            .replace("KEY", "key.pem"),
    );
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        body(&sink, &mihomo, &ports)
    }));
    if let Err(panic) = outcome {
        eprintln!(
            "--- {test}: sink port {} listeners ---\n{listeners}\nconfig ---\n{}\n--- peer log ---\n{}",
            sink.port,
            mihomo.config,
            mihomo.log()
        );
        std::panic::resume_unwind(panic);
    }
}

/// Like [`with_peer`] but the peer's ruleset forwards datagrams DIRECT to the
/// UDP target, because the HTTP sink is a TCP proxy.
fn with_udp_peer<F>(test: &str, listeners: &str, body: F)
where
    F: FnOnce(&Mihomo, &[u16]),
{
    with_udp_peer_on(test, listeners, "MATCH,sink-direct", None, body)
}

/// [`with_udp_peer`] with an explicit ruleset and an optional global
/// `socks-port` (Mihomo starts a UDP relay on it, which is what a chained UDP
/// case needs as its hop).
fn with_udp_peer_on<F>(test: &str, listeners: &str, rule: &str, socks_port: Option<u16>, body: F)
where
    F: FnOnce(&Mihomo, &[u16]),
{
    install_kernel_log();
    static SERIAL: Mutex<()> = Mutex::new(());
    let _serial = SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(bin) = mihomo_bin() else {
        skip(test, "set KC_MIHOMO_BIN to the pinned Mihomo binary");
        return;
    };
    let Some(certs) = cert_dir() else {
        skip(test, "provide the openssl CLI or KC_CERT_DIR with cert.pem/key.pem");
        return;
    };
    let Some(mihomo) = start_mihomo(bin, certs, free_port(), listeners, rule, socks_port) else {
        panic!("{test}: Mihomo did not start its listeners");
    };
    let ports = listener_ports(
        &listeners
            .replace("CERT", "cert.pem")
            .replace("KEY", "key.pem"),
    );
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&mihomo, &ports)));
    if let Err(panic) = outcome {
        eprintln!(
            "--- {test}: peer config ---\n{}\n--- peer log ---\n{}",
            mihomo.config,
            mihomo.log()
        );
        std::panic::resume_unwind(panic);
    }
}

fn expect_marker(test: &str, sink: &Sink, marker: &str) {
    assert!(
        sink.wait_marker(marker, Duration::from_secs(10)),
        "{test}: the sink did not receive '{marker}' (accepted {} connections); it received:\n{}",
        sink.accepted.load(Ordering::Relaxed),
        sink.received()
    );
}


fn expect_not_reached(test: &str, sink: &Sink) {
    std::thread::sleep(Duration::from_millis(500));
    let seen = sink.received();
    assert!(
        !seen.contains("CONNECT"),
        "{test}: the sink must not be reached, got:\n{seen}"
    );
}

fn listener(kind: &str, port: u16, extra: &str) -> String {
    format!("  - {{name: in-{kind}, type: {kind}, listen: 127.0.0.1, port: {port}{extra}}}\n")
}


/// A loopback UDP echo: returns its port and the payloads it received.
struct UdpEcho {
    port: u16,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
}

impl UdpEcho {
    fn start() -> UdpEcho {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (log, stop_task) = (seen.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut buffer = [0u8; 65535];
            while !stop_task.load(Ordering::Relaxed) {
                if let Ok((read, from)) = socket.recv_from(&mut buffer) {
                    log.lock().unwrap().push(buffer[..read].to_vec());
                    let _ = socket.send_to(&buffer[..read], from);
                }
            }
        });
        UdpEcho { port, seen, stop }
    }

    fn received(&self) -> Vec<Vec<u8>> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for UdpEcho {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Open a SOCKS5 UDP association through the kernel and return the control
/// connection (kept alive) plus the relay socket address.
fn udp_associate(proxy: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut stream = TcpStream::connect_timeout(&proxy, Duration::from_secs(5)).expect("control");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection).unwrap();
    assert_eq!(selection, [0x05, 0x00]);
    // UDP ASSOCIATE with 0.0.0.0:0; the relay address comes back in the reply.
    stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0x00, "UDP associate refused: {reply:02x?}");
    let ip = std::net::Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
    let port = u16::from_be_bytes([reply[8], reply[9]]);
    (stream, SocketAddr::from((ip, port)))
}

/// Send one SOCKS5 UDP datagram (RSV RSV FRAG ATYP ADDR PORT payload).
fn send_datagram(relay: SocketAddr, target: SocketAddr, payload: &[u8]) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut packet = vec![0u8, 0u8, 0u8, 0x01];
    packet.extend_from_slice(&target.ip().to_string().parse::<std::net::Ipv4Addr>().unwrap().octets());
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    socket.send_to(&packet, relay).unwrap();
    // Wait for the reply on the same socket, then hand it back.
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut buffer = [0u8; 65535];
    match socket.recv_from(&mut buffer) {
        Ok((read, _)) => {
            assert!(read > 10, "reply too short: {read}");
            let (host, offset) = parse_udp_reply(&buffer[..read]);
            assert_eq!(host, target);
            eprintln!(
                "UDP reply from {host}: {}",
                String::from_utf8_lossy(&buffer[offset..read])
            );
        }
        Err(e) => panic!("no UDP reply through the kernel: {e}"),
    }
}

/// Send a datagram and return the reply payload, or `None` on timeout.
fn try_datagram(relay: SocketAddr, target: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut packet = vec![0u8, 0u8, 0u8, 0x01];
    packet.extend_from_slice(&target.ip().to_string().parse::<std::net::Ipv4Addr>().unwrap().octets());
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    socket.send_to(&packet, relay).ok()?;
    socket
        .set_read_timeout(Some(Duration::from_millis(1200)))
        .ok()?;
    let mut buffer = [0u8; 65535];
    let (read, _) = socket.recv_from(&mut buffer).ok()?;
    let (_, offset) = parse_udp_reply(&buffer[..read]);
    Some(buffer[offset..read].to_vec())
}

fn parse_udp_reply(reply: &[u8]) -> (SocketAddr, usize) {
    assert_eq!(
        reply[3],
        0x01,
        "only IPv4 replies are asserted here; raw reply: {:02x?}",
        reply
    );
    let ip = std::net::Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
    let port = u16::from_be_bytes([reply[8], reply[9]]);
    (SocketAddr::from((ip, port)), 10)
}

/// The sink port is only known after the sink starts, so each listener is
/// built inside `with_peer` through this helper value.
const _: () = ();

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn socks5_outbound_reaches_the_receiving_side_through_mihomo() {
    let port = free_port();
    let listeners = listener(
        "socks",
        port,
        &format!(", users: [{{username: {SOCKS_USER}, password: \"{SOCKS_PASSWORD}\"}}]"),
    );
    with_peer("socks5", &listeners, |sink, _mihomo, _| {
        let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: socks5, server: 127.0.0.1, port: {port}, username: {SOCKS_USER}, password: \"{SOCKS_PASSWORD}\"}}\n"
        ));
        let marker = "marker-socks5-through-mihomo";
        let status = connect_while(
            running.proxy,
            &format!("127.0.0.1:{}", sink.port),
            marker.as_bytes(),
            || expect_marker("socks5", sink, marker),
        );
        assert_eq!(status, "HTTP/1.1 200 Connection Established");
        // The session ends when the client (from `connect`) drops its socket;
        // give the relay a moment to observe that before reading stats.
        let mut completed = 0;
        for _ in 0..100 {
            completed = running.kernel().stats().completed;
            if completed >= 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(completed, 1);
    });
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn socks5_wrong_password_never_reaches_the_sink() {
    let port = free_port();
    let listeners = listener(
        "socks",
        port,
        &format!(", users: [{{username: {SOCKS_USER}, password: \"{SOCKS_PASSWORD}\"}}]"),
    );
    with_peer("socks5-wrong-password", &listeners, |sink, _mihomo, _| {
        let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: socks5, server: 127.0.0.1, port: {port}, username: {SOCKS_USER}, password: wrong}}\n"
        ));
        let (status, _) = connect(
            running.proxy,
            &format!("127.0.0.1:{}", sink.port),
            b"must-not-arrive",
        );
        assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
        expect_not_reached("socks5-wrong-password", sink);
    });
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn http_outbound_with_basic_auth_reaches_the_receiving_side_through_mihomo() {
    let port = free_port();
    let listeners = listener(
        "http",
        port,
        &format!(", users: [{{username: {SOCKS_USER}, password: \"{SOCKS_PASSWORD}\"}}]"),
    );
    with_peer("http", &listeners, |sink, _mihomo, _| {
        let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: http, server: 127.0.0.1, port: {port}, username: {SOCKS_USER}, password: \"{SOCKS_PASSWORD}\"}}\n"
        ));
        let marker = "marker-http-through-mihomo";
        let status = connect_while(
            running.proxy,
            &format!("127.0.0.1:{}", sink.port),
            marker.as_bytes(),
            || {},
        );
        assert_eq!(status, "HTTP/1.1 200 Connection Established");
        expect_marker("http", sink, marker);
    });
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn http_outbound_wrong_password_never_reaches_the_sink() {
    let port = free_port();
    let listeners = listener(
        "http",
        port,
        &format!(", users: [{{username: {SOCKS_USER}, password: \"{SOCKS_PASSWORD}\"}}]"),
    );
    with_peer("http-wrong-password", &listeners, |sink, _mihomo, _| {
        let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: http, server: 127.0.0.1, port: {port}, username: {SOCKS_USER}, password: wrong}}\n"
        ));
        let (status, _) = connect(
            running.proxy,
            &format!("127.0.0.1:{}", sink.port),
            b"must-not-arrive",
        );
        // Mihomo's HTTP inbound answers 407 to a bad credential, which the
        // client sees as a failed handshake, so the kernel reports 502.
        assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
        expect_not_reached("http-wrong-password", sink);
    });
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn dialer_proxy_chain_with_a_closed_first_hop_never_reaches_the_sink() {
    // The exit hop is a Mihomo listener, but the chain starts at a closed port:
    // the dial must fail instead of falling back to a direct connection.
    let exit_port = free_port();
    let dead_port = free_port();
    let listeners = listener(
        "socks",
        exit_port,
        &format!(", users: [{{username: {SOCKS_USER}, password: \"{SOCKS_PASSWORD}\"}}]"),
    );
    with_peer("dialer-proxy-dead-hop", &listeners, |sink, _mihomo, _| {
        let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: socks5, server: 127.0.0.1, port: {exit_port}, username: {SOCKS_USER}, password: \"{SOCKS_PASSWORD}\", dialer-proxy: p1}}\n  - {{name: p1, type: socks5, server: 127.0.0.1, port: {dead_port}}}\n"
        ));
        let (status, _) = connect(
            running.proxy,
            &format!("127.0.0.1:{}", sink.port),
            b"must-not-arrive",
        );
        assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
        expect_not_reached("dialer-proxy-dead-hop", sink);
    });
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn shadowsocks_outbound_reaches_the_receiving_side_through_mihomo() {
    let port = free_port();
    let listeners = listener(
        "shadowsocks",
        port,
        &format!(", cipher: aes-256-gcm, password: \"{SS_PASSWORD}\""),
    );
    with_peer("shadowsocks", &listeners, |sink, _mihomo, _| {
        let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: ss, server: 127.0.0.1, port: {port}, cipher: aes-256-gcm, password: \"{SS_PASSWORD}\"}}\n"
        ));
        let marker = "marker-ss-through-mihomo";
        // The client stays open while the receiving side is checked.
        let status = connect_while(
            running.proxy,
            &format!("127.0.0.1:{}", sink.port),
            marker.as_bytes(),
            || expect_marker("shadowsocks", sink, marker),
        );
        assert_eq!(status, "HTTP/1.1 200 Connection Established");
    });
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn shadowsocks_wrong_password_never_reaches_the_sink() {
    let port = free_port();
    let listeners = listener(
        "shadowsocks",
        port,
        &format!(", cipher: aes-256-gcm, password: \"{SS_PASSWORD}\""),
    );
    with_peer(
        "shadowsocks-wrong-password",
        &listeners,
        |sink, _mihomo, _| {
            let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: ss, server: 127.0.0.1, port: {port}, cipher: aes-256-gcm, password: wrong}}\n"
        ));
            let (status, _) = connect(
                running.proxy,
                &format!("127.0.0.1:{}", sink.port),
                b"must-not-arrive",
            );
            // The kernel cannot tell the server dropped the wrong-key stream (it
            // replies only after the first client bytes); the server discards it.
            assert!(
                status == "HTTP/1.1 200 Connection Established" || status.contains("502"),
                "{status}"
            );
            expect_not_reached("shadowsocks-wrong-password", sink);
        },
    );
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn trojan_outbound_over_tls_reaches_the_receiving_side_through_mihomo() {
    let port = free_port();
    let listeners = listener(
        "trojan",
        port,
        &format!(
            ", certificate: CERT, private-key: KEY, users: [{{password: \"{TROJAN_PASSWORD}\"}}]"
        ),
    );
    with_peer("trojan", &listeners, |sink, _mihomo, _| {
        let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: trojan, server: 127.0.0.1, port: {port}, password: \"{TROJAN_PASSWORD}\", sni: localhost, skip-cert-verify: true}}\n"
        ));
        let marker = "marker-trojan-through-mihomo";
        let status = connect_while(
            running.proxy,
            &format!("127.0.0.1:{}", sink.port),
            marker.as_bytes(),
            || expect_marker("trojan", sink, marker),
        );
        assert_eq!(status, "HTTP/1.1 200 Connection Established");
    });
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn trojan_wrong_password_and_untrusted_certificate_never_reach_the_sink() {
    // The trojan listener closes on a bad password hash; it needs the client
    // to send the first bytes (it does: the address header and the payload).
    let port = free_port();
    let listeners = listener(
        "trojan",
        port,
        &format!(
            ", certificate: CERT, private-key: KEY, users: [{{password: \"{TROJAN_PASSWORD}\"}}]"
        ),
    );
    with_peer("trojan-negatives", &listeners, |sink, _mihomo, _| {
        let (wrong_password, _) = start_kernel(&format!(
            "  - {{name: p0, type: trojan, server: 127.0.0.1, port: {port}, password: wrong, skip-cert-verify: true}}\n"
        ));
        let (status, _) = connect(
            wrong_password.proxy,
            &format!("127.0.0.1:{}", sink.port),
            b"must-not-arrive",
        );
        assert_eq!(
            status, "HTTP/1.1 200 Connection Established",
            "Mihomo's trojan listener closes silently; the kernel sees EOF on the relay, not a 502"
        );
        expect_not_reached("trojan-wrong-password", sink);
        // Without skip-cert-verify, the self-signed listener certificate fails verification.
        let (untrusted, _) = start_kernel(&format!(
            "  - {{name: p0, type: trojan, server: 127.0.0.1, port: {port}, password: \"{TROJAN_PASSWORD}\"}}\n"
        ));
        let (status, _) = connect(
            untrusted.proxy,
            &format!("127.0.0.1:{}", sink.port),
            b"must-not-arrive",
        );
        assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
        expect_not_reached("trojan-untrusted-certificate", sink);
    });
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn vless_outbound_over_tls_reaches_the_receiving_side_through_mihomo() {
    let port = free_port();
    let listeners = listener(
        "vless",
        port,
        &format!(", certificate: CERT, private-key: KEY, users: [{{username: u1, uuid: {UUID}}}]"),
    );
    with_peer("vless", &listeners, |sink, _mihomo, _| {
        let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: vless, server: 127.0.0.1, port: {port}, uuid: {UUID}, tls: true, skip-cert-verify: true}}\n"
        ));
        let marker = "marker-vless-through-mihomo";
        let status = connect_while(
            running.proxy,
            &format!("127.0.0.1:{}", sink.port),
            marker.as_bytes(),
            || expect_marker("vless", sink, marker),
        );
        assert_eq!(status, "HTTP/1.1 200 Connection Established");
    });
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn vless_over_websocket_reaches_the_receiving_side_through_mihomo() {
    let port = free_port();
    let listeners = listener(
        "vless",
        port,
        &format!(", ws-path: /vlws, certificate: CERT, private-key: KEY, users: [{{username: u1, uuid: {UUID}}}]"),
    );
    with_peer("vless-ws", &listeners, |sink, _mihomo, _| {
        let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: vless, server: 127.0.0.1, port: {port}, uuid: {UUID}, tls: true, skip-cert-verify: true, network: ws, ws-opts: {{path: /vlws}}}}\n"
        ));
        let marker = "marker-vless-ws-through-mihomo";
        let status = connect_while(
            running.proxy,
            &format!("127.0.0.1:{}", sink.port),
            marker.as_bytes(),
            || {
                expect_marker("vless-ws", sink, marker);
            },
        );
        let _ = status;
    });
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn vless_over_v2ray_http_upgrade_reaches_the_receiving_side_through_mihomo() {
    // A key-less `Upgrade: websocket` request is what Mihomo treats as the
    // Xray HTTP upgrade (`IsV2rayHttpUpdate`): the same listener then carries a
    // raw byte stream instead of framed WebSocket messages.
    let port = free_port();
    let listeners = listener(
        "vless",
        port,
        &format!(", ws-path: /vlraw, certificate: CERT, private-key: KEY, users: [{{username: u1, uuid: {UUID}}}]"),
    );
    with_peer("vless-ws-raw", &listeners, |sink, _mihomo, _| {
        let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: vless, server: 127.0.0.1, port: {port}, uuid: {UUID}, tls: true, skip-cert-verify: true, network: ws, ws-opts: {{path: /vlraw, v2ray-http-upgrade: true}}}}\n"
        ));
        let marker = "marker-vless-raw-through-mihomo";
        let status = connect_while(
            running.proxy,
            &format!("127.0.0.1:{}", sink.port),
            marker.as_bytes(),
            || expect_marker("vless-ws-raw", sink, marker),
        );
        assert_eq!(status, "HTTP/1.1 200 Connection Established");
    });
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn vless_over_websocket_with_a_host_override_reaches_the_receiving_side_through_mihomo() {
    // The Host override changes only the upgrade request; the tunnel must still
    // reach the sink, which is what a CDN front needs.
    let port = free_port();
    let listeners = listener(
        "vless",
        port,
        &format!(", ws-path: /vlhost, certificate: CERT, private-key: KEY, users: [{{username: u1, uuid: {UUID}}}]"),
    );
    with_peer("vless-ws-host", &listeners, |sink, _mihomo, _| {
        let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: vless, server: 127.0.0.1, port: {port}, uuid: {UUID}, tls: true, skip-cert-verify: true, network: ws, ws-opts: {{path: /vlhost, headers: {{Host: cdn.example}}}}}}\n"
        ));
        let marker = "marker-vless-ws-host-through-mihomo";
        let status = connect_while(
            running.proxy,
            &format!("127.0.0.1:{}", sink.port),
            marker.as_bytes(),
            || expect_marker("vless-ws-host", sink, marker),
        );
        assert_eq!(status, "HTTP/1.1 200 Connection Established");
    });
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn vless_wrong_uuid_never_reaches_the_sink() {
    let port = free_port();
    let listeners = listener(
        "vless",
        port,
        &format!(", certificate: CERT, private-key: KEY, users: [{{username: u1, uuid: {UUID}}}]"),
    );
    with_peer("vless-wrong-uuid", &listeners, |sink, _mihomo, _| {
        let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: vless, server: 127.0.0.1, port: {port}, uuid: 00000000-0000-0000-0000-000000000001, tls: true, skip-cert-verify: true}}\n"
        ));
        let (_, _) = connect(
            running.proxy,
            &format!("127.0.0.1:{}", sink.port),
            b"must-not-arrive",
        );
        expect_not_reached("vless-wrong-uuid", sink);
    });
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn anytls_outbound_reaches_the_receiving_side_through_mihomo() {
    let port = free_port();
    let listeners = listener(
        "anytls",
        port,
        &format!(", certificate: CERT, private-key: KEY, users: {{user1: \"{ANYTLS_PASSWORD}\"}}"),
    );
    with_peer("anytls", &listeners, |sink, _mihomo, _| {
        let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: anytls, server: 127.0.0.1, port: {port}, password: \"{ANYTLS_PASSWORD}\", sni: localhost, skip-cert-verify: true}}\n"
        ));
        let marker = "marker-anytls-through-mihomo";
        let status = connect_while(
            running.proxy,
            &format!("127.0.0.1:{}", sink.port),
            marker.as_bytes(),
            || expect_marker("anytls", sink, marker),
        );
        assert_eq!(status, "HTTP/1.1 200 Connection Established");
    });
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn anytls_wrong_password_and_untrusted_certificate_never_reach_the_sink() {
    let port = free_port();
    let listeners = listener(
        "anytls",
        port,
        &format!(", certificate: CERT, private-key: KEY, users: {{user1: \"{ANYTLS_PASSWORD}\"}}"),
    );
    with_peer("anytls-negatives", &listeners, |sink, _mihomo, _| {
        let (wrong, _) = start_kernel(&format!(
            "  - {{name: p0, type: anytls, server: 127.0.0.1, port: {port}, password: wrong, skip-cert-verify: true}}\n"
        ));
        let (status, _) = connect(
            wrong.proxy,
            &format!("127.0.0.1:{}", sink.port),
            b"must-not-arrive",
        );
        assert_eq!(status, "HTTP/1.1 200 Connection Established", "the server drops an unknown password without a reply; the kernel sees its session close");
        expect_not_reached("anytls-wrong-password", sink);
        let (untrusted, _) = start_kernel(&format!(
            "  - {{name: p0, type: anytls, server: 127.0.0.1, port: {port}, password: \"{ANYTLS_PASSWORD}\"}}\n"
        ));
        let (status, _) = connect(
            untrusted.proxy,
            &format!("127.0.0.1:{}", sink.port),
            b"must-not-arrive",
        );
        assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
        expect_not_reached("anytls-untrusted-certificate", sink);
    });
}


#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn shadowsocks_udp_reaches_the_receiving_side_through_mihomo() {
    // The peer's Shadowsocks listener carries AEAD-2017 UDP; the kernel's
    // SOCKS5 UDP ASSOCIATE forwards each datagram through the configured ss
    // outbound (`udp: true`).
    let port = free_port();
    let listeners = listener(
        "shadowsocks",
        port,
        &format!(", cipher: aes-256-gcm, password: \"{SS_PASSWORD}\""),
    );
    with_udp_peer("ss-udp", &listeners, |_mihomo, _| {
        let echo = UdpEcho::start();
        let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: ss, server: 127.0.0.1, port: {port}, cipher: aes-256-gcm, password: \"{SS_PASSWORD}\", udp: true}}\n"
        ));
        let (_control, relay) = udp_associate(running.proxy);
        let target: SocketAddr = format!("127.0.0.1:{}", echo.port).parse().unwrap();
        let payload = b"marker-ss-udp-through-mihomo";
        send_datagram(relay, target, payload);
        assert_eq!(
            echo.received(),
            vec![payload.to_vec()],
            "the UDP echo must receive the datagram through the ss listener"
        );
    });
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn shadowsocks_udp_wrong_password_never_reaches_the_echo() {
    let port = free_port();
    let listeners = listener(
        "shadowsocks",
        port,
        &format!(", cipher: aes-256-gcm, password: \"{SS_PASSWORD}\""),
    );
    with_udp_peer("ss-udp-wrong-password", &listeners, |_mihomo, _| {
        let echo = UdpEcho::start();
        let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: ss, server: 127.0.0.1, port: {port}, cipher: aes-256-gcm, password: wrong, udp: true}}\n"
        ));
        let (_control, relay) = udp_associate(running.proxy);
        let target: SocketAddr = format!("127.0.0.1:{}", echo.port).parse().unwrap();
        assert!(
            try_datagram(relay, target, b"must-not-arrive").is_none(),
            "a wrong ss password must not produce a reply"
        );
        assert!(echo.received().is_empty(), "the echo must not be reached");
    });
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn trojan_udp_reaches_the_receiving_side_through_mihomo() {
    // The trojan listener accepts command 3 and carries `addr|len|CRLF|payload`
    // frames over TLS; the kernel's association uses the same framing.
    let port = free_port();
    let listeners = listener(
        "trojan",
        port,
        &format!(
            ", certificate: CERT, private-key: KEY, users: [{{password: \"{TROJAN_PASSWORD}\"}}]"
        ),
    );
    with_udp_peer("trojan-udp", &listeners, |_mihomo, _| {
        let echo = UdpEcho::start();
        let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: trojan, server: 127.0.0.1, port: {port}, password: \"{TROJAN_PASSWORD}\", sni: localhost, skip-cert-verify: true, udp: true}}\n"
        ));
        let (_control, relay) = udp_associate(running.proxy);
        let target: SocketAddr = format!("127.0.0.1:{}", echo.port).parse().unwrap();
        let payload = b"marker-trojan-udp-through-mihomo";
        send_datagram(relay, target, payload);
        assert_eq!(echo.received(), vec![payload.to_vec()]);
    });
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn trojan_udp_wrong_password_never_reaches_the_echo() {
    let port = free_port();
    let listeners = listener(
        "trojan",
        port,
        &format!(
            ", certificate: CERT, private-key: KEY, users: [{{password: \"{TROJAN_PASSWORD}\"}}]"
        ),
    );
    with_udp_peer("trojan-udp-wrong-password", &listeners, |_mihomo, _| {
        let echo = UdpEcho::start();
        let (running, _) = start_kernel(&format!(
            "  - {{name: p0, type: trojan, server: 127.0.0.1, port: {port}, password: wrong, sni: localhost, skip-cert-verify: true, udp: true}}\n"
        ));
        let (_control, relay) = udp_associate(running.proxy);
        let target: SocketAddr = format!("127.0.0.1:{}", echo.port).parse().unwrap();
        assert!(
            try_datagram(relay, target, b"must-not-arrive").is_none(),
            "a wrong trojan password must not produce a reply"
        );
        assert!(echo.received().is_empty(), "the echo must not be reached");
    });
}


#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn chained_ss_udp_rejected_by_the_hop_never_reaches_the_echo() {
    // The hop's ruleset REJECTs the datagram it is asked to relay. A kernel
    // that dialled the ss server directly (ignoring `dialer-proxy`) would reach
    // the echo, so this is the proof that the UDP association uses the chain.
    // (A positive chained case against this peer is impossible on loopback:
    // Mihomo's own loopback detector refuses to forward a datagram that came
    // from its own socks UDP listener to a local destination. The positive
    // chain is covered by the two controlled hops in tests/protocols.rs.)
    let ss_port = free_port();
    let hop_port = free_port();
    let listeners = listener(
        "shadowsocks",
        ss_port,
        &format!(", cipher: aes-256-gcm, password: \"{SS_PASSWORD}\""),
    );
    with_udp_peer_on(
        "ss-udp-chain-reject",
        &listeners,
        "MATCH,REJECT",
        Some(hop_port),
        |_mihomo, _| {
            let echo = UdpEcho::start();
            let (running, _) = start_kernel(&format!(
                "  - {{name: p0, type: ss, server: 127.0.0.1, port: {ss_port}, cipher: aes-256-gcm, password: \"{SS_PASSWORD}\", udp: true, dialer-proxy: hop}}\n  - {{name: hop, type: socks5, server: 127.0.0.1, port: {hop_port}}}\n"
            ));
            let (_control, relay) = udp_associate(running.proxy);
            let target: SocketAddr = format!("127.0.0.1:{}", echo.port).parse().unwrap();
            assert!(
                try_datagram(relay, target, b"must-be-rejected-at-the-hop").is_none(),
                "the hop rejects the datagram, so no reply may come back"
            );
            assert!(
                echo.received().is_empty(),
                "the echo must not be reached: the datagram went through the hop"
            );
        },
    );
}


#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn chained_trojan_udp_rejected_by_the_hop_never_reaches_the_echo() {
    // trojan UDP rides a TCP stream, so the chain is the hop's CONNECT. The
    // hop's ruleset REJECTs it; a kernel that dialled the trojan server
    // directly (ignoring `dialer-proxy`) would reach the echo.
    let tj_port = free_port();
    let hop_port = free_port();
    let listeners = listener(
        "trojan",
        tj_port,
        &format!(
            ", certificate: CERT, private-key: KEY, users: [{{password: \"{TROJAN_PASSWORD}\"}}]"
        ),
    );
    with_udp_peer_on(
        "trojan-udp-chain-reject",
        &listeners,
        "MATCH,REJECT",
        Some(hop_port),
        |_mihomo, _| {
            let echo = UdpEcho::start();
            let (running, _) = start_kernel(&format!(
                "  - {{name: p0, type: trojan, server: 127.0.0.1, port: {tj_port}, password: \"{TROJAN_PASSWORD}\", sni: localhost, skip-cert-verify: true, udp: true, dialer-proxy: hop}}\n  - {{name: hop, type: socks5, server: 127.0.0.1, port: {hop_port}}}\n"
            ));
            let (_control, relay) = udp_associate(running.proxy);
            let target: SocketAddr = format!("127.0.0.1:{}", echo.port).parse().unwrap();
            assert!(
                try_datagram(relay, target, b"must-be-rejected-at-the-hop").is_none(),
                "the hop rejects the trojan server connection, so no reply may come back"
            );
            assert!(
                echo.received().is_empty(),
                "the echo must not be reached: the trojan stream went through the hop"
            );
        },
    );
}

#[ignore = "needs the pinned Mihomo peer: set KC_MIHOMO_BIN and run with --ignored"]
#[test]
fn dialer_proxy_chain_connects_through_both_hops_seen_by_mihomo() {
    // Two hops, both real visitors: A is a Mihomo `mixed` listener, B is a
    // Mihomo `socks` listener, and B forwards through A to a plain sink. The
    // rule selects A with `dialer-proxy: B`, so the kernel must reach A's
    // server only through B and dial the sink from A.
    let a_port = free_port();
    let b_port = free_port();
    let listeners = format!(
        "{}{}",
        // A: a `mixed` listener reached through B (its own socks hop).
        listener(
            "mixed",
            a_port,
            &format!(", users: [{{username: {SOCKS_USER}, password: \"{SOCKS_PASSWORD}\"}}]"),
        ),
        listener("socks", b_port, &format!(", users: [{{username: {SOCKS_USER}, password: \"{SOCKS_PASSWORD}\"}}]")),
    );
    with_peer("dialer-proxy-two-hop", &listeners, |sink, _mihomo, _| {
        // The sink must be reachable through A (Mihomo), which is the exit hop.
        let proxies = format!(
            "  - {{name: p0, type: socks5, server: 127.0.0.1, port: {a_port}, dialer-proxy: p1}}\n  - {{name: p1, type: socks5, server: 127.0.0.1, port: {b_port}, username: {SOCKS_USER}, password: \"{SOCKS_PASSWORD}\"}}\n"
        );
        let (running, _) = start_kernel(&proxies);
        let marker = "marker-two-hop-through-mihomo";
        let status = connect_while(
            running.proxy,
            &format!("127.0.0.1:{}", sink.port),
            marker.as_bytes(),
            || {
                expect_marker("dialer-proxy-two-hop", sink, marker);
            },
        );
        eprintln!("two-hop client outcome: {status:?}");
        assert!(sink.received().contains(marker), "the sink saw:\n{}", sink.received());
    });
}
