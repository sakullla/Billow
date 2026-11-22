//! End-to-end session tests: real loopback listeners, both inbound protocols,
//! bidirectional and half-closed payloads, REJECT, bounded sessions, stop/restart.

#[allow(dead_code)]
mod common;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use billow_kernel::{Config, Kernel, Limits};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Running {
    kernel: Option<Kernel>,
    proxy: SocketAddr,
}

impl Running {
    fn start(yaml: &str, limits: Limits) -> (Running, Vec<String>) {
        let (kernel, warnings) =
            Kernel::start_from_yaml(yaml, None, limits).expect("kernel starts");
        let proxy = kernel.listen_addr();
        (
            Running {
                kernel: Some(kernel),
                proxy,
            },
            warnings,
        )
    }

    fn kernel(&self) -> &Kernel {
        self.kernel.as_ref().unwrap()
    }

    fn stop(&mut self) {
        if let Some(mut kernel) = self.kernel.take() {
            kernel.stop().expect("clean stop");
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Build a config for `entries` (one rule per entry). Rules are single-quoted
/// so the comma-separated clauses stay one YAML scalar.
fn config_for(entries: &[&str]) -> String {
    config_on_port(free_port(), entries)
}

fn config_on_port(port: u16, entries: &[&str]) -> String {
    let rules = entries
        .iter()
        .map(|entry| format!("  - '{entry}'\n"))
        .collect::<String>();
    format!("mixed-port: {port}\nlog-level: silent\nrules:\n{rules}")
}

fn direct_config() -> String {
    config_for(&["MATCH,DIRECT"])
}

fn standard_limits() -> Limits {
    Limits {
        half_close_timeout: Duration::from_secs(3),
        ..Limits::default()
    }
}

async fn echo_roundtrip_on(stream: &mut tokio::net::TcpStream, payload: &[u8]) -> Vec<u8> {
    stream.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    stream.read_exact(&mut got).await.expect("echo payload");
    got
}

#[tokio::test]
async fn socks5_relays_and_ip_cidr_and_geosite_rules_apply() {
    let endpoint = spawn_endpoint(EchoMode::Echo).await;
    let geo = std::env::temp_dir().join(format!("billow-geosite-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&geo).unwrap();
    std::fs::write(geo.join("test.yaml"), "key: test\ntags:\n  - name: direct-sites\n    rules:\n      - sub_domain: [localhost, example]\n").unwrap();
    let document = config_for(&[
        "GEOSITE,test,DIRECT",
        "IP-CIDR,127.0.0.0/8,DIRECT",
        "MATCH,REJECT",
    ]);
    let (kernel, _) = Kernel::start_from_yaml(&document, Some(geo.clone()), standard_limits())
        .expect("kernel starts with geosite dir");
    let proxy = kernel.listen_addr();

    // GEOSITE via domain name.
    let mut stream = socks5_connect(proxy, "localhost", endpoint.port)
        .await
        .unwrap();
    let got = echo_roundtrip_on(&mut stream, b"geosite").await;
    assert_eq!(got, b"geosite");
    drop(stream);

    // IP-CIDR rule fires when the client sends a literal address (no resolver in this slice).
    let mut stream = socks5_connect(proxy, "127.0.0.1", endpoint.port)
        .await
        .unwrap();
    let got = echo_roundtrip_on(&mut stream, b"cidr").await;
    assert_eq!(got, b"cidr");
    drop(stream);

    assert_eq!(
        kernel.evaluate("localhost", None).1,
        "GEOSITE,test -> DIRECT"
    );
    assert_eq!(
        kernel.evaluate("www.ads.example", None).1,
        "GEOSITE,test -> DIRECT"
    );
    assert_eq!(kernel.evaluate("10.1.2.3", None).1, "MATCH -> REJECT");
    assert_eq!(
        kernel
            .evaluate("10.1.2.3", Some("10.1.2.3".parse().unwrap()))
            .1,
        "MATCH -> REJECT"
    );
    assert_eq!(
        kernel.evaluate("x", Some("127.0.0.1".parse().unwrap())).1,
        "IP-CIDR,127.0.0.0/8 -> DIRECT"
    );

    let mut kernel = kernel;
    kernel.stop().unwrap();
    std::fs::remove_dir_all(&geo).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reject_rule_blocks_both_protocols_without_dialling() {
    let endpoint = spawn_endpoint(EchoMode::Echo).await;
    let document = config_for(&["DOMAIN-SUFFIX,blocked.test,REJECT", "MATCH,DIRECT"]);
    let (running, _) = Running::start(&document, standard_limits());

    let (_stream, status) =
        http_connect(running.proxy, &format!("x.blocked.test:{}", endpoint.port))
            .await
            .unwrap();
    assert_eq!(status, "HTTP/1.1 403 Forbidden");
    let e = socks5_connect(running.proxy, "y.blocked.test", endpoint.port)
        .await
        .err()
        .expect("rejected");
    assert!(e.to_string().contains("0x07"), "{e}");

    wait_until(Duration::from_secs(3), || {
        running.kernel().stats().active == 0
    })
    .await;
    assert_eq!(running.kernel().stats().rejected, 2);
    assert_eq!(
        endpoint.connections.load(Ordering::Relaxed),
        0,
        "REJECT must not dial the target"
    );
}

#[tokio::test]
async fn half_close_delivers_request_then_response() {
    // The endpoint answers only after it sees EOF; the proxy must propagate the
    // client's half-closes in both directions for this to work.
    let endpoint = spawn_endpoint(EchoMode::ReplyAfterEof {
        reply: b"RESPONSE:",
        delay: Duration::from_millis(50),
    })
    .await;
    let document = direct_config();
    let (running, _) = Running::start(
        &document,
        Limits {
            half_close_timeout: Duration::from_secs(5),
            ..Limits::default()
        },
    );

    let mut stream = socks5_connect(running.proxy, "127.0.0.1", endpoint.port)
        .await
        .unwrap();
    let (mut read, mut write) = stream.split();
    // Half-close upload only: shutdown on the SOCKS5 client stream.
    write.write_all(b"REQUEST-BODY").await.unwrap();
    write.shutdown().await.unwrap();
    let mut out = Vec::new();
    read.read_to_end(&mut out).await.unwrap();
    assert_eq!(&out[..9], b"RESPONSE:");
    assert_eq!(
        u64::from_be_bytes(out[9..17].try_into().unwrap()),
        12,
        "endpoint must receive the full request"
    );
    drop(read);
}

#[tokio::test]
async fn http_connect_half_close_then_response() {
    let endpoint = spawn_endpoint(EchoMode::ReplyAfterEof {
        reply: b"OK",
        delay: Duration::from_millis(20),
    })
    .await;
    let document = direct_config();
    let (running, _) = Running::start(&document, standard_limits());
    let (mut stream, status) = http_connect(running.proxy, &format!("127.0.0.1:{}", endpoint.port))
        .await
        .unwrap();
    assert_eq!(status, "HTTP/1.1 200 Connection Established");
    stream.write_all(b"hello").await.unwrap();
    let (mut read, mut write) = stream.into_split();
    write.shutdown().await.unwrap();
    let mut out = Vec::new();
    read.read_to_end(&mut out).await.unwrap();
    assert_eq!(&out[..2], b"OK");
}

#[tokio::test]
async fn stalled_peer_after_half_close_is_dropped_after_linger() {
    let endpoint = spawn_endpoint(EchoMode::Silent).await;
    let document = direct_config();
    let (running, _) = Running::start(
        &document,
        Limits {
            half_close_timeout: Duration::from_millis(300),
            ..Limits::default()
        },
    );
    let mut stream = socks5_connect(running.proxy, "127.0.0.1", endpoint.port)
        .await
        .unwrap();
    let (mut read, mut write) = stream.split();
    write.write_all(b"x").await.unwrap();
    // Half-close the upload; the target never answers, so the linger deadline must cut it.
    write.shutdown().await.unwrap();
    let started = Instant::now();
    let mut buried = [0u8; 8];
    let result = read.read(&mut buried).await;
    assert_eq!(result.unwrap_or(0), 0, "session must end with EOF");
    assert!(started.elapsed() < Duration::from_secs(3));
    wait_until(Duration::from_secs(2), || {
        running.kernel().stats().active == 0
    })
    .await;
    assert!(running.kernel().stats().failed >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_failures_are_reported_and_sessions_reclaimed() {
    let document = direct_config();
    let (running, _) = Running::start(&document, standard_limits());

    // Unknown first byte (not SOCKS5, not an HTTP method).
    let mut raw = tokio::net::TcpStream::connect(running.proxy).await.unwrap();
    // The kernel closes the connection on the first unknown byte; later writes may fail.
    let _ = raw.write_all(&[0x16, 0x03, 0x01, 0x00]).await;
    let mut closed = Vec::new();
    let _ = raw.read_to_end(&mut closed).await;

    // SOCKS5 BIND is refused explicitly; UDP ASSOCIATE is served (the helper
    // drops its control connection right after the reply, which ends the
    // association and releases its sockets).
    assert_eq!(socks5_command(running.proxy, 0x02).await.unwrap(), 0x07);
    assert_eq!(socks5_command(running.proxy, 0x03).await.unwrap(), 0x00);

    // HTTP proxy request without CONNECT is refused with 405.
    let mut raw = tokio::net::TcpStream::connect(running.proxy).await.unwrap();
    raw.write_all(b"GET http://example/ HTTP/1.1\r\nHost: example\r\n\r\n")
        .await
        .unwrap();
    let mut reply = Vec::new();
    let _ = raw.read_to_end(&mut reply).await;
    assert!(
        reply.starts_with(b"HTTP/1.1 405 Method Not Allowed"),
        "{}",
        String::from_utf8_lossy(&reply)
    );

    wait_until(Duration::from_secs(3), || {
        running.kernel().stats().active == 0
    })
    .await;
    let stats = running.kernel().stats();
    // unknown byte, BIND and the non-CONNECT HTTP request fail; the UDP
    // association completes when its control connection closes.
    assert_eq!(stats.failed, 3, "{stats:?}");
    assert_eq!(stats.completed, 1, "{stats:?}");
    assert_eq!(stats.active, 0);
}

#[tokio::test]
async fn handshake_deadline_drops_silent_clients() {
    let document = direct_config();
    let (running, _) = Running::start(
        &document,
        Limits {
            handshake_timeout: Duration::from_millis(200),
            ..Limits::default()
        },
    );
    let mut idle = tokio::net::TcpStream::connect(running.proxy).await.unwrap();
    idle.write_all(&[0x05, 0x01]).await.unwrap();
    let mut one = [0u8; 1];
    // Method negotiation waits for the method list; the deadline must cut it.
    let n = tokio::time::timeout(Duration::from_secs(2), idle.read(&mut one))
        .await
        .expect("deadline fires")
        .unwrap_or(0);
    assert_eq!(n, 0);
    wait_until(Duration::from_secs(2), || {
        running.kernel().stats().active == 0
    })
    .await;
    drop(idle);
    assert_eq!(running.kernel().stats().failed, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_cap_bounds_concurrency() {
    let endpoint = spawn_endpoint(EchoMode::Echo).await;
    let document = direct_config();
    let (running, _) = Running::start(
        &document,
        Limits {
            max_sessions: 2,
            ..standard_limits()
        },
    );

    let mut first = socks5_connect(running.proxy, "127.0.0.1", endpoint.port)
        .await
        .unwrap();
    let mut second = socks5_connect(running.proxy, "127.0.0.1", endpoint.port)
        .await
        .unwrap();
    first.write_all(b"a").await.unwrap();
    second.write_all(b"b").await.unwrap();
    // A third client connects; the kernel does not accept it until a slot frees.
    let mut third = tokio::net::TcpStream::connect(running.proxy).await.unwrap();
    let mut probe = [0u8; 1];
    first.read_exact(&mut probe).await.unwrap();
    assert_eq!(&probe, b"a");
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(running.kernel().stats().active, 2);
    let mut got = [0u8; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), third.read(&mut got))
            .await
            .is_err(),
        "capped client must not be served"
    );

    drop(first);
    third.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    third.read_exact(&mut got).await.unwrap();
    assert_eq!(got[0], 0x05);
    drop(second);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_releases_in_flight_sessions_and_restart_binds_again() {
    let endpoint = spawn_endpoint(EchoMode::Echo).await;
    let port = free_port();
    let document = config_on_port(port, &["MATCH,DIRECT"]);
    let limits = Limits {
        half_close_timeout: Duration::from_secs(1),
        ..Limits::default()
    };

    for round in 0..3 {
        let (kernel, _) = Kernel::start_from_yaml(&document, None, limits)
            .unwrap_or_else(|e| panic!("round {round}: {e}"));
        let mut kernel = kernel;
        let proxy = kernel.listen_addr();
        assert_eq!(proxy.port(), port);
        let identity = kernel.identity().clone();
        assert!(!identity.uuid.is_empty(), "instance uuid is exposed");
        assert_eq!(identity.pid, std::process::id());
        assert!(identity.to_line().contains("version=0.1.0"));

        let mut open = socks5_connect(proxy, "127.0.0.1", endpoint.port)
            .await
            .unwrap();
        open.write_all(b"live").await.unwrap();
        let mut reply = [0u8; 4];
        open.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"live");

        wait_until(Duration::from_secs(5), || kernel.stats().active == 1).await;
        let started = Instant::now();
        kernel.stop().expect("stop joins sessions");
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "stop must not wait for the linger of an idle peer"
        );
        assert_eq!(kernel.stats().active, 0, "every session must be reclaimed");
        let mut eof = [0u8; 1];
        assert_eq!(
            open.read(&mut eof).await.unwrap_or(0),
            0,
            "in-flight tunnel closes on stop"
        );
        drop(open);

        // A new instance gets a new identity, else logs of restarts could not be told apart.
        let id2 = kernel.identity().uuid.clone();
        drop(kernel);
        let (mut again, _) = Kernel::start_from_yaml(&document, None, limits)
            .unwrap_or_else(|e| panic!("restart {round}: {e}"));
        assert_ne!(again.identity().uuid, id2);
        assert_eq!(again.listen_addr(), proxy, "restart rebinds the same port");
        again.stop().unwrap();
    }
}

#[tokio::test]
async fn direct_dial_failure_reports_502_and_recovers() {
    let closed_port = free_port();
    let document = direct_config();
    let (running, _) = Running::start(&document, standard_limits());
    let (_stream, status) = http_connect(running.proxy, &format!("127.0.0.1:{closed_port}"))
        .await
        .unwrap();
    assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
    let e = socks5_connect(running.proxy, "127.0.0.1", closed_port)
        .await
        .err()
        .expect("dial fails");
    assert!(e.to_string().contains("0x01"), "{e}");
    wait_until(Duration::from_secs(3), || {
        running.kernel().stats().active == 0
    })
    .await;
    assert_eq!(running.kernel().stats().failed, 2);
}

#[test]
fn config_without_rules_goes_direct() {
    let document = format!("mixed-port: {}\n", free_port());
    let (kernel, _) = Kernel::start_from_yaml(&document, None, Limits::default()).unwrap();
    let (action, label) = kernel.evaluate("anything.example", None);
    assert_eq!(action, billow_kernel::Action::Direct);
    assert_eq!(label, "MATCH -> DIRECT");
    let config: &std::sync::Arc<Config> = kernel.config();
    assert!(config.empty_rules);
    let mut kernel = kernel;
    kernel.stop().unwrap();
}
