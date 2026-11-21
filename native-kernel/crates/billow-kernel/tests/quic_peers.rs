//! QUIC family loopback peers (T10).
//!
//! The TUIC v5 peer is a `quinn` server written from
//! `transport/tuic/v5/{protocol,server}.go`: it checks the TLS-exporter token,
//! decodes the Connect address and echoes the stream. It shares only the QUIC
//! transport crate with the client, not the client's framing code, so the test
//! observes the wire format rather than a shared implementation.
//!
//! The pinned Mihomo binary also has a TUIC listener; the interop run lives in
//! `tests/mihomo_peers.rs` and `tool/kernel-compat/peer-tests.sh`. These cases
//! are part of the default suite because they need no external binary.

#[allow(dead_code)]
mod common;

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use billow_kernel::{Kernel, Limits};
use common::{free_port, socks5_connect};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
const UUID: &str = "9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68";
const PASSWORD: &str = "tuic-secret";

#[derive(Debug, Clone, Default)]
struct Attempt {
    details: Vec<String>,
    forwarded: bool,
}

type Log = Arc<Mutex<Vec<Attempt>>>;

fn push(log: &Log, attempt: Attempt) {
    log.lock().unwrap().push(attempt);
}

fn detail(log: &Log) -> Vec<String> {
    log.lock()
        .unwrap()
        .iter()
        .flat_map(|a| a.details.clone())
        .collect()
}

fn forwarded_count(log: &Log) -> usize {
    log.lock().unwrap().iter().filter(|a| a.forwarded).count()
}

async fn wait_for_detail(log: &Log, prefix: &str) -> bool {
    for _ in 0..300 {
        if detail(log).iter().any(|d| d.starts_with(prefix)) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

// ---------------------------------------------------------------------------
// Self-signed loopback certificate (openssl, as in tests/protocols.rs).
// ---------------------------------------------------------------------------

struct Cert {
    der: Vec<u8>,
    key: PathBuf,
    dir: PathBuf,
}

impl Drop for Cert {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn make_cert(name: &str) -> Cert {
    let dir = std::env::temp_dir().join(format!(
        "billow-quic-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("key.pem");
    let cert = dir.join("cert.pem");
    let status = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes"])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args([
            "-days",
            "1",
            "-subj",
            "/CN=billow-quic-test",
            "-addext",
            "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("openssl is required for the QUIC peers");
    assert!(
        status.success(),
        "openssl failed to mint the QUIC certificate"
    );
    let pem = std::fs::read_to_string(&cert).unwrap();
    let der = rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .unwrap()
        .unwrap()
        .as_ref()
        .to_vec();
    Cert { der, key, dir }
}

fn server_config(cert: &Cert, alpn: &[u8]) -> quinn::ServerConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der.clone())],
            rustls_pemfile::private_key(&mut std::io::BufReader::new(
                std::fs::File::open(&cert.key).unwrap(),
            ))
            .unwrap()
            .unwrap(),
        )
        .unwrap();
    config.alpn_protocols = vec![alpn.to_vec()];
    let crypto = QuicServerConfig::try_from(config).unwrap();
    quinn::ServerConfig::with_crypto(Arc::new(crypto))
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn server_config_with_stream_limits(
    cert: &Cert,
    alpn: &[u8],
    uni: u32,
    bidi: u32,
) -> quinn::ServerConfig {
    let mut config = server_config(cert, alpn);
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(uni.into());
    transport.max_concurrent_bidi_streams(bidi.into());
    config.transport_config(Arc::new(transport));
    config
}

// ---------------------------------------------------------------------------
// TUIC v5 peer.
// ---------------------------------------------------------------------------

async fn read_address(recv: &mut quinn::RecvStream) -> io::Result<(String, u16)> {
    let mut kind = [0u8; 1];
    recv.read_exact(&mut kind)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    let host = match kind[0] {
        0 => {
            let mut len = [0u8; 1];
            recv.read_exact(&mut len)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            let mut name = vec![0u8; len[0] as usize];
            recv.read_exact(&mut name)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            String::from_utf8(name)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "domain"))?
        }
        1 => {
            let mut addr = [0u8; 4];
            recv.read_exact(&mut addr)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            std::net::Ipv4Addr::from(addr).to_string()
        }
        2 => {
            let mut addr = [0u8; 16];
            recv.read_exact(&mut addr)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            std::net::Ipv6Addr::from(addr).to_string()
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad TUIC address type {other}"),
            ))
        }
    };
    let mut port = [0u8; 2];
    recv.read_exact(&mut port)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok((host, u16::from_be_bytes(port)))
}

async fn spawn_tuic_peer(password: &'static str, cert: Cert) -> (u16, Log) {
    let port = free_udp_port();
    let endpoint = quinn::Endpoint::server(
        server_config(&cert, b"h3"),
        SocketAddr::from(([127, 0, 0, 1], port)),
    )
    .expect("QUIC server endpoint");
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let log_task = log.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let log = log_task.clone();
            tokio::spawn(async move {
                let connection = match incoming.await {
                    Ok(connection) => connection,
                    Err(e) => {
                        push(
                            &log,
                            Attempt {
                                details: vec![format!("handshake-failed={e}")],
                                forwarded: false,
                            },
                        );
                        return;
                    }
                };
                let mut auth = match connection.accept_uni().await {
                    Ok(stream) => stream,
                    Err(e) => {
                        push(
                            &log,
                            Attempt {
                                details: vec![format!("auth-stream-error={e}")],
                                forwarded: false,
                            },
                        );
                        return;
                    }
                };
                let mut header = [0u8; 50];
                if auth.read_exact(&mut header).await.is_err() {
                    push(
                        &log,
                        Attempt {
                            details: vec!["auth-short".into()],
                            forwarded: false,
                        },
                    );
                    return;
                }
                if header[0] != 0x05 || header[1] != 0x00 {
                    push(
                        &log,
                        Attempt {
                            details: vec![format!("bad-auth-head={:02x?}", &header[..2])],
                            forwarded: false,
                        },
                    );
                    connection.close(
                        quinn::VarInt::from_u32(0xffff_fff1),
                        b"AuthenticationFailed",
                    );
                    return;
                }
                let mut expected = [0u8; 32];
                if connection
                    .export_keying_material(&mut expected, &header[2..18], password.as_bytes())
                    .is_err()
                {
                    push(
                        &log,
                        Attempt {
                            details: vec!["exporter-failed".into()],
                            forwarded: false,
                        },
                    );
                    return;
                }
                if expected != header[18..50] {
                    push(
                        &log,
                        Attempt {
                            details: vec!["auth-failed".into()],
                            forwarded: false,
                        },
                    );
                    connection.close(
                        quinn::VarInt::from_u32(0xffff_fff1),
                        b"AuthenticationFailed",
                    );
                    return;
                }
                push(
                    &log,
                    Attempt {
                        details: vec!["auth-ok".into()],
                        forwarded: false,
                    },
                );
                let (mut send, mut recv) = match connection.accept_bi().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        push(
                            &log,
                            Attempt {
                                details: vec![format!("stream-error={e}")],
                                forwarded: false,
                            },
                        );
                        return;
                    }
                };
                let mut head = [0u8; 2];
                if recv.read_exact(&mut head).await.is_err() || head != [0x05, 0x01] {
                    push(
                        &log,
                        Attempt {
                            details: vec![format!("bad-connect-head={:02x?}", head)],
                            forwarded: false,
                        },
                    );
                    return;
                }
                let (host, port) = match read_address(&mut recv).await {
                    Ok(target) => target,
                    Err(e) => {
                        push(
                            &log,
                            Attempt {
                                details: vec![format!("address-error={e}")],
                                forwarded: false,
                            },
                        );
                        return;
                    }
                };
                push(
                    &log,
                    Attempt {
                        details: vec![format!("target={host}:{port}")],
                        forwarded: true,
                    },
                );
                let mut buffer = [0u8; 4096];
                loop {
                    match recv.read(&mut buffer).await {
                        Ok(Some(0)) | Ok(None) | Err(_) => break,
                        Ok(Some(n)) => {
                            if send.write_all(&buffer[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = send.finish();
            });
        }
    });
    (port, log)
}

// ---------------------------------------------------------------------------
// Kernel helpers.
// ---------------------------------------------------------------------------

fn limits() -> Limits {
    Limits {
        half_close_timeout: Duration::from_secs(3),
        dial_timeout: Duration::from_secs(5),
        ..Limits::default()
    }
}

fn start_kernel(peer_port: u16, password: &str) -> Kernel {
    let yaml = format!(
        "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: t1, type: tuic, server: 127.0.0.1, port: {peer_port}, uuid: {UUID}, password: {password}, skip-cert-verify: true}}\nrules:\n  - MATCH,t1\n",
        free_port()
    );
    let (kernel, warnings) = Kernel::start_from_yaml(&yaml, None, limits())
        .unwrap_or_else(|e| panic!("kernel rejected TUIC config: {e}\n{yaml}"));
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    kernel
}

async fn roundtrip(kernel: &Kernel, host: &str, port: u16, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        socks5_connect(kernel.listen_addr(), host, port),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "inbound handshake timed out"))??;
    stream.write_all(payload).await?;
    let mut back = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut back))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tunnel payload timed out"))??;
    Ok(back)
}

// ---------------------------------------------------------------------------
// Cases.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn tuic_v5_domain_target_roundtrip() {
    let cert = make_cert("tuic-domain");
    let (peer_port, log) = spawn_tuic_peer(PASSWORD, cert).await;
    let mut kernel = start_kernel(peer_port, PASSWORD);
    let echoed = roundtrip(&kernel, "example.com", 443, b"tuic-domain-payload")
        .await
        .expect("TUIC v5 domain roundtrip");
    assert_eq!(echoed, b"tuic-domain-payload");
    assert!(wait_for_detail(&log, "auth-ok").await, "{:?}", detail(&log));
    assert!(
        detail(&log).iter().any(|d| d == "target=example.com:443"),
        "{:?}",
        detail(&log)
    );
    assert_eq!(forwarded_count(&log), 1);
    kernel.stop().unwrap();
}

#[tokio::test]
async fn tuic_v5_ip_target_roundtrip() {
    let cert = make_cert("tuic-ip");
    let (peer_port, log) = spawn_tuic_peer(PASSWORD, cert).await;
    let mut kernel = start_kernel(peer_port, PASSWORD);
    let echoed = roundtrip(&kernel, "127.0.0.1", 8080, b"tuic-ip-payload")
        .await
        .expect("TUIC v5 IP roundtrip");
    assert_eq!(echoed, b"tuic-ip-payload");
    assert!(
        detail(&log).iter().any(|d| d == "target=127.0.0.1:8080"),
        "{:?}",
        detail(&log)
    );
    kernel.stop().unwrap();
}

#[tokio::test]
async fn tuic_v5_wrong_password_fails_without_forwarding() {
    let cert = make_cert("tuic-wrong");
    let (peer_port, log) = spawn_tuic_peer(PASSWORD, cert).await;
    let mut kernel = start_kernel(peer_port, "not-the-password");
    // The success reply may arrive before the server has processed the auth
    // stream; the payload read is what must fail.
    let result = roundtrip(&kernel, "example.com", 443, b"must-not-arrive").await;
    assert!(
        result.is_err() || matches!(&result, Ok(bytes) if bytes.is_empty()),
        "a wrong password must not produce an echo: {result:?}"
    );
    assert!(
        wait_for_detail(&log, "auth-failed").await,
        "{:?}",
        detail(&log)
    );
    assert_eq!(forwarded_count(&log), 0, "{:?}", detail(&log));
    kernel.stop().unwrap();
}

#[tokio::test]
async fn tuic_v5_legacy_token_is_rejected_at_load() {
    let yaml = format!(
        "mixed-port: 17890\nproxies:\n  - {{name: t1, type: tuic, server: 127.0.0.1, port: 443, token: legacy}}\nrules:\n  - MATCH,t1\n"
    );
    let error = billow_kernel::load_config(&yaml, "tuic-token.yaml").unwrap_err();
    assert_eq!(error.tag(), "unsupported");
    assert!(
        error.to_string().contains("v4") && error.to_string().contains("token"),
        "{error}"
    );
}

#[tokio::test]
async fn tuic_v5_unimplemented_options_are_named() {
    for (option, value) in [
        ("reduce-rtt", "true"),
        ("fast-open", "true"),
        ("udp-over-stream", "true"),
        ("congestion-controller", "bbr"),
        ("recv-window", "1024"),
    ] {
        let yaml = format!(
            "mixed-port: 17890\nproxies:\n  - {{name: t1, type: tuic, server: 127.0.0.1, port: 443, uuid: {UUID}, password: x, {option}: {value}}}\nrules:\n  - MATCH,t1\n"
        );
        let error = billow_kernel::load_config(&yaml, "tuic-option.yaml").unwrap_err();
        assert_eq!(error.tag(), "unsupported", "{option}: {error}");
        assert!(error.to_string().contains(option), "{option}: {error}");
    }
}

// ---------------------------------------------------------------------------
// Hysteria v1 peer (`transport/hysteria/core/protocol.go`).
// ---------------------------------------------------------------------------

async fn spawn_hysteria_peer(auth: Vec<u8>, cert: Cert) -> (u16, Log) {
    let port = free_udp_port();
    let endpoint = quinn::Endpoint::server(
        server_config(&cert, b"hysteria"),
        SocketAddr::from(([127, 0, 0, 1], port)),
    )
    .expect("QUIC server endpoint");
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let log_task = log.clone();
    let auth = Arc::new(auth);
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let log = log_task.clone();
            let auth = auth.clone();
            tokio::spawn(async move {
                let connection = match incoming.await {
                    Ok(connection) => connection,
                    Err(e) => {
                        push(
                            &log,
                            Attempt {
                                details: vec![format!("handshake-failed={e}")],
                                forwarded: false,
                            },
                        );
                        return;
                    }
                };
                let (mut control_send, mut control_recv) = match connection.accept_bi().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let mut head = [0u8; 19];
                if control_recv.read_exact(&mut head).await.is_err() {
                    return;
                }
                let version = head[0];
                let send_bps = u64::from_be_bytes(head[1..9].try_into().unwrap());
                let recv_bps = u64::from_be_bytes(head[9..17].try_into().unwrap());
                let auth_len = u16::from_be_bytes([head[17], head[18]]) as usize;
                let mut client_auth = vec![0u8; auth_len];
                if control_recv.read_exact(&mut client_auth).await.is_err() {
                    return;
                }
                let mut hello = Vec::new();
                if version != 3 {
                    push(
                        &log,
                        Attempt {
                            details: vec![format!("bad-version={version}")],
                            forwarded: false,
                        },
                    );
                    hello.push(0);
                    hello.extend_from_slice(&0u64.to_be_bytes());
                    hello.extend_from_slice(&0u64.to_be_bytes());
                    hello.extend_from_slice(&b"unsupported client version".len().to_be_bytes());
                    hello.extend_from_slice(b"unsupported client version");
                    let _ = control_send.write_all(&hello).await;
                    let _ = control_send.finish();
                    return;
                }
                if client_auth != *auth {
                    push(
                        &log,
                        Attempt {
                            details: vec!["auth-failed".into()],
                            forwarded: false,
                        },
                    );
                    hello.push(0);
                    hello.extend_from_slice(&send_bps.to_be_bytes());
                    hello.extend_from_slice(&recv_bps.to_be_bytes());
                    hello.extend_from_slice(&b"auth error".len().to_be_bytes());
                    hello.extend_from_slice(b"auth error");
                    let _ = control_send.write_all(&hello).await;
                    let _ = control_send.finish();
                    return;
                }
                push(
                    &log,
                    Attempt {
                        details: vec!["auth-ok".into()],
                        forwarded: false,
                    },
                );
                hello.push(1);
                hello.extend_from_slice(&send_bps.to_be_bytes());
                hello.extend_from_slice(&recv_bps.to_be_bytes());
                hello.extend_from_slice(&0u16.to_be_bytes());
                let _ = control_send.write_all(&hello).await;
                let _ = control_send.finish();

                let (mut send, mut recv) = match connection.accept_bi().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let mut udp = [0u8; 1];
                if recv.read_exact(&mut udp).await.is_err() {
                    return;
                }
                let mut host_len = [0u8; 2];
                if recv.read_exact(&mut host_len).await.is_err() {
                    return;
                }
                let mut host = vec![0u8; u16::from_be_bytes(host_len) as usize];
                if recv.read_exact(&mut host).await.is_err() {
                    return;
                }
                let mut port = [0u8; 2];
                if recv.read_exact(&mut port).await.is_err() {
                    return;
                }
                let target = format!(
                    "{}:{}",
                    String::from_utf8_lossy(&host),
                    u16::from_be_bytes(port)
                );
                if udp[0] != 0 {
                    push(
                        &log,
                        Attempt {
                            details: vec![format!("udp-request={target}")],
                            forwarded: false,
                        },
                    );
                    let _ = send.write_all(&[0, 0, 0, 0, 0, 0, 2]).await;
                    let _ = send.write_all(b"udp not implemented").await;
                    let _ = send.finish();
                    return;
                }
                push(
                    &log,
                    Attempt {
                        details: vec![format!("target={target}")],
                        forwarded: true,
                    },
                );
                let _ = send.write_all(&[1, 0, 0, 0, 0, 0, 0]).await;
                let mut buffer = [0u8; 4096];
                loop {
                    match recv.read(&mut buffer).await {
                        Ok(Some(0)) | Ok(None) | Err(_) => break,
                        Ok(Some(n)) => {
                            if send.write_all(&buffer[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = send.finish();
            });
        }
    });
    (port, log)
}

fn start_hysteria_kernel(peer_port: u16, auth: &str, extra: &str) -> Kernel {
    let yaml = format!(
        "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: h1, type: hysteria, server: 127.0.0.1, port: {peer_port}, up: 50 Mbps, down: 50 Mbps, auth-str: \"{auth}\", skip-cert-verify: true{extra}}}\nrules:\n  - MATCH,h1\n",
        free_port()
    );
    let (kernel, warnings) = Kernel::start_from_yaml(&yaml, None, limits())
        .unwrap_or_else(|e| panic!("kernel rejected hysteria config: {e}\n{yaml}"));
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    kernel
}

#[tokio::test]
async fn hysteria_v1_tcp_roundtrip_and_target() {
    let cert = make_cert("hysteria");
    let (peer_port, log) = spawn_hysteria_peer(b"hysteria-secret".to_vec(), cert).await;
    let mut kernel = start_hysteria_kernel(peer_port, "hysteria-secret", "");
    let echoed = roundtrip(&kernel, "example.com", 8443, b"hysteria-payload")
        .await
        .expect("hysteria TCP roundtrip");
    assert_eq!(echoed, b"hysteria-payload");
    assert!(wait_for_detail(&log, "auth-ok").await, "{:?}", detail(&log));
    assert!(
        detail(&log).iter().any(|d| d == "target=example.com:8443"),
        "{:?}",
        detail(&log)
    );
    kernel.stop().unwrap();
}

#[tokio::test]
async fn hysteria_v1_wrong_auth_fails_without_forwarding() {
    let cert = make_cert("hysteria-wrong");
    let (peer_port, log) = spawn_hysteria_peer(b"hysteria-secret".to_vec(), cert).await;
    let mut kernel = start_hysteria_kernel(peer_port, "wrong-secret", "");
    let result = roundtrip(&kernel, "example.com", 8443, b"must-not-arrive").await;
    assert!(
        result.is_err() || matches!(&result, Ok(bytes) if bytes.is_empty()),
        "wrong auth must not echo: {result:?}"
    );
    assert!(
        wait_for_detail(&log, "auth-failed").await,
        "{:?}",
        detail(&log)
    );
    assert_eq!(forwarded_count(&log), 0);
    kernel.stop().unwrap();
}

#[tokio::test]
async fn hysteria_v1_base64_auth_roundtrip() {
    // `auth` is base64("aHVzdGxl") = "hustle"; the peer checks the decoded bytes.
    let cert = make_cert("hysteria-b64");
    let (peer_port, log) = spawn_hysteria_peer(b"hustle".to_vec(), cert).await;
    let yaml = format!(
        "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: h1, type: hysteria, server: 127.0.0.1, port: {peer_port}, up: 50 Mbps, down: 50 Mbps, auth: aHVzdGxl, skip-cert-verify: true}}\nrules:\n  - MATCH,h1\n",
        free_port()
    );
    let (mut kernel, _) = Kernel::start_from_yaml(&yaml, None, limits()).expect("kernel starts");
    let echoed = roundtrip(&kernel, "127.0.0.1", 80, b"b64-payload")
        .await
        .expect("hysteria base64 auth roundtrip");
    assert_eq!(echoed, b"b64-payload");
    assert!(wait_for_detail(&log, "auth-ok").await, "{:?}", detail(&log));
    kernel.stop().unwrap();
}

#[tokio::test]
async fn hysteria_v1_unsupported_options_are_named() {
    for (option, value) in [
        ("obfs", "xplus"),
        ("ports", "443,8443"),
        ("protocol", "faketcp"),
        ("fast-open", "true"),
    ] {
        let yaml = format!(
            "mixed-port: 17890\nproxies:\n  - {{name: h1, type: hysteria, server: 127.0.0.1, port: 443, up: 50 Mbps, down: 50 Mbps, {option}: {value}}}\nrules:\n  - MATCH,h1\n"
        );
        let error = billow_kernel::load_config(&yaml, "hysteria-option.yaml").unwrap_err();
        assert_eq!(error.tag(), "unsupported", "{option}: {error}");
        assert!(error.to_string().contains(option), "{option}: {error}");
    }
}

#[tokio::test]
async fn hysteria_v1_requires_valid_rates() {
    for (up, down) in [("", "50 Mbps"), ("50 Mbps", ""), ("fast", "50 Mbps")] {
        let yaml = format!(
            "mixed-port: 17890\nproxies:\n  - {{name: h1, type: hysteria, server: 127.0.0.1, port: 443, up: \"{up}\", down: \"{down}\"}}\nrules:\n  - MATCH,h1\n"
        );
        let error = billow_kernel::load_config(&yaml, "hysteria-rate.yaml").unwrap_err();
        assert_eq!(
            error.tag(),
            "invalid_value",
            "up={up:?} down={down:?}: {error}"
        );
    }
}

// ---------------------------------------------------------------------------
// TUIC `request-timeout`: a peer that advertises no stream credit makes the
// client's open_uni wait, so a small request-timeout is observable.
// ---------------------------------------------------------------------------

async fn spawn_tuic_blocked_peer(cert: Cert) -> u16 {
    let port = free_udp_port();
    let endpoint = quinn::Endpoint::server(
        server_config_with_stream_limits(&cert, b"h3", 0, 0),
        SocketAddr::from(([127, 0, 0, 1], port)),
    )
    .expect("QUIC server endpoint");
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let _connection = incoming.await;
                // Hold the connection without granting stream credit.
                tokio::time::sleep(Duration::from_secs(60)).await;
            });
        }
    });
    port
}

#[tokio::test]
async fn tuic_v5_request_timeout_bounds_stream_open() {
    let cert = make_cert("tuic-timeout");
    let peer_port = spawn_tuic_blocked_peer(cert).await;
    let yaml = format!(
        "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: t1, type: tuic, server: 127.0.0.1, port: {peer_port}, uuid: {UUID}, password: {PASSWORD}, request-timeout: 100, skip-cert-verify: true}}\nrules:\n  - MATCH,t1\n",
        free_port()
    );
    let (mut kernel, warnings) =
        Kernel::start_from_yaml(&yaml, None, limits()).expect("kernel starts");
    assert!(warnings.is_empty(), "{warnings:?}");
    let started = std::time::Instant::now();
    let result = socks5_connect(kernel.listen_addr(), "example.com", 443).await;
    let elapsed = started.elapsed();
    assert!(
        result.is_err(),
        "a blocked TUIC stream open must fail, not hang: {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "request-timeout was not applied (took {elapsed:?})"
    );
    kernel.stop().unwrap();
}

#[tokio::test]
async fn hysteria2_up_is_rejected_at_load() {
    let yaml = "mixed-port: 17890\nproxies:\n  - {name: h2, type: hysteria2, server: 127.0.0.1, port: 443, password: p, up: 50 Mbps}\nrules:\n  - MATCH,h2\n";
    let error = billow_kernel::load_config(yaml, "hysteria2-up.yaml").unwrap_err();
    assert_eq!(error.tag(), "unsupported");
    assert!(error.to_string().contains("'up'"), "{error}");
    // An empty `up` asks for nothing and is accepted, like Mihomo's decoder.
    let empty = "mixed-port: 17890\nproxies:\n  - {name: h2, type: hysteria2, server: 127.0.0.1, port: 443, password: p, up: ''}\nrules:\n  - MATCH,h2\n";
    assert!(billow_kernel::load_config(empty, "hysteria2-up-empty.yaml").is_ok());
}

// ---------------------------------------------------------------------------
// MASQUE CONNECT-UDP peer (RFC 9298 over HTTP/3).
//
// The peer is a quinn server with an independent HTTP/3/QPACK codec: it checks
// the CONNECT-UDP request headers, answers 200 + `capsule-protocol: ?1` and
// echoes every `DATAGRAM` capsule. The pinned Mihomo adapter is a Cloudflare
// WARP CONNECT-IP client with no listener and no reachable endpoint offline,
// so the controlled peer is the verification target; the evidence records why.
// ---------------------------------------------------------------------------

type PeerLog = Arc<Mutex<Vec<String>>>;

fn note(log: &PeerLog, line: impl Into<String>) {
    log.lock().unwrap().push(line.into());
}

fn peer_log_has(log: &PeerLog, needle: &str) -> bool {
    log.lock().unwrap().iter().any(|line| line.contains(needle))
}

async fn wait_for_peer_log(log: &PeerLog, needle: &str) -> bool {
    for _ in 0..300 {
        if peer_log_has(log, needle) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

fn put_varint(value: u64, out: &mut Vec<u8>) {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16_384 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 1_073_741_824 {
        out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

fn take_varint(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *bytes.get(*pos)?;
    let length = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for index in 1..length {
        value = (value << 8) | u64::from(*bytes.get(*pos + index)?);
    }
    *pos += length;
    Some(value)
}

fn put_prefixed(out: &mut Vec<u8>, prefix_bits: u8, first: u8, value: usize) {
    let max = (1usize << prefix_bits) - 1;
    if value < max {
        out.push(first | value as u8);
        return;
    }
    out.push(first | max as u8);
    let mut rest = value - max;
    while rest >= 128 {
        out.push((rest % 128) as u8 | 0x80);
        rest /= 128;
    }
    out.push(rest as u8);
}

fn take_prefixed(bytes: &[u8], pos: &mut usize, prefix_bits: u8) -> Option<usize> {
    let max = (1usize << prefix_bits) - 1;
    let mut value = usize::from(*bytes.get(*pos)?) & max;
    *pos += 1;
    if value < max {
        return Some(value);
    }
    let mut shift = 0;
    loop {
        let byte = *bytes.get(*pos)?;
        *pos += 1;
        value += usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift > 56 {
            return None;
        }
    }
}

/// QPACK field section with literal names/values (the form the client sends)
/// and the static table's indexed `:status` entries (the form this peer could
/// send; it uses literal names instead). Written from the RFC 9204 field-line
/// encodings, not shared with the client's codec.
fn peer_encode_headers(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00];
    for (name, value) in headers {
        put_prefixed(&mut out, 3, 0x20, name.len());
        out.extend_from_slice(name.as_bytes());
        put_prefixed(&mut out, 7, 0x00, value.len());
        out.extend_from_slice(value.as_bytes());
    }
    out
}

fn peer_decode_headers(bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut pos = 0;
    let required = take_prefixed(bytes, &mut pos, 8).ok_or("insert count")?;
    if required != 0 {
        return Err("dynamic table reference".to_string());
    }
    // Delta Base: 7-bit prefix with a sign bit.
    let _ = take_prefixed(bytes, &mut pos, 7).ok_or("delta base")?;
    let mut fields = Vec::new();
    while pos < bytes.len() {
        let first = bytes[pos];
        if first & 0x80 != 0 {
            // Indexed static field: only :status values are needed here.
            let index = take_prefixed(bytes, &mut pos, 6).ok_or("indexed field")?;
            if first & 0x40 == 0 {
                return Err("dynamic indexed field".to_string());
            }
            let status = match index {
                24 => "103",
                25 => "200",
                26 => "304",
                27 => "404",
                28 => "503",
                63 => "100",
                64 => "204",
                65 => "206",
                66 => "302",
                67 => "400",
                68 => "403",
                69 => "421",
                70 => "425",
                71 => "500",
                _ => return Err(format!("static index {index} not decoded by the peer")),
            };
            fields.push((":status".to_string(), status.to_string()));
        } else if first & 0x40 != 0 {
            return Err("static name reference is not used by the client".to_string());
        } else if first & 0x20 != 0 {
            if first & 0x08 != 0 {
                return Err("Huffman is not used by the client".to_string());
            }
            let length = take_prefixed(bytes, &mut pos, 3).ok_or("literal name length")?;
            let end = pos + length;
            let name = bytes.get(pos..end).ok_or("literal name")?;
            pos = end;
            let name = String::from_utf8(name.to_vec()).map_err(|_| "name is not UTF-8")?;
            if bytes.get(pos).is_none() {
                return Err("missing value".to_string());
            }
            let huffman = bytes[pos] & 0x80 != 0;
            if huffman {
                return Err("Huffman value is not used by the client".to_string());
            }
            let length = take_prefixed(bytes, &mut pos, 7).ok_or("value length")?;
            let end = pos + length;
            let value = bytes.get(pos..end).ok_or("value")?;
            pos = end;
            fields.push((
                name,
                String::from_utf8(value.to_vec()).map_err(|_| "value is not UTF-8")?,
            ));
        } else {
            return Err("post-base field line".to_string());
        }
    }
    Ok(fields)
}

async fn peer_read_varint(recv: &mut quinn::RecvStream) -> io::Result<Option<u64>> {
    let mut first = [0u8; 1];
    match recv.read(&mut first).await {
        Ok(Some(_)) => {}
        Ok(None) => return Ok(None),
        Err(e) => return Err(io::Error::other(e.to_string())),
    }
    let extra = 1usize << (first[0] >> 6);
    let mut raw = vec![first[0]];
    if extra > 1 {
        let mut rest = vec![0u8; extra - 1];
        recv.read_exact(&mut rest)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        raw.extend_from_slice(&rest);
    }
    let mut pos = 0;
    Ok(take_varint(&raw, &mut pos))
}

async fn peer_read_frame(recv: &mut quinn::RecvStream) -> io::Result<Option<(u64, Vec<u8>)>> {
    let Some(frame_type) = peer_read_varint(recv).await? else {
        return Ok(None);
    };
    let Some(length) = peer_read_varint(recv).await? else {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "HTTP/3 frame length",
        ));
    };
    if length > 1 << 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut payload = vec![0u8; length as usize];
    recv.read_exact(&mut payload)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(Some((frame_type, payload)))
}

async fn peer_write_headers(
    send: &mut quinn::SendStream,
    headers: &[(&str, &str)],
) -> io::Result<()> {
    let block = peer_encode_headers(headers);
    let mut frame = Vec::new();
    put_varint(0x01, &mut frame);
    put_varint(block.len() as u64, &mut frame);
    frame.extend_from_slice(&block);
    send.write_all(&frame)
        .await
        .map_err(|e| io::Error::other(e.to_string()))
}

/// Take one complete capsule; `Ok(None)` means the bytes so far are partial.
fn peer_take_capsule(buffer: &mut Vec<u8>) -> Result<Option<(u64, Vec<u8>)>, ()> {
    let mut pos = 0;
    let Some(kind) = take_varint(buffer, &mut pos) else {
        return Ok(None);
    };
    let Some(length) = take_varint(buffer, &mut pos) else {
        return Ok(None);
    };
    let length = length as usize;
    let Some(end) = pos.checked_add(length) else {
        return Err(());
    };
    if buffer.len() < end {
        return Ok(None);
    }
    let value = buffer[pos..end].to_vec();
    buffer.drain(..end);
    Ok(Some((kind, value)))
}

#[derive(Clone, Copy)]
enum MasqueMode {
    Accept,
    Refuse(u16),
    /// No `SETTINGS_ENABLE_CONNECT_PROTOCOL`: extended CONNECT is unusable.
    NoExtendedConnect,
    /// A 200 without `capsule-protocol: ?1`: there is no datagram framing.
    NoCapsuleProtocol,
}

async fn handle_masque_request(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    mode: MasqueMode,
    log: PeerLog,
) -> io::Result<()> {
    let mut fields = None;
    while let Some((frame_type, payload)) = peer_read_frame(&mut recv).await? {
        if frame_type == 0x01 {
            fields =
                Some(peer_decode_headers(&payload).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("QPACK: {e}"))
                })?);
            break;
        }
    }
    let fields =
        fields.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no HEADERS frame"))?;
    let get = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .unwrap_or("")
    };
    note(&log, format!("method={}", get(":method")));
    note(&log, format!("protocol={}", get(":protocol")));
    note(&log, format!("scheme={}", get(":scheme")));
    note(&log, format!("authority={}", get(":authority")));
    note(&log, format!("path={}", get(":path")));
    note(
        &log,
        format!("capsule-protocol={}", get("capsule-protocol")),
    );
    match mode {
        MasqueMode::Refuse(status) => {
            peer_write_headers(&mut send, &[(":status", &status.to_string())]).await?;
            let _ = send.finish();
            note(&log, format!("refused={status}"));
            return Ok(());
        }
        MasqueMode::NoCapsuleProtocol => {
            peer_write_headers(&mut send, &[(":status", "200")]).await?;
        }
        MasqueMode::Accept | MasqueMode::NoExtendedConnect => {
            peer_write_headers(&mut send, &[(":status", "200"), ("capsule-protocol", "?1")])
                .await?;
        }
    }
    let mut pending = Vec::new();
    while let Some((frame_type, data)) = peer_read_frame(&mut recv).await? {
        if frame_type != 0x00 {
            continue;
        }
        pending.extend_from_slice(&data);
        loop {
            match peer_take_capsule(&mut pending) {
                Ok(None) => break,
                Ok(Some((0x00, value))) => {
                    let mut pos = 0;
                    let Some(context) = take_varint(&value, &mut pos) else {
                        return Ok(());
                    };
                    let payload = &value[pos..];
                    note(
                        &log,
                        format!(
                            "datagram context={context} bytes={} payload={}",
                            payload.len(),
                            String::from_utf8_lossy(payload)
                        ),
                    );
                    let mut capsule = Vec::new();
                    put_varint(0x00, &mut capsule);
                    put_varint((1 + payload.len()) as u64, &mut capsule);
                    put_varint(0, &mut capsule);
                    capsule.extend_from_slice(payload);
                    let mut frame = Vec::new();
                    put_varint(0x00, &mut frame);
                    put_varint(capsule.len() as u64, &mut frame);
                    frame.extend_from_slice(&capsule);
                    send.write_all(&frame).await?;
                }
                // Unknown capsule types are ignored, as RFC 9297 requires.
                Ok(Some(_)) => {}
                Err(()) => return Ok(()),
            }
        }
    }
    Ok(())
}

async fn spawn_masque_peer(mode: MasqueMode, cert: Cert) -> (u16, PeerLog) {
    let port = free_udp_port();
    let endpoint = quinn::Endpoint::server(
        server_config(&cert, b"h3"),
        SocketAddr::from(([127, 0, 0, 1], port)),
    )
    .expect("MASQUE QUIC peer endpoint");
    let log: PeerLog = Arc::new(Mutex::new(Vec::new()));
    let shared = log.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let log = shared.clone();
            tokio::spawn(async move {
                let connection = match incoming.await {
                    Ok(connection) => connection,
                    Err(e) => {
                        note(&log, format!("handshake-failed={e}"));
                        return;
                    }
                };
                // Server control stream: SETTINGS with ENABLE_CONNECT_PROTOCOL.
                let mut control = match connection.open_uni().await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                let mut settings = Vec::new();
                if !matches!(mode, MasqueMode::NoExtendedConnect) {
                    put_varint(0x08, &mut settings);
                    put_varint(1, &mut settings);
                }
                let mut frame = Vec::new();
                put_varint(0x04, &mut frame);
                put_varint(settings.len() as u64, &mut frame);
                frame.extend_from_slice(&settings);
                if control.write_all(&[0x00]).await.is_err()
                    || control.write_all(&frame).await.is_err()
                {
                    return;
                }
                let mut keep = vec![control];
                for kind in [0x02u8, 0x03u8] {
                    if let Ok(mut stream) = connection.open_uni().await {
                        let _ = stream.write_all(&[kind]).await;
                        keep.push(stream);
                    }
                }
                while let Ok((send, recv)) = connection.accept_bi().await {
                    let log = log.clone();
                    tokio::spawn(async move {
                        let _ = handle_masque_request(send, recv, mode, log).await;
                    });
                }
            });
        }
    });
    (port, log)
}

fn start_masque_kernel(peer_port: u16, skip_verify: bool, udp: bool) -> Kernel {
    let yaml = format!(
        "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: mq, type: masque, server: 127.0.0.1, port: {peer_port}, udp: {udp}, skip-cert-verify: {skip_verify}}}\nrules:\n  - MATCH,mq\n",
        free_port()
    );
    let (kernel, warnings) = Kernel::start_from_yaml(&yaml, None, limits())
        .unwrap_or_else(|e| panic!("kernel rejected the masque config: {e}\n{yaml}"));
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    kernel
}

fn masque_udp_associate(proxy: SocketAddr) -> (std::net::TcpStream, std::net::SocketAddr) {
    use std::io::{Read as _, Write as _};
    let mut control =
        std::net::TcpStream::connect_timeout(&proxy, Duration::from_secs(5)).expect("control");
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
    (control, std::net::SocketAddr::from((ip, port)))
}

fn masque_udp_exchange(
    socket: &std::net::UdpSocket,
    relay: std::net::SocketAddr,
    target: std::net::SocketAddr,
    payload: &[u8],
    wait: Duration,
) -> Option<Vec<u8>> {
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
    Some(buffer[10..read].to_vec())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_connect_udp_forwards_datagrams_per_destination() {
    let cert = make_cert("masque-udp");
    let (peer_port, log) = spawn_masque_peer(MasqueMode::Accept, cert).await;
    let mut kernel = start_masque_kernel(peer_port, true, true);
    let (_control, relay) = masque_udp_associate(kernel.listen_addr());
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let first: SocketAddr = "198.51.100.7:5353".parse().unwrap();
    let reply = masque_udp_exchange(&socket, relay, first, b"masque-one", Duration::from_secs(5))
        .expect("a CONNECT-UDP datagram must come back");
    assert_eq!(reply, b"masque-one");
    let second: SocketAddr = "203.0.113.9:9999".parse().unwrap();
    let reply = masque_udp_exchange(
        &socket,
        relay,
        second,
        b"masque-two",
        Duration::from_secs(5),
    )
    .expect("the second destination opens its own CONNECT-UDP request");
    assert_eq!(reply, b"masque-two");

    assert!(
        wait_for_peer_log(&log, "datagram context=0 bytes=10 payload=masque-one").await,
        "{log:?}"
    );
    let lines = log.lock().unwrap().clone();
    assert!(
        lines.iter().any(|line| line == "method=CONNECT"),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line == "protocol=connect-udp"),
        "{lines:?}"
    );
    assert!(lines.iter().any(|line| line == "scheme=https"), "{lines:?}");
    // RFC 9298 §3.4: `:authority` is the proxy's, not the target's.
    assert!(
        lines
            .iter()
            .any(|line| line == &format!("authority=127.0.0.1:{peer_port}")),
        "{lines:?}"
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.starts_with("authority=198.51.100.7")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line == "path=/.well-known/masque/udp/198.51.100.7/5353/"),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line == "path=/.well-known/masque/udp/203.0.113.9/9999/"),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line == "capsule-protocol=?1"),
        "{lines:?}"
    );
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_connect_udp_refusal_fails_without_a_reply() {
    let cert = make_cert("masque-refuse");
    let (peer_port, log) = spawn_masque_peer(MasqueMode::Refuse(403), cert).await;
    let mut kernel = start_masque_kernel(peer_port, true, true);
    let (_control, relay) = masque_udp_associate(kernel.listen_addr());
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target: SocketAddr = "198.51.100.7:5353".parse().unwrap();
    let reply = masque_udp_exchange(
        &socket,
        relay,
        target,
        b"must-not-arrive",
        Duration::from_secs(2),
    );
    assert!(
        reply.is_none(),
        "a refused CONNECT-UDP must not echo: {reply:?}"
    );
    assert!(wait_for_peer_log(&log, "refused=403").await, "{log:?}");
    assert!(
        peer_log_has(&log, "path=/.well-known/masque/udp/198.51.100.7/5353/"),
        "{log:?}"
    );
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_connect_udp_verifies_the_server_certificate_by_default() {
    let cert = make_cert("masque-tls");
    let (peer_port, log) = spawn_masque_peer(MasqueMode::Accept, cert).await;
    let mut kernel = start_masque_kernel(peer_port, false, true);
    let (_control, relay) = masque_udp_associate(kernel.listen_addr());
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target: SocketAddr = "198.51.100.7:5353".parse().unwrap();
    let reply = masque_udp_exchange(&socket, relay, target, b"tls", Duration::from_secs(2));
    assert!(
        reply.is_none(),
        "a self-signed peer must be refused without skip-cert-verify: {reply:?}"
    );
    assert!(wait_for_peer_log(&log, "handshake-failed").await, "{log:?}");
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_tcp_dial_is_refused_by_name() {
    // No peer is needed: the TCP path is refused before any connection.
    let port = free_udp_port();
    let mut kernel = start_masque_kernel(port, true, true);
    let (tunnel, status) = common::http_connect(kernel.listen_addr(), "127.0.0.1:9")
        .await
        .unwrap();
    drop(tunnel);
    assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_requires_extended_connect_advertisement() {
    let cert = make_cert("masque-no-connect");
    let (peer_port, log) = spawn_masque_peer(MasqueMode::NoExtendedConnect, cert).await;
    let mut kernel = start_masque_kernel(peer_port, true, true);
    let (_control, relay) = masque_udp_associate(kernel.listen_addr());
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target: SocketAddr = "198.51.100.7:5353".parse().unwrap();
    let reply = masque_udp_exchange(
        &socket,
        relay,
        target,
        b"no-connect",
        Duration::from_secs(2),
    );
    assert!(
        reply.is_none(),
        "extended CONNECT was not advertised: {reply:?}"
    );
    // The client must refuse before opening a request stream.
    assert!(!peer_log_has(&log, "method="), "{log:?}");
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_requires_the_capsule_protocol_in_the_response() {
    let cert = make_cert("masque-no-capsule");
    let (peer_port, log) = spawn_masque_peer(MasqueMode::NoCapsuleProtocol, cert).await;
    let mut kernel = start_masque_kernel(peer_port, true, true);
    let (_control, relay) = masque_udp_associate(kernel.listen_addr());
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target: SocketAddr = "198.51.100.7:5353".parse().unwrap();
    let reply = masque_udp_exchange(
        &socket,
        relay,
        target,
        b"no-capsule",
        Duration::from_secs(2),
    );
    assert!(reply.is_none(), "capsules were not negotiated: {reply:?}");
    assert!(wait_for_peer_log(&log, "method=CONNECT").await, "{log:?}");
    assert!(!peer_log_has(&log, "datagram "), "{log:?}");
    kernel.stop().unwrap();
}
