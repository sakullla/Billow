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
