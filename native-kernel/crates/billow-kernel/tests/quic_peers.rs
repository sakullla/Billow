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
    make_cert_with(name, false)
}

/// A P-256 certificate: the WARP endpoint pins an ECDSA key (the pinned
/// adapter refuses anything else), so the CONNECT-IP peer uses one.
fn make_warp_cert(name: &str) -> Cert {
    make_cert_with(name, true)
}

fn make_cert_with(name: &str, ecdsa: bool) -> Cert {
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
    let mut command = Command::new("openssl");
    command.args(["req", "-x509", "-newkey"]);
    if ecdsa {
        command.args(["ec", "-pkeyopt", "ec_paramgen_curve:P-256"]);
    } else {
        command.arg("rsa:2048");
    }
    let status = command
        .arg("-nodes")
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
async fn hysteria2_transport_options_are_parsed() {
    // `up` selects the Brutal sender; ports/hop/obfs/udp-mtu/bbr-profile are
    // parsed into the outbound and applied by the QUIC endpoint.
    let yaml = "mixed-port: 17890\nproxies:\n  - {name: h2, type: hysteria2, server: 127.0.0.1, port: 443, password: p, up: 50 Mbps, ports: '443,8443-8444', hop-interval: 7-9, obfs: salamander, obfs-password: s, udp-mtu: 1280, bbr-profile: aggressive}\nrules:\n  - MATCH,h2\n";
    let config = billow_kernel::load_config(yaml, "hysteria2-options.yaml").unwrap();
    match &config.config.proxies[0].protocol {
        billow_kernel::proxies::Protocol::Hysteria2(proxy) => {
            assert_eq!(proxy.send_bps, 50_000_000 / 8);
            assert_eq!(proxy.ports, vec![443, 8443, 8444]);
            assert_eq!(proxy.hop_interval, (7, 9));
            assert_eq!(proxy.obfs.as_deref(), Some("salamander"));
            assert_eq!(proxy.udp_mtu, 1280);
            assert_eq!(proxy.bbr_profile.as_deref(), Some("aggressive"));
        }
        other => panic!("expected hysteria2, got {other:?}"),
    }
    // An empty `up` asks for nothing and is accepted, like Mihomo's decoder.
    let empty = "mixed-port: 17890\nproxies:\n  - {name: h2, type: hysteria2, server: 127.0.0.1, port: 443, password: p, up: ''}\nrules:\n  - MATCH,h2\n";
    assert!(billow_kernel::load_config(empty, "hysteria2-up-empty.yaml").is_ok());

    // Gecko carries the pinned packet-size range; zero selects the pinned
    // 512/1200 defaults at dial time.
    let gecko = "mixed-port: 17890\nproxies:\n  - {name: h2, type: hysteria2, server: 127.0.0.1, port: 443, password: p, obfs: gecko, obfs-password: s, obfs-min-packet-size: 600, obfs-max-packet-size: 1300}\nrules:\n  - MATCH,h2\n";
    let config = billow_kernel::load_config(gecko, "hysteria2-gecko.yaml").unwrap();
    match &config.config.proxies[0].protocol {
        billow_kernel::proxies::Protocol::Hysteria2(proxy) => {
            assert_eq!(proxy.obfs.as_deref(), Some("gecko"));
            assert_eq!(proxy.obfs_min_packet_size, 600);
            assert_eq!(proxy.obfs_max_packet_size, 1300);
        }
        other => panic!("expected hysteria2, got {other:?}"),
    }
    let bad_range = "mixed-port: 17890\nproxies:\n  - {name: h2, type: hysteria2, server: 127.0.0.1, port: 443, password: p, obfs: gecko, obfs-password: s, obfs-min-packet-size: 1300, obfs-max-packet-size: 600}\nrules:\n  - MATCH,h2\n";
    assert!(billow_kernel::load_config(bad_range, "hysteria2-gecko-bad.yaml").is_err());
}

/// `realm-opts` owns the UDP socket, so the pinned client rejects a non-empty
/// port pool; the realm block now carries the control TLS identity instead of
/// accepting `fingerprint`/`certificate`/`private-key` and dropping them.
#[test]
fn hysteria2_realm_rejects_port_hopping_and_keeps_its_tls_identity() {
    let hopping = "mixed-port: 17890\nproxies:\n  - {name: h2, type: hysteria2, server: 127.0.0.1, port: 443, password: p, ports: '443,8443-8444', realm-opts: {enable: true, server-url: 'https://realm.example', realm-id: r}}\nrules:\n  - MATCH,h2\n";
    let error = billow_kernel::load_config(hopping, "hysteria2-realm-hop.yaml")
        .expect_err("realm plus a port pool is rejected")
        .to_string();
    assert!(
        error.contains("realm and port hopping are mutually exclusive"),
        "{error}"
    );

    let pin = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let realm = format!(
        "mixed-port: 17890\nproxies:\n  - {{name: h2, type: hysteria2, server: 127.0.0.1, port: 443, password: p, hop-interval: 7-9, realm-opts: {{enable: true, server-url: 'https://realm.example', realm-id: r, fingerprint: '{pin}', skip-cert-verify: true}}}}\nrules:\n  - MATCH,h2\n"
    );
    let config = billow_kernel::load_config(&realm, "hysteria2-realm-tls.yaml").unwrap();
    match &config.config.proxies[0].protocol {
        billow_kernel::proxies::Protocol::Hysteria2(proxy) => {
            assert_eq!(proxy.hop_interval, (7, 9));
            let realm = proxy.realm.as_ref().expect("realm block loads");
            assert_eq!(
                realm.tls_settings.fingerprint.as_deref().map(|pin| pin.len()),
                Some(32)
            );
            assert!(realm.tls_settings.skip_cert_verify);
        }
        other => panic!("expected hysteria2, got {other:?}"),
    }

    // A browser name is not a certificate pin.
    let browser = "mixed-port: 17890\nproxies:\n  - {name: h2, type: hysteria2, server: 127.0.0.1, port: 443, password: p, realm-opts: {enable: true, server-url: 'https://realm.example', fingerprint: chrome}}\nrules:\n  - MATCH,h2\n";
    let error = billow_kernel::load_config(browser, "hysteria2-realm-browser.yaml")
        .expect_err("a browser fingerprint is rejected")
        .to_string();
    assert!(error.contains("realm-opts.fingerprint"), "{error}");

    // A client identity is loaded or rejected at load, not silently ignored.
    let relative = "mixed-port: 17890\nproxies:\n  - {name: h2, type: hysteria2, server: 127.0.0.1, port: 443, password: p, realm-opts: {enable: true, server-url: 'https://realm.example', certificate: cert.pem, private-key: key.pem}}\nrules:\n  - MATCH,h2\n";
    let error = billow_kernel::load_config(relative, "hysteria2-realm-relative.yaml")
        .expect_err("a relative path is not resolvable")
        .to_string();
    assert!(error.contains("absolute path"), "{error}");
    let half = "mixed-port: 17890\nproxies:\n  - {name: h2, type: hysteria2, server: 127.0.0.1, port: 443, password: p, realm-opts: {enable: true, server-url: 'https://realm.example', certificate: cert.pem}}\nrules:\n  - MATCH,h2\n";
    let error = billow_kernel::load_config(half, "hysteria2-realm-half.yaml")
        .expect_err("certificate without private-key is rejected")
        .to_string();
    assert!(error.contains("must be set together"), "{error}");
    let missing = "mixed-port: 17890\nproxies:\n  - {name: h2, type: hysteria2, server: 127.0.0.1, port: 443, password: p, realm-opts: {enable: true, server-url: 'https://realm.example', certificate: /nonexistent/billow-cert.pem, private-key: /nonexistent/billow-key.pem}}\nrules:\n  - MATCH,h2\n";
    let error = billow_kernel::load_config(missing, "hysteria2-realm-missing.yaml")
        .expect_err("an unreadable client identity is rejected at load")
        .to_string();
    assert!(error.contains("does not exist"), "{error}");
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
    /// Echo one datagram, then end the request stream: the client must notice
    /// the FIN and open a new stream for the next datagram.
    CloseAfterEcho,
    /// Echo every datagram, then end the request stream after `delay`; used to
    /// hold `MAX_CONCURRENT_DESTINATIONS` flows open and then close them all.
    CloseAfter(Duration),
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
        MasqueMode::Accept
        | MasqueMode::NoExtendedConnect
        | MasqueMode::CloseAfterEcho
        | MasqueMode::CloseAfter(_) => {
            peer_write_headers(&mut send, &[(":status", "200"), ("capsule-protocol", "?1")])
                .await?;
        }
    }
    let close_at = match mode {
        MasqueMode::CloseAfter(delay) => Some(tokio::time::Instant::now() + delay),
        _ => None,
    };
    let mut pending = Vec::new();
    loop {
        let frame = if let Some(close_at) = close_at {
            tokio::select! {
                _ = tokio::time::sleep_until(close_at) => {
                    let _ = send.finish();
                    note(&log, "closed=1");
                    return Ok(());
                }
                frame = peer_read_frame(&mut recv) => frame?,
            }
        } else {
            peer_read_frame(&mut recv).await?
        };
        let Some((frame_type, data)) = frame else {
            return Ok(());
        };
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
                    if matches!(mode, MasqueMode::CloseAfterEcho) {
                        let _ = send.finish();
                        note(&log, "closed=1");
                        return Ok(());
                    }
                }
                // Unknown capsule types are ignored, as RFC 9297 requires.
                Ok(Some(_)) => {}
                Err(()) => return Ok(()),
            }
        }
    }
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

/// Send one datagram repeatedly until a reply arrives or `within` expires. A
/// closed flow is reclaimed on the next send, so this exercises the recovery
/// path without depending on how quickly the reader sees the peer's FIN.
fn masque_udp_exchange_retry(
    socket: &std::net::UdpSocket,
    relay: std::net::SocketAddr,
    target: std::net::SocketAddr,
    payload: &[u8],
    within: Duration,
) -> Option<Vec<u8>> {
    let deadline = std::time::Instant::now() + within;
    loop {
        if let Some(reply) =
            masque_udp_exchange(socket, relay, target, payload, Duration::from_millis(400))
        {
            return Some(reply);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn masque_path_count(log: &PeerLog, path: &str) -> usize {
    log.lock()
        .unwrap()
        .iter()
        .filter(|line| line.as_str() == path)
        .count()
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_reopens_a_request_stream_the_peer_ended() {
    let cert = make_cert("masque-reopen");
    let (peer_port, log) = spawn_masque_peer(MasqueMode::CloseAfterEcho, cert).await;
    let mut kernel = start_masque_kernel(peer_port, true, true);
    let (_control, relay) = masque_udp_associate(kernel.listen_addr());
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target: SocketAddr = "198.51.100.7:5353".parse().unwrap();
    let first = masque_udp_exchange_retry(
        &socket,
        relay,
        target,
        b"first-open",
        Duration::from_secs(5),
    )
    .expect("the first CONNECT-UDP flow must echo");
    assert_eq!(first, b"first-open");
    // The peer ended the first request stream after echoing. The association
    // must notice the FIN, reclaim the flow and open a new request stream for
    // the same destination instead of writing into the dead one.
    let second = masque_udp_exchange_retry(
        &socket,
        relay,
        target,
        b"second-open",
        Duration::from_secs(5),
    )
    .unwrap_or_else(|| panic!("a closed flow was not reopened: {log:?}"));
    assert_eq!(second, b"second-open");
    let path = "path=/.well-known/masque/udp/198.51.100.7/5353/";
    assert_eq!(masque_path_count(&log, path), 2, "{log:?}");
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_reclaims_peer_closed_flows_for_new_destinations() {
    use billow_kernel::outbound::masque::MAX_CONCURRENT_DESTINATIONS;

    let cert = make_cert("masque-reclaim");
    let (peer_port, log) =
        spawn_masque_peer(MasqueMode::CloseAfter(Duration::from_secs(2)), cert).await;
    let mut kernel = start_masque_kernel(peer_port, true, true);
    let (_control, relay) = masque_udp_associate(kernel.listen_addr());
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    // Open one flow per destination and keep every stream open (the peer only
    // echoes), so the association reaches its flow cap.
    for index in 0..MAX_CONCURRENT_DESTINATIONS {
        let target: SocketAddr = format!("198.51.100.{}:5353", index + 1).parse().unwrap();
        let reply = masque_udp_exchange(&socket, relay, target, b"fill", Duration::from_secs(5))
            .unwrap_or_else(|| panic!("flow {index} did not echo: {log:?}"));
        assert_eq!(reply, b"fill");
    }
    // The peer ends every stream two seconds after it was opened; once all of
    // them are closed, a destination beyond the cap must still be reachable.
    std::thread::sleep(Duration::from_millis(2400));
    let fresh: SocketAddr = "203.0.113.250:9999".parse().unwrap();
    let reply = masque_udp_exchange_retry(
        &socket,
        relay,
        fresh,
        b"after-closed",
        Duration::from_secs(5),
    )
    .unwrap_or_else(|| panic!("closed flows pinned the association at the cap: {log:?}"));
    assert_eq!(reply, b"after-closed");
    assert!(
        masque_path_count(&log, "path=/.well-known/masque/udp/203.0.113.250/9999/",) >= 1,
        "{log:?}"
    );
    kernel.stop().unwrap();
}

// ---------------------------------------------------------------------------
// T18: MASQUE CONNECT-IP (RFC 9484) peer.
//
// An independent `quinn` HTTP/3 server: it requires the WARP client
// certificate, advertises extended CONNECT and HTTP Datagrams, answers the
// `cf-connect-ip` request, reads the ROUTE_ADVERTISEMENT capsule, assigns
// addresses, and echoes IP/UDP packets received as HTTP Datagrams. The IP and
// UDP codec below is written against RFC 791/8200/768 rather than reusing the
// client's `outbound::ipstack`, so a checksum or header bug cannot cancel out.
// ---------------------------------------------------------------------------

/// Throwaway P-256 SEC1 private key (base64) for the CONNECT-IP tests.
const WARP_TEST_KEY: &str = "MHcCAQEEIDKh56LbUI7PTfKO5ojiPkNrK2H8jcLrmfdlhv3TsqRzoAoGCCqGSM49AwEHoUQDQgAEMAUkhPqJXQGTsDj6a3yC7F2zxIWXs6UJCc/Mwr6wL3GWgqbrP6tvB52ZUbnalrJXSxMwUFXDTHNqxPhpzzUawA==";

#[derive(Debug, Clone, Copy, PartialEq)]
enum WarpTcpMode {
    /// Echo every data segment; answer SYN with SYN-ACK.
    Echo,
    /// Answer SYN with RST (connection refused).
    Refuse,
    /// Ignore SYN (the dial times out).
    Silent,
    /// Echo the data and close the server side with FIN in the same segment.
    FinAfterEcho,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum WarpMode {
    Accept,
    /// No `SETTINGS_H3_DATAGRAM` (0x33) and no draft-00 (0x276).
    NoDatagramSetting,
    Refuse(u16),
    /// Send an `ADDRESS_REQUEST` after the assignment: this client has no
    /// address-assignment policy and must fail by name.
    AddressRequest,
}

/// A rustls server verifier that requires the WARP client certificate and
/// records the SubjectPublicKeyInfo it carries.
#[derive(Debug)]
struct RecordingClientCerts {
    log: PeerLog,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::server::danger::ClientCertVerifier for RecordingClientCerts {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        match billow_kernel::outbound::warp::spki_of_certificate(end_entity.as_ref()) {
            Some(spki) => {
                note(&self.log, format!("client-spki={}", hex::encode(spki)));
                Ok(rustls::server::danger::ClientCertVerified::assertion())
            }
            None => Err(rustls::Error::General(
                "client certificate has no SubjectPublicKeyInfo".to_string(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn warp_server_config(cert: &Cert, log: &PeerLog) -> quinn::ServerConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(RecordingClientCerts {
        log: log.clone(),
        provider: provider.clone(),
    });
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(cert.der.clone())],
            rustls_pemfile::private_key(&mut std::io::BufReader::new(
                std::fs::File::open(&cert.key).unwrap(),
            ))
            .unwrap()
            .unwrap(),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(64 * 1024));
    transport.datagram_send_buffer_size(64 * 1024);
    let crypto = QuicServerConfig::try_from(config).unwrap();
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(Arc::new(transport));
    server
}

/// RFC 1071 one's-complement sum, written out independently of the client.
fn warp_sum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut index = 0;
    while index + 1 < bytes.len() {
        sum += u32::from(u16::from_be_bytes([bytes[index], bytes[index + 1]]));
        index += 2;
    }
    if index < bytes.len() {
        sum += u32::from(bytes[index]) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn warp_pseudo_sum(src: std::net::IpAddr, dst: std::net::IpAddr, udp: &[u8], with_checksum: bool) -> u16 {
    let mut bytes = Vec::new();
    match (src, dst) {
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
            bytes.extend_from_slice(&src.octets());
            bytes.extend_from_slice(&dst.octets());
            bytes.extend_from_slice(&[0, 17]);
            bytes.extend_from_slice(&(udp.len() as u16).to_be_bytes());
        }
        (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
            bytes.extend_from_slice(&src.octets());
            bytes.extend_from_slice(&dst.octets());
            bytes.extend_from_slice(&(udp.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&[0, 0, 0, 17]);
        }
        _ => return 0xffff,
    }
    if !with_checksum {
        // Verification sums the datagram with its checksum field in place.
        let mut zeroed = udp.to_vec();
        zeroed[6] = 0;
        zeroed[7] = 0;
        bytes.extend_from_slice(&zeroed);
    } else {
        bytes.extend_from_slice(udp);
    }
    warp_sum(&bytes)
}

/// Transport checksum over the IPv4/IPv6 pseudo-header for `protocol`
/// (independent of the kernel's implementation).
fn warp_transport_sum(
    src: std::net::IpAddr,
    dst: std::net::IpAddr,
    protocol: u8,
    segment: &[u8],
) -> u16 {
    let mut bytes = Vec::new();
    match (src, dst) {
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
            bytes.extend_from_slice(&src.octets());
            bytes.extend_from_slice(&dst.octets());
            bytes.extend_from_slice(&[0, protocol]);
            bytes.extend_from_slice(&(segment.len() as u16).to_be_bytes());
        }
        (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
            bytes.extend_from_slice(&src.octets());
            bytes.extend_from_slice(&dst.octets());
            bytes.extend_from_slice(&(segment.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&[0, 0, 0, protocol]);
        }
        _ => return 0xffff,
    }
    bytes.extend_from_slice(segment);
    warp_sum(&bytes)
}

#[allow(dead_code)]
struct WarpTcp<'a> {
    src: std::net::IpAddr,
    dst: std::net::IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    mss: Option<u16>,
    payload: &'a [u8],
}

fn warp_parse_tcp(packet: &[u8]) -> Option<WarpTcp<'_>> {
    let (src, dst, payload) = match packet.first()? >> 4 {
        4 => {
            if packet.len() < 40 || packet[9] != 6 {
                return None;
            }
            let header = usize::from(packet[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if header < 20 || total < header + 20 || total > packet.len() {
                return None;
            }
            if warp_sum(&packet[..header]) != 0xffff {
                return None;
            }
            (
                std::net::IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?),
                std::net::IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?),
                &packet[header..total],
            )
        }
        6 => {
            if packet.len() < 60 || packet[6] != 6 {
                return None;
            }
            let length = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if packet.len() < 40 + length || length < 20 {
                return None;
            }
            (
                std::net::IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?),
                std::net::IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?),
                &packet[40..40 + length],
            )
        }
        _ => return None,
    };
    if warp_transport_sum(src, dst, 6, payload) != 0xffff {
        return None;
    }
    let header_len = usize::from(payload[12] >> 4) * 4;
    if header_len < 20 || header_len > payload.len() {
        return None;
    }
    let mut mss = None;
    let mut option = 20;
    while option + 1 < header_len {
        match payload[option] {
            0 => break,
            1 => {
                option += 1;
                continue;
            }
            kind => {
                let length = usize::from(payload[option + 1]);
                if length < 2 || option + length > header_len {
                    break;
                }
                if kind == 2 && length == 4 {
                    mss = Some(u16::from_be_bytes([
                        payload[option + 2],
                        payload[option + 3],
                    ]));
                }
                option += length;
            }
        }
    }
    Some(WarpTcp {
        src,
        dst,
        src_port: u16::from_be_bytes([payload[0], payload[1]]),
        dst_port: u16::from_be_bytes([payload[2], payload[3]]),
        seq: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
        ack: u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]),
        flags: payload[13],
        window: u16::from_be_bytes([payload[14], payload[15]]),
        mss,
        payload: &payload[header_len..],
    })
}

fn warp_build_tcp(
    src: std::net::IpAddr,
    dst: std::net::IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    mss: Option<u16>,
    payload: &[u8],
) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&src_port.to_be_bytes());
    segment.extend_from_slice(&dst_port.to_be_bytes());
    segment.extend_from_slice(&seq.to_be_bytes());
    segment.extend_from_slice(&ack.to_be_bytes());
    let options_len = if mss.is_some() { 4 } else { 0 };
    segment.push((((20 + options_len) / 4) as u8) << 4);
    segment.push(flags);
    segment.extend_from_slice(&65535u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0, 0, 0]); // checksum + urgent
    if let Some(mss) = mss {
        segment.extend_from_slice(&[2, 4, (mss >> 8) as u8, mss as u8]);
    }
    segment.extend_from_slice(payload);
    let checksum = !warp_transport_sum(src, dst, 6, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    match (src, dst) {
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
            let mut packet = vec![0x45, 0];
            packet.extend_from_slice(&((20 + segment.len()) as u16).to_be_bytes());
            packet.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0]);
            packet.extend_from_slice(&src.octets());
            packet.extend_from_slice(&dst.octets());
            let checksum = !warp_sum(&packet);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            packet.extend_from_slice(&segment);
            packet
        }
        (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
            let mut packet = vec![0x60, 0, 0, 0];
            packet.extend_from_slice(&(segment.len() as u16).to_be_bytes());
            packet.extend_from_slice(&[6, 64]);
            packet.extend_from_slice(&src.octets());
            packet.extend_from_slice(&dst.octets());
            packet.extend_from_slice(&segment);
            packet
        }
        _ => Vec::new(),
    }
}

struct WarpTcpState {
    server_seq: u32,
    rcv_nxt: u32,
    fin_sent: bool,
}

fn warp_tcp_respond(
    state: &mut Option<WarpTcpState>,
    packet: &[u8],
    mode: WarpTcpMode,
    log: &PeerLog,
) -> Option<Vec<u8>> {
    let segment = warp_parse_tcp(packet)?;
    note(
        log,
        format!(
            "tcp seg flags={:#04x} seq={} ack={} len={}",
            segment.flags,
            segment.seq,
            segment.ack,
            segment.payload.len()
        ),
    );
    const SYN: u8 = 0x02;
    const FIN: u8 = 0x01;
    const RST: u8 = 0x04;
    const ACK: u8 = 0x10;
    if segment.flags & RST != 0 {
        return None;
    }
    if segment.flags & SYN != 0 {
        note(&log, "tcp syn");
        if let Some(mss) = segment.mss {
            note(&log, format!("tcp syn mss={mss}"));
        }
        if mode == WarpTcpMode::Silent {
            return None;
        }
        if mode == WarpTcpMode::Refuse {
            note(&log, "tcp rst");
            return Some(warp_build_tcp(
                segment.dst,
                segment.src,
                segment.dst_port,
                segment.src_port,
                0,
                segment.seq.wrapping_add(1),
                RST | ACK,
                None,
                &[],
            ));
        }
        *state = Some(WarpTcpState {
            // The SYN occupies one sequence number, so data starts at 0x5001.
            server_seq: 0x5001,
            rcv_nxt: segment.seq.wrapping_add(1),
            fin_sent: false,
        });
        return Some(warp_build_tcp(
            segment.dst,
            segment.src,
            segment.dst_port,
            segment.src_port,
            0x5000,
            segment.seq.wrapping_add(1),
            SYN | ACK,
            Some(1460),
            &[],
        ));
    }
    let Some(state) = state.as_mut() else {
        return None;
    };
    if segment.flags & FIN != 0 {
        state.rcv_nxt = state
            .rcv_nxt
            .wrapping_add(segment.payload.len() as u32)
            .wrapping_add(1);
        note(&log, "tcp fin");
        let flags = if state.fin_sent { ACK } else { ACK | FIN };
        state.fin_sent = true;
        return Some(warp_build_tcp(
            segment.dst,
            segment.src,
            segment.dst_port,
            segment.src_port,
            state.server_seq,
            state.rcv_nxt,
            flags,
            None,
            &[],
        ));
    }
    if segment.payload.is_empty() {
        return None;
    }
    state.rcv_nxt = state
        .rcv_nxt
        .wrapping_add(segment.payload.len() as u32);
    note(
        &log,
        format!("tcp data bytes={} payload={}", segment.payload.len(), String::from_utf8_lossy(segment.payload)),
    );
    let flags = if mode == WarpTcpMode::FinAfterEcho && !state.fin_sent {
        ACK | FIN
    } else {
        ACK
    };
    if flags & FIN != 0 {
        state.fin_sent = true;
    }
    let reply = warp_build_tcp(
        segment.dst,
        segment.src,
        segment.dst_port,
        segment.src_port,
        state.server_seq,
        state.rcv_nxt,
        flags,
        None,
        segment.payload,
    );
    state.server_seq = state.server_seq.wrapping_add(segment.payload.len() as u32);
    if flags & FIN != 0 {
        state.server_seq = state.server_seq.wrapping_add(1);
    }
    Some(reply)
}

fn warp_ip_protocol(packet: &[u8]) -> Option<u8> {
    match packet.first()? >> 4 {
        4 => Some(*packet.get(9)?),
        6 => Some(*packet.get(6)?),
        _ => None,
    }
}

struct WarpUdp<'a> {
    src: std::net::IpAddr,
    dst: std::net::IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: &'a [u8],
}

/// Parse an IPv4/IPv6 UDP packet, verifying both checksums.
fn warp_parse_udp(packet: &[u8]) -> Option<WarpUdp<'_>> {
    match packet.first()? >> 4 {
        4 => {
            if packet.len() < 28 {
                return None;
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            if header_len < 20 || header_len > packet.len() {
                return None;
            }
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if total < header_len + 8 || total > packet.len() || packet[9] != 17 {
                return None;
            }
            if warp_sum(&packet[..header_len]) != 0xffff {
                return None;
            }
            let src = std::net::IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?);
            let dst = std::net::IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?);
            let udp = &packet[header_len..total];
            warp_udp(src, dst, udp)
        }
        6 => {
            if packet.len() < 48 {
                return None;
            }
            let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if packet.len() < 40 + payload_len || packet[6] != 17 {
                return None;
            }
            let src = std::net::IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
            let dst = std::net::IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
            let udp = &packet[40..40 + payload_len];
            warp_udp(src, dst, udp)
        }
        _ => None,
    }
}

fn warp_udp<'a>(src: std::net::IpAddr, dst: std::net::IpAddr, udp: &'a [u8]) -> Option<WarpUdp<'a>> {
    let length = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if length < 8 || length > udp.len() {
        return None;
    }
    let udp = &udp[..length];
    if warp_pseudo_sum(src, dst, udp, true) != 0xffff {
        return None;
    }
    Some(WarpUdp {
        src,
        dst,
        src_port: u16::from_be_bytes([udp[0], udp[1]]),
        dst_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: &udp[8..],
    })
}

/// Build one IPv4/IPv6 UDP packet with valid checksums.
fn warp_build_udp(
    src: std::net::IpAddr,
    dst: std::net::IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut udp = Vec::new();
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    let mut sum = warp_pseudo_sum(src, dst, &udp, false);
    sum = !sum;
    if sum == 0 && src.is_ipv6() {
        sum = 0xffff;
    }
    udp[6..8].copy_from_slice(&sum.to_be_bytes());

    match (src, dst) {
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
            let mut packet = vec![0x45, 0];
            packet.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
            packet.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
            packet.extend_from_slice(&src.octets());
            packet.extend_from_slice(&dst.octets());
            let checksum = !warp_sum(&packet);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            packet.extend_from_slice(&udp);
            packet
        }
        (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
            let mut packet = vec![0x60, 0, 0, 0];
            packet.extend_from_slice(&(udp.len() as u16).to_be_bytes());
            packet.push(17);
            packet.push(64);
            packet.extend_from_slice(&src.octets());
            packet.extend_from_slice(&dst.octets());
            packet.extend_from_slice(&udp);
            packet
        }
        _ => Vec::new(),
    }
}

/// The peer's answer to one tunnelled packet: an echo with the addresses and
/// ports swapped, or (for a DNS query to 1.1.1.1:53) an A answer.
fn warp_answer(packet: &[u8], log: &PeerLog) -> Option<Vec<u8>> {
    let udp = warp_parse_udp(packet)?;
    note(
        log,
        format!(
            "ip src={} dst={} {}:{} -> {}:{} bytes={}",
            if udp.src.is_ipv4() { "v4" } else { "v6" },
            if udp.dst.is_ipv4() { "v4" } else { "v6" },
            udp.src,
            udp.src_port,
            udp.dst,
            udp.dst_port,
            udp.payload.len()
        ),
    );
    if udp.dst_port == 53 && udp.payload.len() > 12 {
        let query = udp.payload;
        let name = dns_name_of(query);
        note(log, format!("dns-query name={name}"));
        let mut answer = Vec::new();
        answer.extend_from_slice(&query[..2]); // ID
        answer.extend_from_slice(&0x8180u16.to_be_bytes());
        answer.extend_from_slice(&1u16.to_be_bytes()); // questions
        answer.extend_from_slice(&1u16.to_be_bytes()); // answers
        answer.extend_from_slice(&[0, 0, 0, 0]);
        answer.extend_from_slice(&query[12..]); // the question, verbatim
        answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 7]);
        return Some(warp_build_udp(
            udp.dst,
            udp.src,
            udp.dst_port,
            udp.src_port,
            &answer,
        ));
    }
    Some(warp_build_udp(
        udp.dst,
        udp.src,
        udp.dst_port,
        udp.src_port,
        udp.payload,
    ))
}

fn dns_name_of(query: &[u8]) -> String {
    let mut labels = Vec::new();
    let mut pos = 12;
    while let Some(&length) = query.get(pos) {
        if length == 0 {
            break;
        }
        let label = &query[pos + 1..(pos + 1 + usize::from(length)).min(query.len())];
        labels.push(String::from_utf8_lossy(label).to_string());
        pos += 1 + usize::from(length);
    }
    labels.join(".")
}

async fn handle_warp_connection(
    connection: quinn::Connection,
    mode: WarpMode,
    tcp_mode: WarpTcpMode,
    log: PeerLog,
) -> io::Result<()> {
    let mut control = connection.open_uni().await?;
    let mut settings = Vec::new();
    put_varint(0x08, &mut settings);
    put_varint(1, &mut settings);
    if mode != WarpMode::NoDatagramSetting {
        put_varint(0x33, &mut settings);
        put_varint(1, &mut settings);
        put_varint(0x276, &mut settings);
        put_varint(1, &mut settings);
    }
    let mut frame = Vec::new();
    put_varint(0x04, &mut frame);
    put_varint(settings.len() as u64, &mut frame);
    frame.extend_from_slice(&settings);
    control.write_all(&[0x00]).await?;
    control.write_all(&frame).await?;
    let mut keep = vec![control];
    for kind in [0x02u8, 0x03u8] {
        if let Ok(mut stream) = connection.open_uni().await {
            let _ = stream.write_all(&[kind]).await;
            keep.push(stream);
        }
    }
    let (mut send, mut recv) = connection.accept_bi().await?;
    let quarter = recv.id().index();
    let mut fields = None;
    while let Some((frame_type, payload)) = peer_read_frame(&mut recv).await? {
        if frame_type == 0x01 {
            fields = Some(
                peer_decode_headers(&payload)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("QPACK: {e}")))?,
            );
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
    note(&log, format!("authority={}", get(":authority")));
    note(&log, format!("path={}", get(":path")));
    note(&log, format!("capsule-protocol={}", get("capsule-protocol")));
    if let WarpMode::Refuse(status) = mode {
        peer_write_headers(&mut send, &[(":status", &status.to_string())]).await?;
        let _ = send.finish();
        note(&log, format!("refused={status}"));
        return Ok(());
    }
    peer_write_headers(&mut send, &[(":status", "200"), ("capsule-protocol", "?1")]).await?;

    // ADDRESS_ASSIGN: the two prefixes the client's `ip`/`ipv6` select.
    let mut assign = Vec::new();
    put_varint(0, &mut assign);
    assign.push(4);
    assign.extend_from_slice(&[172, 16, 0, 2]);
    assign.push(32);
    put_varint(0, &mut assign);
    assign.push(6);
    let fd00: std::net::Ipv6Addr = "fd00::2".parse().unwrap();
    assign.extend_from_slice(&fd00.octets());
    assign.push(128);
    for (kind, value) in [(0x01u64, assign), (0x02u64, vec![0, 4, 172, 16, 0, 3, 32])] {
        if kind == 0x02 && mode != WarpMode::AddressRequest {
            continue;
        }
        let mut capsule = Vec::new();
        put_varint(0x00, &mut capsule); // DATA
        let mut body = Vec::new();
        put_varint(kind, &mut body);
        put_varint(value.len() as u64, &mut body);
        body.extend_from_slice(&value);
        put_varint(body.len() as u64, &mut capsule);
        capsule.extend_from_slice(&body);
        send.write_all(&capsule).await?;
        note(
            &log,
            format!("sent-capsule={kind} bytes={}", value.len()),
        );
    }
    // Capsule reader: ROUTE_ADVERTISEMENT arrives on the same stream.
    let capsule_log = log.clone();
    tokio::spawn(async move {
        let mut pending = Vec::new();
        while let Ok(Some((frame_type, data))) = peer_read_frame(&mut recv).await {
            if frame_type != 0x00 {
                continue;
            }
            pending.extend_from_slice(&data);
            while let Ok(Some((kind, value))) = peer_take_capsule(&mut pending) {
                note(&capsule_log, format!("capsule type={kind} bytes={}", value.len()));
            }
        }
    });
    // Datagram echo loop: UDP packets are echoed, TCP segments drive the
    // server side of one connection.
    let mut tcp_state = None;
    loop {
        let mut datagram = match connection.read_datagram().await {
            Ok(datagram) => datagram,
            Err(_) => return Ok(()),
        };
        let mut pos = 0;
        let Some(stream) = take_varint(&datagram, &mut pos) else {
            continue;
        };
        if stream != quarter {
            note(&log, format!("datagram-quarter={stream}"));
            continue;
        }
        let Some(context) = take_varint(&mut datagram, &mut pos) else {
            continue;
        };
        if context != 0 {
            continue;
        }
        let packet = &datagram[pos..];
        let reply = if warp_ip_protocol(packet) == Some(6) {
            warp_tcp_respond(&mut tcp_state, packet, tcp_mode, &log)
        } else {
            match warp_answer(packet, &log) {
                Some(reply) => Some(reply),
                None => {
                    note(&log, "unparseable-ip-packet");
                    None
                }
            }
        };
        if let Some(reply) = reply {
            let mut datagram = Vec::new();
            put_varint(quarter, &mut datagram);
            put_varint(0, &mut datagram);
            datagram.extend_from_slice(&reply);
            if connection.send_datagram(datagram.into()).is_err() {
                return Ok(());
            }
        }
    }
}

async fn spawn_warp_peer(mode: WarpMode, cert: Cert) -> (u16, PeerLog) {
    spawn_warp_peer_with(mode, WarpTcpMode::Echo, cert).await
}

async fn spawn_warp_peer_with(
    mode: WarpMode,
    tcp_mode: WarpTcpMode,
    cert: Cert,
) -> (u16, PeerLog) {
    let port = free_udp_port();
    let log: PeerLog = Arc::new(Mutex::new(Vec::new()));
    let config = warp_server_config(&cert, &log);
    let endpoint = quinn::Endpoint::server(config, SocketAddr::from(([127, 0, 0, 1], port)))
        .expect("CONNECT-IP QUIC peer endpoint");
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
                let _ = handle_warp_connection(connection, mode, tcp_mode, log).await;
            });
        }
    });
    (port, log)
}

fn warp_endpoint_public_key(cert: &Cert) -> String {
    let spki = billow_kernel::outbound::warp::spki_of_certificate(&cert.der)
        .expect("the peer certificate carries a SubjectPublicKeyInfo");
    billow_kernel::outbound::warp::base64_encode(&spki)
}

fn start_warp_kernel(peer_port: u16, endpoint_key: &str, extra: &str) -> Kernel {
    let yaml = format!(
        "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: mq, type: masque, server: 127.0.0.1, port: {peer_port}, udp: true, private-key: '{WARP_TEST_KEY}', public-key: '{endpoint_key}', ip: 172.16.0.2, ipv6: fd00::2{extra}}}\nrules:\n  - MATCH,mq\n",
        free_port()
    );
    let (kernel, warnings) = Kernel::start_from_yaml(&yaml, None, limits())
        .unwrap_or_else(|e| panic!("kernel rejected the CONNECT-IP config: {e}\n{yaml}"));
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    kernel
}

fn masque_udp_exchange_v6(
    socket: &std::net::UdpSocket,
    relay: std::net::SocketAddr,
    target: std::net::SocketAddr,
    payload: &[u8],
    wait: Duration,
) -> Option<Vec<u8>> {
    let mut packet = vec![0u8, 0u8, 0u8, 0x04];
    match target.ip() {
        std::net::IpAddr::V6(v6) => packet.extend_from_slice(&v6.octets()),
        _ => return None,
    }
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    socket.send_to(&packet, relay).ok()?;
    socket.set_read_timeout(Some(wait)).ok()?;
    let mut buffer = [0u8; 65535];
    let (read, _) = socket.recv_from(&mut buffer).ok()?;
    Some(buffer[22..read].to_vec())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_connect_ip_tunnels_udp_over_ipv4_and_ipv6() {
    let cert = make_warp_cert("warp-ip");
    let endpoint_key = warp_endpoint_public_key(&cert);
    let (peer_port, log) = spawn_warp_peer(WarpMode::Accept, cert).await;
    let mut kernel = start_warp_kernel(peer_port, &endpoint_key, "");
    let (_control, relay) = masque_udp_associate(kernel.listen_addr());
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let first: SocketAddr = "198.51.100.7:5353".parse().unwrap();
    let reply = masque_udp_exchange(&socket, relay, first, b"connect-ip-v4", Duration::from_secs(5))
        .expect("an IPv4 datagram must come back through the tunnel");
    assert_eq!(reply, b"connect-ip-v4");
    let second: SocketAddr = "[2001:db8::42]:9999".parse().unwrap();
    let reply = masque_udp_exchange_v6(
        &socket,
        relay,
        second,
        b"connect-ip-v6",
        Duration::from_secs(5),
    )
    .expect("an IPv6 datagram must come back through the tunnel");
    assert_eq!(reply, b"connect-ip-v6");

    // Request shape: RFC 9484 extended CONNECT with the pinned protocol token
    // and the default `uri` from the pinned adapter.
    let lines = log.lock().unwrap().clone();
    for line in [
        "method=CONNECT",
        "protocol=cf-connect-ip",
        "authority=cloudflareaccess.com",
        "path=/",
        "capsule-protocol=?1",
        "capsule type=3 bytes=44",
    ] {
        assert!(lines.iter().any(|entry| entry == line), "{line} missing: {lines:?}");
    }
    // The client advertised every destination (two routes: IPv4 then IPv6).
    assert!(
        lines.iter().any(|entry| entry == &format!("client-spki={}", {
            billow_kernel::outbound::warp::parse_private_key(WARP_TEST_KEY)
                .unwrap()
                .spki
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })),
        "the configured client key must be the certificate key: {lines:?}"
    );
    // Tunnelled headers: the client's `ip`/`ipv6` are the packet sources.
    assert!(
        lines
            .iter()
            .any(|entry| entry.starts_with("ip src=v4 dst=v4 172.16.0.2:")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|entry| entry.starts_with("ip src=v6 dst=v6 fd00::2:")),
        "{lines:?}"
    );
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_connect_ip_requires_the_pinned_endpoint_key() {
    let cert = make_warp_cert("warp-pin");
    let wrong = billow_kernel::outbound::warp::base64_encode(
        &billow_kernel::outbound::warp::parse_private_key(WARP_TEST_KEY)
            .unwrap()
            .spki,
    );
    let (peer_port, log) = spawn_warp_peer(WarpMode::Accept, cert).await;
    let mut kernel = start_warp_kernel(peer_port, &wrong, "");
    let (_control, relay) = masque_udp_associate(kernel.listen_addr());
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target: SocketAddr = "198.51.100.7:5353".parse().unwrap();
    let reply = masque_udp_exchange(&socket, relay, target, b"pinned", Duration::from_secs(2));
    assert!(reply.is_none(), "a wrong endpoint pin must not connect: {reply:?}");
    // The pin is checked by our verifier, so the QUIC/TLS handshake completes
    // on paper but the certificate is refused; the peer sees a close.
    let lines = log.lock().unwrap().clone();
    assert!(
        lines.iter().any(|entry| entry.starts_with("handshake-failed=")),
        "{lines:?}"
    );
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_connect_ip_without_http_datagrams_is_refused_by_name() {
    use billow_kernel::outbound::masque_ip::MasqueIp;
    use billow_kernel::outbound::tls::ClientTls;
    use billow_kernel::proxies::Protocol;

    let cert = make_warp_cert("warp-nodatagram");
    let endpoint_key = warp_endpoint_public_key(&cert);
    let (peer_port, _log) = spawn_warp_peer(WarpMode::NoDatagramSetting, cert).await;
    let yaml = format!(
        "proxies:\n  - {{name: mq, type: masque, server: 127.0.0.1, port: {peer_port}, udp: true, private-key: '{WARP_TEST_KEY}', public-key: '{endpoint_key}', ip: 172.16.0.2}}\nrules: ['MATCH,mq']\n"
    );
    let loaded = billow_kernel::load_config(&yaml, "warp.yaml").unwrap();
    let Protocol::Masque(option) = &loaded.config.proxies[0].protocol else {
        panic!("not masque");
    };
    let tls = ClientTls::new(&[]);
    let error = match MasqueIp::connect(option, &tls, Duration::from_secs(5)).await {
        Ok(_) => panic!("datagram support is required"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("HTTP Datagrams"),
        "the refusal must name the missing datagram support: {message}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_connect_ip_refuses_address_request() {
    use billow_kernel::outbound::masque_ip::MasqueIp;
    use billow_kernel::outbound::tls::ClientTls;
    use billow_kernel::proxies::Protocol;

    let cert = make_warp_cert("warp-address-request");
    let endpoint_key = warp_endpoint_public_key(&cert);
    let (peer_port, log) = spawn_warp_peer(WarpMode::AddressRequest, cert).await;
    let yaml = format!(
        "proxies:\n  - {{name: mq, type: masque, server: 127.0.0.1, port: {peer_port}, udp: true, private-key: '{WARP_TEST_KEY}', public-key: '{endpoint_key}', ip: 172.16.0.2}}\nrules: ['MATCH,mq']\n"
    );
    let loaded = billow_kernel::load_config(&yaml, "warp.yaml").unwrap();
    let Protocol::Masque(option) = &loaded.config.proxies[0].protocol else {
        panic!("not masque");
    };
    let tls = ClientTls::new(&[]);
    let mut association = MasqueIp::connect(option, &tls, Duration::from_secs(5))
        .await
        .expect("the request itself succeeds");
    let mut buffer = [0u8; 1500];
    let error = association
        .recv(&mut buffer)
        .await
        .expect_err("ADDRESS_REQUEST must fail the association");
    assert!(
        error.to_string().contains("ADDRESS_REQUEST"),
        "the refusal must name ADDRESS_REQUEST: {error}"
    );
    assert!(peer_log_has(&log, "sent-capsule=2"), "{log:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_connect_ip_refusal_fails_without_a_reply() {
    let cert = make_warp_cert("warp-refuse");
    let endpoint_key = warp_endpoint_public_key(&cert);
    let (peer_port, log) = spawn_warp_peer(WarpMode::Refuse(403), cert).await;
    let mut kernel = start_warp_kernel(peer_port, &endpoint_key, "");
    let (_control, relay) = masque_udp_associate(kernel.listen_addr());
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target: SocketAddr = "198.51.100.7:5353".parse().unwrap();
    let reply = masque_udp_exchange(&socket, relay, target, b"refused", Duration::from_secs(2));
    assert!(reply.is_none(), "a refused CONNECT-IP must not echo: {reply:?}");
    assert!(wait_for_peer_log(&log, "refused=403").await, "{log:?}");
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_connect_ip_resolves_through_the_tunnel_dns() {
    let cert = make_warp_cert("warp-dns");
    let endpoint_key = warp_endpoint_public_key(&cert);
    let (peer_port, log) = spawn_warp_peer(WarpMode::Accept, cert).await;
    let mut kernel = start_warp_kernel(
        peer_port,
        &endpoint_key,
        ", remote-dns-resolve: true, dns: [1.1.1.1]",
    );
    let (_control, relay) = masque_udp_associate(kernel.listen_addr());
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    // The relay payload carries a hostname; only the tunnel's DNS can turn it
    // into the address the peer answers for.
    let mut packet = vec![0u8, 0u8, 0u8, 0x03, 15];
    packet.extend_from_slice(b"dns-target.test");
    packet.extend_from_slice(&5353u16.to_be_bytes());
    packet.extend_from_slice(b"resolved-through-tunnel");
    socket.send_to(&packet, relay).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buffer = [0u8; 65535];
    let (read, _) = socket.recv_from(&mut buffer).expect("the resolved datagram must echo");
    // The reply carries the destination the client asked for (the relay's
    // existing convention: a hostname stays a hostname).
    assert_eq!(buffer[3], 0x03, "{:?}", &buffer[..read]);
    assert_eq!(buffer[4], 15);
    assert_eq!(&buffer[5..20], b"dns-target.test");
    assert_eq!(&buffer[20..22], &5353u16.to_be_bytes());
    assert_eq!(&buffer[22..read], b"resolved-through-tunnel");
    assert!(wait_for_peer_log(&log, "dns-query name=dns-target.test").await, "{log:?}");
    assert!(
        peer_log_has(&log, "ip src=v4 dst=v4 172.16.0.2:"),
        "the DNS query itself must travel the tunnel: {log:?}"
    );
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_connect_ip_records_the_assignment_and_bounds_the_mtu() {
    use billow_kernel::outbound::masque_ip::MasqueIp;
    use billow_kernel::outbound::tls::ClientTls;
    use billow_kernel::outbound::Target;
    use billow_kernel::proxies::Protocol;

    let cert = make_warp_cert("warp-assign");
    let endpoint_key = warp_endpoint_public_key(&cert);
    let (peer_port, _log) = spawn_warp_peer(WarpMode::Accept, cert).await;
    let yaml = format!(
        "proxies:\n  - {{name: mq, type: masque, server: 127.0.0.1, port: {peer_port}, udp: true, private-key: '{WARP_TEST_KEY}', public-key: '{endpoint_key}', ip: 172.16.0.2, ipv6: fd00::2, mtu: 1280}}\nrules: ['MATCH,mq']\n"
    );
    let loaded = billow_kernel::load_config(&yaml, "warp.yaml").unwrap();
    let Protocol::Masque(option) = &loaded.config.proxies[0].protocol else {
        panic!("not masque");
    };
    let tls = ClientTls::new(&[]);
    let mut association = MasqueIp::connect(option, &tls, Duration::from_secs(5))
        .await
        .expect("CONNECT-IP connects");
    // ADDRESS_ASSIGN arrives out of band on the request stream.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut assigned = Vec::new();
    while std::time::Instant::now() < deadline {
        assigned = association.assigned_prefixes();
        if assigned.len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let rendered: Vec<String> = assigned
        .iter()
        .map(|prefix| format!("{}/{}", prefix.addr, prefix.bits))
        .collect();
    assert_eq!(rendered, ["172.16.0.2/32", "fd00::2/128"]);
    assert_eq!(
        association
            .local_prefixes()
            .iter()
            .map(|prefix| prefix.addr.to_string())
            .collect::<Vec<_>>(),
        ["172.16.0.2", "fd00::2"]
    );
    // 1280 - 28 (IPv4 + UDP) leaves 1252 payload bytes.
    let target = Target {
        host: "198.51.100.7".to_string(),
        port: 5353,
    };
    let error = association
        .send(&target, &vec![0u8; 1300])
        .await
        .expect_err("a datagram over the tunnel MTU must be refused");
    assert!(error.to_string().contains("mtu"), "{error}");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    // 1252 bytes is the largest that fits.
    association
        .send(&target, &vec![0u8; 1252])
        .await
        .expect("a datagram at the MTU limit is sent");
}

fn start_warp_kernel_with_limits(
    peer_port: u16,
    endpoint_key: &str,
    extra: &str,
    limits: Limits,
) -> Kernel {
    let yaml = format!(
        "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: mq, type: masque, server: 127.0.0.1, port: {peer_port}, udp: true, private-key: '{WARP_TEST_KEY}', public-key: '{endpoint_key}', ip: 172.16.0.2, ipv6: fd00::2{extra}}}\nrules:\n  - MATCH,mq\n",
        free_port()
    );
    let (kernel, warnings) = Kernel::start_from_yaml(&yaml, None, limits)
        .unwrap_or_else(|e| panic!("kernel rejected the CONNECT-IP config: {e}\n{yaml}"));
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    kernel
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_connect_ip_carries_a_tcp_stream() {
    let cert = make_warp_cert("warp-tcp");
    let endpoint_key = warp_endpoint_public_key(&cert);
    let (peer_port, log) = spawn_warp_peer(WarpMode::Accept, cert).await;
    let mut kernel = start_warp_kernel(peer_port, &endpoint_key, "");
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        common::socks5_connect(kernel.listen_addr(), "198.51.100.7", 80),
    )
    .await
    .expect("SOCKS5 connect timed out")
    .expect("the TCP tunnel must be established");
    stream.write_all(b"tcp-over-connect-ip").await.unwrap();
    let mut buffer = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer))
        .await
        .expect("the echo timed out")
        .unwrap();
    assert_eq!(&buffer[..read], b"tcp-over-connect-ip");
    // A full-size write must be split at the advertised MSS so every segment's
    // IP length stays within the tunnel MTU (1280 - IP(20) - TCP(20) = 1240).
    let large = vec![b'A'; 5_000];
    stream.write_all(&large).await.unwrap();
    let mut echoed = vec![0u8; large.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed))
        .await
        .expect("the large echo timed out")
        .unwrap();
    assert_eq!(echoed, large);
    // Half-close: FIN travels through the tunnel and the peer answers.
    stream.shutdown().await.unwrap();
    let eof = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer))
        .await
        .expect("the close timed out")
        .unwrap();
    assert_eq!(eof, 0, "the peer's FIN must end the stream");

    let lines = log.lock().unwrap().clone();
    assert!(lines.iter().any(|line| line == "tcp syn"), "{lines:?}");
    assert!(
        lines.iter().any(|line| line == "tcp syn mss=1240"),
        "the SYN must advertise 1240 (1280 - IP/TCP headers): {lines:?}"
    );
    let largest = lines
        .iter()
        .filter_map(|line| line.strip_prefix("tcp data bytes="))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|bytes| bytes.parse::<usize>().ok())
        .max()
        .unwrap_or(0);
    assert!(
        largest > 19 && largest <= 1240 && largest + 40 <= 1280,
        "every segment must fit the tunnel MTU; largest payload {largest}: {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line == "tcp data bytes=19 payload=tcp-over-connect-ip"),
        "{lines:?}"
    );
    assert!(lines.iter().any(|line| line == "tcp fin"), "{lines:?}");
    assert!(lines.iter().any(|line| line == "method=CONNECT"), "{lines:?}");
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_connect_ip_tcp_refusal_is_a_502() {
    let cert = make_warp_cert("warp-tcp-rst");
    let endpoint_key = warp_endpoint_public_key(&cert);
    let (peer_port, log) = spawn_warp_peer_with(WarpMode::Accept, WarpTcpMode::Refuse, cert).await;
    let mut kernel = start_warp_kernel(peer_port, &endpoint_key, "");
    let error = tokio::time::timeout(
        Duration::from_secs(10),
        common::socks5_connect(kernel.listen_addr(), "198.51.100.7", 80),
    )
    .await
    .expect("SOCKS5 connect timed out")
    .expect_err("a RST must refuse the tunnel");
    assert!(error.to_string().contains("socks reply code"), "{error}");
    assert!(wait_for_peer_log(&log, "tcp rst").await, "{log:?}");
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_connect_ip_tcp_timeout_is_reported() {
    let cert = make_warp_cert("warp-tcp-silent");
    let endpoint_key = warp_endpoint_public_key(&cert);
    let (peer_port, log) = spawn_warp_peer_with(WarpMode::Accept, WarpTcpMode::Silent, cert).await;
    let mut fast = limits();
    fast.dial_timeout = Duration::from_secs(2);
    let mut kernel = start_warp_kernel_with_limits(peer_port, &endpoint_key, "", fast);
    let started = std::time::Instant::now();
    let error = tokio::time::timeout(
        Duration::from_secs(10),
        common::socks5_connect(kernel.listen_addr(), "198.51.100.7", 80),
    )
    .await
    .expect("SOCKS5 connect hung")
    .expect_err("an unanswered SYN must fail");
    assert!(error.to_string().contains("socks reply code"), "{error}");
    assert!(
        started.elapsed() >= Duration::from_millis(1500),
        "the dial must wait for its timeout: {:?}",
        started.elapsed()
    );
    assert!(wait_for_peer_log(&log, "tcp syn").await, "{log:?}");
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_connect_ip_tcp_rejects_a_wrong_endpoint_pin() {
    let cert = make_warp_cert("warp-tcp-pin");
    let wrong = billow_kernel::outbound::warp::base64_encode(
        &billow_kernel::outbound::warp::parse_private_key(WARP_TEST_KEY)
            .unwrap()
            .spki,
    );
    let (peer_port, log) = spawn_warp_peer(WarpMode::Accept, cert).await;
    let mut kernel = start_warp_kernel(peer_port, &wrong, "");
    let error = tokio::time::timeout(
        Duration::from_secs(10),
        common::socks5_connect(kernel.listen_addr(), "198.51.100.7", 80),
    )
    .await
    .expect("SOCKS5 connect timed out")
    .expect_err("a wrong endpoint pin must refuse the TCP dial");
    assert!(error.to_string().contains("socks reply code"), "{error}");
    // The TLS handshake reaches the peer but the certificate is refused by
    // the client's pin check, so no TCP SYN is sent.
    assert!(!peer_log_has(&log, "tcp syn"), "{log:?}");
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn masque_connect_ip_tcp_half_close_delivers_eof() {
    let cert = make_warp_cert("warp-tcp-fin");
    let endpoint_key = warp_endpoint_public_key(&cert);
    let (peer_port, log) =
        spawn_warp_peer_with(WarpMode::Accept, WarpTcpMode::FinAfterEcho, cert).await;
    let mut kernel = start_warp_kernel(peer_port, &endpoint_key, "");
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        common::socks5_connect(kernel.listen_addr(), "198.51.100.7", 80),
    )
    .await
    .expect("SOCKS5 connect timed out")
    .expect("the TCP tunnel must be established");
    stream.write_all(b"half-close").await.unwrap();
    let mut buffer = [0u8; 64];
    let mut received = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let read = tokio::time::timeout_at(deadline, stream.read(&mut buffer[received..]))
            .await
            .expect("the echo/FIN timed out")
            .unwrap();
        if read == 0 {
            break;
        }
        received += read;
    }
    assert_eq!(&buffer[..received], b"half-close");
    // The peer closed its direction; ours stays open until the app half-closes.
    assert!(
        !peer_log_has(&log, "tcp fin"),
        "the client has not half-closed yet: {log:?}"
    );
    stream.shutdown().await.unwrap();
    assert!(wait_for_peer_log(&log, "tcp fin").await, "{log:?}");
    kernel.stop().unwrap();
}
