//! CLI success paths for the T11 families: the real `billow-kernel` process
//! (not the library) is the client, and a controlled local peer is the server.
//! Each case starts the process, performs one HTTP CONNECT tunnel through the
//! configured outbound and asserts the echoed marker, so the shipped entry
//! point is covered end to end, not just by loading the configuration.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener as TokioListener;

fn free_port() -> u16 {
    static PORTS: std::sync::Mutex<Option<std::collections::BTreeSet<u16>>> =
        std::sync::Mutex::new(None);
    loop {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut ports = PORTS.lock().unwrap_or_else(|p| p.into_inner());
        if ports.get_or_insert_with(std::collections::BTreeSet::new).insert(port) {
            return port;
        }
    }
}

fn spawn_echo() -> (u16, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(AtomicU64::new(0));
    let counter = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let counter = counter.clone();
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut buffer = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buffer) {
                    if n == 0 {
                        break;
                    }
                    counter.fetch_add(n as u64, Ordering::Relaxed);
                    if stream.write_all(&buffer[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, seen)
}

fn start_cli(body: &str, port: u16) -> Child {
    let dir = std::env::temp_dir().join(format!("billow-cli-family-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config: PathBuf = dir.join("config.yaml");
    std::fs::write(
        &config,
        format!("mixed-port: {port}\nlog-level: warn\n{body}"),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_billow-kernel"))
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn billow-kernel");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return child;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("kernel never listened on {port}");
}

fn stop_cli(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn http_connect(proxy: SocketAddr, authority: &str) -> std::io::Result<(TcpStream, String)> {
    let mut stream = TcpStream::connect(proxy)?;
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

fn tunnel(port: u16, echo_port: u16, marker: &[u8]) -> Vec<u8> {
    let (mut stream, status) = http_connect(
        format!("127.0.0.1:{port}").parse().unwrap(),
        &format!("127.0.0.1:{echo_port}"),
    )
    .expect("connect to CLI");
    assert_eq!(status, "HTTP/1.1 200 Connection Established");
    stream.write_all(marker).unwrap();
    let mut back = vec![0u8; marker.len()];
    stream.read_exact(&mut back).unwrap();
    back
}

// ---------------------------------------------------------------------------
// gost-relay v2 server (the CLI process is the client).
// ---------------------------------------------------------------------------

fn spawn_gost_peer() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut header = [0u8; 4];
                if stream.read_exact(&mut header).is_err() || header[0] != 1 {
                    return;
                }
                let mut features = vec![0u8; u16::from_be_bytes([header[2], header[3]]) as usize];
                if stream.read_exact(&mut features).is_err() {
                    return;
                }
                let mut pos = 0;
                let mut target = None;
                while pos + 3 <= features.len() {
                    let kind = features[pos];
                    let len = u16::from_be_bytes([features[pos + 1], features[pos + 2]]) as usize;
                    let payload = &features[pos + 3..pos + 3 + len];
                    if kind == 0x02 {
                        let (host, rest) = match payload[0] {
                            0x01 => (
                                std::net::Ipv4Addr::new(payload[1], payload[2], payload[3], payload[4])
                                    .to_string(),
                                &payload[5..],
                            ),
                            0x03 => (
                                String::from_utf8_lossy(&payload[2..2 + payload[1] as usize])
                                    .into_owned(),
                                &payload[2 + payload[1] as usize..],
                            ),
                            _ => return,
                        };
                        target = Some((host, u16::from_be_bytes([rest[0], rest[1]])));
                    }
                    pos += 3 + len;
                }
                let Some((host, port)) = target else {
                    let _ = stream.write_all(&[1, 1, 0, 0]);
                    return;
                };
                let Ok(upstream) = TcpStream::connect((host.as_str(), port)) else {
                    let _ = stream.write_all(&[1, 6, 0, 0]);
                    return;
                };
                if stream.write_all(&[1, 0, 0, 0]).is_err() {
                    return;
                }
                let (mut up_r, mut up_w) = (upstream.try_clone().unwrap(), upstream);
                let mut down = stream.try_clone().unwrap();
                let back = std::thread::spawn(move || {
                    let _ = std::io::copy(&mut up_r, &mut down);
                });
                let _ = std::io::copy(&mut stream, &mut up_w);
                let _ = back.join();
            });
        }
    });
    port
}

// ---------------------------------------------------------------------------
// SSR origin/plain server.
// ---------------------------------------------------------------------------

fn spawn_ssr_peer(cipher: billow_kernel::proxies::SsrCipher, password: &'static str) -> u16 {
    let key = billow_kernel::keys::evp_bytes_to_key(password.as_bytes(), cipher.key_len());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = TokioListener::bind(("127.0.0.1", 0)).await.unwrap();
            tx.send(listener.local_addr().unwrap().port()).unwrap();
            loop {
                let Ok((mut tcp, _)) = listener.accept().await else {
                    return;
                };
                let key = key.clone();
                tokio::spawn(async move {
                    let mut server_iv = vec![0u8; cipher.iv_len()];
                    if cipher != billow_kernel::proxies::SsrCipher::Dummy {
                        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut server_iv);
                        if tcp.write_all(&server_iv).await.is_err() {
                            return;
                        }
                    }
                    let mut stream = billow_kernel::outbound::ssr::SsrStream::new(
                        tcp,
                        cipher,
                        key,
                        server_iv,
                    );
                    let mut kind = [0u8; 1];
                    if stream.read_exact(&mut kind).await.is_err() {
                        return;
                    }
                    let host = match kind[0] {
                        0x01 => {
                            let mut octets = [0u8; 4];
                            if stream.read_exact(&mut octets).await.is_err() {
                                return;
                            }
                            std::net::Ipv4Addr::from(octets).to_string()
                        }
                        0x03 => {
                            let mut len = [0u8; 1];
                            if stream.read_exact(&mut len).await.is_err() {
                                return;
                            }
                            let mut name = vec![0u8; len[0] as usize];
                            if stream.read_exact(&mut name).await.is_err() {
                                return;
                            }
                            String::from_utf8_lossy(&name).into_owned()
                        }
                        _ => return,
                    };
                    let mut port = [0u8; 2];
                    if stream.read_exact(&mut port).await.is_err() {
                        return;
                    }
                    let port = u16::from_be_bytes(port);
                    let Ok(mut upstream) = tokio::net::TcpStream::connect((host.as_str(), port)).await
                    else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                });
            }
        });
    });
    rx.recv().unwrap()
}

// ---------------------------------------------------------------------------
// SSH server.
// ---------------------------------------------------------------------------

struct SshPeerState {
    username: String,
    password: String,
}

#[derive(Clone)]
struct SshPeer {
    state: Arc<SshPeerState>,
}

impl russh::server::Server for SshPeer {
    type Handler = SshPeer;

    fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
}

impl russh::server::Handler for SshPeer {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<russh::server::Auth, Self::Error> {
        let ok = user == self.state.username && password == self.state.password;
        Ok(if ok {
            russh::server::Auth::Accept
        } else {
            russh::server::Auth::reject()
        })
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        let host = host_to_connect.to_string();
        let port = port_to_connect as u16;
        tokio::spawn(async move {
            let mut channel = channel.into_stream();
            if let Ok(mut upstream) = tokio::net::TcpStream::connect((host.as_str(), port)).await {
                let _ = tokio::io::copy_bidirectional(&mut channel, &mut upstream).await;
            }
        });
        Ok(true)
    }
}

fn spawn_ssh_peer(username: &'static str, password: &'static str) -> u16 {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let host_key = russh::keys::PrivateKey::random(
                &mut rand::rngs::OsRng,
                russh::keys::Algorithm::Ed25519,
            )
            .unwrap();
            let listener = TokioListener::bind(("127.0.0.1", 0)).await.unwrap();
            tx.send(listener.local_addr().unwrap().port()).unwrap();
            let config = Arc::new(russh::server::Config {
                keys: vec![host_key],
                inactivity_timeout: Some(Duration::from_secs(30)),
                auth_rejection_time: Duration::from_millis(10),
                auth_rejection_time_initial: Some(Duration::from_millis(0)),
                ..Default::default()
            });
            let mut server = SshPeer {
                state: Arc::new(SshPeerState {
                    username: username.to_string(),
                    password: password.to_string(),
                }),
            };
            let _ = russh::server::Server::run_on_socket(&mut server, config, &listener).await;
        });
    });
    rx.recv().unwrap()
}

#[test]
fn cli_process_tunnels_through_gost_relay() {
    let (echo_port, _seen) = spawn_echo();
    let peer_port = spawn_gost_peer();
    let port = free_port();
    let child = start_cli(
        &format!(
            "proxies:\n  - {{name: p, type: gost-relay, server: 127.0.0.1, port: {peer_port}}}\nrules:\n  - 'MATCH,p'\n"
        ),
        port,
    );
    assert_eq!(
        tunnel(port, echo_port, b"cli-gost-marker"),
        b"cli-gost-marker".to_vec()
    );
    stop_cli(child);
}

#[test]
fn cli_process_tunnels_through_ssh() {
    let (echo_port, _seen) = spawn_echo();
    let peer_port = spawn_ssh_peer("tester", "secret");
    let port = free_port();
    let child = start_cli(
        &format!(
            "proxies:\n  - {{name: p, type: ssh, server: 127.0.0.1, port: {peer_port}, username: tester, password: secret}}\nrules:\n  - 'MATCH,p'\n"
        ),
        port,
    );
    assert_eq!(
        tunnel(port, echo_port, b"cli-ssh-marker"),
        b"cli-ssh-marker".to_vec()
    );
    stop_cli(child);
}

#[test]
fn cli_process_tunnels_through_ssr() {
    let (echo_port, _seen) = spawn_echo();
    let peer_port = spawn_ssr_peer(billow_kernel::proxies::SsrCipher::Aes256Cfb, "ssr-pass");
    let port = free_port();
    let child = start_cli(
        &format!(
            "proxies:\n  - {{name: p, type: ssr, server: 127.0.0.1, port: {peer_port}, cipher: aes-256-cfb, password: ssr-pass, protocol: origin, obfs: plain}}\nrules:\n  - 'MATCH,p'\n"
        ),
        port,
    );
    assert_eq!(
        tunnel(port, echo_port, b"cli-ssr-marker"),
        b"cli-ssr-marker".to_vec()
    );
    stop_cli(child);
}

// ---------------------------------------------------------------------------
// TUIC v5 peer (QUIC) for the T10 CLI entry point.
// ---------------------------------------------------------------------------

struct QuicCert {
    der: Vec<u8>,
    key: PathBuf,
    dir: PathBuf,
}

impl Drop for QuicCert {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn make_quic_cert(name: &str) -> QuicCert {
    let dir = std::env::temp_dir().join(format!(
        "billow-cli-quic-{name}-{}-{}",
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
        .args(["-days", "1", "-subj", "/CN=billow-cli-quic", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("openssl is required for the QUIC CLI peer");
    assert!(status.success());
    let pem = std::fs::read_to_string(&cert).unwrap();
    let der = rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .unwrap()
        .unwrap()
        .as_ref()
        .to_vec();
    QuicCert { der, key, dir }
}

fn quic_server_config(cert: &QuicCert) -> quinn::ServerConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert.der.clone())],
            rustls_pemfile::private_key(&mut std::io::BufReader::new(
                std::fs::File::open(&cert.key).unwrap(),
            ))
            .unwrap()
            .unwrap(),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(config).unwrap();
    quinn::ServerConfig::with_crypto(Arc::new(crypto))
}

fn spawn_tuic_cli_peer(password: &'static str) -> u16 {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let cert = make_quic_cert("tuic");
            let endpoint = quinn::Endpoint::server(
                quic_server_config(&cert),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            tx.send(endpoint.local_addr().unwrap().port()).unwrap();
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    let Ok(mut auth) = connection.accept_uni().await else {
                        return;
                    };
                    let mut header = [0u8; 50];
                    if auth.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    if header[0] != 0x05 || header[1] != 0x00 {
                        return;
                    }
                    let mut expected = [0u8; 32];
                    if connection
                        .export_keying_material(&mut expected, &header[2..18], password.as_bytes())
                        .is_err()
                        || expected != header[18..50]
                    {
                        connection.close(quinn::VarInt::from_u32(0xffff_fff1), b"AuthenticationFailed");
                        return;
                    }
                    let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                        return;
                    };
                    let mut head = [0u8; 2];
                    if recv.read_exact(&mut head).await.is_err() || head != [0x05, 0x01] {
                        return;
                    }
                    let mut kind = [0u8; 1];
                    if recv.read_exact(&mut kind).await.is_err() {
                        return;
                    }
                    let host = match kind[0] {
                        0 => {
                            let mut len = [0u8; 1];
                            if recv.read_exact(&mut len).await.is_err() {
                                return;
                            }
                            let mut name = vec![0u8; len[0] as usize];
                            if recv.read_exact(&mut name).await.is_err() {
                                return;
                            }
                            String::from_utf8_lossy(&name).into_owned()
                        }
                        1 => {
                            let mut octets = [0u8; 4];
                            if recv.read_exact(&mut octets).await.is_err() {
                                return;
                            }
                            std::net::Ipv4Addr::from(octets).to_string()
                        }
                        2 => {
                            let mut octets = [0u8; 16];
                            if recv.read_exact(&mut octets).await.is_err() {
                                return;
                            }
                            std::net::Ipv6Addr::from(octets).to_string()
                        }
                        _ => return,
                    };
                    let mut port = [0u8; 2];
                    if recv.read_exact(&mut port).await.is_err() {
                        return;
                    }
                    let port = u16::from_be_bytes(port);
                    let Ok(upstream) = tokio::net::TcpStream::connect((host.as_str(), port)).await
                    else {
                        return;
                    };
                    let (mut up_r, mut up_w) = upstream.into_split();
                    let up = tokio::spawn(async move {
                        let _ = tokio::io::copy(&mut recv, &mut up_w).await;
                        let _ = up_w.shutdown().await;
                    });
                    let _ = tokio::io::copy(&mut up_r, &mut send).await;
                    let _ = send.finish();
                    let _ = up.await;
                });
            }
        });
    });
    rx.recv().unwrap()
}

#[test]
fn cli_process_tunnels_through_tuic() {
    let (echo_port, _seen) = spawn_echo();
    let peer_port = spawn_tuic_cli_peer("cli-tuic-secret");
    let port = free_port();
    let child = start_cli(
        &format!(
            "proxies:\n  - {{name: p, type: tuic, server: 127.0.0.1, port: {peer_port}, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, password: cli-tuic-secret, skip-cert-verify: true}}\nrules:\n  - 'MATCH,p'\n"
        ),
        port,
    );
    assert_eq!(
        tunnel(port, echo_port, b"cli-tuic-marker"),
        b"cli-tuic-marker".to_vec()
    );
    stop_cli(child);
}
