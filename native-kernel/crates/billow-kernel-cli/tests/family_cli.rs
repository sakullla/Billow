//! CLI success paths for the T11 families: the real `billow-kernel` process
//! (not the library) is the client, and a controlled local peer is the server.
//! Each case starts the process, performs one HTTP CONNECT tunnel through the
//! configured outbound and asserts the echoed marker, so the shipped entry
//! point is covered end to end, not just by loading the configuration.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener as TokioListener;

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
    // Keep the kernel's stderr in a file rather than /dev/null: a bind failure
    // or an early exit is then reported with its own message instead of as a
    // later ConnectionRefused.
    let stderr_path = dir.join("stderr.log");
    let stderr = std::fs::File::create(&stderr_path).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_billow-kernel"))
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn billow-kernel");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("wait for billow-kernel") {
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            panic!("kernel exited with {status} before listening on {port}: {stderr}");
        }
        if kernel_ready(port) {
            return child;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    let _ = child.kill();
    let _ = child.wait();
    panic!("kernel never listened on {port}: {stderr}");
}

/// A bare TCP connect only proves *some* listener owns the port. The mixed
/// inbound's SOCKS5 method negotiation proves the kernel itself is serving, and
/// the read timeout keeps a foreign listener from stalling the probe.
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

fn stop_cli(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Connect to the CLI's listener, retrying a refused connection for a short
/// while. `start_cli` already waits for the SOCKS5 handshake, so a refusal here
/// is a transient scheduling/port-reuse race, not a protocol verdict; a kernel
/// that is gone still fails within the deadline.
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

fn tunnel(port: u16, echo_port: u16, marker: &[u8]) -> Vec<u8> {
    let (mut stream, status) = http_connect(
        format!("127.0.0.1:{port}").parse().unwrap(),
        &format!("127.0.0.1:{echo_port}"),
    )
    .expect("connect to CLI");
    assert_eq!(status, "HTTP/1.1 200 Connection Established");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    stream.write_all(marker).unwrap();
    let mut back = vec![0u8; marker.len()];
    stream.read_exact(&mut back).expect("relayed marker");
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
                                std::net::Ipv4Addr::new(
                                    payload[1], payload[2], payload[3], payload[4],
                                )
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
                    let mut stream =
                        billow_kernel::outbound::ssr::SsrStream::new(tcp, cipher, key, server_iv);
                    // Bound the address read: garbage (a wrong password) must
                    // not wait for bytes the client never sends.
                    let address = async {
                        let mut kind = [0u8; 1];
                        stream.read_exact(&mut kind).await?;
                        let host = match kind[0] {
                            0x01 => {
                                let mut octets = [0u8; 4];
                                stream.read_exact(&mut octets).await?;
                                std::net::Ipv4Addr::from(octets).to_string()
                            }
                            0x03 => {
                                let mut len = [0u8; 1];
                                stream.read_exact(&mut len).await?;
                                let mut name = vec![0u8; len[0] as usize];
                                stream.read_exact(&mut name).await?;
                                String::from_utf8_lossy(&name).into_owned()
                            }
                            _ => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "bad address type",
                                ))
                            }
                        };
                        let mut port = [0u8; 2];
                        stream.read_exact(&mut port).await?;
                        Ok::<_, std::io::Error>((host, u16::from_be_bytes(port)))
                    };
                    let Ok(Ok((host, port))) =
                        tokio::time::timeout(Duration::from_secs(2), address).await
                    else {
                        return;
                    };
                    let Ok(mut upstream) =
                        tokio::net::TcpStream::connect((host.as_str(), port)).await
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
// gost-relay v2 server behind a version-1 smux session. One stream per
// connection (the pinned relay dialer's `mux` mode) and a one-shot echo relay,
// which is what the CLI's single marker roundtrip needs.
// ---------------------------------------------------------------------------

struct MuxPeer {
    stream: TcpStream,
    sid: u32,
    under: Vec<u8>,
    out: Vec<u8>,
}

impl Read for MuxPeer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if !self.out.is_empty() {
                let take = self.out.len().min(buf.len());
                buf[..take].copy_from_slice(&self.out[..take]);
                self.out.drain(..take);
                return Ok(take);
            }
            let mut consumed = 0;
            while self.under.len() >= consumed + 8 {
                let frame = &self.under[consumed..];
                let cmd = frame[1];
                let len = u16::from_le_bytes([frame[2], frame[3]]) as usize;
                let sid = u32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]);
                if self.under.len() < consumed + 8 + len {
                    break;
                }
                let payload = self.under[consumed + 8..consumed + 8 + len].to_vec();
                consumed += 8 + len;
                if cmd == 2 && sid == self.sid {
                    self.out.extend_from_slice(&payload);
                }
            }
            if consumed > 0 {
                self.under.drain(..consumed);
                continue;
            }
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                return Ok(0);
            }
            self.under.extend_from_slice(&chunk[..n]);
        }
    }
}

impl Write for MuxPeer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut header = [0u8; 8];
        header[0] = 1;
        header[1] = 2;
        header[2..4].copy_from_slice(&(buf.len() as u16).to_le_bytes());
        header[4..8].copy_from_slice(&self.sid.to_le_bytes());
        self.stream.write_all(&header)?;
        self.stream.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

fn spawn_gost_mux_peer() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut syn = [0u8; 8];
                if stream.read_exact(&mut syn).is_err() || syn[0] != 1 || syn[1] != 0 {
                    return;
                }
                let sid = u32::from_le_bytes([syn[4], syn[5], syn[6], syn[7]]);
                let mut mux = MuxPeer {
                    stream,
                    sid,
                    under: Vec::new(),
                    out: Vec::new(),
                };
                let mut header = [0u8; 4];
                if mux.read_exact(&mut header).is_err() || header[0] != 1 {
                    return;
                }
                let mut features = vec![0u8; u16::from_be_bytes([header[2], header[3]]) as usize];
                if mux.read_exact(&mut features).is_err() {
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
                                std::net::Ipv4Addr::new(
                                    payload[1], payload[2], payload[3], payload[4],
                                )
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
                    let _ = mux.write_all(&[1, 1, 0, 0]);
                    return;
                };
                let Ok(mut upstream) = TcpStream::connect((host.as_str(), port)) else {
                    let _ = mux.write_all(&[1, 6, 0, 0]);
                    return;
                };
                if mux.write_all(&[1, 0, 0, 0]).is_err() {
                    return;
                }
                // One-shot relay: the CLI sends one marker and waits for it.
                let mut buffer = [0u8; 4096];
                let Ok(n) = mux.read(&mut buffer) else {
                    return;
                };
                if n == 0 {
                    return;
                }
                if upstream.write_all(&buffer[..n]).is_err() {
                    return;
                }
                let mut back = vec![0u8; n];
                if upstream.read_exact(&mut back).is_err() {
                    return;
                }
                let _ = mux.write_all(&back);
            });
        }
    });
    port
}

#[test]
fn cli_process_tunnels_through_gost_relay_mux() {
    let (echo_port, _seen) = spawn_echo();
    let peer_port = spawn_gost_mux_peer();
    let port = free_port();
    let child = start_cli(
        &format!(
            "proxies:\n  - {{name: p, type: gost-relay, server: 127.0.0.1, port: {peer_port}, mux: true}}\nrules:\n  - 'MATCH,p'\n"
        ),
        port,
    );
    assert_eq!(
        tunnel(port, echo_port, b"cli-gost-mux-marker"),
        b"cli-gost-mux-marker".to_vec()
    );
    stop_cli(child);
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

/// The SSR plugin layers through the real CLI process. The peer is the Go
/// server from `tool/kernel-compat/peers/ssr-plugins` (the pinned tree has no
/// SSR listener); the case is `#[ignore]`d and driven by
/// `tool/kernel-compat/family-peers.sh`, which builds the peer and sets
/// `KC_SSR_PLUGINS_BIN`.
#[test]
#[ignore = "needs the Go SSR plugin peer: run tool/kernel-compat/family-peers.sh"]
fn cli_process_tunnels_through_an_ssr_plugin() {
    let Some(bin) = std::env::var_os("KC_SSR_PLUGINS_BIN") else {
        eprintln!("SKIP cli_process_tunnels_through_an_ssr_plugin (set KC_SSR_PLUGINS_BIN; run tool/kernel-compat/family-peers.sh)");
        return;
    };
    let (echo_port, _seen) = spawn_echo();
    let peer_port = free_port();
    let mut peer = Command::new(bin)
        .args([
            "-listen",
            &format!("127.0.0.1:{peer_port}"),
            "-cipher",
            "aes-256-cfb",
            "-password",
            "cli-plugin-pass",
            "-protocol",
            "auth_chain_b",
            "-obfs",
            "tls1.2_ticket_auth",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the SSR plugin peer");
    let stdout = peer.stdout.take().expect("peer stdout");
    let mut lines = std::io::BufRead::lines(std::io::BufReader::new(stdout));
    let ready = lines.next().expect("peer READY line").expect("peer READY");
    assert!(ready.starts_with("READY "), "peer said: {ready}");
    let port = free_port();
    let child = start_cli(
        &format!(
            "proxies:\n  - {{name: p, type: ssr, server: 127.0.0.1, port: {peer_port}, cipher: aes-256-cfb, password: cli-plugin-pass, protocol: auth_chain_b, obfs: tls1.2_ticket_auth}}\nrules:\n  - 'MATCH,p'\n"
        ),
        port,
    );
    assert_eq!(
        tunnel(port, echo_port, b"cli-ssr-plugin-marker"),
        b"cli-ssr-plugin-marker".to_vec()
    );
    stop_cli(child);
    let _ = peer.kill();
    let _ = peer.wait();
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
    make_quic_cert_with(name, false)
}

/// A P-256 certificate: the WARP endpoint key is ECDSA (the pinned adapter
/// refuses anything else), so the CONNECT-IP CLI peer needs one.
fn make_quic_ec_cert(name: &str) -> QuicCert {
    make_quic_cert_with(name, true)
}

fn make_quic_cert_with(name: &str, ecdsa: bool) -> QuicCert {
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
            "/CN=billow-cli-quic",
            "-addext",
            "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ])
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

fn quic_server_config(cert: &QuicCert, alpn: &[u8]) -> quinn::ServerConfig {
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
    config.alpn_protocols = vec![alpn.to_vec()];
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
                quic_server_config(&cert, b"h3"),
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
                        connection.close(
                            quinn::VarInt::from_u32(0xffff_fff1),
                            b"AuthenticationFailed",
                        );
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

// ---------------------------------------------------------------------------
// Hysteria v1 peer (QUIC, `transport/hysteria/core/protocol.go`).
// ---------------------------------------------------------------------------

fn spawn_hysteria_cli_peer(auth: &'static str) -> u16 {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let cert = make_quic_cert("hysteria");
            let endpoint = quinn::Endpoint::server(
                quic_server_config(&cert, b"hysteria"),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            tx.send(endpoint.local_addr().unwrap().port()).unwrap();
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    let Ok((mut control_send, mut control_recv)) = connection.accept_bi().await
                    else {
                        return;
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
                    let message: &[u8] = if version != 3 {
                        b"unsupported client version"
                    } else if client_auth != auth.as_bytes() {
                        b"auth error"
                    } else {
                        b""
                    };
                    if !message.is_empty() {
                        hello.push(0);
                        hello.extend_from_slice(&send_bps.to_be_bytes());
                        hello.extend_from_slice(&recv_bps.to_be_bytes());
                        hello.extend_from_slice(&(message.len() as u16).to_be_bytes());
                        hello.extend_from_slice(message);
                        let _ = control_send.write_all(&hello).await;
                        let _ = control_send.finish();
                        return;
                    }
                    hello.push(1);
                    hello.extend_from_slice(&send_bps.to_be_bytes());
                    hello.extend_from_slice(&recv_bps.to_be_bytes());
                    hello.extend_from_slice(&0u16.to_be_bytes());
                    let _ = control_send.write_all(&hello).await;
                    let _ = control_send.finish();

                    let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                        return;
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
                    let host = String::from_utf8_lossy(&host).into_owned();
                    let port = u16::from_be_bytes(port);
                    let Ok(upstream) = tokio::net::TcpStream::connect((host.as_str(), port)).await
                    else {
                        let _ = send.write_all(&[0, 0, 0, 0, 0, 0, 0]).await;
                        return;
                    };
                    let _ = send.write_all(&[1, 0, 0, 0, 0, 0, 0]).await;
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
fn cli_process_tunnels_through_hysteria() {
    let (echo_port, _seen) = spawn_echo();
    let peer_port = spawn_hysteria_cli_peer("cli-hysteria-secret");
    let port = free_port();
    let child = start_cli(
        &format!(
            "proxies:\n  - {{name: p, type: hysteria, server: 127.0.0.1, port: {peer_port}, up: 50 Mbps, down: 50 Mbps, auth-str: cli-hysteria-secret, skip-cert-verify: true}}\nrules:\n  - 'MATCH,p'\n"
        ),
        port,
    );
    assert_eq!(
        tunnel(port, echo_port, b"cli-hysteria-marker"),
        b"cli-hysteria-marker".to_vec()
    );
    stop_cli(child);
}

// ---------------------------------------------------------------------------
// Hysteria2 peer: the minimal HTTP/3 auth exchange followed by the 0x401 TCP
// frame, using the library's h3 field-section codec (so the CLI test does not
// need a second QPACK implementation).
// ---------------------------------------------------------------------------

fn spawn_hysteria2_cli_peer(password: &'static str) -> u16 {
    use billow_kernel::outbound::h3;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let cert = make_quic_cert("hysteria2");
            let endpoint = quinn::Endpoint::server(
                quic_server_config(&cert, b"h3"),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            tx.send(endpoint.local_addr().unwrap().port()).unwrap();
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    let Ok((mut auth_send, mut auth_recv)) = connection.accept_bi().await else {
                        return;
                    };
                    let headers = loop {
                        let Some(frame_type) =
                            h3::read_varint_async(&mut auth_recv).await.ok().flatten()
                        else {
                            return;
                        };
                        let Some(length) =
                            h3::read_varint_async(&mut auth_recv).await.ok().flatten()
                        else {
                            return;
                        };
                        let mut payload = vec![0u8; length as usize];
                        if auth_recv.read_exact(&mut payload).await.is_err() {
                            return;
                        }
                        if frame_type == 0x01 {
                            break h3::decode_field_section(&payload).unwrap_or_default();
                        }
                    };
                    let auth_ok = headers
                        .iter()
                        .any(|(name, value)| name == "hysteria-auth" && value == password);
                    let status = if auth_ok { "233" } else { "401" };
                    let block = h3::encode_field_section(&[
                        (":status", status),
                        ("hysteria-udp", "false"),
                        ("hysteria-cc-rx", "0"),
                    ]);
                    let mut response = Vec::new();
                    h3::encode_varint(0x01, &mut response);
                    h3::encode_varint(block.len() as u64, &mut response);
                    response.extend_from_slice(&block);
                    let _ = auth_send.write_all(&response).await;
                    let _ = auth_send.finish();
                    if !auth_ok {
                        return;
                    }
                    let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                        return;
                    };
                    let frame_type = h3::read_varint_async(&mut recv).await.ok().flatten();
                    if frame_type != Some(0x401) {
                        return;
                    }
                    let Some(addr_len) = h3::read_varint_async(&mut recv).await.ok().flatten()
                    else {
                        return;
                    };
                    let mut addr = vec![0u8; addr_len as usize];
                    if recv.read_exact(&mut addr).await.is_err() {
                        return;
                    }
                    let Some(padding_len) = h3::read_varint_async(&mut recv).await.ok().flatten()
                    else {
                        return;
                    };
                    let mut padding = vec![0u8; padding_len as usize];
                    if recv.read_exact(&mut padding).await.is_err() {
                        return;
                    }
                    let addr = String::from_utf8_lossy(&addr).into_owned();
                    let Ok(upstream) = tokio::net::TcpStream::connect(addr.as_str()).await else {
                        let mut error = vec![1u8];
                        h3::encode_varint(14, &mut error);
                        error.extend_from_slice(b"connect failed");
                        h3::encode_varint(0, &mut error);
                        let _ = send.write_all(&error).await;
                        let _ = send.finish();
                        return;
                    };
                    // status 0, message length 0, padding length 0
                    let _ = send.write_all(&[0, 0, 0]).await;
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
fn cli_process_tunnels_through_hysteria2() {
    let (echo_port, _seen) = spawn_echo();
    let peer_port = spawn_hysteria2_cli_peer("cli-hysteria2-secret");
    let port = free_port();
    let child = start_cli(
        &format!(
            "proxies:\n  - {{name: p, type: hysteria2, server: 127.0.0.1, port: {peer_port}, password: cli-hysteria2-secret, skip-cert-verify: true}}\nrules:\n  - 'MATCH,p'\n"
        ),
        port,
    );
    assert_eq!(
        tunnel(port, echo_port, b"cli-hysteria2-marker"),
        b"cli-hysteria2-marker".to_vec()
    );
    stop_cli(child);
}

// ---------------------------------------------------------------------------
// MASQUE CONNECT-UDP peer (RFC 9298). The CLI process is the client and the
// peer uses the library's h3 codec for brevity; the independent wire-format
// check (its own QPACK/capsule codec) lives in tests/quic_peers.rs.
// ---------------------------------------------------------------------------

fn spawn_masque_cli_peer() -> u16 {
    use billow_kernel::outbound::h3;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let cert = make_quic_cert("masque");
            let endpoint = quinn::Endpoint::server(
                quic_server_config(&cert, b"h3"),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            tx.send(endpoint.local_addr().unwrap().port()).unwrap();
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    // Server control stream: SETTINGS_ENABLE_CONNECT_PROTOCOL.
                    let Ok(mut control) = connection.open_uni().await else {
                        return;
                    };
                    let mut settings = Vec::new();
                    h3::encode_varint(0x08, &mut settings);
                    h3::encode_varint(1, &mut settings);
                    let mut frame = Vec::new();
                    h3::encode_varint(0x04, &mut frame);
                    h3::encode_varint(settings.len() as u64, &mut frame);
                    frame.extend_from_slice(&settings);
                    if control.write_all(&[0x00]).await.is_err()
                        || control.write_all(&frame).await.is_err()
                    {
                        return;
                    }
                    let _control = control;
                    let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                        return;
                    };
                    let mut headers = false;
                    while let Ok(Some((frame_type, _))) = h3::read_frame(&mut recv).await {
                        if frame_type == 0x01 {
                            headers = true;
                            break;
                        }
                    }
                    if !headers {
                        return;
                    }
                    let block =
                        h3::encode_field_section(&[(":status", "200"), ("capsule-protocol", "?1")]);
                    let mut response = Vec::new();
                    h3::encode_varint(0x01, &mut response);
                    h3::encode_varint(block.len() as u64, &mut response);
                    response.extend_from_slice(&block);
                    if send.write_all(&response).await.is_err() {
                        return;
                    }
                    let mut pending = Vec::new();
                    while let Ok(Some((frame_type, data))) = h3::read_frame(&mut recv).await {
                        if frame_type != 0x00 {
                            continue;
                        }
                        pending.extend_from_slice(&data);
                        while let Some((capsule_type, value)) = masque_cli_capsule(&mut pending) {
                            if capsule_type != 0x00 {
                                continue;
                            }
                            let mut pos = 0;
                            let Some(context) = h3::decode_varint(&value, &mut pos) else {
                                return;
                            };
                            if context != 0 {
                                return;
                            }
                            let payload = &value[pos..];
                            let mut capsule = Vec::new();
                            h3::encode_varint(0x00, &mut capsule);
                            h3::encode_varint((1 + payload.len()) as u64, &mut capsule);
                            h3::encode_varint(0, &mut capsule);
                            capsule.extend_from_slice(payload);
                            let mut frame = Vec::new();
                            h3::encode_varint(0x00, &mut frame);
                            h3::encode_varint(capsule.len() as u64, &mut frame);
                            frame.extend_from_slice(&capsule);
                            if send.write_all(&frame).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
    });
    rx.recv().unwrap()
}

/// A T18 CONNECT-IP peer for the shipped process: it advertises extended
/// CONNECT and HTTP Datagrams, answers `cf-connect-ip`, assigns the client's
/// local addresses and echoes every tunnelled IP/UDP packet. It returns the
/// port and the endpoint SubjectPublicKeyInfo (base64) the client pins.
/// The IP codec is the kernel's `outbound::ipstack`; the HTTP/3 and datagram
/// framing is written here, and `tests/quic_peers.rs` covers the same path
/// with an independent IP codec and a mandatory client certificate.
fn spawn_masque_connect_ip_cli_peer() -> (u16, String) {
    use billow_kernel::outbound::h3;
    use billow_kernel::outbound::ipstack;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let cert = make_quic_ec_cert("masque-ip");
            let endpoint_key = billow_kernel::outbound::warp::base64_encode(
                &billow_kernel::outbound::warp::spki_of_certificate(&cert.der)
                    .expect("peer SPKI"),
            );
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut tls = rustls::ServerConfig::builder_with_provider(provider)
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
            tls.alpn_protocols = vec![b"h3".to_vec()];
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
            let mut transport = quinn::TransportConfig::default();
            transport.datagram_receive_buffer_size(Some(64 * 1024));
            transport.datagram_send_buffer_size(64 * 1024);
            let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            config.transport_config(Arc::new(transport));
            let endpoint =
                quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
            tx.send((endpoint.local_addr().unwrap().port(), endpoint_key))
                .unwrap();
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    let Ok(mut control) = connection.open_uni().await else {
                        return;
                    };
                    let mut settings = Vec::new();
                    for id in [0x08u64, 0x33, 0x276] {
                        h3::encode_varint(id, &mut settings);
                        h3::encode_varint(1, &mut settings);
                    }
                    let mut frame = Vec::new();
                    h3::encode_varint(0x04, &mut frame);
                    h3::encode_varint(settings.len() as u64, &mut frame);
                    frame.extend_from_slice(&settings);
                    if control.write_all(&[0x00]).await.is_err()
                        || control.write_all(&frame).await.is_err()
                    {
                        return;
                    }
                    let Ok(mut encoder) = connection.open_uni().await else {
                        return;
                    };
                    let _ = encoder.write_all(&[0x02]).await;
                    let Ok(mut decoder) = connection.open_uni().await else {
                        return;
                    };
                    let _ = decoder.write_all(&[0x03]).await;
                    let _keep = (control, encoder, decoder);
                    let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                        return;
                    };
                    let quarter = recv.id().index();
                    let mut headers = false;
                    while let Ok(Some((frame_type, _))) = h3::read_frame(&mut recv).await {
                        if frame_type == 0x01 {
                            headers = true;
                            break;
                        }
                    }
                    if !headers {
                        return;
                    }
                    let block =
                        h3::encode_field_section(&[(":status", "200"), ("capsule-protocol", "?1")]);
                    let mut response = Vec::new();
                    h3::encode_varint(0x01, &mut response);
                    h3::encode_varint(block.len() as u64, &mut response);
                    response.extend_from_slice(&block);
                    // ADDRESS_ASSIGN (0x01): 172.16.0.2/32 and fd00::2/128.
                    let mut assign = Vec::new();
                    assign.extend_from_slice(&[0, 4, 172, 16, 0, 2, 32]);
                    let fd00: std::net::Ipv6Addr = "fd00::2".parse().unwrap();
                    assign.push(0);
                    assign.push(6);
                    assign.extend_from_slice(&fd00.octets());
                    assign.push(128);
                    let mut body = Vec::new();
                    h3::encode_varint(0x01, &mut body);
                    h3::encode_varint(assign.len() as u64, &mut body);
                    body.extend_from_slice(&assign);
                    h3::encode_varint(0x00, &mut response);
                    h3::encode_varint(body.len() as u64, &mut response);
                    response.extend_from_slice(&body);
                    if send.write_all(&response).await.is_err() {
                        return;
                    }
                    // Drain the request stream (the client's route advertisement)
                    // and echo tunnelled packets.
                    let mut capsule_buf = Vec::new();
                    loop {
                        tokio::select! {
                            frame = h3::read_frame(&mut recv) => {
                                match frame {
                                    Ok(Some((0x00, data))) => capsule_buf.extend_from_slice(&data),
                                    Ok(Some(_)) => {}
                                    Ok(None) | Err(_) => return,
                                }
                                let _ = (&mut capsule_buf, quarter);
                            }
                            datagram = connection.read_datagram() => {
                                let Ok(datagram) = datagram else { return };
                                let mut pos = 0;
                                let Some(stream) = h3::decode_varint(&datagram, &mut pos) else {
                                    continue;
                                };
                                if stream != quarter {
                                    continue;
                                }
                                let Some(context) = h3::decode_varint(&datagram, &mut pos) else {
                                    continue;
                                };
                                if context != 0 {
                                    continue;
                                }
                                let Ok(packet) = ipstack::parse_ip_packet(&datagram[pos..]) else {
                                    continue;
                                };
                                let Ok(udp) = ipstack::parse_udp(&packet) else {
                                    continue;
                                };
                                let Ok(reply) = ipstack::build_udp_packet(
                                    udp.dst,
                                    udp.src,
                                    udp.dst_port,
                                    udp.src_port,
                                    udp.payload,
                                    64,
                                ) else {
                                    continue;
                                };
                                let mut out = Vec::new();
                                h3::encode_varint(quarter, &mut out);
                                h3::encode_varint(0, &mut out);
                                out.extend_from_slice(&reply);
                                if connection.send_datagram(out.into()).is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
    });
    rx.recv().unwrap()
}

fn masque_cli_capsule(buffer: &mut Vec<u8>) -> Option<(u64, Vec<u8>)> {
    use billow_kernel::outbound::h3;
    let mut pos = 0;
    let kind = h3::decode_varint(buffer, &mut pos)?;
    let length = h3::decode_varint(buffer, &mut pos)? as usize;
    let end = pos.checked_add(length)?;
    if buffer.len() < end {
        return None;
    }
    let value = buffer[pos..end].to_vec();
    buffer.drain(..end);
    Some((kind, value))
}

fn masque_udp_associate(proxy: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut control =
        TcpStream::connect_timeout(&proxy, Duration::from_secs(5)).expect("UDP control");
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

fn masque_udp_exchange(
    socket: &UdpSocket,
    relay: SocketAddr,
    target: SocketAddr,
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

/// The shipped process forwards a UDP datagram through a masque CONNECT-UDP
/// outbound: start the real `billow-kernel`, open a SOCKS5 `UDP ASSOCIATE`,
/// send one datagram and read the controlled HTTP/3 peer's echo.
#[test]
fn cli_process_tunnels_udp_through_masque() {
    let peer_port = spawn_masque_cli_peer();
    let port = free_port();
    let child = start_cli(
        &format!(
            "proxies:\n  - {{name: p, type: masque, server: 127.0.0.1, port: {peer_port}, udp: true, skip-cert-verify: true}}\nrules:\n  - 'MATCH,p'\n"
        ),
        port,
    );
    let (control, relay) = masque_udp_associate(format!("127.0.0.1:{port}").parse().unwrap());
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target: SocketAddr = "198.51.100.7:5353".parse().unwrap();
    let reply = masque_udp_exchange(
        &socket,
        relay,
        target,
        b"cli-masque-marker",
        Duration::from_secs(10),
    )
    .expect("a CONNECT-UDP datagram through the CLI must echo");
    assert_eq!(reply, b"cli-masque-marker");
    drop(control);
    stop_cli(child);
}

/// Throwaway P-256 SEC1 private key (base64) for the CONNECT-IP CLI case.
const WARP_CLI_KEY: &str = "MHcCAQEEIDKh56LbUI7PTfKO5ojiPkNrK2H8jcLrmfdlhv3TsqRzoAoGCCqGSM49AwEHoUQDQgAEMAUkhPqJXQGTsDj6a3yC7F2zxIWXs6UJCc/Mwr6wL3GWgqbrP6tvB52ZUbnalrJXSxMwUFXDTHNqxPhpzzUawA==";

/// T18's CONNECT-IP path in the shipped process: a WARP-shaped configuration
/// (keys, local addresses, pinned endpoint key) loads, and a SOCKS5 UDP
/// datagram is tunnelled as an IP/UDP packet and comes back.
#[test]
fn cli_process_tunnels_udp_through_masque_connect_ip() {
    let (peer_port, endpoint_key) = spawn_masque_connect_ip_cli_peer();
    let port = free_port();
    let child = start_cli(
        &format!(
            "proxies:\n  - {{name: p, type: masque, server: 127.0.0.1, port: {peer_port}, udp: true, private-key: '{WARP_CLI_KEY}', public-key: '{endpoint_key}', ip: 172.16.0.2, ipv6: fd00::2}}\nrules:\n  - 'MATCH,p'\n"
        ),
        port,
    );
    let (control, relay) = masque_udp_associate(format!("127.0.0.1:{port}").parse().unwrap());
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target: SocketAddr = "198.51.100.7:5353".parse().unwrap();
    let reply = masque_udp_exchange(
        &socket,
        relay,
        target,
        b"cli-connect-ip-marker",
        Duration::from_secs(10),
    )
    .expect("a CONNECT-IP datagram through the CLI must echo");
    assert_eq!(reply, b"cli-connect-ip-marker");
    drop(control);
    stop_cli(child);
}
