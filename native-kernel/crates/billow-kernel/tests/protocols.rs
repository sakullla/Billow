//! Protocol-family integration tests: the kernel dials a configured proxy
//! over a real loopback listener that implements the server side of the
//! protocol (SOCKS5, HTTP CONNECT, Shadowsocks AEAD, Trojan over TLS, VLESS
//! over TLS, VLESS over TLS+WebSocket). Each peer records the exact bytes a
//! Mihomo listener would decode (credentials, address, payload) and the
//! negative tests drive wrong credentials, TLS verification failures and
//! protocol mismatches.
//!
//! The Mihomo↔Mihomo / Mihomo↔Rust comparison lives in
//! `tool/kernel-compat` and needs the pinned Mihomo binary.

#[allow(dead_code)]
mod common;

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use billow_kernel::keys::trojan_password_key;
use billow_kernel::outbound::shadowsocks::SsDatagram;
use billow_kernel::outbound::vless::parse_header as vless_parse;
use billow_kernel::{load_config, ConfigError, Kernel, Limits};
use common::{free_port, http_connect, socks5_connect};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

// ---------------------------------------------------------------------------
// Scenario descriptors returned by each peer after every accepted connection.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct Attempt {
    /// What the peer observed before (or instead of) forwarding: credentials,
    /// decoded address, payload. Free-form so each protocol records its own.
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

/// Wait for the peer's log to contain a line with `prefix`. A peer writes its
/// reply before it records the attempt, so a negative case can observe the
/// client failure a moment before the peer's own line appears.
async fn wait_detail_prefix(log: &Log, prefix: &str) -> bool {
    for _ in 0..200 {
        if detail(log).iter().any(|d| d.starts_with(prefix)) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

fn forwarded_count(log: &Log) -> usize {
    log.lock().unwrap().iter().filter(|a| a.forwarded).count()
}

async fn spawn_tcp() -> (TcpListener, std::net::SocketAddr) {
    let std_listener = common::bind_loopback();
    let addr = std_listener.local_addr().unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let listener = TcpListener::from_std(std_listener).expect("adopt listener");
    (listener, addr)
}

/// Relays between the peer's stream and the target, echo-copying in both
/// directions. The proxy protocol header is already consumed by the caller.
fn relay_task<R, W>(mut client_r: R, mut client_w: W, target: SocketAddr)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let upstream = TcpStream::connect(target).await.expect("peer dials target");
        let (mut up_r, mut up_w) = upstream.into_split();
        let up = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut client_r, &mut up_w).await;
            let _ = up_w.shutdown().await;
        });
        let _ = tokio::io::copy(&mut up_r, &mut client_w).await;
        let _ = client_w.shutdown().await;
        let _ = up.await;
    });
}

// ---------------------------------------------------------------------------
// TLS certificates generated with the openssl CLI (no third-party crypto
// dependency): a self-signed RSA certificate for 127.0.0.1/localhost.
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

fn make_cert(name: &str) -> Option<Cert> {
    let dir = std::env::temp_dir().join(format!(
        "billow-tls-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).ok()?;
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
            "/CN=billow-test",
            "-addext",
            "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }
    let pem = std::fs::read_to_string(&cert).ok()?;
    let der = rustls_pemfile::certs(&mut pem.as_bytes())
        .next()?
        .ok()?
        .as_ref()
        .to_vec();
    Some(Cert { der, key, dir })
}

/// Skipping the tests without openssl would be a silent pass; the platform note
/// says so explicitly instead.
fn require_cert(name: &str) -> Cert {
    make_cert(name).unwrap_or_else(|| {
        panic!("these tests need the openssl CLI to mint a loopback certificate; without it the TLS peers are not exercised")
    })
}

/// A private CA and a server certificate signed by it (SAN for 127.0.0.1 and
/// localhost). The CA PEM stays next to the server identity, so a kernel can
/// be started with `tls: {custom-cert: [<ca>]}` while the `Cert` is alive.
fn make_ca_signed_cert(name: &str) -> Option<(Cert, PathBuf)> {
    let dir = std::env::temp_dir().join(format!(
        "billow-ca-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).ok()?;
    let ca_key = dir.join("ca.key");
    let ca_pem = dir.join("ca.pem");
    let key = dir.join("key.pem");
    let csr = dir.join("server.csr");
    let server_pem = dir.join("cert.pem");
    let ext = dir.join("server.ext");
    std::fs::write(
        &ext,
        "subjectAltName=IP:127.0.0.1,DNS:localhost\n         basicConstraints=critical,CA:FALSE\n         keyUsage=critical,digitalSignature,keyEncipherment\n         extendedKeyUsage=serverAuth\n",
    )
    .ok()?;
    let openssl = |args: &[&std::ffi::OsStr]| -> bool {
        Command::new("openssl")
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    };
    let ok = openssl(&[
        "req".as_ref(),
        "-x509".as_ref(),
        "-newkey".as_ref(),
        "rsa:2048".as_ref(),
        "-nodes".as_ref(),
        "-keyout".as_ref(),
        ca_key.as_os_str(),
        "-out".as_ref(),
        ca_pem.as_os_str(),
        "-days".as_ref(),
        "1".as_ref(),
        "-subj".as_ref(),
        "/CN=billow-test-ca".as_ref(),
        "-addext".as_ref(),
        "basicConstraints=critical,CA:TRUE".as_ref(),
    ]) && openssl(&[
        "req".as_ref(),
        "-newkey".as_ref(),
        "rsa:2048".as_ref(),
        "-nodes".as_ref(),
        "-keyout".as_ref(),
        key.as_os_str(),
        "-out".as_ref(),
        csr.as_os_str(),
        "-subj".as_ref(),
        "/CN=localhost".as_ref(),
    ]) && openssl(&[
        "x509".as_ref(),
        "-req".as_ref(),
        "-in".as_ref(),
        csr.as_os_str(),
        "-CA".as_ref(),
        ca_pem.as_os_str(),
        "-CAkey".as_ref(),
        ca_key.as_os_str(),
        "-CAcreateserial".as_ref(),
        "-out".as_ref(),
        server_pem.as_os_str(),
        "-days".as_ref(),
        "1".as_ref(),
        "-extfile".as_ref(),
        ext.as_os_str(),
    ]);
    if !ok {
        let _ = std::fs::remove_dir_all(&dir);
        return None;
    }
    let pem = std::fs::read_to_string(&server_pem).ok()?;
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let der: Vec<u8> = rustls_pemfile::certs(&mut reader)
        .flatten()
        .flat_map(|cert| cert.as_ref().to_vec())
        .collect();
    if der.is_empty() {
        return None;
    }
    Some((
        Cert {
            der,
            key,
            dir,
        },
        ca_pem,
    ))
}

fn require_ca_cert(name: &str) -> (Cert, PathBuf) {
    make_ca_signed_cert(name).unwrap_or_else(|| {
        panic!("these tests need the openssl CLI to mint a private CA; without it the custom-root case is not exercised")
    })
}

fn tls_acceptor(cert: &Cert) -> TlsAcceptor {
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der.clone())],
            PrivateKeyDer::Pkcs8(
                rustls_pemfile::private_key(&mut std::io::BufReader::new(
                    std::fs::File::open(&cert.key).unwrap(),
                ))
                .unwrap()
                .map(|k| match k {
                    PrivateKeyDer::Pkcs8(k) => k,
                    _ => PrivatePkcs8KeyDer::from(Vec::new()),
                })
                .unwrap(),
            ),
        )
        .expect("server tls config");
    TlsAcceptor::from(Arc::new(config))
}

// ---------------------------------------------------------------------------
// Kernel configuration: proxies, then a rule that names the proxy.
// ---------------------------------------------------------------------------

/// Build a kernel on a free port whose only rule sends `target` host to `proxy`.
fn start_kernel(
    config_dir: &PathBuf,
    proxies: &str,
    rule_target: &str,
    limits: Limits,
) -> Result<(Kernel, String), (billow_kernel::StartError, String)> {
    let path = config_dir.join("kernel.yaml");
    let yaml = format!(
        "mixed-port: {}\nlog-level: warn\nproxies:\n{proxies}rules:\n  - 'MATCH,{rule_target}'\n",
        free_port()
    );
    std::fs::write(&path, &yaml).unwrap();
    match Kernel::start(&path, None, limits) {
        Ok((kernel, _)) => Ok((kernel, yaml)),
        Err(e) => Err((e, yaml)),
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("billow-proto-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn limits() -> Limits {
    Limits {
        half_close_timeout: Duration::from_secs(3),
        dial_timeout: Duration::from_secs(5),
        ..Limits::default()
    }
}

/// One CONNECT through the kernel's mixed inbound (SOCKS5), echo the payload.
async fn roundtrip(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut stream =
        tokio::time::timeout(Duration::from_secs(10), socks5_connect(proxy, host, port))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "kernel inbound handshake timed out",
                )
            })??;
    stream.write_all(payload).await?;
    let mut back = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut back))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tunnel payload timed out"))??;
    Ok(back)
}

async fn wait_for(value: &Arc<AtomicU64>, at_least: u64) {
    for _ in 0..200 {
        if value.load(Ordering::Relaxed) >= at_least {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "counter stayed at {} (wanted {at_least})",
        value.load(Ordering::Relaxed)
    );
}

async fn wait_for_counters<F: Fn(billow_kernel::Stats) -> bool>(kernel: &Kernel, predicate: F) {
    for _ in 0..200 {
        if predicate(kernel.stats()) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("stats never matched: {:?}", kernel.stats());
}

async fn echo_target() -> (u16, Arc<AtomicU64>) {
    let std_listener = common::bind_loopback();
    let port = std_listener.local_addr().unwrap().port();
    std_listener.set_nonblocking(true).unwrap();
    let listener = TcpListener::from_std(std_listener).unwrap();
    let bytes = Arc::new(AtomicU64::new(0));
    let counter = bytes.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            counter.fetch_add(n as u64, Ordering::Relaxed);
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (port, bytes)
}

// ---------------------------------------------------------------------------
// SOCKS5 peer (RFC 1928/1929 server side).
// ---------------------------------------------------------------------------

async fn socks5_peer(user: &str, pass: &str) -> (u16, Log) {
    let (listener, addr) = spawn_tcp().await;
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let (user, pass) = (user.to_string(), pass.to_string());
    let log_task = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let (user, pass, log) = (user.clone(), pass.clone(), log_task.clone());
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                if stream.read_exact(&mut head).await.is_err() || head[0] != 5 {
                    push(
                        &log,
                        Attempt {
                            details: vec!["not socks5".into()],
                            forwarded: false,
                        },
                    );
                    return;
                }
                let mut methods = vec![0u8; head[1] as usize];
                stream.read_exact(&mut methods).await.unwrap();
                if !methods.contains(&2) {
                    stream.write_all(&[5, 0xff]).await.unwrap();
                    push(
                        &log,
                        Attempt {
                            details: vec!["no auth method offered".into()],
                            forwarded: false,
                        },
                    );
                    return;
                }
                stream.write_all(&[5, 2]).await.unwrap();
                let mut ver = [0u8; 2];
                stream.read_exact(&mut ver).await.unwrap();
                let mut u = vec![0u8; ver[1] as usize];
                stream.read_exact(&mut u).await.unwrap();
                let mut plen = [0u8; 1];
                stream.read_exact(&mut plen).await.unwrap();
                let mut p = vec![0u8; plen[0] as usize];
                stream.read_exact(&mut p).await.unwrap();
                let ok = u == user.as_bytes() && p == pass.as_bytes();
                stream
                    .write_all(&[1, if ok { 0 } else { 1 }])
                    .await
                    .unwrap();
                if !ok {
                    push(
                        &log,
                        Attempt {
                            details: vec![format!(
                                "auth rejected user={}",
                                String::from_utf8_lossy(&u)
                            )],
                            forwarded: false,
                        },
                    );
                    return;
                }
                let mut req = [0u8; 4];
                stream.read_exact(&mut req).await.unwrap();
                let host = match req[3] {
                    1 => {
                        let mut a = [0u8; 4];
                        stream.read_exact(&mut a).await.unwrap();
                        std::net::Ipv4Addr::from(a).to_string()
                    }
                    3 => {
                        let mut l = [0u8; 1];
                        stream.read_exact(&mut l).await.unwrap();
                        let mut n = vec![0u8; l[0] as usize];
                        stream.read_exact(&mut n).await.unwrap();
                        String::from_utf8(n).unwrap()
                    }
                    other => panic!("unexpected atyp {other}"),
                };
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await.unwrap();
                let port = u16::from_be_bytes(port);
                push(
                    &log,
                    Attempt {
                        details: vec![
                            format!("auth={}", String::from_utf8_lossy(&u)),
                            format!("cmd={}", req[1]),
                            format!("target={host}:{port}"),
                        ],
                        forwarded: true,
                    },
                );
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
                let (r, w) = stream.into_split();
                let ip: std::net::IpAddr = host.parse().unwrap();
                relay_task(r, w, (ip, port).into());
            });
        }
    });
    (addr.port(), log)
}

// ---------------------------------------------------------------------------
// HTTP CONNECT peer.
// ---------------------------------------------------------------------------

async fn http_peer(user: Option<(&str, &str)>) -> (u16, Log) {
    let (listener, addr) = spawn_tcp().await;
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let expected = user.map(|(u, p)| format!("Basic {}", base64(format!("{u}:{p}").as_bytes())));
    let log_task = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let expected = expected.clone();
            let log = log_task.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let text = String::from_utf8_lossy(&head).to_string();
                let mut lines = text.split("\r\n");
                let request = lines.next().unwrap().to_string();
                let auth = lines
                    .filter_map(|l| l.split_once(':'))
                    .find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))
                    .map(|(_, v)| v.trim().to_string());
                match (&expected, &auth) {
                    (Some(want), Some(got)) if want == got => {}
                    (None, _) => {}
                    _ => {
                        stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"x\"\r\nContent-Length: 0\r\n\r\n").await.unwrap();
                        push(
                            &log,
                            Attempt {
                                details: vec![format!("407 auth={auth:?}")],
                                forwarded: false,
                            },
                        );
                        return;
                    }
                }
                let target = request.split_whitespace().nth(1).unwrap().to_string();
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .unwrap();
                push(
                    &log,
                    Attempt {
                        details: vec![
                            format!("request={request}"),
                            format!("auth-ok={}", auth.is_some()),
                        ],
                        forwarded: true,
                    },
                );
                let (r, w) = stream.into_split();
                relay_task(r, w, target.parse().unwrap());
            });
        }
    });
    (addr.port(), log)
}

fn base64(input: &[u8]) -> String {
    billow_kernel::outbound::http_pub_base64(input)
}

// ---------------------------------------------------------------------------
// Shadowsocks AEAD peer: decodes the client stream and verifies it.
// ---------------------------------------------------------------------------

async fn ss_peer(cipher: billow_kernel::proxies::SsCipher, password: &'static str) -> (u16, Log) {
    let (listener, addr) = spawn_tcp().await;
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let log_task = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let log = log_task.clone();
            let log_panic = log.clone();
            tokio::spawn(async move {
                let inner = async move {
                    // Server side: read the client's salt, then decode its
                    // chunks. The first chunk is the target address (as a
                    // Mihomo Shadowsocks server reads it), later chunks are
                    // payload. Echoed bytes travel back under a *server* salt
                    // and a separate write cipher, as SIP004 requires.
                    let key_len = cipher.key_len();
                    let mut salt = vec![0u8; key_len];
                    if stream.read_exact(&mut salt).await.is_err() {
                        return;
                    }
                    let mut decoder = ss_server_decoder(cipher, password, &salt);
                    let mut writer = SsPeerWriter::new(cipher, password);
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let mut address: Option<String> = None;
                    loop {
                        let n = match stream.read(&mut tmp).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                        match decoder.push(&mut buf) {
                            Ok(frames) => {
                                for frame in frames {
                                    if address.is_none() {
                                        address = Some(describe_socks_addr(&frame));
                                        push(
                                            &log,
                                            Attempt {
                                                details: vec![format!(
                                                    "address={}",
                                                    address.clone().unwrap()
                                                )],
                                                forwarded: true,
                                            },
                                        );
                                    } else {
                                        push(
                                            &log,
                                            Attempt {
                                                details: vec![format!(
                                                    "payload={}",
                                                    String::from_utf8_lossy(&frame)
                                                )],
                                                forwarded: true,
                                            },
                                        );
                                        if let Err(e) = writer.send(&mut stream, &frame).await {
                                            push(
                                                &log,
                                                Attempt {
                                                    details: vec![format!("echo-error={e}")],
                                                    forwarded: false,
                                                },
                                            );
                                            return;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                push(
                                    &log,
                                    Attempt {
                                        details: vec![format!("decode-error={e}")],
                                        forwarded: false,
                                    },
                                );
                                return;
                            }
                        }
                    }
                };
                if let Err(e) = tokio::spawn(inner).await {
                    push(
                        &log_panic,
                        Attempt {
                            details: vec![format!("peer-panic={e}")],
                            forwarded: false,
                        },
                    );
                }
            });
        }
    });
    (addr.port(), log)
}

/// Instance-level AEAD of the test peer, built from the public `aes-gcm` /
/// `chacha20poly1305` crates (not from the client's own type) so the peer
/// really checks the wire format.
enum TestAead {
    Aes128(aes_gcm::Aes128Gcm),
    Aes256(aes_gcm::Aes256Gcm),
    Chacha(chacha20poly1305::ChaCha20Poly1305),
}

impl TestAead {
    fn new(cipher: billow_kernel::proxies::SsCipher, key: &[u8]) -> TestAead {
        use aes_gcm::aead::KeyInit;
        match cipher {
            billow_kernel::proxies::SsCipher::Aes128Gcm => {
                TestAead::Aes128(aes_gcm::Aes128Gcm::new_from_slice(key).unwrap())
            }
            billow_kernel::proxies::SsCipher::Aes256Gcm => {
                TestAead::Aes256(aes_gcm::Aes256Gcm::new_from_slice(key).unwrap())
            }
            billow_kernel::proxies::SsCipher::Chacha20IetfPoly1305 => TestAead::Chacha(
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).unwrap(),
            ),
        }
    }

    fn seal(&self, nonce: &[u8; 12], buffer: &mut Vec<u8>) {
        use aes_gcm::aead::AeadInPlace;
        let tag = match self {
            TestAead::Aes128(c) => c.encrypt_in_place_detached(nonce.into(), &[], buffer),
            TestAead::Aes256(c) => c.encrypt_in_place_detached(nonce.into(), &[], buffer),
            TestAead::Chacha(c) => c.encrypt_in_place_detached(nonce.into(), &[], buffer),
        }
        .expect("seal");
        buffer.extend_from_slice(&tag);
    }

    fn open(&self, nonce: &[u8; 12], buffer: &mut Vec<u8>) -> Result<(), String> {
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::aead::AeadInPlace;
        if buffer.len() < 16 {
            return Err("record shorter than its tag".into());
        }
        let split = buffer.len() - 16;
        let tag = GenericArray::clone_from_slice(&buffer[split..]);
        buffer.truncate(split);
        match self {
            TestAead::Aes128(c) => c.decrypt_in_place_detached(nonce.into(), &[], buffer, &tag),
            TestAead::Aes256(c) => c.decrypt_in_place_detached(nonce.into(), &[], buffer, &tag),
            TestAead::Chacha(c) => c.decrypt_in_place_detached(nonce.into(), &[], buffer, &tag),
        }
        .map(|_| ())
        .map_err(|_| "authentication failed".to_string())
    }
}

/// Server-side AEAD writer: `salt || sealed(length) || sealed(payload)` under
/// consecutive nonces, exactly like the client's chunk layout.
struct SsPeerWriter {
    aead: TestAead,
    salt: Vec<u8>,
    nonce: [u8; 12],
    started: bool,
}

impl SsPeerWriter {
    fn new(cipher: billow_kernel::proxies::SsCipher, password: &str) -> SsPeerWriter {
        let mut salt = vec![0u8; cipher.key_len()];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
        let key = billow_kernel::keys::hkdf_sha1_with_salt(
            &salt,
            &billow_kernel::keys::evp_bytes_to_key(password.as_bytes(), cipher.key_len()),
            cipher.key_len(),
        );
        SsPeerWriter {
            aead: TestAead::new(cipher, &key),
            salt,
            nonce: [0u8; 12],
            started: false,
        }
    }

    async fn send<S: AsyncWrite + Unpin>(&mut self, stream: &mut S, payload: &[u8]) -> io::Result<()> {
        let mut out = Vec::new();
        if !self.started {
            self.started = true;
            out.extend_from_slice(&self.salt);
        }
        let mut length = (payload.len() as u16).to_be_bytes().to_vec();
        self.aead.seal(&self.nonce, &mut length);
        next_nonce(&mut self.nonce);
        out.extend_from_slice(&length);
        let mut body = payload.to_vec();
        self.aead.seal(&self.nonce, &mut body);
        next_nonce(&mut self.nonce);
        out.extend_from_slice(&body);
        stream.write_all(&out).await?;
        stream.flush().await
    }
}

/// Independent server-side AEAD decoder (counterpart of the client stream):
/// the salt and every record are opened here with the same public AEAD
/// primitives a Mihomo server uses, and a wrong password fails the tag check.
struct SsStreamDecoder {
    aead: TestAead,
    nonce: [u8; 12],
}

fn ss_server_decoder(
    cipher: billow_kernel::proxies::SsCipher,
    password: &str,
    salt: &[u8],
) -> SsStreamDecoder {
    let key = billow_kernel::keys::hkdf_sha1_with_salt(
        salt,
        &billow_kernel::keys::evp_bytes_to_key(password.as_bytes(), cipher.key_len()),
        cipher.key_len(),
    );
    SsStreamDecoder {
        aead: TestAead::new(cipher, &key),
        nonce: [0u8; 12],
    }
}

impl SsStreamDecoder {
    /// Decode every complete chunk currently buffered; consumes their bytes.
    fn push(&mut self, buf: &mut Vec<u8>) -> Result<Vec<Vec<u8>>, String> {
        const TAG: usize = 16;
        let mut out = Vec::new();
        loop {
            if buf.len() < 2 + TAG {
                return Ok(out);
            }
            let mut sealed_len = buf[..2 + TAG].to_vec();
            self.aead.open(&self.nonce, &mut sealed_len)?;
            next_nonce(&mut self.nonce);
            if sealed_len.len() != 2 {
                return Err("bad length record".into());
            }
            let size = u16::from_be_bytes([sealed_len[0], sealed_len[1]]) as usize & 0x3FFF;
            if size == 0 {
                return Err("zero-length chunk".into());
            }
            let total = 2 + TAG + size + TAG;
            if buf.len() < total {
                return Ok(out);
            }
            let mut sealed = buf[2 + TAG..total].to_vec();
            self.aead.open(&self.nonce, &mut sealed)?;
            next_nonce(&mut self.nonce);
            buf.drain(..total);
            out.push(sealed);
        }
    }
}

fn next_nonce(nonce: &mut [u8; 12]) {
    for b in nonce.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            return;
        }
    }
}

fn describe_socks_addr(frame: &[u8]) -> String {
    match frame[0] {
        1 => format!(
            "{}.{}.{}.{}:{}",
            frame[1],
            frame[2],
            frame[3],
            frame[4],
            u16::from_be_bytes([frame[5], frame[6]])
        ),
        3 => format!(
            "{}:{}",
            String::from_utf8_lossy(&frame[2..2 + frame[1] as usize]),
            u16::from_be_bytes([frame[2 + frame[1] as usize], frame[3 + frame[1] as usize]])
        ),
        other => format!("atyp{other}"),
    }
}

// ---------------------------------------------------------------------------
// Trojan peer over TLS.
// ---------------------------------------------------------------------------

async fn read_line<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        if stream.read(&mut b).await? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in line"));
        }
        line.push(b[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return Ok(line);
        }
        if line.len() > 512 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
    }
}

/// Decode the RFC 1928 address (`ATYP ADDR PORT`) of a Trojan header.
fn parse_socks_addr(raw: &[u8]) -> Option<SocketAddr> {
    let port = u16::from_be_bytes([*raw.get(raw.len() - 2)?, *raw.last()?]);
    let ip = match raw.first()? {
        0x01 => std::net::IpAddr::from(<[u8; 4]>::try_from(&raw[1..5]).ok()?),
        0x04 => std::net::IpAddr::from(<[u8; 16]>::try_from(&raw[1..17]).ok()?),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

async fn trojan_peer(cert: &Cert, password: &'static str) -> (u16, Log) {
    let acceptor = tls_acceptor(cert);
    let (listener, addr) = spawn_tcp().await;
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let log_task = log.clone();
    let expected = trojan_password_key(password);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let log = log_task.clone();
            let expected = expected.clone();
            tokio::spawn(async move {
                let mut stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        push(
                            &log,
                            Attempt {
                                details: vec![format!("tls-error={e}")],
                                forwarded: false,
                            },
                        );
                        return;
                    }
                };
                let hash = match read_line(&mut stream).await {
                    Ok(h) => h,
                    Err(e) => {
                        push(
                            &log,
                            Attempt {
                                details: vec![format!("header-error={e}")],
                                forwarded: false,
                            },
                        );
                        return;
                    }
                };
                if hash != expected {
                    push(
                        &log,
                        Attempt {
                            details: vec![format!("bad-password len={}", hash.len())],
                            forwarded: false,
                        },
                    );
                    return;
                }
                // One line carries `command` followed by the RFC 1928 address,
                // exactly as Mihomo's `trojan.WriteHeader` writes it.
                let command_line = match read_line(&mut stream).await {
                    Ok(line) => line,
                    Err(e) => {
                        push(&log, Attempt { details: vec![format!("header-error={e}")], forwarded: false });
                        return;
                    }
                };
                let Some((&command, addr_line)) = command_line.split_first() else {
                    push(&log, Attempt { details: vec!["empty command line".into()], forwarded: false });
                    return;
                };
                if command != 1 {
                    push(
                        &log,
                        Attempt {
                            details: vec!["bad cmd".into()],
                            forwarded: false,
                        },
                    );
                    return;
                }
                let target = match parse_socks_addr(addr_line) {
                    Some(target) => target,
                    None => {
                        push(&log, Attempt { details: vec![format!("address-error={addr_line:02x?}")], forwarded: false });
                        return;
                    }
                };
                push(
                    &log,
                    Attempt {
                        details: vec![
                            "password-hash-ok".to_string(),
                            format!("target={target}"),
                        ],
                        forwarded: true,
                    },
                );
                let (r, w) = tokio::io::split(stream);
                relay_task(r, w, target);
            });
        }
    });
    (addr.port(), log)
}

/// Trojan over TLS + WebSocket: upgrades, records the Host header and the
/// target, then echoes the payload frames. Covers `network: ws` for trojan,
/// which has no other test.
async fn trojan_ws_peer(cert: &Cert, password: &'static str) -> (u16, Log) {
    let acceptor = tls_acceptor(cert);
    let (listener, addr) = spawn_tcp().await;
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let log_task = log.clone();
    let expected = trojan_password_key(password);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let log = log_task.clone();
            let expected = expected.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let text = String::from_utf8_lossy(&head).to_string();
                let host = text
                    .lines()
                    .filter_map(|l| l.split_once(':'))
                    .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                    .map(|(_, v)| v.trim().to_string())
                    .unwrap_or_default();
                let key = text
                    .lines()
                    .filter_map(|l| l.split_once(':'))
                    .find(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-key"))
                    .map(|(_, v)| v.trim().to_string())
                    .unwrap_or_default();
                let accept =
                    base64(&sha1(&format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
                let response = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n");
                stream.write_all(response.as_bytes()).await.unwrap();
                push(
                    &log,
                    Attempt {
                        details: vec![format!("ws-host={host}")],
                        forwarded: true,
                    },
                );
                // The trojan header arrives as a byte stream over frames: the
                // password line, then the command and address, each CRLF-ended.
                let mut bytes = Vec::new();
                let header_end = loop {
                    if let Some(frame) = read_ws_frame(&mut stream).await {
                        bytes.extend_from_slice(&frame);
                    } else {
                        return;
                    }
                    let mut seen = 0;
                    let mut at = None;
                    for (index, window) in bytes.windows(2).enumerate() {
                        if window == b"\r\n" {
                            seen += 1;
                            if seen == 2 {
                                at = Some(index);
                                break;
                            }
                        }
                    }
                    if let Some(at) = at {
                        break at;
                    }
                    if bytes.len() > 4096 {
                        return;
                    }
                };
                let header = bytes[..header_end + 2].to_vec();
                let mut lines = header.split(|byte| *byte == b'\n').map(|line| {
                    let mut line = line.to_vec();
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    line
                });
                let hash = lines.next().unwrap_or_default();
                let command_line = lines.next().unwrap_or_default();
                if hash != expected {
                    push(
                        &log,
                        Attempt {
                            details: vec!["bad-password".into()],
                            forwarded: false,
                        },
                    );
                    return;
                }
                let Some((&command, addr_line)) = command_line.split_first() else {
                    return;
                };
                if command != 1 {
                    push(
                        &log,
                        Attempt {
                            details: vec!["bad cmd".into()],
                            forwarded: false,
                        },
                    );
                    return;
                }
                let Some(target) = parse_socks_addr(addr_line) else {
                    push(
                        &log,
                        Attempt {
                            details: vec!["address-error".into()],
                            forwarded: false,
                        },
                    );
                    return;
                };
                push(
                    &log,
                    Attempt {
                        details: vec!["password-hash-ok".into(), format!("target={target}")],
                        forwarded: true,
                    },
                );
                // Echo payload frames back (the test sends one tagged payload).
                while let Some(frame) = read_ws_frame(&mut stream).await {
                    let mut out = vec![0x82u8];
                    if frame.len() < 126 {
                        out.push(frame.len() as u8);
                    } else {
                        out.push(126);
                        out.extend_from_slice(&(frame.len() as u16).to_be_bytes());
                    }
                    out.extend_from_slice(&frame);
                    if stream.write_all(&out).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr.port(), log)
}

// ---------------------------------------------------------------------------
// VLESS peer over TLS (optionally behind a WebSocket upgrade).
// ---------------------------------------------------------------------------

/// SOCKS5 server behind TLS: answers the greeting, records the target and
/// relays to it. Used by the custom-CA case, where the certificate is signed by
/// a private authority rather than self-signed.
async fn tls_socks5_peer(cert: &Cert) -> (u16, Log) {
    let acceptor = tls_acceptor(cert);
    let (listener, addr) = spawn_tcp().await;
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let log_task = log.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let log = log_task.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    push(
                        &log,
                        Attempt {
                            details: vec!["tls-error".into()],
                            forwarded: false,
                        },
                    );
                    return;
                };
                let mut greeting = [0u8; 3];
                if stream.read_exact(&mut greeting).await.is_err() {
                    return;
                }
                stream.write_all(&[5, 0]).await.ok();
                let mut request = [0u8; 4];
                if stream.read_exact(&mut request).await.is_err() {
                    return;
                }
                let host = match request[3] {
                    0x01 => {
                        let mut v4 = [0u8; 4];
                        stream.read_exact(&mut v4).await.unwrap();
                        std::net::Ipv4Addr::from(v4).to_string()
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        stream.read_exact(&mut len).await.unwrap();
                        let mut name = vec![0u8; len[0] as usize];
                        stream.read_exact(&mut name).await.unwrap();
                        String::from_utf8_lossy(&name).to_string()
                    }
                    0x04 => {
                        let mut v6 = [0u8; 16];
                        stream.read_exact(&mut v6).await.unwrap();
                        std::net::Ipv6Addr::from(v6).to_string()
                    }
                    _ => return,
                };
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await.unwrap();
                let target = match host.parse::<std::net::IpAddr>() {
                    Ok(ip) => SocketAddr::new(ip, u16::from_be_bytes(port)),
                    Err(_) => return,
                };
                push(
                    &log,
                    Attempt {
                        details: vec![format!("target={target}")],
                        forwarded: true,
                    },
                );
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                    .await
                    .ok();
                let (r, w) = tokio::io::split(stream);
                relay_task(r, w, target);
            });
        }
    });
    (addr.port(), log)
}

/// Read one WebSocket data frame from a tunnel and return its application
/// bytes (binary or continuation opcode). `None` on close or a broken frame.
async fn read_ws_frame<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Option<Vec<u8>> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await.ok()?;
    let opcode = head[0] & 0x0f;
    if !matches!(opcode, 0x2 | 0x0) {
        return None;
    }
    let masked = head[1] & 0x80 != 0;
    let mut len = u64::from(head[1] & 0x7f);
    if len == 126 {
        let mut ext = [0u8; 2];
        stream.read_exact(&mut ext).await.ok()?;
        len = u64::from(u16::from_be_bytes(ext));
    } else if len == 127 {
        let mut ext = [0u8; 8];
        stream.read_exact(&mut ext).await.ok()?;
        len = u64::from_be_bytes(ext);
    }
    if len > 1 << 20 {
        return None;
    }
    let mut mask = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask).await.ok()?;
    }
    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload).await.ok()?;
    if masked {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
    }
    Some(payload)
}

async fn vless_peer(cert: &Cert, uuid: [u8; 16], ws_path: Option<&'static str>) -> (u16, Log) {
    let acceptor = tls_acceptor(cert);
    let (listener, addr) = spawn_tcp().await;
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let log_task = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let log = log_task.clone();
            tokio::spawn(async move {
                let mut stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        push(
                            &log,
                            Attempt {
                                details: vec![format!("tls-error={e}")],
                                forwarded: false,
                            },
                        );
                        return;
                    }
                };
                if let Some(path) = ws_path {
                    let mut head = Vec::new();
                    let mut b = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if stream.read(&mut b).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(b[0]);
                    }
                    let text = String::from_utf8_lossy(&head).to_string();
                    let request_line = text.lines().next().unwrap_or_default().to_string();
                    let key = text
                        .lines()
                        .filter_map(|l| l.split_once(':'))
                        .find(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-key"))
                        .map(|(_, v)| v.trim().to_string())
                        .unwrap_or_default();
                    let accept =
                        base64(&sha1(&format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
                    let host = text
                        .lines()
                        .filter_map(|l| l.split_once(':'))
                        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                        .map(|(_, v)| v.trim().to_string())
                        .unwrap_or_default();
                    // A key-less upgrade is the Xray HTTP upgrade: raw bytes follow.
                    let raw = key.is_empty();
                    push(
                        &log,
                        Attempt {
                            details: vec![
                                format!("ws-host={host}"),
                                format!("ws-mode={}", if raw { "raw" } else { "framed" }),
                            ],
                            forwarded: true,
                        },
                    );
                    if !request_line.starts_with(&format!("GET {path} ")) {
                        stream
                            .write_all(b"HTTP/1.1 404 Not Found\r\n\r\n")
                            .await
                            .unwrap();
                        push(
                            &log,
                            Attempt {
                                details: vec![format!("ws-path-mismatch request={request_line}")],
                                forwarded: false,
                            },
                        );
                        return;
                    }
                    let method = request_line
                        .split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_string();
                    push(
                        &log,
                        Attempt {
                            details: vec![format!("ws-upgrade={method}")],
                            forwarded: true,
                        },
                    );
                    let response = if raw {
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".to_string()
                    } else {
                        format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n")
                    };
                    stream.write_all(response.as_bytes()).await.unwrap();
                    if raw {
                        // Raw upgrade: the VLESS request follows as plain bytes.
                        match read_vless_request(&mut stream).await {
                            Ok((got_id, target, payload)) => {
                                if got_id != uuid {
                                    push(
                                        &log,
                                        Attempt {
                                            details: vec!["uuid-mismatch".into()],
                                            forwarded: false,
                                        },
                                    );
                                    return;
                                }
                                push(
                                    &log,
                                    Attempt {
                                        details: vec![
                                            "uuid-ok".into(),
                                            format!("target={}:{}", target.host, target.port),
                                            format!(
                                                "payload={}",
                                                String::from_utf8_lossy(&payload)
                                            ),
                                        ],
                                        forwarded: true,
                                    },
                                );
                                let _ = stream.write_all(&payload).await;
                                let _ = stream.shutdown().await;
                            }
                            Err(e) => push(
                                &log,
                                Attempt {
                                    details: vec![format!("vless-error={e}")],
                                    forwarded: false,
                                },
                            ),
                        }
                        return;
                    }
                    // The WebSocket transport carries a byte stream: a VLESS
                    // request may span several frames (the client sends the
                    // header and the first payload separately), so the peer
                    // reassembles frames until the header parses.
                    let mut bytes = Vec::new();
                    let (got_id, target, payload) = loop {
                        let Some(frame) = read_ws_frame(&mut stream).await else {
                            push(
                                &log,
                                Attempt {
                                    details: vec!["ws-frame-error".into()],
                                    forwarded: false,
                                },
                            );
                            return;
                        };
                        bytes.extend_from_slice(&frame);
                        match vless_parse(&bytes) {
                            Ok((id, target)) => {
                                let header_len =
                                    billow_kernel::outbound::vless::request_header(&id, &target)
                                        .len();
                                if bytes.len() >= header_len {
                                    let payload = bytes[header_len..].to_vec();
                                    if payload.is_empty() {
                                        // Wait for the first payload frame.
                                        continue;
                                    }
                                    break (id, target, payload);
                                }
                            }
                            Err(_) if bytes.len() < 1024 => continue,
                            Err(e) => {
                                push(
                                    &log,
                                    Attempt {
                                        details: vec![format!("vless-error={e}")],
                                        forwarded: false,
                                    },
                                );
                                return;
                            }
                        }
                    };
                    if got_id != uuid {
                        push(
                            &log,
                            Attempt {
                                details: vec!["uuid-mismatch".into()],
                                forwarded: false,
                            },
                        );
                        return;
                    }
                    push(
                        &log,
                        Attempt {
                            details: vec![
                                "uuid-ok".to_string(),
                                format!("target={}:{}", target.host, target.port),
                                format!("payload={}", String::from_utf8_lossy(&payload)),
                            ],
                            forwarded: true,
                        },
                    );
                    // Echo one masked-free binary frame back, like the echo target.
                    let mut out = vec![0x82u8];
                    if payload.len() < 126 {
                        out.push(payload.len() as u8);
                    } else {
                        out.push(126);
                        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                    }
                    out.extend_from_slice(&payload);
                    stream.write_all(&out).await.unwrap();
                    // A Mihomo WS handler finishes the stream with a TLS close_notify;
                    // returning here would drop the socket without one.
                    let _ = stream.shutdown().await;
                    return;
                }
                match read_vless_request(&mut stream).await {
                    Ok((got_id, target, payload)) => {
                        if got_id != uuid {
                            push(
                                &log,
                                Attempt {
                                    details: vec!["uuid-mismatch".into()],
                                    forwarded: false,
                                },
                            );
                            return;
                        }
                        push(
                            &log,
                            Attempt {
                                details: vec![
                                    "uuid-ok".to_string(),
                                    format!("target={}:{}", target.host, target.port),
                                    format!("payload={}", String::from_utf8_lossy(&payload)),
                                ],
                                forwarded: true,
                            },
                        );
                        let _ = stream.write_all(&payload).await;
                        let _ = stream.shutdown().await;
                    }
                    Err(e) => push(
                        &log,
                        Attempt {
                            details: vec![format!("vless-error={e}")],
                            forwarded: false,
                        },
                    ),
                }
            });
        }
    });
    (addr.port(), log)
}

/// Read exactly the VLESS header (length depends on the address type) and any
/// payload that follows, then parse it with the shared client parser.
async fn read_vless_request<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> io::Result<([u8; 16], billow_kernel::outbound::Target, Vec<u8>)> {
    let mut header = vec![0u8; 19];
    stream.read_exact(&mut header).await?;
    let addon = header[17] as usize;
    let mut addons = vec![0u8; addon];
    if addon > 0 {
        stream.read_exact(&mut addons).await?;
    }
    let mut rest = [0u8; 3];
    stream.read_exact(&mut rest).await?; // port (2) + atyp (1)
    let port_bytes = [rest[0], rest[1]];
    let mut addr = vec![rest[2]];
    match rest[2] {
        1 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            addr.extend_from_slice(&a);
        }
        2 | 3 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            let mut name = vec![0u8; l[0] as usize];
            stream.read_exact(&mut name).await?;
            addr.push(l[0]);
            addr.extend_from_slice(&name);
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("atyp {other}"),
            ))
        }
    }
    let mut full = header.clone();
    full.extend_from_slice(&port_bytes);
    full.extend_from_slice(&addr);
    let (id, target) = vless_parse(&full)?;
    let mut payload = Vec::new();
    let mut chunk = [0u8; 256];
    let n = stream.read(&mut chunk).await.unwrap_or(0);
    payload.extend_from_slice(&chunk[..n]);
    Ok((id, target, payload))
}

fn sha1(input: &str) -> Vec<u8> {
    // ring exposes SHA-1, avoiding a separate sha1 dependency in tests.
    ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, input.as_bytes())
        .as_ref()
        .to_vec()
}

// ---------------------------------------------------------------------------
// Tests: SOCKS5
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_outbound_with_username_password_reaches_the_target() {
    let (peer_port, log) = socks5_peer("alice", "s3cret").await;
    let (target_port, received) = echo_target().await;
    let dir = scratch("socks5");
    let (mut kernel, yaml) = start_kernel(
        &dir,
        &format!("  - {{name: s5, type: socks5, server: 127.0.0.1, port: {peer_port}, username: alice, password: s3cret}}\n"),
        "s5",
        limits(),
    )
    .unwrap_or_else(|(e, _)| panic!("kernel start: {e}"));
    let proxy = kernel.listen_addr();
    let payload = b"tagged-socks5-payload";
    let back = roundtrip(proxy, "127.0.0.1", target_port, payload)
        .await
        .expect("roundtrip");
    assert_eq!(back, payload);
    // Stats settle when the session task returns, slightly after the client got its reply.
    wait_for_counters(&kernel, |s| s.completed == 1).await;
    wait_for(&received, payload.len() as u64).await;
    let details = detail(&log);
    assert!(details.contains(&"auth=alice".to_string()), "{details:?}");
    assert!(
        details.contains(&format!("target=127.0.0.1:{target_port}")),
        "{details:?}"
    );
    assert!(yaml.contains("type: socks5"));
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_outbound_wrong_password_fails_without_reaching_the_target() {
    let (peer_port, log) = socks5_peer("alice", "s3cret").await;
    let (target_port, received) = echo_target().await;
    let dir = scratch("socks5-bad");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!("  - {{name: s5, type: socks5, server: 127.0.0.1, port: {peer_port}, username: alice, password: wrong}}\n"),
        "s5",
        limits(),
    )
    .unwrap();
    let proxy = kernel.listen_addr();
    let err = roundtrip(proxy, "127.0.0.1", target_port, b"x")
        .await
        .expect_err("must fail");
    assert!(err.to_string().contains("socks reply"), "{err}");
    assert_eq!(received.load(Ordering::Relaxed), 0);
    assert_eq!(forwarded_count(&log), 0);
    assert!(kernel.stats().failed >= 1);
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_and_http_outbounds_over_tls_verify_the_peer_certificate() {
    let cert = require_cert("socks-http");
    // A TLS server that answers the SOCKS5 greeting.
    let acceptor = tls_acceptor(&cert);
    let (listener, addr) = spawn_tcp().await;
    let (target_port, received) = echo_target().await;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut greeting = [0u8; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                stream.write_all(&[5, 0]).await.unwrap();
                let mut req = [0u8; 10];
                stream.read_exact(&mut req).await.unwrap();
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
                let mut payload = [0u8; 64];
                let n = stream.read(&mut payload).await.unwrap();
                let _ = stream.write_all(&payload[..n]).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    // Without trust: the self-signed certificate fails verification. The
    // kernel reports failure with the SOCKS5 reply (0x01) before replying
    // success, so the client must be refused, not handed a tunnel.
    let dir = scratch("socks-tls-untrusted");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!(
            "  - {{name: s5, type: socks5, server: 127.0.0.1, port: {}, tls: true}}\n",
            addr.port()
        ),
        "s5",
        limits(),
    )
    .unwrap();
    let proxy = kernel.listen_addr();
    let err = roundtrip(proxy, "127.0.0.1", target_port, b"hello")
        .await
        .expect_err("untrusted TLS must fail");
    assert!(
        err.to_string().contains("socks reply") || err.to_string().contains("handshake"),
        "{err}"
    );
    kernel.stop().unwrap();

    // With `skip-cert-verify` the tunnel works (the kernel's TLS client accepts any cert).
    let dir = scratch("socks-tls-trusted");
    let peer_yaml = format!("  - {{name: s5, type: socks5, server: 127.0.0.1, port: {}, tls: true, sni: localhost, skip-cert-verify: true}}\n", addr.port());
    let (mut kernel, _) = start_kernel(&dir, &peer_yaml, "s5", limits()).unwrap();
    let proxy = kernel.listen_addr();
    let back = roundtrip(proxy, "127.0.0.1", target_port, b"hello")
        .await
        .expect("skip-cert-verify tunnel");
    assert_eq!(back, b"hello");
    kernel.stop().unwrap();
    assert_eq!(
        received.load(Ordering::Relaxed),
        0,
        "the TLS peer answers itself; the echo is not reached"
    );
}

// ---------------------------------------------------------------------------
// HTTP CONNECT
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_connect_outbound_with_basic_auth() {
    let (peer_port, log) = http_peer(Some(("bob", "hunter2"))).await;
    let (target_port, received) = echo_target().await;
    let dir = scratch("http");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!("  - {{name: hp, type: http, server: 127.0.0.1, port: {peer_port}, username: bob, password: hunter2}}\n"),
        "hp",
        limits(),
    )
    .unwrap();
    let (mut stream, status) =
        http_connect(kernel.listen_addr(), &format!("127.0.0.1:{target_port}"))
            .await
            .unwrap();
    assert_eq!(status, "HTTP/1.1 200 Connection Established");
    stream.write_all(b"tagged-http-payload").await.unwrap();
    let mut back = vec![0u8; b"tagged-http-payload".len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut back))
        .await
        .expect("reply")
        .unwrap();
    assert_eq!(back, b"tagged-http-payload".to_vec(), "reply bytes");
    // The peer relays to the target: the echo saw the tag once the relay opened.
    wait_for(&received, 18).await;
    let details = detail(&log);
    assert!(
        details
            .iter()
            .any(|d| d == &format!("request=CONNECT 127.0.0.1:{target_port} HTTP/1.1")),
        "{details:?}"
    );
    assert!(details.contains(&"auth-ok=true".to_string()), "{details:?}");
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_connect_outbound_wrong_password_is_refused() {
    let (peer_port, log) = http_peer(Some(("bob", "hunter2"))).await;
    let (target_port, received) = echo_target().await;
    let dir = scratch("http-bad");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!("  - {{name: hp, type: http, server: 127.0.0.1, port: {peer_port}, username: bob, password: nope}}\n"),
        "hp",
        limits(),
    )
    .unwrap();
    let (_, status) = http_connect(kernel.listen_addr(), &format!("127.0.0.1:{target_port}"))
        .await
        .unwrap();
    assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
    assert_eq!(received.load(Ordering::Relaxed), 0);
    assert!(
        wait_detail_prefix(&log, "407").await,
        "{:?}",
        detail(&log)
    );
    kernel.stop().unwrap();
}

// ---------------------------------------------------------------------------
// Shadowsocks AEAD (the two additional ciphers use the same frames; the peer
// decodes each one, so a wrong key size or cipher is caught).
// ---------------------------------------------------------------------------

async fn ss_case(cipher: billow_kernel::proxies::SsCipher) {
    let (peer_port, log) = ss_peer(cipher, "ss-password").await;
    let (target_port, _) = echo_target().await;
    let dir = scratch(&format!("ss-{}", cipher.as_str()));
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!("  - {{name: ss1, type: ss, server: 127.0.0.1, port: {peer_port}, cipher: {}, password: ss-password}}\n", cipher.as_str()),
        "ss1",
        limits(),
    )
    .unwrap();
    let payload = format!("tagged-{}", cipher.as_str());
    // The fake peer echoes the decoded frame back (not routed), so this proves
    // both directions' frame layout and the auth of the client's frames.
    let back = roundtrip(
        kernel.listen_addr(),
        "127.0.0.1",
        target_port,
        payload.as_bytes(),
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "roundtrip {e}; peer log {:?}; kernel {:?}",
            detail(&log),
            kernel.stats()
        )
    });
    assert_eq!(String::from_utf8_lossy(&back), payload);
    let details = detail(&log);
    assert!(
        details
            .iter()
            .any(|d| d == &format!("address=127.0.0.1:{target_port}")),
        "{details:?}"
    );
    assert!(
        details.iter().any(|d| d == &format!("payload={payload}")),
        "{details:?}"
    );
    assert!(
        details.iter().all(|d| !d.starts_with("decode-error")),
        "{details:?}"
    );
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadowsocks_aes_256_gcm_roundtrip() {
    ss_case(billow_kernel::proxies::SsCipher::Aes256Gcm).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadowsocks_chacha20_ietf_poly1305_roundtrip() {
    ss_case(billow_kernel::proxies::SsCipher::Chacha20IetfPoly1305).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadowsocks_aes_128_gcm_wrong_password_fails_authentication() {
    let (peer_port, log) = ss_peer(
        billow_kernel::proxies::SsCipher::Aes128Gcm,
        "right-password",
    )
    .await;
    let (target_port, received) = echo_target().await;
    let dir = scratch("ss-bad");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!("  - {{name: ss1, type: ss, server: 127.0.0.1, port: {peer_port}, cipher: aes-128-gcm, password: wrong-password}}\n"),
        "ss1",
        limits(),
    )
    .unwrap();
    let err = roundtrip(kernel.listen_addr(), "127.0.0.1", target_port, b"secret")
        .await
        .expect_err("must fail");
    // The server drops the undecodable frame; the AEAD client cannot learn the
    // reason, so it observes the tunnel closing before its payload returns.
    assert!(!err.to_string().is_empty());
    let details = detail(&log);
    assert!(
        details.iter().any(|d| d.starts_with("decode-error")),
        "{details:?}"
    );
    assert_eq!(
        received.load(Ordering::Relaxed),
        0,
        "the receiving side saw bytes of a rejected session; peer log {details:?}"
    );
    // The session ends (completed or failed); nothing stays active.
    wait_for_counters(&kernel, |stats| stats.active == 0).await;
    kernel.stop().unwrap();
}

#[test]
fn shadowsocks_udp_datagram_roundtrip_and_tamper_detection() {
    let codec = SsDatagram {
        cipher: billow_kernel::proxies::SsCipher::Aes256Gcm,
        password: "udp-password".to_string(),
    };
    let plaintext = billow_kernel::outbound::shadowsocks::datagram_plaintext(
        &[1, 127, 0, 0, 1, 0, 53],
        b"dns-query",
    );
    let packet = codec.encode(&plaintext);
    assert_eq!(codec.decode(&packet).unwrap(), plaintext);
    let wrong = SsDatagram {
        cipher: billow_kernel::proxies::SsCipher::Aes256Gcm,
        password: "other".to_string(),
    };
    assert!(wrong.decode(&packet).is_err());
    let mut flipped = packet.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert!(codec.decode(&flipped).is_err());
}

// ---------------------------------------------------------------------------
// Trojan over TLS.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_outbound_over_tls_sends_hash_command_address_and_payload() {
    let cert = require_cert("trojan");
    let (peer_port, log) = trojan_peer(&cert, "trojan-pw").await;
    let (target_port, received) = echo_target().await;
    let dir = scratch("trojan");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!("  - {{name: tj, type: trojan, server: 127.0.0.1, port: {peer_port}, password: trojan-pw, sni: localhost, skip-cert-verify: true}}\n"),
        "tj",
        limits(),
    )
    .unwrap();
    let back = roundtrip(
        kernel.listen_addr(),
        "127.0.0.1",
        target_port,
        b"tagged-trojan",
    )
    .await
    .unwrap_or_else(|e| panic!("roundtrip {e}; peer log {:?}", detail(&log)));
    assert_eq!(back, b"tagged-trojan");
    let details = detail(&log);
    assert!(
        details.contains(&"password-hash-ok".to_string()),
        "{details:?}"
    );
    assert!(
        details
            .iter()
            .any(|d| d == &format!("target=127.0.0.1:{target_port}")),
        "{details:?}"
    );
    assert!(received.load(Ordering::Relaxed) > 0);
    kernel.stop().unwrap();
}


#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_over_websocket_tunnels_with_a_host_override() {
    let cert = require_cert("trojan-ws");
    let (peer_port, log) = trojan_ws_peer(&cert, "trojan-ws-pw").await;
    let (target_port, _) = echo_target().await;
    let dir = scratch("trojan-ws");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!("  - {{name: tjw, type: trojan, server: 127.0.0.1, port: {peer_port}, password: trojan-ws-pw, sni: localhost, skip-cert-verify: true, network: ws, ws-opts: {{path: /tj, headers: {{Host: front.example}}}}}}\n"),
        "tjw",
        limits(),
    )
    .unwrap();
    let back = roundtrip(kernel.listen_addr(), "127.0.0.1", target_port, b"trojan-ws-payload")
        .await
        .expect("trojan ws roundtrip");
    assert_eq!(back, b"trojan-ws-payload");
    let details = detail(&log);
    assert!(details.contains(&"ws-host=front.example".to_string()), "{details:?}");
    assert!(details.contains(&"password-hash-ok".to_string()), "{details:?}");
    assert!(
        details.contains(&format!("target=127.0.0.1:{target_port}")),
        "{details:?}"
    );
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_wrong_password_is_rejected() {
    let cert = require_cert("trojan-bad");
    let (peer_port, log) = trojan_peer(&cert, "trojan-pw").await;
    let (target_port, received) = echo_target().await;
    let dir = scratch("trojan-bad");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!("  - {{name: tj, type: trojan, server: 127.0.0.1, port: {peer_port}, password: wrong, skip-cert-verify: true}}\n"),
        "tj",
        limits(),
    )
    .unwrap();
    assert!(
        roundtrip(kernel.listen_addr(), "127.0.0.1", target_port, b"x")
            .await
            .is_err()
    );
    assert_eq!(received.load(Ordering::Relaxed), 0);
    assert!(
        detail(&log).iter().any(|d| d.starts_with("bad-password")),
        "{:?}",
        detail(&log)
    );
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_without_skip_cert_verify_fails_on_an_untrusted_certificate() {
    let cert = require_cert("trojan-untrusted");
    let (peer_port, log) = trojan_peer(&cert, "trojan-pw").await;
    let (target_port, _) = echo_target().await;
    let dir = scratch("trojan-untrusted");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!("  - {{name: tj, type: trojan, server: 127.0.0.1, port: {peer_port}, password: trojan-pw}}\n"),
        "tj",
        limits(),
    )
    .unwrap();
    assert!(
        roundtrip(kernel.listen_addr(), "127.0.0.1", target_port, b"x")
            .await
            .is_err()
    );
    assert!(
        detail(&log).iter().any(|d| d.starts_with("tls-error")),
        "{:?}",
        detail(&log)
    );
    kernel.stop().unwrap();
}

// ---------------------------------------------------------------------------
// VLESS over TLS, with and without WebSocket.
// ---------------------------------------------------------------------------

const VLESS_UUID: [u8; 16] = [
    0x9d, 0x0c, 0xb9, 0xd0, 0x96, 0x4f, 0x4e, 0xf6, 0x89, 0x7d, 0x6c, 0x6b, 0x3c, 0xcf, 0x9e, 0x68,
];

/// The same UUID in the textual form a configuration uses.
const VLESS_UUID_TEXT: &str = "9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vless_over_tls_sends_uuid_target_and_payload() {
    let cert = require_cert("vless");
    let (peer_port, log) = vless_peer(&cert, VLESS_UUID, None).await;
    let (target_port, _) = echo_target().await;
    let dir = scratch("vless");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!("  - {{name: vl, type: vless, server: 127.0.0.1, port: {peer_port}, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true, skip-cert-verify: true}}\n"),
        "vl",
        limits(),
    )
    .unwrap();
    let back = roundtrip(
        kernel.listen_addr(),
        "127.0.0.1",
        target_port,
        b"tagged-vless",
    )
    .await
    .expect("roundtrip");
    assert_eq!(back, b"tagged-vless");
    let details = detail(&log);
    assert!(details.contains(&"uuid-ok".to_string()), "{details:?}");
    assert!(
        details
            .iter()
            .any(|d| d == &format!("target=127.0.0.1:{target_port}")),
        "{details:?}"
    );
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vless_over_tls_and_websocket_tunnels_the_header_frame() {
    let cert = require_cert("vless-ws");
    let (peer_port, log) = vless_peer(&cert, VLESS_UUID, Some("/vless-ws")).await;
    let (target_port, _) = echo_target().await;
    let dir = scratch("vless-ws");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!("  - {{name: vlw, type: vless, server: 127.0.0.1, port: {peer_port}, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true, skip-cert-verify: true, network: ws, ws-opts: {{path: /vless-ws}}}}\n"),
        "vlw",
        limits(),
    )
    .unwrap();
    let (mut stream, status) =
        http_connect(kernel.listen_addr(), &format!("127.0.0.1:{target_port}"))
            .await
            .unwrap();
    assert_eq!(status, "HTTP/1.1 200 Connection Established");
    stream.write_all(b"ws-payload").await.unwrap();
    let mut back = vec![0u8; b"ws-payload".len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut back))
        .await
        .expect("ws reply")
        .unwrap();
    assert_eq!(&back, b"ws-payload");
    let details = detail(&log);
    assert!(
        details.contains(&"ws-upgrade=GET".to_string()),
        "{details:?}"
    );
    assert!(details.contains(&"uuid-ok".to_string()), "{details:?}");
    kernel.stop().unwrap();
}

/// `ws-opts.headers: {Host: ...}` overrides the upgrade request's Host while
/// the tunnel still carries the VLESS request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vless_over_websocket_honours_the_host_header_override() {
    let cert = require_cert("vless-ws-host");
    let (peer_port, log) = vless_peer(&cert, VLESS_UUID, Some("/vless-ws")).await;
    let (target_port, _) = echo_target().await;
    let dir = scratch("vless-ws-host");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!("  - {{name: vlw, type: vless, server: 127.0.0.1, port: {peer_port}, uuid: {VLESS_UUID_TEXT}, tls: true, skip-cert-verify: true, network: ws, ws-opts: {{path: /vless-ws, headers: {{Host: cdn.example}}}}}}\n"),
        "vlw",
        limits(),
    )
    .unwrap();
    let back = roundtrip(kernel.listen_addr(), "127.0.0.1", target_port, b"host-override")
        .await
        .expect("roundtrip");
    assert_eq!(back, b"host-override");
    let details = detail(&log);
    assert!(details.contains(&"ws-host=cdn.example".to_string()), "{details:?}");
    assert!(details.contains(&"ws-mode=framed".to_string()), "{details:?}");
    kernel.stop().unwrap();
}

/// `ws-opts.v2ray-http-upgrade: true` sends a key-less upgrade and then uses
/// the stream as raw bytes (no WebSocket framing).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vless_over_v2ray_http_upgrade_tunnels_raw_bytes() {
    let cert = require_cert("vless-ws-raw");
    let (peer_port, log) = vless_peer(&cert, VLESS_UUID, Some("/vless-raw")).await;
    let (target_port, _) = echo_target().await;
    let dir = scratch("vless-ws-raw");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!("  - {{name: vlw, type: vless, server: 127.0.0.1, port: {peer_port}, uuid: {VLESS_UUID_TEXT}, tls: true, skip-cert-verify: true, network: ws, ws-opts: {{path: /vless-raw, v2ray-http-upgrade: true}}}}\n"),
        "vlw",
        limits(),
    )
    .unwrap();
    let back = roundtrip(kernel.listen_addr(), "127.0.0.1", target_port, b"raw-upgrade")
        .await
        .expect("roundtrip");
    assert_eq!(back, b"raw-upgrade");
    let details = detail(&log);
    assert!(details.contains(&"ws-mode=raw".to_string()), "{details:?}");
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vless_wrong_uuid_is_rejected_by_the_peer() {
    let cert = require_cert("vless-bad");
    let (peer_port, log) = vless_peer(&cert, VLESS_UUID, None).await;
    let (target_port, received) = echo_target().await;
    let dir = scratch("vless-bad");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!("  - {{name: vl, type: vless, server: 127.0.0.1, port: {peer_port}, uuid: 00000000-0000-0000-0000-000000000001, tls: true, skip-cert-verify: true}}\n"),
        "vl",
        limits(),
    )
    .unwrap();
    assert!(
        roundtrip(kernel.listen_addr(), "127.0.0.1", target_port, b"x")
            .await
            .is_err()
    );
    assert_eq!(received.load(Ordering::Relaxed), 0);
    assert!(detail(&log).contains(&"uuid-mismatch".to_string()));
    kernel.stop().unwrap();
}

// ---------------------------------------------------------------------------
// Cross-cutting: inbound authentication, protocol mismatch, embedded API.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_authentication_guards_socks5_and_http_connect() {
    let (target_port, _) = echo_target().await;
    let dir = scratch("inbound-auth");
    let path = dir.join("auth.yaml");
    std::fs::write(
        &path,
        format!(
            "mixed-port: {}\nallow-lan: false\nlog-level: warn\nauthentication: [\"alice:secret\"]\nrules:\n  - 'MATCH,DIRECT'\n",
            free_port()
        ),
    )
    .unwrap();
    let loaded = load_config(
        &std::fs::read_to_string(&path).unwrap(),
        &path.display().to_string(),
    )
    .unwrap();
    assert_eq!(loaded.config.inbound_users.len(), 1);
    let (mut kernel, _) = Kernel::start(&path, None, limits()).unwrap();
    let proxy = kernel.listen_addr();
    // No credentials: the SOCKS5 server selects user/pass and the bare client is refused.
    let client = TcpStream::connect(proxy).await.unwrap();
    client.writable().await.unwrap();
    // Authorized through the SOCKS5 username/password exchange.
    let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 2, 0, 2]).await.unwrap();
    let mut sel = [0u8; 2];
    stream.read_exact(&mut sel).await.unwrap();
    assert_eq!(sel, [5, 2]);
    stream
        .write_all(&[
            1, 5, b'a', b'l', b'i', b'c', b'e', 6, b's', b'e', b'c', b'r', b'e', b't',
        ])
        .await
        .unwrap();
    let mut ok = [0u8; 2];
    stream.read_exact(&mut ok).await.unwrap();
    assert_eq!(ok, [1, 0]);
    let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    stream.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0);
    stream.write_all(b"authed").await.unwrap();
    let mut back = [0u8; 6];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"authed");
    // Wrong password.
    let mut bad = TcpStream::connect(proxy).await.unwrap();
    bad.write_all(&[5, 1, 2]).await.unwrap();
    let mut sel = [0u8; 2];
    bad.read_exact(&mut sel).await.unwrap();
    assert_eq!(sel, [5, 2]);
    bad.write_all(&[1, 5, b'a', b'l', b'i', b'c', b'e', 3, b'b', b'a', b'd'])
        .await
        .unwrap();
    let mut ok = [0u8; 2];
    bad.read_exact(&mut ok).await.unwrap();
    assert_eq!(ok, [1, 1]);
    // HTTP CONNECT without Proxy-Authorization gets 407.
    let (_, status) = http_connect(proxy, &format!("127.0.0.1:{target_port}"))
        .await
        .unwrap();
    assert_eq!(status, "HTTP/1.1 407 Proxy Authentication Required");
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_mismatch_reports_a_failed_session() {
    // The rule selects an HTTP proxy but the peer answers with the SOCKS5
    // greeting: the handshake fails, the client gets 502 and nothing is forwarded.
    let (listener, addr) = spawn_tcp().await;
    let served = Arc::new(AtomicU64::new(0));
    let counter = served.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::Relaxed);
            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        }
    });
    let (target_port, received) = echo_target().await;
    let dir = scratch("mismatch");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!(
            "  - {{name: hp, type: http, server: 127.0.0.1, port: {}}}\n",
            addr.port()
        ),
        "hp",
        limits(),
    )
    .unwrap();
    let (_, status) = http_connect(kernel.listen_addr(), &format!("127.0.0.1:{target_port}"))
        .await
        .unwrap();
    assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
    assert_eq!(served.load(Ordering::Relaxed), 1);
    assert_eq!(received.load(Ordering::Relaxed), 0);
    assert_eq!(kernel.stats().failed, 1);
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_api_selects_the_rule_proxy() {
    let (target_port, _) = echo_target().await;
    let yaml = format!(
        "mixed-port: 0\nlog-level: warn\nproxies:\n  - {{name: tj, type: trojan, server: 192.0.2.10, port: 443, password: pw}}\nrules:\n  - 'DOMAIN-SUFFIX,corp.example,tj'\n  - 'MATCH,DIRECT'\n"
    );
    // Port 0 is the CLI's concern; the library binds the configured address, so pick one.
    let yaml = yaml.replace("mixed-port: 0", &format!("mixed-port: {}", free_port()));
    let (mut kernel, _) = Kernel::start_from_yaml(&yaml, None, Limits::default()).unwrap();
    let (action, label) = kernel.evaluate("a.corp.example", None);
    assert_eq!(action, billow_kernel::Action::Proxy(0));
    assert_eq!(label, "DOMAIN-SUFFIX,corp.example -> tj");
    let (action, _) = kernel.evaluate("127.0.0.1", None);
    assert_eq!(action, billow_kernel::Action::Direct);
    assert!(kernel.identity().features.contains("protocols=tj=trojan"));
    // The rule routes the tagged host to the unreachable trojan server: the session fails.
    let err = roundtrip(kernel.listen_addr(), "a.corp.example", target_port, b"x")
        .await
        .expect_err("unreachable trojan");
    assert!(!err.to_string().is_empty());
    kernel.stop().unwrap();
}

/// The embedding entry point (`Kernel::start_from_yaml`, the path the iOS
/// extension host and `examples/embed.rs` use) carries a protocol outbound,
/// not only the process entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_api_tunnels_through_a_protocol_outbound() {
    let (peer_port, _log) = socks5_peer("alice", "secret").await;
    let (target_port, received) = echo_target().await;
    let yaml = format!(
        "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: s, type: socks5, server: 127.0.0.1, port: {peer_port}, username: alice, password: secret}}\nrules:\n  - 'MATCH,s'\n",
        free_port()
    );
    let (mut kernel, _) = Kernel::start_from_yaml(&yaml, None, limits()).unwrap();
    let back = roundtrip(kernel.listen_addr(), "127.0.0.1", target_port, b"embedded")
        .await
        .expect("embedded roundtrip");
    assert_eq!(back, b"embedded");
    assert!(received.load(Ordering::Relaxed) > 0);
    assert!(kernel.identity().features.contains("protocols=s=socks5"));
    kernel.stop().unwrap();
}


/// The library entry point carries the T11 families: a host that embeds the
/// kernel (the iOS extension, `examples/embed.rs`) can load and dial them
/// without the CLI. The tunnel runs through the controlled gost-relay peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_api_loads_and_dials_the_t11_outbounds() {
    let (peer_port, _log) = gost_peer(GostMode::default(), None).await;
    let (target_port, received) = echo_target().await;
    let yaml = format!(
        "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: gr, type: gost-relay, server: 127.0.0.1, port: {peer_port}}}\n  - {{name: sh, type: ssh, server: 127.0.0.1, port: {peer_port}, username: u, password: p}}\n  - {{name: sr, type: ssr, server: 127.0.0.1, port: {peer_port}, cipher: aes-256-cfb, password: p, protocol: origin, obfs: plain}}\nrules:\n  - 'MATCH,gr'\n",
        free_port()
    );
    let (mut kernel, _) = Kernel::start_from_yaml(&yaml, None, limits()).unwrap();
    let features = kernel.identity().features.clone();
    assert!(features.contains("gr=gost-relay"), "{features}");
    assert!(features.contains("sh=ssh"), "{features}");
    assert!(features.contains("sr=ssr"), "{features}");
    let back = roundtrip(kernel.listen_addr(), "127.0.0.1", target_port, b"embedded-t11")
        .await
        .expect("embedded gost-relay roundtrip");
    assert_eq!(back, b"embedded-t11");
    wait_for(&received, 12).await;
    kernel.stop().unwrap();
}

/// The configuration's own trust anchors (`tls.custom-cert`) are installed for
/// every outbound TLS dial: the same private-CA peer succeeds when the CA is
/// configured and fails when it is not. Runs in one process, so it also proves
/// the anchors are per kernel rather than a process-wide singleton.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_ca_roots_are_installed_for_outbound_tls() {
    let (cert, ca) = require_ca_cert("ca-roots");
    let (target_port, _) = echo_target().await;
    let (tj_port, _) = trojan_peer(&cert, "trojan-pw").await;
    let (vl_port, _) = vless_peer(&cert, VLESS_UUID, None).await;
    let (s5_port, _) = tls_socks5_peer(&cert).await;
    let cases = [
        (
            "trojan",
            format!("  - {{name: p, type: trojan, server: 127.0.0.1, port: {tj_port}, password: trojan-pw, sni: localhost}}\n"),
        ),
        (
            "vless",
            format!("  - {{name: p, type: vless, server: 127.0.0.1, port: {vl_port}, uuid: {VLESS_UUID_TEXT}, tls: true, sni: localhost}}\n"),
        ),
        (
            "socks5-tls",
            format!("  - {{name: p, type: socks5, server: 127.0.0.1, port: {s5_port}, tls: true, sni: localhost}}\n"),
        ),
    ];
    for (label, proxy) in cases {
        // Without the CA: verification must fail before any tunnel is used.
        let dir = scratch(&format!("ca-none-{label}"));
        let (mut kernel, _) = start_kernel(&dir, &proxy, "p", limits())
            .unwrap_or_else(|(e, _)| panic!("{label}: kernel start: {e}"));
        let err = roundtrip(kernel.listen_addr(), "127.0.0.1", target_port, b"x")
            .await
            .expect_err("an untrusted private CA must fail");
        assert!(
            !err.to_string().is_empty(),
            "{label}: expected a handshake failure"
        );
        kernel.stop().unwrap();

        // With `tls: {custom-cert: [<ca>]}` the same peer is trusted.
        let dir = scratch(&format!("ca-installed-{label}"));
        let path = dir.join("kernel.yaml");
        std::fs::write(
            &path,
            format!(
                "mixed-port: {}\nlog-level: warn\ntls:\n  custom-cert: [{}]\nproxies:\n{proxy}rules:\n  - 'MATCH,p'\n",
                free_port(),
                ca.display()
            ),
        )
        .unwrap();
        let (mut kernel, _) = Kernel::start(&path, None, limits())
            .unwrap_or_else(|e| panic!("{label}: kernel start with custom CA: {e}"));
        let payload = format!("ca-tagged-{label}");
        let back = roundtrip(
            kernel.listen_addr(),
            "127.0.0.1",
            target_port,
            payload.as_bytes(),
        )
        .await
        .unwrap_or_else(|e| panic!("{label}: custom CA tunnel: {e}"));
        assert_eq!(back, payload.as_bytes());
        kernel.stop().unwrap();
    }
}


// ---------------------------------------------------------------------------
// UDP: the mixed inbound's SOCKS5 UDP ASSOCIATE and the ss datagram path.
// ---------------------------------------------------------------------------

/// Independent ss UDP server: decodes `salt || sealed(addr || payload)` with
/// `TestAead`, forwards the payload to `echo_port` and returns the echo under
/// the peer's own salt. Records what it decoded.
async fn ss_udp_peer(
    cipher: billow_kernel::proxies::SsCipher,
    password: &'static str,
    echo_port: u16,
) -> (u16, Log) {
    ss_udp_peer_bound("127.0.0.1:0", cipher, password, echo_port).await
}

async fn ss_udp_peer_bound(
    bind: &'static str,
    cipher: billow_kernel::proxies::SsCipher,
    password: &'static str,
    echo_port: u16,
) -> (u16, Log) {
    let server = tokio::net::UdpSocket::bind(bind).await.unwrap();
    let server_port = server.local_addr().unwrap().port();
    common::reserve_port(server_port);
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let log_task = log.clone();
    tokio::spawn(async move {
        let log = log_task;
        let mut buffer = vec![0u8; 65535];
        loop {
            let Ok((read, from)) = server.recv_from(&mut buffer).await else {
                return;
            };
            let salt_len = cipher.key_len();
            if read <= salt_len {
                continue;
            }
            let key = billow_kernel::keys::hkdf_sha1_with_salt(
                &buffer[..salt_len],
                &billow_kernel::keys::evp_bytes_to_key(password.as_bytes(), 32),
                32,
            );
            let aead = TestAead::new(cipher, &key);
            let mut body = buffer[salt_len..read].to_vec();
            if aead.open(&[0u8; 12], &mut body).is_err() {
                push(
                    &log,
                    Attempt {
                        details: vec!["decode-error".into()],
                        forwarded: false,
                    },
                );
                continue;
            }
            let Some((target, header)) = billow_kernel::outbound::udp::parse_address(&body, 0)
            else {
                continue;
            };
            let payload = body[header..].to_vec();
            push(
                &log,
                Attempt {
                    details: vec![
                        format!("target={}:{}", target.host, target.port),
                        format!("payload={}", String::from_utf8_lossy(&payload)),
                    ],
                    forwarded: true,
                },
            );
            let reply_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let _ = reply_socket
                .send_to(&payload, ("127.0.0.1", echo_port))
                .await;
            let mut echo_reply = vec![0u8; 4096];
            let Ok((n, _)) = reply_socket.recv_from(&mut echo_reply).await else {
                continue;
            };
            let mut reply = billow_kernel::outbound::udp::address_header(&target);
            reply.extend_from_slice(&echo_reply[..n]);
            let mut salt = vec![0u8; salt_len];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
            let key = billow_kernel::keys::hkdf_sha1_with_salt(
                &salt,
                &billow_kernel::keys::evp_bytes_to_key(password.as_bytes(), 32),
                32,
            );
            let aead = TestAead::new(cipher, &key);
            let mut sealed = reply;
            aead.seal(&[0u8; 12], &mut sealed);
            let mut packet = salt;
            packet.extend_from_slice(&sealed);
            let _ = server.send_to(&packet, from).await;
        }
    });
    (server_port, log)
}

/// A SOCKS5 server that really serves `UDP ASSOCIATE`: the control connection
/// answers with a relay socket, and every datagram is decoded to its target,
/// forwarded, and the reply wrapped back. It records the targets it relayed to,
/// which is how a chained test proves the hop was used.
async fn socks5_udp_peer() -> (u16, Log) {
    socks5_udp_peer_with(None, None).await
}

/// `prefer` selects the resolved address family for the relayed target (a
/// multi-A server), `bogus_source` rewrites the reply header so the client sees
/// an address it did not resolve to.
async fn socks5_udp_peer_with(
    prefer: Option<&'static str>,
    bogus_source: Option<std::net::SocketAddr>,
) -> (u16, Log) {
    let (listener, addr) = spawn_tcp().await;
    let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    common::reserve_port(relay_addr.port());
    let log: Log = Arc::new(Mutex::new(Vec::new()));

    let relay_log = log.clone();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65535];
        loop {
            let Ok((read, from)) = relay.recv_from(&mut buffer).await else {
                return;
            };
            let Some(datagram) = billow_kernel::outbound::udp::parse_datagram(&buffer[..read])
            else {
                continue;
            };
            let payload = buffer[datagram.offset..read].to_vec();
            let target = datagram.target.clone();
            let resolved = match billow_kernel::outbound::udp::resolve_all(&target).await {
                Ok(addrs) => match prefer {
                    Some("ipv6") => addrs.iter().find(|addr| addr.is_ipv6()).copied(),
                    Some("ipv4") => addrs.iter().find(|addr| addr.is_ipv4()).copied(),
                    _ => addrs.first().copied(),
                }
                .unwrap_or(addrs[0]),
                Err(_) => continue,
            };
            push(
                &relay_log,
                Attempt {
                    details: vec![
                        format!("udp-target={}:{}", target.host, target.port),
                        format!("udp-bytes={}", payload.len()),
                    ],
                    forwarded: true,
                },
            );
            let bind = if resolved.is_ipv4() { "127.0.0.1:0" } else { "[::1]:0" };
            let socket = tokio::net::UdpSocket::bind(bind).await.unwrap();
            let _ = socket.send_to(&payload, resolved).await;
            let mut reply = vec![0u8; 65535];
            let Ok(Ok((n, source))) =
                tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut reply)).await
            else {
                continue;
            };
            let source = bogus_source.unwrap_or(source);
            let origin = billow_kernel::outbound::Target {
                host: source.ip().to_string(),
                port: source.port(),
            };
            let mut packet = vec![0u8, 0u8, 0u8];
            packet.extend_from_slice(&billow_kernel::outbound::udp::address_header(&origin));
            packet.extend_from_slice(&reply[..n]);
            let _ = relay.send_to(&packet, from).await;
        }
    });

    let control_log = log.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let log = control_log.clone();
            let relay_addr = relay_addr;
            tokio::spawn(async move {
                let mut greeting = [0u8; 2];
                if stream.read_exact(&mut greeting).await.is_err() {
                    return;
                }
                let mut methods = vec![0u8; greeting[1] as usize];
                if stream.read_exact(&mut methods).await.is_err() {
                    return;
                }
                stream.write_all(&[0x05, 0x00]).await.ok();
                let mut request = [0u8; 4];
                if stream.read_exact(&mut request).await.is_err() {
                    return;
                }
                // Consume the client's hint address and port.
                let skip = match request[3] {
                    0x01 => 4,
                    0x04 => 16,
                    0x03 => {
                        let mut len = [0u8; 1];
                        if stream.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        len[0] as usize
                    }
                    _ => return,
                };
                let mut discard = vec![0u8; skip + 2];
                if stream.read_exact(&mut discard).await.is_err() {
                    return;
                }
                if request[1] != 0x03 {
                    stream
                        .write_all(&[0x05, 0x07, 0, 1, 0, 0, 0, 0, 0, 0])
                        .await
                        .ok();
                    return;
                }
                let mut reply = vec![0x05, 0x00, 0x00, 0x01];
                reply.extend_from_slice(&relay_addr.ip().to_string().parse::<std::net::Ipv4Addr>().unwrap().octets());
                reply.extend_from_slice(&relay_addr.port().to_be_bytes());
                if stream.write_all(&reply).await.is_err() {
                    return;
                }
                push(
                    &log,
                    Attempt {
                        details: vec!["udp-associate".into()],
                        forwarded: true,
                    },
                );
                // The association lives as long as this control connection.
                let mut scratch = [0u8; 64];
                while stream.read(&mut scratch).await.unwrap_or(0) > 0 {}
            });
        }
    });
    (addr.port(), log)
}

/// Trojan UDP peer over TLS: accepts command 3, then forwards each
/// `addr|len|CRLF|payload` frame to `echo_port` and returns the echo in the
/// same framing. Records the targets it served.
async fn trojan_udp_peer(cert: &Cert, password: &'static str, echo_port: u16) -> (u16, Log) {
    let acceptor = tls_acceptor(cert);
    let (listener, addr) = spawn_tcp().await;
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let log_task = log.clone();
    let expected = trojan_password_key(password);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let log = log_task.clone();
            let expected = expected.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut bytes = Vec::new();
                let mut byte = [0u8; 1];
                let mut crlfs = 0;
                while crlfs < 2 {
                    if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    bytes.push(byte[0]);
                    if bytes.ends_with(b"\r\n") {
                        crlfs += 1;
                    }
                }
                let mut lines = bytes
                    .split(|value| *value == b'\n')
                    .map(|line| line.strip_suffix(b"\r").unwrap_or(line).to_vec());
                let hash = lines.next().unwrap_or_default();
                if hash != expected {
                    push(
                        &log,
                        Attempt {
                            details: vec!["bad-password".into()],
                            forwarded: false,
                        },
                    );
                    return;
                }
                loop {
                    let mut atyp = [0u8; 1];
                    if stream.read_exact(&mut atyp).await.is_err() {
                        return;
                    }
                    let skip = match atyp[0] {
                        0x01 => 4,
                        0x04 => 16,
                        0x03 => {
                            let mut len = [0u8; 1];
                            stream.read_exact(&mut len).await.unwrap();
                            len[0] as usize
                        }
                        _ => return,
                    };
                    let mut rest = vec![0u8; skip + 2 + 2 + 2];
                    if stream.read_exact(&mut rest).await.is_err() {
                        return;
                    }
                    let port = u16::from_be_bytes([rest[skip], rest[skip + 1]]);
                    let length = u16::from_be_bytes([rest[skip + 2], rest[skip + 3]]) as usize;
                    let mut payload = vec![0u8; length];
                    if stream.read_exact(&mut payload).await.is_err() {
                        return;
                    }
                    push(
                        &log,
                        Attempt {
                            details: vec![
                                format!("target=127.0.0.1:{port}"),
                                format!("payload={}", String::from_utf8_lossy(&payload)),
                            ],
                            forwarded: true,
                        },
                    );
                    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let _ = socket
                        .send_to(&payload, ("127.0.0.1", echo_port))
                        .await;
                    let mut reply = vec![0u8; 4096];
                    let Ok(Ok((n, _))) =
                        tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut reply))
                            .await
                    else {
                        continue;
                    };
                    let mut frame = vec![0x01, 127, 0, 0, 1];
                    frame.extend_from_slice(&port.to_be_bytes());
                    frame.extend_from_slice(&(n as u16).to_be_bytes());
                    frame.extend_from_slice(b"\r\n");
                    frame.extend_from_slice(&reply[..n]);
                    if stream.write_all(&frame).await.is_err() {
                        return;
                    }
                    let _ = stream.flush().await;
                }
            });
        }
    });
    (addr.port(), log)
}

/// A UDP echo on loopback; returns its port and the payload counter.
async fn udp_echo() -> (u16, Arc<AtomicU64>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    common::reserve_port(port);
    let received = Arc::new(AtomicU64::new(0));
    let counter = received.clone();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65535];
        while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
            counter.fetch_add(read as u64, Ordering::Relaxed);
            let _ = socket.send_to(&buffer[..read], from).await;
        }
    });
    (port, received)
}

/// Open a SOCKS5 UDP association through the kernel; the control connection
/// must stay alive for the association to work.
fn udp_associate(proxy: SocketAddr) -> (std::net::TcpStream, std::net::SocketAddr) {
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

/// Send one SOCKS5 UDP datagram and return the reply payload (without header).
fn udp_roundtrip(
    relay: std::net::SocketAddr,
    target: std::net::SocketAddr,
    payload: &[u8],
    wait: Duration,
) -> Option<Vec<u8>> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    udp_exchange(&socket, relay, target, payload, wait)
}

/// One datagram exchange on an existing client socket: the association pins the
/// first source address it sees (RFC 1928), so a client that sends twice must
/// reuse its socket.
fn udp_exchange(
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
    assert_eq!(buffer[3], 0x01, "reply header: {:02x?}", &buffer[..read]);
    Some(buffer[10..read].to_vec())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_udp_associate_forwards_datagrams_and_honours_reject() {
    let (echo_port, received) = udp_echo().await;
    let dir = scratch("udp-direct");
    let path = dir.join("kernel.yaml");
    std::fs::write(
        &path,
        format!(
            "mixed-port: {}\nlog-level: warn\nrules:\n  - 'IP-CIDR,127.0.0.1/32,DIRECT'\n  - 'MATCH,REJECT'\n",
            free_port()
        ),
    )
    .unwrap();
    let (mut kernel, _) = Kernel::start(&path, None, limits()).unwrap();
    let (control, relay) = udp_associate(kernel.listen_addr());
    let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().unwrap();

    let reply = udp_roundtrip(relay, target, b"udp-tagged", Duration::from_secs(3))
        .expect("a DIRECT datagram must come back through the relay");
    assert_eq!(reply, b"udp-tagged");
    wait_for(&received, b"udp-tagged".len() as u64).await;

    // A destination the rules REJECT is dropped before it reaches the echo.
    let blocked: SocketAddr = format!("127.0.0.2:{echo_port}").parse().unwrap();
    assert!(
        udp_roundtrip(relay, blocked, b"udp-blocked", Duration::from_millis(600)).is_none(),
        "REJECT must not produce a reply"
    );
    let seen = received.load(Ordering::Relaxed);
    assert_eq!(seen, b"udp-tagged".len() as u64);

    // The association ends with its control connection; no session stays active.
    drop(control);
    wait_for_counters(&kernel, |stats| stats.active == 0).await;

    // A live association must not outlive `stop()`: stop returns, the relay
    // socket and the buffers are released with the session.
    let (_live_control, _live_relay) = udp_associate(kernel.listen_addr());
    std::thread::sleep(Duration::from_millis(50));
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadowsocks_udp_datagrams_are_forwarded_with_the_peers_aead() {
    // An independent ss UDP server (TestAead, not the client's codec) proves
    // the datagram framing: `salt || sealed(addr || payload)` both ways.
    let cipher = billow_kernel::proxies::SsCipher::Aes256Gcm;
    let password = "ss-udp-password";
    let (echo_port, _) = udp_echo().await;
    let (server_port, _log) = ss_udp_peer(cipher, password, echo_port).await;
    let dir = scratch("ss-udp");
    let path = dir.join("kernel.yaml");
    std::fs::write(
        &path,
        format!(
            "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: s, type: ss, server: 127.0.0.1, port: {server_port}, cipher: aes-256-gcm, password: {password}, udp: true}}\nrules:\n  - 'MATCH,s'\n",
            free_port()
        ),
    )
    .unwrap();
    let (mut kernel, _) = Kernel::start(&path, None, limits()).unwrap();
    let (control, relay) = udp_associate(kernel.listen_addr());
    // The target the ss server sees is the echo; the address header carries it.
    let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().unwrap();
    let reply = udp_roundtrip(relay, target, b"ss-udp-tagged", Duration::from_secs(3))
        .expect("the ss datagram must come back");
    assert_eq!(reply, b"ss-udp-tagged");
    drop(control);
    kernel.stop().unwrap();
}


/// `ss` + `udp: true` + `dialer-proxy: hop`: the datagrams must travel through
/// the SOCKS5 hop's UDP relay, not straight to the server. The hop's own log
/// proves the chain (it names the ss server as its target).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadowsocks_udp_goes_through_the_dialer_proxy_hop() {
    let cipher = billow_kernel::proxies::SsCipher::Aes256Gcm;
    let password = "chained-ss-pw";
    let (echo_port, _) = udp_echo().await;
    let (ss_port, ss_log) = ss_udp_peer(cipher, password, echo_port).await;
    let (hop_port, hop_log) = socks5_udp_peer().await;
    let dir = scratch("ss-udp-chain");
    let path = dir.join("kernel.yaml");
    std::fs::write(
        &path,
        format!(
            "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: exit, type: ss, server: 127.0.0.1, port: {ss_port}, cipher: aes-256-gcm, password: {password}, udp: true, dialer-proxy: hop}}\n  - {{name: hop, type: socks5, server: 127.0.0.1, port: {hop_port}}}\nrules:\n  - 'MATCH,exit'\n",
            free_port()
        ),
    )
    .unwrap();
    let (mut kernel, _) = Kernel::start(&path, None, limits()).unwrap();
    let (control, relay) = udp_associate(kernel.listen_addr());
    let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().unwrap();
    let reply = udp_roundtrip(relay, target, b"chained-udp", Duration::from_secs(3))
        .expect("the chained ss datagram must come back");
    assert_eq!(reply, b"chained-udp");
    let hop_details = detail(&hop_log);
    assert!(
        hop_details.contains(&"udp-associate".to_string()),
        "the hop must see a UDP association: {hop_details:?}"
    );
    assert!(
        hop_details.contains(&format!("udp-target=127.0.0.1:{ss_port}")),
        "the hop must relay to the ss server, not the kernel: {hop_details:?}"
    );
    let ss_details = detail(&ss_log);
    assert!(
        ss_details.iter().any(|d| d == "payload=chained-udp"),
        "the ss peer must decode the payload: {ss_details:?}"
    );
    drop(control);
    kernel.stop().unwrap();
}

/// `dialer-proxy` keeps the matched exit (regression: the dispatcher used to
/// drop `chain[0]`, so the last hop dialled the final target directly and the
/// exit never saw the request). The hop must be asked to CONNECT the exit's
/// server; the exit then carries the request to the final target.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_dialer_proxy_reaches_the_exit_through_the_hop() {
    let (echo_port, received) = echo_target().await;
    let (exit_port, exit_log) = socks5_peer("exit-user", "exit-pass").await;
    let (hop_port, hop_log) = socks5_peer("hop-user", "hop-pass").await;
    let dir = scratch("tcp-dialer-chain");
    let path = dir.join("kernel.yaml");
    std::fs::write(
        &path,
        format!(
            "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: exit, type: socks5, server: 127.0.0.1, port: {exit_port}, username: exit-user, password: exit-pass, dialer-proxy: hop}}\n  - {{name: hop, type: socks5, server: 127.0.0.1, port: {hop_port}, username: hop-user, password: hop-pass}}\nrules:\n  - 'MATCH,exit'\n",
            free_port()
        ),
    )
    .unwrap();
    let (mut kernel, _) = Kernel::start(&path, None, limits()).unwrap();
    let payload = b"chain-keeps-the-exit";
    let reply = roundtrip(kernel.listen_addr(), "127.0.0.1", echo_port, payload)
        .await
        .expect("the chained dial must reach the echo through the exit");
    assert_eq!(reply, payload);
    let hop = detail(&hop_log);
    assert!(
        hop.iter()
            .any(|d| d == &format!("target=127.0.0.1:{exit_port}")),
        "the hop must be asked for the exit server: {hop:?}"
    );
    assert!(
        !hop.iter()
            .any(|d| d == &format!("target=127.0.0.1:{echo_port}")),
        "the hop must not dial the final target directly: {hop:?}"
    );
    let exit = detail(&exit_log);
    assert!(
        exit.iter()
            .any(|d| d == &format!("target=127.0.0.1:{echo_port}")),
        "the exit must receive the final target: {exit:?}"
    );
    wait_for(&received, payload.len() as u64).await;
    kernel.stop().unwrap();
}

/// An exit whose protocol cannot run over a hop must fail with the chain
/// error, not quietly let the hop dial the final target.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_dialer_proxy_never_bypasses_an_unsupported_exit() {
    let (echo_port, received) = echo_target().await;
    let (hop_port, hop_log) = socks5_peer("hop-user", "hop-pass").await;
    let dir = scratch("tcp-dialer-chain-unsupported");
    let path = dir.join("kernel.yaml");
    std::fs::write(
        &path,
        format!(
            "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: exit, type: ss, server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p, dialer-proxy: hop}}\n  - {{name: hop, type: socks5, server: 127.0.0.1, port: {hop_port}, username: hop-user, password: hop-pass}}\nrules:\n  - 'MATCH,exit'\n",
            free_port()
        ),
    )
    .unwrap();
    let (mut kernel, _) = Kernel::start(&path, None, limits()).unwrap();
    let result = roundtrip(kernel.listen_addr(), "127.0.0.1", echo_port, b"must-not-arrive").await;
    assert!(result.is_err(), "the unsupported exit must fail the dial: {result:?}");
    let hop = detail(&hop_log);
    assert!(
        !hop.iter()
            .any(|d| d == &format!("target=127.0.0.1:{echo_port}")),
        "the hop must never dial the final target: {hop:?}"
    );
    assert_eq!(
        received.load(Ordering::Relaxed),
        0,
        "the target must not be reached when the exit cannot be used"
    );
    kernel.stop().unwrap();
}

/// A trojan UDP peer whose stream ends after each reply: the association must
/// reconnect on the next datagram instead of staying deaf (the EOF flag must be
/// reset when the transport is dropped).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_udp_reconnects_after_the_server_closes_the_stream() {
    let cert = require_cert("trojan-udp-reconnect");
    let acceptor = tls_acceptor(&cert);
    let (listener, addr) = spawn_tcp().await;
    let (echo_port, _) = udp_echo().await;
    let connections = Arc::new(AtomicU64::new(0));
    let counter = connections.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                counter.fetch_add(1, Ordering::Relaxed);
                // Trojan header: password line, then command + address + CRLF.
                let mut bytes = Vec::new();
                let mut byte = [0u8; 1];
                let mut crlfs = 0;
                while crlfs < 2 {
                    if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    bytes.push(byte[0]);
                    if bytes.ends_with(b"\r\n") {
                        crlfs += 1;
                    }
                }
                // Serve exactly one UDP frame, echo it, then close the stream.
                // Frame: ATYP | address | port(2) | length(2) | CRLF | payload.
                let mut atyp = [0u8; 1];
                if stream.read_exact(&mut atyp).await.is_err() {
                    return;
                }
                let skip = match atyp[0] {
                    0x01 => 4,
                    0x04 => 16,
                    0x03 => {
                        let mut len = [0u8; 1];
                        stream.read_exact(&mut len).await.unwrap();
                        len[0] as usize
                    }
                    _ => return,
                };
                let mut rest = vec![0u8; skip + 2 + 2 + 2];
                if stream.read_exact(&mut rest).await.is_err() {
                    return;
                }
                let port = u16::from_be_bytes([rest[skip], rest[skip + 1]]);
                let length = u16::from_be_bytes([rest[skip + 2], rest[skip + 3]]) as usize;
                let mut payload = vec![0u8; length];
                if stream.read_exact(&mut payload).await.is_err() {
                    return;
                }
                let mut frame = Vec::new();
                frame.push(0x01);
                frame.extend_from_slice(&[127, 0, 0, 1]);
                frame.extend_from_slice(&port.to_be_bytes());
                frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                frame.extend_from_slice(b"\r\n");
                frame.extend_from_slice(&payload);
                let _ = stream.write_all(&frame).await;
                let _ = stream.flush().await;
                // End the stream: the kernel must notice and reconnect.
                let _ = stream.shutdown().await;
            });
        }
    });
    let dir = scratch("trojan-udp-reconnect");
    let path = dir.join("kernel.yaml");
    std::fs::write(
        &path,
        format!(
            "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: t, type: trojan, server: 127.0.0.1, port: {}, password: pw, sni: localhost, skip-cert-verify: true, udp: true}}\nrules:\n  - 'MATCH,t'\n",
            free_port(),
            addr.port()
        ),
    )
    .unwrap();
    let (mut kernel, _) = Kernel::start(&path, None, limits()).unwrap();
    let (control, relay) = udp_associate(kernel.listen_addr());
    let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().unwrap();
    let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let first = udp_exchange(&client, relay, target, b"first", Duration::from_secs(3))
        .expect("the first datagram must be answered");
    assert_eq!(first, b"first");
    // Give the kernel a moment to observe the server's EOF, then send again.
    std::thread::sleep(Duration::from_millis(150));
    let second = udp_exchange(&client, relay, target, b"second", Duration::from_secs(3))
        .expect("the association must reconnect and answer the second datagram");
    assert_eq!(second, b"second");
    assert!(
        connections.load(Ordering::Relaxed) >= 2,
        "the trojan server must have been reconnected"
    );
    drop(control);
    kernel.stop().unwrap();
}


/// A chained ss UDP association whose `server` is a *name*: the hop reports the
/// resolved address in its reply header, so the kernel must compare resolved
/// addresses instead of the configured string (otherwise every reply is
/// dropped).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadowsocks_udp_chained_with_a_domain_server_keeps_the_replies() {
    let cipher = billow_kernel::proxies::SsCipher::Aes256Gcm;
    let password = "domain-ss-pw";
    let (echo_port, _) = udp_echo().await;
    let (ss_port, ss_log) = ss_udp_peer(cipher, password, echo_port).await;
    let (hop_port, hop_log) = socks5_udp_peer().await;
    let dir = scratch("ss-udp-domain");
    let path = dir.join("kernel.yaml");
    std::fs::write(
        &path,
        format!(
            "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: exit, type: ss, server: localhost, port: {ss_port}, cipher: aes-256-gcm, password: {password}, udp: true, dialer-proxy: hop}}\n  - {{name: hop, type: socks5, server: 127.0.0.1, port: {hop_port}}}\nrules:\n  - 'MATCH,exit'\n",
            free_port()
        ),
    )
    .unwrap();
    let (mut kernel, _) = Kernel::start(&path, None, limits()).unwrap();
    let (control, relay) = udp_associate(kernel.listen_addr());
    let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().unwrap();
    let reply = udp_roundtrip(relay, target, b"domain-chained", Duration::from_secs(3))
        .expect("a domain server must not drop the replies");
    assert_eq!(reply, b"domain-chained");
    assert!(
        detail(&hop_log).contains(&format!("udp-target=127.0.0.1:{ss_port}")),
        "the hop resolves the name and relays to the IP: {:?}",
        detail(&hop_log)
    );
    assert!(detail(&ss_log).iter().any(|d| d == "payload=domain-chained"));
    drop(control);
    kernel.stop().unwrap();
}

/// `trojan` + `udp: true` + `dialer-proxy`: the server connection is TCP, so it
/// goes through the hop's CONNECT exactly like the TCP path, and the UDP frames
/// ride that tunnel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_udp_goes_through_the_dialer_proxy_hop() {
    let cert = require_cert("trojan-udp-chain");
    let (echo_port, _) = udp_echo().await;
    let (tj_port, tj_log) = trojan_udp_peer(&cert, "chain-pw", echo_port).await;
    let (hop_port, hop_log) = socks5_peer("alice", "s3cret").await;
    let dir = scratch("trojan-udp-chain");
    let path = dir.join("kernel.yaml");
    std::fs::write(
        &path,
        format!(
            "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: exit, type: trojan, server: 127.0.0.1, port: {tj_port}, password: chain-pw, sni: localhost, skip-cert-verify: true, udp: true, dialer-proxy: hop}}\n  - {{name: hop, type: socks5, server: 127.0.0.1, port: {hop_port}, username: alice, password: s3cret}}\nrules:\n  - 'MATCH,exit'\n",
            free_port()
        ),
    )
    .unwrap();
    let (mut kernel, _) = Kernel::start(&path, None, limits()).unwrap();
    let (control, relay) = udp_associate(kernel.listen_addr());
    let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().unwrap();
    let reply = udp_roundtrip(relay, target, b"trojan-chained", Duration::from_secs(3))
        .expect("the chained trojan datagram must come back");
    assert_eq!(reply, b"trojan-chained");
    assert!(
        detail(&hop_log).contains(&format!("target=127.0.0.1:{tj_port}")),
        "the hop must carry the trojan server connection: {:?}",
        detail(&hop_log)
    );
    assert!(
        detail(&tj_log).iter().any(|d| d == "payload=trojan-chained"),
        "{:?}",
        detail(&tj_log)
    );
    drop(control);
    kernel.stop().unwrap();
}


/// A reply whose header names an address the server name did not resolve to is
/// dropped, so the association never accepts an arbitrary sender.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadowsocks_udp_chained_drops_a_reply_from_an_unresolved_address() {
    let cipher = billow_kernel::proxies::SsCipher::Aes256Gcm;
    let password = "rogue-pw";
    let (echo_port, _) = udp_echo().await;
    let (ss_port, _ss_log) = ss_udp_peer(cipher, password, echo_port).await;
    let rogue: SocketAddr = "203.0.113.9:53".parse().unwrap();
    let (hop_port, _hop_log) = socks5_udp_peer_with(None, Some(rogue)).await;
    let dir = scratch("ss-udp-rogue");
    let path = dir.join("kernel.yaml");
    std::fs::write(
        &path,
        format!(
            "mixed-port: {}\nlog-level: warn\nproxies:\n  - {{name: exit, type: ss, server: 127.0.0.1, port: {ss_port}, cipher: aes-256-gcm, password: {password}, udp: true, dialer-proxy: hop}}\n  - {{name: hop, type: socks5, server: 127.0.0.1, port: {hop_port}}}\nrules:\n  - 'MATCH,exit'\n",
            free_port()
        ),
    )
    .unwrap();
    let (mut kernel, _) = Kernel::start(&path, None, limits()).unwrap();
    let (control, relay) = udp_associate(kernel.listen_addr());
    let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().unwrap();
    assert!(
        udp_roundtrip(relay, target, b"rogue-source", Duration::from_millis(800)).is_none(),
        "a reply from an unresolved address must be dropped"
    );
    drop(control);
    kernel.stop().unwrap();
}

#[test]
fn config_errors_tag_the_exact_proxy_field() {
    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let yaml = format!(
        "mixed-port: 1\nproxies:\n  - {{name: s1, type: wireguard, private-key: {KEY}, peers: [{{server: x, port: 1, public-key: {KEY}, allowed-ips: [0.0.0.0/0]}}], amnezia-wg-option: {{jc: 4}}}}\nrules: ['MATCH,DIRECT']\n"
    );
    let err = load_config(&yaml, "t").unwrap_err();
    assert_eq!(err.tag(), "unsupported");
    assert!(matches!(err, ConfigError::Unsupported(_)));
    assert!(
        err.to_string()
            .contains("proxies[0] (name=s1, type=wireguard)"),
        "{err}"
    );
}

// ---------------------------------------------------------------------------
// Gost relay v2 (transport/gost/relay.go): controlled server peer.
//
// The pinned Mihomo has no relay listener, so the server side below is an
// independent implementation of the version-1 request/response header from the
// pinned source. `tool/kernel-compat/peers/gost-relay-server` is the same peer
// in Go, used by `tool/kernel-compat/family-peers.sh` as a cross-check that
// the Rust client does not merely agree with itself.
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct GostMode {
    require_auth: Option<(String, String)>,
    forward: Option<u16>,
    bad_version: bool,
    /// Wrap the relay in an smux session (the client must send SYN first).
    mux: bool,
    /// Accept the UDP association command.
    udp: bool,
}

fn parse_gost_addr(bytes: &[u8]) -> Option<(String, u16)> {
    let (host, rest) = match bytes.first()? {
        0x01 if bytes.len() >= 7 => {
            let ip = std::net::Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4]);
            (ip.to_string(), &bytes[5..])
        }
        0x04 if bytes.len() >= 19 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[1..17]);
            (std::net::Ipv6Addr::from(octets).to_string(), &bytes[17..])
        }
        0x03 if bytes.len() >= 2 => {
            let len = bytes[1] as usize;
            if bytes.len() < 2 + len + 2 {
                return None;
            }
            (
                String::from_utf8(bytes[2..2 + len].to_vec()).ok()?,
                &bytes[2 + len..],
            )
        }
        _ => return None,
    };
    if rest.len() < 2 {
        return None;
    }
    Some((host, u16::from_be_bytes([rest[0], rest[1]])))
}

async fn gost_peer(mode: GostMode, tls_cert: Option<&Cert>) -> (u16, Log) {
    let std_listener = common::bind_loopback();
    let port = std_listener.local_addr().unwrap().port();
    std_listener.set_nonblocking(true).unwrap();
    let listener = TcpListener::from_std(std_listener).unwrap();
    let acceptor = tls_cert.map(tls_acceptor);
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let log_task = log.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let mode = mode.clone();
            let log = log_task.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                match acceptor {
                    Some(acceptor) => match acceptor.accept(stream).await {
                        Ok(tls) => serve_gost(tls, mode, log).await,
                        Err(e) => push(
                            &log,
                            Attempt {
                                details: vec![format!("tls-error={e}")],
                                forwarded: false,
                            },
                        ),
                    },
                    None => serve_gost(stream, mode, log).await,
                }
            });
        }
    });
    (port, log)
}

async fn serve_gost<S>(mut stream: S, mode: GostMode, log: Log)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    if mode.mux {
        match smux_accept(&mut stream).await {
            Ok(mut mux) => {
                push(
                    &log,
                    Attempt {
                        details: vec!["smux-syn".to_string()],
                        forwarded: false,
                    },
                );
                serve_relay(&mut mux, mode, log).await
            }
            Err(e) => push(
                &log,
                Attempt {
                    details: vec![format!("smux-error={e}")],
                    forwarded: false,
                },
            ),
        }
        return;
    }
    serve_relay(&mut stream, mode, log).await;
}

async fn serve_relay<S>(stream: &mut S, mode: GostMode, log: Log)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut header = [0u8; 4];
    if stream.read_exact(&mut header).await.is_err() {
        return;
    }
    let version = header[0];
    let command = header[1];
    let mut features = vec![0u8; u16::from_be_bytes([header[2], header[3]]) as usize];
    if stream.read_exact(&mut features).await.is_err() {
        return;
    }
    let mut pos = 0;
    let mut auth: Option<(String, String)> = None;
    let mut addr: Option<(String, u16)> = None;
    let mut network: u16 = 0xffff;
    while pos + 3 <= features.len() {
        let kind = features[pos];
        let len = u16::from_be_bytes([features[pos + 1], features[pos + 2]]) as usize;
        let payload = &features[pos + 3..pos + 3 + len];
        match kind {
            0x01 => {
                let ulen = payload[0] as usize;
                let user = String::from_utf8_lossy(&payload[1..1 + ulen]).into_owned();
                let plen = payload[1 + ulen] as usize;
                let pass =
                    String::from_utf8_lossy(&payload[2 + ulen..2 + ulen + plen]).into_owned();
                auth = Some((user, pass));
            }
            0x02 => addr = parse_gost_addr(payload),
            0x04 => network = u16::from_be_bytes([payload[0], payload[1]]),
            _ => {}
        }
        pos += 3 + len;
    }
    if mode.bad_version {
        let _ = stream.write_all(&[0x02, 0x00, 0x00, 0x00]).await;
        push(
            &log,
            Attempt {
                details: vec!["bad-version-sent".to_string()],
                forwarded: false,
            },
        );
        return;
    }
    if let Some((user, pass)) = &mode.require_auth {
        if auth.as_ref() != Some(&(user.clone(), pass.clone())) {
            let _ = stream.write_all(&[0x01, 0x02, 0x00, 0x00]).await;
            push(
                &log,
                Attempt {
                    details: vec![format!("unauthorized auth={auth:?}")],
                    forwarded: false,
                },
            );
            return;
        }
    }
    let target = match (addr, mode.forward) {
        (Some(addr), _) => addr,
        (None, Some(port)) => ("127.0.0.1".to_string(), port),
        (None, None) => {
            let _ = stream.write_all(&[0x01, 0x01, 0x00, 0x00]).await;
            push(
                &log,
                Attempt {
                    details: vec!["missing-address".to_string()],
                    forwarded: false,
                },
            );
            return;
        }
    };
    if command & 0x80 != 0 {
        serve_relay_udp(stream, &mode, &log, version, command, network, target, auth).await;
        return;
    }
    let upstream = match TcpStream::connect((target.0.as_str(), target.1)).await {
        Ok(upstream) => upstream,
        Err(e) => {
            let _ = stream.write_all(&[0x01, 0x06, 0x00, 0x00]).await;
            push(
                &log,
                Attempt {
                    details: vec![format!("target-error={e}")],
                    forwarded: false,
                },
            );
            return;
        }
    };
    let _ = stream.write_all(&[0x01, 0x00, 0x00, 0x00]).await;
    push(
        &log,
        Attempt {
            details: vec![
                format!("version={version}"),
                format!("network={network}"),
                format!("target={}:{}", target.0, target.1),
                format!("auth={auth:?}"),
            ],
            forwarded: true,
        },
    );
    let mut upstream = upstream;
    let _ = tokio::io::copy_bidirectional(stream, &mut upstream).await;
}

/// The UDP association: `length(u16 BE) || payload` in both directions, one
/// bound target, matching `relayPacketConn`.
async fn serve_relay_udp<S>(
    stream: &mut S,
    mode: &GostMode,
    log: &Log,
    version: u8,
    command: u8,
    network: u16,
    target: (String, u16),
    auth: Option<(String, String)>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if !mode.udp || network != 0x0001 {
        let _ = stream.write_all(&[0x01, 0x01, 0x00, 0x00]).await;
        push(
            log,
            Attempt {
                details: vec![format!("udp-unsupported network={network}")],
                forwarded: false,
            },
        );
        return;
    }
    let bind = if target.0.contains(':') { "[::]:0" } else { "127.0.0.1:0" };
    let socket = match tokio::net::UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(e) => {
            let _ = stream.write_all(&[0x01, 0x08, 0x00, 0x00]).await;
            push(
                log,
                Attempt {
                    details: vec![format!("udp-bind-error={e}")],
                    forwarded: false,
                },
            );
            return;
        }
    };
    let _ = stream.write_all(&[0x01, 0x00, 0x00, 0x00]).await;
    push(
        log,
        Attempt {
            details: vec![
                format!("version={version}"),
                format!("command=0x{command:02x}"),
                format!("network={network}"),
                format!("target={}:{}", target.0, target.1),
                format!("auth={auth:?}"),
            ],
            forwarded: true,
        },
    );
    loop {
        let mut len = [0u8; 2];
        if stream.read_exact(&mut len).await.is_err() {
            return;
        }
        let length = u16::from_be_bytes(len) as usize;
        let mut payload = vec![0u8; length];
        if stream.read_exact(&mut payload).await.is_err() {
            return;
        }
        if socket
            .send_to(&payload, (target.0.as_str(), target.1))
            .await
            .is_err()
        {
            return;
        }
        let mut reply = vec![0u8; 65_535];
        let Ok(read) = socket.recv(&mut reply).await else {
            return;
        };
        let mut frame = Vec::with_capacity(2 + read);
        frame.extend_from_slice(&(read as u16).to_be_bytes());
        frame.extend_from_slice(&reply[..read]);
        if stream.write_all(&frame).await.is_err() {
            return;
        }
        let _ = stream.flush().await;
    }
}

/// Server side of one smux session: accept the SYN and relay one stream. The
/// frame layout is the version-1 one from `github.com/metacubex/smux`
/// (`version(1) command(1) length(u16 LE) stream id(u32 LE) payload`).
struct SmuxPeer<'a, S> {
    inner: &'a mut S,
    sid: u32,
    under: Vec<u8>,
    decoded: Vec<u8>,
    decoded_pos: usize,
    pending: Vec<u8>,
    pending_pos: usize,
    fin: bool,
    fin_sent: bool,
}

async fn smux_accept<S>(inner: &mut S) -> io::Result<SmuxPeer<'_, S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut header = [0u8; 8];
    inner.read_exact(&mut header).await?;
    if header[0] != 1 || header[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected an smux SYN frame",
        ));
    }
    let sid = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    Ok(SmuxPeer {
        inner,
        sid,
        under: Vec::new(),
        decoded: Vec::new(),
        decoded_pos: 0,
        pending: Vec::new(),
        pending_pos: 0,
        fin: false,
        fin_sent: false,
    })
}

impl<'a, S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for SmuxPeer<'a, S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.decoded_pos < this.decoded.len() {
                let available = this.decoded.len() - this.decoded_pos;
                let take = available.min(buf.remaining());
                let start = this.decoded_pos;
                buf.put_slice(&this.decoded[start..start + take]);
                this.decoded_pos += take;
                return std::task::Poll::Ready(Ok(()));
            }
            this.decoded.clear();
            this.decoded_pos = 0;
            let mut consumed = 0;
            while this.under.len() >= consumed + 8 {
                let frame = &this.under[consumed..];
                let cmd = frame[1];
                let length = u16::from_le_bytes([frame[2], frame[3]]) as usize;
                let sid = u32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]);
                if this.under.len() < consumed + 8 + length {
                    break;
                }
                let payload = this.under[consumed + 8..consumed + 8 + length].to_vec();
                consumed += 8 + length;
                match cmd {
                    2 if sid == this.sid && !payload.is_empty() => {
                        this.decoded.extend_from_slice(&payload)
                    }
                    1 if sid == this.sid => this.fin = true,
                    _ => {}
                }
            }
            if consumed > 0 {
                this.under.drain(..consumed);
            }
            if !this.decoded.is_empty() {
                continue;
            }
            if this.fin {
                return std::task::Poll::Ready(Ok(()));
            }
            let mut scratch = [0u8; 4096];
            let mut piece = tokio::io::ReadBuf::new(&mut scratch);
            match std::pin::Pin::new(&mut *this.inner).poll_read(cx, &mut piece) {
                std::task::Poll::Ready(Ok(())) => {
                    let filled = piece.filled().to_vec();
                    if filled.is_empty() {
                        return std::task::Poll::Ready(Ok(()));
                    }
                    this.under.extend_from_slice(&filled);
                }
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

impl<'a, S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for SmuxPeer<'a, S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = self.get_mut();
        while this.pending_pos < this.pending.len() {
            match std::pin::Pin::new(&mut *this.inner).poll_write(cx, &this.pending[this.pending_pos..]) {
                std::task::Poll::Ready(Ok(0)) => {
                    return std::task::Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "smux peer stopped accepting bytes",
                    )))
                }
                std::task::Poll::Ready(Ok(n)) => this.pending_pos += n,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
        this.pending.clear();
        this.pending_pos = 0;
        let mut rest = buf;
        while !rest.is_empty() {
            let size = rest.len().min(32768);
            let mut header = [0u8; 8];
            header[0] = 1;
            header[1] = 2;
            header[2..4].copy_from_slice(&(size as u16).to_le_bytes());
            header[4..8].copy_from_slice(&this.sid.to_le_bytes());
            this.pending.extend_from_slice(&header);
            this.pending.extend_from_slice(&rest[..size]);
            rest = &rest[size..];
        }
        while this.pending_pos < this.pending.len() {
            match std::pin::Pin::new(&mut *this.inner).poll_write(cx, &this.pending[this.pending_pos..]) {
                std::task::Poll::Ready(Ok(0)) => {
                    return std::task::Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "smux peer stopped accepting bytes",
                    )))
                }
                std::task::Poll::Ready(Ok(n)) => this.pending_pos += n,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => break,
            }
        }
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.pending_pos < this.pending.len() {
            match std::pin::Pin::new(&mut *this.inner).poll_write(cx, &this.pending[this.pending_pos..]) {
                std::task::Poll::Ready(Ok(0)) => {
                    return std::task::Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "smux peer stopped accepting bytes",
                    )))
                }
                std::task::Poll::Ready(Ok(n)) => this.pending_pos += n,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
        std::pin::Pin::new(&mut *this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.fin_sent {
            this.fin_sent = true;
            let mut header = [0u8; 8];
            header[0] = 1;
            header[1] = 1;
            header[4..8].copy_from_slice(&this.sid.to_le_bytes());
            this.pending.extend_from_slice(&header);
        }
        while this.pending_pos < this.pending.len() {
            match std::pin::Pin::new(&mut *this.inner)
                .poll_write(cx, &this.pending[this.pending_pos..])
            {
                std::task::Poll::Ready(Ok(0)) => {
                    return std::task::Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "smux peer stopped accepting bytes",
                    )))
                }
                std::task::Poll::Ready(Ok(n)) => this.pending_pos += n,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
        std::pin::Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

async fn gost_roundtrip(proxy: SocketAddr, target: &str, payload: &[u8]) -> io::Result<Vec<u8>> {
    let (mut stream, status) = http_connect(proxy, target).await?;
    assert_eq!(status, "HTTP/1.1 200 Connection Established");
    stream.write_all(payload).await?;
    let mut back = vec![0u8; payload.len()];
    stream.read_exact(&mut back).await?;
    Ok(back)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gost_relay_outbound_relays_to_the_address_feature_target() {
    let (peer_port, log) = gost_peer(GostMode::default(), None).await;
    let (target_port, received) = echo_target().await;
    let dir = scratch("gost");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!("  - {{name: gr, type: gost-relay, server: 127.0.0.1, port: {peer_port}}}\n"),
        "gr",
        limits(),
    )
    .unwrap();
    let payload = b"tagged-gost-relay-payload";
    let back = gost_roundtrip(
        kernel.listen_addr(),
        &format!("127.0.0.1:{target_port}"),
        payload,
    )
    .await
    .unwrap();
    assert_eq!(back, payload.to_vec());
    wait_for(&received, payload.len() as u64).await;
    let details = detail(&log);
    assert!(
        details
            .iter()
            .any(|d| d == &format!("target=127.0.0.1:{target_port}")),
        "{details:?}"
    );
    assert!(details.iter().any(|d| d == "network=0"), "{details:?}");
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gost_relay_outbound_sends_user_auth_and_forward_omits_the_address() {
    let (target_port, received) = echo_target().await;
    let mode = GostMode {
        require_auth: Some(("relay-user".into(), "relay-pass".into())),
        forward: Some(target_port),
        bad_version: false,
        mux: false,
        udp: false,
        };
    let (peer_port, log) = gost_peer(mode, None).await;
    let dir = scratch("gost-forward");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!(
            "  - {{name: gr, type: gost-relay, server: 127.0.0.1, port: {peer_port}, forward: true, username: relay-user, password: relay-pass}}\n"
        ),
        "gr",
        limits(),
    )
    .unwrap();
    // The CONNECT target is deliberately a dead port: `forward: true` must
    // send no address feature, so the peer uses its own forward target.
    let payload = b"tagged-gost-forward";
    let back = gost_roundtrip(
        kernel.listen_addr(),
        &format!("127.0.0.1:{}", common::free_port()),
        payload,
    )
    .await
    .unwrap();
    assert_eq!(back, payload.to_vec());
    wait_for(&received, payload.len() as u64).await;
    let details = detail(&log);
    assert!(
        details
            .iter()
            .any(|d| d == "auth=Some((\"relay-user\", \"relay-pass\"))"),
        "{details:?}"
    );
    assert!(
        details
            .iter()
            .any(|d| d == &format!("target=127.0.0.1:{target_port}")),
        "{details:?}"
    );
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gost_relay_outbound_wrong_credentials_never_reach_the_target() {
    let mode = GostMode {
        require_auth: Some(("relay-user".into(), "relay-pass".into())),
        ..GostMode::default()
    };
    let (peer_port, log) = gost_peer(mode, None).await;
    let (target_port, received) = echo_target().await;
    let dir = scratch("gost-bad-auth");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!(
            "  - {{name: gr, type: gost-relay, server: 127.0.0.1, port: {peer_port}, username: relay-user, password: wrong}}\n"
        ),
        "gr",
        limits(),
    )
    .unwrap();
    let (_, status) = http_connect(
        kernel.listen_addr(),
        &format!("127.0.0.1:{target_port}"),
    )
    .await
    .unwrap();
    assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
    assert_eq!(received.load(Ordering::Relaxed), 0);
    assert!(
        wait_detail_prefix(&log, "unauthorized").await,
        "{:?}",
        detail(&log)
    );
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gost_relay_outbound_rejects_a_bad_response_version() {
    let (peer_port, log) = gost_peer(
        GostMode {
            bad_version: true,
            ..GostMode::default()
        },
        None,
    )
    .await;
    let (target_port, _received) = echo_target().await;
    let dir = scratch("gost-bad-version");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!("  - {{name: gr, type: gost-relay, server: 127.0.0.1, port: {peer_port}}}\n"),
        "gr",
        limits(),
    )
    .unwrap();
    let (_, status) = http_connect(
        kernel.listen_addr(),
        &format!("127.0.0.1:{target_port}"),
    )
    .await
    .unwrap();
    assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
    assert!(
        wait_detail_prefix(&log, "bad-version-sent").await,
        "{:?}",
        detail(&log)
    );
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gost_relay_outbound_over_tls_relays_and_verifies_the_certificate() {
    let cert = require_cert("gost-relay");
    let (peer_port, log) = gost_peer(GostMode::default(), Some(&cert)).await;
    let (target_port, received) = echo_target().await;
    let dir = scratch("gost-tls");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!(
            "  - {{name: gr, type: gost-relay, server: 127.0.0.1, port: {peer_port}, tls: true, sni: localhost, skip-cert-verify: true}}\n"
        ),
        "gr",
        limits(),
    )
    .unwrap();
    let payload = b"tagged-gost-tls";
    let back = gost_roundtrip(
        kernel.listen_addr(),
        &format!("127.0.0.1:{target_port}"),
        payload,
    )
    .await
    .unwrap();
    assert_eq!(back, payload.to_vec());
    wait_for(&received, payload.len() as u64).await;
    let details = detail(&log);
    assert!(
        details
            .iter()
            .any(|d| d == &format!("target=127.0.0.1:{target_port}")),
        "{details:?}"
    );
    kernel.stop().unwrap();
}

// ---------------------------------------------------------------------------
// SSH (adapter/outbound/ssh.go): controlled russh server peer.
//
// The pinned Mihomo has no SSH listener. This peer is a real SSH server built
// on the same `russh` crate the outbound uses for its client side; it accepts
// password or public-key authentication and opens the requested
// `direct-tcpip` channel to a loopback echo target. The wire behaviour under
// test is the client's, so sharing the SSH implementation does not hide a
// client-side framing bug (the server enforces the protocol independently).
// ---------------------------------------------------------------------------

struct SshPeerState {
    username: String,
    password: String,
    client_key: Option<russh::keys::PublicKey>,
    log: Log,
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

    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        push(
            &self.state.log,
            Attempt {
                details: vec![format!("session-error={error}")],
                forwarded: false,
            },
        );
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
        push(
            &self.state.log,
            Attempt {
                details: vec![format!("auth-password user={user} ok={ok}")],
                forwarded: false,
            },
        );
        Ok(if ok {
            russh::server::Auth::Accept
        } else {
            russh::server::Auth::reject()
        })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh::keys::PublicKey,
    ) -> Result<russh::server::Auth, Self::Error> {
        let ok = user == self.state.username
            && self
                .state
                .client_key
                .as_ref()
                .is_none_or(|expected| expected.key_data() == key.key_data());
        push(
            &self.state.log,
            Attempt {
                details: vec![format!("auth-publickey user={user} ok={ok}")],
                forwarded: false,
            },
        );
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
        push(
            &self.state.log,
            Attempt {
                details: vec![format!("direct-tcpip {host}:{port}")],
                forwarded: true,
            },
        );
        tokio::spawn(async move {
            let mut channel = channel.into_stream();
            if let Ok(mut upstream) = TcpStream::connect((host.as_str(), port)).await {
                let _ = tokio::io::copy_bidirectional(&mut channel, &mut upstream).await;
            }
        });
        Ok(true)
    }
}

async fn ssh_peer(
    username: &str,
    password: &str,
    client_key: Option<russh::keys::PublicKey>,
) -> (u16, Log, russh::keys::PrivateKey) {
    let host_key =
        russh::keys::PrivateKey::random(&mut rand::rngs::OsRng, russh::keys::Algorithm::Ed25519)
            .expect("generate ssh host key");
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(russh::server::Config {
        keys: vec![host_key.clone()],
        inactivity_timeout: Some(Duration::from_secs(30)),
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        ..Default::default()
    });
    let mut server = SshPeer {
        state: Arc::new(SshPeerState {
            username: username.to_string(),
            password: password.to_string(),
            client_key,
            log: log.clone(),
        }),
    };
    tokio::spawn(async move {
        let _ = russh::server::Server::run_on_socket(&mut server, config, &listener).await;
    });
    (port, log, host_key)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_outbound_password_auth_relays_direct_tcpip() {
    let (peer_port, log, _host_key) = ssh_peer("tester", "secret", None).await;
    let (target_port, received) = echo_target().await;
    let dir = scratch("ssh-password");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!(
            "  - {{name: sp, type: ssh, server: 127.0.0.1, port: {peer_port}, username: tester, password: secret}}\n"
        ),
        "sp",
        limits(),
    )
    .unwrap();
    let payload = b"tagged-ssh-password";
    let back = roundtrip(kernel.listen_addr(), "127.0.0.1", target_port, payload)
        .await
        .unwrap();
    assert_eq!(back, payload.to_vec());
    wait_for(&received, payload.len() as u64).await;
    let details = detail(&log);
    assert!(
        details.iter().any(|d| d == "auth-password user=tester ok=true"),
        "{details:?}"
    );
    assert!(
        details
            .iter()
            .any(|d| d == &format!("direct-tcpip 127.0.0.1:{target_port}")),
        "{details:?}"
    );
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_outbound_wrong_password_never_reaches_the_target() {
    let (peer_port, log, _host_key) = ssh_peer("tester", "secret", None).await;
    let (target_port, received) = echo_target().await;
    let dir = scratch("ssh-bad-password");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!(
            "  - {{name: sp, type: ssh, server: 127.0.0.1, port: {peer_port}, username: tester, password: wrong}}\n"
        ),
        "sp",
        limits(),
    )
    .unwrap();
    let error = roundtrip(kernel.listen_addr(), "127.0.0.1", target_port, b"nope").await;
    assert!(error.is_err(), "wrong password must fail the dial: {error:?}");
    assert_eq!(received.load(Ordering::Relaxed), 0);
    let details = detail(&log);
    assert!(
        details.iter().any(|d| d == "auth-password user=tester ok=false"),
        "{details:?}"
    );
    assert!(
        !details.iter().any(|d| d.starts_with("direct-tcpip")),
        "{details:?}"
    );
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_outbound_public_key_auth_relays_direct_tcpip() {
    let client_key =
        russh::keys::PrivateKey::random(&mut rand::rngs::OsRng, russh::keys::Algorithm::Ed25519)
            .expect("generate client key");
    let client_public = client_key.public_key().clone();
    let pem = client_key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .expect("encode client key");
    let (peer_port, log, _host_key) = ssh_peer("tester", "", Some(client_public)).await;
    let (target_port, received) = echo_target().await;
    let dir = scratch("ssh-publickey");
    let proxies = format!(
        "  - name: sp\n    type: ssh\n    server: 127.0.0.1\n    port: {peer_port}\n    username: tester\n    private-key: |\n{}",
        pem.lines()
            .map(|line| format!("      {line}\n"))
            .collect::<String>()
    );
    let (mut kernel, _) = start_kernel(&dir, &proxies, "sp", limits()).unwrap();
    let payload = b"tagged-ssh-publickey";
    let back = roundtrip(kernel.listen_addr(), "127.0.0.1", target_port, payload)
        .await
        .unwrap();
    assert_eq!(back, payload.to_vec());
    wait_for(&received, payload.len() as u64).await;
    let details = detail(&log);
    assert!(
        details
            .iter()
            .any(|d| d == "auth-publickey user=tester ok=true"),
        "{details:?}"
    );
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_outbound_pinned_host_key_must_match_the_server() {
    let (peer_port, log, host_key) = ssh_peer("tester", "secret", None).await;
    let (target_port, received) = echo_target().await;
    let wrong_key =
        russh::keys::PrivateKey::random(&mut rand::rngs::OsRng, russh::keys::Algorithm::Ed25519)
            .expect("generate other key");
    let wrong_line = wrong_key.public_key().to_openssh().unwrap();
    let right_line = host_key.public_key().to_openssh().unwrap();
    let dir = scratch("ssh-hostkey");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!(
            "  - {{name: sp, type: ssh, server: 127.0.0.1, port: {peer_port}, username: tester, password: secret, host-key: [\"{wrong_line}\"]}}\n"
        ),
        "sp",
        limits(),
    )
    .unwrap();
    let error = roundtrip(kernel.listen_addr(), "127.0.0.1", target_port, b"nope").await;
    assert!(error.is_err(), "a mismatched host key must fail: {error:?}");
    assert_eq!(received.load(Ordering::Relaxed), 0);
    assert!(
        !detail(&log).iter().any(|d| d.starts_with("direct-tcpip")),
        "{:?}",
        detail(&log)
    );
    kernel.stop().unwrap();

    // The same peer is accepted once the pinned key is the server's own key.
    let dir = scratch("ssh-hostkey-ok");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!(
            "  - {{name: sp, type: ssh, server: 127.0.0.1, port: {peer_port}, username: tester, password: secret, host-key: [\"{right_line}\"]}}\n"
        ),
        "sp",
        limits(),
    )
    .unwrap();
    let payload = b"tagged-ssh-pinned";
    let back = roundtrip(kernel.listen_addr(), "127.0.0.1", target_port, payload)
        .await
        .unwrap();
    assert_eq!(back, payload.to_vec());
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gost_relay_udp_relays_datagrams_to_the_bound_target() {
    let mode = GostMode {
        udp: true,
        ..GostMode::default()
    };
    let (peer_port, log) = gost_peer(mode, None).await;
    let (echo_port, received) = udp_echo().await;
    let dir = scratch("gost-udp");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!(
            "  - {{name: gr, type: gost-relay, server: 127.0.0.1, port: {peer_port}, udp: true}}\n"
        ),
        "gr",
        limits(),
    )
    .unwrap();
    let (control, relay) = udp_associate(kernel.listen_addr());
    let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().unwrap();
    let payload = b"gost-udp-tagged";
    let reply = udp_roundtrip(relay, target, payload, Duration::from_secs(3))
        .expect("a UDP association must relay the datagram");
    assert_eq!(reply, payload.to_vec());
    wait_for(&received, payload.len() as u64).await;
    let details = detail(&log);
    assert!(
        details
            .iter()
            .any(|d| d == "command=0x81" && details.iter().any(|n| n == "network=1")),
        "{details:?}"
    );
    drop(control);
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gost_relay_udp_without_the_option_is_refused_by_the_server() {
    // The peer refuses the UDP association when it has no UDP support; the
    // kernel must not fall back to DIRECT and no datagram may arrive.
    let (peer_port, log) = gost_peer(GostMode::default(), None).await;
    let (echo_port, received) = udp_echo().await;
    let dir = scratch("gost-udp-refused");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!(
            "  - {{name: gr, type: gost-relay, server: 127.0.0.1, port: {peer_port}, udp: true}}\n"
        ),
        "gr",
        limits(),
    )
    .unwrap();
    let (control, relay) = udp_associate(kernel.listen_addr());
    let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().unwrap();
    assert!(
        udp_roundtrip(relay, target, b"gost-udp-refused", Duration::from_millis(700)).is_none(),
        "a refused association must not produce a reply"
    );
    assert_eq!(received.load(Ordering::Relaxed), 0);
    let details = detail(&log);
    assert!(
        details.iter().any(|d| d.starts_with("udp-unsupported")),
        "{details:?}"
    );
    drop(control);
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gost_relay_mux_relays_over_one_smux_stream() {
    let mode = GostMode {
        mux: true,
        ..GostMode::default()
    };
    let (peer_port, log) = gost_peer(mode, None).await;
    let (target_port, received) = echo_target().await;
    let dir = scratch("gost-mux");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!(
            "  - {{name: gr, type: gost-relay, server: 127.0.0.1, port: {peer_port}, mux: true}}\n"
        ),
        "gr",
        limits(),
    )
    .unwrap();
    let payload = b"gost-mux-tagged";
    let back = gost_roundtrip(
        kernel.listen_addr(),
        &format!("127.0.0.1:{target_port}"),
        payload,
    )
    .await
    .expect("mux relay");
    assert_eq!(back, payload.to_vec());
    wait_for(&received, payload.len() as u64).await;
    let details = detail(&log);
    assert!(details.iter().any(|d| d == "smux-syn"), "{details:?}");
    assert!(
        details
            .iter()
            .any(|d| d == &format!("target=127.0.0.1:{target_port}")),
        "{details:?}"
    );
    kernel.stop().unwrap();
}

/// The pinned `transport/gost.NewRelayDialer` (the client Mihomo ships) must be
/// accepted by the same controlled peer the Rust client is checked against.
/// That closes the "both sides are our own implementation" gap for the UDP
/// association and the smux session. Controlled entry:
/// `tool/kernel-compat/family-peers.sh` builds
/// `tool/kernel-compat/peers/gost-relay-harness` and sets `KC_GOST_HARNESS_BIN`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the pinned gost dialer harness: run tool/kernel-compat/family-peers.sh"]
async fn gost_relay_pinned_dialer_accepts_the_controlled_peer() {
    let Some(bin) = std::env::var_os("KC_GOST_HARNESS_BIN") else {
        eprintln!("SKIP gost_relay_pinned_dialer (set KC_GOST_HARNESS_BIN; run tool/kernel-compat/family-peers.sh)");
        return;
    };
    let mode = GostMode {
        mux: true,
        udp: true,
        ..GostMode::default()
    };
    let (peer_port, log) = gost_peer(mode, None).await;
    let (target_port, received) = echo_target().await;
    let (udp_port, udp_received) = udp_echo().await;
    let run = |mode: &'static str, target: String, marker: &'static str| {
        let bin = bin.clone();
        async move {
            tokio::process::Command::new(bin)
                .args([
                    "-relay",
                    &format!("127.0.0.1:{peer_port}"),
                    "-target",
                    &target,
                    "-mux",
                    "-mode",
                    mode,
                    "-marker",
                    marker,
                ])
                .output()
                .await
                .expect("run the pinned dialer harness")
        }
    };
    let tcp = run("tcp", format!("127.0.0.1:{target_port}"), "pinned-dialer-tcp").await;
    assert!(
        tcp.status.success(),
        "pinned tcp dialer failed: {}\n{}",
        String::from_utf8_lossy(&tcp.stdout),
        String::from_utf8_lossy(&tcp.stderr)
    );
    assert!(
        String::from_utf8_lossy(&tcp.stdout).contains("OK tcp"),
        "{}",
        String::from_utf8_lossy(&tcp.stdout)
    );
    wait_for(&received, "pinned-dialer-tcp".len() as u64).await;

    let udp = run("udp", format!("127.0.0.1:{udp_port}"), "pinned-dialer-udp").await;
    assert!(
        udp.status.success(),
        "pinned udp dialer failed: {}\n{}",
        String::from_utf8_lossy(&udp.stdout),
        String::from_utf8_lossy(&udp.stderr)
    );
    assert!(
        String::from_utf8_lossy(&udp.stdout).contains("OK udp"),
        "{}",
        String::from_utf8_lossy(&udp.stdout)
    );
    wait_for(&udp_received, "pinned-dialer-udp".len() as u64).await;

    let details = detail(&log);
    assert!(details.iter().any(|d| d == "smux-syn"), "{details:?}");
    assert!(details.iter().any(|d| d == "command=0x81"), "{details:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gost_relay_mux_and_udp_share_the_smux_session() {
    let mode = GostMode {
        mux: true,
        udp: true,
        ..GostMode::default()
    };
    let (peer_port, log) = gost_peer(mode, None).await;
    let (echo_port, received) = udp_echo().await;
    let dir = scratch("gost-mux-udp");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!(
            "  - {{name: gr, type: gost-relay, server: 127.0.0.1, port: {peer_port}, mux: true, udp: true}}\n"
        ),
        "gr",
        limits(),
    )
    .unwrap();
    let (control, relay) = udp_associate(kernel.listen_addr());
    let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().unwrap();
    let payload = b"gost-mux-udp";
    let reply = udp_roundtrip(relay, target, payload, Duration::from_secs(3))
        .expect("mux UDP association");
    assert_eq!(reply, payload.to_vec());
    wait_for(&received, payload.len() as u64).await;
    let details = detail(&log);
    assert!(details.iter().any(|d| d == "smux-syn"), "{details:?}");
    assert!(details.iter().any(|d| d == "command=0x81"), "{details:?}");
    drop(control);
    kernel.stop().unwrap();
}

// ---------------------------------------------------------------------------
// ShadowsocksR (origin/plain subset): controlled server peer.
//
// The pinned Mihomo has no SSR listener. The peer wraps the same cipher stream
// in the opposite direction, reads the IV + encrypted SOCKS address and relays
// to a loopback echo target. Cipher correctness is pinned independently by the
// Go vectors in `src/outbound/ssr.rs`; this peer proves the IV placement,
// address framing and bidirectional relay of the client.
// ---------------------------------------------------------------------------

async fn ssr_peer(
    cipher: billow_kernel::proxies::SsrCipher,
    password: &str,
) -> (u16, Log) {
    let key = billow_kernel::keys::evp_bytes_to_key(password.as_bytes(), cipher.key_len());
    let std_listener = common::bind_loopback();
    let port = std_listener.local_addr().unwrap().port();
    std_listener.set_nonblocking(true).unwrap();
    let listener = TcpListener::from_std(std_listener).unwrap();
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let log_task = log.clone();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let key = key.clone();
            let log = log_task.clone();
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
                // Read the encrypted SOCKS address. A wrong password decrypts
                // to arbitrary bytes, so the read is bounded: an unbounded
                // `read_exact` would wait for bytes the client never sends
                // (the client is waiting for the echo at the same time).
                let (host, target_port) = match read_ssr_address(&mut stream).await {
                    Ok(address) => address,
                    Err(detail) => {
                        push(
                            &log,
                            Attempt {
                                details: vec![detail],
                                forwarded: false,
                            },
                        );
                        return;
                    }
                };
                let connect = TcpStream::connect((host.as_str(), target_port));
                let mut upstream = match tokio::time::timeout(SSR_PEER_ADDRESS_TIMEOUT, connect)
                    .await
                {
                    Ok(Ok(upstream)) => upstream,
                    Ok(Err(e)) => {
                        push(
                            &log,
                            Attempt {
                                details: vec![format!("target-error={e}")],
                                forwarded: false,
                            },
                        );
                        return;
                    }
                    Err(_) => {
                        push(
                            &log,
                            Attempt {
                                details: vec!["target-error=timeout".to_string()],
                                forwarded: false,
                            },
                        );
                        return;
                    }
                };
                push(
                    &log,
                    Attempt {
                        details: vec![format!("target={host}:{target_port}")],
                        forwarded: true,
                    },
                );
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
            });
        }
    });
    (port, log)
}

/// Read one SSR address with a hard bound. The first bytes come from the
/// cipher stream, so a wrong password yields arbitrary values; without the
/// bound an `0x03` (domain) or `0x04` (IPv6) type would read a random number of
/// bytes that never arrive.
async fn read_ssr_address<S>(stream: &mut S) -> Result<(String, u16), String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let read = async {
        let mut kind = [0u8; 1];
        stream.read_exact(&mut kind).await?;
        let host = match kind[0] {
            0x01 => {
                let mut octets = [0u8; 4];
                stream.read_exact(&mut octets).await?;
                std::net::Ipv4Addr::from(octets).to_string()
            }
            0x04 => {
                let mut octets = [0u8; 16];
                stream.read_exact(&mut octets).await?;
                std::net::Ipv6Addr::from(octets).to_string()
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut name = vec![0u8; len[0] as usize];
                stream.read_exact(&mut name).await?;
                String::from_utf8_lossy(&name).into_owned()
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("bad-address-type={other}"),
                ))
            }
        };
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await?;
        Ok((host, u16::from_be_bytes(port)))
    };
    match tokio::time::timeout(SSR_PEER_ADDRESS_TIMEOUT, read).await {
        Ok(Ok(address)) => Ok(address),
        Ok(Err(e)) if e.kind() == io::ErrorKind::InvalidData => Err(format!("bad-address-type={}", e)),
        Ok(Err(e)) => Err(format!("address-error={e}")),
        Err(_) => Err("address-error=timeout".to_string()),
    }
}

/// Bound for the peer's address read; a valid client sends the whole address
/// in its first write, so this only ever fires on a garbage decrypt.
const SSR_PEER_ADDRESS_TIMEOUT: Duration = Duration::from_secs(2);

async fn ssr_roundtrip(
    proxy: SocketAddr,
    target: &str,
    payload: &[u8],
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let roundtrip = async {
        let (mut stream, status) = http_connect(proxy, target).await?;
        assert_eq!(status, "HTTP/1.1 200 Connection Established");
        stream.write_all(payload).await?;
        let mut back = vec![0u8; payload.len()];
        stream.read_exact(&mut back).await?;
        Ok(back)
    };
    match tokio::time::timeout(timeout, roundtrip).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("ssr roundtrip to {target} timed out after {timeout:?}"),
        )),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssr_outbound_origin_plain_relays_with_aes_256_cfb() {
    use billow_kernel::proxies::SsrCipher;
    let (peer_port, log) = ssr_peer(SsrCipher::Aes256Cfb, "ssr-password").await;
    let (target_port, received) = echo_target().await;
    let dir = scratch("ssr-aes");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!(
            "  - {{name: sr, type: ssr, server: 127.0.0.1, port: {peer_port}, cipher: aes-256-cfb, password: ssr-password, protocol: origin, obfs: plain}}\n"
        ),
        "sr",
        limits(),
    )
    .unwrap();
    let payload = b"tagged-ssr-aes-256-cfb";
    let back = ssr_roundtrip(
        kernel.listen_addr(),
        &format!("127.0.0.1:{target_port}"),
        payload,
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert_eq!(back, payload.to_vec());
    wait_for(&received, payload.len() as u64).await;
    let details = detail(&log);
    assert!(
        details
            .iter()
            .any(|d| d == &format!("target=127.0.0.1:{target_port}")),
        "{details:?}"
    );
    kernel.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssr_outbound_rc4_md5_and_dummy_ciphers_relay() {
    use billow_kernel::proxies::SsrCipher;
    for (cipher_name, cipher) in [
        ("rc4-md5", SsrCipher::Rc4Md5),
        ("none", SsrCipher::Dummy),
    ] {
        let (peer_port, _log) = ssr_peer(cipher, "ssr-password").await;
        let (target_port, received) = echo_target().await;
        let dir = scratch(&format!("ssr-{cipher_name}"));
        let (mut kernel, _) = start_kernel(
            &dir,
            &format!(
                "  - {{name: sr, type: ssr, server: 127.0.0.1, port: {peer_port}, cipher: {cipher_name}, password: ssr-password, protocol: origin, obfs: plain}}\n"
            ),
            "sr",
            limits(),
        )
        .unwrap();
        let payload = format!("tagged-ssr-{cipher_name}").into_bytes();
        let back = ssr_roundtrip(
            kernel.listen_addr(),
            &format!("127.0.0.1:{target_port}"),
            &payload,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!(back, payload, "{cipher_name}");
        wait_for(&received, payload.len() as u64).await;
        kernel.stop().unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssr_outbound_wrong_password_never_reaches_the_target() {
    use billow_kernel::proxies::SsrCipher;
    let (peer_port, log) = ssr_peer(SsrCipher::Aes256Cfb, "right-password").await;
    let (target_port, received) = echo_target().await;
    let dir = scratch("ssr-bad-password");
    let (mut kernel, _) = start_kernel(
        &dir,
        &format!(
            "  - {{name: sr, type: ssr, server: 127.0.0.1, port: {peer_port}, cipher: aes-256-cfb, password: wrong-password, protocol: origin, obfs: plain}}\n"
        ),
        "sr",
        limits(),
    )
    .unwrap();
    let error = ssr_roundtrip(
        kernel.listen_addr(),
        &format!("127.0.0.1:{target_port}"),
        b"nope",
        Duration::from_secs(5),
    )
    .await;
    assert!(error.is_err(), "wrong password must not relay: {error:?}");
    assert_eq!(received.load(Ordering::Relaxed), 0);
    // The peer either fails to read an address (garbage decrypt) or sees an
    // unknown address type; wait for that record so the assertion is not a
    // race with the peer's log write.
    let saw_rejection = wait_detail_prefix(&log, "address-error").await
        || wait_detail_prefix(&log, "bad-address-type").await;
    assert!(saw_rejection, "{:?}", detail(&log));
    assert!(
        !detail(&log).iter().any(|d| d.starts_with("target=")),
        "{:?}",
        detail(&log)
    );
    kernel.stop().unwrap();
}

// ---------------------------------------------------------------------------
// Sudoku (T17) differential vectors against the pinned Go codec.
//
// `tool/kernel-compat/peers/sudoku-vectors` builds the table from the locked
// `transport/sudoku` and exposes both directions: the pinned pure/packed
// encoders (so the Rust decoder can be checked) and the pinned decoders (so
// the Rust encoder can be checked). The test is `#[ignore]`d because it needs
// the `go` toolchain and the locked source tree; `family-peers.sh` runs it.
// ---------------------------------------------------------------------------

fn sudoku_vectors_dir() -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("../../..")
        .join("tool/kernel-compat/peers/sudoku-vectors")
}

fn go_run(args: &[&str]) -> String {
    let dir = sudoku_vectors_dir();
    let output = std::process::Command::new("go")
        .arg("run")
        .arg(".")
        .args(args)
        .current_dir(&dir)
        .output()
        .unwrap_or_else(|e| panic!("run go in {}: {e}", dir.display()));
    assert!(
        output.status.success(),
        "go {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn json_field<'a>(json: &'a str, name: &str) -> &'a str {
    let key = format!("\"{name}\":");
    let start = json.find(&key).unwrap_or_else(|| panic!("missing {name} in {json}")) + key.len();
    let rest = json[start..].trim_start();
    let end = rest.find([',', '\n', '}']).unwrap_or(rest.len());
    rest[..end].trim().trim_matches('"')
}

fn unhex(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let at = |b: u8| (b as char).to_digit(16).unwrap() as u8;
        out.push(at(pair[0]) * 16 + at(pair[1]));
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[ignore = "needs the Go toolchain and the locked source tree: run tool/kernel-compat/family-peers.sh"]
#[test]
fn sudoku_codec_matches_the_pinned_implementation() {
    use billow_kernel::outbound::sudoku::codec::Downlink;
    use billow_kernel::outbound::sudoku::table::{
        build_tables, padding_threshold, Encoder, WyRand,
    };

    let plain: Vec<u8> = (0..=255u8).chain([0u8, 255]).collect();
    let plain_hex = hex(&plain);
    let cases = [
        ("test-key-123", "prefer_entropy", ""),
        ("test-key-123", "prefer_ascii", ""),
        ("test-key-123", "up_ascii_down_entropy", ""),
        ("test-key-123", "prefer_entropy", "xpxvvpvv"),
        ("hex-0123456789abcdef", "prefer_entropy", ""),
    ];
    for (key, mode, custom) in cases {
        let mut args = vec![
            "-op", "vectors", "-key", key, "-mode", mode, "-plaintext", &plain_hex,
        ];
        if !custom.is_empty() {
            args.extend(["-custom", custom]);
        }
        let json = go_run(&args);
        let hint: u32 = json_field(&json, "hint").parse().expect("hint");
        let tables = build_tables(key, mode, Some(custom).filter(|c| !c.is_empty()))
            .unwrap_or_else(|e| panic!("{key}/{mode}/{custom}: {e}"));
        assert_eq!(tables.uplink.hint, hint, "{key}/{mode}/{custom}: table hint");

        // The pinned pure encoder is the uplink codec (client -> server), so
        // it decodes with the uplink table; the packed encoder writes the
        // downlink direction and decodes with the downlink table.
        let pure_wire = unhex(json_field(&json, "pureWire"));
        let mut decoder = billow_kernel::outbound::sudoku::codec::PureDownlink::new(
            tables.uplink.clone(),
        );
        let mut decoded = Vec::new();
        assert!(
            decoder.push(&pure_wire, &mut decoded),
            "{key}/{mode}/{custom}: pure wire rejected"
        );
        assert_eq!(decoded, plain, "{key}/{mode}/{custom}: pinned pure encode");

        let packed_wire = unhex(json_field(&json, "packedWire"));
        let mut decoder = billow_kernel::outbound::sudoku::codec::PackedDownlink::new(
            tables.downlink.clone(),
        );
        let mut decoded = Vec::new();
        assert!(
            decoder.push(&packed_wire, &mut decoded),
            "{key}/{mode}/{custom}: packed wire rejected"
        );
        assert_eq!(decoded, plain, "{key}/{mode}/{custom}: pinned packed encode");

        // Our encoder, with and without padding, must decode with the pinned
        // codec (which also proves the table is identical in both directions).
        for (min, max) in [(0u8, 0u8), (10, 30)] {
            let mut rng = WyRand::new(0x5eed);
            let threshold = padding_threshold(&mut rng, min, max);
            let mut encoder = Encoder::new(tables.uplink.clone(), WyRand::new(7), threshold);
            let wire = encoder.encode(&plain);
            let out = go_run(&[
                "-op",
                "decode",
                "-key",
                key,
                "-mode",
                mode,
                "-custom",
                custom,
                "-wire",
                &hex(&wire),
            ]);
            assert_eq!(
                json_field(&out, "plaintext"),
                plain_hex,
                "{key}/{mode}/{custom}: our pure encode with padding {min}-{max}"
            );
        }
    }
}
