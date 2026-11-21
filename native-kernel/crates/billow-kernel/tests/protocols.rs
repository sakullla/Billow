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
                            format!("password-hash-ok"),
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

// ---------------------------------------------------------------------------
// VLESS peer over TLS (optionally behind a WebSocket upgrade).
// ---------------------------------------------------------------------------

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
                    let response = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: binary\r\n\r\n");
                    stream.write_all(response.as_bytes()).await.unwrap();
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
                                format!("uuid-ok"),
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
                                    format!("uuid-ok"),
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
        detail(&log).iter().any(|d| d.starts_with("407")),
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
    let (action, _) = kernel.evaluate(&format!("127.0.0.1"), None);
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

#[test]
fn config_errors_tag_the_exact_proxy_field() {
    let yaml = "mixed-port: 1\nproxies:\n  - {name: s1, type: hysteria2, server: x, port: 1, up: 100}\nrules: ['MATCH,DIRECT']\n";
    let err = load_config(yaml, "t").unwrap_err();
    assert_eq!(err.tag(), "unsupported");
    assert!(matches!(err, ConfigError::Unsupported(_)));
    assert!(
        err.to_string()
            .contains("proxies[0] (name=s1, type=hysteria2)"),
        "{err}"
    );
}
