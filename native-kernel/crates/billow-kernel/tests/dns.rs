//! T22 DNS/hosts tests: pinned trie semantics, resolver fallback/policy,
//! UDP/TCP/DoT/DoH transports, fake-ip allocation and destination rebuild, and
//! engine rule-time resolution with `no-resolve`.

#[allow(dead_code)]
mod common;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use billow_kernel::dns::{EnhancedMode, HostValue, HostsConfig, HostsTable};
use billow_kernel::{load_config, Kernel, Limits};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

// ---------------------------------------------------------------------------
// Minimal DNS wire helpers (server side of the tests)
// ---------------------------------------------------------------------------

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn parse_question(raw: &[u8]) -> Option<(String, u16, usize)> {
    let mut offset = 12;
    let mut labels = Vec::new();
    loop {
        let len = *raw.get(offset)? as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        labels.push(
            std::str::from_utf8(raw.get(offset..offset + len)?)
                .ok()?
                .to_ascii_lowercase(),
        );
        offset += len;
    }
    let qtype = u16::from_be_bytes([*raw.get(offset)?, *raw.get(offset + 1)?]);
    offset += 4;
    Some((labels.join("."), qtype, offset))
}

/// Build an answer: `rcode` 0 with IPv4/IPv6 answers, 3 for NXDOMAIN.
fn build_answer(query: &[u8], ips: &[IpAddr], rcode: u8, ttl: u32) -> Vec<u8> {
    let (name, qtype, q_end) = match parse_question(query) {
        Some(parts) => parts,
        None => return Vec::new(),
    };
    let id = [query[0], query[1]];
    let mut out = Vec::new();
    out.extend_from_slice(&id);
    let mut flags = 0x8000u16 | 0x0400 | 0x0080 | rcode as u16;
    if rcode != 0 {
        flags |= 0x0003;
    }
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(ips.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&query[12..q_end]);
    let _ = qtype;
    for ip in ips {
        encode_name(&mut out, &name);
        match ip {
            IpAddr::V4(v4) => {
                out.extend_from_slice(&TYPE_A.to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes());
                out.extend_from_slice(&ttl.to_be_bytes());
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&TYPE_AAAA.to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes());
                out.extend_from_slice(&ttl.to_be_bytes());
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    out
}

type AnswerMap = Arc<HashMap<(String, u16), (Vec<IpAddr>, u8, u32)>>;

/// One UDP DNS fixture; queries without a scripted answer get NXDOMAIN.
struct UdpDns {
    port: u16,
    queries: Arc<AtomicU64>,
}

fn spawn_udp_dns(map: HashMap<(String, u16), (Vec<IpAddr>, u8, u32)>) -> UdpDns {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp dns");
    socket.set_nonblocking(true).expect("nonblocking");
    let port = socket.local_addr().unwrap().port();
    let queries = Arc::new(AtomicU64::new(0));
    let counter = queries.clone();
    let map: AnswerMap = Arc::new(map);
    std::mem::forget(tokio::spawn(async move {
        let socket = UdpSocket::from_std(socket).unwrap();
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                continue;
            };
            counter.fetch_add(1, Ordering::Relaxed);
            let Some((name, qtype, _)) = parse_question(&buf[..len]) else {
                continue;
            };
            let (ips, rcode, ttl) = map
                .get(&(name, qtype))
                .cloned()
                .unwrap_or_else(|| (Vec::new(), 3, 0));
            let answer = build_answer(&buf[..len], &ips, rcode, ttl);
            let _ = socket.send_to(&answer, peer).await;
        }
    }));
    UdpDns { port, queries }
}

/// A UDP DNS fixture that accepts queries and never answers (timeout case).
fn spawn_silent_udp() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind silent udp");
    socket.set_nonblocking(true).expect("nonblocking");
    let port = socket.local_addr().unwrap().port();
    std::mem::forget(tokio::spawn(async move {
        let socket = UdpSocket::from_std(socket).unwrap();
        let mut buf = vec![0u8; 4096];
        loop {
            let _ = socket.recv_from(&mut buf).await;
        }
    }));
    port
}

/// NXDOMAIN with an authority record (TTL 45): the pinned cache keeps the
/// negative answer for the SOA TTL.
fn spawn_negative_cache_dns() -> (u16, Arc<AtomicU64>) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind negative dns");
    socket.set_nonblocking(true).expect("nonblocking");
    let port = socket.local_addr().unwrap().port();
    let queries = Arc::new(AtomicU64::new(0));
    let counter = queries.clone();
    std::mem::forget(tokio::spawn(async move {
        let socket = UdpSocket::from_std(socket).unwrap();
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                continue;
            };
            counter.fetch_add(1, Ordering::Relaxed);
            let Some((name, _qtype, q_end)) = parse_question(&buf[..len]) else {
                continue;
            };
            let mut out = Vec::new();
            out.extend_from_slice(&buf[..2]);
            out.extend_from_slice(&0x8183u16.to_be_bytes()); // QR|RD|RA, NXDOMAIN
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes());
            out.extend_from_slice(&buf[12..q_end]);
            encode_name(&mut out, &name);
            out.extend_from_slice(&2u16.to_be_bytes()); // NS
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&45u32.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.push(0); // root name as the NS target
            let _ = socket.send_to(&out, peer).await;
        }
    }));
    (port, queries)
}

/// A TCP DNS fixture answering each length-prefixed query.
fn spawn_tcp_dns(map: HashMap<(String, u16), (Vec<IpAddr>, u8, u32)>) -> u16 {
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp dns");
    let port = std_listener.local_addr().unwrap().port();
    std_listener.set_nonblocking(true).unwrap();
    let map: AnswerMap = Arc::new(map);
    std::mem::forget(tokio::spawn(async move {
        let listener = TcpListener::from_std(std_listener).unwrap();
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let map = map.clone();
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 2];
                    if stream.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
                    if stream.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    let (ips, rcode, ttl) = parse_question(&body)
                        .and_then(|(name, qtype, _)| map.get(&(name, qtype)).cloned())
                        .unwrap_or_else(|| (Vec::new(), 3, 0));
                    let answer = build_answer(&body, &ips, rcode, ttl);
                    let _ = stream.write_all(&(answer.len() as u16).to_be_bytes()).await;
                    let _ = stream.write_all(&answer).await;
                }
            });
        }
    }));
    port
}

fn answer_map(entries: &[(&str, IpAddr)]) -> HashMap<(String, u16), (Vec<IpAddr>, u8, u32)> {
    entries
        .iter()
        .map(|(name, ip)| {
            let qtype = if ip.is_ipv4() { TYPE_A } else { TYPE_AAAA };
            (
                (name.to_string(), qtype),
                (vec![*ip], 0, 60),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// TLS fixture for DoT/DoH
// ---------------------------------------------------------------------------

struct CertPair {
    dir: std::path::PathBuf,
    cert_pem: std::path::PathBuf,
    key_pem: std::path::PathBuf,
    ca_pem: std::path::PathBuf,
}

fn make_cert() -> Option<CertPair> {
    use std::process::{Command, Stdio};
    let dir = std::env::temp_dir().join(format!(
        "billow-dns-cert-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).ok()?;
    let ca_key = dir.join("ca.key");
    let ca_pem = dir.join("ca.pem");
    let key_pem = dir.join("server.key");
    let cert_pem = dir.join("server.pem");
    let csr = dir.join("server.csr");
    let ext = dir.join("server.ext");
    std::fs::write(
        &ext,
        "subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n",
    )
    .ok()?;
    let openssl = |args: &[&std::ffi::OsStr]| -> bool {
        Command::new("openssl")
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
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
        "/CN=billow-dns-test-ca".as_ref(),
        "-addext".as_ref(),
        "basicConstraints=critical,CA:TRUE".as_ref(),
    ]) && openssl(&[
        "req".as_ref(),
        "-newkey".as_ref(),
        "rsa:2048".as_ref(),
        "-nodes".as_ref(),
        "-keyout".as_ref(),
        key_pem.as_os_str(),
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
        cert_pem.as_os_str(),
        "-days".as_ref(),
        "1".as_ref(),
        "-extfile".as_ref(),
        ext.as_os_str(),
    ]);
    if !ok {
        return None;
    }
    Some(CertPair {
        dir,
        cert_pem,
        key_pem,
        ca_pem,
    })
}

fn tls_acceptor(cert: &CertPair) -> tokio_rustls::TlsAcceptor {
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    let pem = std::fs::read(&cert.cert_pem).unwrap();
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::BufReader::new(&pem[..]))
        .flatten()
        .collect();
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(&cert.key_pem).unwrap(),
    ))
    .unwrap()
    .expect("private key");
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key as PrivateKeyDer<'static>)
        .expect("server tls config");
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

fn spawn_dot_dns(cert: &CertPair, map: HashMap<(String, u16), (Vec<IpAddr>, u8, u32)>) -> u16 {
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = std_listener.local_addr().unwrap().port();
    std_listener.set_nonblocking(true).unwrap();
    let acceptor = tls_acceptor(cert);
    let map: AnswerMap = Arc::new(map);
    std::mem::forget(tokio::spawn(async move {
        let listener = TcpListener::from_std(std_listener).unwrap();
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            let map = map.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                loop {
                    let mut len = [0u8; 2];
                    if stream.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
                    if stream.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    let (ips, rcode, ttl) = parse_question(&body)
                        .and_then(|(name, qtype, _)| map.get(&(name, qtype)).cloned())
                        .unwrap_or_else(|| (Vec::new(), 3, 0));
                    let answer = build_answer(&body, &ips, rcode, ttl);
                    let _ = stream.write_all(&(answer.len() as u16).to_be_bytes()).await;
                    let _ = stream.write_all(&answer).await;
                }
            });
        }
    }));
    port
}

fn spawn_doh_dns(cert: &CertPair, map: HashMap<(String, u16), (Vec<IpAddr>, u8, u32)>) -> u16 {
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = std_listener.local_addr().unwrap().port();
    std_listener.set_nonblocking(true).unwrap();
    let acceptor = tls_acceptor(cert);
    let map: AnswerMap = Arc::new(map);
    std::mem::forget(tokio::spawn(async move {
        let listener = TcpListener::from_std(std_listener).unwrap();
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            let map = map.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut request = Vec::new();
                let mut buf = [0u8; 2048];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            request.extend_from_slice(&buf[..n]);
                            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                let head = String::from_utf8_lossy(&request);
                let path = head
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("");
                let encoded = path.split("dns=").nth(1).unwrap_or("");
                let Some(body) = base64_url_decode(encoded) else {
                    return;
                };
                let (ips, rcode, ttl) = parse_question(&body)
                    .and_then(|(name, qtype, _)| map.get(&(name, qtype)).cloned())
                    .unwrap_or_else(|| (Vec::new(), 3, 0));
                let answer = build_answer(&body, &ips, rcode, ttl);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    answer.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(&answer).await;
                let _ = stream.shutdown().await;
            });
        }
    }));
    port
}

fn spawn_plain_doh_dns(map: HashMap<(String, u16), (Vec<IpAddr>, u8, u32)>) -> u16 {
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = std_listener.local_addr().unwrap().port();
    std_listener.set_nonblocking(true).unwrap();
    let map: AnswerMap = Arc::new(map);
    std::mem::forget(tokio::spawn(async move {
        let listener = TcpListener::from_std(std_listener).unwrap();
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let map = map.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 2048];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            request.extend_from_slice(&buf[..n]);
                            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                let head = String::from_utf8_lossy(&request);
                let path = head
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("");
                let encoded = path.split("dns=").nth(1).unwrap_or("");
                let Some(body) = base64_url_decode(encoded) else {
                    return;
                };
                let (ips, rcode, ttl) = parse_question(&body)
                    .and_then(|(name, qtype, _)| map.get(&(name, qtype)).cloned())
                    .unwrap_or_else(|| (Vec::new(), 3, 0));
                let answer = build_answer(&body, &ips, rcode, ttl);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    answer.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(&answer).await;
                let _ = stream.shutdown().await;
            });
        }
    }));
    port
}

fn base64_url_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bits = 0u32;
    let mut count = 0u8;
    let mut out = Vec::new();
    for byte in input.bytes() {
        let value = TABLE.iter().position(|candidate| *candidate == byte)? as u32;
        bits = (bits << 6) | value;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Configuration parsing
// ---------------------------------------------------------------------------

#[test]
fn parses_dns_and_hosts_like_the_pinned_defaults() {
    let loaded = load_config(
        "mixed-port: 18990\ndns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver: ['udp://1.1.1.1', 'tls://dns.google']\n  fallback: ['tcp://9.9.9.9:53']\n  fallback-filter: {geoip: false, ipcidr: ['10.0.0.0/8'], domain: ['+.fallback.test']}\n  nameserver-policy:\n    '+.policy.test': ['udp://8.8.4.4']\n  proxy-server-nameserver: ['https://1.0.0.1/dns-query']\n  direct-nameserver: ['tcp://1.1.1.1:53']\n  fake-ip-range: 198.18.0.1/16\n  fake-ip-filter: ['+.filter.test']\n  fake-ip-ttl: 7\nhosts:\n  example.test: 127.0.0.1\n  multi.test: [10.0.0.1, 10.0.0.2]\n  alias.test: canonical.test\n",
        "t.yaml",
    )
    .expect("pinned DNS shape loads");
    let dns = &loaded.config.dns;
    assert!(dns.enable);
    assert_eq!(dns.enhanced_mode, EnhancedMode::FakeIp);
    assert_eq!(dns.nameserver.len(), 2);
    assert_eq!(dns.nameserver[1].host, "dns.google");
    assert_eq!(dns.nameserver[1].port, 853);
    assert_eq!(dns.fallback[0].port, 53);
    assert!(!dns.fallback_filter.geoip);
    assert_eq!(dns.fallback_filter.geoip_code, "CN");
    assert_eq!(dns.nameserver_policy.len(), 1);
    assert_eq!(dns.proxy_server_nameserver[0].port, 443);
    assert_eq!(dns.direct_nameserver[0].host, "1.1.1.1");
    assert_eq!(dns.fake_ip_ttl, 7);
    // Omitted default-nameserver uses the pinned defaults.
    assert_eq!(dns.default_nameserver.len(), 4);
    assert_eq!(loaded.config.hosts.entries.len(), 3);
    assert!(loaded.config.hosts.entries.iter().any(|(domain, value)| {
        domain == "alias.test" && value == &HostValue::Domain("canonical.test".into())
    }));
}

#[test]
fn rejects_unimplemented_dns_shapes_by_name() {
    let cases = [
        (
            "quic://dns.example",
            "DoQ",
        ),
        (
            "system://",
            "system://",
        ),
        (
            "https://dns.example/dns-query#h3=true",
            "h3=true",
        ),
        (
            "https://dns.example/dns-query#ecs=1.2.3.0/24",
            "client subnet",
        ),
        (
            "https://dns.example/dns-query#PROXY",
            "routing through proxy",
        ),
    ];
    for (nameserver, needle) in cases {
        for key in ["nameserver", "fallback"] {
            let yaml = format!(
                "mixed-port: 18990\ndns:\n  enable: true\n  {key}: ['{nameserver}']\n"
            );
            let error = load_config(&yaml, "t").expect_err(nameserver);
            assert_eq!(error.tag(), "unsupported", "{nameserver}: {error}");
            assert!(
                error.to_string().contains(needle),
                "{nameserver}: {error}"
            );
        }
    }
    let rejects = |yaml: &str, needle: &str| {
        let error = load_config(yaml, "t").expect_err(yaml);
        assert!(
            error.to_string().contains(needle),
            "{yaml}: {error}"
        );
    };
    rejects(
        "mixed-port: 18990\ndns:\n  enable: true\n  nameserver: [1.1.1.1]\n  fake-ip-filter-mode: rule\n  enhanced-mode: fake-ip\n",
        "rule mode",
    );
    rejects(
        "mixed-port: 18990\ndns:\n  enable: true\n  nameserver: [1.1.1.1]\n  respect-rules: true\n",
        "proxy-server-nameserver",
    );
    rejects(
        "mixed-port: 18990\ndns:\n  enable: true\n  nameserver: [1.1.1.1]\n  respect-rules: true\n  proxy-server-nameserver: [1.0.0.1]\n",
        "UDP nameserver",
    );
    rejects(
        "mixed-port: 18990\ndns:\n  enable: true\n  nameserver: [1.1.1.1]\n  enhanced-mode: fake-ip\n  fake-ip-range:\n",
        "fake-ip-range",
    );
    rejects(
        "mixed-port: 18990\ndns:\n  enable: true\n  nameserver: [1.1.1.1]\n  default-nameserver: [dns.google]\n",
        "pure IP",
    );
    rejects(
        "mixed-port: 18990\ndns:\n  enable: false\n  enhanced-mode: bogus\n",
        "enhanced-mode",
    );
    rejects(
        "mixed-port: 18990\nhosts:\n  lan.test: lan\n",
        "'lan'",
    );
    rejects(
        "mixed-port: 18990\nhosts:\n  a.test: b.test\n  b.test: a.test\n",
        "cycle",
    );
    rejects(
        "mixed-port: 18990\nhosts:\n  multi.test: [1.2.3.4, nope.test]\n",
        "not an IP",
    );
}

// ---------------------------------------------------------------------------
// hosts trie
// ---------------------------------------------------------------------------

fn hosts_table(entries: &[(&str, HostValue)]) -> HostsTable {
    let mut config = HostsConfig::default();
    for (domain, value) in entries {
        config.entries.push((domain.to_string(), value.clone()));
    }
    HostsTable::build(&config, false).expect("hosts table")
}

#[test]
fn hosts_patterns_follow_the_pinned_trie_priority() {
    let ip = |last: u8| IpAddr::V4(Ipv4Addr::new(10, 0, 0, last));
    let table = hosts_table(&[
        ("exact.test", HostValue::Ips(vec![ip(1)])),
        ("+.suffix.test", HostValue::Ips(vec![ip(2)])),
        ("*.wild.test", HostValue::Ips(vec![ip(3)])),
        (".only.test", HostValue::Ips(vec![ip(4)])),
        ("deep.*.seg.test", HostValue::Ips(vec![ip(5)])),
        ("chain.test", HostValue::Domain("exact.test".into())),
        ("dead.end", HostValue::Domain("nowhere.test".into())),
    ]);
    let lookup = |host: &str| {
        table
            .search(host, false)
            .and_then(|(value, matched)| matched.then(|| value.ips().first().copied()))
            .flatten()
    };
    assert_eq!(lookup("localhost"), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert_eq!(lookup("exact.test"), Some(ip(1)));
    assert_eq!(lookup("suffix.test"), Some(ip(2)));
    assert_eq!(lookup("a.b.suffix.test"), Some(ip(2)));
    assert_eq!(lookup("wild.test"), None);
    assert_eq!(lookup("a.wild.test"), Some(ip(3)));
    assert_eq!(lookup("a.b.wild.test"), None);
    assert_eq!(lookup("only.test"), None);
    assert_eq!(lookup("a.only.test"), Some(ip(4)));
    assert_eq!(lookup("a.b.only.test"), Some(ip(4)));
    assert_eq!(lookup("deep.x.seg.test"), Some(ip(5)));
    assert_eq!(lookup("deep.x.y.seg.test"), None);
    // A domain-valued entry is followed to its IPs for an IP request.
    assert_eq!(lookup("chain.test"), Some(ip(1)));
    assert_eq!(lookup("dead.end"), None);
    // A domain request sees the mapping itself.
    let (_value, matched) = table.search("chain.test", true).expect("domain entry");
    assert!(matched);
    assert_eq!(
        table.search("chain.test", true).unwrap().0,
        HostValue::Domain("exact.test".into())
    );
}

// ---------------------------------------------------------------------------
// Resolver behaviour against controlled DNS servers
// ---------------------------------------------------------------------------

fn start_kernel(yaml: &str) -> Kernel {
    let (kernel, _warnings) = Kernel::start_from_yaml(yaml, None, Limits::default())
        .expect("kernel with DNS starts");
    kernel
}

fn dns_block(nameservers: &str, extra: &str) -> String {
    format!(
        "dns:\n  enable: true\n  ipv6: false\n  use-hosts: true\n  nameserver: [{nameservers}]\n{extra}"
    )
}

#[tokio::test]
async fn udp_resolution_and_cache_ttl() {
    let server = spawn_udp_dns(answer_map(&[("cached.test", IpAddr::V4(Ipv4Addr::new(10, 9, 8, 7)))]));
    let yaml = format!(
        "mixed-port: {}\n{}",
        free_port(),
        dns_block(&format!("udp://127.0.0.1:{}", server.port), "")
    );
    let mut kernel = start_kernel(&yaml);
    let dns = kernel.dns().expect("DNS runtime");
    assert_eq!(
        dns.resolve_one("cached.test").await,
        Some(IpAddr::V4(Ipv4Addr::new(10, 9, 8, 7)))
    );
    // Second lookup is answered from the cache: one upstream query only.
    assert_eq!(
        dns.resolve_one("cached.test").await,
        Some(IpAddr::V4(Ipv4Addr::new(10, 9, 8, 7)))
    );
    assert_eq!(server.queries.load(Ordering::Relaxed), 1);
    // NXDOMAIN is an error the caller can observe, not an empty success.
    assert_eq!(dns.resolve_one("missing.test").await, None);
    kernel.stop().ok();
}

#[tokio::test]
async fn negative_answers_cache_through_the_authority_ttl() {
    let (port, queries) = spawn_negative_cache_dns();
    let yaml = format!(
        "mixed-port: {}\n{}",
        free_port(),
        dns_block(&format!("udp://127.0.0.1:{port}"), "")
    );
    let mut kernel = start_kernel(&yaml);
    let dns = kernel.dns().expect("dns");
    assert_eq!(dns.resolve_one("negative.test").await, None);
    assert_eq!(dns.resolve_one("negative.test").await, None);
    assert_eq!(
        queries.load(Ordering::Relaxed),
        1,
        "the NXDOMAIN answer is cached for the authority TTL"
    );
    kernel.stop().ok();
}

#[tokio::test]
async fn tcp_transport() {
    // Only the TCP server is configured: pinned `batchExchange` races every
    // main server and takes the first answer, so mixing in a UDP server with
    // no answer for this name would make the outcome a race.
    let tcp_port = spawn_tcp_dns(answer_map(&[("tcp.test", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))]));
    let yaml = format!(
        "mixed-port: {}\n{}",
        free_port(),
        dns_block(&format!("tcp://127.0.0.1:{tcp_port}"), "")
    );
    let mut kernel = start_kernel(&yaml);
    let dns = kernel.dns().expect("DNS runtime");
    assert_eq!(
        dns.resolve_one("tcp.test").await,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
    );
    kernel.stop().ok();
}

#[tokio::test]
async fn plain_http_doh_transport() {
    let port = spawn_plain_doh_dns(answer_map(&[(
        "http-doh.test",
        IpAddr::V4(Ipv4Addr::new(10, 4, 0, 1)),
    )]));
    let yaml = format!(
        "mixed-port: {}\n{}",
        free_port(),
        dns_block(&format!("http://127.0.0.1:{port}/dns-query"), "")
    );
    let mut kernel = start_kernel(&yaml);
    assert_eq!(
        kernel.dns().expect("dns").resolve_one("http-doh.test").await,
        Some(IpAddr::V4(Ipv4Addr::new(10, 4, 0, 1)))
    );
    kernel.stop().ok();
}

#[tokio::test]
async fn nameserver_policy_selects_the_configured_server() {
    let main = spawn_udp_dns(answer_map(&[("default.test", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))]));
    let policy = spawn_udp_dns(answer_map(&[
        ("policy.test", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))),
        ("deep.policy.test", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))),
    ]));
    let yaml = format!(
        "mixed-port: {}\n{}  nameserver-policy:\n    '+.policy.test': ['udp://127.0.0.1:{}']\n",
        free_port(),
        dns_block(&format!("udp://127.0.0.1:{}", main.port), ""),
        policy.port
    );
    let mut kernel = start_kernel(&yaml);
    let dns = kernel.dns().expect("DNS runtime");
    // `+.policy.test` matches the name and every subdomain, and the policy
    // server answers instead of the main list.
    assert_eq!(
        dns.resolve_one("policy.test").await,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)))
    );
    assert_eq!(
        dns.resolve_one("deep.policy.test").await,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)))
    );
    assert_eq!(
        dns.resolve_one("default.test").await,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    );
    assert_eq!(
        dns.policy_servers_for("deep.policy.test"),
        vec![format!("udp://127.0.0.1:{}", policy.port)]
    );
    kernel.stop().ok();
}

#[tokio::test]
async fn fallback_ip_and_domain_filters() {
    let main = spawn_udp_dns(HashMap::from([
        (
            ("filtered.test".to_string(), TYPE_A),
            (vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))], 0, 60),
        ),
        (
            ("public.test".to_string(), TYPE_A),
            (vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))], 0, 60),
        ),
        (
            ("only.test".to_string(), TYPE_A),
            (vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))], 0, 60),
        ),
    ]));
    let fallback = spawn_udp_dns(HashMap::from([
        (
            ("filtered.test".to_string(), TYPE_A),
            (vec![IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7))], 0, 60),
        ),
        (
            ("only.test".to_string(), TYPE_A),
            (vec![IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6))], 0, 60),
        ),
    ]));
    let yaml = format!(
        "mixed-port: {}\n{}  fallback: ['udp://127.0.0.1:{}']\n  fallback-filter:\n    geoip: false\n    ipcidr: ['1.0.0.0/8']\n    domain: ['+.only.test']\n",
        free_port(),
        dns_block(&format!("udp://127.0.0.1:{}", main.port), ""),
        fallback.port
    );
    let mut kernel = start_kernel(&yaml);
    let dns = kernel.dns().expect("DNS runtime");
    // A main answer inside `ipcidr` falls back.
    assert_eq!(
        dns.resolve_one("filtered.test").await,
        Some(IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7)))
    );
    // A public main answer wins without the fallback answer.
    assert_eq!(
        dns.resolve_one("public.test").await,
        Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
    );
    // A domain filter sends the query to the fallback only.
    assert_eq!(
        dns.resolve_one("only.test").await,
        Some(IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6)))
    );
    kernel.stop().ok();
}

#[tokio::test]
async fn dot_and_doh_transports_verify_the_server_certificate() {
    let Some(cert) = make_cert() else {
        eprintln!("skipping DoT/DoH: the openssl CLI is unavailable");
        return;
    };
    let map = answer_map(&[
        ("dot.test", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1))),
        ("doh.test", IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2))),
    ]);
    let dot = spawn_dot_dns(&cert, map.clone());
    let doh = spawn_doh_dns(&cert, map);
    let ca = cert.ca_pem.display().to_string();
    let yaml_dot = format!(
        "mixed-port: {}\ntls:\n  custom-cert: ['{ca}']\n{}",
        free_port(),
        dns_block(&format!("tls://127.0.0.1:{}", dot), "")
    );
    let mut kernel = start_kernel(&yaml_dot);
    assert_eq!(
        kernel.dns().expect("dns").resolve_one("dot.test").await,
        Some(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1)))
    );
    kernel.stop().ok();

    let yaml_doh = format!(
        "mixed-port: {}\ntls:\n  custom-cert: ['{ca}']\n{}",
        free_port(),
        dns_block(&format!("https://127.0.0.1:{doh}/dns-query"), "")
    );
    let mut kernel = start_kernel(&yaml_doh);
    assert_eq!(
        kernel.dns().expect("dns").resolve_one("doh.test").await,
        Some(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)))
    );
    kernel.stop().ok();
    let _ = std::fs::remove_dir_all(&cert.dir);
}

#[tokio::test]
async fn timeout_is_reported_and_the_call_returns() {
    let port = spawn_silent_udp();
    let yaml = format!(
        "mixed-port: {}\n{}",
        free_port(),
        dns_block(&format!("udp://127.0.0.1:{port}"), "")
    );
    let mut kernel = start_kernel(&yaml);
    let dns = kernel.dns().expect("dns");
    let started = std::time::Instant::now();
    let result = dns.resolve_one("slow.test").await;
    assert_eq!(result, None);
    assert!(
        started.elapsed() >= Duration::from_secs(4),
        "the pinned 5s DNS timeout applies"
    );
    kernel.stop().ok();
}

// ---------------------------------------------------------------------------
// fake-ip and the DNS server
// ---------------------------------------------------------------------------

async fn dns_query_tcp(addr: SocketAddr, name: &str, qtype: u16) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect dns tcp");
    let mut query = Vec::new();
    query.extend_from_slice(&0x1234u16.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    encode_name(&mut query, name);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    stream.write_all(&(query.len() as u16).to_be_bytes()).await.unwrap();
    stream.write_all(&query).await.unwrap();
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await.expect("dns length");
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).await.expect("dns body");
    body
}

fn first_answer_ip(message: &[u8]) -> Option<IpAddr> {
    // Header + question, then the first answer's RDATA.
    let (_name, _qtype, q_end) = parse_question(message)?;
    let mut offset = q_end;
    // Answer name: pointer (0xc0) or labels.
    if message.get(offset).copied()? & 0xc0 == 0xc0 {
        offset += 2;
    } else {
        loop {
            let len = *message.get(offset)? as usize;
            offset += 1;
            if len == 0 {
                break;
            }
            offset += len;
        }
    }
    let rtype = u16::from_be_bytes([*message.get(offset)?, *message.get(offset + 1)?]);
    let rdlength = u16::from_be_bytes([*message.get(offset + 8)?, *message.get(offset + 9)?]) as usize;
    offset += 10;
    let data = message.get(offset..offset + rdlength)?;
    match rtype {
        TYPE_A if rdlength == 4 => Some(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3]))),
        TYPE_AAAA if rdlength == 16 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(data);
            Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// Read a possibly-compressed name; returns the name and the next offset in
/// the containing message.
fn read_answer_name(message: &[u8], start: usize) -> (String, usize) {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut end = start;
    let mut jumped = false;
    for _ in 0..64 {
        let len = match message.get(cursor) {
            Some(len) => *len as usize,
            None => break,
        };
        if len == 0 {
            if !jumped {
                end = cursor + 1;
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            if !jumped {
                end = cursor + 2;
            }
            let pointer =
                ((len & 0x3f) << 8) | message.get(cursor + 1).copied().unwrap_or(0) as usize;
            cursor = pointer;
            jumped = true;
            continue;
        }
        let begin = cursor + 1;
        let stop = begin + len;
        if stop > message.len() {
            break;
        }
        labels.push(String::from_utf8_lossy(&message[begin..stop]).to_ascii_lowercase());
        cursor = stop;
    }
    (labels.join("."), end)
}

/// All answer records as `(owner, rtype, ttl, data)`: A/AAAA data is the
/// address, CNAME data is the target.
fn parse_answers(message: &[u8]) -> Vec<(String, u16, u32, String)> {
    let Some((_name, _qtype, q_end)) = parse_question(message) else {
        return Vec::new();
    };
    let ancount = u16::from_be_bytes([message[6], message[7]]) as usize;
    let mut offset = q_end;
    let mut out = Vec::new();
    for _ in 0..ancount {
        let (owner, next) = read_answer_name(message, offset);
        offset = next;
        let Some(header) = message.get(offset..offset + 10) else {
            break;
        };
        let rtype = u16::from_be_bytes([header[0], header[1]]);
        let ttl = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let rdlength = u16::from_be_bytes([header[8], header[9]]) as usize;
        offset += 10;
        let data_start = offset;
        let data = match rtype {
            TYPE_A if rdlength == 4 => {
                let d = &message[data_start..data_start + 4];
                format!("{}.{}.{}.{}", d[0], d[1], d[2], d[3])
            }
            TYPE_AAAA if rdlength == 16 => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&message[data_start..data_start + 16]);
                std::net::Ipv6Addr::from(bytes).to_string()
            }
            TYPE_CNAME => read_answer_name(message, data_start).0,
            _ => String::new(),
        };
        offset = data_start + rdlength;
        out.push((owner, rtype, ttl, data));
    }
    out
}

const TYPE_CNAME: u16 = 5;

#[tokio::test]
async fn fake_ip_pool_ttl_filter_and_dns_server() {
    let upstream = spawn_udp_dns(answer_map(&[
        ("fake.test", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        ("real.test", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
    ]));
    let listen = free_port();
    let yaml = format!(
        "mixed-port: {}\ndns:\n  enable: true\n  enhanced-mode: fake-ip\n  listen: 127.0.0.1:{listen}\n  fake-ip-range: 198.18.0.1/16\n  fake-ip-ttl: 3\n  fake-ip-filter: ['real.test']\n  nameserver: ['udp://127.0.0.1:{}']\n",
        free_port(),
        upstream.port
    );
    let mut kernel = start_kernel(&yaml);
    let dns = kernel.dns().expect("dns");
    let addr = dns.listen_addr().expect("dns.listen bound");
    assert_eq!(addr, format!("127.0.0.1:{listen}").parse().unwrap());

    let first = dns_query_tcp(addr, "fake.test", TYPE_A).await;
    assert_eq!(
        first_answer_ip(&first),
        Some(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 4)))
    );
    // The answer TTL is the configured fake-ip-ttl.
    assert_eq!(u32::from_be_bytes([first[first.len() - 10], first[first.len() - 9], first[first.len() - 8], first[first.len() - 7]]), 3);
    // Stable mapping and sequential allocation.
    assert_eq!(
        first_answer_ip(&dns_query_tcp(addr, "fake.test", TYPE_A).await),
        Some(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 4)))
    );
    assert_eq!(
        first_answer_ip(&dns_query_tcp(addr, "other.test", TYPE_A).await),
        Some(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 5)))
    );
    // A filtered domain gets the real answer.
    assert_eq!(
        first_answer_ip(&dns_query_tcp(addr, "real.test", TYPE_A).await),
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
    );
    // AAAA is empty because dns.ipv6 is false.
    assert_eq!(
        first_answer_ip(&dns_query_tcp(addr, "fake.test", TYPE_AAAA).await),
        None
    );
    let fake = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 4));
    assert!(dns.is_fake_ip(fake));
    assert_eq!(dns.find_host_by_ip(fake).as_deref(), Some("fake.test"));
    assert_eq!(
        dns.pre_handle("", Some(fake)),
        Ok(("fake.test".to_string(), None))
    );
    assert_eq!(
        dns.pre_handle("", Some(IpAddr::V4(Ipv4Addr::new(198, 18, 9, 9)))),
        Err("fake DNS record 198.18.9.9 missing".to_string())
    );
    kernel.stop().ok();
}

// ---------------------------------------------------------------------------
// Engine integration: rule-time resolution, no-resolve, fake-ip rebuild
// ---------------------------------------------------------------------------

#[tokio::test]
async fn engine_resolves_ip_rules_and_honours_no_resolve() {
    let echo = spawn_endpoint(EchoMode::Echo).await;
    let upstream = spawn_udp_dns(answer_map(&[(
        "loop.test",
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    )]));
    let nameserver = format!("udp://127.0.0.1:{}", upstream.port);
    let mixed = free_port();
    let yaml = format!(
        "mixed-port: {mixed}\ndns:\n  enable: true\n  nameserver: ['{nameserver}']\nrules:\n  - 'IP-CIDR,127.0.0.0/8,REJECT'\n  - 'MATCH,DIRECT'\n"
    );
    let mut kernel = start_kernel(&yaml);
    let proxy: SocketAddr = format!("127.0.0.1:{mixed}").parse().unwrap();
    let (stream, status) = http_connect(proxy, &format!("loop.test:{}", echo.port))
        .await
        .expect("connect reply");
    assert!(status.contains("403"), "IP-CIDR after DNS must reject: {status}");
    drop(stream);
    assert_eq!(
        upstream.queries.load(Ordering::Relaxed),
        1,
        "the rule-time resolution queried the configured nameserver once"
    );

    // `no-resolve` leaves the rule unresolved, so the IP-CIDR does not match
    // even though the resolve at dial time would return 127.0.0.1.
    let mixed_no = free_port();
    let yaml = format!(
        "mixed-port: {mixed_no}\ndns:\n  enable: true\n  nameserver: ['{nameserver}']\nrules:\n  - 'IP-CIDR,127.0.0.0/8,REJECT,no-resolve'\n  - 'MATCH,DIRECT'\n"
    );
    let mut kernel_no = start_kernel(&yaml);
    let proxy: SocketAddr = format!("127.0.0.1:{mixed_no}").parse().unwrap();
    let (mut stream, status) = http_connect(proxy, &format!("loop.test:{}", echo.port))
        .await
        .expect("connect reply");
    assert!(status.contains("200"), "no-resolve must skip the IP rule: {status}");
    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
    kernel.stop().ok();
    kernel_no.stop().ok();
}

#[tokio::test]
async fn hosts_resolve_ip_rules_without_dns() {
    let echo = spawn_endpoint(EchoMode::Echo).await;
    let mixed = free_port();
    let yaml = format!(
        "mixed-port: {mixed}\nhosts:\n  hosts-rule.test: 127.0.0.1\nrules:\n  - 'IP-CIDR,127.0.0.0/8,REJECT'\n  - 'MATCH,DIRECT'\n"
    );
    let mut kernel = start_kernel(&yaml);
    assert!(kernel.dns().is_none());
    let proxy: SocketAddr = format!("127.0.0.1:{mixed}").parse().unwrap();
    let (_stream, status) = http_connect(proxy, &format!("hosts-rule.test:{}", echo.port))
        .await
        .expect("connect reply");
    assert!(
        status.contains("403"),
        "the configured hosts entry feeds IP rules even without dns.enable: {status}"
    );
    kernel.stop().ok();
}

#[tokio::test]
async fn fake_ip_destination_is_rebuilt_to_its_host() {
    let echo = spawn_endpoint(EchoMode::Echo).await;
    let upstream = spawn_udp_dns(answer_map(&[(
        "fake-host.test",
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    )]));
    let listen = free_port();
    let mixed = free_port();
    let yaml = format!(
        "mixed-port: {mixed}\ndns:\n  enable: true\n  enhanced-mode: fake-ip\n  listen: 127.0.0.1:{listen}\n  fake-ip-range: 198.18.0.1/16\n  nameserver: ['udp://127.0.0.1:{}']\nrules:\n  - 'MATCH,DIRECT'\n",
        upstream.port
    );
    let mut kernel = start_kernel(&yaml);
    let dns_addr: SocketAddr = format!("127.0.0.1:{listen}").parse().unwrap();
    let answer = dns_query_tcp(dns_addr, "fake-host.test", TYPE_A).await;
    let fake = first_answer_ip(&answer).expect("fake answer");
    assert!(kernel.dns().unwrap().is_fake_ip(fake));
    assert_eq!(
        kernel.dns().unwrap().pre_handle("", Some(fake)),
        Ok(("fake-host.test".to_string(), None))
    );
    assert_eq!(
        kernel.dns().unwrap().resolve_one("fake-host.test").await,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
    );
    let proxy: SocketAddr = format!("127.0.0.1:{mixed}").parse().unwrap();
    let (mut stream, status) = http_connect(proxy, &format!("{fake}:{}", echo.port))
        .await
        .expect("connect reply");
    assert!(
        status.contains("200"),
        "the fake IP is rebuilt to fake-host.test and resolved to loopback: {status}"
    );
    stream.write_all(b"fake").await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"fake");
    kernel.stop().ok();
}

// ---------------------------------------------------------------------------
// dns.listen hosts middleware in every enhanced mode
// ---------------------------------------------------------------------------

/// Query the listener with a hard timeout: before T22-A2 the enhancer mutex was
/// locked twice on the hosts path, so the first hosts query deadlocked the
/// listener task and every later query hung too.
async fn listener_query(addr: SocketAddr, name: &str, qtype: u16) -> Option<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(3), dns_query_tcp(addr, name, qtype))
        .await
        .ok()
}

/// A wedged DNS listener also wedges `Kernel::stop` (its runtime thread is
/// blocked on the mutex), so a regression leak is better than hanging the
/// whole test binary in the panic-unwind `Drop`.
async fn expect_listener(
    addr: SocketAddr,
    kernel: Kernel,
    name: &str,
    qtype: u16,
) -> (Kernel, Vec<u8>) {
    match listener_query(addr, name, qtype).await {
        Some(answer) => (kernel, answer),
        None => {
            std::mem::forget(kernel);
            panic!("query {name}/{qtype} timed out (DNS listener deadlock)")
        }
    }
}

#[tokio::test]
async fn hosts_answers_on_the_listener_in_every_enhanced_mode() {
    let upstream = spawn_udp_dns(answer_map(&[(
        "upstream.test",
        IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5)),
    )]));
    for mode in ["normal", "redir-host", "fake-ip"] {
        let listen = free_port();
        let mut yaml = format!(
            "mixed-port: {}\nhosts:\n  host-only.test: 1.2.3.4\ndns:\n  enable: true\n  enhanced-mode: {mode}\n  listen: 127.0.0.1:{listen}\n  nameserver: ['udp://127.0.0.1:{}']\n",
            free_port(),
            upstream.port
        );
        if mode == "fake-ip" {
            yaml.push_str("  fake-ip-range: 198.18.0.1/16\n  fake-ip-filter: ['upstream.test']\n");
        }
        let mut kernel = start_kernel(&yaml);
        let addr: SocketAddr = format!("127.0.0.1:{listen}").parse().unwrap();

        // The built-in `localhost` entry hits the hosts middleware too.
        let (next, answer) = expect_listener(addr, kernel, "localhost", TYPE_A).await;
        kernel = next;
        assert_eq!(
            first_answer_ip(&answer),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "{mode}: built-in localhost is answered from hosts with TTL 10"
        );
        assert_eq!(parse_answers(&answer)[0].2, 10, "{mode}");
        // The configured entry.
        let (next, answer) = expect_listener(addr, kernel, "host-only.test", TYPE_A).await;
        kernel = next;
        assert_eq!(
            first_answer_ip(&answer),
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            "{mode}: a configured hosts entry is answered from hosts"
        );
        // The listener still serves other names after a hosts answer.
        let (next, answer) = expect_listener(addr, kernel, "upstream.test", TYPE_A).await;
        kernel = next;
        assert_eq!(
            first_answer_ip(&answer),
            Some(IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5))),
            "{mode}: the listener is not wedged after a hosts answer"
        );
        kernel.stop().ok();
    }
}

#[tokio::test]
async fn listener_follows_a_domain_valued_hosts_entry() {
    let upstream = spawn_udp_dns(answer_map(&[(
        "alias-target.test",
        IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
    )]));
    let listen = free_port();
    let yaml = format!(
        "mixed-port: {}\nhosts:\n  alias.test: alias-target.test\ndns:\n  enable: true\n  listen: 127.0.0.1:{listen}\n  nameserver: ['udp://127.0.0.1:{}']\n",
        free_port(),
        upstream.port
    );
    let kernel = start_kernel(&yaml);
    let addr: SocketAddr = format!("127.0.0.1:{listen}").parse().unwrap();
    let (mut kernel, answer) = expect_listener(addr, kernel, "alias.test", TYPE_A).await;
    let answers = parse_answers(&answer);
    assert_eq!(
        answers,
        vec![
            (
                "alias.test".to_string(),
                TYPE_CNAME,
                10,
                "alias-target.test".to_string()
            ),
            (
                "alias-target.test".to_string(),
                TYPE_A,
                60,
                "9.9.9.9".to_string()
            ),
        ],
        "pinned withHosts replaces the question name, resolves it and prepends a CNAME"
    );
    // The upstream saw the hosts target, not the alias.
    assert_eq!(upstream.queries.load(Ordering::Relaxed), 1);
    // Rule-time handling rewrites the host through the same hosts chain, so
    // the listener and the engine agree on which name is resolved.
    let dns = kernel.dns().expect("dns");
    assert_eq!(
        dns.pre_handle("alias.test", None),
        Ok(("alias-target.test".to_string(), None))
    );
    assert_eq!(
        dns.resolve_one("alias-target.test").await,
        Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
    );
    kernel.stop().ok();
}

#[tokio::test]
async fn failed_domain_hosts_alias_reports_servfail_without_a_cname() {
    // Pinned `withHosts` prepends its CNAME only when the inner exchange
    // returned `err == nil`; a transport failure is written as an empty
    // SERVFAIL (`dns/server.go`). Rule-time resolution keeps the failure.
    let port = spawn_silent_udp();
    let listen = free_port();
    let yaml = format!(
        "mixed-port: {}\nhosts:\n  alias.test: dead-target.test\ndns:\n  enable: true\n  listen: 127.0.0.1:{listen}\n  nameserver: ['udp://127.0.0.1:{port}']\n",
        free_port()
    );
    let kernel = start_kernel(&yaml);
    let addr: SocketAddr = format!("127.0.0.1:{listen}").parse().unwrap();
    // The silent upstream makes the inner exchange wait for the pinned 5 s
    // timeout, longer than `expect_listener`'s 3 s deadlock guard.
    let mut kernel = kernel;
    let answer = tokio::time::timeout(Duration::from_secs(15), dns_query_tcp(addr, "alias.test", TYPE_A))
        .await
        .expect("alias query timed out (DNS listener deadlock)");
    assert_eq!(answer[3] & 0x0f, 2, "a failed alias exchange is SERVFAIL");
    assert!(
        parse_answers(&answer).is_empty(),
        "no CNAME (or A) may be synthesized for a failed alias target"
    );
    kernel.stop().ok();
}

// ---------------------------------------------------------------------------
// fallback-filter.geoip-code negation
// ---------------------------------------------------------------------------

fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn field_bytes(field: u64, bytes: &[u8]) -> Vec<u8> {
    let mut out = varint((field << 3) | 2);
    out.extend(varint(bytes.len() as u64));
    out.extend(bytes);
    out
}

fn field_varint(field: u64, value: u64) -> Vec<u8> {
    let mut out = varint(field << 3);
    out.extend(varint(value));
    out
}

/// `GeoIPList { entry: GeoIP { country_code: "zz", cidr: 1.2.3.4/32 } }`.
fn geoip_dat_zz() -> Vec<u8> {
    let mut cidr = field_bytes(1, &[1, 2, 3, 4]);
    cidr.extend(field_varint(2, 32));
    let mut entry = field_bytes(1, b"zz");
    entry.extend(field_bytes(2, &cidr));
    field_bytes(1, &entry)
}

#[tokio::test]
async fn fallback_geoip_code_negation_matches_the_pinned_filter() {
    let dir = std::env::temp_dir().join(format!(
        "billow-dns-geoip-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("GeoIP.dat"), geoip_dat_zz()).unwrap();
    let main = spawn_udp_dns(HashMap::from([
        (
            ("classified.test".to_string(), TYPE_A),
            (vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))], 0, 60),
        ),
        (
            ("foreign.test".to_string(), TYPE_A),
            (vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))], 0, 60),
        ),
    ]));
    let fallback = spawn_udp_dns(HashMap::from([
        (
            ("classified.test".to_string(), TYPE_A),
            (vec![IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7))], 0, 60),
        ),
        (
            ("foreign.test".to_string(), TYPE_A),
            (vec![IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6))], 0, 60),
        ),
    ]));
    // `zz` matches 1.2.3.4, so the filter keeps the main answer for it and
    // falls back for any other address; `!zz` is the exact reverse.
    for (code, classified, foreign) in [
        ("zz", Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(6, 6, 6, 6)),
        ("!zz", Ipv4Addr::new(7, 7, 7, 7), Ipv4Addr::new(8, 8, 8, 8)),
    ] {
        let yaml = format!(
            "mixed-port: {}\ngeodata-mode: true\n{}  fallback: ['udp://127.0.0.1:{}']\n  fallback-filter:\n    geoip: true\n    geoip-code: '{code}'\n",
            free_port(),
            dns_block(&format!("udp://127.0.0.1:{}", main.port), ""),
            fallback.port
        );
        let (mut kernel, _warnings) =
            Kernel::start_from_yaml(&yaml, Some(dir.clone()), Limits::default())
                .expect("kernel with GeoIP.dat starts");
        let dns = kernel.dns().expect("dns");
        assert_eq!(
            dns.resolve_one("classified.test").await,
            Some(IpAddr::V4(classified)),
            "geoip-code {code}: the fallback filter direction for a zz address"
        );
        assert_eq!(
            dns.resolve_one("foreign.test").await,
            Some(IpAddr::V4(foreign)),
            "geoip-code {code}: the fallback filter direction for a non-zz address"
        );
        kernel.stop().ok();
    }
    let _ = std::fs::remove_dir_all(&dir);
}
