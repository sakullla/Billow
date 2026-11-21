//! Test helpers: local echo endpoints, SOCKS5/HTTP CONNECT clients and free ports.
//! Everything here runs against real loopback sockets.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Ports already used by this test process. The OS hands a released ephemeral
/// port out again at once, and tests run in parallel: without this registry a
/// kernel could dial another test's endpoint and every positive case turns
/// into a confusing 502 or a missing marker.
static PORTS: std::sync::Mutex<Option<std::collections::BTreeSet<u16>>> = std::sync::Mutex::new(None);

/// Claim `port` for this process; `false` when another test already has it.
pub fn reserve_port(port: u16) -> bool {
    let mut ports = PORTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    ports.get_or_insert_with(std::collections::BTreeSet::new).insert(port)
}

/// Ports handed out by [`free_port`]; the kernel and endpoints use distinct ones.
pub fn free_port() -> u16 {
    for _ in 0..64 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        if reserve_port(port) {
            return port;
        }
    }
    panic!("no unused loopback port in 64 attempts");
}

/// Bind a loopback listener on a port this process has not used yet and claim
/// it, so a later [`free_port`] cannot hand the same number out.
pub fn bind_loopback() -> std::net::TcpListener {
    for _ in 0..64 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        if reserve_port(port) {
            return listener;
        }
    }
    panic!("no unused loopback port in 64 attempts");
}

/// A loopback echo server that replies `banner + payload` for every connection,
/// or a custom mode. Returns its bound port and a task handle.
pub enum EchoMode {
    /// Echoes everything (bidirectional load).
    Echo,
    /// Reads the request until EOF, waits `delay`, then answers `reply` (request/response).
    ReplyAfterEof {
        reply: &'static [u8],
        delay: Duration,
    },
    /// Never answers and keeps the connection open (stall).
    Silent,
}

pub struct Endpoint {
    pub port: u16,
    pub connections: std::sync::Arc<AtomicU64>,
    pub bytes_received: std::sync::Arc<AtomicU64>,
}

pub async fn spawn_endpoint(mode: EchoMode) -> Endpoint {
    let std_listener = bind_loopback();
    let port = std_listener.local_addr().unwrap().port();
    std_listener.set_nonblocking(true).expect("nonblocking endpoint");
    let listener = TcpListener::from_std(std_listener).expect("adopt endpoint listener");
    let connections = std::sync::Arc::new(AtomicU64::new(0));
    let bytes_received = std::sync::Arc::new(AtomicU64::new(0));
    let mode_config = EndpointConfig {
        reply: match mode {
            EchoMode::ReplyAfterEof { reply, delay } => Some((reply.to_vec(), delay)),
            _ => None,
        },
        silent: matches!(mode, EchoMode::Silent),
        connections: connections.clone(),
        bytes_received: bytes_received.clone(),
    };
    // Detached on purpose: endpoints stay up for the rest of the test process,
    // and must not hold the test runtime open at shutdown.
    std::mem::forget(tokio::spawn(endpoint_loop(listener, mode_config)));
    Endpoint {
        port,
        connections,
        bytes_received,
    }
}

#[derive(Clone)]
struct EndpointConfig {
    reply: Option<(Vec<u8>, Duration)>,
    silent: bool,
    connections: std::sync::Arc<AtomicU64>,
    bytes_received: std::sync::Arc<AtomicU64>,
}

async fn endpoint_loop(listener: TcpListener, config: EndpointConfig) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        config.connections.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(handle_connection(stream, config.clone()));
    }
}

async fn handle_connection(mut stream: TcpStream, config: EndpointConfig) {
    let mut buffer = vec![0u8; 4096];
    let mut received = 0u64;
    if config.silent {
        // Stall after the first read: stops reading and never answers.
        if let Ok(n) = stream.read(&mut buffer).await {
            received += n as u64;
        }
        config.bytes_received.fetch_add(received, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(3600)).await;
        return;
    }
    let mut request = Vec::new();
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => {
                received += n as u64;
                if config.reply.is_some() {
                    request.extend_from_slice(&buffer[..n]);
                } else if stream.write_all(&buffer[..n]).await.is_err() {
                    return;
                }
            }
            Err(_) => break,
        }
    }
    config.bytes_received.fetch_add(received, Ordering::Relaxed);
    if let Some((reply, delay)) = config.reply {
        tokio::time::sleep(delay).await;
        let mut body = reply;
        body.extend_from_slice(&request.len().to_be_bytes());
        let _ = stream.write_all(&body).await;
    }
    let _ = stream.shutdown().await;
}

/// Minimal SOCKS5 CONNECT client (no-auth). Returns the stream after the success reply.
pub async fn socks5_connect(
    proxy: SocketAddr,
    host: &str,
    port: u16,
) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection).await?;
    if selection != [0x05, 0x00] {
        return Err(std::io::Error::other(format!(
            "unexpected method selection {selection:?}"
        )));
    }
    let mut request = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        request.extend_from_slice(&[0x01]);
        request.extend_from_slice(&ip.octets());
    } else {
        request.push(0x03);
        request.push(host.len() as u8);
        request.extend_from_slice(host.as_bytes());
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "socks reply code 0x{:02x}",
            reply[1]
        )));
    }
    match reply[3] {
        0x01 => {
            let mut a = [0u8; 6];
            stream.read_exact(&mut a).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut rest).await?;
        }
        0x04 => {
            let mut a = [0u8; 18];
            stream.read_exact(&mut a).await?;
        }
        other => return Err(std::io::Error::other(format!("bad atyp {other}"))),
    }
    Ok(stream)
}

/// Send an SOCKS5 request with a chosen command byte and return the reply code.
pub async fn socks5_command(proxy: SocketAddr, command: u8) -> std::io::Result<u8> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection).await?;
    stream
        .write_all(&[0x05, command, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
        .await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    Ok(reply[1])
}

/// HTTP CONNECT client. Returns the stream after `200`, or the raw status line on failure.
pub async fn http_connect(
    proxy: SocketAddr,
    authority: &str,
) -> std::io::Result<(TcpStream, String)> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 4096 {
            return Err(std::io::Error::other("header too large"));
        }
        if stream.read(&mut byte).await? == 0 {
            return Err(std::io::Error::other("closed during CONNECT reply"));
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let status = text.lines().next().unwrap_or_default().to_string();
    Ok((stream, status))
}

/// Wait until `predicate` holds, polling every 10 ms, up to `timeout`.
pub async fn wait_until<F: Fn() -> bool>(timeout: Duration, predicate: F) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if predicate() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    predicate()
}
