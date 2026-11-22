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
static PORTS: std::sync::Mutex<Option<std::collections::BTreeSet<u16>>> =
    std::sync::Mutex::new(None);

/// Claim `port` for this process; `false` when another test already has it.
pub fn reserve_port(port: u16) -> bool {
    let mut ports = PORTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    ports
        .get_or_insert_with(std::collections::BTreeSet::new)
        .insert(port)
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
    /// Answers a health-check `HEAD` as soon as the request head is complete.
    Health { delay: Duration, status: u16 },
}

pub struct Endpoint {
    pub port: u16,
    pub connections: std::sync::Arc<AtomicU64>,
    pub bytes_received: std::sync::Arc<AtomicU64>,
}

pub async fn spawn_endpoint(mode: EchoMode) -> Endpoint {
    let std_listener = bind_loopback();
    let port = std_listener.local_addr().unwrap().port();
    std_listener
        .set_nonblocking(true)
        .expect("nonblocking endpoint");
    let listener = TcpListener::from_std(std_listener).expect("adopt endpoint listener");
    let connections = std::sync::Arc::new(AtomicU64::new(0));
    let bytes_received = std::sync::Arc::new(AtomicU64::new(0));
    let mode_config = EndpointConfig {
        reply: match mode {
            EchoMode::ReplyAfterEof { reply, delay } => Some((reply.to_vec(), delay)),
            _ => None,
        },
        silent: matches!(mode, EchoMode::Silent),
        health: match mode {
            EchoMode::Health { delay, status } => Some((delay, status)),
            _ => None,
        },
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
    health: Option<(Duration, u16)>,
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
    if let Some((delay, status)) = config.health {
        // Health-check node: answer as soon as a full request head arrived
        // (the kernel's probe sends `HEAD ... Connection: close` without
        // half-closing its write side).
        let mut head = Vec::new();
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    received += n as u64;
                    head.extend_from_slice(&buffer[..n]);
                    if head.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        config.bytes_received.fetch_add(received, Ordering::Relaxed);
        tokio::time::sleep(delay).await;
        let reason = if status == 204 { "No Content" } else { "OK" };
        let _ = stream
            .write_all(format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n").as_bytes())
            .await;
        let _ = stream.shutdown().await;
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

/// A minimal SOCKS5 CONNECT server (no-auth). Used as a `dialer-proxy` hop or
/// exit in chain tests; it counts accepted connections.
pub struct Socks5Node {
    pub port: u16,
    pub connections: std::sync::Arc<AtomicU64>,
}

pub fn spawn_socks5_node() -> Socks5Node {
    let std_listener = bind_loopback();
    let port = std_listener.local_addr().unwrap().port();
    std_listener
        .set_nonblocking(true)
        .expect("nonblocking socks5 node");
    let listener =
        tokio::net::TcpListener::from_std(std_listener).expect("adopt socks5 listener");
    let connections = std::sync::Arc::new(AtomicU64::new(0));
    let counter = connections.clone();
    std::mem::forget(tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let _ = serve_socks5_node(stream).await;
            });
        }
    }));
    Socks5Node { port, connections }
}

async fn serve_socks5_node(mut client: TcpStream) -> std::io::Result<()> {
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await?;
    if greeting[0] != 0x05 {
        return Ok(());
    }
    let mut methods = vec![0u8; usize::from(greeting[1])];
    client.read_exact(&mut methods).await?;
    client.write_all(&[0x05, 0x00]).await?;
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x01 {
        client.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Ok(());
    }
    let host = match head[3] {
        0x01 => {
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr).await?;
            std::net::Ipv4Addr::from(addr).to_string()
        }
        0x03 => {
            let mut length = [0u8; 1];
            client.read_exact(&mut length).await?;
            let mut name = vec![0u8; usize::from(length[0])];
            client.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).to_string()
        }
        0x04 => {
            let mut addr = [0u8; 16];
            client.read_exact(&mut addr).await?;
            std::net::Ipv6Addr::from(addr).to_string()
        }
        _ => {
            client.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Ok(());
        }
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    match TcpStream::connect((host.as_str(), port)).await {
        Ok(mut upstream) => {
            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        }
        Err(_) => {
            client
                .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
        }
    }
    Ok(())
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

/// A local HTTP CONNECT proxy used as a group member. `Health` answers the
/// health-check `HEAD` itself (with a controllable delay/status); `Forward`
/// tunnels to the requested target.
#[derive(Debug, Clone)]
pub enum ProxyNodeMode {
    Health { delay: Duration, status: u16 },
    /// Successive health answers use the next delay (the last one repeats).
    HealthSequence { delays: Vec<Duration>, status: u16 },
    Forward,
}

pub struct ProxyNode {
    pub port: u16,
    pub connections: std::sync::Arc<AtomicU64>,
    pub heads: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

/// Spawn a proxy node on a reserved loopback port (call inside a runtime).
pub fn spawn_http_proxy_node(mode: ProxyNodeMode) -> ProxyNode {
    let std_listener = bind_loopback();
    let port = std_listener.local_addr().unwrap().port();
    std_listener
        .set_nonblocking(true)
        .expect("nonblocking proxy node");
    let listener = tokio::net::TcpListener::from_std(std_listener)
        .expect("adopt proxy listener");
    let connections = std::sync::Arc::new(AtomicU64::new(0));
    let heads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let health_requests = std::sync::Arc::new(AtomicU64::new(0));
    let state = (connections.clone(), heads.clone(), health_requests);
    let mode = std::sync::Arc::new(mode);
    std::mem::forget(tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (connections, heads, health_requests) = state.clone();
            let mode = mode.clone();
            tokio::spawn(async move {
                connections.fetch_add(1, Ordering::Relaxed);
                let _ = serve_proxy_node(stream, mode, heads, health_requests).await;
            });
        }
    }));
    ProxyNode {
        port,
        connections,
        heads,
    }
}

async fn serve_proxy_node(
    mut stream: TcpStream,
    mode: std::sync::Arc<ProxyNodeMode>,
    heads: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    health_requests: std::sync::Arc<AtomicU64>,
) -> std::io::Result<()> {
    let mut buffer = vec![0u8; 4096];
    let mut head = Vec::new();
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        head.extend_from_slice(&buffer[..read]);
        if head.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if head.len() > 16 * 1024 {
            return Err(std::io::Error::other("proxy head too large"));
        }
    }
    let text = String::from_utf8_lossy(&head).to_string();
    heads
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(text.lines().next().unwrap_or_default().to_string());
    let mut lines = text.lines();
    let request = lines.next().unwrap_or_default();
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let (host, port) = match target.rsplit_once(':') {
        Some((host, port)) => (
            host.trim_start_matches('[').trim_end_matches(']').to_string(),
            port.parse::<u16>().ok(),
        ),
        None => (String::new(), None),
    };
    if !method.eq_ignore_ascii_case("CONNECT") {
        stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    }
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: test-node\r\n\r\n")
        .await?;
    // Any bytes after the CONNECT head belong to the tunneled stream.
    let head_end = head
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .unwrap_or(head.len());
    let mut leftover = head[head_end..].to_vec();

    let mut first_request = Vec::new();
    let health = match mode.as_ref() {
        ProxyNodeMode::Health { delay, status } => Some((*delay, *status)),
        ProxyNodeMode::HealthSequence { delays, status } => {
            let index = health_requests.fetch_add(1, Ordering::Relaxed) as usize;
            let delay = delays
                .get(index)
                .copied()
                .or_else(|| delays.last().copied())
                .unwrap_or_default();
            Some((delay, *status))
        }
        ProxyNodeMode::Forward => None,
    };
    if let Some((delay, status)) = health {
        // Serve the health-check HEAD here; tunnel anything else.
        if leftover.is_empty() {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                return Ok(());
            }
            first_request.extend_from_slice(&buffer[..read]);
        } else {
            first_request = std::mem::take(&mut leftover);
        }
        if first_request.starts_with(b"HEAD ") {
            while !first_request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).await?;
                if read == 0 {
                    return Ok(());
                }
                first_request.extend_from_slice(&buffer[..read]);
                if first_request.len() > 16 * 1024 {
                    return Ok(());
                }
            }
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let reason = if status == 204 { "No Content" } else { "OK" };
            stream
                .write_all(
                    format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                )
                .await?;
            let _ = stream.shutdown().await;
            return Ok(());
        }
        leftover = first_request;
    }

    let Ok(port) = port.ok_or(()) else {
        stream
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    };
    match TcpStream::connect((host.as_str(), port)).await {
        Ok(mut upstream) => {
            if !leftover.is_empty() {
                upstream.write_all(&leftover).await?;
            }
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
        }
        Err(_) => {
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await?;
        }
    }
    Ok(())
}
