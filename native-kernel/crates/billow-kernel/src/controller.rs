//! RESTful control API (T25): the subset of Mihomo's external-controller that
//! Billow consumes, with the pinned response shapes and status codes.
//!
//! The server speaks HTTP/1.1 over TCP (`external-controller`), a Unix socket
//! (`external-controller-unix`) and TLS (`external-controller-tls`, using the
//! top-level `tls.certificate`/`tls.private-key`). Authentication, CORS,
//! streaming (`/logs`, `/traffic`, `/memory`) and WebSocket upgrades follow
//! the pinned `hub/route` handlers. A reload swaps the live runtime generation
//! (see `engine::ControlCore`); the previous one is released by its last
//! session, so no rule/provider/DNS object leaks across reloads.

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::broadcast;

use crate::config::{Action, Config, ControllerConfig, GroupKind, ProviderVehicle};
use crate::engine::{
    chain_for, rule_payload_text, rule_type_name, ControlCore, Kernel, OpenConnection, VERSION,
};
use crate::proxies::Proxy;
use crate::rules::Target;

/// A log line published to `/logs` subscribers.
#[derive(Debug, Clone)]
pub struct LogRecord {
    pub level: &'static str,
    pub payload: String,
}

/// Broadcast ring for the `/logs` stream. The kernel publishes lifecycle and
/// control events here; hosts that want the tracing log forwarded as well can
/// call [`LogBus::publish`] from their logger (the CLI does).
#[derive(Clone)]
pub struct LogBus {
    sender: broadcast::Sender<LogRecord>,
}

impl std::fmt::Debug for LogBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LogBus")
    }
}

impl Default for LogBus {
    fn default() -> Self {
        Self::new()
    }
}

impl LogBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1024);
        LogBus { sender }
    }

    pub fn publish(&self, level: &'static str, payload: impl Into<String>) {
        let _ = self.sender.send(LogRecord {
            level,
            payload: payload.into(),
        });
    }

    fn subscribe(&self) -> broadcast::Receiver<LogRecord> {
        self.sender.subscribe()
    }
}

type BoxConn = Box<dyn ConnIo>;

trait ConnIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ConnIo for T {}

/// One bound controller listener set. `stop` closes every accept loop and the
/// connection tasks; `Kernel::stop` joins the threads before the supervisor.
pub struct Controller {
    stops: Vec<tokio::sync::watch::Sender<bool>>,
    threads: Vec<std::thread::JoinHandle<()>>,
    tcp_addr: Option<SocketAddr>,
    tls_addr: Option<SocketAddr>,
    unix_path: Option<PathBuf>,
}

impl Controller {
    /// Starts every configured listener. A listener that cannot bind is logged
    /// and skipped (pinned `hub/route.start*` logs `External controller listen
    /// error` and returns without failing the process); the mixed inbound and
    /// the other listeners keep running.
    pub(crate) fn start(kernel: &Kernel) -> Option<Controller> {
        let core = kernel.control();
        let runtime = core.runtime.snapshot();
        let config = runtime.config.controller.clone();
        if !config.enabled() {
            return None;
        }
        let state = Arc::new(ControlState {
            core: core.clone(),
            secret: config.secret.clone(),
            cors: config.cors.clone(),
            tls_config: build_tls_config(&config, &core),
        });
        let mut controller = Controller {
            stops: Vec::new(),
            threads: Vec::new(),
            tcp_addr: None,
            tls_addr: None,
            unix_path: None,
        };
        if let Some(spec) = &config.external_controller {
            match bind_tcp(spec) {
                Ok(listener) => {
                    let addr = listener.local_addr().ok();
                    let stop =
                        spawn_plain(state.clone(), listener, None, &mut controller.threads);
                    controller.stops.push(stop);
                    controller.tcp_addr = addr;
                    core.log_bus.publish(
                        "info",
                        format!(
                            "RESTful API listening at: {}",
                            addr.map(|addr| addr.to_string())
                                .unwrap_or_else(|| spec.clone())
                        ),
                    );
                }
                Err(error) => {
                    // The log bus is the control API's own log stream; a
                    // failed bind must also reach the process logger so a
                    // bare CLI run shows why no controller came up.
                    tracing::error!(
                        "External controller listen error at {spec}: {error}; the TCP control listener is skipped"
                    );
                    core.log_bus.publish(
                        "error",
                        format!(
                            "External controller listen error at {spec}: {error}; the TCP control listener is skipped"
                        ),
                    );
                }            }
        }
        if let Some(spec) = &config.external_controller_tls {
            match state.tls_config.clone() {
                Some(tls) => match bind_tcp(spec) {
                    Ok(listener) => {
                        let addr = listener.local_addr().ok();
                        let stop =
                            spawn_plain(state.clone(), listener, Some(tls), &mut controller.threads);
                        controller.stops.push(stop);
                        controller.tls_addr = addr;
                        core.log_bus.publish(
                            "info",
                            format!(
                                "RESTful API tls listening at: {}",
                                addr.map(|addr| addr.to_string())
                                    .unwrap_or_else(|| spec.clone())
                            ),
                        );
                    }
                    Err(error) => {
                        tracing::error!(
                            "External controller tls listen error at {spec}: {error}; the TLS control listener is skipped"
                        );
                        core.log_bus.publish(
                            "error",
                            format!(
                                "External controller tls listen error at {spec}: {error}; the TLS control listener is skipped"
                            ),
                        );
                    }
                },
                None => {
                    tracing::error!(
                        "External controller tls listen error: tls.certificate/tls.private-key are missing or invalid; the TLS listener is skipped"
                    );
                    core.log_bus.publish(
                        "error",
                        "External controller tls listen error: tls.certificate/tls.private-key are missing or invalid; the TLS listener is skipped",
                    );
                }
            }
        }
        #[cfg(unix)]
        if let Some(path) = &config.external_controller_unix {
            match bind_unix(path) {
                Ok(listener) => {
                    let stop = spawn_unix(state.clone(), listener, &mut controller.threads);
                    controller.stops.push(stop);
                    controller.unix_path = Some(path.clone());
                    core.log_bus.publish(
                        "info",
                        format!("RESTful API unix listening at: {}", path.display()),
                    );
                }
                Err(error) => {
                    tracing::error!(
                        "External controller unix listen error at {}: {error}",
                        path.display()
                    );
                    core.log_bus.publish(
                        "error",
                        format!(
                            "External controller unix listen error at {}: {error}",
                            path.display()
                        ),
                    );
                }
            }
        }
        #[cfg(not(unix))]
        if config.external_controller_unix.is_some() {
            tracing::warn!(
                "external-controller-unix is configured but Unix sockets are not available on this platform; no unix listener is started"
            );
        }
        Some(controller)
    }

    /// Actual TCP controller address (`None` without `external-controller`).
    pub(crate) fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp_addr
    }

    /// Actual TLS controller address.
    pub(crate) fn tls_addr(&self) -> Option<SocketAddr> {
        self.tls_addr
    }

    /// Configured Unix socket path.
    pub(crate) fn unix_path(&self) -> Option<&std::path::Path> {
        self.unix_path.as_deref()
    }

    pub fn stop(&mut self) {
        for stop in &self.stops {
            let _ = stop.send(true);
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        self.stops.clear();
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.stop();
    }
}

struct ControlState {
    core: Arc<ControlCore>,
    secret: String,
    cors: crate::config::CorsConfig,
    tls_config: Option<Arc<rustls::ServerConfig>>,
}

fn bind_tcp(spec: &str) -> io::Result<std::net::TcpListener> {
    use std::net::ToSocketAddrs;
    // Pinned passes the string straight to `net.Listen("tcp", addr)`, so a
    // hostless `:9090` binds every interface (`[::]` with the platform's
    // dual-stack default). `to_socket_addrs` rejects that form, so resolve it
    // explicitly and fall back to IPv4 wildcard where IPv6 is unavailable.
    let listener = if let Some(port) = spec.strip_prefix(':') {
        let port: u16 = port.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("external-controller '{spec}' has an invalid port"),
            )
        })?;
        match std::net::TcpListener::bind((std::net::Ipv6Addr::UNSPECIFIED, port)) {
            Ok(listener) => listener,
            Err(_) => std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port))?,
        }
    } else {
        let mut addrs = spec.to_socket_addrs()?;
        let addr = addrs.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("external-controller '{spec}' resolved to no address"),
            )
        })?;
        std::net::TcpListener::bind(addr)?
    };
    listener.set_nonblocking(true)?;
    Ok(listener)
}

#[cfg(unix)]
fn bind_unix(path: &std::path::Path) -> io::Result<std::os::unix::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            std::fs::create_dir_all(dir)?;
        }
    }
    // Pinned unlinks a stale socket path before binding.
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn build_tls_config(
    config: &ControllerConfig,
    core: &ControlCore,
) -> Option<Arc<rustls::ServerConfig>> {
    let cert = config.certificate.as_ref()?;
    let key = config.private_key.as_ref()?;
    let mut cert_reader = std::io::BufReader::new(cert.as_slice());
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(Result::ok)
        .collect();
    if certs.is_empty() {
        core.log_bus
            .publish("error", "External controller tls: tls.certificate has no PEM certificate");
        return None;
    }
    let mut key_reader = std::io::BufReader::new(key.as_slice());
    let private_key = match rustls_pemfile::private_key(&mut key_reader) {
        Ok(Some(key)) => key,
        _ => {
            core.log_bus.publish(
                "error",
                "External controller tls: tls.private-key is not a PEM private key",
            );
            return None;
        }
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    match rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
    {
        Ok(mut server) => {
            // This listener speaks HTTP/1.1 only. Pinned advertises
            // `["h2","http/1.1"]` because Go's http server also serves h2;
            // advertising h2 here would make an h2-only client negotiate a
            // protocol the router never speaks. Offer only http/1.1 so curl
            // and h2-capable clients fall back to the implemented protocol.
            server.alpn_protocols = vec![b"http/1.1".to_vec()];
            Some(Arc::new(server))
        }
        Err(error) => {
            core.log_bus.publish(
                "error",
                format!("External controller tls certificate rejected: {error}"),
            );
            None
        }
    }
}

fn spawn_plain(
    state: Arc<ControlState>,
    listener: std::net::TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
    threads: &mut Vec<std::thread::JoinHandle<()>>,
) -> tokio::sync::watch::Sender<bool> {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let handle = std::thread::Builder::new()
        .name("billow-controller".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    tracing::error!("controller runtime build failed: {error}");
                    return;
                }
            };
            runtime.block_on(async move {
                let listener = match tokio::net::TcpListener::from_std(listener) {
                    Ok(listener) => listener,
                    Err(error) => {
                        tracing::error!("controller listener adopt failed: {error}");
                        return;
                    }
                };
                accept_tcp(listener, state, tls, stop_rx).await;
            });
        });
    match handle {
        Ok(handle) => threads.push(handle),
        Err(error) => tracing::error!("controller thread spawn failed: {error}"),
    }
    stop_tx
}

#[cfg(unix)]
fn spawn_unix(
    state: Arc<ControlState>,
    listener: std::os::unix::net::UnixListener,
    threads: &mut Vec<std::thread::JoinHandle<()>>,
) -> tokio::sync::watch::Sender<bool> {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let handle = std::thread::Builder::new()
        .name("billow-controller-unix".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    tracing::error!("controller runtime build failed: {error}");
                    return;
                }
            };
            runtime.block_on(async move {
                let listener = match tokio::net::UnixListener::from_std(listener) {
                    Ok(listener) => listener,
                    Err(error) => {
                        tracing::error!("controller unix listener adopt failed: {error}");
                        return;
                    }
                };
                accept_unix(listener, state, stop_rx).await;
            });
        });
    match handle {
        Ok(handle) => threads.push(handle),
        Err(error) => tracing::error!("controller thread spawn failed: {error}"),
    }
    stop_tx
}

async fn accept_tcp(
    listener: tokio::net::TcpListener,
    state: Arc<ControlState>,
    tls: Option<Arc<rustls::ServerConfig>>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, _peer)) = accepted else { continue };
                let state = state.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    let conn: BoxConn = match tls {
                        Some(config) => {
                            let acceptor = tokio_rustls::TlsAcceptor::from(config);
                            match acceptor.accept(stream).await {
                                Ok(stream) => Box::new(stream),
                                Err(error) => {
                                    tracing::debug!("controller TLS handshake failed: {error}");
                                    return;
                                }
                            }
                        }
                        None => Box::new(stream),
                    };
                    serve_connection(conn, state, true).await;
                });
            }
        }
    }
}

#[cfg(unix)]
async fn accept_unix(
    listener: tokio::net::UnixListener,
    state: Arc<ControlState>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, _peer)) = accepted else { continue };
                let state = state.clone();
                tokio::spawn(async move {
                    // Pinned starts the Unix router with an empty secret; the
                    // socket permission is the access control there.
                    serve_connection(Box::new(stream), state, false).await;
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP/1.1 framing
// ---------------------------------------------------------------------------

struct Request {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    fn query(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(String::as_str)
    }

    fn is_websocket(&self) -> bool {
        self.header("upgrade")
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
    }
}

async fn serve_connection(mut conn: BoxConn, state: Arc<ControlState>, enforce_auth: bool) {
    let request = match tokio::time::timeout(Duration::from_secs(15), read_request(&mut conn)).await
    {
        Ok(Ok(Some(request))) => request,
        Ok(Ok(None)) => return,
        Ok(Err(error)) => {
            let _ = write_simple(&mut conn, 400, "Bad Request", error.as_bytes()).await;
            return;
        }
        Err(_) => return,
    };
    handle_request(conn, state, request, enforce_auth).await;
}

async fn read_request(conn: &mut BoxConn) -> Result<Option<Request>, String> {
    let mut buffer = Vec::with_capacity(4096);
    let head_end;
    loop {
        if buffer.len() > 64 * 1024 {
            return Err("request head too large".to_string());
        }
        let mut chunk = [0u8; 4096];
        let read = conn
            .read(&mut chunk)
            .await
            .map_err(|e| format!("read failed: {e}"))?;
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = find_subsequence(&buffer, b"\r\n\r\n") {
            head_end = position;
            break;
        }
    }
    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    if method.is_empty() || target.is_empty() {
        return Err("malformed request line".to_string());
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    let (path, query) = split_target(&target);
    let mut body = buffer[head_end + 4..].to_vec();
    if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        body = read_chunked(conn, body).await?;
    } else if let Some(length) = headers
        .get("content-length")
        .and_then(|value| value.trim().parse::<usize>().ok())
    {
        if length > 32 * 1024 * 1024 {
            return Err("request body too large".to_string());
        }
        while body.len() < length {
            let mut chunk = [0u8; 8192];
            let read = conn
                .read(&mut chunk)
                .await
                .map_err(|e| format!("read body failed: {e}"))?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..read]);
        }
        body.truncate(length);
    }
    Ok(Some(Request {
        method,
        path,
        query,
        headers,
        body,
    }))
}

async fn read_chunked(conn: &mut BoxConn, mut pending: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = loop {
            if let Some(position) = find_subsequence(&pending, b"\r\n") {
                break position;
            }
            let mut chunk = [0u8; 4096];
            let read = conn
                .read(&mut chunk)
                .await
                .map_err(|e| format!("chunk read failed: {e}"))?;
            if read == 0 {
                return Err("chunked body truncated".to_string());
            }
            pending.extend_from_slice(&chunk[..read]);
        };
        let line = String::from_utf8_lossy(&pending[..line_end]).to_string();
        let size_text = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| "invalid chunk size".to_string())?;
        pending.drain(..line_end + 2);
        if size == 0 {
            return Ok(out);
        }
        while pending.len() < size + 2 {
            let mut chunk = [0u8; 4096];
            let read = conn
                .read(&mut chunk)
                .await
                .map_err(|e| format!("chunk read failed: {e}"))?;
            if read == 0 {
                return Err("chunked body truncated".to_string());
            }
            pending.extend_from_slice(&chunk[..read]);
        }
        out.extend_from_slice(&pending[..size]);
        pending.drain(..size + 2);
    }
}

fn split_target(target: &str) -> (String, BTreeMap<String, String>) {
    let (raw_path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    let mut query = BTreeMap::new();
    for pair in raw_query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        query.insert(percent_decode(key), percent_decode(value));
    }
    (raw_path.to_string(), query)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
                match hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                    Some(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    None => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

struct Response {
    status: u16,
    reason: &'static str,
    content_type: Option<&'static str>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn empty(status: u16, reason: &'static str) -> Self {
        Response {
            status,
            reason,
            content_type: None,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn json(status: u16, reason: &'static str, value: Value) -> Self {
        // Pinned `render.JSON` uses `json.Encoder`, which terminates every
        // body with a newline; keep byte-for-byte parity for clients that
        // compare lengths.
        let mut body = serde_json::to_vec(&value).unwrap_or_default();
        body.push(b'\n');
        Response {
            status,
            reason,
            content_type: Some("application/json"),
            headers: Vec::new(),
            body,
        }
    }

    fn message(status: u16, reason: &'static str, message: impl Into<String>) -> Self {
        Self::json(status, reason, json!({ "message": message.into() }))
    }

    fn not_found() -> Self {
        Response {
            status: 404,
            reason: "Not Found",
            content_type: Some("text/plain; charset=utf-8"),
            headers: vec![("X-Content-Type-Options".to_string(), "nosniff".to_string())],
            body: b"404 page not found".to_vec(),
        }
    }

    fn method_not_allowed(allow: &[&str]) -> Self {
        let mut response = Response::empty(405, "Method Not Allowed");
        for method in allow {
            response.headers.push(("Allow".to_string(), method.to_string()));
        }
        response
    }
}

fn common_headers(request: &Request, state: &ControlState) -> Vec<(String, String)> {
    let mut headers = vec![("Vary".to_string(), "Origin".to_string())];
    if let Some(origin) = request.header("origin") {
        if cors_allows(state, origin) {
            let value = if state.cors.allow_origins.iter().any(|entry| entry == "*") {
                "*".to_string()
            } else {
                origin.to_string()
            };
            headers.push(("Access-Control-Allow-Origin".to_string(), value));
        }
    }
    headers
}

fn cors_allows(state: &ControlState, origin: &str) -> bool {
    state
        .cors
        .allow_origins
        .iter()
        .any(|entry| entry == "*" || entry.eq_ignore_ascii_case(origin))
}

fn preflight_response(request: &Request, state: &ControlState) -> Response {
    let mut headers = Vec::new();
    headers.push((
        "Access-Control-Allow-Methods".to_string(),
        request
            .header("access-control-request-method")
            .unwrap_or("GET")
            .to_string(),
    ));
    if let Some(requested) = request.header("access-control-request-headers") {
        headers.push((
            "Access-Control-Allow-Headers".to_string(),
            requested
                .split(',')
                .map(str::trim)
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    headers.push(("Access-Control-Max-Age".to_string(), "300".to_string()));
    if state.cors.allow_private_network
        && request
            .header("access-control-request-private-network")
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
    {
        headers.push((
            "Access-Control-Allow-Private-Network".to_string(),
            "true".to_string(),
        ));
    }
    headers.push(("Vary".to_string(), "Access-Control-Request-Method".to_string()));
    headers.push(("Vary".to_string(), "Access-Control-Request-Headers".to_string()));
    Response {
        status: 200,
        reason: "OK",
        content_type: None,
        headers,
        body: Vec::new(),
    }
}

async fn write_response(
    conn: &mut BoxConn,
    request: &Request,
    state: &ControlState,
    mut response: Response,
) {
    response.headers.extend(common_headers(request, state));
    response.headers.push(("Connection".to_string(), "close".to_string()));
    let body_length = if response.status == 204 || response.status == 304 {
        String::new()
    } else {
        format!("Content-Length: {}\r\n", response.body.len())
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\n{}{}{body_length}\r\n",
        response.status,
        response.reason,
        response
            .content_type
            .map(|value| format!("Content-Type: {value}\r\n"))
            .unwrap_or_default(),
        response
            .headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}\r\n"))
            .collect::<String>(),
    );
    if conn.write_all(head.as_bytes()).await.is_err() {
        return;
    }
    let _ = conn.write_all(&response.body).await;
    let _ = conn.flush().await;
}

async fn write_simple(
    conn: &mut BoxConn,
    status: u16,
    reason: &'static str,
    body: &[u8],
) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    conn.write_all(head.as_bytes()).await?;
    conn.write_all(body).await?;
    conn.flush().await
}

async fn write_stream_head(
    conn: &mut BoxConn,
    request: &Request,
    state: &ControlState,
) -> io::Result<()> {
    let headers = common_headers(request, state);
    let mut head = String::from("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    conn.write_all(head.as_bytes()).await
}

async fn write_chunk(conn: &mut BoxConn, bytes: &[u8]) -> io::Result<()> {
    conn.write_all(format!("{:x}\r\n", bytes.len()).as_bytes())
        .await?;
    conn.write_all(bytes).await?;
    conn.write_all(b"\r\n").await?;
    conn.flush().await
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

fn segments(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .map(percent_decode)
        .collect()
}

async fn handle_request(
    mut conn: BoxConn,
    state: Arc<ControlState>,
    request: Request,
    enforce_auth: bool,
) {
    // CORS preflight is answered before routing/auth, like the pinned `chi/cors`
    // middleware. An OPTIONS request without the preflight headers falls through
    // to the router (and usually gets 405).
    if request.method == "OPTIONS"
        && request.header("origin").is_some()
        && request.header("access-control-request-method").is_some()
    {
        let response = preflight_response(&request, &state);
        write_response(&mut conn, &request, &state, response).await;
        return;
    }
    let parts = segments(&request.path);
    let route = match resolve_route(&request, &parts) {
        Ok(route) => route,
        Err(response) => {
            write_response(&mut conn, &request, &state, response).await;
            return;
        }
    };
    // Authentication comes after routing, exactly like the pinned group
    // middleware: an unknown path is a 404 even without a secret, a known
    // method without credentials is a 401.
    if enforce_auth && !authenticated(&request, &state) {
        write_response(
            &mut conn,
            &request,
            &state,
            Response::message(401, "Unauthorized", "Unauthorized"),
        )
        .await;
        return;
    }
    if let Some((stream, response)) = route.stream(&request, &state).await {
        match response {
            Some(response) => write_response(&mut conn, &request, &state, response).await,
            None => run_stream(&mut conn, &request, &state, stream).await,
        }
        return;
    }
    let response = route.respond(&request, &state).await;
    write_response(&mut conn, &request, &state, response).await;
}

fn authenticated(request: &Request, state: &ControlState) -> bool {
    if state.secret.is_empty() {
        return true;
    }
    if request.is_websocket() {
        if let Some(token) = request.query("token") {
            if token == state.secret {
                return true;
            }
        }
    }
    request
        .header("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|token| token == state.secret)
}

enum Route {
    Hello,
    Version,
    ConfigsGet,
    ConfigsPut,
    ConfigsPatch,
    Proxies,
    ProxyGet(String),
    ProxyDelay(String),
    ProxyPut(String),
    ProxyDelete(String),
    Rules,
    Connections,
    ConnectionDeleteAll,
    ConnectionDelete(String),
    ProxyProviders,
    ProxyProviderGet(String),
    ProxyProviderPut(String),
    ProxyProviderHealth(String),
    ProxyProviderNodeGet(String, String),
    ProxyProviderNodeHealth(String, String),
    RuleProviders,
    RuleProviderPut(String),
    Logs,
    Traffic,
    Memory,
}

impl Route {
    async fn stream(
        &self,
        request: &Request,
        _state: &ControlState,
    ) -> Option<(StreamKind, Option<Response>)> {
        match self {
            Route::Logs => match requested_log_level(request) {
                Ok(_) => Some((StreamKind::Logs, None)),
                Err(response) => Some((StreamKind::Logs, Some(response))),
            },
            Route::Traffic => Some((StreamKind::Traffic, None)),
            Route::Memory => Some((StreamKind::Memory, None)),
            Route::Connections => {
                if request.is_websocket() {
                    let interval = match request.query("interval") {
                        Some(value) => match value.parse::<u64>() {
                            Ok(value) if value > 0 => value,
                            _ => {
                                return Some((
                                    StreamKind::Connections { interval: 1000 },
                                    Some(Response::message(
                                        400,
                                        "Bad Request",
                                        "Body invalid",
                                    )),
                                ))
                            }
                        },
                        None => 1000,
                    };
                    Some((StreamKind::Connections { interval }, None))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    async fn respond(&self, request: &Request, state: &ControlState) -> Response {
        let core = &state.core;
        match self {
            Route::Hello => Response::json(200, "OK", json!({"hello": "mihomo"})),
            Route::Version => Response::json(
                200,
                "OK",
                json!({"meta": false, "version": VERSION}),
            ),
            Route::ConfigsGet => {
                let runtime = core.runtime.snapshot();
                Response::json(200, "OK", configs_json(&runtime.config))
            }
            Route::ConfigsPatch => patch_configs(request, state),
            Route::ConfigsPut => put_configs(request, state).await,
            Route::Proxies => {
                let runtime = core.runtime.snapshot();
                Response::json(200, "OK", json!({ "proxies": proxies_map(&runtime) }))
            }
            Route::ProxyGet(name) => {
                let runtime = core.runtime.snapshot();
                match proxy_value(&runtime, name) {
                    Some(value) => Response::json(200, "OK", value),
                    None => Response::message(404, "Not Found", "Resource not found"),
                }
            }
            Route::ProxyPut(name) => put_selection(request, state, name),
            Route::ProxyDelete(name) => delete_selection(name, state),
            Route::ProxyDelay(name) => proxy_delay(request, state, name, None).await,
            Route::Rules => {
                let runtime = core.runtime.snapshot();
                let mut rules = Vec::new();
                for (index, rule) in runtime.config.rules.iter().enumerate() {
                    rules.push(json!({
                        "index": index,
                        "type": rule_type_name(&rule.matcher),
                        "payload": rule_payload_text(&rule.matcher),
                        "proxy": runtime.config.action_name(rule.action),
                        "size": -1,
                    }));
                }
                Response::json(200, "OK", json!({ "rules": rules }))
            }
            Route::Connections => Response::json(200, "OK", connections_json(core)),
            Route::ConnectionDeleteAll => {
                core.connections.close_all();
                Response::empty(204, "No Content")
            }
            Route::ConnectionDelete(id) => {
                core.connections.close(id);
                Response::empty(204, "No Content")
            }
            Route::ProxyProviders => {
                let runtime = core.runtime.snapshot();
                Response::json(200, "OK", json!({ "providers": proxy_providers_map(&runtime) }))
            }
            Route::ProxyProviderGet(name) => {
                let runtime = core.runtime.snapshot();
                match proxy_provider_value(&runtime, name) {
                    Some(value) => Response::json(200, "OK", value),
                    None => Response::message(404, "Not Found", "Resource not found"),
                }
            }
            Route::ProxyProviderPut(name) => {
                let runtime = core.runtime.snapshot();
                if runtime.providers.proxy_provider(name).is_none() {
                    // Groups and the built-in `default` provider are
                    // Compatible providers whose Update is a no-op upstream.
                    if provider_is_compatible(&runtime, name) {
                        return Response::empty(204, "No Content");
                    }
                    return Response::message(404, "Not Found", "Resource not found");
                }
                // `update_proxy_provider` fetches http(s) providers with a
                // blocking socket; keep it off this current_thread runtime.
                let groups = runtime.groups.clone();
                let runtime = runtime.clone();
                let name_for_task = name.clone();
                let update = tokio::task::spawn_blocking(move || {
                    runtime.providers.update_proxy_provider(&name_for_task)
                })
                .await;
                match update {
                    Ok(Ok(update)) => {
                        groups.note_provider_update(name);
                        core.log_bus.publish(
                            "info",
                            format!(
                                "proxy provider '{}' updated (generation {}, {} proxies)",
                                name, update.generation, update.entries
                            ),
                        );
                        Response::empty(204, "No Content")
                    }
                    Ok(Err(error)) => {
                        core.log_bus.publish(
                            "warning",
                            format!("proxy provider '{name}' update failed: {error}"),
                        );
                        Response::message(503, "Service Unavailable", error.to_string())
                    }
                    Err(error) => {
                        core.log_bus.publish(
                            "warning",
                            format!("proxy provider '{name}' update task failed: {error}"),
                        );
                        Response::message(503, "Service Unavailable", "provider update failed")
                    }
                }
            }
            Route::ProxyProviderHealth(name) => {
                let runtime = core.runtime.snapshot();
                if runtime.providers.proxy_provider(name).is_none() {
                    if let Some(_status) = runtime.groups.group_status(name) {
                        // Compatible providers probe their members in the
                        // background and answer 204 immediately, like pinned.
                        let groups = runtime.groups.clone();
                        let name = name.clone();
                        tokio::spawn(async move {
                            let _ = groups.probe_group_named(&name).await;
                        });
                        return Response::empty(204, "No Content");
                    }
                    if name == "default" {
                        return Response::empty(204, "No Content");
                    }
                    return Response::message(404, "Not Found", "Resource not found");
                }
                let groups = runtime.groups.clone();
                let _ = groups.probe_provider_named(name).await;
                Response::empty(204, "No Content")
            }
            Route::ProxyProviderNodeGet(provider, name) => {
                let runtime = core.runtime.snapshot();
                if let Some(proxy) = provider_node(&runtime, provider, name) {
                    return Response::json(
                        200,
                        "OK",
                        proxy_json(&runtime, &proxy, Some(provider)),
                    );
                }
                if provider_is_compatible(&runtime, provider)
                    && compatible_provider_has_node(&runtime, provider, name)
                {
                    if let Some(value) = proxy_value(&runtime, name) {
                        return Response::json(200, "OK", value);
                    }
                }
                Response::message(404, "Not Found", "Resource not found")
            }
            Route::ProxyProviderNodeHealth(provider, name) => {
                let runtime = core.runtime.snapshot();
                if runtime.providers.proxy_provider(provider).is_none()
                    && !(provider_is_compatible(&runtime, provider)
                        && compatible_provider_has_node(&runtime, provider, name))
                {
                    return Response::message(404, "Not Found", "Resource not found");
                }
                proxy_delay(request, state, name, Some(provider)).await
            }
            Route::RuleProviders => {
                let runtime = core.runtime.snapshot();
                Response::json(200, "OK", json!({ "providers": rule_providers_map(&runtime) }))
            }
            Route::RuleProviderPut(name) => {
                let runtime = core.runtime.snapshot();
                let Some(slot) = runtime.providers.rule_provider(name) else {
                    return Response::message(404, "Not Found", "Resource not found");
                };
                if matches!(slot.config.vehicle, ProviderVehicle::Inline) {
                    // Pinned inline `Update` only refreshes the timestamp.
                    return Response::empty(204, "No Content");
                }
                // Blocking file/http read; keep it off the control runtime.
                let runtime = runtime.clone();
                let name_for_task = name.clone();
                let update = tokio::task::spawn_blocking(move || {
                    runtime.providers.update_rule_provider(&name_for_task)
                })
                .await;
                match update {
                    Ok(Ok(update)) => {
                        core.log_bus.publish(
                            "info",
                            format!(
                                "rule provider '{}' updated (generation {}, {} entries)",
                                name, update.generation, update.entries
                            ),
                        );
                        Response::empty(204, "No Content")
                    }
                    Ok(Err(error)) => {
                        core.log_bus.publish(
                            "warning",
                            format!("rule provider '{name}' update failed: {error}"),
                        );
                        Response::message(503, "Service Unavailable", error.to_string())
                    }
                    Err(error) => {
                        core.log_bus.publish(
                            "warning",
                            format!("rule provider '{name}' update task failed: {error}"),
                        );
                        Response::message(503, "Service Unavailable", "provider update failed")
                    }
                }
            }
            Route::Logs | Route::Traffic | Route::Memory => {
                let _ = request;
                Response::empty(204, "No Content")
            }
        }
    }
}

fn resolve_route(request: &Request, parts: &[String]) -> Result<Route, Response> {
    let method = request.method.as_str();
    let allow = |methods: &[&str]| -> Response { Response::method_not_allowed(methods) };
    let matched = |route: Route, methods: &[&str]| {
        if methods.contains(&method) {
            Ok(route)
        } else {
            Err(allow(methods))
        }
    };
    match parts {
        [] => matched(Route::Hello, &["GET"]),
        [one] if one == "version" => matched(Route::Version, &["GET"]),
        [one] if one == "logs" => matched(Route::Logs, &["GET"]),
        [one] if one == "traffic" => matched(Route::Traffic, &["GET"]),
        [one] if one == "memory" => matched(Route::Memory, &["GET"]),
        [one] if one == "configs" => match method {
            "GET" => Ok(Route::ConfigsGet),
            "PUT" => Ok(Route::ConfigsPut),
            "PATCH" => Ok(Route::ConfigsPatch),
            _ => Err(allow(&["GET", "PUT", "PATCH"])),
        },
        [configs, ..] if configs == "configs" => {
            // `/configs/geo` (geodata download) is not implemented; a 404 lets
            // Billow fall back to `/upgrade/geo` and report the missing
            // capability instead of a silent success.
            Err(Response::not_found())
        }
        [one] if one == "rules" => matched(Route::Rules, &["GET"]),
        [one] if one == "connections" => match method {
            "GET" => Ok(Route::Connections),
            "DELETE" => Ok(Route::ConnectionDeleteAll),
            _ => Err(allow(&["GET", "DELETE"])),
        },
        [connections, id] if connections == "connections" => match method {
            "DELETE" => Ok(Route::ConnectionDelete(id.clone())),
            _ => Err(allow(&["DELETE"])),
        },
        [one] if one == "proxies" => matched(Route::Proxies, &["GET"]),
        [proxies, name] if proxies == "proxies" => match method {
            "GET" => Ok(Route::ProxyGet(name.clone())),
            "PUT" => Ok(Route::ProxyPut(name.clone())),
            "DELETE" => Ok(Route::ProxyDelete(name.clone())),
            _ => Err(allow(&["GET", "PUT", "DELETE"])),
        },
        [proxies, name, delay] if proxies == "proxies" && delay == "delay" => {
            matched(Route::ProxyDelay(name.clone()), &["GET"])
        }
        [providers, proxies] if providers == "providers" && proxies == "proxies" => {
            matched(Route::ProxyProviders, &["GET"])
        }
        [providers, proxies, name] if providers == "providers" && proxies == "proxies" => {
            match method {
                "GET" => Ok(Route::ProxyProviderGet(name.clone())),
                "PUT" => Ok(Route::ProxyProviderPut(name.clone())),
                _ => Err(allow(&["GET", "PUT"])),
            }
        }
        [providers, proxies, name, health] if providers == "providers"
            && proxies == "proxies"
            && health == "healthcheck" =>
        {
            matched(Route::ProxyProviderHealth(name.clone()), &["GET"])
        }
        [providers, proxies, provider, name] if providers == "providers" && proxies == "proxies" => {
            match method {
                "GET" => Ok(Route::ProxyProviderNodeGet(provider.clone(), name.clone())),
                _ => Err(allow(&["GET"])),
            }
        }
        [providers, proxies, provider, name, health] if providers == "providers"
            && proxies == "proxies"
            && health == "healthcheck" =>
        {
            matched(
                Route::ProxyProviderNodeHealth(provider.clone(), name.clone()),
                &["GET"],
            )
        }
        [providers, rules] if providers == "providers" && rules == "rules" => {
            matched(Route::RuleProviders, &["GET"])
        }
        [providers, rules, name] if providers == "providers" && rules == "rules" => {
            matched(Route::RuleProviderPut(name.clone()), &["PUT"])
        }
        _ => Err(Response::not_found()),
    }
}

// ---------------------------------------------------------------------------
// /configs
// ---------------------------------------------------------------------------

fn configs_json(config: &Config) -> Value {
    let mut object = Map::new();
    object.insert("port".into(), json!(0));
    object.insert("socks-port".into(), json!(0));
    object.insert("redir-port".into(), json!(0));
    object.insert("tproxy-port".into(), json!(0));
    object.insert("mixed-port".into(), json!(config.listen.port()));
    object.insert(
        "tun".into(),
        json!({
            "enable": config.tun.enable,
            "device": config.tun.device,
            "stack": config.tun.stack,
            "mtu": config.tun.mtu,
            "auto-route": config.tun.auto_route,
            "auto-detect-interface": config.tun.auto_detect_interface,
            "strict-route": config.tun.strict_route,
            "dns-hijack": config.tun.dns_hijack,
        }),
    );
    object.insert(
        "tuic-server".into(),
        json!({"enable": false, "listen": "", "certificate": "", "private-key": ""}),
    );
    object.insert("ss-config".into(), json!(""));
    object.insert("vmess-config".into(), json!(""));
    object.insert(
        "authentication".into(),
        if config.inbound_users.is_empty() {
            Value::Null
        } else {
            json!(config
                .inbound_users
                .iter()
                .map(|(user, pass)| format!("{user}:{pass}"))
                .collect::<Vec<_>>())
        },
    );
    object.insert("skip-auth-prefixes".into(), Value::Null);
    object.insert("lan-allowed-ips".into(), Value::Null);
    object.insert("lan-disallowed-ips".into(), Value::Null);
    object.insert("allow-lan".into(), json!(!config.listen.ip().is_loopback()));
    object.insert("bind-address".into(), json!(config.listen.ip().to_string()));
    object.insert("inbound-tfo".into(), json!(false));
    object.insert("inbound-mptcp".into(), json!(false));
    object.insert("mode".into(), json!("rule"));
    object.insert("log-level".into(), json!(config.log_level.clone().unwrap_or_else(|| "info".to_string())));
    object.insert("ipv6".into(), json!(config.ipv6));
    object.insert("geodata-mode".into(), json!(config.geodata_mode));
    object.insert("geodata-loader".into(), json!(config.geodata_loader));
    object.insert("geosite-matcher".into(), json!(config.geosite_matcher));
    object.insert("geo-auto-update".into(), json!(config.geo_auto_update));
    Value::Object(object)
}

async fn put_configs(request: &Request, state: &ControlState) -> Response {
    let body = match serde_json::from_slice::<Value>(&request.body) {
        Ok(value) => value,
        Err(_) => return Response::message(400, "Bad Request", "Body invalid"),
    };
    let payload = body
        .get("payload")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let path = body
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if payload.is_empty() && path.is_empty() {
        // Pinned falls back to the config file; the controller does not know
        // a file path when it was started from YAML text.
        return Response::message(
            400,
            "Bad Request",
            "config path is empty and no payload was given",
        );
    }
    // `PUT /configs` reads provider files and fetches http(s) providers while
    // building the replacement generation. That path uses blocking sockets
    // (`std::net::TcpStream`, 15s connect / 30s read) and the controller runs
    // on a current_thread runtime, so the whole build must stay off the event
    // loop or every other control request (accept, /version, /traffic) stalls.
    let core = state.core.clone();
    let built = tokio::task::spawn_blocking(move || -> Result<(), Response> {
        let yaml = if !payload.is_empty() {
            payload
        } else {
            let path = std::path::PathBuf::from(&path);
            if !path.is_absolute() {
                return Err(Response::message(400, "Bad Request", "path is not a absolute path"));
            }
            let base = core
                .base_dir
                .canonicalize()
                .unwrap_or_else(|_| core.base_dir.clone());
            let candidate = path.canonicalize().unwrap_or_else(|_| path.clone());
            if !candidate.starts_with(&base) {
                return Err(Response::message(
                    400,
                    "Bad Request",
                    format!("path is not a safe path: {}", path.display()),
                ));
            }
            match std::fs::read_to_string(&candidate) {
                Ok(text) => text,
                Err(error) => {
                    return Err(Response::message(
                        400,
                        "Bad Request",
                        format!("{}: {error}", candidate.display()),
                    ))
                }
            }
        };
        core.reload(&yaml).map(|_| ()).map_err(|error| {
            core.log_bus.publish(
                "warning",
                format!("configuration reload failed: {error}"),
            );
            Response::message(400, "Bad Request", error.to_string())
        })
    })
    .await;
    match built {
        Ok(Ok(())) => {
            state.core.log_bus.publish("info", "configuration reloaded");
            Response::empty(204, "No Content")
        }
        Ok(Err(response)) => response,
        Err(error) => {
            state.core.log_bus.publish(
                "error",
                format!("configuration reload task failed: {error}"),
            );
            Response::message(500, "Internal Server Error", "reload task failed")
        }
    }
}

fn patch_configs(request: &Request, state: &ControlState) -> Response {
    let body = match serde_json::from_slice::<Value>(&request.body) {
        Ok(Value::Object(body)) => body,
        _ => return Response::message(400, "Bad Request", "Body invalid"),
    };
    let runtime = state.core.runtime.snapshot();
    let config = &runtime.config;
    let mut changed = Vec::new();
    for (key, value) in &body {
        let unsupported = |detail: String| Response::message(400, "Bad Request", detail);
        match key.as_str() {
            "tun" => {
                if let Some(enable) = value.get("enable") {
                    match enable.as_bool() {
                        Some(false) => {}
                        Some(true) => {
                            return unsupported(
                                "tun.enable: true cannot be applied live; restart the kernel with --tun (feature desktop-tun)"
                                    .to_string(),
                            )
                        }
                        None => return unsupported("tun.enable must be a boolean".to_string()),
                    }
                }
            }
            "mode" => {
                if value.as_str() != Some("rule") {
                    return unsupported(format!(
                        "mode {value} cannot be applied (only 'rule' can be honoured)"
                    ));
                }
            }
            "log-level" => {
                let Some(level) = value.as_str() else {
                    return unsupported("log-level must be a string".to_string());
                };
                if !matches!(
                    level,
                    "silent" | "error" | "warn" | "warning" | "info" | "debug"
                ) {
                    return unsupported(format!("log-level '{level}' is not a pinned value"));
                }
                let current = config.log_level.as_deref().unwrap_or("info");
                if level != current {
                    return unsupported(
                        "log-level cannot change at runtime; restart the kernel with the new log-level"
                            .to_string(),
                    );
                }
            }
            "mixed-port" | "port" | "socks-port" => {
                return unsupported(format!(
                    "{key} cannot change at runtime (listener is {}); restart the kernel",
                    config.listen
                ));
            }
            "ipv6" => {
                if value.as_bool() != Some(config.ipv6) {
                    return unsupported(
                        "ipv6 cannot change at runtime; restart the kernel with the new value"
                            .to_string(),
                    );
                }
            }
            "allow-lan" => {
                let expected = !config.listen.ip().is_loopback();
                if value.as_bool() != Some(expected) {
                    return unsupported(
                        "allow-lan cannot change at runtime; restart the kernel".to_string(),
                    );
                }
            }
            other => changed.push(other.to_string()),
        }
    }
    if let Some(key) = changed.first() {
        return Response::message(
            400,
            "Bad Request",
            format!("{key} cannot be applied by this kernel at runtime"),
        );
    }
    state
        .core
        .log_bus
        .publish("info", "configuration patched");
    Response::empty(204, "No Content")
}

// ---------------------------------------------------------------------------
// /proxies
// ---------------------------------------------------------------------------

fn proxy_name_uuid(name: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(name.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

fn adapter_fields(
    name: &str,
    type_name: &str,
    udp: bool,
    provider: Option<&str>,
    dialer_proxy: Option<&str>,
    with_id: bool,
) -> Map<String, Value> {
    let mut object = Map::new();
    object.insert("type".into(), json!(type_name));
    object.insert("name".into(), json!(name));
    object.insert("udp".into(), json!(udp));
    object.insert("uot".into(), json!(false));
    object.insert("xudp".into(), json!(false));
    object.insert("tfo".into(), json!(false));
    object.insert("mptcp".into(), json!(false));
    object.insert("smux".into(), json!(false));
    object.insert("interface".into(), json!(""));
    object.insert("routing-mark".into(), json!(0));
    object.insert("provider-name".into(), json!(provider.unwrap_or("")));
    object.insert("dialer-proxy".into(), json!(dialer_proxy.unwrap_or("")));
    object.insert("history".into(), json!([]));
    object.insert("extra".into(), json!({}));
    object.insert("alive".into(), json!(true));
    if with_id {
        object.insert("id".into(), json!(proxy_name_uuid(name)));
    }
    object
}

/// Health of a member name from the group runtime, when it was probed.
fn member_health(
    runtime: &crate::engine::RuntimeSnapshot,
) -> BTreeMap<String, (bool, Option<u16>)> {
    let mut out = BTreeMap::new();
    for status in runtime.groups.snapshot() {
        for member in status.members {
            out.entry(member.name.clone())
                .or_insert((member.alive, member.delay));
        }
    }
    out
}

fn proxy_json(
    runtime: &crate::engine::RuntimeSnapshot,
    proxy: &Proxy,
    provider: Option<&str>,
) -> Value {
    let health = member_health(runtime);
    let mut object = adapter_fields(
        &proxy.name,
        proxy.adapter_type_name(),
        proxy.udp_enabled(),
        provider,
        proxy.dialer_proxy(),
        true,
    );
    if let Some((alive, delay)) = health.get(&proxy.name) {
        object.insert("alive".into(), json!(*alive));
        if let Some(delay) = delay {
            object.insert(
                "history".into(),
                json!([{ "time": now_rfc3339(), "delay": delay }]),
            );
        }
    }
    Value::Object(object)
}

fn group_json(
    runtime: &crate::engine::RuntimeSnapshot,
    status: &crate::groups::GroupStatus,
) -> Value {
    let group_type = match status.kind {
        "select" => "Selector",
        "url-test" => "URLTest",
        "fallback" => "Fallback",
        "load-balance" => "LoadBalance",
        other => other,
    };
    let definition = runtime
        .config
        .proxy_groups
        .iter()
        .find(|group| group.name == status.name);
    let udp = definition.map(|group| !group.disable_udp).unwrap_or(true);
    let mut object = adapter_fields(&status.name, group_type, udp, None, None, false);
    object.insert("all".into(), json!(status.all));
    object.insert("hidden".into(), json!(status.hidden));
    object.insert("icon".into(), json!(status.icon));
    object.insert("emptyFallback".into(), json!(status.empty_fallback));
    match status.kind {
        "select" => {
            object.insert("now".into(), json!(status.now));
            let test_url = if status.test_url == crate::config::DEFAULT_TEST_URL {
                ""
            } else {
                status.test_url.as_str()
            };
            object.insert("testUrl".into(), json!(test_url));
        }
        "url-test" | "fallback" => {
            object.insert("now".into(), json!(status.now));
            object.insert(
                "testUrl".into(),
                json!(status.test_url),
            );
            object.insert("expectedStatus".into(), json!(status.expected_status));
            object.insert(
                "fixed".into(),
                json!(status.fixed.clone().unwrap_or_default()),
            );
        }
        "load-balance" => {
            object.insert("testUrl".into(), json!(status.test_url));
            object.insert("expectedStatus".into(), json!(status.expected_status));
        }
        _ => {}
    }
    Value::Object(object)
}

fn proxies_map(runtime: &crate::engine::RuntimeSnapshot) -> Map<String, Value> {
    let mut map = Map::new();
    for name in ["DIRECT", "REJECT", "REJECT-DROP"] {
        let mut object = adapter_fields(name, builtin_type(name), true, None, None, true);
        if name != "DIRECT" {
            object.insert("udp".into(), json!(true));
        }
        map.insert(name.to_string(), Value::Object(object));
    }
    for proxy in &runtime.config.proxies {
        map.insert(proxy.name.clone(), proxy_json(runtime, proxy, None));
    }
    for status in runtime.groups.snapshot() {
        map.insert(status.name.clone(), group_json(runtime, &status));
    }
    map
}

fn builtin_type(name: &str) -> &'static str {
    match name {
        "DIRECT" => "Direct",
        "REJECT" => "Reject",
        "REJECT-DROP" => "RejectDrop",
        _ => "Direct",
    }
}

fn proxy_value(runtime: &crate::engine::RuntimeSnapshot, name: &str) -> Option<Value> {
    if matches!(name, "DIRECT" | "COMPATIBLE") {
        return Some(Value::Object(adapter_fields(
            if name == "COMPATIBLE" { "DIRECT" } else { name },
            builtin_type(name),
            true,
            None,
            None,
            true,
        )));
    }
    if name == "REJECT" || name == "REJECT-DROP" {
        return Some(Value::Object(adapter_fields(
            name,
            builtin_type(name),
            true,
            None,
            None,
            true,
        )));
    }
    if let Some(status) = runtime.groups.group_status(name) {
        return Some(group_json(runtime, &status));
    }
    if let Some(proxy) = runtime.config.proxies.iter().find(|proxy| proxy.name == name) {
        return Some(proxy_json(runtime, proxy, None));
    }
    None
}

fn put_selection(request: &Request, state: &ControlState, group: &str) -> Response {
    let body = match serde_json::from_slice::<Value>(&request.body) {
        Ok(value) => value,
        Err(_) => return Response::message(400, "Bad Request", "Body invalid"),
    };
    let Some(name) = body.get("name").and_then(Value::as_str) else {
        return Response::message(400, "Bad Request", "Body invalid");
    };
    let runtime = state.core.runtime.snapshot();
    match runtime.groups.select(group, name) {
        Ok(true) => {
            state.core.log_bus.publish(
                "info",
                format!("group '{group}' selected '{name}'"),
            );
            Response::empty(204, "No Content")
        }
        Ok(false) => Response::message(
            400,
            "Bad Request",
            "Selector update error: proxy not exist",
        ),
        Err(crate::groups::GroupError::UnknownGroup(_)) => {
            Response::message(404, "Not Found", "Resource not found")
        }
        Err(crate::groups::GroupError::UnknownMember(_, _)) => Response::message(
            400,
            "Bad Request",
            "Selector update error: proxy not exist",
        ),
        Err(error) => Response::message(400, "Bad Request", error.to_string()),
    }
}

fn delete_selection(group: &str, state: &ControlState) -> Response {
    let runtime = state.core.runtime.snapshot();
    let Some(definition) = runtime
        .config
        .proxy_groups
        .iter()
        .find(|definition| definition.name == group)
    else {
        return Response::message(404, "Not Found", "Resource not found");
    };
    // Pinned `unfixedProxy` only clears `url-test`/`fallback`; a Selector has
    // no `fixed` state and answers 400.
    if definition.kind == GroupKind::Select || definition.kind == GroupKind::LoadBalance {
        return Response::message(400, "Bad Request", "Body invalid");
    }
    if let Some(status) = runtime.groups.group_status(group) {
        if status.now.is_empty() {
            return Response::message(400, "Bad Request", "Body invalid");
        }
    }
    match runtime.groups.select(group, "") {
        Ok(_) => Response::empty(204, "No Content"),
        Err(_) => Response::empty(204, "No Content"),
    }
}

// ---------------------------------------------------------------------------
// /providers/proxies
// ---------------------------------------------------------------------------

fn provider_vehicle(vehicle: &ProviderVehicle) -> &'static str {
    match vehicle {
        ProviderVehicle::File { .. } => "File",
        ProviderVehicle::Http { .. } => "HTTP",
        ProviderVehicle::Inline => "Inline",
    }
}

fn rule_format_name(format: crate::config::RuleFormat) -> &'static str {
    match format {
        crate::config::RuleFormat::Yaml => "YamlRule",
        crate::config::RuleFormat::Text => "TextRule",
        crate::config::RuleFormat::Mrs => "MrsRule",
    }
}

fn provider_nodes(
    runtime: &crate::engine::RuntimeSnapshot,
    provider: &str,
) -> Vec<Value> {
    let mut nodes = Vec::new();
    if let Some(slot) = runtime.providers.proxy_provider(provider) {
        for proxy in &slot.snapshot().proxies {
            nodes.push(proxy_json(runtime, proxy, Some(provider)));
        }
    }
    nodes
}

fn proxy_provider_value(
    runtime: &crate::engine::RuntimeSnapshot,
    provider: &str,
) -> Option<Value> {
    if let Some(slot) = runtime.providers.proxy_provider(provider) {
        let snapshot = slot.snapshot();
        return Some(json!({
            "name": provider,
            "type": "Proxy",
            "vehicleType": provider_vehicle(&slot.config.vehicle),
            "proxies": provider_nodes(runtime, provider),
            "testUrl": slot.config.health_check.url.clone().unwrap_or_default(),
            "expectedStatus": slot.config.health_check.expected_status.clone(),
            "updatedAt": system_time_rfc3339(snapshot.updated_at),
        }));
    }
    if let Some(status) = runtime.groups.group_status(provider) {
        let mut nodes = Vec::new();
        for name in &status.all {
            if let Some(value) = proxy_value(runtime, name) {
                nodes.push(value);
            }
        }
        let test_url = if status.test_url == crate::config::DEFAULT_TEST_URL {
            String::new()
        } else {
            status.test_url.clone()
        };
        return Some(json!({
            "name": provider,
            "type": "Proxy",
            "vehicleType": "Compatible",
            "proxies": nodes,
            "testUrl": test_url,
            "expectedStatus": status.expected_status,
            "updatedAt": system_time_rfc3339(SystemTime::UNIX_EPOCH),
        }));
    }
    if provider == "default" {
        let mut nodes = Vec::new();
        for name in ["DIRECT", "REJECT", "REJECT-DROP"] {
            nodes.push(Value::Object(adapter_fields(
                name,
                builtin_type(name),
                true,
                None,
                None,
                true,
            )));
        }
        for proxy in &runtime.config.proxies {
            nodes.push(proxy_json(runtime, proxy, None));
        }
        for status in runtime.groups.snapshot() {
            nodes.push(group_json(runtime, &status));
        }
        return Some(json!({
            "name": "default",
            "type": "Proxy",
            "vehicleType": "Compatible",
            "proxies": nodes,
            "testUrl": "",
            "expectedStatus": "*",
            "updatedAt": system_time_rfc3339(SystemTime::UNIX_EPOCH),
        }));
    }
    None
}

fn provider_is_compatible(runtime: &crate::engine::RuntimeSnapshot, provider: &str) -> bool {
    provider == "default" || runtime.groups.group_status(provider).is_some()
}

/// Whether a Compatible provider (a group or the reserved `default`) exposes
/// `name` as one of its adapters. Pinned registers the reserved `default`
/// provider over every proxy/group and each group's explicit `proxies:` list
/// as its own Compatible provider, so `/providers/proxies/<group>/<node>` and
/// `<node>/healthcheck` resolve members through it.
fn compatible_provider_has_node(
    runtime: &crate::engine::RuntimeSnapshot,
    provider: &str,
    name: &str,
) -> bool {
    if let Some(status) = runtime.groups.group_status(provider) {
        return status.all.iter().any(|member| member == name);
    }
    if provider == "default" {
        return matches!(name, "DIRECT" | "COMPATIBLE" | "REJECT" | "REJECT-DROP")
            || runtime.config.proxies.iter().any(|proxy| proxy.name == name)
            || runtime.groups.group_status(name).is_some();
    }
    false
}

fn proxy_providers_map(runtime: &crate::engine::RuntimeSnapshot) -> Map<String, Value> {
    let mut map = Map::new();
    for provider in runtime.providers.proxy_provider_names() {
        if let Some(value) = proxy_provider_value(runtime, provider) {
            map.insert(provider.to_string(), value);
        }
    }
    for status in runtime.groups.snapshot() {
        if let Some(value) = proxy_provider_value(runtime, &status.name) {
            map.insert(status.name.clone(), value);
        }
    }
    if let Some(value) = proxy_provider_value(runtime, "default") {
        map.insert("default".to_string(), value);
    }
    map
}

fn provider_node(
    runtime: &crate::engine::RuntimeSnapshot,
    provider: &str,
    name: &str,
) -> Option<Proxy> {
    runtime
        .providers
        .proxy_provider(provider)?
        .snapshot()
        .proxies
        .iter()
        .find(|proxy| proxy.name == name)
        .cloned()
}

// ---------------------------------------------------------------------------
// /providers/rules
// ---------------------------------------------------------------------------

fn rule_providers_map(runtime: &crate::engine::RuntimeSnapshot) -> Map<String, Value> {
    let mut map = Map::new();
    for name in runtime.providers.rule_provider_names() {
        let Some(slot) = runtime.providers.rule_provider(name) else {
            continue;
        };
        let snapshot = slot.snapshot();
        let mut object = Map::new();
        object.insert("behavior".into(), json!(match slot.config.behavior {
            crate::config::RuleBehavior::Domain => "Domain",
            crate::config::RuleBehavior::IpCidr => "IPCIDR",
            crate::config::RuleBehavior::Classical => "Classical",
        }));
        // Pinned inline providers leave `format` at its zero value (""); file
        // providers report the parsed format.
        object.insert(
            "format".into(),
            if matches!(slot.config.vehicle, ProviderVehicle::Inline) {
                json!("")
            } else {
                json!(rule_format_name(slot.config.format))
            },
        );
        object.insert("name".into(), json!(name));
        object.insert("ruleCount".into(), json!(snapshot.compiled.count));
        object.insert("type".into(), json!("Rule"));
        object.insert("vehicleType".into(), json!(provider_vehicle(&slot.config.vehicle)));
        object.insert(
            "updatedAt".into(),
            json!(system_time_rfc3339(snapshot.updated_at)),
        );
        if matches!(slot.config.vehicle, ProviderVehicle::Inline) {
            object.insert("payload".into(), json!(snapshot.payload.entries));
        }
        map.insert(name.to_string(), Value::Object(object));
    }
    map
}

// ---------------------------------------------------------------------------
// /connections
// ---------------------------------------------------------------------------

fn connections_json(core: &ControlCore) -> Value {
    let stats = core.counters.snapshot();
    let dns_mode = core
        .runtime
        .snapshot()
        .config
        .dns
        .enhanced_mode
        .as_str()
        .to_string();
    let entries = core.connections.snapshot();
    let connections = if entries.is_empty() {
        Value::Null
    } else {
        Value::Array(
            entries
                .iter()
                .map(|entry| connection_json(entry, &dns_mode))
                .collect(),
        )
    };
    json!({
        "downloadTotal": stats.bytes_down,
        "uploadTotal": stats.bytes_up,
        "connections": connections,
        "memory": rss_bytes(),
    })
}

fn connection_json(entry: &Arc<OpenConnection>, dns_mode: &str) -> Value {
    let destination_ip = entry
        .destination_ip
        .map(|ip| ip.to_string())
        .unwrap_or_default();
    json!({
        "id": entry.id,
        "metadata": {
            "network": entry.network,
            "type": entry.kind,
            "sourceIP": entry.source_ip.to_string(),
            "destinationIP": destination_ip,
            "sourceGeoIP": Value::Null,
            "destinationGeoIP": Value::Null,
            "sourceIPASN": "",
            "destinationIPASN": "",
            "sourcePort": entry.source_port.to_string(),
            "destinationPort": entry.destination_port.to_string(),
            "inboundIP": inbound_ip(entry),
            "inboundPort": entry.inbound_port.to_string(),
            "inboundName": "DEFAULT-MIXED",
            "inboundUser": "",
            "rematchName": "",
            "host": entry.host,
            "dnsMode": dns_mode,
            "uid": 0,
            "process": "",
            "processPath": "",
            "specialProxy": "",
            "specialRules": "",
            "remoteDestination": if entry.host.is_empty() { destination_ip } else { entry.host.clone() },
            "dscp": 0,
            "sniffHost": "",
        },
        "upload": entry.upload.load(Ordering::Relaxed),
        "download": entry.download.load(Ordering::Relaxed),
        "start": system_time_rfc3339(entry.start),
        "chains": entry.chains,
        "providerChains": [],
        "rule": entry.rule,
        "rulePayload": entry.rule_payload,
    })
}

fn inbound_ip(entry: &OpenConnection) -> String {
    entry.source_ip.to_string()
}

// ---------------------------------------------------------------------------
// Delay tests
// ---------------------------------------------------------------------------

enum DelayNode {
    Direct,
    Proxy(Arc<Proxy>),
    Group(usize),
}

enum DelayError {
    Failed(String),
}

fn parse_url(raw: &str) -> Option<(String, bool, u16, String)> {
    let (scheme, rest) = raw.split_once("://")?;
    let scheme_lower = scheme.to_ascii_lowercase();
    let https = match scheme_lower.as_str() {
        "http" => false,
        "https" => true,
        _ => return None,
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = authority[1..end].to_string();
        let port = authority[end + 1..]
            .strip_prefix(':')
            .and_then(|port| port.parse().ok())
            .unwrap_or(if https { 443 } else { 80 });
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (
                host.to_string(),
                port.parse().ok().unwrap_or(if https { 443 } else { 80 }),
            ),
            None => (
                authority.to_string(),
                if https { 443 } else { 80 },
            ),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some((host, https, port, path.to_string()))
}

fn expected_matches(spec: Option<&str>, status: u16) -> bool {
    let Some(spec) = spec.map(str::trim).filter(|spec| !spec.is_empty()) else {
        return true;
    };
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() || part == "*" {
            return true;
        }
        if let Some((start, end)) = part.split_once('-') {
            let (Ok(start), Ok(end)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>())
            else {
                return false;
            };
            if (start..=end).contains(&status) {
                return true;
            }
        } else if part.parse::<u16>() == Ok(status) {
            return true;
        }
    }
    false
}

async fn proxy_delay(
    request: &Request,
    state: &ControlState,
    name: &str,
    provider: Option<&str>,
) -> Response {
    let Some(timeout_text) = request.query("timeout") else {
        return Response::message(400, "Bad Request", "Body invalid");
    };
    let Ok(timeout_ms) = timeout_text.parse::<i64>() else {
        return Response::message(400, "Bad Request", "Body invalid");
    };
    if !(i16::MIN as i64..=i16::MAX as i64).contains(&timeout_ms) {
        return Response::message(400, "Bad Request", "Body invalid");
    }
    if let Some(expected) = request.query("expected") {
        if expected != "*" && !expected_ranges_valid(expected) {
            return Response::message(400, "Bad Request", "Body invalid");
        }
    }
    let url = request.query("url").unwrap_or_default();
    let runtime = state.core.runtime.snapshot();
    let node = match provider {
        Some(provider) => match provider_node(&runtime, provider, name) {
            Some(proxy) => DelayNode::Proxy(Arc::new(proxy)),
            None => {
                // A Compatible provider (group or reserved `default`) exposes
                // its members through the same route; resolve them like
                // `/proxies/:name/delay` once membership is confirmed.
                match resolve_delay_node(&runtime, name) {
                    Some(node)
                        if provider_is_compatible(&runtime, provider)
                            && compatible_provider_has_node(&runtime, provider, name) =>
                    {
                        node
                    }
                    _ => return Response::message(404, "Not Found", "Resource not found"),
                }
            }
        },
        None => match resolve_delay_node(&runtime, name) {
            Some(node) => node,
            None => return Response::message(404, "Not Found", "Resource not found"),
        },
    };
    let timeout = Duration::from_millis(timeout_ms.max(1) as u64);
    let expected = request.query("expected").map(str::to_string);
    let tls = runtime.tls.clone();
    let counters = state.core.counters.clone();
    let result = tokio::time::timeout(
        timeout,
        measure_delay(&runtime, node, &url, timeout, &tls, expected.as_deref(), &counters),
    )
    .await;
    match result {
        Err(_) => Response::message(504, "Gateway Timeout", "Timeout"),
        Ok(Ok(delay)) => Response::json(200, "OK", json!({ "delay": delay })),
        Ok(Err(DelayError::Failed(detail))) => {
            tracing::debug!("delay test failed: {detail}");
            Response::message(
                503,
                "Service Unavailable",
                "An error occurred in the delay test",
            )
        }
    }
}

fn expected_ranges_valid(spec: &str) -> bool {
    spec.split(',').all(|part| {
        let part = part.trim();
        if part.is_empty() {
            return true;
        }
        match part.split_once('-') {
            Some((start, end)) => {
                start.trim().parse::<u16>().is_ok() && end.trim().parse::<u16>().is_ok()
            }
            None => part.parse::<u16>().is_ok(),
        }
    })
}

fn resolve_delay_node(
    runtime: &crate::engine::RuntimeSnapshot,
    name: &str,
) -> Option<DelayNode> {
    if name == "DIRECT" || name == "COMPATIBLE" {
        return Some(DelayNode::Direct);
    }
    if name == "REJECT" || name == "REJECT-DROP" {
        return None;
    }
    if let Some(index) = runtime.groups.group_index(name) {
        return Some(DelayNode::Group(index));
    }
    if let Some(proxy) = runtime.config.proxies.iter().find(|proxy| proxy.name == name) {
        return Some(DelayNode::Proxy(Arc::new(proxy.clone())));
    }
    None
}

async fn measure_delay(
    runtime: &Arc<crate::engine::RuntimeSnapshot>,
    node: DelayNode,
    url: &str,
    _timeout: Duration,
    tls: &Arc<crate::outbound::tls::ClientTls>,
    expected: Option<&str>,
    counters: &crate::engine::Counters,
) -> Result<u16, DelayError> {
    let Some((host, https, port, path)) = parse_url(url) else {
        return Err(DelayError::Failed("unsupported url".to_string()));
    };
    let target = Target::new(&host, host.parse().ok()).with_port(port);
    let selected = match node {
        DelayNode::Direct => crate::groups::Selected::Direct,
        DelayNode::Proxy(proxy) => crate::groups::Selected::Proxy {
            proxy,
            path: Vec::new(),
        },
        DelayNode::Group(index) => runtime
            .groups
            .resolve_action(Action::Group(index), &target, false)
            .map_err(|error| DelayError::Failed(error.to_string()))?,
    };
    let start = Instant::now();
    let mut stream: Box<dyn crate::outbound::Stream> = match &selected {
        crate::groups::Selected::Direct => {
            let stream = crate::outbound::connect_bound_str(&host, port)
                .await
                .map_err(|error| DelayError::Failed(format!("connect: {error}")))?;
            Box::new(stream)
        }
        crate::groups::Selected::Proxy { proxy, .. } => {
            let hops = chain_for(&runtime.config, proxy);
            let dialed = crate::outbound::dial_chain(
                &hops,
                &crate::outbound::Target {
                    host: host.clone(),
                    port,
                },
                Duration::from_secs(10),
                tls,
            )
            .await
            .map_err(|error| DelayError::Failed(error.to_string()))?;
            dialed.stream
        }
        crate::groups::Selected::Reject | crate::groups::Selected::RejectDrop => {
            return Err(DelayError::Failed("rejected".to_string()))
        }
    };
    let request = format!(
        "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: billow-kernel/{VERSION}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    let status = if https {
        let settings = crate::proxies::TlsSettings {
            sni: None,
            skip_cert_verify: false,
            alpn: Vec::new(),
            ..Default::default()
        };
        let mut tls_stream = crate::outbound::tls::wrap_stream(stream, &host, &settings, tls)
            .await
            .map_err(|error| DelayError::Failed(format!("tls: {error}")))?;
        tls_stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| DelayError::Failed(format!("write: {error}")))?;
        read_head_status(&mut tls_stream, counters).await?
    } else {
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| DelayError::Failed(format!("write: {error}")))?;
        read_head_status(&mut stream, counters).await?
    };
    // Pinned records an unsatisfied `expected` as a failed health sample but
    // still reports the measured delay; the API response is the delay.
    if !expected_matches(expected, status) {
        tracing::debug!("delay status {status} does not match the requested expected ranges");
    }
    let elapsed = start.elapsed().as_millis().clamp(1, u16::MAX as u128) as u16;
    Ok(elapsed)
}

async fn read_head_status<S>(stream: &mut S, counters: &crate::engine::Counters) -> Result<u16, DelayError>
where
    S: AsyncRead + Unpin,
{
    let mut head = Vec::with_capacity(256);
    loop {
        let mut byte = [0u8; 1];
        let read = stream
            .read(&mut byte)
            .await
            .map_err(|error| DelayError::Failed(format!("read: {error}")))?;
        if read == 0 {
            return Err(DelayError::Failed("closed before the head".to_string()));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") || head.len() > 8192 {
            break;
        }
    }
    counters.bytes_down.fetch_add(head.len() as u64, Ordering::Relaxed);
    let text = String::from_utf8_lossy(&head);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| DelayError::Failed("malformed response head".to_string()))?;
    Ok(status)
}

// ---------------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------------

enum StreamKind {
    Logs,
    Traffic,
    Memory,
    Connections { interval: u64 },
}

async fn run_stream(
    conn: &mut BoxConn,
    request: &Request,
    state: &ControlState,
    kind: StreamKind,
) {
    if request.is_websocket() {
        if !write_websocket_upgrade(conn, request, state).await {
            return;
        }
        match kind {
            StreamKind::Logs => websocket_logs(conn, request, state).await,
            StreamKind::Traffic => websocket_traffic(conn, state).await,
            StreamKind::Memory => websocket_memory(conn, state).await,
            StreamKind::Connections { interval } => {
                websocket_connections(conn, state, interval).await
            }
        }
        return;
    }
    if write_stream_head(conn, request, state).await.is_err() {
        return;
    }
    match kind {
        StreamKind::Logs => ndjson_logs(conn, request, state).await,
        StreamKind::Traffic => ndjson_traffic(conn, state).await,
        StreamKind::Memory => ndjson_memory(conn, state).await,
        StreamKind::Connections { .. } => {
            // A plain `/connections` request is not a stream; the router
            // returns the one-shot snapshot instead.
            let _ = write_chunk(conn, &serde_json::to_vec(&connections_json(&state.core)).unwrap_or_default()).await;
        }
    }
}

fn log_level_rank(level: &str) -> u8 {
    match level {
        "debug" => 0,
        "info" => 1,
        "warning" | "warn" => 2,
        "error" => 3,
        "silent" => 4,
        _ => 1,
    }
}

fn requested_log_level(request: &Request) -> Result<u8, Response> {
    // Pinned `getLogs` defaults an empty/missing `level` to info and rejects
    // anything outside `log.LogLevelMapping` before switching to stream mode
    // (`warn` is not a key there; the emitted type is `warning`).
    let level = match request.query("level") {
        None | Some("") => "info",
        Some(level) => level,
    };
    match level {
        "debug" | "info" | "warning" | "error" | "silent" => Ok(log_level_rank(level)),
        _ => Err(Response::message(400, "Bad Request", "Body invalid")),
    }
}

fn log_record_json(request: &Request, record: &LogRecord, structured: bool) -> Vec<u8> {
    if structured {
        let level = match record.level {
            "warning" => "warn",
            other => other,
        };
        let value = json!({
            "time": local_time_only(),
            "level": level,
            "message": record.payload,
            "fields": [],
        });
        let mut bytes = serde_json::to_vec(&value).unwrap_or_default();
        bytes.push(b'\n');
        bytes
    } else {
        let _ = request;
        let value = json!({"type": record.level, "payload": record.payload});
        let mut bytes = serde_json::to_vec(&value).unwrap_or_default();
        bytes.push(b'\n');
        bytes
    }
}

async fn ndjson_logs(conn: &mut BoxConn, request: &Request, state: &ControlState) {
    let Ok(level) = requested_log_level(request) else {
        return;
    };
    let structured = request.query("format") == Some("structured");
    let mut receiver = state.core.log_bus.subscribe();
    loop {
        match receiver.recv().await {
            Ok(record) => {
                if log_level_rank(record.level) < level {
                    continue;
                }
                let bytes = log_record_json(request, &record, structured);
                if write_chunk(conn, &bytes).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

async fn websocket_logs(conn: &mut BoxConn, request: &Request, state: &ControlState) {
    let Ok(level) = requested_log_level(request) else {
        return;
    };
    let structured = request.query("format") == Some("structured");
    let mut receiver = state.core.log_bus.subscribe();
    loop {
        match receiver.recv().await {
            Ok(record) => {
                if log_level_rank(record.level) < level {
                    continue;
                }
                let bytes = log_record_json(request, &record, structured);
                if write_ws_text(conn, &bytes).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

async fn ndjson_traffic(conn: &mut BoxConn, state: &ControlState) {
    let counters = state.core.counters.clone();
    let mut last_total = counters.snapshot();
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let stats = counters.snapshot();
        let up = stats.bytes_up.saturating_sub(last_total.bytes_up);
        let down = stats.bytes_down.saturating_sub(last_total.bytes_down);
        last_total = stats;
        let value = json!({
            "up": up,
            "down": down,
            "upTotal": stats.bytes_up,
            "downTotal": stats.bytes_down,
        });
        let mut bytes = serde_json::to_vec(&value).unwrap_or_default();
        bytes.push(b'\n');
        if write_chunk(conn, &bytes).await.is_err() {
            break;
        }
    }
}

async fn websocket_traffic(conn: &mut BoxConn, state: &ControlState) {
    let counters = state.core.counters.clone();
    let mut last_total = counters.snapshot();
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    loop {
        ticker.tick().await;
        let stats = counters.snapshot();
        let up = stats.bytes_up.saturating_sub(last_total.bytes_up);
        let down = stats.bytes_down.saturating_sub(last_total.bytes_down);
        last_total = stats;
        let bytes = serde_json::to_vec(&json!({
            "up": up,
            "down": down,
            "upTotal": stats.bytes_up,
            "downTotal": stats.bytes_down,
        }))
        .unwrap_or_default();
        if write_ws_text(conn, &bytes).await.is_err() {
            break;
        }
    }
}

async fn ndjson_memory(conn: &mut BoxConn, state: &ControlState) {
    let _ = state;
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    loop {
        ticker.tick().await;
        let mut bytes = serde_json::to_vec(&json!({"inuse": rss_bytes(), "oslimit": 0}))
            .unwrap_or_default();
        bytes.push(b'\n');
        if write_chunk(conn, &bytes).await.is_err() {
            break;
        }
    }
}

async fn websocket_memory(conn: &mut BoxConn, state: &ControlState) {
    let _ = state;
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    loop {
        ticker.tick().await;
        let bytes = serde_json::to_vec(&json!({"inuse": rss_bytes(), "oslimit": 0}))
            .unwrap_or_default();
        if write_ws_text(conn, &bytes).await.is_err() {
            break;
        }
    }
}

async fn websocket_connections(conn: &mut BoxConn, state: &ControlState, interval: u64) {
    let mut ticker = tokio::time::interval(Duration::from_millis(interval.max(1)));
    loop {
        ticker.tick().await;
        let bytes =
            serde_json::to_vec(&connections_json(&state.core)).unwrap_or_default();
        if write_ws_text(conn, &bytes).await.is_err() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// WebSocket framing
// ---------------------------------------------------------------------------

async fn write_websocket_upgrade(
    conn: &mut BoxConn,
    request: &Request,
    state: &ControlState,
) -> bool {
    let Some(key) = request.header("sec-websocket-key") else {
        let _ = write_simple(conn, 400, "Bad Request", b"handshake error: bad Sec-WebSocket-Key header").await;
        return false;
    };
    if key.len() != 24 {
        let _ = write_simple(conn, 400, "Bad Request", b"handshake error: bad Sec-WebSocket-Key header").await;
        return false;
    }
    let connection = request
        .header("connection")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    if !connection.contains("upgrade") {
        let _ = write_simple(conn, 400, "Bad Request", b"handshake error: bad Connection header").await;
        return false;
    }
    let accept = websocket_accept(key);
    let headers = common_headers(request, state);
    let mut head = String::from("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n");
    head.push_str(&format!("Sec-WebSocket-Accept: {accept}\r\n"));
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    conn.write_all(head.as_bytes()).await.is_ok()
}

async fn write_ws_text(conn: &mut BoxConn, payload: &[u8]) -> io::Result<()> {
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x81);
    match payload.len() {
        length @ 0..=125 => frame.push(length as u8),
        length @ 126..=65535 => {
            frame.push(126);
            frame.extend_from_slice(&(length as u16).to_be_bytes());
        }
        length => {
            frame.push(127);
            frame.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    conn.write_all(&frame).await?;
    conn.flush().await
}

fn websocket_accept(key: &str) -> String {
    use sha1::{Digest, Sha1};
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(GUID.as_bytes());
    base64(&hasher.finalize())
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0] as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        let combined = (first << 16) | (second << 8) | third;
        out.push(TABLE[((combined >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((combined >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((combined >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(combined & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

fn system_time_rfc3339(time: SystemTime) -> String {
    let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();
    let days = (secs / 86_400) as i64;
    let seconds_of_day = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        seconds_of_day / 3600,
        seconds_of_day / 60 % 60,
        seconds_of_day % 60
    )
}

fn now_rfc3339() -> String {
    system_time_rfc3339(SystemTime::now())
}

fn local_time_only() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds_of_day = duration.as_secs() % 86_400;
    format!(
        "{:02}:{:02}:{:02}Z",
        seconds_of_day / 3600,
        seconds_of_day / 60 % 60,
        seconds_of_day % 60
    )
}

/// Howard Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

fn rss_bytes() -> u64 {
    #[cfg(unix)]
    {
        // `ru_maxrss` is bytes on macOS and kilobytes on Linux/Android.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } == 0 {
            let value = usage.ru_maxrss.max(0) as u64;
            if cfg!(target_os = "macos") {
                return value;
            }
            return value.saturating_mul(1024);
        }
        0
    }
    #[cfg(not(unix))]
    {
        0
    }
}
