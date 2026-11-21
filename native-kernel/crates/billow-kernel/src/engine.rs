//! Session engine: binds the mixed listener, evaluates rules, dials DIRECT
//! targets and copies bytes in both directions with bounded buffers.
//!
//! Every accepted connection is tracked until its task has returned, so after
//! [`Kernel::stop`] returns there are no live sessions, tasks or buffers.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;


use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::config::{Action, Config, ConfigError, GeoSiteDatabase, LoadedConfig};
use crate::identity::Identity;
use crate::inbound::{self, HandshakeError, InboundAuth};
use crate::outbound;
use crate::rules::{RuleSet, Target};

/// Version of this kernel (crate version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Tunables. Defaults keep memory bounded (R3/R4); T7 can shrink buffers for the extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Per-direction copy buffer size in bytes.
    pub buffer_size: usize,
    /// Sessions holding a slot at once; further connections wait in the backlog.
    pub max_sessions: usize,
    /// Deadline for the inbound handshake.
    pub handshake_timeout: Duration,
    /// Deadline for dialling the DIRECT target.
    pub dial_timeout: Duration,
    /// Extra time given to the second direction after the first one finished.
    pub half_close_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            buffer_size: 16 * 1024,
            max_sessions: 256,
            handshake_timeout: crate::config::default_handshake_timeout(),
            dial_timeout: Duration::from_secs(10),
            half_close_timeout: Duration::from_secs(30),
        }
    }
}

/// Error returned by [`Kernel::start`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum StartError {
    #[error("invalid kernel limits: {0}")]
    Limits(String),
    #[error("bind {addr} failed: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: Arc<io::Error>,
    },
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),
}

/// Per-session accounting exposed to hosts and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    pub accepted: u64,
    pub active: u64,
    pub completed: u64,
    pub rejected: u64,
    pub failed: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

#[derive(Default)]
pub(crate) struct Counters {
    accepted: AtomicU64,
    active: AtomicU64,
    completed: AtomicU64,
    rejected: AtomicU64,
    failed: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
}

impl Counters {
    pub(crate) fn snapshot(&self) -> Stats {
        Stats {
            accepted: self.accepted.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
        }
    }
}

/// Shared, immutable session context.
struct SessionContext {
    rules: Arc<RuleSet>,
    /// `authentication` users for the mixed inbound (SOCKS5 RFC 1929 / HTTP 407).
    auth: InboundAuth,
    limits: Limits,
    counters: Arc<Counters>,
}

/// A running kernel. Dropping it without calling [`Kernel::stop`] stops it too.
pub struct Kernel {
    identity: Identity,
    config: Arc<Config>,
    rules: Arc<RuleSet>,
    limits: Limits,
    counters: Arc<Counters>,
    stop_tx: watch::Sender<bool>,
    supervisor: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Kernel {
    /// Load `path`, compile rules (geosite databases from `geosite_dir`) and bind the listener.
    pub fn start(
        path: &std::path::Path,
        geosite_dir: Option<PathBuf>,
        limits: Limits,
    ) -> Result<(Kernel, Vec<String>), StartError> {
        let yaml = std::fs::read_to_string(path).map_err(|e| {
            StartError::Config(ConfigError::Invalid(format!("{}: {e}", path.display())))
        })?;
        let loaded = crate::config::load_config(&yaml, &path.display().to_string())?;
        Kernel::start_with_yaml(&loaded, geosite_dir, limits)
    }

    /// Start from YAML text (embedding hosts such as the iOS extension use this entry).
    pub fn start_from_yaml(
        yaml: &str,
        geosite_dir: Option<PathBuf>,
        limits: Limits,
    ) -> Result<(Kernel, Vec<String>), StartError> {
        let loaded = crate::config::load_config(yaml, "<inline>")?;
        Kernel::start_with_yaml(&loaded, geosite_dir, limits)
    }

    /// Start from a [`LoadedConfig`]; returns warnings so hosts can surface them.
    pub fn start_with_yaml(
        loaded: &LoadedConfig,
        geosite_dir: Option<PathBuf>,
        limits: Limits,
    ) -> Result<(Kernel, Vec<String>), StartError> {
        validate_limits(&limits)?;
        let keys = loaded.config.geosite_databases();
        let geosite = if keys.is_empty() {
            GeoSiteDatabase::default()
        } else {
            let key = keys.iter().next().cloned().unwrap_or_default();
            let dir = geosite_dir.as_ref().ok_or_else(|| {
                StartError::Config(ConfigError::Unsupported(format!(
                    "GEOSITE,{key} requires --geosite-dir"
                )))
            })?;
            GeoSiteDatabase::load_from_dir(dir, &keys)?
        };
        let config = Arc::new(loaded.config.clone());
        let rules = RuleSet::from_config(&config, geosite);

        // Bind with a short-lived current-thread runtime on this thread; the
        // caller may itself be inside a tokio runtime (tests, hosts), so the
        // long-lived runtime must never block here.
        let requested = config.listen;
        let listener =
            std::net::TcpListener::bind(requested).map_err(|source| StartError::Bind {
                addr: requested,
                source: Arc::new(source),
            })?;
        listener
            .set_nonblocking(true)
            .map_err(|source| StartError::Bind {
                addr: requested,
                source: Arc::new(source),
            })?;
        let local = listener.local_addr().map_err(|source| StartError::Bind {
            addr: requested,
            source: Arc::new(source),
        })?;

        let counters = Arc::new(Counters::default());
        let (stop_tx, stop_rx) = watch::channel(false);
        let context = Arc::new(SessionContext {
            rules: rules.clone(),
            auth: InboundAuth {
                users: loaded.config.inbound_users.clone(),
            },
            limits,
            counters: counters.clone(),
        });
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let config_for_thread = config.clone();
        let supervisor = std::thread::Builder::new()
            .name("billow-kernel-supervisor".to_string())
            .spawn(move || {
                supervisor_thread(listener, context, config_for_thread, stop_rx, started_tx)
            })
            .map_err(|e| StartError::Limits(format!("spawn supervisor: {e}")))?;
        if let Err(e) = started_rx.recv() {
            let _ = supervisor;
            return Err(StartError::Limits(format!(
                "supervisor failed to start: {e}"
            )));
        }

        let identity = Identity::new(VERSION, local, &config, &geosite_dir, rules.rule_count());
        info!(
            instance = %identity.uuid, pid = identity.pid, version = VERSION, listen = %local,
            "billow-kernel started; {}", config.feature_summary()
        );
        Ok((
            Kernel {
                identity,
                config,
                rules,
                limits,
                counters,
                stop_tx,
                supervisor: Mutex::new(Some(supervisor)),
            },
            loaded.warnings.clone(),
        ))
    }

    /// Correlatable instance identity (uuid, pid, version, listener, config digest).
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Actually bound address.
    pub fn listen_addr(&self) -> SocketAddr {
        self.identity.listen
    }

    /// Host-supplied metadata such as the actual port override used at start.
    pub fn set_identity(&mut self, identity: Identity) {
        self.identity = identity;
    }

    pub fn config(&self) -> &Arc<Config> {
        &self.config
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub fn stats(&self) -> Stats {
        self.counters.snapshot()
    }

    /// Evaluate a destination without accepting a connection (diagnostics/tests).
    /// Returns the action and a human-readable `rule -> ACTION` label.
    pub fn evaluate(&self, host: &str, ip: Option<IpAddr>) -> (Action, String) {
        let m = self.rules.evaluate(&Target::new(host, ip));
        (m.rule.action, m.label(&self.config))
    }

    /// Stop accepting, wait for every session task and the listener to exit.
    pub fn stop(&mut self) -> io::Result<()> {
        let _ = self.stop_tx.send(true);
        let handle = self
            .supervisor
            .lock()
            .expect("supervisor mutex poisoned")
            .take();
        let mut join_error = None;
        if let Some(handle) = handle {
            if handle.join().is_err() {
                join_error = Some(io::Error::other("kernel thread panicked"));
            }
        }
        let stats = self.stats();
        info!(
            instance = %self.identity.uuid, sessions = stats.accepted, active = stats.active,
            finished = stats.completed + stats.rejected + stats.failed, "billow-kernel stopped"
        );
        match join_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl Drop for Kernel {
    fn drop(&mut self) {
        if self
            .supervisor
            .get_mut()
            .map(|g| g.is_some())
            .unwrap_or(false)
        {
            debug!(instance = %self.identity.uuid, "Kernel dropped without stop(); stopping now");
            let _ = self.stop();
        }
    }
}

fn validate_limits(limits: &Limits) -> Result<(), StartError> {
    if limits.buffer_size == 0 || limits.buffer_size > 1024 * 1024 {
        return Err(StartError::Limits(format!(
            "buffer_size {} outside 1..=1048576",
            limits.buffer_size
        )));
    }
    if limits.max_sessions == 0 {
        return Err(StartError::Limits("max_sessions must be > 0".to_string()));
    }
    if limits.handshake_timeout.is_zero() || limits.dial_timeout.is_zero() {
        return Err(StartError::Limits("timeouts must be > 0".to_string()));
    }
    Ok(())
}

/// Supervisor thread: owns the long-lived runtime (listener, accept loop,
/// session tasks) and drops it only after every session has been joined.
fn supervisor_thread(
    listener: std::net::TcpListener,
    context: Arc<SessionContext>,
    config: Arc<Config>,
    mut stop: watch::Receiver<bool>,
    started: std::sync::mpsc::SyncSender<()>,
) {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("billow-kernel")
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            let _ = started.send(());
            warn!("runtime build failed: {e}");
            return;
        }
    };
    let result = runtime.block_on(async {
        let listener = match TcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(e) => return Err(io::Error::other(format!("adopt listener: {e}"))),
        };
        let _ = started.send(());

        let r = listen_loop(&listener, &mut stop, &context, &config).await;
        r
    });
    if let Err(e) = &result {
        warn!("listener stopped with error: {e}");
    }
    // Drops every remaining task, connection and buffer owned by the runtime.
    drop(runtime);
}

fn has_session_slot(context: &SessionContext) -> bool {
    (context.counters.active.load(Ordering::Relaxed) as usize) < context.limits.max_sessions
}

/// Accept loop: one accept at a time, sessions tracked in a join set that is
/// drained on every iteration so finished tasks release buffers promptly.
async fn listen_loop(
    listener: &TcpListener,
    stop: &mut watch::Receiver<bool>,
    context: &Arc<SessionContext>,
    config: &Arc<Config>,
) -> io::Result<()> {
    let mut set: JoinSet<()> = JoinSet::new();
    let mut session_id: u64 = 0;
    loop {
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() {
                    return Err(io::Error::other("stop signal dropped"));
                }
                break;
            }
            done = set.join_next(), if !set.is_empty() => {
                if let Some(Err(e)) = done {
                    warn!("session task panicked: {e}");
                }
            }
            accepted = listener.accept(), if has_session_slot(context) => {
                let (stream, peer) = accepted?;
                session_id += 1;
                context.counters.accepted.fetch_add(1, Ordering::Relaxed);
                context.counters.active.fetch_add(1, Ordering::Relaxed);
                let _ = stream.set_nodelay(true);
                set.spawn(serve(stream, peer, session_id, context.clone(), config.clone(), stop.clone()));
            }
        }
    }
    info!(
        sessions = session_id,
        "listener stopped; waiting for {} session tasks",
        set.len()
    );
    while let Some(done) = set.join_next().await {
        if let Err(e) = done {
            warn!("session task failed at shutdown: {e}");
        }
    }
    info!("all session tasks joined; listener released");
    Ok(())
}

async fn serve(
    mut stream: TcpStream,
    peer: SocketAddr,
    id: u64,
    context: Arc<SessionContext>,
    config: Arc<Config>,
    mut stop: watch::Receiver<bool>,
) {
    // The inbound request is read before the stop-aware select: the bytes
    // arrive with the accept, and reading them here keeps the relay framed by
    // the select below, where a stop request cuts live tunnels too.
    let request = tokio::time::timeout(
        context.limits.handshake_timeout,
        inbound::accept_request_with_auth(&mut stream, &context.auth),
    )
    .await
    .unwrap_or(Err(HandshakeError::TooLarge));
    let outcome = tokio::select! {
        biased;
        _ = stop.changed() => {
            debug!(session = id, "stopped with the kernel");
            None
        }
        outcome = serve_request(stream, peer, id, request, &context, &config) => Some(outcome),
    };
    let Some(outcome) = outcome else {
        context.counters.active.fetch_sub(1, Ordering::Relaxed);
        return;
    };
    let counters = &context.counters;
    match outcome {
        Ok(()) => {
            counters.completed.fetch_add(1, Ordering::Relaxed);
        }
        Err(SessionOutcome::Rejected) => {
            counters.rejected.fetch_add(1, Ordering::Relaxed);
        }
        Err(SessionOutcome::Failed) => {
            counters.failed.fetch_add(1, Ordering::Relaxed);
        }
    }
    counters.active.fetch_sub(1, Ordering::Relaxed);
}

enum SessionOutcome {
    Rejected,
    Failed,
}

async fn serve_request(
    mut client: TcpStream,
    peer: SocketAddr,
    id: u64,
    request: Result<inbound::Request, HandshakeError>,
    context: &SessionContext,
    config: &Config,
) -> Result<(), SessionOutcome> {
    let limits = context.limits;
    let counters = &context.counters;

    let request = match request {
        Ok(request) => request,
        Err(err) => {
            warn!(session = id, peer = %peer, code = err.code(), "handshake failed: {err}");
            return Err(SessionOutcome::Failed);
        }
    };
    let protocol = request.protocol;
    if protocol == inbound::Protocol::HttpConnect && !inbound::http_authorized(&request, &context.auth) {
        info!(session = id, peer = %peer, "HTTP CONNECT without a valid Proxy-Authorization");
        inbound::reply_http_auth_required(&mut client).await;
        return Err(SessionOutcome::Failed);
    }
    let ip: Option<IpAddr> = request.host.parse().ok();
    let decision = context.rules.evaluate(&Target::new(&request.host, ip));
    debug!(
        session = id, peer = %peer, protocol = protocol.as_str(), target = %request.authority(),
        rule = %decision, config = %config.digest, "request matched"
    );

    if decision.rule.action == Action::Reject {
        info!(session = id, target = %request.authority(), protocol = protocol.as_str(), rule = %decision, "REJECT");
        inbound::reply_failure(&mut client, protocol, 0x07).await;
        return Err(SessionOutcome::Rejected);
    }

    let authority = request.authority();
    // REJECT was handled above; other actions name a configured proxy, and any
    // rule without a proxy (including the implicit DIRECT fallback) dials the
    // target directly.
    let proxy = match decision.rule.action {
        Action::Proxy(index) => match config.proxies.get(index) {
            Some(proxy) => Some(proxy),
            None => {
                warn!(session = id, rule = %decision, "rule names a proxy that is no longer configured");
                inbound::reply_failure(&mut client, protocol, 0x01).await;
                return Err(SessionOutcome::Failed);
            }
        },
        _ => None,
    };
    let (upstream, outbound, outbound_kind): (Box<dyn outbound::Stream>, String, &str) = match proxy {
        None => {
            let stream = match tokio::time::timeout(limits.dial_timeout, TcpStream::connect(&authority))
                .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    warn!(session = id, target = %authority, rule = %decision, "direct dial failed: {e}");
                    inbound::reply_failure(&mut client, protocol, 0x01).await;
                    return Err(SessionOutcome::Failed);
                }
                Err(_) => {
                    warn!(session = id, target = %authority, "direct dial timed out after {:?}", limits.dial_timeout);
                    inbound::reply_failure(&mut client, protocol, 0x01).await;
                    return Err(SessionOutcome::Failed);
                }
            };
            let _ = stream.set_nodelay(true);
            let peer = stream
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "?".to_string());
            (Box::new(stream) as Box<dyn outbound::Stream>, peer, "DIRECT")
        }
        Some(proxy) => {
            // Follow `dialer-proxy` from the matched proxy; the loader has
            // already rejected unknown references and cycles.
            let mut hops: Vec<&crate::proxies::Proxy> = Vec::new();
            let mut current = Some(proxy);
            while let Some(hop) = current {
                hops.push(hop);
                current = hop
                    .dialer_proxy()
                    .and_then(|name| config.proxies.iter().find(|p| p.name == name));
            }
            let target = outbound::Target { host: request.host.clone(), port: request.port };
            match tokio::time::timeout(limits.dial_timeout, outbound::dial_chain(&hops, &target, limits.dial_timeout)).await {
                Err(_) => {
                    warn!(session = id, target = %authority, rule = %decision, proxy = %proxy.name, "outbound dial timed out after {:?}", limits.dial_timeout);
                    inbound::reply_failure(&mut client, protocol, 0x01).await;
                    return Err(SessionOutcome::Failed);
                }
                Ok(Err(e)) => {
                    warn!(session = id, target = %authority, rule = %decision, proxy = %proxy.name, "outbound dial failed: {e}");
                    inbound::reply_failure(&mut client, protocol, 0x01).await;
                    return Err(SessionOutcome::Failed);
                }
                Ok(Ok(dialed)) => {
                    let label = hops
                        .iter()
                        .map(|hop| hop.name.as_str())
                        .collect::<Vec<_>>()
                        .join("->");
                    (
                        dialed.stream,
                        format!("proxy={} type={} server={} chain={label}", proxy.name, proxy.type_name(), dialed.server),
                        "PROXY",
                    )
                }
            }
        }
    };
    info!(
        session = id, target = %authority, protocol = protocol.as_str(), rule = %decision,
        outbound = %outbound, config = %config.digest, "{} tunnel established", outbound_kind
    );

    if inbound::reply_success(&mut client, &request).await.is_err() {
        return Err(SessionOutcome::Failed);
    }

    let relayed =
        relay(client, upstream, limits.buffer_size, limits.half_close_timeout).await;
    counters
        .bytes_up
        .fetch_add(relayed.bytes_up, Ordering::Relaxed);
    counters
        .bytes_down
        .fetch_add(relayed.bytes_down, Ordering::Relaxed);
    let mut failed = relayed.up_error || relayed.down_error;
    if relayed.lingering {
        // The second direction exceeded `half_close_timeout` and was dropped.
        failed = true;
    }
    info!(session = id, target = %authority, bytes_up = relayed.bytes_up, bytes_down = relayed.bytes_down, "session closed");
    if failed {
        Err(SessionOutcome::Failed)
    } else {
        Ok(())
    }
}

struct Relayed {
    bytes_up: u64,
    bytes_down: u64,
    up_error: bool,
    down_error: bool,
    lingering: bool,
}

/// Relay between the inbound client socket and its upstream transport (a direct
/// TCP socket or an outbound proxy stream). A proxy stream is not a socket and
/// cannot be duplicated, so both sides are split into read/write halves. The
/// client is a real socket and uses `TcpStream::into_split` (owned, lock-free
/// halves): `tokio::io::split` around an accepted socket was observed on this
/// host to leave the first client-to-upstream read pending in rare runs of the
/// peer suite, while the same code path with owned halves never did.
/// Both directions run inside this one session future (a `select` over two
/// pinned copies), so no extra task has to be scheduled, a stop request drops
/// them with the session, and after the session ends nothing is left behind.
/// Buffers are the same fixed size and a read stops while the writer is blocked
/// (back-pressure).
async fn relay(
    client: TcpStream,
    upstream: Box<dyn outbound::Stream>,
    buffer_size: usize,
    linger: Duration,
) -> Relayed {
    let (client_r, client_w) = client.into_split();
    let (upstream_r, upstream_w) = tokio::io::split(upstream);
    let up_bytes = Arc::new(AtomicU64::new(0));
    let down_bytes = Arc::new(AtomicU64::new(0));
    let upload = copy_half(client_r, upstream_w, buffer_size, up_bytes.clone());
    let download = copy_half(upstream_r, client_w, buffer_size, down_bytes.clone());
    tokio::pin!(upload);
    tokio::pin!(download);

    // Upload ends on the client's EOF / half-close; the download side keeps
    // running while the client is still sending.
    let mut download_done = false;
    let mut down_error = false;
    let up_error = loop {
        tokio::select! {
            error = &mut upload => break error,
            error = &mut download, if !download_done => {
                download_done = true;
                down_error = error;
            }
        }
    };
    // After the first direction finished, the second one is cut once `linger`
    // elapses: a stalled peer never keeps a session, a task and buffers alive.
    let lingering = if download_done {
        false
    } else {
        match tokio::time::timeout(linger, &mut download).await {
            Ok(error) => {
                down_error = error;
                false
            }
            Err(_) => {
                debug!("second direction exceeded half-close timeout");
                down_error = true;
                true
            }
        }
    };
    Relayed {
        bytes_up: up_bytes.load(Ordering::Relaxed),
        bytes_down: down_bytes.load(Ordering::Relaxed),
        up_error,
        down_error,
        lingering,
    }
}

/// Re-poll interval for a suspended read: 1 ms at first, backing off to 128 ms.
///
/// A read that should wake on new bytes has been observed to stay pending on
/// this host (darwin reactor) while the peer suite's extra processes run.
/// `AsyncRead::read` is cancel-safe, so re-polling cannot lose bytes; the
/// backoff keeps an idle tunnel at a few wake-ups per second.
const READ_RETRY_MIN: Duration = Duration::from_millis(1);
const READ_RETRY_MAX: Duration = Duration::from_millis(128);

async fn read_with_retry<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
    interval: &mut Duration,
) -> io::Result<usize> {
    loop {
        match tokio::time::timeout(*interval, reader.read(buffer)).await {
            Ok(result) => {
                *interval = READ_RETRY_MIN;
                return result;
            }
            Err(_) => *interval = (*interval * 2).min(READ_RETRY_MAX),
        }
    }
}

async fn copy_half<R, W>(
    mut reader: R,
    mut writer: W,
    buffer_size: usize,
    bytes: Arc<AtomicU64>,
) -> bool
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Fixed-size buffer per direction; reads stop while the writer is blocked,
    // which is the back-pressure on the sender.
    let mut buffer = vec![0u8; buffer_size];
    let mut interval = READ_RETRY_MIN;
    loop {
        let n = match read_with_retry(&mut reader, &mut buffer, &mut interval).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => break,
            Err(e) => {
                debug!("read failed: {e}");
                return true;
            }
        };
        if let Err(e) = writer.write_all(&buffer[..n]).await {
            debug!("write failed: {e}");
            return true;
        }
        bytes.fetch_add(n as u64, Ordering::Relaxed);
    }
    // Shuts the write side only; the peer observes a FIN (half-close).
    let _ = writer.shutdown().await;
    false
}
