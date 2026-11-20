//! Session engine: binds the mixed listener, evaluates rules, dials DIRECT
//! targets and copies bytes in both directions with bounded buffers.
//!
//! Every accepted connection is tracked until its task has returned, so after
//! [`Kernel::stop`] returns there are no live sessions, tasks or buffers.

use std::io;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::config::{Action, Config, ConfigError, GeoSiteDatabase, LoadedConfig};
use crate::identity::Identity;
use crate::inbound::{self, HandshakeError};
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
            GeoSiteDatabase::load_from_dir(&dir, &keys)?
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
        (m.rule.action, m.to_string())
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
    stream: TcpStream,
    peer: SocketAddr,
    id: u64,
    context: Arc<SessionContext>,
    config: Arc<Config>,
    mut stop: watch::Receiver<bool>,
) {
    // A stop request cuts live tunnels too: dropping the streams closes both
    // sides, and the runtime drop cancels anything still pending.
    let outcome = tokio::select! {
        biased;
        _ = stop.changed() => {
            debug!(session = id, "stopped with the kernel");
            None
        }
        outcome = serve_inner(stream, peer, id, &context, &config) => Some(outcome),
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

async fn serve_inner(
    mut client: TcpStream,
    peer: SocketAddr,
    id: u64,
    context: &SessionContext,
    config: &Config,
) -> Result<(), SessionOutcome> {
    let limits = context.limits;
    let counters = &context.counters;

    let request = tokio::time::timeout(
        limits.handshake_timeout,
        inbound::accept_request(&mut client),
    )
    .await
    .unwrap_or(Err(HandshakeError::TooLarge));
    let request = match request {
        Ok(request) => request,
        Err(err) => {
            warn!(session = id, peer = %peer, code = err.code(), "handshake failed: {err}");
            return Err(SessionOutcome::Failed);
        }
    };
    let protocol = request.protocol;
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

    // This slice has no protocol outbounds: anything not REJECT is a direct TCP dial.
    let authority = request.authority();
    let upstream = match tokio::time::timeout(limits.dial_timeout, TcpStream::connect(&authority))
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
    let _ = upstream.set_nodelay(true);
    let outbound = upstream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".to_string());
    info!(
        session = id, target = %authority, protocol = protocol.as_str(), rule = %decision,
        outbound = %outbound, config = %config.digest, "DIRECT tunnel established"
    );

    if inbound::reply_success(&mut client, &request).await.is_err() {
        return Err(SessionOutcome::Failed);
    }

    let relayed = relay(
        client,
        upstream,
        limits.buffer_size,
        limits.half_close_timeout,
    )
    .await;
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

/// Copy in both directions with fixed-size buffers. EOF is propagated as a
/// write-side shutdown of the opposite stream (TCP half-close), so
/// request/response protocols work. After the first direction finishes, the
/// second direction is abandoned once `linger` elapses: a stalled peer never
/// keeps a session alive indefinitely.
async fn relay(
    client: TcpStream,
    upstream: TcpStream,
    buffer_size: usize,
    linger: Duration,
) -> Relayed {
    // One direction per task, each with its own duplicate of both sockets:
    //   upload   = read client  -> write upstream
    //   download = read upstream -> write client
    // Every session has a single reader and a single writer per socket.
    let (up_client, down_upstream) = match (duplicate(&client), duplicate(&upstream)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => {
            return Relayed {
                bytes_up: 0,
                bytes_down: 0,
                up_error: true,
                down_error: true,
                lingering: false,
            }
        }
    };
    let upload = spawn_direction(client, upstream, buffer_size);
    let download = spawn_direction(down_upstream, up_client, buffer_size);

    let mut upload = upload;
    let mut download = download;
    // Upload ends on the client's EOF / half-close.
    let (bytes_up, up_error) = upload.finish().await;
    let (bytes_down, down_error, lingering) =
        match tokio::time::timeout(linger, download.finish()).await {
            Ok(result) => (result.0, result.1, false),
            Err(_) => {
                // The peer stopped reading/writing after a half-close: cut the
                // session instead of holding the socket, task and buffer forever.
                debug!("second direction exceeded half-close timeout");
                (0, false, true)
            }
        };
    // Both tasks are done or stale; aborting is harmless for finished tasks and
    // releases the sockets and buffers of a cancelled direction.
    upload.abort();
    download.abort();
    Relayed {
        bytes_up,
        bytes_down,
        up_error,
        down_error,
        lingering,
    }
}

/// Handle on one copy task plus the byte counter it updates while running.
struct DirectionTask {
    handle: tokio::task::JoinHandle<()>,
    result: tokio::sync::oneshot::Receiver<(u64, bool)>,
}

impl DirectionTask {
    /// Bytes and error state of the direction; returns once its task finished.
    async fn finish(&mut self) -> (u64, bool) {
        match (&mut self.result).await {
            Ok((bytes, error)) => (bytes, error),
            Err(_) => (0, true),
        }
    }

    fn abort(&self) {
        self.handle.abort();
    }
}

fn spawn_direction(reader: TcpStream, writer: TcpStream, buffer_size: usize) -> DirectionTask {
    let bytes = Arc::new(AtomicU64::new(0));
    let (tx, result) = tokio::sync::oneshot::channel();
    let counter = bytes.clone();
    let handle = tokio::spawn(async move {
        let outcome = copy_half(SyncReader(reader), writer, buffer_size, &counter).await;
        let _ = tx.send(outcome);
    });
    DirectionTask { handle, result }
}

/// Duplicate a socket so one direction reads and another writes the same
/// connection. Implemented with `dup(2)`; the original stays with the caller.
#[cfg(unix)]
fn duplicate(stream: &TcpStream) -> io::Result<TcpStream> {
    let fd = stream.as_raw_fd();
    extern "C" {
        fn dup(fd: std::os::unix::io::RawFd) -> std::os::unix::io::RawFd;
    }
    // SAFETY: `dup` only reads the descriptor number and returns a fresh one.
    let dup_fd = unsafe { dup(fd) };
    if dup_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `dup_fd` is a fresh, valid descriptor owned by this call.
    let std_stream =
        unsafe { <std::net::TcpStream as std::os::fd::FromRawFd>::from_raw_fd(dup_fd) };
    TcpStream::from_std(std_stream)
}

/// Windows has no `dup(2)` in std; the platform session path lands with T6, so
/// sessions here fail explicitly (502 to the client) instead of forwarding wrongly.
#[cfg(not(unix))]
fn duplicate(_stream: &TcpStream) -> io::Result<TcpStream> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "socket duplication is not implemented on this platform yet",
    ))
}

/// Read-only view of a TCP socket: readiness waits, then a non-blocking read.
struct SyncReader(TcpStream);

impl SyncReader {
    async fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            self.0.readable().await?;
            match self.0.try_read(buffer) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

/// A single-direction copy: returns total bytes and whether an I/O error
/// occurred, once EOF is reached and the writer's write side is shut down.
async fn copy_half<R: ReadHalf>(
    reader: R,
    mut writer: TcpStream,
    buffer_size: usize,
    bytes: &AtomicU64,
) -> (u64, bool) {
    // Fixed-size buffer per direction; reads stop while the writer is blocked,
    // which is the back-pressure on the sender.
    let mut buffer = vec![0u8; buffer_size];
    loop {
        let n = match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => break,
            Err(e) => {
                debug!("read failed: {e}");
                return (bytes.load(Ordering::Relaxed), true);
            }
        };
        let pending = &buffer[..n];
        match writer.write(pending).await {
            Ok(0) => {
                bytes.fetch_add(0, Ordering::Relaxed);
                break;
            }
            Ok(written) => {
                bytes.fetch_add(written as u64, Ordering::Relaxed);
            }
            Err(e) => {
                debug!("write failed: {e}");
                return (bytes.load(Ordering::Relaxed), true);
            }
        }
    }
    // Shuts the write side only; the peer observes a FIN (half-close).
    let _ = writer.shutdown().await;
    (bytes.load(Ordering::Relaxed), false)
}

trait ReadHalf {
    async fn read(&self, buffer: &mut [u8]) -> io::Result<usize>;
}

impl ReadHalf for SyncReader {
    async fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        SyncReader::read(self, buffer).await
    }
}
