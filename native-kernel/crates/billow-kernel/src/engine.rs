//! Session engine: binds the mixed listener, evaluates rules, dials DIRECT
//! targets and copies bytes in both directions with bounded buffers.
//!
//! Every accepted connection is tracked until its task has returned, so after
//! [`Kernel::stop`] returns there are no live sessions, tasks or buffers.

use std::collections::HashMap;
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

use crate::config::{Action, Config, ConfigError, InType, LoadedConfig, Matcher, NetworkKind};
use crate::dns::{DnsRoute, DnsService, HostValue, HostsTable, RouteStreamBox};
use crate::groups::{GroupRegistry, Selected};
use crate::identity::Identity;
use crate::inbound::{self, HandshakeError, InboundAuth};
use crate::outbound::tls::ClientTls;
use crate::outbound;
use crate::proxies::IpVersion;
use crate::rules::{MatchInput, MatchStep, RuleMatch, RuleSet, Target};

/// Version of this kernel (crate version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Options a host can set beyond [`Limits`].
#[derive(Debug, Clone, Default)]
pub struct KernelOptions {
    /// Directory that holds the selection cache (`cache.yaml`). `None`
    /// disables `profile.store-selected` persistence; the kernel warns when the
    /// configuration asks for it. The CLI and T25 pass the configuration
    /// directory (pinned uses `<homeDir>/cache.db`).
    pub cache_dir: Option<PathBuf>,
    /// Host log bus shared with `/logs`. A host that installs its own tracing
    /// logger can publish the same records to this bus (the CLI does), so the
    /// control stream carries engine events and not only controller events.
    pub log_bus: Option<crate::controller::LogBus>,
}

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
    /// How long a SOCKS5 UDP association may stay idle before its sockets and
    /// buffers are released (the control connection normally closes first).
    pub udp_idle_timeout: Duration,
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
            udp_idle_timeout: Duration::from_secs(60),
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
    pub(crate) accepted: AtomicU64,
    active: AtomicU64,
    completed: AtomicU64,
    rejected: AtomicU64,
    failed: AtomicU64,
    pub(crate) bytes_up: Arc<AtomicU64>,
    pub(crate) bytes_down: Arc<AtomicU64>,
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

/// One open, routed connection as the control API reports it. Pinned
/// `statistic.TrackerInfo` equivalent for the fields Billow reads.
pub(crate) struct OpenConnection {
    pub id: String,
    pub host: String,
    pub destination_ip: Option<IpAddr>,
    pub destination_port: u16,
    pub source_ip: IpAddr,
    pub source_port: u16,
    /// Pinned metadata `type`: `HTTP` or `Socks5`.
    pub kind: &'static str,
    pub network: &'static str,
    pub inbound_port: u16,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
    pub start: std::time::SystemTime,
    pub upload: Arc<AtomicU64>,
    pub download: Arc<AtomicU64>,
    pub(crate) close: Arc<tokio::sync::Notify>,
}

impl OpenConnection {
    pub fn request_close(&self) {
        self.close.notify_waiters();
    }
}

/// Live connection registry (`/connections`, `DELETE /connections/:id`).
#[derive(Default)]
pub(crate) struct ConnectionRegistry {
    entries: Mutex<std::collections::BTreeMap<String, Arc<OpenConnection>>>,
}

impl ConnectionRegistry {
    pub fn register(self: &Arc<Self>, entry: OpenConnection) -> ConnectionGuard {
        let id = entry.id.clone();
        let entry = Arc::new(entry);
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id.clone(), entry);
        ConnectionGuard {
            registry: self.clone(),
            id,
        }
    }

    pub fn snapshot(&self) -> Vec<Arc<OpenConnection>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect()
    }

    pub fn close(&self, id: &str) -> bool {
        let entry = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(id)
            .cloned();
        match entry {
            Some(entry) => {
                entry.request_close();
                true
            }
            None => false,
        }
    }

    pub fn close_all(&self) -> usize {
        let entries = self.snapshot();
        for entry in &entries {
            entry.request_close();
        }
        entries.len()
    }

    fn remove(&self, id: &str) {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(id);
    }
}

/// Removes the entry when the session task ends for any reason.
pub(crate) struct ConnectionGuard {
    registry: Arc<ConnectionRegistry>,
    id: String,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.registry.remove(&self.id);
    }
}

/// Shared, immutable session context for one configuration generation.
///
/// A reload builds a new [`RuntimeSnapshot`] and swaps the `Arc`; sessions that
/// already started keep the generation they evaluated until they finish, so
/// their rules, providers and DNS objects are reclaimed exactly then (R4).
pub(crate) struct RuntimeSnapshot {
    pub config: Arc<Config>,
    pub rules: Arc<RuleSet>,
    pub providers: Arc<crate::provider::RuleProviders>,
    pub groups: Arc<GroupRegistry>,
    /// Trust anchors of this generation: platform store plus the
    /// configuration's `tls.custom-cert`/`tls.certificate` entries.
    pub tls: Arc<ClientTls>,
    /// DNS runtime (T22); `None` when `dns.enable` is false or absent,
    /// in which case rule-time lookups use the OS resolver like the pinned
    /// engine's `SystemResolver` fallback.
    pub dns: Option<Arc<DnsService>>,
    /// Configured `hosts` trie plus the built-in `localhost` entry; active
    /// even when DNS is disabled (pinned `updateHosts`).
    pub hosts: Arc<HostsTable>,
    /// `authentication` users for the mixed inbound (SOCKS5 RFC 1929 / HTTP 407).
    pub auth: InboundAuth,
}

impl RuntimeSnapshot {
    pub fn listen_port(&self) -> u16 {
        self.config.listen.port()
    }
}

/// Per-generation runtime plus the kernel-wide counters/limits.
///
/// Shared with the listener-less data planes (`tunnel`, feature `ios-vpn`), so
/// a packet path evaluates rules, groups and DNS against exactly the same
/// generation an accepted session would.
pub(crate) struct SessionContext {
    pub(crate) runtime: Arc<RuntimeSnapshot>,
    pub(crate) limits: Limits,
    pub(crate) counters: Arc<Counters>,
    pub(crate) connections: Arc<ConnectionRegistry>,
}

impl SessionContext {
    pub(crate) fn listen_port(&self) -> u16 {
        self.runtime.listen_port()
    }
}

/// The current runtime generation. Reload swaps the inner `Arc` only after a
/// replacement has been fully built and validated.
pub(crate) struct SharedRuntime {
    current: std::sync::RwLock<Arc<RuntimeSnapshot>>,
    scheduler_stop: Mutex<Option<watch::Sender<bool>>>,
}

impl SharedRuntime {
    pub fn snapshot(&self) -> Arc<RuntimeSnapshot> {
        self.current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Replace the generation; returns the previous one (dropped once its
    /// last session finishes). The caller stops the old scheduler first.
    pub fn replace(&self, next: Arc<RuntimeSnapshot>) -> Arc<RuntimeSnapshot> {
        let mut current = self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::replace(&mut *current, next)
    }
}

/// A running kernel. Dropping it without calling [`Kernel::stop`] stops it too.
pub struct Kernel {
    control: Arc<ControlCore>,
    controller: Option<crate::controller::Controller>,
    stop_tx: watch::Sender<bool>,
    supervisor: Mutex<Option<std::thread::JoinHandle<()>>>,
}

/// Shared state of one kernel process: the live generation, identity, counter
/// handles and the supervisor runtime handle. The control API and `Kernel`
/// both use it, so a reload never needs exclusive access to the kernel object.
pub(crate) struct ControlCore {
    pub runtime: Arc<SharedRuntime>,
    identity: std::sync::RwLock<Identity>,
    pub base_dir: PathBuf,
    pub geodata_dir: Option<PathBuf>,
    pub options: KernelOptions,
    pub limits: Limits,
    pub counters: Arc<Counters>,
    pub connections: Arc<ConnectionRegistry>,
    runtime_handle: Mutex<Option<tokio::runtime::Handle>>,
    pub log_bus: crate::controller::LogBus,
}

impl ControlCore {
    pub fn identity(&self) -> Identity {
        self.identity
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn set_identity(&self, identity: Identity) {
        *self
            .identity
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = identity;
    }

    /// Validate `yaml` against the live generation and build a replacement.
    pub fn build_reload(&self, yaml: &str) -> Result<Arc<RuntimeSnapshot>, StartError> {
        let loaded = crate::config::load_config(yaml, "<reload>")?;
        let current = self.runtime.snapshot();
        if loaded.config.listen != current.config.listen {
            return Err(StartError::Config(ConfigError::Unsupported(format!(
                "mixed-port/bind-address cannot change on reload (listener is {}); restart the kernel to move it",
                current.config.listen
            ))));
        }
        if loaded.config.dns.listen != current.config.dns.listen {
            return Err(StartError::Config(ConfigError::Unsupported(
                "dns.listen cannot change on reload; restart the kernel to move the DNS server"
                    .to_string(),
            )));
        }
        if !loaded.config.controller.same_listeners(&current.config.controller) {
            return Err(StartError::Config(ConfigError::Unsupported(
                "external-controller/external-controller-unix/external-controller-tls/secret/external-controller-cors cannot change on reload; restart the kernel"
                    .to_string(),
            )));
        }
        let (next, _) = build_runtime(
            &loaded,
            &self.geodata_dir,
            &self.base_dir,
            self.limits,
            &self.options,
        )?;
        Ok(next)
    }

    /// Swap the live generation; the old one is released by its last session.
    pub fn install_reload(&self, next: Arc<RuntimeSnapshot>) -> Result<(), StartError> {
        if let Some(stop) = self
            .runtime
            .scheduler_stop
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = stop.send(true);
        }
        let old = self.runtime.replace(next.clone());
        let (scheduler_stop, scheduler_rx) = watch::channel(false);
        *self
            .runtime
            .scheduler_stop
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(scheduler_stop);
        let handle = self
            .runtime_handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(handle) = handle {
            let groups = next.groups.clone();
            handle.spawn(async move {
                groups.spawn_scheduler(scheduler_rx);
            });
        } else {
            tracing::warn!("reload without a supervisor runtime; interval health checks are not scheduled");
        }
        self.set_identity({
            let mut identity = self.identity();
            identity.config_digest = next.config.digest.clone();
            identity.rules = next.rules.rule_count();
            identity.features = next.config.feature_summary();
            identity
        });
        drop(old);
        Ok(())
    }

    /// `PUT /configs` implementation: build first, then swap.
    pub fn reload(&self, yaml: &str) -> Result<Vec<String>, StartError> {
        let loaded = crate::config::load_config(yaml, "<reload>")?;
        let warnings = loaded.warnings.clone();
        let next = self.build_reload(yaml)?;
        self.install_reload(next)?;
        Ok(warnings)
    }
}

impl Kernel {
    /// Load `path`, compile rules (geodata from `geodata_dir`) and bind the listener.
    pub fn start(
        path: &std::path::Path,
        geodata_dir: Option<PathBuf>,
        limits: Limits,
    ) -> Result<(Kernel, Vec<String>), StartError> {
        let yaml = std::fs::read_to_string(path).map_err(|e| {
            StartError::Config(ConfigError::Invalid(format!("{}: {e}", path.display())))
        })?;
        let loaded = crate::config::load_config(&yaml, &path.display().to_string())?;
        let base_dir = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        Kernel::start_with_dir(&loaded, geodata_dir, base_dir, limits)
    }

    /// Start from YAML text (embedding hosts such as the iOS extension use this entry).
    pub fn start_from_yaml(
        yaml: &str,
        geodata_dir: Option<PathBuf>,
        limits: Limits,
    ) -> Result<(Kernel, Vec<String>), StartError> {
        let loaded = crate::config::load_config(yaml, "<inline>")?;
        let base_dir = geodata_dir.clone().unwrap_or_else(|| PathBuf::from("."));
        Kernel::start_with_dir(&loaded, geodata_dir, base_dir, limits)
    }

    /// Start from a [`LoadedConfig`]; returns warnings so hosts can surface them.
    pub fn start_with_yaml(
        loaded: &LoadedConfig,
        geodata_dir: Option<PathBuf>,
        limits: Limits,
    ) -> Result<(Kernel, Vec<String>), StartError> {
        let base_dir = geodata_dir.clone().unwrap_or_else(|| PathBuf::from("."));
        Kernel::start_with_dir(loaded, geodata_dir, base_dir, limits)
    }

    /// Start from a [`LoadedConfig`] with an explicit directory for relative
    /// provider paths (the CLI passes the configuration file's directory).
    pub fn start_with_dir(
        loaded: &LoadedConfig,
        geodata_dir: Option<PathBuf>,
        base_dir: PathBuf,
        limits: Limits,
    ) -> Result<(Kernel, Vec<String>), StartError> {
        Kernel::start_with_options(loaded, geodata_dir, base_dir, limits, &KernelOptions::default())
    }

    /// Start with host options (selection cache location).
    pub fn start_with_options(
        loaded: &LoadedConfig,
        geodata_dir: Option<PathBuf>,
        base_dir: PathBuf,
        limits: Limits,
        options: &KernelOptions,
    ) -> Result<(Kernel, Vec<String>), StartError> {
        validate_limits(&limits)?;
        let (runtime, warnings) = build_runtime(loaded, &geodata_dir, &base_dir, limits, options)?;
        let config = runtime.config.clone();
        let dns = runtime.dns.clone();

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
        let dns_listeners = match dns.as_ref().and_then(|dns| dns.listen_addr()) {
            Some(addr) => Some(
                crate::dns::bind_dns_listeners(addr)
                    .map_err(|source| StartError::Bind {
                        addr,
                        source: Arc::new(source),
                    })?,
            ),
            None => None,
        };

        let counters = Arc::new(Counters::default());
        let connections = Arc::new(ConnectionRegistry::default());
        let (stop_tx, stop_rx) = watch::channel(false);
        let (scheduler_stop, scheduler_rx) = watch::channel(false);
        let context = Arc::new(SessionContext {
            runtime: runtime.clone(),
            limits,
            counters: counters.clone(),
            connections: connections.clone(),
        });
        let shared = Arc::new(SharedRuntime {
            current: std::sync::RwLock::new(runtime.clone()),
            scheduler_stop: Mutex::new(Some(scheduler_stop)),
        });
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let shared_for_thread = shared.clone();
        let supervisor = std::thread::Builder::new()
            .name("billow-kernel-supervisor".to_string())
            .spawn(move || {
                supervisor_thread(
                    listener,
                    context,
                    shared_for_thread,
                    dns_listeners,
                    scheduler_rx,
                    stop_rx,
                    started_tx,
                )
            })
            .map_err(|e| StartError::Limits(format!("spawn supervisor: {e}")))?;
        let runtime_handle = match started_rx.recv() {
            Ok(Some(handle)) => handle,
            Ok(None) => {
                let _ = supervisor;
                return Err(StartError::Limits(
                    "supervisor runtime could not be built".to_string(),
                ));
            }
            Err(e) => {
                let _ = supervisor;
                return Err(StartError::Limits(format!(
                    "supervisor failed to start: {e}"
                )));
            }
        };

        let mut identity = Identity::new(VERSION, local, &config, &geodata_dir, runtime.rules.rule_count());
        identity.listen = local;
        let control = Arc::new(ControlCore {
            runtime: shared,
            identity: std::sync::RwLock::new(identity),
            base_dir,
            geodata_dir,
            options: options.clone(),
            limits,
            counters,
            connections,
            runtime_handle: Mutex::new(Some(runtime_handle)),
            log_bus: options
                .log_bus
                .clone()
                .unwrap_or_else(crate::controller::LogBus::new),
        });
        let mut kernel = Kernel {
            control,
            controller: None,
            stop_tx,
            supervisor: Mutex::new(Some(supervisor)),
        };
        let controller = crate::controller::Controller::start(&kernel);
        kernel.controller = controller;
        let identity = kernel.identity();
        info!(
            instance = %identity.uuid, pid = identity.pid, version = VERSION, listen = %local,
            "billow-kernel started; {}", config.feature_summary()
        );
        Ok((kernel, warnings))
    }

    /// A session context for a data plane that owns no listener (the iOS
    /// Packet Tunnel and the Android VpnService fd pump behind
    /// `feature = "device-vpn"`, and, later, a desktop TUN). The snapshot is
    /// the current generation, so a reload affects the next flow and an
    /// in-flight flow keeps the generation it started with.
    #[cfg(feature = "device-vpn")]
    pub(crate) fn packet_session(&self) -> Arc<SessionContext> {
        Arc::new(SessionContext {
            runtime: self.control.runtime.snapshot(),
            limits: self.control.limits,
            counters: self.control.counters.clone(),
            connections: self.control.connections.clone(),
        })
    }

    /// Correlatable instance identity (uuid, pid, version, listener, config digest).
    pub fn identity(&self) -> Identity {
        self.control.identity()
    }

    /// Actually bound address.
    pub fn listen_addr(&self) -> SocketAddr {
        self.control.identity().listen
    }

    /// Host-supplied metadata such as the actual port override used at start.
    pub fn set_identity(&mut self, identity: Identity) {
        self.control.set_identity(identity);
    }

    pub fn config(&self) -> Arc<Config> {
        self.control.runtime.snapshot().config.clone()
    }

    /// The live generation (T25 control API reads one snapshot per request).
    #[allow(dead_code)]
    pub(crate) fn runtime_snapshot(&self) -> Arc<RuntimeSnapshot> {
        self.control.runtime.snapshot()
    }

    /// Actual control-API addresses for hosts and tests.
    pub fn controller_addrs(
        &self,
    ) -> (Option<SocketAddr>, Option<SocketAddr>, Option<PathBuf>) {
        match &self.controller {
            Some(controller) => (
                controller.tcp_addr(),
                controller.tls_addr(),
                controller.unix_path().map(std::path::Path::to_path_buf),
            ),
            None => (None, None, None),
        }
    }

    pub(crate) fn control(&self) -> Arc<ControlCore> {
        self.control.clone()
    }

    pub fn limits(&self) -> Limits {
        self.control.limits
    }

    /// The `/logs` broadcast bus (also usable by a host logger).
    pub fn log_bus(&self) -> crate::controller::LogBus {
        self.control.log_bus.clone()
    }

    /// Provider registry (rule + proxy snapshots) for hosts and the T25 API.
    pub fn providers(&self) -> Arc<crate::provider::RuleProviders> {
        self.control.runtime.snapshot().providers.clone()
    }

    /// Group runtime: status list, selection and health probes (T25 builds its
    /// API from this handle).
    pub fn groups(&self) -> Arc<GroupRegistry> {
        self.control.runtime.snapshot().groups.clone()
    }

    /// DNS runtime (T22); `None` when the configuration disables DNS.
    pub fn dns(&self) -> Option<Arc<DnsService>> {
        self.control.runtime.snapshot().dns.clone()
    }

    /// Effective `hosts` table (configured entries, `localhost`, and the
    /// platform hosts file when `use-system-hosts` is on).
    pub fn hosts_table(&self) -> Arc<HostsTable> {
        self.control.runtime.snapshot().hosts.clone()
    }

    /// Apply a validated configuration payload to the live kernel (the
    /// `PUT /configs` path). Returns the warnings of the new generation.
    pub fn reload(&self, yaml: &str) -> Result<Vec<String>, StartError> {
        self.control.reload(yaml)
    }

    /// Group statuses (`now`, `all`, per-member liveness/delay).
    pub fn group_statuses(&self) -> Vec<crate::groups::GroupStatus> {
        self.groups().snapshot()
    }

    /// Fix a group's selection; `Ok(false)` means the member does not exist.
    pub fn select_group(&self, group: &str, member: &str) -> Result<bool, crate::groups::GroupError> {
        self.groups().select(group, member)
    }

    /// Re-read one rule provider. On failure the old snapshot stays in use.
    pub fn update_rule_provider(
        &self,
        name: &str,
    ) -> Result<crate::provider::ProviderUpdate, ConfigError> {
        self.providers().update_rule_provider(name)
    }

    pub fn update_all_rule_providers(
        &self,
    ) -> (Vec<crate::provider::ProviderUpdate>, Vec<ConfigError>) {
        self.providers().update_all_rule_providers()
    }

    pub fn update_proxy_provider(
        &self,
        name: &str,
    ) -> Result<crate::provider::ProviderUpdate, ConfigError> {
        let groups = self.groups();
        let update = self.providers().update_proxy_provider(name)?;
        // Pinned `baseProvider.setProxies` starts a health check immediately
        // when the snapshot is swapped. The scheduler forces the provider's
        // tasks on its next tick (and the generation watch covers providers
        // updated through `providers()` directly).
        groups.note_provider_update(name);
        Ok(update)
    }

    pub fn stats(&self) -> Stats {
        self.control.counters.snapshot()
    }

    /// Evaluate a destination without accepting a connection (diagnostics/tests).
    /// Returns the action and a human-readable `rule -> ACTION` label.
    pub fn evaluate(&self, host: &str, ip: Option<IpAddr>) -> (Action, String) {
        let runtime = self.control.runtime.snapshot();
        let m = runtime.rules.evaluate(&Target::new(host, ip));
        (m.action, m.label(&runtime.config))
    }

    /// Evaluate a full [`Target`] (port, network, source address, listener type,
    /// process metadata). Used by diagnostics and provider/rule tests.
    pub fn evaluate_target(&self, target: &Target) -> (Action, String) {
        let runtime = self.control.runtime.snapshot();
        let m = runtime.rules.evaluate(target);
        (m.action, m.label(&runtime.config))
    }

    /// Stop accepting, wait for every session task and the listener to exit.
    pub fn stop(&mut self) -> io::Result<()> {
        // The controller is joined first so no request can race the shutdown
        // or start a reload while the supervisor is going away.
        if let Some(mut controller) = self.controller.take() {
            controller.stop();
        }
        if let Some(stop) = self
            .control
            .runtime
            .scheduler_stop
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = stop.send(true);
        }
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
        // A mux session holds a socket and background tasks created by this
        // engine; do not let a later engine in the same process reuse it.
        crate::outbound::sudoku::mux::close_all();
        let stats = self.stats();
        info!(
            instance = %self.control.identity().uuid, sessions = stats.accepted, active = stats.active,
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
            debug!(instance = %self.control.identity().uuid, "Kernel dropped without stop(); stopping now");
            let _ = self.stop();
        }
    }
}

/// Build one immutable runtime generation (providers, geodata, DNS, groups,
/// rules) without binding a listener. The initial start and a reload share it,
/// so a rejected reload cannot leave a half-built generation behind.
fn build_runtime(
    loaded: &LoadedConfig,
    geodata_dir: &Option<PathBuf>,
    base_dir: &PathBuf,
    limits: Limits,
    options: &KernelOptions,
) -> Result<(Arc<RuntimeSnapshot>, Vec<String>), StartError> {
    let config = Arc::new(loaded.config.clone());
    let mut warnings = loaded.warnings.clone();
    // The configuration's own anchors are part of the kernel instance: they
    // are installed before the listener exists, so no dial can run without
    // them, and a second kernel in this process cannot inherit the first one's
    // private authorities.
    let tls = Arc::new(ClientTls::new(&config.tls_roots));

    // 1. Read every provider vehicle. The payloads decide which geodata files
    //    are needed (a classical provider may use GEOSITE/GEOIP).
    let prepared = crate::provider::prepare(&config, base_dir, &tls)?;
    warnings.extend(prepared.warnings.iter().cloned());
    let requirements = prepared.requirements.clone();
    // 2. Load only the referenced geodata. A missing file is a named error.
    let geodata = if requirements.geosite_keys.is_empty()
        && !requirements.geoip
        && !requirements.asn
    {
        Arc::new(crate::geodata::Geodata::default())
    } else {
        let dir = geodata_dir.as_ref().ok_or_else(|| {
            StartError::Config(ConfigError::Unsupported(
                "GEOSITE/GEOIP/IP-ASN rules require --geosite-dir (the directory with GeoSite.dat, GeoIP.dat/Country.mmdb and ASN.mmdb)"
                    .to_string(),
            ))
        })?;
        Arc::new(crate::geodata::Geodata::load(
            dir,
            crate::provider::geodata_source(&config),
            !requirements.geosite_keys.is_empty(),
            requirements.geoip,
            requirements.asn,
            &requirements.geosite_keys,
        )?)
    };
    // 3. Compile provider snapshots, then the rule list that references them.
    let providers = crate::provider::finish(
        &config,
        prepared,
        geodata,
        base_dir,
        tls.clone(),
    )?;
    // 4. `hosts` and the DNS runtime. Hosts are always active; the DNS runtime
    //    exists only with `dns.enable: true`.
    let hosts = Arc::new(HostsTable::build(
        &config.hosts,
        config.dns.enable && config.dns.use_system_hosts,
    )?);
    let dns = if config.dns.enable {
        Some(Arc::new(DnsService::build(
            &config.dns,
            config.ipv6,
            hosts.clone(),
            tls.clone(),
            &providers,
            &mut warnings,
        )?))
    } else {
        if config.dns.listen.is_some() {
            warnings.push(
                "dns.listen is recorded but DNS is disabled; no DNS server is started (set dns.enable: true)"
                    .to_string(),
            );
        }
        None
    };
    // 5. Group runtime: member expansion, selection and health checks.
    //    `profile.store-selected` without a cache directory is surfaced.
    let cache_path = options.cache_dir.as_ref().map(|dir| dir.join("cache.yaml"));
    if config.profile.store_selected && cache_path.is_none() && !config.proxy_groups.is_empty() {
        warnings.push(
            "profile.store-selected is true but no cache directory was given: manual group selections last only for this process (pass a cache dir to persist them)"
                .to_string(),
        );
    }
    let groups = GroupRegistry::new(
        &config,
        providers.clone(),
        tls.clone(),
        limits.dial_timeout,
        base_dir.clone(),
        cache_path,
        dns.clone(),
    )?;
    let rules = RuleSet::compile(&config, providers.clone())?;
    if let Some(dns) = &dns {
        // `respect-rules`: DNS upstreams follow the rule set and proxy groups
        // through the same engine path as client sessions.
        dns.set_route(Arc::new(EngineRoute {
            config: config.clone(),
            rules: rules.clone(),
            groups: groups.clone(),
            tls: tls.clone(),
            timeout: limits.dial_timeout,
        }));
    }
    let snapshot = Arc::new(RuntimeSnapshot {
        config,
        rules,
        providers,
        groups,
        tls,
        dns,
        hosts,
        auth: InboundAuth {
            users: loaded.config.inbound_users.clone(),
        },
    });
    Ok((snapshot, warnings))
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
    shared: Arc<SharedRuntime>,
    dns_listeners: Option<(std::net::UdpSocket, std::net::TcpListener)>,
    scheduler_stop: watch::Receiver<bool>,
    mut stop: watch::Receiver<bool>,
    started: std::sync::mpsc::SyncSender<Option<tokio::runtime::Handle>>,
) {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("billow-kernel")
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            let _ = started.send(None);
            warn!("runtime build failed: {e}");
            return;
        }
    };
    let handle = runtime.handle().clone();
    let _ = started.send(Some(handle));
    let result = runtime.block_on(async {
        let listener = match TcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(e) => return Err(io::Error::other(format!("adopt listener: {e}"))),
        };
        // Interval health checks run on this runtime and stop with their
        // generation (a reload sends the old generation's stop signal).
        {
            let runtime = context.runtime.clone();
            runtime.groups.clone().spawn_scheduler(scheduler_stop);
        }
        // The optional DNS server (`dns.listen`) shares the same stop signal
        // and reads the current generation on every query, so a reload
        // replaces the answering config without rebinding the socket.
        if let Some((udp, tcp)) = dns_listeners {
            let provider: crate::dns::DnsProvider = {
                let shared = shared.clone();
                Arc::new(move || shared.snapshot().dns.clone())
            };
            tokio::spawn(crate::dns::serve_dns_with(provider, udp, tcp, stop.clone()));
        }
        let r = listen_loop(&listener, &mut stop, &context, &shared).await;
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
    shared: &Arc<SharedRuntime>,
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
                // Snapshot the generation at accept time: a concurrent reload
                // affects the next connection, never one already in flight.
                let session = Arc::new(SessionContext {
                    runtime: shared.snapshot(),
                    limits: context.limits,
                    counters: context.counters.clone(),
                    connections: context.connections.clone(),
                });
                set.spawn(serve(stream, peer, session_id, session, stop.clone()));
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
    mut stop: watch::Receiver<bool>,
) {
    // The inbound request is read before the stop-aware select: the bytes
    // arrive with the accept, and reading them here keeps the relay framed by
    // the select below, where a stop request cuts live tunnels too.
    let request = tokio::time::timeout(
        context.limits.handshake_timeout,
        inbound::accept_request_with_auth(&mut stream, &context.runtime.auth),
    )
    .await
    .unwrap_or(Err(HandshakeError::TooLarge));
    // `DELETE /connections/:id` notifies this future, which drops the client
    // and upstream sockets exactly like a kernel stop does.
    let closed = Arc::new(tokio::sync::Notify::new());
    let outcome = tokio::select! {
        biased;
        _ = stop.changed() => {
            debug!(session = id, "stopped with the kernel");
            None
        }
        _ = closed.notified() => {
            debug!(session = id, "closed by the control API");
            None
        }
        outcome = serve_request(stream, peer, id, request, &context, &closed) => Some(outcome),
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

/// `respect-rules` routing for DNS upstreams: evaluate the upstream address
/// through the same rule set and group selection as a client session.
struct EngineRoute {
    config: Arc<Config>,
    rules: Arc<RuleSet>,
    groups: Arc<GroupRegistry>,
    tls: Arc<ClientTls>,
    timeout: Duration,
}

impl DnsRoute for EngineRoute {
    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> crate::dns::BoxFuture<'a, io::Result<RouteStreamBox>> {
        Box::pin(async move {
            let ip = host.parse::<IpAddr>().ok();
            let target = Target::new(host, ip)
                .with_port(port)
                .with_network(NetworkKind::Tcp);
            let decision = self.rules.evaluate(&target);
            if matches!(decision.action, Action::Reject | Action::RejectDrop) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("DNS upstream {host}:{port} rejected by rule {decision}"),
                ));
            }
            let selected = self
                .groups
                .resolve_action(decision.rule.action, &target, true)
                .map_err(io::Error::other)?;
            match selected {
                Selected::Direct => {
                    let stream = crate::outbound::connect_bound_str(&host, port).await?;
                    let _ = stream.set_nodelay(true);
                    let stream: RouteStreamBox = Box::new(stream);
                    Ok(stream)
                }
                Selected::Proxy { proxy, .. } => {
                    let hops = chain_for(&self.config, &proxy);
                    let dialed = outbound::dial_chain(
                        &hops,
                        &outbound::Target {
                            host: host.to_string(),
                            port,
                        },
                        self.timeout,
                        &self.tls,
                    )
                    .await
                    .map_err(io::Error::other)?;
                    Ok(dialed.stream)
                }
                Selected::Reject | Selected::RejectDrop => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("DNS upstream {host}:{port} rejected by group"),
                )),
            }
        })
    }
}

/// Pinned `preHandleMetadata`: hosts domain mapping, redir-host/fake-ip
/// reconstruction. Without a DNS runtime only the hosts mapping applies.
pub(crate) async fn pre_handle_destination(
    context: &SessionContext,
    host: &str,
    ip: Option<IpAddr>,
) -> Result<(String, Option<IpAddr>), String> {
    // Pinned `fixMetadata`: an IP literal in `Host` becomes `DstIP` and the
    // host string is cleared before `preHandleMetadata` runs.
    let (host, ip) = match host.parse::<IpAddr>() {
        Ok(literal) => (String::new(), Some(literal)),
        Err(_) => (host.to_string(), ip),
    };
    match &context.runtime.dns {
        Some(dns) => dns.pre_handle(&host, ip),
        None => {
            if let Some((HostValue::Domain(domain), _)) = context.runtime.hosts.search(&host, true) {
                Ok((domain, ip))
            } else {
                Ok((host, ip))
            }
        }
    }
}

/// Resolve `host` for rule matching (pinned `resolver.ResolveIP`): the DNS
/// runtime when configured, otherwise the OS resolver.
async fn resolve_for_rules(context: &SessionContext, host: &str) -> Option<IpAddr> {
    if host.is_empty() {
        return None;
    }
    // Pinned `resolver.LookupIPWithResolver` consults the configured hosts
    // before any resolver, with or without `dns.enable`.
    let hosted = context.runtime.hosts.lookup_ips(host);
    if let Some(ip) = hosted.iter().find(|ip| ip.is_ipv4()).or_else(|| hosted.first()) {
        return Some(*ip);
    }
    if let Some(dns) = &context.runtime.dns {
        return dns.resolve_one(host).await;
    }
    match tokio::net::lookup_host((host, 0)).await {
        Ok(addrs) => {
            let mut ipv4 = None;
            let mut any = None;
            for addr in addrs {
                any.get_or_insert(addr.ip());
                if addr.is_ipv4() {
                    ipv4 = Some(addr.ip());
                    break;
                }
            }
            ipv4.or(any)
        }
        Err(_) => None,
    }
}

/// First-match evaluation with lazy IP resolution (`no-resolve` is honoured
/// by [`RuleSet::evaluate_step`]). `target.ip` is updated when a resolution
/// happens so group resolution sees the same address.
pub(crate) async fn rule_decision(context: &SessionContext, target: &mut Target) -> RuleMatch {
    // Pinned `resolveMetadata` applies a hosts entry to `DstIP` before the
    // first rule runs, independently of `no-resolve`.
    if target.ip.is_none() && !target.host.is_empty() {
        let hosted = context.runtime.hosts.lookup_ips(&target.host);
        if let Some(ip) = hosted.iter().find(|ip| ip.is_ipv4()).or_else(|| hosted.first()) {
            target.ip = Some(*ip);
        }
    }
    let mut input = MatchInput::default();
    loop {
        match context.runtime.rules.evaluate_step(target, input, 0) {
            MatchStep::Matched(found) => return found,
            MatchStep::Fallthrough => return RuleSet::fallthrough_match(),
            MatchStep::NeedResolve => {
                let host = target.host.clone();
                input.ip = resolve_for_rules(context, &host).await;
                input.resolved = true;
                if let Some(ip) = input.ip {
                    target.ip = Some(ip);
                }
            }
        }
    }
}

/// DIRECT TCP dial: the pinned `Direct` adapter resolves a domain through
/// `DirectHostResolver` (configured DNS when on, the OS resolver otherwise).
pub(crate) async fn direct_stream(
    context: &SessionContext,
    host: &str,
    ip: Option<IpAddr>,
    port: u16,
) -> Result<TcpStream, String> {
    if let Some(ip) = ip {
        return crate::outbound::connect_bound(SocketAddr::new(ip, port))
            .await
            .map_err(|e| format!("connect {ip}:{port}: {e}"));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return crate::outbound::connect_bound(SocketAddr::new(ip, port))
            .await
            .map_err(|e| format!("connect {ip}:{port}: {e}"));
    }
    let hosted = context.runtime.hosts.lookup_ips(host);
    if let Some(ip) = hosted.iter().find(|ip| ip.is_ipv4()).or_else(|| hosted.first()) {
        return crate::outbound::connect_bound(SocketAddr::new(*ip, port))
            .await
            .map_err(|e| format!("connect {ip}:{port}: {e}"));
    }
    if let Some(dns) = &context.runtime.dns {
        let mut ips = dns
            .resolve_direct(host)
            .await
            .map_err(|e| format!("resolve {host}: {e}"))?;
        ips.sort_by_key(|ip| if ip.is_ipv4() { 0 } else { 1 });
        let mut last = format!("resolve {host}: no address");
        for ip in ips {
            match crate::outbound::connect_bound(SocketAddr::new(ip, port)).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last = format!("connect {ip}:{port}: {e}"),
            }
        }
        return Err(last);
    }
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("resolve {host}: {e}"))?;
    let mut last = format!("resolve {host}: no address");
    for addr in addrs.by_ref() {
        match crate::outbound::connect_bound(addr).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = format!("connect {host}:{port}: {error}"),
        }
    }
    Err(last)
}

/// DIRECT UDP destination (pinned `Direct.ResolveUDP`).
pub(crate) async fn direct_udp_destination(
    context: &SessionContext,
    host: &str,
    ip: Option<IpAddr>,
    port: u16,
) -> io::Result<SocketAddr> {
    if let Some(ip) = ip {
        return Ok(SocketAddr::new(ip, port));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let hosted = context.runtime.hosts.lookup_ips(host);
    if let Some(ip) = hosted.iter().find(|ip| ip.is_ipv4()).or_else(|| hosted.first()) {
        return Ok(SocketAddr::new(*ip, port));
    }
    if let Some(dns) = &context.runtime.dns {
        let mut ips = dns
            .resolve_direct(host)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        ips.sort_by_key(|ip| if ip.is_ipv4() { 0 } else { 1 });
        return ips.into_iter().next().map(|ip| SocketAddr::new(ip, port)).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "resolved to no address")
        });
    }
    let mut addrs = tokio::net::lookup_host((host, port)).await?;
    addrs
        .find(|addr| addr.is_ipv4())
        .or_else(|| addrs.next())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "resolved to no address"))
}

/// The preferred address from a resolved set according to `ip-version`
/// (pinned `SortationAddr`: v4 unless prefer-6, a single family for ipv4/ipv6).
fn preferred_udp_address(addrs: &[IpAddr], ip_version: IpVersion) -> Option<IpAddr> {
    match ip_version {
        IpVersion::V4Only => addrs.iter().copied().find(IpAddr::is_ipv4),
        IpVersion::V6Only => addrs.iter().copied().find(IpAddr::is_ipv6),
        IpVersion::V6Prefer => addrs
            .iter()
            .copied()
            .find(IpAddr::is_ipv6)
            .or_else(|| addrs.first().copied()),
        IpVersion::Dual | IpVersion::V4Prefer => addrs
            .iter()
            .copied()
            .find(IpAddr::is_ipv4)
            .or_else(|| addrs.first().copied()),
    }
}

/// Resolve a proxied UDP destination the way the pinned `Base.ResolveUDP` does
/// before an outbound whose packet format only carries IP addresses frames it:
/// an already resolved `ip` wins (the pinned early return when `DstIP` is set),
/// a literal is checked against the proxy's `ip-version`, and a name goes
/// through the session `hosts` table and DNS runtime before the system
/// resolver, with `ip-version` filtering/preference (pinned
/// `resolveIPWithResolver`). Used for `trusttunnel`, whose `_udp2` record has
/// no address-type field for a name.
pub(crate) async fn proxy_udp_destination(
    context: &SessionContext,
    ip_version: IpVersion,
    host: &str,
    ip: Option<IpAddr>,
    port: u16,
) -> io::Result<SocketAddr> {
    if let Some(ip) = ip {
        return Ok(SocketAddr::new(ip, port));
    }
    if let Ok(literal) = host.parse::<IpAddr>() {
        if ip_version == IpVersion::V4Only && !literal.is_ipv4()
            || ip_version == IpVersion::V6Only && !literal.is_ipv6()
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("address does not match ip-version {}", ip_version.as_str()),
            ));
        }
        return Ok(SocketAddr::new(literal, port));
    }
    // The configured hosts table is consulted before any resolver, with or
    // without `dns.enable` (pinned `DefaultHosts.Search`).
    let hosted = context.runtime.hosts.lookup_ips(host);
    if let Some(ip) = preferred_udp_address(&hosted, ip_version) {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs: Vec<IpAddr> = if let Some(dns) = &context.runtime.dns {
        dns.resolve_direct(host)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?
    } else {
        tokio::net::lookup_host((host, port))
            .await?
            .map(|addr| addr.ip())
            .collect()
    };
    if addrs.is_empty() {
        addrs = hosted;
    }
    preferred_udp_address(&addrs, ip_version)
        .map(|ip| SocketAddr::new(ip, port))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("'{host}' resolves to no address for ip-version {}", ip_version.as_str()),
            )
        })
}

/// The `dialer-proxy` chain of `proxy`, starting with the proxy itself. The
/// loader has already rejected unknown references and cycles.
/// Pinned `RuleType().String()` for one matcher (`/rules` `type`).
pub(crate) fn rule_type_name(matcher: &Matcher) -> String {
    let text = matcher.to_string();
    let kind = text.split(',').next().unwrap_or_default();
    match kind {
        "DOMAIN" => "Domain",
        "DOMAIN-SUFFIX" => "DomainSuffix",
        "DOMAIN-KEYWORD" => "DomainKeyword",
        "DOMAIN-REGEX" => "DomainRegex",
        "DOMAIN-WILDCARD" => "DomainWildcard",
        "GEOSITE" => "GeoSite",
        "GEOIP" => "GeoIP",
        "SRC-GEOIP" => "SrcGeoIP",
        "IP-ASN" => "IPASN",
        "SRC-IP-ASN" => "SrcIPASN",
        "IP-CIDR" => "IPCIDR",
        "SRC-IP-CIDR" => "SrcIPCIDR",
        "IP-SUFFIX" => "IPSuffix",
        "SRC-IP-SUFFIX" => "SrcIPSuffix",
        "SRC-PORT" => "SrcPort",
        "DST-PORT" => "DstPort",
        "IN-PORT" => "InPort",
        "IN-TYPE" => "InType",
        "PROCESS-NAME" => "ProcessName",
        "PROCESS-PATH" => "ProcessPath",
        "PROCESS-NAME-REGEX" => "ProcessNameRegex",
        "PROCESS-PATH-REGEX" => "ProcessPathRegex",
        "PROCESS-NAME-WILDCARD" => "ProcessNameWildcard",
        "PROCESS-PATH-WILDCARD" => "ProcessPathWildcard",
        "NETWORK" => "Network",
        "MATCH" => "Match",
        "RULE-SET" => "RuleSet",
        "SUB-RULE" => "SubRules",
        "AND" => "AND",
        "OR" => "OR",
        "NOT" => "NOT",
        other => other,
    }
    .to_string()
}

/// Pinned `Rule.Payload()`: the matcher text without its type and trailing
/// `no-resolve`/`src` options.
pub(crate) fn rule_payload_text(matcher: &Matcher) -> String {
    let text = matcher.to_string();
    let Some((_, rest)) = text.split_once(',') else {
        return String::new();
    };
    let options = ["no-resolve", "src", "no-resolve,src", "src,no-resolve"];
    let mut payload = rest;
    for option in options {
        if let Some(stripped) = payload.strip_suffix(&format!(",{option}")) {
            payload = stripped;
            break;
        }
    }
    payload.to_string()
}

pub(crate) fn chain_for<'a>(
    config: &'a Config,
    proxy: &'a crate::proxies::Proxy,
) -> Vec<&'a crate::proxies::Proxy> {
    let mut hops = vec![proxy];
    let mut current = proxy.dialer_proxy();
    while let Some(name) = current {
        match config.proxies.iter().find(|candidate| candidate.name == name) {
            Some(next) => {
                hops.push(next);
                current = next.dialer_proxy();
            }
            None => break,
        }
    }
    hops
}

async fn serve_request(
    mut client: TcpStream,
    peer: SocketAddr,
    id: u64,
    request: Result<inbound::Request, HandshakeError>,
    context: &SessionContext,
    closed: &Arc<tokio::sync::Notify>,
) -> Result<(), SessionOutcome> {
    let limits = context.limits;
    let counters = &context.counters;
    let config: &Config = &context.runtime.config;

    let request = match request {
        Ok(request) => request,
        Err(err) => {
            warn!(session = id, peer = %peer, code = err.code(), "handshake failed: {err}");
            return Err(SessionOutcome::Failed);
        }
    };
    let protocol = request.protocol;
    if protocol == inbound::Protocol::HttpConnect && !inbound::http_authorized(&request, &context.runtime.auth) {
        info!(session = id, peer = %peer, "HTTP CONNECT without a valid Proxy-Authorization");
        inbound::reply_http_auth_required(&mut client).await;
        return Err(SessionOutcome::Failed);
    }
    if request.command == inbound::Command::UdpAssociate {
        return serve_udp_associate(client, peer, id, context, config).await;
    }
    let raw_ip: Option<IpAddr> = request.host.parse().ok();
    // Pinned `preHandleMetadata`: a fake-ip/redir-host mapped address becomes
    // its host name again, and a domain-valued `hosts` entry is followed.
    let (host, ip) = match pre_handle_destination(context, &request.host, raw_ip).await {
        Ok(pair) => pair,
        Err(reason) => {
            warn!(session = id, target = %request.authority(), "destination mapping failed: {reason}");
            inbound::reply_failure(&mut client, protocol, 0x01).await;
            return Err(SessionOutcome::Failed);
        }
    };
    let mut target = Target::new(&host, ip)
        .with_port(request.port)
        .with_network(NetworkKind::Tcp)
        .with_source(peer.ip(), peer.port())
        .with_inbound(
            context.listen_port(),
            match protocol {
                inbound::Protocol::Socks5 => InType::Socks5,
                inbound::Protocol::HttpConnect => InType::Https,
            },
        );
    let decision = rule_decision(context, &mut target).await;
    let display_host = if host.is_empty() {
        ip.map(|ip| ip.to_string()).unwrap_or_default()
    } else {
        host.clone()
    };
    let authority = if display_host.contains(':') {
        format!("[{display_host}]:{}", request.port)
    } else {
        format!("{display_host}:{}", request.port)
    };
    debug!(
        session = id, peer = %peer, protocol = protocol.as_str(), target = %authority,
        rule = %decision, config = %config.digest, "request matched"
    );

    match decision.action {
        Action::Reject => {
            info!(session = id, target = %authority, protocol = protocol.as_str(), rule = %decision, "REJECT");
            inbound::reply_failure(&mut client, protocol, 0x07).await;
            return Err(SessionOutcome::Rejected);
        }
        Action::RejectDrop => {
            info!(session = id, target = %authority, protocol = protocol.as_str(), rule = %decision, "REJECT-DROP");
            return Err(SessionOutcome::Rejected);
        }
        _ => {}
    }

    // Group selection decides the leaf outbound (T23). REJECT was handled
    // above; a group may still choose REJECT/REJECT-DROP/DIRECT.
    let selected = match context
        .runtime
        .groups
        .resolve_action(decision.rule.action, &target, true)
    {
        Ok(selected) => selected,
        Err(error) => {
            warn!(session = id, target = %authority, rule = %decision, "group resolution failed: {error}");
            inbound::reply_failure(&mut client, protocol, 0x01).await;
            return Err(SessionOutcome::Failed);
        }
    };
    match selected {
        Selected::Reject => {
            info!(session = id, target = %authority, protocol = protocol.as_str(), rule = %decision, "REJECT (group member)");
            inbound::reply_failure(&mut client, protocol, 0x07).await;
            return Err(SessionOutcome::Rejected);
        }
        Selected::RejectDrop => {
            info!(session = id, target = %authority, protocol = protocol.as_str(), rule = %decision, "REJECT-DROP (group member)");
            return Err(SessionOutcome::Rejected);
        }
        _ => {}
    }
    let group_path: Vec<String> = selected.path().to_vec();
    // Pinned `chains`: the leaf outbound first, then every group outward.
    let chains: Vec<String> = match &selected {
        Selected::Direct => vec!["DIRECT".to_string()],
        Selected::Proxy { proxy, path } => {
            let mut names = vec![proxy.name.clone()];
            names.extend(path.iter().rev().cloned());
            names
        }
        Selected::Reject | Selected::RejectDrop => vec!["REJECT".to_string()],
    };
    let rule_kind = rule_type_name(&decision.rule.matcher);
    let rule_payload = rule_payload_text(&decision.rule.matcher);
    let (upstream, outbound, outbound_kind): (Box<dyn outbound::Stream>, String, &str) = match selected {
        Selected::Direct => {
            let stream = match tokio::time::timeout(
                limits.dial_timeout,
                direct_stream(context, &host, ip, request.port),
            )
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
        Selected::Proxy { proxy, .. } => {
            let hops = chain_for(config, &proxy);
            let dial_host = if host.is_empty() {
                ip.map(|ip| ip.to_string()).unwrap_or_default()
            } else {
                host.clone()
            };
            let dial_target = outbound::Target {
                host: dial_host,
                port: request.port,
            };
            // Proxy server names resolve through `proxy-server-nameserver`
            // when DNS is on (pinned `ProxyServerHostResolver`).
            let dial = async {
                match &context.runtime.dns {
                    Some(dns) => {
                        outbound::with_proxy_dns(
                            dns.clone(),
                            outbound::dial_chain(&hops, &dial_target, limits.dial_timeout, &context.runtime.tls),
                        )
                        .await
                    }
                    None => {
                        outbound::dial_chain(&hops, &dial_target, limits.dial_timeout, &context.runtime.tls)
                            .await
                    }
                }
            };
            match tokio::time::timeout(limits.dial_timeout, dial).await
            {
                Err(_) => {
                    warn!(session = id, target = %authority, rule = %decision, proxy = %proxy.name, "outbound dial timed out after {:?}", limits.dial_timeout);
                    context.runtime.groups.note_dial_failure(&group_path, "timeout");
                    inbound::reply_failure(&mut client, protocol, 0x01).await;
                    return Err(SessionOutcome::Failed);
                }
                Ok(Err(e)) => {
                    warn!(session = id, target = %authority, rule = %decision, proxy = %proxy.name, "outbound dial failed: {e}");
                    context.runtime.groups.note_dial_failure(&group_path, &e.to_string());
                    inbound::reply_failure(&mut client, protocol, 0x01).await;
                    return Err(SessionOutcome::Failed);
                }
                Ok(Ok(dialed)) => {
                    context.runtime.groups.note_dial_success(&group_path);
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
        Selected::Reject | Selected::RejectDrop => unreachable!("handled above"),
    };
    info!(
        session = id, target = %authority, protocol = protocol.as_str(), rule = %decision,
        outbound = %outbound, config = %config.digest, "{} tunnel established", outbound_kind
    );

    if inbound::reply_success(&mut client, &request).await.is_err() {
        return Err(SessionOutcome::Failed);
    }

    let upload = Arc::new(AtomicU64::new(0));
    let download = Arc::new(AtomicU64::new(0));
    let _connection = context.connections.register(OpenConnection {
        id: uuid::Uuid::new_v4().to_string(),
        host: host.clone(),
        destination_ip: ip,
        destination_port: request.port,
        source_ip: peer.ip(),
        source_port: peer.port(),
        kind: match protocol {
            inbound::Protocol::Socks5 => "Socks5",
            inbound::Protocol::HttpConnect => "HTTPS",
        },
        network: "tcp",
        inbound_port: context.listen_port(),
        chains,
        rule: rule_kind,
        rule_payload,
        start: std::time::SystemTime::now(),
        upload: upload.clone(),
        download: download.clone(),
        close: closed.clone(),
    });

    let relayed = relay(
        client,
        upstream,
        limits.buffer_size,
        limits.half_close_timeout,
        upload,
        download,
        counters.bytes_up.clone(),
        counters.bytes_down.clone(),
    )
    .await;
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

/// Serve a SOCKS5 `UDP ASSOCIATE`: bind the relay socket, tell the client where
/// it is, then forward every datagram through the rule set. The association
/// ends with the control connection (or `udp_idle_timeout`), and both sockets
/// and buffers are released with it.
///
/// Memory is bounded: two 64 KiB buffers (client datagram, one reply at a
/// time) plus one socket per transport actually used, so an association costs
/// at most ~128 KiB regardless of how many destinations it talks to.
async fn serve_udp_associate(
    client: TcpStream,
    peer: SocketAddr,
    id: u64,
    context: &SessionContext,
    config: &Config,
) -> Result<(), SessionOutcome> {
    // The association runs in its own session task, and a task-local scope is
    // not inherited across `tokio::spawn`. Re-enter the engine's
    // `proxy-server-nameserver` scope here so ss/ssr/socks5 server names are
    // resolved the same way the TCP path resolves them.
    match context.runtime.dns.clone() {
        Some(dns) => {
            outbound::with_proxy_dns(
                dns,
                serve_udp_associate_inner(client, peer, id, context, config),
            )
            .await
        }
        None => serve_udp_associate_inner(client, peer, id, context, config).await,
    }
}

/// One live per-destination UDP association. The pinned anytls UoT / ss UoT v2
/// / vmess plain outbounds open a packet conn or UoT stream per destination, so
/// the relay keeps one writer and one reader task per (proxy, target).
struct UotEntry {
    id: u64,
    writer: outbound::udp::UotWriter,
    abort: tokio::task::AbortHandle,
}

fn install_uot(
    map: &mut HashMap<outbound::udp::UotKey, UotEntry>,
    next_id: &mut u64,
    events: &tokio::sync::mpsc::UnboundedSender<outbound::udp::UotEvent>,
    key: outbound::udp::UotKey,
    reader: outbound::udp::UotReader,
    writer: outbound::udp::UotWriter,
) {
    let assoc_id = *next_id;
    *next_id = next_id.wrapping_add(1);
    let abort = outbound::udp::spawn_uot_reader(reader, key.clone(), assoc_id, events.clone());
    map.insert(
        key,
        UotEntry {
            id: assoc_id,
            writer,
            abort,
        },
    );
}

/// Send on an existing per-target association; a failed write retires it so
/// the next datagram opens a fresh one instead of losing traffic silently.
async fn send_on_uot(
    map: &mut HashMap<outbound::udp::UotKey, UotEntry>,
    key: &outbound::udp::UotKey,
    payload: &[u8],
) -> io::Result<()> {
    let result = match map.get_mut(key) {
        Some(entry) => entry.writer.send(payload).await,
        None => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no association for this destination",
        )),
    };
    if result.is_err() {
        if let Some(entry) = map.remove(key) {
            entry.abort.abort();
        }
    }
    result
}

async fn serve_udp_associate_inner(
    mut client: TcpStream,
    peer: SocketAddr,
    id: u64,
    context: &SessionContext,
    config: &Config,
) -> Result<(), SessionOutcome> {
    let limits = context.limits;
    let counters = &context.counters;
    let local = match client.local_addr() {
        Ok(local) => local,
        Err(e) => {
            warn!(session = id, "UDP associate: no local address: {e}");
            return Err(SessionOutcome::Failed);
        }
    };
    let relay = match tokio::net::UdpSocket::bind((local.ip(), 0)).await {
        Ok(socket) => socket,
        Err(e) => {
            warn!(session = id, "UDP associate: cannot bind relay: {e}");
            inbound::reply_failure(&mut client, inbound::Protocol::Socks5, 0x01).await;
            return Err(SessionOutcome::Failed);
        }
    };
    let relay_addr = match relay.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            warn!(session = id, "UDP associate: no relay address: {e}");
            return Err(SessionOutcome::Failed);
        }
    };
    if let Err(e) = inbound::reply_udp_associate(&mut client, relay_addr).await {
        warn!(session = id, "UDP associate: reply failed: {e}");
        return Err(SessionOutcome::Failed);
    }
    info!(
        session = id, peer = %peer, relay = %relay_addr, config = %config.digest,
        "UDP association established"
    );

    let mut client_udp: Option<SocketAddr> = None;
    let mut direct: Option<tokio::net::UdpSocket> = None;
    // The DIRECT socket is bound to the wildcard of the destination's family,
    // so a loopback-bound listener can still reach remote UDP targets (a socket
    // bound to 127.0.0.1 cannot). A destination of the other family recreates
    // it; in-flight replies of the previous family are dropped, which the log
    // records.
    let mut direct_v4 = true;
    let mut socks5: Option<outbound::socks5::Socks5Udp> = None;
    let mut ss: Option<outbound::udp::SsUdp> = None;
    let mut vless: Option<outbound::udp::VlessUdp> = None;
    let mut vmess: Option<outbound::udp::VmessUdp> = None;
    let mut trojan: Option<outbound::udp::TrojanUdp> = None;
    let mut ssr: Option<outbound::udp::SsrUdp> = None;
    let mut gost: Option<outbound::gost_relay::GostRelayUdp> = None;
    let mut gost_target: Option<outbound::Target> = None;
    let mut trusttunnel: Option<outbound::trusttunnel::TrustTunnelUdp> = None;
    let mut sudoku: Option<outbound::udp::SudokuUdp> = None;
    let mut masque: Option<outbound::masque::MasqueUdpAssociation> = None;
    let mut shadowquic: Option<outbound::shadowquic::ShadowQuicUdp> = None;
    let mut hysteria: Option<outbound::udp::HysteriaUdp> = None;
    let mut hysteria2: Option<outbound::udp::Hysteria2Udp> = None;
    let mut tuic: Option<outbound::tuic::TuicUdp> = None;
    // WireGuard/OpenVPN UDP is terminated by the shared userspace L3 stack.
    // The stack owns one unconnected smoltcp UDP socket per association; the
    // association carries every destination of this client flow.
    let mut l3: Option<outbound::l3::L3UdpSocket> = None;
    // Destination-bound UoT / plain-UDP associations (anytls, ss UoT v2/v1,
    // vmess plain). The pinned outbound opens one packet conn per destination
    // and reads every one of them concurrently; the relay mirrors that with a
    // writer map plus one reader task per association.
    let (uot_tx, mut uot_events) =
        tokio::sync::mpsc::unbounded_channel::<outbound::udp::UotEvent>();
    let mut uot_map: HashMap<outbound::udp::UotKey, UotEntry> = HashMap::new();
    let mut uot_next_id: u64 = 0;
    // One datagram buffer for the client, plus one reply buffer per transport
    // that is actually used: a direct-only association never allocates the ss
    // or trojan buffer.
    let mut client_buf = vec![0u8; outbound::udp::MAX_DATAGRAM];
    let mut direct_buf: Option<Vec<u8>> = None;
    let mut socks5_buf: Option<Vec<u8>> = None;
    let mut ss_buf: Option<Vec<u8>> = None;
    let mut vless_buf: Option<Vec<u8>> = None;
    let mut vmess_buf: Option<Vec<u8>> = None;
    let mut trojan_buf: Option<Vec<u8>> = None;
    let mut ssr_buf: Option<Vec<u8>> = None;
    let mut gost_buf: Option<Vec<u8>> = None;
    let mut trusttunnel_buf: Option<Vec<u8>> = None;
    let mut sudoku_buf: Option<Vec<u8>> = None;
    let mut masque_buf: Option<Vec<u8>> = None;
    let mut shadowquic_buf: Option<Vec<u8>> = None;
    let mut hysteria_buf: Option<Vec<u8>> = None;
    let mut hysteria2_buf: Option<Vec<u8>> = None;
    let mut tuic_buf: Option<Vec<u8>> = None;
    let mut l3_buf: Option<Vec<u8>> = None;
    let mut control_probe = [0u8; 1];
    let mut failed = false;
    let mut idle_deadline = tokio::time::Instant::now() + limits.udp_idle_timeout;
    // A transport that reported EOF/error is dropped outside the `select`, so
    // its branch cannot be polled again against a dead stream (which would spin
    // on an immediate EOF).
    let mut direct_eof = false;
    let mut socks5_eof = false;
    let mut ss_eof = false;
    let mut vless_eof = false;
    let mut vmess_eof = false;
    let mut trojan_eof = false;
    let mut ssr_eof = false;
    let mut gost_eof = false;
    let mut trusttunnel_eof = false;
    let mut sudoku_eof = false;
    let mut masque_eof = false;
    let mut shadowquic_eof = false;
    let mut hysteria_eof = false;
    let mut hysteria2_eof = false;
    let mut tuic_eof = false;
    let mut l3_eof = false;

    'associate: loop {
        if direct_eof {
            direct = None;
            direct_buf = None;
            direct_eof = false;
        }
        if socks5_eof {
            socks5 = None;
            socks5_buf = None;
            socks5_eof = false;
        }
        if ss_eof {
            ss = None;
            ss_buf = None;
            ss_eof = false;
        }
        if vless_eof {
            vless = None;
            vless_buf = None;
            vless_eof = false;
        }
        if vmess_eof {
            vmess = None;
            vmess_buf = None;
            vmess_eof = false;
        }
        if trojan_eof {
            trojan = None;
            trojan_buf = None;
            trojan_eof = false;
        }
        if ssr_eof {
            ssr = None;
            ssr_buf = None;
            ssr_eof = false;
        }
        if gost_eof {
            gost = None;
            gost_buf = None;
            gost_target = None;
            gost_eof = false;
        }
        if trusttunnel_eof {
            trusttunnel = None;
            trusttunnel_buf = None;
            trusttunnel_eof = false;
        }
        if sudoku_eof {
            sudoku = None;
            sudoku_buf = None;
            sudoku_eof = false;
        }
        if masque_eof {
            masque = None;
            masque_buf = None;
            masque_eof = false;
        }
        if shadowquic_eof {
            shadowquic = None;
            shadowquic_buf = None;
            shadowquic_eof = false;
        }
        if hysteria_eof {
            hysteria = None;
            hysteria_buf = None;
            hysteria_eof = false;
        }
        if hysteria2_eof {
            hysteria2 = None;
            hysteria2_buf = None;
            hysteria2_eof = false;
        }
        if tuic_eof {
            tuic = None;
            tuic_buf = None;
            tuic_eof = false;
        }
        if l3_eof {
            l3 = None;
            l3_buf = None;
            l3_eof = false;
        }
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(idle_deadline) => {
                debug!(session = id, "UDP association idle timeout");
                break 'associate;
            }
            read = client.read(&mut control_probe) => {
                match read {
                    Ok(0) | Err(_) => break 'associate,
                    // Data on the control connection is not part of RFC 1928's
                    // UDP association; it is discarded, the association stays.
                    Ok(_) => {}
                }
            }
            event = uot_events.recv() => {
                match event {
                    Some(outbound::udp::UotEvent::Datagram { from, payload }) => {
                        if let Some(client_udp) = client_udp {
                            let mut reply = outbound::udp::reply_header(&from);
                            reply.extend_from_slice(&payload);
                            let _ = relay.send_to(&reply, client_udp).await;
                            counters
                                .bytes_down
                                .fetch_add(payload.len() as u64, Ordering::Relaxed);
                        }
                    }
                    Some(outbound::udp::UotEvent::Closed { key, id: assoc_id }) => {
                        if uot_map.get(&key).is_some_and(|entry| entry.id == assoc_id) {
                            if let Some(entry) = uot_map.remove(&key) {
                                entry.abort.abort();
                            }
                        }
                    }
                    None => {}
                }
            }
            received = relay.recv_from(&mut client_buf) => {
                let (read, source) = match received {
                    Ok(pair) => pair,
                    Err(e) => {
                        debug!(session = id, "UDP relay read failed: {e}");
                        failed = true;
                        break 'associate;
                    }
                };
                // RFC 1928: only the client that created the association may use
                // it. The first datagram teaches the port, then it must match.
                match client_udp {
                    Some(known) if known != source => continue,
                    None if source.ip() != peer.ip() => continue,
                    None => client_udp = Some(source),
                    _ => {}
                }
                idle_deadline = tokio::time::Instant::now() + limits.udp_idle_timeout;
                let Some(datagram) = outbound::udp::parse_datagram(&client_buf[..read]) else {
                    debug!(session = id, "UDP datagram dropped: malformed or fragmented");
                    continue;
                };
                let payload = &client_buf[datagram.offset..read];
                let raw_ip: Option<IpAddr> = datagram.target.host.parse().ok();
                let (host, ip) = match pre_handle_destination(
                    context,
                    &datagram.target.host,
                    raw_ip,
                )
                .await
                {
                    Ok(pair) => pair,
                    Err(reason) => {
                        debug!(session = id, target = %datagram.target.host, "UDP destination mapping failed: {reason}");
                        failed = true;
                        continue;
                    }
                };
                let mut udp_target = Target::new(&host, ip)
                    .with_port(datagram.target.port)
                    .with_network(NetworkKind::Udp)
                    .with_source(peer.ip(), peer.port())
                    .with_inbound(context.listen_port(), InType::Socks5);
                let decision = rule_decision(context, &mut udp_target).await;
                let action = decision.action;
                if matches!(action, Action::Reject | Action::RejectDrop) {
                    debug!(session = id, target = %datagram.target.host, rule = %decision, "UDP REJECT");
                    continue;
                }
                let selected = match context.runtime.groups.resolve_action(action, &udp_target, true) {
                    Ok(selected) => selected,
                    Err(error) => {
                        debug!(session = id, target = %datagram.target.host, "UDP group resolution failed: {error}");
                        failed = true;
                        continue;
                    }
                };
                let proxy = match selected {
                    Selected::Direct => None,
                    Selected::Reject | Selected::RejectDrop => {
                        debug!(session = id, target = %datagram.target.host, rule = %decision, "UDP REJECT (group member)");
                        continue;
                    }
                    Selected::Proxy { proxy, path } => {
                        if context.runtime.groups.path_disables_udp(&path) {
                            debug!(
                                session = id, target = %datagram.target.host, group = %path.join("->"),
                                "UDP datagram dropped: the group sets disable-udp"
                            );
                            failed = true;
                            continue;
                        }
                        Some(proxy)
                    }
                };
                let dial_host = if host.is_empty() {
                    ip.map(|ip| ip.to_string()).unwrap_or_default()
                } else {
                    host.clone()
                };
                let outgoing = outbound::Target {
                    host: dial_host,
                    port: datagram.target.port,
                };
                let sent = match proxy {
                    None => {
                        let destination = match direct_udp_destination(
                            context,
                            &outgoing.host,
                            ip,
                            outgoing.port,
                        )
                        .await
                        {
                            Ok(addr) => addr,
                            Err(e) => {
                                debug!(session = id, target = %datagram.target.host, "UDP resolve failed: {e}");
                                failed = true;
                                continue;
                            }
                        };
                        let wants_v4 = destination.is_ipv4();
                        if direct.is_none() || wants_v4 != direct_v4 {
                            let bind = if wants_v4 { "0.0.0.0:0" } else { "[::]:0" };
                            match tokio::net::UdpSocket::bind(bind).await {
                                Ok(socket) => {
                                    direct = Some(socket);
                                    direct_v4 = wants_v4;
                                    direct_buf = Some(vec![0u8; outbound::udp::MAX_DATAGRAM]);
                                    direct_eof = false;
                                }
                                Err(e) => {
                                    warn!(session = id, "UDP direct socket: {e}");
                                    failed = true;
                                    continue;
                                }
                            }
                        }
                        let socket = direct.as_ref().expect("bound above");
                        socket.send_to(payload, destination).await.map(|_| ())
                    }
                    Some(proxy) => match &proxy.protocol {
                        crate::proxies::Protocol::Socks5(option) if option.udp => {
                            if socks5.is_none() {
                                match outbound::with_dialer(
                                    proxy.dialer.clone(),
                                    outbound::socks5::Socks5Udp::connect(
                                        option,
                                        limits.dial_timeout,
                                        &context.runtime.tls,
                                    ),
                                )
                                .await
                                {
                                    Ok(association) => {
                                        socks5 = Some(association);
                                        socks5_buf = Some(vec![0u8; outbound::udp::MAX_DATAGRAM]);
                                    }
                                    Err(e) => {
                                        warn!(session = id, proxy = %proxy.name, "socks5 UDP association failed: {e}");
                                        failed = true;
                                        continue;
                                    }
                                }
                            }
                            socks5
                                .as_mut()
                                .expect("connected above")
                                .send(&outgoing, payload)
                                .await
                        }
                        crate::proxies::Protocol::Shadowsocks(option)
                            if option.udp && option.udp_over_tcp =>
                        {
                            let key = outbound::udp::UotKey {
                                proxy: proxy.name.clone(),
                                target: outgoing.clone(),
                            };
                            if !uot_map.contains_key(&key) {
                                let hops = chain_for(config, &proxy);
                                match outbound::with_dialer(
                                    proxy.dialer.clone(),
                                    outbound::udp::SsUot::connect(
                                        option,
                                        &outgoing,
                                        &hops,
                                        limits.dial_timeout,
                                        &context.runtime.tls,
                                    ),
                                )
                                .await
                                {
                                    Ok(association) => {
                                        let (reader, writer) = association.into_halves();
                                        install_uot(
                                            &mut uot_map,
                                            &mut uot_next_id,
                                            &uot_tx,
                                            key.clone(),
                                            outbound::udp::UotReader::SsUot(reader),
                                            outbound::udp::UotWriter::SsUot(writer),
                                        );
                                    }
                                    Err(e) => {
                                        warn!(session = id, proxy = %proxy.name, "ss UoT association failed: {e}");
                                        failed = true;
                                        continue;
                                    }
                                }
                            }
                            send_on_uot(&mut uot_map, &key, payload).await
                        }
                        crate::proxies::Protocol::Vless(option) if option.udp => {
                            if vless.is_none() {
                                let hops = chain_for(config, &proxy);
                                match outbound::udp::VlessUdp::connect(
                                    option,
                                    &hops,
                                    limits.dial_timeout,
                                    &context.runtime.tls,
                                )
                                .await
                                {
                                    Ok(association) => {
                                        vless = Some(association);
                                        vless_buf = Some(vec![0u8; outbound::udp::MAX_DATAGRAM]);
                                    }
                                    Err(e) => {
                                        warn!(session = id, proxy = %proxy.name, "vless UDP association failed: {e}");
                                        failed = true;
                                        continue;
                                    }
                                }
                            }
                            vless
                                .as_mut()
                                .expect("connected above")
                                .send(&outgoing, payload)
                                .await
                        }
                        crate::proxies::Protocol::Anytls(option) if option.udp => {
                            let key = outbound::udp::UotKey {
                                proxy: proxy.name.clone(),
                                target: outgoing.clone(),
                            };
                            if !uot_map.contains_key(&key) {
                                let hops = chain_for(config, &proxy);
                                match outbound::with_dialer(
                                    proxy.dialer.clone(),
                                    outbound::udp::AnytlsUot::connect(
                                        option,
                                        &outgoing,
                                        &hops,
                                        limits.dial_timeout,
                                        &context.runtime.tls,
                                    ),
                                )
                                .await
                                {
                                    Ok(association) => {
                                        let (reader, writer) = association.into_halves();
                                        install_uot(
                                            &mut uot_map,
                                            &mut uot_next_id,
                                            &uot_tx,
                                            key.clone(),
                                            outbound::udp::UotReader::Anytls(reader),
                                            outbound::udp::UotWriter::Anytls(writer),
                                        );
                                    }
                                    Err(e) => {
                                        warn!(session = id, proxy = %proxy.name, "anytls UoT association failed: {e}");
                                        failed = true;
                                        continue;
                                    }
                                }
                            }
                            send_on_uot(&mut uot_map, &key, payload).await
                        }
                        crate::proxies::Protocol::Vmess(option) if option.udp => {
                            if option.xudp || option.packet_addr {
                                // XUDP and packet-addr carry the destination per
                                // frame, so one association serves every target.
                                if vmess.is_none() {
                                    let hops = chain_for(config, &proxy);
                                    match outbound::with_dialer(
                                        proxy.dialer.clone(),
                                        outbound::udp::VmessUdp::connect(
                                            option,
                                            &outgoing,
                                            &hops,
                                            limits.dial_timeout,
                                            &context.runtime.tls,
                                        ),
                                    )
                                    .await
                                    {
                                        Ok(association) => {
                                            vmess = Some(association);
                                            vmess_buf =
                                                Some(vec![0u8; outbound::udp::MAX_DATAGRAM]);
                                        }
                                        Err(e) => {
                                            warn!(session = id, proxy = %proxy.name, "vmess UDP association failed: {e}");
                                            failed = true;
                                            continue;
                                        }
                                    }
                                }
                                vmess
                                    .as_mut()
                                    .expect("connected above")
                                    .send(&outgoing, payload)
                                    .await
                            } else {
                                // Plain `command 2` binds one destination, so
                                // mirror the pinned per-destination packet conn.
                                let key = outbound::udp::UotKey {
                                    proxy: proxy.name.clone(),
                                    target: outgoing.clone(),
                                };
                                if !uot_map.contains_key(&key) {
                                    let hops = chain_for(config, &proxy);
                                    match outbound::with_dialer(
                                        proxy.dialer.clone(),
                                        outbound::udp::VmessUdp::connect(
                                            option,
                                            &outgoing,
                                            &hops,
                                            limits.dial_timeout,
                                            &context.runtime.tls,
                                        ),
                                    )
                                    .await
                                    {
                                        Ok(association) => {
                                            let (reader, writer) = association.into_plain_halves();
                                            install_uot(
                                                &mut uot_map,
                                                &mut uot_next_id,
                                                &uot_tx,
                                                key.clone(),
                                                outbound::udp::UotReader::Vmess {
                                                    reader,
                                                    bound: outgoing.clone(),
                                                },
                                                outbound::udp::UotWriter::Vmess(writer),
                                            );
                                        }
                                        Err(e) => {
                                            warn!(session = id, proxy = %proxy.name, "vmess UDP association failed: {e}");
                                            failed = true;
                                            continue;
                                        }
                                    }
                                }
                                send_on_uot(&mut uot_map, &key, payload).await
                            }
                        }
                        crate::proxies::Protocol::Shadowsocks(option) if option.udp => {
                            if ss.is_none() {
                                let hops = chain_for(config, &proxy);
                            match outbound::with_dialer(
                                proxy.dialer.clone(),
                                outbound::udp::SsUdp::connect(
                                    option,
                                    &hops,
                                    limits.dial_timeout,
                                    &context.runtime.tls,
                                ),
                            )
                            .await
                            {
                                    Ok(association) => {
                                        ss = Some(association);
                                        ss_buf = Some(vec![0u8; outbound::udp::MAX_DATAGRAM]);
                                    }
                                    Err(e) => {
                                        warn!(session = id, proxy = %proxy.name, "ss UDP association failed: {e}");
                                        failed = true;
                                        continue;
                                    }
                                }
                            }
                            ss.as_mut().expect("connected above").send(&outgoing, payload).await
                        }
                        crate::proxies::Protocol::Trojan(option) if option.udp => {
                            if trojan.is_none() {
                                let hops = chain_for(config, &proxy);
                                match outbound::with_dialer(
                                    proxy.dialer.clone(),
                                    outbound::udp::TrojanUdp::connect(
                                        option,
                                        &hops,
                                        limits.dial_timeout,
                                        &context.runtime.tls,
                                    ),
                                )
                                .await
                                {
                                    Ok(association) => {
                                        trojan = Some(association);
                                        trojan_buf = Some(vec![0u8; outbound::udp::MAX_DATAGRAM]);
                                    }
                                    Err(e) => {
                                        warn!(session = id, proxy = %proxy.name, "trojan UDP association failed: {e}");
                                        failed = true;
                                        continue;
                                    }
                                }
                            }
                            trojan.as_mut().expect("connected above").send(&outgoing, payload).await
                        }
                        crate::proxies::Protocol::Ssr(option) if option.udp => {
                            if ssr.is_none() {
                                let hops = chain_for(config, &proxy);
                                match outbound::with_dialer(
                                    proxy.dialer.clone(),
                                    outbound::udp::SsrUdp::connect(
                                        option,
                                        &hops,
                                        limits.dial_timeout,
                                        &context.runtime.tls,
                                    ),
                                )
                                .await
                                {
                                    Ok(association) => {
                                        ssr = Some(association);
                                        ssr_buf = Some(vec![0u8; outbound::udp::MAX_DATAGRAM]);
                                    }
                                    Err(e) => {
                                        warn!(session = id, proxy = %proxy.name, "ssr UDP association failed: {e}");
                                        failed = true;
                                        continue;
                                    }
                                }
                            }
                            ssr.as_mut()
                                .expect("connected above")
                                .send(&datagram.target, payload)
                                .await
                        }
                        crate::proxies::Protocol::GostRelay(option) if option.udp => {
                            // The pinned relay binds one association to one
                            // target, so a new destination replaces the
                            // association (and its in-flight replies).
                            let reuse = gost_target.as_ref() == Some(&outgoing);
                            if !reuse {
                                gost = None;
                                gost_target = None;
                                match outbound::with_dialer(
                                    proxy.dialer.clone(),
                                    outbound::gost_relay::GostRelayUdp::connect(
                                        option,
                                        &outgoing,
                                        &context.runtime.tls,
                                    ),
                                )
                                .await
                                {
                                    Ok(association) => {
                                        gost = Some(association);
                                        gost_target = Some(outgoing.clone());
                                        gost_buf = Some(vec![0u8; outbound::udp::MAX_DATAGRAM]);
                                    }
                                    Err(e) => {
                                        warn!(session = id, proxy = %proxy.name, "gost-relay UDP association failed: {e}");
                                        failed = true;
                                        continue;
                                    }
                                }
                            }
                            gost.as_mut().expect("connected above").send(payload).await
                        }
                        crate::proxies::Protocol::Masque(option) if option.udp => {
                            if masque.is_none() {
                                match outbound::with_dialer(
                                    proxy.dialer.clone(),
                                    outbound::masque::MasqueUdpAssociation::connect(
                                        option,
                                        &context.runtime.tls,
                                        limits.dial_timeout,
                                    ),
                                )
                                .await
                                {
                                    Ok(association) => {
                                        masque = Some(association);
                                        masque_buf = Some(vec![0u8; outbound::udp::MAX_DATAGRAM]);
                                    }
                                    Err(e) => {
                                        warn!(session = id, proxy = %proxy.name, "masque UDP association failed: {e}");
                                        failed = true;
                                        continue;
                                    }
                                }
                            }
                            masque
                                .as_mut()
                                .expect("connected above")
                                .send(&datagram.target, payload)
                                .await
                        }
                        crate::proxies::Protocol::Sudoku(option) if option.udp => {
                            if sudoku.is_none() {
                                let hops = chain_for(config, &proxy);
                                match outbound::with_dialer(
                                    proxy.dialer.clone(),
                                    outbound::udp::SudokuUdp::connect(
                                        option,
                                        &hops,
                                        limits.dial_timeout,
                                        &context.runtime.tls,
                                    ),
                                )
                                .await
                                {
                                    Ok(association) => {
                                        sudoku = Some(association);
                                        sudoku_buf = Some(vec![0u8; outbound::udp::MAX_DATAGRAM]);
                                    }
                                    Err(e) => {
                                        warn!(session = id, proxy = %proxy.name, "sudoku UDP association failed: {e}");
                                        failed = true;
                                        continue;
                                    }
                                }
                            }
                            sudoku
                                .as_mut()
                                .expect("connected above")
                                .send(&outgoing, payload)
                                .await
                        }
                        crate::proxies::Protocol::TrustTunnel(option) if option.udp => {
                            if trusttunnel.is_none() {
                                let hops = chain_for(config, &proxy);
                                match outbound::with_dialer(
                                    proxy.dialer.clone(),
                                    outbound::trusttunnel::TrustTunnelUdp::connect(
                                        option,
                                        &hops,
                                        limits.dial_timeout,
                                        &context.runtime.tls,
                                    ),
                                )
                                .await
                                {
                                    Ok(association) => {
                                        trusttunnel = Some(association);
                                        trusttunnel_buf = Some(vec![0u8; outbound::udp::MAX_DATAGRAM]);
                                    }
                                    Err(e) => {
                                        warn!(session = id, proxy = %proxy.name, "trusttunnel UDP association failed: {e}");
                                        failed = true;
                                        continue;
                                    }
                                }
                            }
                            // The `_udp2` record has no address-type field: the
                            // pinned `ListenPacketContext` resolves the
                            // destination (`ResolveUDP`) before framing it, so
                            // a name must go through the session hosts/DNS and
                            // the proxy's `ip-version` here, not the system
                            // resolver inside the transport.
                            let destination = match proxy_udp_destination(
                                context,
                                proxy.dialer.ip_version,
                                &outgoing.host,
                                ip,
                                outgoing.port,
                            )
                            .await
                            {
                                Ok(destination) => destination,
                                Err(e) => {
                                    debug!(session = id, proxy = %proxy.name, target = %outgoing.host, "trusttunnel UDP resolve failed: {e}");
                                    failed = true;
                                    continue;
                                }
                            };
                            let resolved = outbound::Target {
                                host: destination.ip().to_string(),
                                port: destination.port(),
                            };
                            trusttunnel
                                .as_mut()
                                .expect("connected above")
                                .send(&resolved, payload)
                                .await
                        }
                        crate::proxies::Protocol::ShadowQuic(option) => {
                            if shadowquic.is_none() {
                                match outbound::shadowquic::ShadowQuicUdp::connect(
                                    option,
                                    &context.runtime.tls,
                                    limits.dial_timeout,
                                )
                                .await
                                {
                                    Ok(association) => {
                                        shadowquic = Some(association);
                                        shadowquic_buf = Some(vec![0u8; outbound::udp::MAX_DATAGRAM]);
                                    }
                                    Err(e) => {
                                        warn!(session = id, proxy = %proxy.name, "shadowquic UDP association failed: {e}");
                                        failed = true;
                                        continue;
                                    }
                                }
                            }
                            shadowquic
                                .as_mut()
                                .expect("connected above")
                                .send(&datagram.target, payload)
                                .await
                        }
                        crate::proxies::Protocol::Hysteria(option) => {
                            // Hysteria v1 always enables UDP in the pinned
                            // outbound (`ProxyInfo.UDP: true`): one `udp=1`
                            // session carries every destination.
                            if hysteria.is_none() {
                                let hops = chain_for(config, &proxy);
                                match outbound::with_dialer(
                                    proxy.dialer.clone(),
                                    outbound::udp::HysteriaUdp::connect(
                                        option,
                                        &hops,
                                        limits.dial_timeout,
                                        &context.runtime.tls,
                                    ),
                                )
                                .await
                                {
                                    Ok(association) => {
                                        hysteria = Some(association);
                                        hysteria_buf = Some(vec![0u8; outbound::udp::MAX_DATAGRAM]);
                                    }
                                    Err(e) => {
                                        warn!(session = id, proxy = %proxy.name, "hysteria UDP association failed: {e}");
                                        failed = true;
                                        continue;
                                    }
                                }
                            }
                            hysteria
                                .as_mut()
                                .expect("connected above")
                                .send(&outgoing, payload)
                                .await
                        }
                        crate::proxies::Protocol::Hysteria2(option) => {
                            // Hysteria2 UDP is always enabled in the pinned
                            // outbound: one QUIC datagram session serves every
                            // destination, so the association is reused.
                            if hysteria2.is_none() {
                                let hops = chain_for(config, &proxy);
                                match outbound::with_dialer(
                                    proxy.dialer.clone(),
                                    outbound::udp::Hysteria2Udp::connect(
                                        option,
                                        &hops,
                                        limits.dial_timeout,
                                        &context.runtime.tls,
                                    ),
                                )
                                .await
                                {
                                    Ok(association) => {
                                        hysteria2 = Some(association);
                                        hysteria2_buf = Some(vec![0u8; outbound::udp::MAX_DATAGRAM]);
                                    }
                                    Err(e) => {
                                        warn!(session = id, proxy = %proxy.name, "hysteria2 UDP association failed: {e}");
                                        failed = true;
                                        continue;
                                    }
                                }
                            }
                            hysteria2
                                .as_mut()
                                .expect("connected above")
                                .send(&outgoing, payload)
                                .await
                        }
                        crate::proxies::Protocol::Tuic(option) => {
                            if option.udp_over_stream {
                                let key = outbound::udp::UotKey {
                                    proxy: proxy.name.clone(),
                                    target: outgoing.clone(),
                                };
                                if !uot_map.contains_key(&key) {
                                    match outbound::with_dialer(
                                        proxy.dialer.clone(),
                                        outbound::udp::TuicUot::connect(
                                            option,
                                            &outgoing,
                                            &chain_for(config, &proxy),
                                            limits.dial_timeout,
                                            &context.runtime.tls,
                                        ),
                                    )
                                    .await
                                    {
                                        Ok(association) => {
                                            let (reader, writer) = association.into_halves();
                                            install_uot(
                                                &mut uot_map,
                                                &mut uot_next_id,
                                                &uot_tx,
                                                key.clone(),
                                                outbound::udp::UotReader::Tuic(reader),
                                                outbound::udp::UotWriter::Tuic(writer),
                                            );
                                        }
                                        Err(e) => {
                                            warn!(session = id, proxy = %proxy.name, "tuic UoT association failed: {e}");
                                            failed = true;
                                            continue;
                                        }
                                    }
                                }
                                send_on_uot(&mut uot_map, &key, payload).await
                            } else {
                                if tuic.is_none() {
                                    let hops = chain_for(config, &proxy);
                                    match outbound::with_dialer(
                                        proxy.dialer.clone(),
                                        outbound::tuic::TuicUdp::connect(
                                            option,
                                            &hops,
                                            &context.runtime.tls,
                                            limits.dial_timeout,
                                        ),
                                    )
                                    .await
                                    {
                                        Ok(association) => {
                                            tuic = Some(association);
                                            tuic_buf = Some(vec![0u8; outbound::udp::MAX_DATAGRAM]);
                                        }
                                        Err(e) => {
                                            warn!(session = id, proxy = %proxy.name, "tuic UDP association failed: {e}");
                                            failed = true;
                                            continue;
                                        }
                                    }
                                }
                                tuic
                                    .as_mut()
                                    .expect("connected above")
                                    .send(&outgoing, payload)
                                    .await
                            }
                        }
                        crate::proxies::Protocol::Wireguard(option) if option.udp => {
                            if l3.is_none() {
                                match outbound::with_dialer(
                                    proxy.dialer.clone(),
                                    outbound::wireguard::connect_stack(
                                        option,
                                        limits.dial_timeout,
                                    ),
                                )
                                .await
                                {
                                    Ok(stack) => match stack.udp_socket() {
                                        Ok(socket) => {
                                            l3 = Some(socket);
                                            l3_buf = Some(vec![0u8; outbound::udp::MAX_DATAGRAM]);
                                            l3_eof = false;
                                        }
                                        Err(e) => {
                                            warn!(session = id, proxy = %proxy.name, "wireguard UDP socket: {e}");
                                            failed = true;
                                            continue;
                                        }
                                    },
                                    Err(e) => {
                                        warn!(session = id, proxy = %proxy.name, "wireguard UDP stack failed: {e}");
                                        failed = true;
                                        continue;
                                    }
                                }
                            }
                            let destination = match direct_udp_destination(
                                context,
                                &outgoing.host,
                                ip,
                                outgoing.port,
                            )
                            .await
                            {
                                Ok(addr) => addr,
                                Err(e) => {
                                    debug!(session = id, target = %datagram.target.host, "wireguard UDP resolve failed: {e}");
                                    failed = true;
                                    continue;
                                }
                            };
                            l3.as_ref()
                                .expect("created above")
                                .send(destination, payload)
                                .await
                        }
                        crate::proxies::Protocol::OpenVpn(option) => {
                            if l3.is_none() {
                                match outbound::with_dialer(
                                    proxy.dialer.clone(),
                                    outbound::openvpn::connect_stack(
                                        option,
                                        limits.dial_timeout,
                                    ),
                                )
                                .await
                                {
                                    Ok(stack) => match stack.udp_socket() {
                                        Ok(socket) => {
                                            l3 = Some(socket);
                                            l3_buf = Some(vec![0u8; outbound::udp::MAX_DATAGRAM]);
                                            l3_eof = false;
                                        }
                                        Err(e) => {
                                            warn!(session = id, proxy = %proxy.name, "openvpn UDP socket: {e}");
                                            failed = true;
                                            continue;
                                        }
                                    },
                                    Err(e) => {
                                        warn!(session = id, proxy = %proxy.name, "openvpn UDP stack failed: {e}");
                                        failed = true;
                                        continue;
                                    }
                                }
                            }
                            let destination = match direct_udp_destination(
                                context,
                                &outgoing.host,
                                ip,
                                outgoing.port,
                            )
                            .await
                            {
                                Ok(addr) => addr,
                                Err(e) => {
                                    debug!(session = id, target = %datagram.target.host, "openvpn UDP resolve failed: {e}");
                                    failed = true;
                                    continue;
                                }
                            };
                            l3.as_ref()
                                .expect("created above")
                                .send(destination, payload)
                                .await
                        }
                        other => {
                            // The pinned outbound has no UDP association this
                            // kernel implements for this family; dropping is a
                            // recorded gap, never a silent success.
                            debug!(
                                session = id, proxy = %proxy.name, proxy_type = %other_type(other),
                                "UDP datagram dropped: no UDP association for this proxy type"
                            );
                            failed = true;
                            continue;
                        }
                    },
                };
                match sent {
                    Ok(()) => {
                        counters.bytes_up.fetch_add(payload.len() as u64, Ordering::Relaxed);
                    }
                    Err(e) => {
                        debug!(session = id, "UDP send failed: {e}");
                        failed = true;
                    }
                }
            }
            received = async {
                match (direct.as_ref(), direct_buf.as_mut()) {
                    (Some(socket), Some(buffer)) => socket.recv_from(buffer.as_mut_slice()).await,
                    _ => std::future::pending().await,
                }
            }, if direct.is_some() && !direct_eof => {
                if received.is_err() {
                    direct_eof = true;
                    failed = true;
                }
                if let (Ok((read, from)), Some(buffer)) = (received, direct_buf.as_ref()) {
                    if let Some(client_udp) = client_udp {
                        let target = outbound::Target {
                            host: from.ip().to_string(),
                            port: from.port(),
                        };
                        let mut reply = outbound::udp::reply_header(&target);
                        reply.extend_from_slice(&buffer[..read]);
                        let _ = relay.send_to(&reply, client_udp).await;
                        counters.bytes_down.fetch_add(read as u64, Ordering::Relaxed);
                    }
                }
            }
            received = async {
                match (socks5.as_mut(), socks5_buf.as_mut()) {
                    (Some(association), Some(buffer)) => {
                        association.recv(buffer.as_mut_slice()).await
                    }
                    _ => std::future::pending().await,
                }
            }, if socks5.is_some() && !socks5_eof => {
                if received.is_err() {
                    socks5_eof = true;
                    failed = true;
                }
                if let (Ok(Some((from, read))), Some(buffer)) = (received, socks5_buf.as_ref()) {
                    if let Some(client_udp) = client_udp {
                        let mut reply = outbound::udp::reply_header(&from);
                        reply.extend_from_slice(&buffer[..read]);
                        let _ = relay.send_to(&reply, client_udp).await;
                        counters.bytes_down.fetch_add(read as u64, Ordering::Relaxed);
                    }
                }
            }
            received = async {
                match (ss.as_mut(), ss_buf.as_mut()) {
                    (Some(association), Some(buffer)) => {
                        association.recv(buffer.as_mut_slice()).await
                    }
                    _ => std::future::pending().await,
                }
            }, if ss.is_some() && !ss_eof => {
                // `Ok(None)` is one dropped datagram (a foreign or tampered
                // packet), not the end of the association; only a socket error
                // retires it.
                if received.is_err() {
                    ss_eof = true;
                    failed = true;
                }
                if let (Ok(Some((from, read))), Some(buffer)) = (received, ss_buf.as_ref()) {
                    if let Some(client_udp) = client_udp {
                        let mut reply = outbound::udp::reply_header(&from);
                        reply.extend_from_slice(&buffer[..read]);
                        let _ = relay.send_to(&reply, client_udp).await;
                        counters.bytes_down.fetch_add(read as u64, Ordering::Relaxed);
                    }
                }
            }
            received = async {
                match (vless.as_mut(), vless_buf.as_mut()) {
                    (Some(association), Some(buffer)) => {
                        association.recv(buffer.as_mut_slice()).await
                    }
                    _ => std::future::pending().await,
                }
            }, if vless.is_some() && !vless_eof => {
                match &received {
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => {
                        vless_eof = true;
                        failed = true;
                    }
                }
                if let (Ok(Some((from, read))), Some(buffer)) = (received, vless_buf.as_ref()) {
                    if let Some(client_udp) = client_udp {
                        let mut reply = outbound::udp::reply_header(&from);
                        reply.extend_from_slice(&buffer[..read]);
                        let _ = relay.send_to(&reply, client_udp).await;
                        counters.bytes_down.fetch_add(read as u64, Ordering::Relaxed);
                    }
                }
            }
            received = async {
                match (vmess.as_mut(), vmess_buf.as_mut()) {
                    (Some(association), Some(buffer)) => {
                        association.recv(buffer.as_mut_slice()).await
                    }
                    _ => std::future::pending().await,
                }
            }, if vmess.is_some() && !vmess_eof => {
                match &received {
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => {
                        vmess_eof = true;
                        failed = true;
                    }
                }
                if let (Ok(Some((from, read))), Some(buffer)) = (received, vmess_buf.as_ref()) {
                    if let Some(client_udp) = client_udp {
                        let mut reply = outbound::udp::reply_header(&from);
                        reply.extend_from_slice(&buffer[..read]);
                        let _ = relay.send_to(&reply, client_udp).await;
                        counters.bytes_down.fetch_add(read as u64, Ordering::Relaxed);
                    }
                }
            }
            received = async {
                match (trojan.as_mut(), trojan_buf.as_mut()) {
                    (Some(association), Some(buffer)) => {
                        association.recv(buffer.as_mut_slice()).await
                    }
                    _ => std::future::pending().await,
                }
            }, if trojan.is_some() && !trojan_eof => {
                match &received {
                    Ok(Some(_)) => {}
                    // EOF or a broken stream: the server rejected the
                    // association (for example a wrong password).
                    Ok(None) | Err(_) => {
                        trojan_eof = true;
                        failed = true;
                    }
                }
                if let (Ok(Some((from, read))), Some(buffer)) = (received, trojan_buf.as_ref()) {
                    if let Some(client_udp) = client_udp {
                        let mut reply = outbound::udp::reply_header(&from);
                        reply.extend_from_slice(&buffer[..read]);
                        let _ = relay.send_to(&reply, client_udp).await;
                        counters.bytes_down.fetch_add(read as u64, Ordering::Relaxed);
                    }
                }
            }
            received = async {
                match (ssr.as_mut(), ssr_buf.as_mut()) {
                    (Some(association), Some(buffer)) => {
                        association.recv(buffer.as_mut_slice()).await
                    }
                    _ => std::future::pending().await,
                }
            }, if ssr.is_some() && !ssr_eof => {
                if received.is_err() {
                    ssr_eof = true;
                    failed = true;
                }
                if let (Ok(Some((from, read))), Some(buffer)) = (received, ssr_buf.as_ref()) {
                    if let Some(client_udp) = client_udp {
                        let mut reply = outbound::udp::reply_header(&from);
                        reply.extend_from_slice(&buffer[..read]);
                        let _ = relay.send_to(&reply, client_udp).await;
                        counters.bytes_down.fetch_add(read as u64, Ordering::Relaxed);
                    }
                }
            }
            received = async {
                match (gost.as_mut(), gost_buf.as_mut()) {
                    (Some(association), Some(buffer)) => {
                        association.recv(buffer.as_mut_slice()).await
                    }
                    _ => std::future::pending().await,
                }
            }, if gost.is_some() && !gost_eof => {
                match &received {
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => {
                        gost_eof = true;
                        failed = true;
                    }
                }
                if let (Ok(Some(read)), Some(buffer), Some(bound)) =
                    (received, gost_buf.as_ref(), gost_target.as_ref())
                {
                    if let Some(client_udp) = client_udp {
                        let mut reply = outbound::udp::reply_header(bound);
                        reply.extend_from_slice(&buffer[..read]);
                        let _ = relay.send_to(&reply, client_udp).await;
                        counters.bytes_down.fetch_add(read as u64, Ordering::Relaxed);
                    }
                }
            }
            received = async {
                match (masque.as_mut(), masque_buf.as_mut()) {
                    (Some(association), Some(buffer)) => {
                        association.recv(buffer.as_mut_slice()).await
                    }
                    _ => std::future::pending().await,
                }
            }, if masque.is_some() && !masque_eof => {
                if received.is_err() {
                    masque_eof = true;
                    failed = true;
                }
                if let (Ok(Some((from, read))), Some(buffer)) = (received, masque_buf.as_ref()) {
                    if let Some(client_udp) = client_udp {
                        let mut reply = outbound::udp::reply_header(&from);
                        reply.extend_from_slice(&buffer[..read]);
                        let _ = relay.send_to(&reply, client_udp).await;
                        counters.bytes_down.fetch_add(read as u64, Ordering::Relaxed);
                    }
                }
            }
            received = async {
                match (sudoku.as_mut(), sudoku_buf.as_mut()) {
                    (Some(association), Some(buffer)) => {
                        association.recv(buffer.as_mut_slice()).await
                    }
                    _ => std::future::pending().await,
                }
            }, if sudoku.is_some() && !sudoku_eof => {
                if received.is_err() {
                    sudoku_eof = true;
                    failed = true;
                }
                if let (Ok(Some((from, read))), Some(buffer)) = (received, sudoku_buf.as_ref()) {
                    if let Some(client_udp) = client_udp {
                        let mut reply = outbound::udp::reply_header(&from);
                        reply.extend_from_slice(&buffer[..read]);
                        let _ = relay.send_to(&reply, client_udp).await;
                        counters.bytes_down.fetch_add(read as u64, Ordering::Relaxed);
                    }
                }
            }
            received = async {
                match (trusttunnel.as_mut(), trusttunnel_buf.as_mut()) {
                    (Some(association), Some(buffer)) => {
                        association.recv(buffer.as_mut_slice()).await
                    }
                    _ => std::future::pending().await,
                }
            }, if trusttunnel.is_some() && !trusttunnel_eof => {
                if received.is_err() {
                    trusttunnel_eof = true;
                    failed = true;
                }
                if let (Ok(Some((from, read))), Some(buffer)) = (received, trusttunnel_buf.as_ref()) {
                    if let Some(client_udp) = client_udp {
                        let mut reply = outbound::udp::reply_header(&from);
                        reply.extend_from_slice(&buffer[..read]);
                        let _ = relay.send_to(&reply, client_udp).await;
                        counters.bytes_down.fetch_add(read as u64, Ordering::Relaxed);
                    }
                }
            }
            received = async {
                match (shadowquic.as_mut(), shadowquic_buf.as_mut()) {
                    (Some(association), Some(buffer)) => {
                        association.recv(buffer.as_mut_slice()).await
                    }
                    _ => std::future::pending().await,
                }
            }, if shadowquic.is_some() && !shadowquic_eof => {
                match &received {
                    Ok(None) | Err(_) => {
                        shadowquic_eof = true;
                        failed = true;
                    }
                    Ok(Some(_)) => {}
                }
                if let (Ok(Some((from, read))), Some(buffer)) = (received, shadowquic_buf.as_ref()) {
                    if let Some(client_udp) = client_udp {
                        let mut reply = outbound::udp::reply_header(&from);
                        reply.extend_from_slice(&buffer[..read]);
                        let _ = relay.send_to(&reply, client_udp).await;
                        counters.bytes_down.fetch_add(read as u64, Ordering::Relaxed);
                    }
                }
            }
            received = async {
                match (hysteria.as_mut(), hysteria_buf.as_mut()) {
                    (Some(association), Some(buffer)) => {
                        association.recv(buffer.as_mut_slice()).await
                    }
                    _ => std::future::pending().await,
                }
            }, if hysteria.is_some() && !hysteria_eof => {
                if matches!(&received, Ok(None) | Err(_)) {
                    hysteria_eof = true;
                    failed = true;
                }
                if let (Ok(Some((from, read))), Some(buffer)) = (received, hysteria_buf.as_ref()) {
                    if let Some(client_udp) = client_udp {
                        let mut reply = outbound::udp::reply_header(&from);
                        reply.extend_from_slice(&buffer[..read]);
                        let _ = relay.send_to(&reply, client_udp).await;
                        counters.bytes_down.fetch_add(read as u64, Ordering::Relaxed);
                    }
                }
            }
            received = async {
                match (hysteria2.as_mut(), hysteria2_buf.as_mut()) {
                    (Some(association), Some(buffer)) => {
                        association.recv(buffer.as_mut_slice()).await
                    }
                    _ => std::future::pending().await,
                }
            }, if hysteria2.is_some() && !hysteria2_eof => {
                // The QUIC connection ending is the association ending; the
                // client keeps its UDP association and simply has no exit.
                if matches!(&received, Ok(None) | Err(_)) {
                    hysteria2_eof = true;
                    failed = true;
                }
                if let (Ok(Some((from, read))), Some(buffer)) = (received, hysteria2_buf.as_ref()) {
                    if let Some(client_udp) = client_udp {
                        let mut reply = outbound::udp::reply_header(&from);
                        reply.extend_from_slice(&buffer[..read]);
                        let _ = relay.send_to(&reply, client_udp).await;
                        counters.bytes_down.fetch_add(read as u64, Ordering::Relaxed);
                    }
                }
            }
            received = async {
                match (l3.as_ref(), l3_buf.as_mut()) {
                    (Some(association), Some(buffer)) => {
                        association.recv(buffer.as_mut_slice()).await.map(Some)
                    }
                    _ => std::future::pending().await,
                }
            }, if l3.is_some() && !l3_eof => {
                if matches!(&received, Ok(None) | Err(_)) {
                    l3_eof = true;
                    failed = true;
                }
                if let (Ok(Some((from, read))), Some(buffer)) = (received, l3_buf.as_ref()) {
                    if let Some(client_udp) = client_udp {
                        let target = outbound::Target {
                            host: from.ip().to_string(),
                            port: from.port(),
                        };
                        let mut reply = outbound::udp::reply_header(&target);
                        reply.extend_from_slice(&buffer[..read]);
                        let _ = relay.send_to(&reply, client_udp).await;
                        counters.bytes_down.fetch_add(read as u64, Ordering::Relaxed);
                    }
                }
            }
            received = async {
                match (tuic.as_mut(), tuic_buf.as_mut()) {
                    (Some(association), Some(buffer)) => {
                        association.recv(buffer.as_mut_slice()).await
                    }
                    _ => std::future::pending().await,
                }
            }, if tuic.is_some() && !tuic_eof => {
                if matches!(&received, Ok(None) | Err(_)) {
                    tuic_eof = true;
                    failed = true;
                }
                if let (Ok(Some((from, read))), Some(buffer)) = (received, tuic_buf.as_ref()) {
                    if let Some(client_udp) = client_udp {
                        let mut reply = outbound::udp::reply_header(&from);
                        reply.extend_from_slice(&buffer[..read]);
                        let _ = relay.send_to(&reply, client_udp).await;
                        counters.bytes_down.fetch_add(read as u64, Ordering::Relaxed);
                    }
                }
            }
        }
    }
    // Retire every per-destination reader task with the association; a task
    // must not outlive the client that owns the relay.
    for (_, entry) in uot_map.drain() {
        entry.abort.abort();
    }
    info!(session = id, "UDP association closed");
    if failed {
        Err(SessionOutcome::Failed)
    } else {
        Ok(())
    }
}

fn other_type(protocol: &crate::proxies::Protocol) -> &'static str {
    match protocol {
        crate::proxies::Protocol::Socks5(_) => "socks5",
        crate::proxies::Protocol::Http(_) => "http",
        crate::proxies::Protocol::Shadowsocks(_) => "ss (udp: false)",
        crate::proxies::Protocol::Trojan(_) => "trojan (udp: false)",
        crate::proxies::Protocol::Vless(_) => "vless",
        crate::proxies::Protocol::Anytls(_) => "anytls",
        crate::proxies::Protocol::Vmess(_) => "vmess (udp: false)",
        crate::proxies::Protocol::Snell(_) => "snell (udp: false)",
        crate::proxies::Protocol::TrustTunnel(_) => "trusttunnel (udp: false)",
        crate::proxies::Protocol::GostRelay(_) => "gost-relay (udp: false)",
        crate::proxies::Protocol::Ssh(_) => "ssh (udp: false)",
        crate::proxies::Protocol::Ssr(_) => "ssr (udp: false)",
        crate::proxies::Protocol::Tuic(_) => "tuic",
        crate::proxies::Protocol::Hysteria(_) => "hysteria",
        crate::proxies::Protocol::Hysteria2(_) => "hysteria2",
        crate::proxies::Protocol::Mieru(_) => "mieru (udp: false)",
        crate::proxies::Protocol::Sudoku(_) => "sudoku (udp: false)",
        crate::proxies::Protocol::Masque(_) => "masque (udp: false)",
        crate::proxies::Protocol::ShadowQuic(_) => "shadowquic",
        crate::proxies::Protocol::Wireguard(_) => "wireguard (udp: false)",
        crate::proxies::Protocol::OpenVpn(_) => "openvpn",
        crate::proxies::Protocol::Tailscale(_) => "tailscale (no UDP association)",
        crate::proxies::Protocol::Zerotier(_) => "zerotier (no UDP association)",
        crate::proxies::Protocol::Easytier(_) => "easytier (no UDP association)",
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
    up_bytes: Arc<AtomicU64>,
    down_bytes: Arc<AtomicU64>,
    total_up: Arc<AtomicU64>,
    total_down: Arc<AtomicU64>,
) -> Relayed {
    let (client_r, client_w) = client.into_split();
    let (upstream_r, upstream_w) = tokio::io::split(upstream);
    let upload = copy_half(client_r, upstream_w, buffer_size, up_bytes.clone(), total_up);
    let download = copy_half(upstream_r, client_w, buffer_size, down_bytes.clone(), total_down);
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
    total: Arc<AtomicU64>,
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
        total.fetch_add(n as u64, Ordering::Relaxed);
    }
    // Shuts the write side only; the peer observes a FIN (half-close).
    let _ = writer.shutdown().await;
    false
}
