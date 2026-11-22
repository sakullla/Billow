//! Proxy groups (T23): member expansion, selection, health checks and the
//! selection cache.
//!
//! Parsing lives in [`crate::config`]; this module owns the runtime:
//!
//! - members are expanded per the pinned `outboundgroup.Parser` rules: the
//!   inline `proxies` list first (the "compatible" provider), then every `use`
//!   provider snapshot, with `filter`/`exclude-filter`/`exclude-type` applied;
//! - `select`/`url-test`/`fallback`/`load-balance` choose a member per dial;
//!   nested groups recurse until a leaf outbound is reached;
//! - health state is keyed by (member source, member name, test URL), matching
//!   the pinned per-URL `extra` history: a member with no probe record yet is
//!   considered alive, and `LastDelayForTestUrl` is `0xffff` until a probe
//!   succeeds;
//! - selections are persisted to a small YAML cache when
//!   `profile.store-selected` is true (pinned writes a bbolt `cache.db`; only
//!   the selected map semantics are shared).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use regex::Regex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

use crate::config::{
    Action, Config, ConfigError, EmptyFallback, ExpectedStatus, GroupKind, HashKey,
    LoadBalanceStrategy, ProxyGroup,
};
use crate::outbound::tls::ClientTls;
use crate::outbound::{self, Target as DialTarget};
use crate::proxies::{Proxy, TlsSettings};
use crate::provider::RuleProviders;

/// `timeout` default (milliseconds) of a health check.
pub const DEFAULT_TIMEOUT_MS: u64 = 5_000;
/// `max-failed-times` default.
pub const DEFAULT_MAX_FAILED_TIMES: usize = 5;
/// Pinned health checks run at most ten probes at a time (`errgroup.SetLimit(10)`).
const PROBE_LIMIT: usize = 10;
/// `LastDelayForTestUrl` before any successful probe.
const UNKNOWN_DELAY: u16 = u16::MAX;

/// An error while expanding or resolving a group.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GroupError {
    #[error("unknown proxy group '{0}'")]
    UnknownGroup(String),
    #[error("'{1}' not found in proxy group '{0}'")]
    UnknownMember(String, String),
    #[error("proxy group '{0}' has no member")]
    Empty(String),
    #[error("proxy group '{0}' resolves to '{1}', which cannot be dialed: {2}")]
    NotDialable(String, String, String),
}

/// A member of a group after name resolution.
#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    pub source: MemberSource,
    pub reference: MemberRef,
}

/// Where a member came from. Two providers may carry proxies with the same
/// name; health records are kept per source (pinned keeps one adapter per
/// provider entry).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemberSource {
    Inline,
    Provider(String),
    Group,
    EmptyFallback,
}

#[derive(Debug, Clone)]
pub enum MemberRef {
    Proxy(Arc<Proxy>),
    Group(usize),
    Builtin(Builtin),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Builtin {
    Direct,
    Reject,
    RejectDrop,
}

/// The leaf outbound a rule action resolved to.
#[derive(Debug, Clone)]
pub enum Selected {
    Direct,
    Reject,
    RejectDrop,
    Proxy {
        proxy: Arc<Proxy>,
        /// Group names traversed, outermost first (for logging and health).
        path: Vec<String>,
    },
}

impl Selected {
    /// Group path this selection went through (empty for a direct action).
    pub fn path(&self) -> &[String] {
        match self {
            Selected::Proxy { path, .. } => path,
            _ => &[],
        }
    }
}

/// One member's health as exposed to hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberHealth {
    pub name: String,
    pub alive: bool,
    /// Last successful delay in milliseconds; `None` when unknown.
    pub delay: Option<u16>,
}

/// Group status for the library/control entry (T25 builds its JSON from this).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupStatus {
    pub name: String,
    pub kind: &'static str,
    pub now: String,
    /// Member names in the pinned `all` order.
    pub all: Vec<String>,
    /// Explicitly fixed selection (`fixed` in the pinned JSON), if any.
    pub fixed: Option<String>,
    pub default_selected: Option<String>,
    pub test_url: String,
    pub expected_status: String,
    pub hidden: bool,
    pub icon: String,
    pub empty_fallback: String,
    pub members: Vec<MemberHealth>,
}

/// The `profile.store-selected` cache: a tiny YAML file mapping group name to
/// the selected member.
#[derive(Debug)]
pub struct SelectionCache {
    path: PathBuf,
    selected: Mutex<BTreeMap<String, String>>,
}

impl SelectionCache {
    /// Load `path` if it exists; a malformed cache starts empty (the pinned
    /// engine removes an invalid `cache.db` and continues).
    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let selected = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_yaml::from_str::<serde_yaml::Value>(&text).ok())
            .and_then(|value| {
                let mapping = value.get("selected")?.as_mapping()?.clone();
                let mut out = BTreeMap::new();
                for (key, value) in mapping {
                    if let (Some(group), Some(member)) = (key.as_str(), value.as_str()) {
                        out.insert(group.to_string(), member.to_string());
                    }
                }
                Some(out)
            })
            .unwrap_or_default();
        SelectionCache {
            path,
            selected: Mutex::new(selected),
        }
    }

    pub fn get(&self, group: &str) -> Option<String> {
        self.selected
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(group)
            .cloned()
    }

    /// Store one selection and rewrite the file. A write failure is returned so
    /// hosts can log it; the in-memory selection is still applied.
    pub fn set(&self, group: &str, member: Option<&str>) -> std::io::Result<()> {
        let snapshot = {
            let mut map = self
                .selected
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match member {
                Some(member) => map.insert(group.to_string(), member.to_string()),
                None => map.remove(group),
            };
            map.clone()
        };
        let mut value = serde_yaml::Mapping::new();
        let mut entries = serde_yaml::Mapping::new();
        for (group, member) in snapshot {
            entries.insert(
                serde_yaml::Value::String(group),
                serde_yaml::Value::String(member),
            );
        }
        value.insert(
            serde_yaml::Value::String("selected".to_string()),
            serde_yaml::Value::Mapping(entries),
        );
        let text = serde_yaml::to_string(&serde_yaml::Value::Mapping(value))
            .map_err(std::io::Error::other)?;
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let temporary = self.path.with_extension("tmp");
        std::fs::write(&temporary, text)?;
        std::fs::rename(&temporary, &self.path)?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
struct HealthState {
    alive: bool,
    delay: u16,
}

#[derive(Debug, Default)]
struct GroupState {
    /// Explicit selection (API or cache).
    selected: Option<String>,
    /// Cached url-test winner (`fastNode`).
    fast_node: Option<String>,
    /// Round-robin cursor and sticky-sessions cache for load-balance.
    round_robin: usize,
    sticky: BTreeMap<u64, (usize, Instant)>,
    /// Failed dial accounting (`onDialFailed`).
    failed_times: usize,
    failed_since: Option<Instant>,
    testing: bool,
}

#[derive(Debug)]
struct MemberCache {
    versions: Vec<u64>,
    members: Vec<Member>,
}

struct GroupRuntime {
    def: ProxyGroup,
    filter: Vec<Regex>,
    exclude_filter: Vec<Regex>,
    members: RwLock<MemberCache>,
    state: Mutex<GroupState>,
    touched: Mutex<Option<Instant>>,
}

impl GroupRuntime {
    fn new(def: ProxyGroup) -> Self {
        let compile = |patterns: &[String]| {
            patterns
                .iter()
                .map(|pattern| Regex::new(pattern).expect("validated at load"))
                .collect::<Vec<_>>()
        };
        let filter = compile(&def.filter);
        let exclude_filter = compile(&def.exclude_filter);
        GroupRuntime {
            def,
            filter,
            exclude_filter,
            members: RwLock::new(MemberCache {
                versions: Vec::new(),
                members: Vec::new(),
            }),
            state: Mutex::new(GroupState::default()),
            touched: Mutex::new(None),
        }
    }
}

/// A health task: one URL checked for one set of members.
struct HealthTask {
    label: String,
    url: String,
    expected: ExpectedStatus,
    timeout: Duration,
    interval: Duration,
    lazy: bool,
    filter: Vec<Regex>,
    targets: HealthTarget,
    /// Next scheduled probe (pinned uses one ticker per interval).
    next_due: Mutex<Instant>,
    running: AtomicBool,
    /// Pinned `HealthCheck.process` starts with `go hc.check()` and
    /// `baseProvider.setProxies` checks again on every snapshot swap, both
    /// regardless of `lazy`. This flag marks such a forced run.
    initial: AtomicBool,
    /// Provider generation already probed by a `HealthTarget::Provider` task;
    /// a newer snapshot forces an immediate check.
    generation: AtomicU64,
}

enum HealthTarget {
    /// Inline members of one group (the pinned "compatible provider").
    Inline(usize),
    /// Every current snapshot proxy of one provider.
    Provider(String),
}

/// The group runtime of one kernel instance.
pub struct GroupRegistry {
    base_dir: PathBuf,
    inline: Vec<Arc<Proxy>>,
    inline_index: BTreeMap<String, usize>,
    providers: Arc<RuleProviders>,
    tls: Arc<ClientTls>,
    dial_timeout: Duration,
    groups: Vec<GroupRuntime>,
    index: BTreeMap<String, usize>,
    health: Mutex<BTreeMap<(MemberSource, String, String), HealthState>>,
    /// Pinned provider `Touch()` timestamps (one `lastTouch` per provider
    /// health check). Only provider-targeted lazy tasks consult them.
    provider_touched: Mutex<BTreeMap<String, Instant>>,
    tasks: Vec<HealthTask>,
    cache: Option<SelectionCache>,
    dials: AtomicU64,
}

impl std::fmt::Debug for GroupRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupRegistry")
            .field("groups", &self.groups.len())
            .field("tasks", &self.tasks.len())
            .field("cache", &self.cache.as_ref().map(|cache| cache.path.clone()))
            .finish()
    }
}

impl GroupRegistry {
    /// Build the runtime for `config`. `cache_path` enables
    /// `profile.store-selected` (the caller decides the location; the kernel
    /// uses the configuration directory).
    pub fn new(
        config: &Config,
        providers: Arc<RuleProviders>,
        tls: Arc<ClientTls>,
        dial_timeout: Duration,
        base_dir: PathBuf,
        cache_path: Option<PathBuf>,
    ) -> Result<Arc<Self>, ConfigError> {
        let inline = config.proxies.iter().cloned().map(Arc::new).collect::<Vec<_>>();
        let mut inline_index = BTreeMap::new();
        for (index, proxy) in inline.iter().enumerate() {
            inline_index.insert(proxy.name.clone(), index);
        }
        let groups = config
            .proxy_groups
            .iter()
            .cloned()
            .map(GroupRuntime::new)
            .collect::<Vec<_>>();
        let mut index = BTreeMap::new();
        for (position, group) in groups.iter().enumerate() {
            index.insert(group.def.name.clone(), position);
        }
        // Every provider proxy reachable through `use` must have its
        // `dialer-proxy` (set by the provider or its override) resolved here:
        // the pinned engine accepts a group name there, which this kernel does
        // not implement. Rejecting at load keeps it from silently dialing
        // directly at runtime.
        for provider in &config.proxy_providers {
            let Some(slot) = providers.proxy_provider(&provider.name) else {
                continue;
            };
            for proxy in &slot.snapshot().proxies {
                let Some(target) = proxy.dialer_proxy() else {
                    continue;
                };
                if target.is_empty() || config.proxies.iter().any(|inline| inline.name == target) {
                    continue;
                }
                return Err(ConfigError::Unsupported(format!(
                    "proxy-provider '{}' proxy '{}': dialer-proxy '{target}' is not an inline proxy (a group or provider proxy as a dialer target is not implemented)",
                    provider.name, proxy.name
                )));
            }
        }
        let cache = if config.profile.store_selected {
            cache_path.map(SelectionCache::load)
        } else {
            None
        };

        let mut registry = GroupRegistry {
            base_dir,
            inline,
            inline_index,
            providers,
            tls,
            dial_timeout,
            groups,
            index,
            health: Mutex::new(BTreeMap::new()),
            provider_touched: Mutex::new(BTreeMap::new()),
            tasks: Vec::new(),
            cache,
            dials: AtomicU64::new(0),
        };

        // A cached selection wins over `default-selected` (`ForceSet` in the
        // pinned `patchSelectGroup`); `default-selected` only exists for
        // `select` groups (the pinned SelectorOption).
        for position in 0..registry.groups.len() {
            let def = &registry.groups[position].def;
            let name = def.name.clone();
            let default = if def.kind == GroupKind::Select {
                def.default_selected.clone()
            } else {
                None
            };
            let cached = registry.cache.as_ref().and_then(|cache| cache.get(&name));
            let mut state = registry.groups[position]
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.selected = cached.or(default);
        }

        // Validate member references and build the initial caches so a broken
        // nested reference fails at start, not on the first packet.
        for position in 0..registry.groups.len() {
            registry.members(position);
        }
        registry.tasks = registry.build_tasks()?;
        Ok(Arc::new(registry))
    }

    pub fn group_defs(&self) -> Vec<&ProxyGroup> {
        self.groups.iter().map(|group| &group.def).collect()
    }

    pub fn group_names(&self) -> Vec<&str> {
        self.groups
            .iter()
            .map(|group| group.def.name.as_str())
            .collect()
    }

    pub fn group_index(&self, name: &str) -> Option<usize> {
        self.index.get(name).copied()
    }

    pub fn group(&self, name: &str) -> Option<&ProxyGroup> {
        self.index.get(name).map(|position| &self.groups[*position].def)
    }

    /// Member names in pinned `all` order.
    pub fn members(&self, position: usize) -> Vec<Member> {
        let runtime = &self.groups[position];
        let versions = self.member_versions(&runtime.def);
        {
            let cache = runtime
                .members
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if cache.versions == versions && !cache.members.is_empty() {
                return cache.members.clone();
            }
        }
        let members = self.expand_members(runtime);
        let mut cache = runtime
            .members
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.versions = versions;
        cache.members = members.clone();
        members
    }

    /// The group's inline (compatible-provider) members only. Pinned creates
    /// a group `HealthCheck` with the `proxies` list, never with the expanded
    /// `use` provider members.
    fn inline_members(&self, position: usize) -> Vec<Member> {
        self.groups[position]
            .def
            .proxies
            .iter()
            .map(|name| Member {
                name: name.clone(),
                source: MemberSource::Inline,
                reference: self.resolve_inline_name(name),
            })
            .collect()
    }

    fn member_versions(&self, def: &ProxyGroup) -> Vec<u64> {
        let mut versions = Vec::with_capacity(def.use_providers.len());
        for name in &def.use_providers {
            versions.push(
                self.providers
                    .proxy_provider(name)
                    .map(|slot| slot.snapshot().generation)
                    .unwrap_or(0),
            );
        }
        versions
    }

    fn resolve_inline_name(&self, name: &str) -> MemberRef {
        match name {
            "COMPATIBLE" | "DIRECT" => MemberRef::Builtin(Builtin::Direct),
            "REJECT" => MemberRef::Builtin(Builtin::Reject),
            "REJECT-DROP" => MemberRef::Builtin(Builtin::RejectDrop),
            other => match self.inline_index.get(other) {
                Some(index) => MemberRef::Proxy(self.inline[*index].clone()),
                None => match self.index.get(other) {
                    Some(position) => MemberRef::Group(*position),
                    // Validated at load; an unknown name here means the
                    // configuration was built by hand.
                    None => MemberRef::Builtin(Builtin::Reject),
                },
            },
        }
    }

    fn expand_members(&self, runtime: &GroupRuntime) -> Vec<Member> {
        let def = &runtime.def;
        let mut blocks: Vec<(bool, Vec<Member>)> = Vec::new();
        if !def.proxies.is_empty() {
            let members = def
                .proxies
                .iter()
                .map(|name| Member {
                    name: name.clone(),
                    source: MemberSource::Inline,
                    reference: self.resolve_inline_name(name),
                })
                .collect();
            blocks.push((true, members));
        }
        for provider_name in &def.use_providers {
            let mut members = Vec::new();
            if let Some(slot) = self.providers.proxy_provider(provider_name) {
                let snapshot = slot.snapshot();
                for proxy in &snapshot.proxies {
                    members.push(Member {
                        name: proxy.name.clone(),
                        source: MemberSource::Provider(provider_name.clone()),
                        reference: MemberRef::Proxy(Arc::new(proxy.clone())),
                    });
                }
            }
            blocks.push((false, members));
        }

        let mut proxies: Vec<Member> = Vec::new();
        if runtime.filter.is_empty() {
            for (_, members) in &blocks {
                proxies.extend(members.iter().cloned());
            }
        } else {
            for (compatible, members) in &blocks {
                if *compatible {
                    proxies.extend(members.iter().cloned());
                    continue;
                }
                let mut seen = BTreeSet::new();
                for regex in &runtime.filter {
                    for member in members {
                        if regex.is_match(&member.name) && seen.insert(member.name.clone()) {
                            proxies.push(member.clone());
                        }
                    }
                }
            }
        }

        // Multiple providers and filters: order the combined list by filter,
        // then append the unmatched rest (pinned `GroupBase.GetProxies`).
        if blocks.len() > 1 && runtime.filter.len() > 1 {
            let mut seen = BTreeSet::new();
            let mut reordered = Vec::new();
            for regex in &runtime.filter {
                for member in &proxies {
                    if regex.is_match(&member.name) && seen.insert(member.name.clone()) {
                        reordered.push(member.clone());
                    }
                }
            }
            for member in &proxies {
                if seen.insert(member.name.clone()) {
                    reordered.push(member.clone());
                }
            }
            proxies = reordered;
        }

        if !runtime.exclude_filter.is_empty() {
            proxies.retain(|member| {
                !runtime
                    .exclude_filter
                    .iter()
                    .any(|regex| regex.is_match(&member.name))
            });
        }
        if !def.exclude_type.is_empty() {
            proxies.retain(|member| {
                let kind = self.member_type_name(&member.reference);
                !def.exclude_type
                    .iter()
                    .any(|exclude| exclude.eq_ignore_ascii_case(kind))
            });
        }

        if proxies.is_empty() {
            proxies.push(self.empty_fallback(&def.empty_fallback));
        }
        proxies
    }

    fn member_type_name(&self, reference: &MemberRef) -> &'static str {
        match reference {
            MemberRef::Proxy(proxy) => proxy.adapter_type_name(),
            MemberRef::Group(position) => match self.groups[*position].def.kind {
                GroupKind::Select => "Selector",
                GroupKind::UrlTest => "URLTest",
                GroupKind::Fallback => "Fallback",
                GroupKind::LoadBalance => "LoadBalance",
            },
            MemberRef::Builtin(Builtin::Direct) => "Compatible",
            MemberRef::Builtin(Builtin::Reject) => "Reject",
            MemberRef::Builtin(Builtin::RejectDrop) => "RejectDrop",
        }
    }

    fn empty_fallback(&self, fallback: &EmptyFallback) -> Member {
        match fallback {
            EmptyFallback::Compatible => Member {
                name: "COMPATIBLE".to_string(),
                source: MemberSource::EmptyFallback,
                reference: MemberRef::Builtin(Builtin::Direct),
            },
            EmptyFallback::Direct => Member {
                name: "DIRECT".to_string(),
                source: MemberSource::EmptyFallback,
                reference: MemberRef::Builtin(Builtin::Direct),
            },
            EmptyFallback::Reject => Member {
                name: "REJECT".to_string(),
                source: MemberSource::EmptyFallback,
                reference: MemberRef::Builtin(Builtin::Reject),
            },
            EmptyFallback::RejectDrop => Member {
                name: "REJECT-DROP".to_string(),
                source: MemberSource::EmptyFallback,
                reference: MemberRef::Builtin(Builtin::RejectDrop),
            },
            EmptyFallback::Proxy(index) => {
                let proxy = self.inline[*index].clone();
                Member {
                    name: proxy.name.clone(),
                    source: MemberSource::EmptyFallback,
                    reference: MemberRef::Proxy(proxy),
                }
            }
        }
    }

    fn health_key(&self, member: &Member, url: &str) -> (MemberSource, String, String) {
        (member.source.clone(), member.name.clone(), url.to_string())
    }

    fn health_state(&self, member: &Member, url: &str) -> Option<HealthState> {
        self.health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&self.health_key(member, url))
            .cloned()
    }

    fn record_health(&self, member: &Member, url: &str, alive: bool, delay: u16) {
        self.health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                self.health_key(member, url),
                HealthState { alive, delay },
            );
    }

    /// Pinned `AliveForTestUrl`: a URL with no record yet falls back to the
    /// adapter's initial `alive = true`.
    fn alive_for(&self, member: &Member, url: &str) -> bool {
        self.health_state(member, url)
            .map(|state| state.alive)
            .unwrap_or(true)
    }

    /// Pinned `LastDelayForTestUrl`: `0xffff` unless the last probe succeeded
    /// with a non-zero delay.
    fn last_delay_for(&self, member: &Member, url: &str) -> u16 {
        match self.health_state(member, url) {
            Some(state) if state.alive && state.delay != 0 => state.delay,
            _ => UNKNOWN_DELAY,
        }
    }

    fn status_member(&self, member: &Member, url: &str) -> MemberHealth {
        let state = self.health_state(member, url);
        MemberHealth {
            name: member.name.clone(),
            alive: state.as_ref().map(|state| state.alive).unwrap_or(true),
            delay: state
                .as_ref()
                .filter(|state| state.alive && state.delay != 0)
                .map(|state| state.delay),
        }
    }

    fn now(&self, position: usize) -> Option<Member> {
        let runtime = &self.groups[position];
        let members = self.members(position);
        match runtime.def.kind {
            GroupKind::Select => self.select_member(runtime, &members),
            GroupKind::UrlTest => self.fast_member(position, &members),
            GroupKind::Fallback => self.fallback_member(runtime, &members),
            GroupKind::LoadBalance => None,
        }
    }

    fn select_member(&self, runtime: &GroupRuntime, members: &[Member]) -> Option<Member> {
        let state = runtime
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let wanted = state
            .selected
            .as_deref()
            .or(runtime.def.default_selected.as_deref());
        if let Some(wanted) = wanted {
            if let Some(member) = members.iter().find(|member| member.name == wanted) {
                return Some(member.clone());
            }
        }
        members.first().cloned()
    }

    fn fast_member(&self, position: usize, members: &[Member]) -> Option<Member> {
        let runtime = &self.groups[position];
        let def = &runtime.def;
        let mut state = runtime
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // A fixed selection wins while it is alive.
        if let Some(selected) = state.selected.clone() {
            if let Some(member) = members
                .iter()
                .find(|member| member.name == selected && self.alive_for(member, &def.url))
            {
                state.fast_node = Some(member.name.clone());
                return Some(member.clone());
            }
        }
        let first = members.first()?;
        let mut fast = first.clone();
        let mut min_delay = self.last_delay_for(first, &def.url);
        let mut fast_not_exist = state.fast_node.is_none();
        for member in &members[1..] {
            if state
                .fast_node
                .as_deref()
                .is_some_and(|node| node == member.name)
            {
                fast_not_exist = false;
            }
            if !self.alive_for(member, &def.url) {
                continue;
            }
            let delay = self.last_delay_for(member, &def.url);
            if delay < min_delay {
                fast = member.clone();
                min_delay = delay;
            }
        }
        let replace = match state.fast_node.as_deref() {
            None => true,
            Some(node) => {
                let previous = members.iter().find(|member| member.name == node);
                match previous {
                    None => true,
                    Some(previous) => {
                        fast_not_exist
                            || !self.alive_for(previous, &def.url)
                            || u32::from(self.last_delay_for(previous, &def.url))
                                > u32::from(self.last_delay_for(&fast, &def.url))
                                    + u32::from(def.tolerance)
                    }
                }
            }
        };
        if replace {
            state.fast_node = Some(fast.name.clone());
        }
        let node = state.fast_node.clone().unwrap_or_else(|| fast.name.clone());
        members
            .iter()
            .find(|member| member.name == node)
            .cloned()
            .or(Some(fast))
    }

    fn fallback_member(&self, runtime: &GroupRuntime, members: &[Member]) -> Option<Member> {
        let def = &runtime.def;
        let mut state = runtime
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut selected = state.selected.clone();
        for member in members {
            match &selected {
                None => {
                    if self.alive_for(member, &def.url) {
                        return Some(member.clone());
                    }
                }
                Some(name) if *name == member.name => {
                    if self.alive_for(member, &def.url) {
                        return Some(member.clone());
                    }
                    // Pinned clears the fixed choice when it died and keeps
                    // scanning the remaining members.
                    state.selected = None;
                    selected = None;
                }
                Some(_) => {}
            }
        }
        members.first().cloned()
    }

    fn load_balance_member(
        &self,
        position: usize,
        members: &[Member],
        target: &crate::rules::Target,
        touch: bool,
    ) -> Option<Member> {
        let runtime = &self.groups[position];
        let def = &runtime.def;
        if members.is_empty() {
            return None;
        }
        let mut state = runtime
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match def.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let length = members.len();
                let mut index = state.round_robin % length;
                let start = index;
                for _ in 0..length {
                    let member = &members[index];
                    if self.alive_for(member, &def.url) {
                        if touch {
                            state.round_robin = (index + 1) % length;
                        }
                        return Some(member.clone());
                    }
                    index = (index + 1) % length;
                }
                state.round_robin = (start + 1) % length;
                members.first().cloned()
            }
            LoadBalanceStrategy::ConsistentHashing => {
                let key = map_hash(&hash_key(target, def.hash_key));
                let buckets = members.len() as i64;
                for retry in 0..5 {
                    let index = jump_hash(key.wrapping_add(retry), buckets) as usize;
                    let member = &members[index];
                    if self.alive_for(member, &def.url) {
                        return Some(member.clone());
                    }
                }
                for member in members {
                    if self.alive_for(member, &def.url) {
                        return Some(member.clone());
                    }
                }
                members.first().cloned()
            }
            LoadBalanceStrategy::StickySessions => {
                let key = map_hash(&sticky_key(target));
                let length = members.len();
                let ttl = Duration::from_secs(600);
                let now = Instant::now();
                state.sticky.retain(|_, (_, at)| now.duration_since(*at) < ttl);
                while state.sticky.len() > 1000 {
                    let Some(oldest) = state
                        .sticky
                        .iter()
                        .min_by_key(|(_, (_, at))| *at)
                        .map(|(key, _)| *key)
                    else {
                        break;
                    };
                    state.sticky.remove(&oldest);
                }
                let (mut index, cached) = match state.sticky.get(&key) {
                    Some((index, _)) if *index < length => (*index, true),
                    _ => (jump_hash(key.wrapping_add(now.elapsed().as_nanos() as u64), length as i64) as usize, false),
                };
                for _ in 1..5 {
                    let member = &members[index];
                    if self.alive_for(member, &def.url) {
                        if !cached {
                            state.sticky.insert(key, (index, now));
                        }
                        return Some(member.clone());
                    }
                    index = jump_hash(
                        key.wrapping_add(now.elapsed().as_nanos() as u64),
                        length as i64,
                    ) as usize;
                }
                state.sticky.entry(key).or_insert((0, now));
                members.first().cloned()
            }
        }
    }

    /// Resolve one rule action to a leaf outbound for a real dial. `touch`
    /// updates the health-check idle timer (pinned `GetProxies(true)`).
    pub fn resolve_action(
        &self,
        action: Action,
        target: &crate::rules::Target,
        touch: bool,
    ) -> Result<Selected, GroupError> {
        match action {
            Action::Direct => Ok(Selected::Direct),
            Action::Reject => Ok(Selected::Reject),
            Action::RejectDrop => Ok(Selected::RejectDrop),
            Action::Proxy(index) => self
                .inline
                .get(index)
                .map(|proxy| Selected::Proxy {
                    proxy: proxy.clone(),
                    path: Vec::new(),
                })
                .ok_or_else(|| {
                    GroupError::NotDialable(
                        "<rule>".to_string(),
                        format!("proxies[{index}]"),
                        "the configured proxy index is stale".to_string(),
                    )
                }),
            Action::Group(index) => {
                if touch {
                    self.dials.fetch_add(1, Ordering::Relaxed);
                }
                self.resolve_group(index, target, &mut Vec::new(), touch)
            }
        }
    }

    fn resolve_group(
        &self,
        position: usize,
        target: &crate::rules::Target,
        visiting: &mut Vec<usize>,
        touch: bool,
    ) -> Result<Selected, GroupError> {
        if visiting.contains(&position) {
            return Err(GroupError::UnknownGroup(format!(
                "circular proxy group reference at '{}'",
                self.groups[position].def.name
            )));
        }
        // Pinned `GetProxies(true)` touches every provider of the group on a
        // real dial; a nested group is reached through its own `DialContext`,
        // which touches the nested group's providers as well.
        if touch {
            self.touch_group(position);
        }
        visiting.push(position);
        let def = &self.groups[position];
        let members = self.members(position);
        let member = match def.def.kind {
            GroupKind::Select => self.select_member(def, &members),
            GroupKind::UrlTest => self.fast_member(position, &members),
            GroupKind::Fallback => self.fallback_member(def, &members),
            GroupKind::LoadBalance => self.load_balance_member(position, &members, target, true),
        };
        let Some(member) = member else {
            return Err(GroupError::Empty(def.def.name.clone()));
        };
        match &member.reference {
            MemberRef::Builtin(Builtin::Direct) => Ok(Selected::Direct),
            MemberRef::Builtin(Builtin::Reject) => Ok(Selected::Reject),
            MemberRef::Builtin(Builtin::RejectDrop) => Ok(Selected::RejectDrop),
            MemberRef::Group(inner) => {
                let mut selected = self.resolve_group(*inner, target, visiting, touch)?;
                if let Selected::Proxy { path, .. } = &mut selected {
                    path.insert(0, def.def.name.clone());
                }
                Ok(selected)
            }
            MemberRef::Proxy(proxy) => Ok(Selected::Proxy {
                proxy: proxy.clone(),
                path: vec![def.def.name.clone()],
            }),
        }
    }

    /// Pinned `GroupBase.Touch()`: touch every provider attached to the group.
    /// The inline block is the group's own compatible provider, so its
    /// `lastTouch` is the group timestamp; every `use` provider gets its own.
    fn touch_group(&self, position: usize) {
        let now = Instant::now();
        *self.groups[position]
            .touched
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(now);
        let mut touched = self
            .provider_touched
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for provider in &self.groups[position].def.use_providers {
            touched.insert(provider.clone(), now);
        }
    }

    /// The `dialer-proxy` chain of `proxy`, starting with the proxy itself.
    /// The loader accepts only inline proxy names as a dialer target, so the
    /// inline index is the complete graph (the engine's `chain_for` walks the
    /// same list).
    fn proxy_chain(&self, proxy: &Arc<Proxy>) -> Vec<Arc<Proxy>> {
        let mut hops = vec![proxy.clone()];
        let mut current = proxy.dialer_proxy().map(str::to_string);
        while let Some(name) = current {
            let Some(index) = self.inline_index.get(&name).copied() else {
                break;
            };
            let next = self.inline[index].clone();
            let following = next.dialer_proxy().map(str::to_string);
            hops.push(next);
            current = following;
        }
        hops
    }

    /// Group status list for hosts (T25 builds `/proxies` from this).
    pub fn snapshot(&self) -> Vec<GroupStatus> {
        self.groups
            .iter()
            .enumerate()
            .map(|(position, runtime)| self.status(position, runtime))
            .collect()
    }

    pub fn group_status(&self, name: &str) -> Option<GroupStatus> {
        self.index
            .get(name)
            .map(|position| self.status(*position, &self.groups[*position]))
    }

    fn status(&self, position: usize, runtime: &GroupRuntime) -> GroupStatus {
        let members = self.members(position);
        let now = self
            .now(position)
            .map(|member| member.name)
            .unwrap_or_default();
        let state = runtime
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fixed = state.selected.clone();
        GroupStatus {
            name: runtime.def.name.clone(),
            kind: runtime.def.kind.as_str(),
            now,
            all: members.iter().map(|member| member.name.clone()).collect(),
            fixed,
            default_selected: if runtime.def.kind == GroupKind::Select {
                runtime.def.default_selected.clone()
            } else {
                None
            },
            test_url: runtime.def.url.clone(),
            expected_status: runtime.def.expected_status.as_spec(),
            hidden: runtime.def.hidden,
            icon: runtime.def.icon.clone(),
            empty_fallback: match runtime.def.empty_fallback {
                EmptyFallback::Compatible => "COMPATIBLE".to_string(),
                EmptyFallback::Direct => "DIRECT".to_string(),
                EmptyFallback::Reject => "REJECT".to_string(),
                EmptyFallback::RejectDrop => "REJECT-DROP".to_string(),
                EmptyFallback::Proxy(index) => self.inline[index].name.clone(),
            },
            members: members
                .iter()
                .map(|member| self.status_member(member, &runtime.def.url))
                .collect(),
        }
    }

    /// Fix a group selection (pinned `Selector.Set`/`Fallback.Set`). `false`
    /// means the name is not a current member and nothing changed.
    pub fn select(&self, group: &str, member: &str) -> Result<bool, GroupError> {
        let position = *self
            .index
            .get(group)
            .ok_or_else(|| GroupError::UnknownGroup(group.to_string()))?;
        let runtime = &self.groups[position];
        if runtime.def.kind == GroupKind::LoadBalance {
            return Err(GroupError::UnknownMember(
                group.to_string(),
                "load-balance groups have no selection".to_string(),
            ));
        }
        let members = self.members(position);
        if !members.iter().any(|entry| entry.name == member) {
            return Err(GroupError::UnknownMember(
                group.to_string(),
                member.to_string(),
            ));
        }
        {
            let mut state = runtime
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.selected = Some(member.to_string());
            state.fast_node = None;
        }
        self.persist(group, Some(member));
        Ok(true)
    }

    fn persist(&self, group: &str, member: Option<&str>) {
        if let Some(cache) = &self.cache {
            if let Err(error) = cache.set(group, member) {
                tracing::warn!(
                    group,
                    path = %cache.path.display(),
                    "selection cache write failed: {error}"
                );
            }
        }
    }

    /// Record a dial failure and trigger a health check when the pinned
    /// `onDialFailed` thresholds are reached. Every group on the path is
    /// notified, like the nested adapter wrappers.
    pub fn note_dial_failure(self: &Arc<Self>, path: &[String], error: &str) {
        for name in path {
            let Some(position) = self.index.get(name).copied() else {
                continue;
            };
            self.note_group_failure(position, error);
        }
    }

    fn note_group_failure(self: &Arc<Self>, position: usize, error: &str) {
        let runtime = &self.groups[position];
        let test_timeout = Duration::from_millis(if runtime.def.timeout == 0 {
            DEFAULT_TIMEOUT_MS
        } else {
            runtime.def.timeout
        });
        let max_failed = if runtime.def.max_failed_times == 0 {
            DEFAULT_MAX_FAILED_TIMES
        } else {
            runtime.def.max_failed_times
        };
        let trigger = {
            let mut state = runtime
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if error.contains("connection refused") {
                true
            } else {
                let now = Instant::now();
                state.failed_times += 1;
                if state.failed_times == 1 {
                    state.failed_since = Some(now);
                    false
                } else if state
                    .failed_since
                    .is_some_and(|since| now.duration_since(since) > test_timeout)
                {
                    state.failed_times = 0;
                    false
                } else {
                    state.failed_times >= max_failed
                }
            }
        };
        if trigger {
            self.trigger_health_check(position);
        }
    }

    /// Reset the failure count after a successful dial (`onDialSuccess`).
    pub fn note_dial_success(&self, path: &[String]) {
        for name in path {
            let Some(position) = self.index.get(name).copied() else {
                continue;
            };
            let mut state = self.groups[position]
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.failed_times = 0;
        }
    }

    fn trigger_health_check(self: &Arc<Self>, position: usize) {
        {
            let mut state = self.groups[position]
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.testing {
                return;
            }
            state.testing = true;
        }
        let registry = self.clone();
        tokio::spawn(async move {
            let _ = registry.probe_group(position).await;
            let mut state = registry.groups[position]
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.testing = false;
            state.failed_times = 0;
        });
    }

    /// Probe every inline member of one group at the group URL once and update
    /// the health records. Returns the probe results.
    pub async fn probe_group(self: &Arc<Self>, position: usize) -> Vec<MemberHealth> {
        let runtime = &self.groups[position];
        let expected = runtime.def.expected_status.clone();
        let timeout = Duration::from_millis(if runtime.def.timeout == 0 {
            DEFAULT_TIMEOUT_MS
        } else {
            runtime.def.timeout
        });
        let members = self.members(position);
        let results = self
            .probe_members(members.clone(), runtime.def.url.clone(), expected, timeout, Vec::new())
            .await;
        results
    }

    /// Probe one group by name (used by the CLI diagnostic and T25).
    pub async fn probe_group_named(self: &Arc<Self>, name: &str) -> Option<Vec<MemberHealth>> {
        let position = *self.index.get(name)?;
        Some(self.probe_group(position).await)
    }

    /// Probe every group and every provider health task once.
    pub async fn probe_all(self: &Arc<Self>) -> usize {
        let mut probed = 0;
        for position in 0..self.groups.len() {
            probed += self.probe_group(position).await.len();
        }
        let provider_names = self.providers.proxy_provider_names();
        for name in provider_names {
            probed += self.probe_provider_task(&name).await.len();
        }
        probed
    }

    async fn probe_provider_task(self: &Arc<Self>, provider: &str) -> Vec<MemberHealth> {
        let Some(slot) = self.providers.proxy_provider(provider) else {
            return Vec::new();
        };
        let config = slot.config.health_check.clone();
        if !config.enable || config.url.as_deref().unwrap_or("").trim().is_empty() {
            return Vec::new();
        }
        let expected = ExpectedStatus::parse(&config.expected_status).unwrap_or_default();
        let timeout = Duration::from_millis(if config.timeout == 0 {
            DEFAULT_TIMEOUT_MS
        } else {
            config.timeout
        });
        let members = slot
            .snapshot()
            .proxies
            .iter()
            .map(|proxy| Member {
                name: proxy.name.clone(),
                source: MemberSource::Provider(provider.to_string()),
                reference: MemberRef::Proxy(Arc::new(proxy.clone())),
            })
            .collect::<Vec<_>>();
        self.probe_members(members, config.url.clone().unwrap_or_default(), expected, timeout, Vec::new())
            .await
    }

    async fn probe_members(
        self: &Arc<Self>,
        members: Vec<Member>,
        url: String,
        expected: ExpectedStatus,
        timeout: Duration,
        filter: Vec<Regex>,
    ) -> Vec<MemberHealth> {
        let mut results: Vec<(usize, MemberHealth)> = Vec::new();
        let mut iter = members
            .into_iter()
            .enumerate()
            .filter(|(_, member)| {
                filter.is_empty() || filter.iter().any(|regex| regex.is_match(&member.name))
            });
        let mut set: tokio::task::JoinSet<(usize, MemberSource, String, bool)> =
            tokio::task::JoinSet::new();
        loop {
            while set.len() < PROBE_LIMIT {
                let Some((index, member)) = iter.next() else {
                    break;
                };
                let registry = self.clone();
                let url = url.clone();
                let expected = expected.clone();
                set.spawn(async move {
                    let outcome = registry
                        .probe_one(&member, &url, &expected, timeout)
                        .await;
                    (index, member.source.clone(), member.name.clone(), outcome.0)
                });
            }
            match set.join_next().await {
                Some(Ok((index, source, name, alive))) => {
                    let member = Member {
                        name: name.clone(),
                        source,
                        reference: MemberRef::Builtin(Builtin::Direct),
                    };
                    // `probe_one` recorded the state on the real member; this
                    // is only the display copy.
                    let state = self.health_state(&member, &url);
                    results.push((
                        index,
                        MemberHealth {
                            name,
                            alive: state.as_ref().map(|state| state.alive).unwrap_or(alive),
                            delay: state
                                .as_ref()
                                .filter(|state| state.alive && state.delay != 0)
                                .map(|state| state.delay),
                        },
                    ));
                }
                Some(Err(error)) => {
                    tracing::warn!("health probe task failed: {error}");
                }
                None => break,
            }
        }
        results.sort_by_key(|(index, _)| *index);
        results.into_iter().map(|(_, health)| health).collect()
    }

    /// One probe: dial through `member` to `url` and issue `HEAD`.
    async fn probe_one(
        &self,
        member: &Member,
        url: &str,
        expected: &ExpectedStatus,
        timeout: Duration,
    ) -> (bool, u16) {
        let parsed = match ParsedUrl::parse(url) {
            Some(parsed) => parsed,
            None => {
                self.record_health(member, url, false, 0);
                return (false, 0);
            }
        };
        let dial_target = DialTarget {
            host: parsed.host.clone(),
            port: parsed.port,
        };
        let started = Instant::now();
        let result = tokio::time::timeout(timeout, async {
            let target = crate::rules::Target::new(&parsed.host, parsed.host.parse().ok())
                .with_port(parsed.port)
                .with_network(crate::config::NetworkKind::Tcp);
            let selected = match &member.reference {
                MemberRef::Builtin(Builtin::Direct) => Selected::Direct,
                MemberRef::Builtin(_) => return Err("reject member".to_string()),
                // Pinned `URLTest`/`GroupBase.URLTest` walks nested members
                // with `GetProxies(false)`: a probe must not refresh the lazy
                // touch state of the nested group.
                MemberRef::Group(position) => self
                    .resolve_group(*position, &target, &mut Vec::new(), false)
                    .map_err(|error| error.to_string())?,
                MemberRef::Proxy(proxy) => Selected::Proxy {
                    proxy: proxy.clone(),
                    path: Vec::new(),
                },
            };
            let stream: outbound::BoxStream = match selected {
                Selected::Direct => {
                    let stream = tokio::net::TcpStream::connect((
                        parsed.host.as_str(),
                        parsed.port,
                    ))
                    .await
                    .map_err(|e| e.to_string())?;
                    Box::new(stream)
                }
                Selected::Proxy { proxy, .. } => {
                    // Pinned `Proxy.URLTest` dials through the same adapter,
                    // whose `DialContext` applies the full `dialer-proxy`
                    // chain. Use the engine's chain resolution rather than a
                    // single hop so a probe is not bypassed around the hop.
                    let chain = self.proxy_chain(&proxy);
                    let hops = chain.iter().map(|hop| hop.as_ref()).collect::<Vec<_>>();
                    let dialed = outbound::dial_chain(
                        &hops,
                        &dial_target,
                        self.dial_timeout,
                        &self.tls,
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                    dialed.stream
                }
                Selected::Reject | Selected::RejectDrop => {
                    return Err("reject member".to_string())
                }
            };
            let request = if parsed.tls {
                let settings = TlsSettings {
                    sni: Some(parsed.host.clone()),
                    skip_cert_verify: false,
                    alpn: Vec::new(),
                };
                let mut stream = crate::outbound::tls::wrap_stream(stream, &parsed.host, &settings, &self.tls)
                    .await
                    .map_err(|e| e.to_string())?;
                write_head(&mut stream, &parsed).await?;
                read_status(&mut stream).await?
            } else {
                let mut stream = stream;
                write_head(&mut stream, &parsed).await?;
                read_status(&mut stream).await?
            };
            Ok::<u16, String>(request)
        })
        .await;
        let (alive, delay) = match result {
            Ok(Ok(status)) => {
                let delay = started.elapsed().as_millis().min(u128::from(u16::MAX)) as u16;
                (expected.check(status), delay.max(1))
            }
            _ => (false, 0),
        };
        self.record_health(member, url, alive, if alive { delay } else { 0 });
        tracing::debug!(
            member = %member.name,
            url,
            alive,
            delay,
            "group health probe"
        );
        (alive, delay)
    }

    fn build_tasks(&self) -> Result<Vec<HealthTask>, ConfigError> {
        let mut tasks = Vec::new();
        for (position, runtime) in self.groups.iter().enumerate() {
            let def = &runtime.def;
            // The group's own health check covers its inline members only.
            if !def.proxies.is_empty() && def.interval > 0 {
                tasks.push(HealthTask {
                    label: format!("group:{}", def.name),
                    url: def.url.clone(),
                    expected: def.expected_status.clone(),
                    timeout: Duration::from_millis(if def.timeout == 0 {
                        DEFAULT_TIMEOUT_MS
                    } else {
                        def.timeout
                    }),
                    interval: Duration::from_secs(def.interval),
                    lazy: def.lazy,
                    filter: Vec::new(),
                    targets: HealthTarget::Inline(position),
                    // Pinned `HealthCheck.process` starts with
                    // `go hc.check()` before its first interval tick.
                    next_due: Mutex::new(Instant::now()),
                    running: AtomicBool::new(false),
                    initial: AtomicBool::new(true),
                    generation: AtomicU64::new(0),
                });
            }
            // An explicit group URL registers an extra probe on `use` providers.
            let explicit_url = def.url_explicit && !def.use_providers.is_empty();
            if explicit_url {
                for provider in &def.use_providers {
                    // Pinned `registerHealthCheckTask`: an enabled provider
                    // health check keeps its own interval and ticker; only a
                    // provider without one borrows the group interval.
                    let provider_config = self
                        .providers
                        .proxy_provider(provider)
                        .map(|slot| slot.config.health_check.clone());
                    let provider_interval = provider_config
                        .as_ref()
                        .filter(|config| config.enable)
                        .map(|config| config.interval)
                        .unwrap_or(0);
                    let interval = if provider_interval > 0 {
                        provider_interval
                    } else {
                        def.interval
                    };
                    if interval == 0 {
                        continue;
                    }
                    // The extra URL lives inside the provider's own
                    // `HealthCheck`, so its `lazy` flag and `lastTouch` are the
                    // provider's, never the group's.
                    let lazy = provider_config
                        .as_ref()
                        .map(|config| config.lazy)
                        .unwrap_or(true);
                    let generation = self
                        .providers
                        .proxy_provider(provider)
                        .map(|slot| slot.snapshot().generation)
                        .unwrap_or(0);
                    tasks.push(HealthTask {
                        label: format!("group:{}->provider:{provider}", def.name),
                        url: def.url.clone(),
                        expected: def.expected_status.clone(),
                        timeout: Duration::from_millis(if def.timeout == 0 {
                            DEFAULT_TIMEOUT_MS
                        } else {
                            def.timeout
                        }),
                        interval: Duration::from_secs(interval),
                        lazy,
                        filter: runtime.filter.clone(),
                        targets: HealthTarget::Provider(provider.clone()),
                        next_due: Mutex::new(Instant::now()),
                        running: AtomicBool::new(false),
                        initial: AtomicBool::new(true),
                        generation: AtomicU64::new(generation),
                    });
                }
            }
        }
        for provider in &self.providers.proxy_provider_names() {
            let Some(slot) = self.providers.proxy_provider(provider) else {
                continue;
            };
            let config = slot.config.health_check.clone();
            if !config.enable || config.url.as_deref().unwrap_or("").trim().is_empty() {
                continue;
            }
            let expected = ExpectedStatus::parse(&config.expected_status)
                .map_err(|e| ConfigError::InvalidValue(format!("proxy-provider '{provider}': {e}")))?;
            let interval = if config.interval == 0 { 300 } else { config.interval };
            tasks.push(HealthTask {
                label: format!("provider:{provider}"),
                url: config.url.clone().unwrap_or_default(),
                expected,
                timeout: Duration::from_millis(if config.timeout == 0 {
                    DEFAULT_TIMEOUT_MS
                } else {
                    config.timeout
                }),
                interval: Duration::from_secs(interval),
                lazy: config.lazy,
                filter: Vec::new(),
                targets: HealthTarget::Provider(provider.to_string()),
                next_due: Mutex::new(Instant::now()),
                running: AtomicBool::new(false),
                initial: AtomicBool::new(true),
                generation: AtomicU64::new(slot.snapshot().generation),
            });
        }
        Ok(tasks)
    }

    /// Pinned `baseProvider.setProxies`: a snapshot swap triggers one check
    /// immediately, regardless of `lazy`. The scheduler wakes on its next tick
    /// (at most one second, and the initial probes are already spawned).
    pub fn note_provider_update(&self, provider: &str) {
        let generation = self
            .providers
            .proxy_provider(provider)
            .map(|slot| slot.snapshot().generation)
            .unwrap_or(0);
        for task in &self.tasks {
            if matches!(&task.targets, HealthTarget::Provider(name) if name == provider) {
                task.generation.store(generation, Ordering::Relaxed);
                task.initial.store(true, Ordering::SeqCst);
                *task
                    .next_due
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
            }
        }
    }

    /// Start the interval-driven health loop on the current Tokio runtime. It
    /// stops with the kernel's `stop` watch channel.
    pub fn spawn_scheduler(self: &Arc<Self>, mut stop: watch::Receiver<bool>) {
        if self.tasks.is_empty() {
            return;
        }
        let registry = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = ticker.tick() => {}
                }
                registry.scheduler_tick().await;
            }
        });
    }

    async fn scheduler_tick(self: &Arc<Self>) {
        let mut due = Vec::new();
        for (index, task) in self.tasks.iter().enumerate() {
            let now = Instant::now();
            // Pinned `setProxies` checks again on every provider snapshot
            // swap; a generation change is a forced (lazy-independent) run.
            if let HealthTarget::Provider(name) = &task.targets {
                let current = self
                    .providers
                    .proxy_provider(name)
                    .map(|slot| slot.snapshot().generation)
                    .unwrap_or(0);
                if current != task.generation.load(Ordering::Relaxed) {
                    task.generation.store(current, Ordering::Relaxed);
                    task.initial.store(true, Ordering::SeqCst);
                }
            }
            let forced = task.initial.load(Ordering::SeqCst);
            let ready = {
                let mut next = task
                    .next_due
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if !forced && now < *next {
                    false
                } else {
                    // Pinned creates one ticker per interval; a skipped lazy
                    // tick waits for the next interval boundary.
                    *next = now + task.interval;
                    true
                }
            };
            if !ready {
                continue;
            }
            if task.running.swap(true, Ordering::SeqCst) {
                // A forced snapshot check arriving while the task runs stays
                // pending for the next tick (pinned `singleDo` shares the run
                // but the new snapshot is picked up by the next check).
                continue;
            }
            if forced {
                task.initial.store(false, Ordering::SeqCst);
            } else if task.lazy {
                // Pinned `HealthCheck.process` reads the task's own
                // `lastTouch`: the group timestamp for a compatible provider,
                // the provider timestamp for a provider health check.
                let touched = match &task.targets {
                    HealthTarget::Inline(position) => *self.groups[*position]
                        .touched
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()),
                    HealthTarget::Provider(name) => self
                        .provider_touched
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .get(name)
                        .copied(),
                };
                let skip = match touched {
                    None => true,
                    Some(at) => now.duration_since(at) >= task.interval,
                };
                if skip {
                    task.running.store(false, Ordering::SeqCst);
                    continue;
                }
            }
            due.push(index);
        }
        // Pinned runs each `HealthCheck.check()` as its own goroutine and
        // `setProxies` starts one per swap; do not serialise slow probes or
        // stall the one-second scheduler tick on a distant timeout.
        for index in due {
            let registry = self.clone();
            tokio::spawn(async move {
                registry.run_task(index).await;
            });
        }
    }

    async fn run_task(self: &Arc<Self>, index: usize) {
        let task = &self.tasks[index];
        let members = match &task.targets {
            HealthTarget::Inline(position) => self.inline_members(*position),
            HealthTarget::Provider(name) => match self.providers.proxy_provider(name) {
                Some(slot) => slot
                    .snapshot()
                    .proxies
                    .iter()
                    .map(|proxy| Member {
                        name: proxy.name.clone(),
                        source: MemberSource::Provider(name.clone()),
                        reference: MemberRef::Proxy(Arc::new(proxy.clone())),
                    })
                    .collect(),
                None => Vec::new(),
            },
        };
        tracing::debug!(
            task = %task.label,
            url = %task.url,
            members = members.len(),
            "group health check"
        );
        let _ = self
            .probe_members(
                members,
                task.url.clone(),
                task.expected.clone(),
                task.timeout,
                task.filter.clone(),
            )
            .await;
        task.running.store(false, Ordering::SeqCst);
    }

    /// Whether any group on `path` sets `disable-udp` (pinned `SupportUDP()`
    /// returns false for the group and the datagram is dropped).
    pub fn path_disables_udp(&self, path: &[String]) -> bool {
        path.iter().any(|name| {
            self.index
                .get(name)
                .map(|position| self.groups[*position].def.disable_udp)
                .unwrap_or(false)
        })
    }

    /// Selection cache path, for hosts that display it.
    pub fn cache_path(&self) -> Option<&Path> {
        self.cache.as_ref().map(|cache| cache.path.as_path())
    }

    /// Number of real outbound dials that resolved through a group.
    pub fn dial_count(&self) -> u64 {
        self.dials.load(Ordering::Relaxed)
    }

    /// Base directory of this instance (provider paths); kept for diagnostics.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}

struct ParsedUrl {
    tls: bool,
    host: String,
    port: u16,
    path: String,
}

impl ParsedUrl {
    fn parse(url: &str) -> Option<ParsedUrl> {
        let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            return None;
        };
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return None;
        }
        let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
            let end = stripped.find(']')?;
            let host = stripped[..end].to_string();
            let port = stripped[end + 1..]
                .strip_prefix(':')
                .and_then(|port| port.parse().ok())
                .unwrap_or(if tls { 443 } else { 80 });
            (host, port)
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => {
                    (host.to_string(), port.parse().ok()?)
                }
                _ => (authority.to_string(), if tls { 443 } else { 80 }),
            }
        };
        Some(ParsedUrl {
            tls,
            host,
            port,
            path: path.to_string(),
        })
    }
}

async fn write_head<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    url: &ParsedUrl,
) -> Result<(), String> {
    let host = if url.port == 80 || url.port == 443 {
        url.host.clone()
    } else {
        format!("{}:{}", url.host, url.port)
    };
    let request = format!(
        "HEAD {} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: billow-kernel-health\r\n\r\n",
        url.path
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())
}

async fn read_status<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<u16, String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n") {
        if head.len() > 4096 {
            return Err("status line too long".to_string());
        }
        match stream.read(&mut byte).await {
            Ok(0) => break,
            Ok(_) => head.push(byte[0]),
            Err(error) => return Err(error.to_string()),
        }
    }
    let text = String::from_utf8_lossy(&head);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("malformed status line: {text:?}"))?;
    Ok(status)
}

/// The `load-balance` key for consistent hashing: the destination host's
/// effective second-level domain when it is a name, or the IP itself.
fn hash_key(target: &crate::rules::Target, key: HashKey) -> String {
    // `hash-key: in-user` is rejected at load; `Default` is the only variant.
    let _ = key;
    host_key(target)
}

fn host_key(target: &crate::rules::Target) -> String {
    if !target.host.is_empty() {
        if target.host.parse::<IpAddr>().is_ok() {
            return target.host.clone();
        }
        // No public-suffix list in this kernel: the last two labels are the
        // documented approximation of pinned `EffectiveTLDPlusOne`.
        let labels = target.host.split('.').collect::<Vec<_>>();
        if labels.len() >= 2 {
            return labels[labels.len() - 2..].join(".");
        }
        return target.host.clone();
    }
    target
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_default()
}

fn sticky_key(target: &crate::rules::Target) -> String {
    format!(
        "{}{}",
        target
            .source_ip
            .map(|ip| ip.to_string())
            .unwrap_or_default(),
        host_key(target)
    )
}

/// FNV-1a 64: deterministic across processes (pinned `utils.MapHash` uses a
/// per-process random seed, so its bucket assignment is not byte-comparable).
fn map_hash(material: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in material.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Pinned `jumpHash` (used by consistent-hashing and sticky-sessions).
fn jump_hash(key: u64, buckets: i64) -> i64 {
    let mut key = key;
    let mut b: i64 = -1;
    let mut j: i64 = 0;
    while j < buckets {
        b = j;
        key = key.wrapping_mul(2_862_933_555_777_941_757).wrapping_add(1);
        j = ((b + 1) as f64 * ((1u64 << 31) as f64 / ((key >> 33) + 1) as f64)) as i64;
    }
    b
}
