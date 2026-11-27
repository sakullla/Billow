//! Rule and proxy providers: vehicles (`file`, `http`, `inline`), payload
//! formats (`yaml`, `text`, `mrs`), proxy filters and atomic generation swaps.
//!
//! The network-facing half lives here too because a provider is read once at
//! start and again on update. Fetching is deliberately synchronous (a plain
//! TCP/TLS HTTP/1.1 GET) so a host can load a configuration from any thread,
//! including inside an existing Tokio runtime. A failed update leaves the old
//! snapshot in place; a successful update swaps the `Arc`, so sessions that
//! already evaluated a rule keep the generation they used until they finish.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use crate::config::{
    Config, ConfigError, GeodataRequirements, ProviderVehicle, ProxyOverride,
    ProxyProviderConfig, RuleBehavior, RuleFormat, RuleProviderConfig,
};
use crate::domain_index::{self, IndexedDomains};
use crate::geodata::{decode_mrs, GeoIpSource, Geodata};
use crate::outbound::tls::{self, ClientTls};
use crate::proxies::{parse_proxies, Proxy};
use crate::rules::{compile_provider_payload, CompiledRuleSet, RuleProviderSlot, RuleProviderSnapshot};

/// Provider payload before it is compiled into matchers.
#[derive(Debug, Clone)]
pub struct ProviderPayload {
    pub entries: Vec<String>,
    pub format: RuleFormat,
    pub vehicle: &'static str,
    pub(crate) indexed: Option<IndexedProvider>,
}

#[derive(Debug, Clone)]
pub(crate) struct IndexedProvider {
    pub domains: Arc<IndexedDomains>,
    pub other_positions: Arc<[u64]>,
    pub count: usize,
}

#[derive(Debug, Clone)]
pub struct ProviderUpdate {
    pub name: String,
    pub generation: u64,
    pub entries: usize,
    pub vehicle: &'static str,
    pub updated_at: SystemTime,
}

/// A proxy provider snapshot. Group selection/latency belongs to T23; this
/// snapshot only carries the parsed proxies and their generation.
#[derive(Debug)]
pub struct ProxyProviderSnapshot {
    pub generation: u64,
    pub proxies: Vec<Proxy>,
    pub updated_at: SystemTime,
}

#[derive(Debug)]
pub struct ProxyProviderSlot {
    pub name: String,
    pub config: ProxyProviderConfig,
    state: RwLock<Arc<ProxyProviderSnapshot>>,
}

impl ProxyProviderSlot {
    fn new(name: String, config: ProxyProviderConfig, snapshot: ProxyProviderSnapshot) -> Arc<Self> {
        Arc::new(ProxyProviderSlot {
            name,
            config,
            state: RwLock::new(Arc::new(snapshot)),
        })
    }

    pub fn snapshot(&self) -> Arc<ProxyProviderSnapshot> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Swaps in a new snapshot and returns the generation it was stamped with.
    /// The `+1` happens under the write lock: two concurrent updates must not
    /// both derive the same generation from the same old snapshot.
    fn replace_next(&self, mut snapshot: ProxyProviderSnapshot) -> u64 {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let generation = state.generation + 1;
        snapshot.generation = generation;
        *state = Arc::new(snapshot);
        generation
    }
}

/// The provider registry of one kernel instance.
#[derive(Debug)]
pub struct RuleProviders {
    geodata: Arc<Geodata>,
    base_dir: PathBuf,
    tls: Arc<ClientTls>,
    slots: BTreeMap<String, Arc<RuleProviderSlot>>,
    proxy_slots: BTreeMap<String, Arc<ProxyProviderSlot>>,
}

impl RuleProviders {
    pub fn geodata(&self) -> Arc<Geodata> {
        self.geodata.clone()
    }

    pub fn slots(&self) -> BTreeMap<String, Arc<RuleProviderSlot>> {
        self.slots.clone()
    }

    pub fn rule_provider_count(&self) -> usize {
        self.slots.len()
    }

    pub fn rule_provider(&self, name: &str) -> Option<&Arc<RuleProviderSlot>> {
        self.slots.get(name)
    }

    pub fn rule_provider_names(&self) -> Vec<&str> {
        self.slots.keys().map(String::as_str).collect()
    }

    pub fn proxy_provider(&self, name: &str) -> Option<&Arc<ProxyProviderSlot>> {
        self.proxy_slots.get(name)
    }

    pub fn proxy_provider_names(&self) -> Vec<&str> {
        self.proxy_slots.keys().map(String::as_str).collect()
    }

    /// Re-read one rule provider and swap its snapshot. The old generation is
    /// dropped when the last `Arc` (a session evaluation) releases it.
    pub fn update_rule_provider(&self, name: &str) -> Result<ProviderUpdate, ConfigError> {
        let slot = self.slots.get(name).ok_or_else(|| {
            ConfigError::InvalidValue(format!("unknown rule-provider '{name}'"))
        })?;
        if matches!(slot.config.vehicle, ProviderVehicle::Inline) {
            // Mihomo's inline provider `Update` only refreshes the timestamp.
            let current = slot.snapshot();
            return Ok(ProviderUpdate {
                name: name.to_string(),
                generation: current.generation,
                entries: current.compiled.count,
                vehicle: "inline",
                updated_at: SystemTime::now(),
            });
        }
        let payload = read_rule_payload(
            &slot.config,
            &self.base_dir,
            &self.tls,
            &mut Vec::new(),
            false,
        )?;
        let compiled = compile_provider_payload(
            name,
            slot.config.behavior,
            &payload,
            &self.geodata,
            &self.slots,
        )?;
        let entries = payload.indexed.as_ref().map_or(payload.entries.len(), |index| index.count);
        let vehicle = payload.vehicle;
        let updated_at = SystemTime::now();
        let generation = slot.replace_next(RuleProviderSnapshot {
            generation: 0,
            payload,
            compiled: Arc::new(compiled),
            updated_at,
        });
        Ok(ProviderUpdate {
            name: name.to_string(),
            generation,
            entries,
            vehicle,
            updated_at,
        })
    }

    /// Re-read every non-inline rule provider. The first failure is returned
    /// after the providers before it have already swapped to the new bytes.
    pub fn update_all_rule_providers(&self) -> (Vec<ProviderUpdate>, Vec<ConfigError>) {
        let mut updates = Vec::new();
        let mut errors = Vec::new();
        for name in self.slots.keys() {
            match self.update_rule_provider(name) {
                Ok(update) => updates.push(update),
                Err(error) => errors.push(error),
            }
        }
        (updates, errors)
    }

    pub fn update_proxy_provider(&self, name: &str) -> Result<ProviderUpdate, ConfigError> {
        let slot = self.proxy_slots.get(name).ok_or_else(|| {
            ConfigError::InvalidValue(format!("unknown proxy-provider '{name}'"))
        })?;
        if matches!(slot.config.vehicle, ProviderVehicle::Inline) {
            let current = slot.snapshot();
            return Ok(ProviderUpdate {
                name: name.to_string(),
                generation: current.generation,
                entries: current.proxies.len(),
                vehicle: "inline",
                updated_at: SystemTime::now(),
            });
        }
        let proxies = read_proxy_payload(&slot.config, &self.base_dir, &self.tls, false)?;
        let entries = proxies.len();
        let generation = slot.replace_next(ProxyProviderSnapshot {
            generation: 0,
            proxies,
            updated_at: SystemTime::now(),
        });
        Ok(ProviderUpdate {
            name: name.to_string(),
            generation,
            entries,
            vehicle: slot.config.vehicle.as_str(),
            updated_at: SystemTime::now(),
        })
    }
}

/// Raw provider bytes plus the geodata references they add. The engine reads
/// every file/http provider first, loads the referenced geodata, and only then
/// compiles the matchers.
#[derive(Debug)]
pub struct PreparedProviders {
    pub rule: BTreeMap<String, ProviderPayload>,
    pub proxy: BTreeMap<String, Vec<Proxy>>,
    pub requirements: GeodataRequirements,
    pub warnings: Vec<String>,
}

/// Read the rule and proxy providers declared by `config`, without compiling.
pub fn prepare(
    config: &Config,
    base_dir: &Path,
    tls: &Arc<ClientTls>,
) -> Result<PreparedProviders, ConfigError> {
    let mut prepared = PreparedProviders {
        rule: BTreeMap::new(),
        proxy: BTreeMap::new(),
        requirements: config.geodata_requirements(),
        warnings: Vec::new(),
    };
    let provider_names = config
        .rule_providers
        .iter()
        .map(|provider| provider.name.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for provider in &config.rule_providers {
        let mut warnings = Vec::new();
        let payload = read_rule_payload(provider, base_dir, tls, &mut warnings, true)?;
        prepared.warnings.extend(warnings);
        if provider.behavior == RuleBehavior::Classical {
            for entry in &payload.entries {
                if let Ok(rule) =
                    crate::config::parse_rule_without_target_in(entry, &provider_names)
                {
                    prepared
                        .requirements
                        .merge(requirements_for_matcher(&rule.matcher));
                }
            }
        }
        prepared.rule.insert(provider.name.clone(), payload);
    }
    for provider in &config.proxy_providers {
        let proxies = read_proxy_payload(provider, base_dir, tls, true)?;
        prepared.proxy.insert(provider.name.clone(), proxies);
    }
    Ok(prepared)
}

fn requirements_for_matcher(
    matcher: &crate::config::Matcher,
) -> GeodataRequirements {
    let mut requirements = GeodataRequirements::default();
    // `GeodataRequirements` owns the traversal; reuse it through a tiny rule.
    let rule = crate::config::Rule {
        matcher: matcher.clone(),
        action: crate::config::Action::Direct,
        no_resolve: false,
    };
    requirements.collect_rule(&rule);
    requirements
}

/// Compile the prepared payloads. Placeholder slots are created first so a
/// classical provider may reference another provider declared later; the
/// handle is stable and its snapshot is swapped in the second pass.
pub fn finish(
    config: &Config,
    mut prepared: PreparedProviders,
    geodata: Arc<Geodata>,
    base_dir: &Path,
    tls: Arc<ClientTls>,
) -> Result<Arc<RuleProviders>, ConfigError> {
    verify_provider_references(&prepared)?;
    let mut slots: BTreeMap<String, Arc<RuleProviderSlot>> = BTreeMap::new();
    for provider in &config.rule_providers {
        let empty = CompiledRuleSet {
            behavior: provider.behavior,
            domain: Default::default(),
            cidr: Vec::new(),
            classical: Vec::new(),
            indexed: None,
            count: 0,
        };
        slots.insert(
            provider.name.clone(),
            RuleProviderSlot::new(
                provider.name.clone(),
                provider.clone(),
                RuleProviderSnapshot {
                    generation: 1,
                    payload: ProviderPayload {
                        entries: Vec::new(),
                        format: provider.format,
                        vehicle: provider.vehicle.as_str(),
                        indexed: None,
                    },
                    compiled: Arc::new(empty),
                    updated_at: SystemTime::now(),
                },
            ),
        );
    }
    // Second pass: compile every real payload against the stable handles.
    for provider in &config.rule_providers {
        let payload = prepared
            .rule
            .remove(&provider.name)
            .unwrap_or(ProviderPayload {
                entries: Vec::new(),
                format: provider.format,
                vehicle: provider.vehicle.as_str(),
                indexed: None,
            });
        let compiled =
            compile_provider_payload(&provider.name, provider.behavior, &payload, &geodata, &slots)?;
        let slot = slots.get(&provider.name).expect("placed above");
        slot.replace(RuleProviderSnapshot {
            generation: 1,
            payload,
            compiled: Arc::new(compiled),
            updated_at: SystemTime::now(),
        });
    }
    let mut proxy_slots = BTreeMap::new();
    for provider in &config.proxy_providers {
        let proxies = prepared
            .proxy
            .remove(&provider.name)
            .unwrap_or_default();
        proxy_slots.insert(
            provider.name.clone(),
            ProxyProviderSlot::new(
                provider.name.clone(),
                provider.clone(),
                ProxyProviderSnapshot {
                    generation: 1,
                    proxies,
                    updated_at: SystemTime::now(),
                },
            ),
        );
    }
    Ok(Arc::new(RuleProviders {
        geodata,
        base_dir: base_dir.to_path_buf(),
        tls,
        slots,
        proxy_slots,
    }))
}

/// A classical provider may reference another provider with RULE-SET. Reject
/// cycles at load so evaluation cannot recurse forever.
fn verify_provider_references(prepared: &PreparedProviders) -> Result<(), ConfigError> {
    let names = prepared.rule.keys().cloned().collect::<std::collections::BTreeSet<_>>();
    let mut graph: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, payload) in &prepared.rule {
        let mut edges = Vec::new();
        // Only classical entries can carry RULE-SET; domain/ip entries are raw
        // patterns and cannot name another provider.
        if payload.format != RuleFormat::Mrs {
            for entry in &payload.entries {
                // Also catches SRC-RULE-SET and references inside logic rules.
                // Valid references always contain this literal rule type.
                if !entry
                    .as_bytes()
                    .windows(b"RULE-SET".len())
                    .any(|bytes| bytes.eq_ignore_ascii_case(b"RULE-SET"))
                {
                    continue;
                }
                if let Ok(rule) =
                    crate::config::parse_rule_without_target_in(entry, &names)
                {
                    collect_rule_set_names(&rule.matcher, &mut edges);
                }
            }
        }
        graph.insert(name.clone(), edges);
    }
    fn visit(
        name: &str,
        graph: &BTreeMap<String, Vec<String>>,
        stack: &mut Vec<String>,
    ) -> Result<(), ConfigError> {
        if stack.iter().any(|entry| entry == name) {
            return Err(ConfigError::InvalidValue(format!(
                "rule-providers contain a circular reference: {} -> {name}",
                stack.join(" -> ")
            )));
        }
        stack.push(name.to_string());
        if let Some(edges) = graph.get(name) {
            for edge in edges {
                visit(edge, graph, stack)?;
            }
        }
        stack.pop();
        Ok(())
    }
    for name in graph.keys() {
        visit(name, &graph, &mut Vec::new())?;
    }
    Ok(())
}

fn collect_rule_set_names(
    matcher: &crate::config::Matcher,
    out: &mut Vec<String>,
) {
    use crate::config::Matcher;
    match matcher {
        Matcher::RuleSet { name, .. } => out.push(name.clone()),
        Matcher::And(rules) | Matcher::Or(rules) => {
            for rule in rules {
                collect_rule_set_names(&rule.matcher, out);
            }
        }
        Matcher::Not(rule) | Matcher::SubRule { gate: rule, .. } => {
            collect_rule_set_names(&rule.matcher, out);
        }
        _ => {}
    }
}

/// Which geodata files the prepared requirements need.
pub fn geodata_source(config: &Config) -> GeoIpSource {
    if config.geodata_mode {
        GeoIpSource::Dat
    } else {
        GeoIpSource::Mmdb
    }
}

// ---------------------------------------------------------------------------
// Provider vehicles and payload parsing
// ---------------------------------------------------------------------------

/// Lexically normalize an absolute path without touching the filesystem. A
/// `..` at the root stays at the root (as `filepath.Clean` does); callers only
/// use this for the pinned path-containment check.
fn normalize_absolute(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(Component::RootDir.as_os_str());
    }
    out
}

fn absolute_from(base_dir: &Path, path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    };
    absolute_from_cwd(&joined)
}

fn absolute_from_cwd(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    normalize_absolute(&absolute)
}

fn validate_vehicle_path(
    name: &str,
    kind: &str,
    vehicle: &ProviderVehicle,
    base_dir: &Path,
) -> Result<(), ConfigError> {
    let path = match vehicle {
        ProviderVehicle::Inline => return Ok(()),
        ProviderVehicle::File { path } => Some(path),
        ProviderVehicle::Http { path, .. } => path.as_ref(),
    };
    let Some(path) = path else {
        return Ok(());
    };
    resolve_provider_path(base_dir, path).map(|_| ()).map_err(|error| {
        ConfigError::Unsupported(format!("{kind} '{name}': {error}"))
    })
}

/// Provider paths follow the pinned `C.Path.IsSafePath` rule
/// (`constant/path.go`): a relative path is resolved against the
/// configuration directory (Mihomo's `homeDir`), then must stay under that
/// directory or one of the `SAFE_PATHS` entries. The check is lexical, like
/// `filepath.IsLocal(filepath.Rel(...))`; it rejects absolute paths outside the
/// roots and any `..` that escapes them.
fn resolve_provider_path(base_dir: &Path, path: &Path) -> Result<PathBuf, String> {
    let root = absolute_from(base_dir, Path::new(""));
    let candidate = absolute_from(&root, path);
    let mut allowed = vec![root.clone()];
    if let Ok(extra) = std::env::var("SAFE_PATHS") {
        for entry in std::env::split_paths(&extra) {
            if entry.as_os_str().is_empty() {
                continue;
            }
            allowed.push(absolute_from_cwd(&entry));
        }
    }
    if allowed
        .iter()
        .any(|allowed| candidate.strip_prefix(allowed).is_ok())
    {
        return Ok(candidate);
    }
    Err(format!(
        "provider path {} is not a subpath of the provider root {} or SAFE_PATHS (pinned Mihomo IsSafePath rule)",
        candidate.display(),
        root.display()
    ))
}

fn read_rule_payload(
    provider: &RuleProviderConfig,
    base_dir: &Path,
    tls: &Arc<ClientTls>,
    warnings: &mut Vec<String>,
    allow_fallback: bool,
) -> Result<ProviderPayload, ConfigError> {
    if matches!(provider.vehicle, ProviderVehicle::Inline) {
        let payload = ProviderPayload {
            entries: provider.payload.clone(),
            format: provider.format,
            vehicle: "inline",
            indexed: None,
        };
        return Ok(payload);
    }
    // A path outside the root is a configuration error, not a reason to use
    // the payload fallback: pinned `ParseRuleProvider` rejects it up front.
    validate_vehicle_path(&provider.name, "rule-provider", &provider.vehicle, base_dir)?;
    if provider.behavior == RuleBehavior::Classical
        && matches!(provider.format, RuleFormat::Text | RuleFormat::Yaml)
    {
        if let ProviderVehicle::File { path } = &provider.vehicle {
            let path = resolve_provider_path(base_dir, path).map_err(ConfigError::Unsupported)?;
            if let Ok(file) = std::fs::File::open(&path) {
                if file.metadata().is_ok_and(|metadata| {
                    metadata.len() >= 1024 * 1024
                        && provider.size_limit.is_none_or(|limit| metadata.len() <= limit)
                }) {
                    let indexed = domain_index::index_file(file, provider.format).map_err(|error| {
                        ConfigError::Unsupported(format!(
                            "rule-provider '{}' could not build its domain index: {error}",
                            provider.name
                        ))
                    })?;
                    if let Some(indexed) = indexed {
                        return Ok(ProviderPayload {
                            entries: indexed.other_rules,
                            format: provider.format,
                            vehicle: provider.vehicle.as_str(),
                            indexed: Some(IndexedProvider {
                                domains: indexed.domains,
                                other_positions: indexed.other_positions.into(),
                                count: indexed.count,
                            }),
                        });
                    }
                }
            }
        }
    }
    if matches!(provider.vehicle, ProviderVehicle::Http { .. }) {
        if let Some(proxy) = &provider.proxy {
            if !proxy.is_empty() {
                return Err(ConfigError::Unsupported(format!(
                    "rule-provider '{}': fetching through proxy '{proxy}' is not implemented",
                    provider.name
                )));
            }
        }
    }
    let bytes = match read_vehicle(
        &provider.vehicle,
        provider.header.as_slice(),
        provider.size_limit,
        base_dir,
        tls,
        allow_fallback,
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            if allow_fallback && !provider.payload.is_empty() {
                warnings.push(format!(
                    "rule-provider '{}' could not be read ({error}); using its payload fallback",
                    provider.name
                ));
                return Ok(ProviderPayload {
                    entries: provider.payload.clone(),
                    format: RuleFormat::Yaml,
                    vehicle: provider.vehicle.as_str(),
                    indexed: None,
                });
            }
            return Err(ConfigError::Unsupported(format!(
                "rule-provider '{}': {error}",
                provider.name
            )));
        }
    };
    let entries = parse_rule_payload_bytes(provider.behavior, provider.format, &bytes).map_err(|e| {
        ConfigError::Unsupported(format!(
            "rule-provider '{}' ({} {}): {e}",
            provider.name,
            provider.vehicle.as_str(),
            provider.format.as_str()
        ))
    })?;
    Ok(ProviderPayload {
        entries,
        format: provider.format,
        vehicle: provider.vehicle.as_str(),
        indexed: None,
    })
}

fn parse_rule_payload_bytes(
    behavior: RuleBehavior,
    format: RuleFormat,
    bytes: &[u8],
) -> Result<Vec<String>, String> {
    match format {
        RuleFormat::Mrs => {
            if behavior == RuleBehavior::Classical {
                return Err("MRS payloads carry domain or ipcidr sets, not classical rules".to_string());
            }
            let decoded = decode_mrs(bytes)?;
            let expected = match behavior {
                RuleBehavior::Domain => "domain",
                RuleBehavior::IpCidr => "ipcidr",
                RuleBehavior::Classical => unreachable!("checked above"),
            };
            if decoded.behavior != expected {
                return Err(format!(
                    "MRS behavior '{}' does not match provider behavior '{expected}'",
                    decoded.behavior
                ));
            }
            Ok(decoded.rules)
        }
        RuleFormat::Text => {
            let text = std::str::from_utf8(bytes)
                .map_err(|e| format!("payload is not UTF-8: {e}"))?;
            Ok(text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with("//"))
                .map(str::to_string)
                .collect())
        }
        RuleFormat::Yaml => {
            let text = std::str::from_utf8(bytes)
                .map_err(|e| format!("payload is not UTF-8: {e}"))?;
            let mut value: serde_yaml::Value = serde_yaml::from_str(text)
                .map_err(|e| format!("payload is not YAML: {e}"))?;
            let Some(mapping) = value.as_mapping_mut() else {
                return Err("YAML payload must be a mapping with payload or rules".to_string());
            };
            for key in ["payload", "rules"] {
                if let Some(entries) = mapping.get_mut(serde_yaml::Value::String(key.to_string())) {
                    let entries = entries
                        .as_sequence_mut()
                        .ok_or_else(|| format!("'{key}' must be a list"))?;
                    let entries = std::mem::take(entries);
                    drop(value);
                    return entries
                        .into_iter()
                        .map(|entry| match entry {
                            serde_yaml::Value::String(text) => Ok(text),
                            other => other
                                .as_str()
                                .map(str::to_string)
                                .ok_or_else(|| format!("'{key}' entries must be strings")),
                        })
                        .collect();
                }
            }
            Err("file must have a `payload` field".to_string())
        }
    }
}

fn read_proxy_payload(
    provider: &ProxyProviderConfig,
    base_dir: &Path,
    tls: &Arc<ClientTls>,
    allow_fallback: bool,
) -> Result<Vec<Proxy>, ConfigError> {
    let raw = if matches!(provider.vehicle, ProviderVehicle::Inline) {
        serde_yaml::Value::Sequence(provider.payload.clone())
    } else {
        validate_vehicle_path(&provider.name, "proxy-provider", &provider.vehicle, base_dir)?;
        if matches!(provider.vehicle, ProviderVehicle::Http { .. }) {
            if let Some(proxy) = &provider.proxy {
                if !proxy.is_empty() {
                    return Err(ConfigError::Unsupported(format!(
                        "proxy-provider '{}': fetching through proxy '{proxy}' is not implemented",
                        provider.name
                    )));
                }
            }
        }
        match read_vehicle(&provider.vehicle, &provider.header, provider.size_limit, base_dir, tls, allow_fallback) {
            Ok(bytes) => {
                let text = std::str::from_utf8(&bytes).map_err(|e| {
                    ConfigError::Unsupported(format!(
                        "proxy-provider '{}': payload is not UTF-8: {e}",
                        provider.name
                    ))
                })?;
                let value: serde_yaml::Value = serde_yaml::from_str(text).map_err(|e| {
                    ConfigError::Unsupported(format!(
                        "proxy-provider '{}': payload is not YAML: {e}",
                        provider.name
                    ))
                })?;
                match value.as_mapping().and_then(|mapping| {
                    mapping.get(serde_yaml::Value::String("proxies".to_string()))
                }) {
                    Some(proxies) => proxies.clone(),
                    None => {
                        return Err(ConfigError::Unsupported(format!(
                            "proxy-provider '{}': file must have a `proxies` field",
                            provider.name
                        )))
                    }
                }
            }
            Err(error) if allow_fallback && !provider.payload.is_empty() => {
                let _ = error;
                serde_yaml::Value::Sequence(provider.payload.clone())
            }
            Err(error) => {
                return Err(ConfigError::Unsupported(format!(
                    "proxy-provider '{}': {error}",
                    provider.name
                )))
            }
        }
    };
    let entries = raw.as_sequence().ok_or_else(|| {
        ConfigError::InvalidValue(format!(
            "proxy-provider '{}': payload must be a list of proxy mappings",
            provider.name
        ))
    })?;
    let filter = compile_provider_filters(provider, provider.filter.as_deref(), "filter")?;
    let exclude_filter =
        compile_provider_filters(provider, provider.exclude_filter.as_deref(), "exclude-filter")?;
    let mut kept = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (index, entry) in entries.iter().enumerate() {
        let mapping = entry.as_mapping().ok_or_else(|| {
            ConfigError::InvalidValue(format!(
                "proxy-provider '{}': proxies[{index}] must be a mapping",
                provider.name
            ))
        })?;
        // The pinned parser filters on the source `type`/`name`, before any
        // override renames the proxy.
        let kind = mapping
            .get(serde_yaml::Value::String("type".to_string()))
            .and_then(serde_yaml::Value::as_str);
        let name = mapping
            .get(serde_yaml::Value::String("name".to_string()))
            .and_then(serde_yaml::Value::as_str);
        let (Some(kind), Some(name)) = (kind, name) else {
            // Pinned `NewProxiesParser` skips an entry without a string
            // type/name; it is not a rule that could silently go missing.
            continue;
        };
        if provider
            .exclude_type
            .iter()
            .any(|excluded| excluded.eq_ignore_ascii_case(kind))
        {
            continue;
        }
        if exclude_filter.iter().any(|regex| regex.is_match(name)) {
            continue;
        }
        if !filter.is_empty() && !filter.iter().any(|regex| regex.is_match(name)) {
            continue;
        }
        if !seen.insert(name.to_string()) {
            continue;
        }
        let mut mapping = mapping.clone();
        apply_proxy_override(&mut mapping, &provider.overrides, provider)?;
        kept.push(serde_yaml::Value::Mapping(mapping));
    }
    if kept.is_empty() {
        let reason = if provider.filter.as_deref().is_some_and(|value| !value.is_empty()) {
            "doesn't match any proxy, please check your filter"
        } else {
            "file doesn't have any proxy"
        };
        return Err(ConfigError::Unsupported(format!(
            "proxy-provider '{}': {reason}",
            provider.name
        )));
    }
    let mut proxies = parse_proxies(&serde_yaml::Value::Sequence(kept))?;
    // Pinned applies the provider-level dialer first, then `override` may
    // replace it. Doing this after `parse_proxies` keeps the hop lookup at
    // evaluation time (the hop may be a top-level proxy, not in this provider).
    let dialer = provider
        .overrides
        .dialer_proxy
        .clone()
        .or_else(|| provider.dialer_proxy.clone());
    if let Some(dialer) = dialer {
        for proxy in &mut proxies {
            if !proxy.set_dialer_proxy(Some(dialer.clone())) {
                return Err(ConfigError::Unsupported(format!(
                    "proxy-provider '{}': dialer-proxy cannot be applied to {} proxy '{}'",
                    provider.name,
                    proxy.type_name(),
                    proxy.name
                )));
            }
        }
    }
    Ok(proxies)
}

fn compile_provider_filters(
    provider: &ProxyProviderConfig,
    patterns: Option<&str>,
    key: &str,
) -> Result<Vec<regex::Regex>, ConfigError> {
    let Some(patterns) = patterns else {
        return Ok(Vec::new());
    };
    let mut compiled = Vec::new();
    for pattern in patterns.split('`') {
        if pattern.is_empty() {
            continue;
        }
        compiled.push(regex::Regex::new(pattern).map_err(|e| {
            ConfigError::Unsupported(format!(
                "proxy-provider '{}' {key} {pattern:?}: {e}",
                provider.name
            ))
        })?);
    }
    Ok(compiled)
}

fn apply_proxy_override(
    mapping: &mut serde_yaml::Mapping,
    overrides: &ProxyOverride,
    provider: &ProxyProviderConfig,
) -> Result<(), ConfigError> {
    let key = |name: &str| serde_yaml::Value::String(name.to_string());
    if let Some(udp) = overrides.udp {
        mapping.insert(key("udp"), serde_yaml::Value::Bool(udp));
    }
    if let Some(skip) = overrides.skip_cert_verify {
        mapping.insert(key("skip-cert-verify"), serde_yaml::Value::Bool(skip));
    }
    let mut name = mapping
        .get(&key("name"))
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or_default()
        .to_string();
    for rewrite in &overrides.proxy_name {
        let regex = regex::Regex::new(&rewrite.pattern).map_err(|e| {
            ConfigError::Unsupported(format!(
                "proxy-provider '{}': override.proxy-name {:?}: {e}",
                provider.name, rewrite.pattern
            ))
        })?;
        name = regex.replace_all(&name, rewrite.target.as_str()).into_owned();
    }
    if let Some(prefix) = &overrides.additional_prefix {
        name = format!("{prefix}{name}");
    }
    if let Some(suffix) = &overrides.additional_suffix {
        name = format!("{name}{suffix}");
    }
    if !name.is_empty() {
        mapping.insert(key("name"), serde_yaml::Value::String(name));
    }
    Ok(())
}

fn read_vehicle(
    vehicle: &ProviderVehicle,
    headers: &[(String, String)],
    size_limit: Option<u64>,
    base_dir: &Path,
    tls: &Arc<ClientTls>,
    allow_cache: bool,
) -> Result<Vec<u8>, String> {
    match vehicle {
        ProviderVehicle::Inline => Err("inline providers carry their payload in the YAML".to_string()),
        ProviderVehicle::File { path } => {
            let path = resolve_provider_path(base_dir, path)?;
            let bytes = std::fs::read(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            check_limit(bytes.len(), size_limit)?;
            Ok(bytes)
        }
        ProviderVehicle::Http { url, path } => {
            // Validate before the fetch so an out-of-root cache path cannot be
            // created even when the server response is malformed.
            let cache = path
                .as_ref()
                .map(|path| resolve_provider_path(base_dir, path))
                .transpose()?;
            match http_get(url, headers, tls, size_limit) {
                Ok(bytes) => {
                    if let Some(cache) = cache {
                        if let Some(parent) = cache.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        std::fs::write(&cache, &bytes).map_err(|e| {
                            format!("cannot write provider cache {}: {e}", cache.display())
                        })?;
                    }
                    Ok(bytes)
                }
                Err(error) => {
                    if allow_cache {
                        if let Some(cache) = cache {
                            if let Ok(bytes) = std::fs::read(&cache) {
                                check_limit(bytes.len(), size_limit)?;
                                return Ok(bytes);
                            }
                        }
                    }
                    Err(error)
                }
            }
        }
    }
}

fn check_limit(len: usize, limit: Option<u64>) -> Result<(), String> {
    if let Some(limit) = limit {
        if len as u64 > limit {
            return Err(format!("payload is {len} bytes, above size-limit {limit}"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// A bounded HTTP/1.1 GET
// ---------------------------------------------------------------------------

struct Url {
    https: bool,
    authority: String,
    host: String,
    port: u16,
    path: String,
}

fn parse_url(url: &str) -> Result<Url, String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("provider url '{url}' has no scheme"))?;
    let https = match scheme.to_ascii_lowercase().as_str() {
        "http" => false,
        "https" => true,
        other => return Err(format!("provider url scheme '{other}' is not http(s)")),
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(format!("provider url '{url}' has no host"));
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("provider url '{url}' has an unterminated IPv6 host"))?;
        let port = match tail.strip_prefix(':') {
            Some(port) => port
                .parse::<u16>()
                .map_err(|e| format!("provider url '{url}' port: {e}"))?,
            None => {
                if https {
                    443
                } else {
                    80
                }
            }
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (
                host.to_string(),
                port.parse::<u16>()
                    .map_err(|e| format!("provider url '{url}' port: {e}"))?,
            ),
            _ => (
                authority.to_string(),
                if https { 443 } else { 80 },
            ),
        }
    };
    Ok(Url {
        https,
        authority: authority.to_string(),
        host,
        port,
        path: path.to_string(),
    })
}

fn http_get(
    url: &str,
    headers: &[(String, String)],
    tls: &Arc<ClientTls>,
    size_limit: Option<u64>,
) -> Result<Vec<u8>, String> {
    let mut current = url.to_string();
    for _ in 0..6 {
        let parsed = parse_url(&current)?;
        let (status, response_headers, body) = http_request(&parsed, headers, tls, size_limit)?;
        if (300..400).contains(&status) {
            let location = response_headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("location"))
                .map(|(_, value)| value.clone())
                .ok_or_else(|| format!("provider url {current} returned {status} without Location"))?;
            current = if location.starts_with("http://") || location.starts_with("https://") {
                location
            } else if location.starts_with('/') {
                format!(
                    "{}://{}{}",
                    if parsed.https { "https" } else { "http" },
                    parsed.authority,
                    location
                )
            } else {
                let base = parsed.path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");
                format!(
                    "{}://{}{base}/{location}",
                    if parsed.https { "https" } else { "http" },
                    parsed.authority
                )
            };
            continue;
        }
        if status != 200 {
            return Err(format!("provider url {current} returned HTTP {status}"));
        }
        return Ok(body);
    }
    Err(format!("provider url {url} redirected more than 5 times"))
}

fn http_request(
    url: &Url,
    headers: &[(String, String)],
    tls: &Arc<ClientTls>,
    size_limit: Option<u64>,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    let addr = format!("{}:{}", url.host, url.port);
    let socket: SocketAddr = addr
        .to_socket_addrs()
        .map_err(|e| format!("resolve {addr}: {e}"))?
        .next()
        .ok_or_else(|| format!("resolve {addr}: no address"))?;
    let tcp = crate::outbound::tcp_stream_std_blocking(socket, Duration::from_secs(15))
        .map_err(|e| format!("connect {addr}: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("{addr}: {e}"))?;
    tcp.set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("{addr}: {e}"))?;
    let mut conn = if url.https {
        let settings = crate::proxies::TlsSettings::default();
        let config = tls::client_config(&settings, tls)
            .map_err(|e| format!("TLS config for {addr}: {e}"))?;
        let name = rustls::pki_types::ServerName::try_from(url.host.clone())
            .map_err(|e| format!("TLS name {}: {e}", url.host))?;
        let session = rustls::ClientConnection::new(config, name)
            .map_err(|e| format!("TLS handshake setup for {addr}: {e}"))?;
        Conn::Tls(Box::new(rustls::StreamOwned::new(session, tcp)))
    } else {
        Conn::Plain(tcp)
    };
    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: clash.meta\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
        url.path, url.authority
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    conn.write_all(request.as_bytes())
        .map_err(|e| format!("write request {addr}: {e}"))?;
    conn.flush().map_err(|e| format!("flush request {addr}: {e}"))?;

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 64 * 1024 {
            return Err(format!("{addr}: response headers are too large"));
        }
        let read = conn
            .read(&mut byte)
            .map_err(|e| format!("read response {addr}: {e}"))?;
        if read == 0 {
            return Err(format!("{addr}: connection closed before response headers"));
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).to_string();
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| format!("{addr}: empty response"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("{addr}: bad status line {status_line:?}"))?;
    let mut response_headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            response_headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    let header = |name: &str| {
        response_headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    if header("content-encoding").is_some_and(|value| !value.eq_ignore_ascii_case("identity")) {
        return Err(format!(
            "{addr}: compressed provider responses ({}) are not implemented",
            header("content-encoding").unwrap_or_default()
        ));
    }
    let mut body = Vec::new();
    if header("transfer-encoding").is_some_and(|value| value.eq_ignore_ascii_case("chunked")) {
        loop {
            let size_line = read_line(&mut conn, &addr)?;
            let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|e| format!("{addr}: chunk size {size_line:?}: {e}"))?;
            if size == 0 {
                // Trailer lines end with an empty line.
                while !read_line(&mut conn, &addr)?.is_empty() {}
                break;
            }
            let mut chunk = vec![0u8; size];
            conn.read_exact(&mut chunk)
                .map_err(|e| format!("{addr}: chunk body: {e}"))?;
            body.extend(chunk);
            check_limit(body.len(), size_limit)?;
            let mut crlf = [0u8; 2];
            conn.read_exact(&mut crlf)
                .map_err(|e| format!("{addr}: chunk terminator: {e}"))?;
        }
    } else if let Some(length) = header("content-length") {
        let length = length
            .parse::<usize>()
            .map_err(|e| format!("{addr}: content-length {length:?}: {e}"))?;
        check_limit(length, size_limit)?;
        body.resize(length, 0);
        conn.read_exact(&mut body)
            .map_err(|e| format!("{addr}: body: {e}"))?;
    } else {
        let budget = size_limit.unwrap_or(64 * 1024 * 1024);
        conn.take(budget + 1)
            .read_to_end(&mut body)
            .map_err(|e| format!("{addr}: body: {e}"))?;
        check_limit(body.len(), size_limit)?;
    }
    Ok((status, response_headers, body))
}

fn read_line(conn: &mut Conn, addr: &str) -> Result<String, String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while !line.ends_with(b"\r\n") {
        if line.len() > 8 * 1024 {
            return Err(format!("{addr}: response line is too long"));
        }
        let read = conn
            .read(&mut byte)
            .map_err(|e| format!("{addr}: read line: {e}"))?;
        if read == 0 {
            return Err(format!("{addr}: connection closed in a line"));
        }
        line.push(byte[0]);
    }
    line.truncate(line.len() - 2);
    Ok(String::from_utf8_lossy(&line).to_string())
}

enum Conn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(stream) => stream.read(buf),
            Conn::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(stream) => stream.write(buf),
            Conn::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Plain(stream) => stream.flush(),
            Conn::Tls(stream) => stream.flush(),
        }
    }
}
