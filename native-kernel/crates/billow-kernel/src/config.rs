//! Clash-style YAML loading for the first slice of the kernel.
//!
//! Parsing is strict: every top-level key, every rule and every rule field is
//! checked against an explicit capability list. Anything this slice cannot
//! honour is reported as [`ConfigError::Unsupported`] (or
//! [`ConfigError::Invalid`] for malformed input) so a caller never gets a
//! silently reduced configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use serde::Deserialize;

use sha2::{Digest, Sha256};

/// Top-level keys understood by the first slice. Everything else fails.
pub const SUPPORTED_TOP_LEVEL_KEYS: &[&str] = &[
    "mixed-port",
    "socks-port",
    "port",
    "allow-lan",
    "bind-address",
    "mode",
    "log-level",
    "rules",
];
/// Rule types understood by the first slice.
pub const SUPPORTED_RULE_TYPES: &[&str] = &[
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "GEOSITE",
    "IP-CIDR",
    "IP-CIDR6",
    "MATCH",
];
/// Outbound names understood by the first slice.
pub const SUPPORTED_OUTBOUNDS: &[&str] = &["DIRECT", "REJECT"];

/// Default listen port when the YAML has none (Mihomo defaults to 7890).
pub const DEFAULT_PORT: u16 = 7890;

/// Error returned by [`load_config`]. Each variant maps to a stable string tag
/// in [`ConfigError::tag`] so hosts can map failures to UI states.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid YAML: {0}")]
    Invalid(String),
    #[error("invalid configuration: {0}")]
    InvalidValue(String),
    #[error("unsupported configuration: {0}")]
    Unsupported(String),
}

impl ConfigError {
    /// Stable machine-readable tag: `invalid_yaml`, `invalid_value` or `unsupported`.
    pub fn tag(&self) -> &'static str {
        match self {
            ConfigError::Invalid(_) => "invalid_yaml",
            ConfigError::InvalidValue(_) => "invalid_value",
            ConfigError::Unsupported(_) => "unsupported",
        }
    }
}

/// One parsed rule. `Matcher` is evaluated against the destination host (lowercased),
/// the destination IP (if known before connecting) and the geosite database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub matcher: Matcher,
    pub action: Action,
    /// `no-resolve` was accepted on IP rules: the destination IP is unknown
    /// before connecting, which is exactly what the rule already sees here.
    pub no_resolve: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matcher {
    Domain(String),
    DomainSuffix(String),
    Geosite(String),
    IpCidr(ipnet_like::IpNet),
    /// Unconditional final rule (`MATCH`).
    Match,
}

impl fmt::Display for Matcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Matcher::Domain(v) => write!(f, "DOMAIN,{v}"),
            Matcher::DomainSuffix(v) => write!(f, "DOMAIN-SUFFIX,{v}"),
            Matcher::Geosite(v) => write!(f, "GEOSITE,{v}"),
            Matcher::IpCidr(v) => write!(f, "CIDR,{v}"),
            Matcher::Match => write!(f, "MATCH"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Direct,
    Reject,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Direct => "DIRECT",
            Action::Reject => "REJECT",
        }
    }
}

/// Parsed, validated configuration for the first slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen: SocketAddr,
    /// First port that asked to be rebound on a clash-style port key, if any.
    pub port_rebound_from: Option<u16>,
    pub mode: Option<String>,
    pub log_level: Option<String>,
    pub rules: Vec<Rule>,
    /// Rule-less configuration goes straight to DIRECT like Mihomo does.
    pub empty_rules: bool,
    pub rules_source: RulesSource,
    /// Kept so the identity survives a reload that is rejected.
    pub digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesSource {
    Inline,
    /// No `rules` key at all; traffic goes DIRECT.
    None,
}

impl Config {
    /// Target keywords (lowercased) referenced by GEOSITE rules.
    pub fn geosite_databases(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for rule in &self.rules {
            if let Matcher::Geosite(db) = &rule.matcher {
                out.insert(db.clone());
            }
        }
        out
    }

    /// Honest label of what this configuration enables; used by identity output.
    pub fn feature_summary(&self) -> String {
        format!(
            "mixed-inbound(tcp,http-connect,socks5); rules=inline({} entries); outbounds=DIRECT,REJECT; protocols=none; dns=none",
            self.rules.len()
        )
    }
}

/// Result of `load_config`: the configuration plus warnings for values that
/// are accepted only in their non-default form.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: Config,
    pub warnings: Vec<String>,
}

/// Parse and validate `yaml`. `path` is only used for diagnostics.
pub fn load_config(yaml: &str, path: &str) -> Result<LoadedConfig, ConfigError> {
    let raw: serde_yaml::Value =
        serde_yaml::from_str(yaml).map_err(|e| ConfigError::Invalid(format!("{path}: {e}")))?;
    let mapping = match raw {
        serde_yaml::Value::Mapping(m) => m,
        other => {
            return Err(ConfigError::Invalid(format!(
                "{path}: top level must be a mapping, found {}",
                kind_of(&other)
            )))
        }
    };
    let digest = format!("sha256:{}", hex_digest(yaml.as_bytes()));
    let mut warnings = Vec::new();

    let mut rules_value = None;
    let mut listen_port: Option<u16> = None;
    let mut requested_port: Option<u16> = None;
    let mut allow_lan: Option<bool> = None;
    let mut bind: Option<String> = None;
    let mut mode = None;
    let mut log_level = None;

    for (key, value) in mapping.iter() {
        let key = key.as_str().ok_or_else(|| {
            ConfigError::Invalid(format!(
                "{path}: top-level key must be a string, found {key:?}"
            ))
        })?;
        match key {
            "mixed-port" => listen_port = Some(parse_port(value, path, key)?),
            "port" => {
                let port = parse_port(value, path, key)?;
                requested_port.get_or_insert(port);
            }
            "socks-port" => {
                // Legacy alias is only honoured when nothing else set the listener.
                let port = parse_port(value, path, key)?;
                if listen_port.is_none() {
                    listen_port = Some(port);
                    warnings.push(
                        "socks-port alias used: the mixed listener also accepts HTTP CONNECT"
                            .to_string(),
                    );
                } else {
                    warnings.push(
                        "socks-port ignored because mixed-port already set the listener"
                            .to_string(),
                    );
                }
            }
            "allow-lan" => allow_lan = Some(parse_bool(value, path, key)?),
            "bind-address" => {
                let s = parse_string(value, path, key)?;
                bind = Some(s);
            }
            "mode" => {
                let s = parse_string(value, path, key)?;
                if s != "rule" {
                    return Err(ConfigError::Unsupported(format!(
                        "mode '{s}' (only 'rule' can be honoured by this slice)"
                    )));
                }
                mode = Some(s);
            }
            "log-level" => {
                let s = parse_string(value, path, key)?;
                if !matches!(
                    s.as_str(),
                    "silent" | "error" | "warn" | "warning" | "info" | "debug"
                ) {
                    return Err(ConfigError::Unsupported(format!(
                        "log-level '{s}' (supported: silent, error, warn, info, debug)"
                    )));
                }
                log_level = Some(s);
            }
            "rules" => rules_value = Some(value),
            _ => {
                return Err(ConfigError::Unsupported(format!(
                    "top-level key '{key}' is not implemented by the Rust kernel slice"
                )));
            }
        }
    }

    let port = listen_port.unwrap_or(DEFAULT_PORT);
    let host = match bind.as_deref() {
        None | Some("") => IpAddr::from([127, 0, 0, 1]),
        Some(s) => IpAddr::from_str(s).map_err(|_| {
            ConfigError::InvalidValue(format!("bind-address '{s}' is not an IP address"))
        })?,
    };
    if !host.is_loopback() {
        match allow_lan {
            Some(true) => {}
            _ => {
                return Err(ConfigError::InvalidValue(format!("bind-address '{host}' is not loopback; set allow-lan: true to expose the listener")));
            }
        }
    }
    if let Some(bind) = &bind {
        if bind.is_empty() {
            return Err(ConfigError::InvalidValue(
                "bind-address must not be empty".to_string(),
            ));
        }
    }

    let (rules, rules_source) = match rules_value {
        None => (Vec::new(), RulesSource::None),
        Some(value) => (parse_rules(value, path)?, RulesSource::Inline),
    };

    let config = Config {
        listen: SocketAddr::new(host, port),
        port_rebound_from: requested_port.filter(|p| Some(*p) != listen_port),
        mode,
        log_level,
        empty_rules: rules.is_empty() && rules_source == RulesSource::None,
        rules,
        rules_source,
        digest,
    };
    Ok(LoadedConfig { config, warnings })
}

fn parse_rules(value: &serde_yaml::Value, path: &str) -> Result<Vec<Rule>, ConfigError> {
    let seq = value
        .as_sequence()
        .ok_or_else(|| ConfigError::Invalid(format!("{path}: rules must be a list")))?;
    let mut rules = Vec::with_capacity(seq.len());
    for (index, item) in seq.iter().enumerate() {
        let line = item.as_str().ok_or_else(|| {
            ConfigError::Invalid(format!(
                "{path}: rules[{index}] must be a string, found {}",
                kind_of(item)
            ))
        })?;
        rules.push(parse_rule(line).map_err(|e| {
            let prefix = format!("rules[{index}] ('{line}')");
            match e {
                ConfigError::Unsupported(m) => ConfigError::Unsupported(format!("{prefix}: {m}")),
                ConfigError::InvalidValue(m) => ConfigError::InvalidValue(format!("{prefix}: {m}")),
                ConfigError::Invalid(m) => ConfigError::Invalid(format!("{path}: {prefix}: {m}")),
            }
        })?);
    }
    if rules.iter().any(|r| r.matcher == Matcher::Match) {
        let match_index = rules
            .iter()
            .position(|r| r.matcher == Matcher::Match)
            .expect("checked above");
        if match_index != rules.len() - 1 {
            return Err(ConfigError::InvalidValue(format!(
                "MATCH must be the last rule (found at rules[{match_index}] of {})",
                rules.len()
            )));
        }
    }
    Ok(rules)
}

/// Parse one clash rule line such as `DOMAIN-SUFFIX,example.com,REJECT` or
/// `IP-CIDR,10.0.0.0/8,DIRECT,no-resolve`.
pub fn parse_rule(line: &str) -> Result<Rule, ConfigError> {
    // Fields may be quoted (`'REJECT'`); split before unquoting and trim each field.
    let mut parts: Vec<String> = line
        .split(',')
        .map(|p| p.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
        .collect();
    let rule_type = parts.first().cloned().unwrap_or_default();
    if !SUPPORTED_RULE_TYPES.contains(&rule_type.as_str()) {
        return Err(ConfigError::Unsupported(format!("rule type '{rule_type}'")));
    }
    let no_resolve = parts.last().is_some_and(|p| p == "no-resolve");
    if no_resolve {
        parts.pop();
    }
    if parts
        .iter()
        .any(|p| p.is_empty() || p.chars().any(char::is_whitespace))
    {
        return Err(ConfigError::InvalidValue(format!(
            "empty or whitespace field in rule '{line}'"
        )));
    }
    if no_resolve && !matches!(rule_type.as_str(), "IP-CIDR" | "IP-CIDR6") {
        return Err(ConfigError::InvalidValue(
            "no-resolve is only valid on IP-CIDR rules".to_string(),
        ));
    }
    match rule_type.as_str() {
        "MATCH" => {
            if parts.len() != 2 {
                return Err(ConfigError::InvalidValue(format!(
                    "MATCH takes <action>, got '{line}'"
                )));
            }
            Ok(Rule {
                matcher: Matcher::Match,
                action: parse_action(&parts[1])?,
                no_resolve,
            })
        }
        "DOMAIN" | "DOMAIN-SUFFIX" | "GEOSITE" => {
            if parts.len() != 3 {
                return Err(ConfigError::InvalidValue(format!(
                    "{rule_type} takes <value>,<action>, got '{line}'"
                )));
            }
            let value = parts[1].to_ascii_lowercase();
            let matcher = match rule_type.as_str() {
                "DOMAIN" => Matcher::Domain(value),
                "DOMAIN-SUFFIX" => Matcher::DomainSuffix(value),
                _ => Matcher::Geosite(value),
            };
            Ok(Rule {
                matcher,
                action: parse_action(&parts[2])?,
                no_resolve,
            })
        }
        "IP-CIDR" | "IP-CIDR6" => {
            if parts.len() != 3 {
                return Err(ConfigError::Unsupported(format!(
                    "{rule_type} form '{line}' (only <cidr>,<action>[,no-resolve] is implemented)"
                )));
            }
            let network = ipnet_like::IpNet::from_str(&parts[1]).map_err(|e| {
                ConfigError::InvalidValue(format!("{rule_type} '{}': {e}", parts[1]))
            })?;
            if rule_type == "IP-CIDR6" && network.is_v4() {
                return Err(ConfigError::InvalidValue(format!(
                    "IP-CIDR6 '{}' must be an IPv6 CIDR",
                    parts[1]
                )));
            }
            Ok(Rule {
                matcher: Matcher::IpCidr(network),
                action: parse_action(&parts[2])?,
                no_resolve,
            })
        }
        _ => unreachable!("rule type checked above"),
    }
}

fn parse_action(raw: &str) -> Result<Action, ConfigError> {
    match raw {
        "DIRECT" => Ok(Action::Direct),
        "REJECT" => Ok(Action::Reject),
        "" => Err(ConfigError::InvalidValue(
            "missing outbound in rule".to_string(),
        )),
        other => Err(ConfigError::Unsupported(format!(
            "outbound '{other}' (only DIRECT/REJECT can be honoured by this slice)"
        ))),
    }
}

fn parse_port(value: &serde_yaml::Value, path: &str, key: &str) -> Result<u16, ConfigError> {
    let port = match value {
        serde_yaml::Value::Number(n) => n.as_u64(),
        serde_yaml::Value::String(s) => s.parse::<u64>().ok(),
        _ => None,
    }
    .ok_or_else(|| {
        ConfigError::InvalidValue(format!(
            "{path}: {key} must be an integer port, found {value:?}"
        ))
    })?;
    if port == 0 || port > u16::MAX as u64 {
        return Err(ConfigError::InvalidValue(format!(
            "{path}: {key} {port} is out of range 1..=65535"
        )));
    }
    Ok(port as u16)
}

fn parse_bool(value: &serde_yaml::Value, path: &str, key: &str) -> Result<bool, ConfigError> {
    match value {
        serde_yaml::Value::Bool(b) => Ok(*b),
        _ => Err(ConfigError::InvalidValue(format!(
            "{path}: {key} must be a boolean, found {value:?}"
        ))),
    }
}

fn parse_string(value: &serde_yaml::Value, path: &str, key: &str) -> Result<String, ConfigError> {
    match value {
        serde_yaml::Value::String(s) => Ok(s.clone()),
        _ => Err(ConfigError::InvalidValue(format!(
            "{path}: {key} must be a string, found {value:?}"
        ))),
    }
}

fn kind_of(value: &serde_yaml::Value) -> &'static str {
    match value {
        serde_yaml::Value::Null => "null",
        serde_yaml::Value::Bool(_) => "boolean",
        serde_yaml::Value::Number(_) => "number",
        serde_yaml::Value::String(_) => "string",
        serde_yaml::Value::Sequence(_) => "list",
        serde_yaml::Value::Mapping(_) => "mapping",
        serde_yaml::Value::Tagged(_) => "tagged value",
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Minimal IP network type so the slice does not pull in an extra crate.
#[allow(non_snake_case)]
pub mod ipnet_like {
    use std::fmt;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct IpNet {
        addr: IpAddr,
        prefix: u8,
    }

    impl IpNet {
        pub fn is_v4(&self) -> bool {
            self.addr.is_ipv4()
        }

        pub fn contains(&self, ip: IpAddr) -> bool {
            match (self.addr, ip) {
                (IpAddr::V4(net), IpAddr::V4(ip)) => {
                    let mask = v4_mask(self.prefix);
                    (u32::from(net) & mask) == (u32::from(ip) & mask)
                }
                (IpAddr::V6(net), IpAddr::V6(ip)) => {
                    let mask = v6_mask(self.prefix);
                    (u128::from(net) & mask) == (u128::from(ip) & mask)
                }
                _ => false,
            }
        }
    }

    fn v4_mask(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        }
    }

    fn v6_mask(prefix: u8) -> u128 {
        if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        }
    }

    impl FromStr for IpNet {
        type Err = String;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let (addr, prefix) = s
                .split_once('/')
                .ok_or_else(|| "missing '/prefix'".to_string())?;
            let addr: IpAddr = addr.parse().map_err(|e| format!("bad address: {e}"))?;
            let prefix: u8 = prefix.parse().map_err(|e| format!("bad prefix: {e}"))?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            if prefix > max {
                return Err(format!("prefix {prefix} exceeds {max}"));
            }
            Ok(IpNet { addr, prefix })
        }
    }

    impl fmt::Display for IpNet {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}/{}", self.addr, self.prefix)
        }
    }
}

/// Subset of Mihomo's geosite database understood by the slice:
/// `{"key": name, "tags": [{"name": tag, "rules": [{"domain": ..., "sub_domain": ..., "domain_keyword": ...}]}]}`.
#[derive(Debug, Clone, Default)]
pub struct GeoSiteDatabase {
    entries: BTreeMap<(String, String), GeoSiteEntry>,
}

#[derive(Debug, Clone, Default)]
struct GeoSiteEntry {
    domains: Vec<String>,
    suffixes: Vec<String>,
    keywords: Vec<String>,
}

#[derive(Deserialize)]
struct RawGeoSite {
    key: String,
    tags: Vec<RawGeoSiteTag>,
}

#[derive(Deserialize)]
struct RawGeoSiteTag {
    name: String,
    #[serde(default)]
    rules: Vec<RawGeoSiteRule>,
}

#[derive(Deserialize)]
struct RawGeoSiteRule {
    #[serde(default)]
    domain: Vec<String>,
    #[serde(default)]
    sub_domain: Vec<String>,
    #[serde(default)]
    domain_keyword: Vec<String>,
    /// Any other geosite rule kind (regex, domain_keyword variants, ...) is rejected.
    #[serde(flatten)]
    unknown: BTreeMap<String, serde_yaml::Value>,
}

impl GeoSiteDatabase {
    /// Load `<key>`, `<key>.yaml`, `<key>.dat` or `<key>.json` from `dir` for each requested key.
    /// `.dat`/`.json` need the JSON text form; compiled MRS/protobuf databases are rejected (T5).
    /// A requested database that cannot be found fails loudly.
    pub fn load_from_dir(
        dir: &std::path::Path,
        keys: &BTreeSet<String>,
    ) -> Result<Self, ConfigError> {
        let mut db = GeoSiteDatabase::default();
        for key in keys {
            let mut candidates = vec![
                dir.join(key),
                dir.join(format!("{key}.yaml")),
                dir.join(format!("{key}.dat")),
            ];
            let json_candidate = dir.join(format!("{key}.json"));
            candidates.push(json_candidate);
            let path = candidates.iter().find(|p| p.is_file()).ok_or_else(|| {
                ConfigError::Unsupported(format!("GEOSITE database '{key}' not found in {} (looked for {key}, {key}.yaml, {key}.dat, {key}.json)", dir.display()))
            })?;
            let text = std::fs::read_to_string(path).map_err(|e| {
                ConfigError::Unsupported(format!(
                    "cannot read geosite database {}: {e}",
                    path.display()
                ))
            })?;
            db.merge_yaml(&text)?;
            if !db.entries.keys().any(|(k, _)| k == key) {
                return Err(ConfigError::Unsupported(format!(
                    "geosite database {} does not contain key '{key}'",
                    path.display()
                )));
            }
        }
        Ok(db)
    }

    /// Merge a geosite YAML document. Incompatible geosite entries fail loudly.
    pub fn merge_yaml(&mut self, yaml: &str) -> Result<(), ConfigError> {
        // Mihomo's geosite text form holds several YAML documents; also accept one list or one mapping.
        let documents = serde_yaml::Deserializer::from_str(yaml)
            .map(serde_yaml::Value::deserialize)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                ConfigError::Unsupported(format!(
                    "geosite database not readable by this slice: {e}"
                ))
            })?;
        let mut raw = Vec::new();
        for document in documents {
            match document {
                serde_yaml::Value::Sequence(items) => {
                    for item in items {
                        raw.push(serde_yaml::from_value::<RawGeoSite>(item).map_err(|e| {
                            ConfigError::Unsupported(format!(
                                "geosite database not readable by this slice: {e}"
                            ))
                        })?);
                    }
                }
                serde_yaml::Value::Null => {}
                other => {
                    let site: RawGeoSite = serde_yaml::from_value(other).map_err(|e| {
                        ConfigError::Unsupported(format!(
                            "geosite database not readable by this slice: {e}"
                        ))
                    })?;
                    if site.key.is_empty()
                        || site
                            .key
                            .chars()
                            .any(|c| c.is_whitespace() || c == '/' || c == '.' || c == ',')
                    {
                        return Err(ConfigError::Unsupported(format!("geosite key '{}' (only plain names selectable by GEOSITE,<key> are implemented)", site.key)));
                    }
                    raw.push(site)
                }
            }
        }
        for site in raw {
            for tag in site.tags {
                let value = self
                    .entries
                    .entry((site.key.clone(), tag.name.clone()))
                    .or_default();
                for rule in tag.rules {
                    let unknown = rule.unknown;
                    if !unknown.is_empty() {
                        return Err(ConfigError::Unsupported(format!("geosite {}/{} rule fields {unknown:?} (only domain, sub_domain and domain_keyword are implemented)", site.key, tag.name)));
                    }
                    if rule.domain.is_empty()
                        && rule.sub_domain.is_empty()
                        && rule.domain_keyword.is_empty()
                    {
                        return Err(ConfigError::Unsupported(format!(
                            "geosite {}/{} uses a regex/other rule type",
                            site.key, tag.name
                        )));
                    }
                    if let Some(bad) = rule.sub_domain.iter().find(|s| {
                        s.matches('*').count() > 1
                            || (s.contains('*') && !s.starts_with("*."))
                            || (s.starts_with("*.") && s[2..].contains('*'))
                    }) {
                        return Err(ConfigError::Unsupported(format!("geosite {}/{} sub_domain pattern '{bad}' (only literal and a single leading '*.' wildcard are implemented)", site.key, tag.name)));
                    }
                    value
                        .domains
                        .extend(rule.domain.into_iter().map(|d| d.to_ascii_lowercase()));
                    value.suffixes.extend(
                        rule.sub_domain
                            .into_iter()
                            .map(|d| d.trim_start_matches("*.").to_ascii_lowercase()),
                    );
                    value.keywords.extend(
                        rule.domain_keyword
                            .into_iter()
                            .map(|d| d.to_ascii_lowercase()),
                    );
                }
            }
        }
        Ok(())
    }

    /// `GEOSITE,<key>` matches when the destination matches any tag of `key`.
    pub fn matches_key(&self, key: &str, host: &str) -> bool {
        self.entries
            .iter()
            .filter(|((k, _), _)| k == key)
            .any(|(_, entry)| entry.matches(host))
    }

    /// `GEOSITE,<key>/<tag>` first, then all tags of `<key>`; `false` when unknown.
    pub fn matches(&self, value: &str, host: &str) -> bool {
        match value.split_once('/') {
            Some((key, tag)) => self.matches_tag(key, tag, host) || self.matches_key(key, host),
            None => self.matches_key(value, host),
        }
    }

    /// Exact `GEOSITE,<key>/<tag>` lookup, as Mihomo resolves it first.
    pub fn matches_tag(&self, key: &str, tag: &str, host: &str) -> bool {
        self.entries
            .get(&(key.to_string(), tag.to_string()))
            .is_some_and(|e| e.matches(host))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl GeoSiteEntry {
    fn matches(&self, host: &str) -> bool {
        self.domains.iter().any(|d| d == host)
            // geosite `sub_domain` entries match any subdomain: equality is a match too.
            || self.suffixes.iter().any(|s| *s == "*" || host.ends_with(&format!(".{s}")) || host == s.trim_start_matches("*."))
            || self.keywords.iter().any(|k| host.contains(k))
    }
}

/// Duration helper kept here so tests share one place with defaults.
pub fn default_handshake_timeout() -> Duration {
    Duration::from_secs(10)
}
