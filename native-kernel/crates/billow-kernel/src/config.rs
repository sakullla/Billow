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
    "rule-providers",
    "proxy-providers",
    "sub-rules",
    "geodata-mode",
    "geodata-loader",
    "geosite-matcher",
    "geo-auto-update",
    "geo-update-interval",
];
/// Top-level keys the pinned `RawConfig` declares but this kernel does not
/// implement. They fail with `[unsupported]`; a key outside both lists is not a
/// Mihomo key at all and is ignored exactly as Mihomo's decoder ignores it (R2:
/// a valid configuration must load).
pub const KNOWN_UNSUPPORTED_TOP_LEVEL_KEYS: &[&str] = &[
    "redir-port", "tproxy-port", "ss-config", "vmess-config", "inbound-tfo", "inbound-mptcp",
    "skip-auth-prefixes", "lan-allowed-ips", "lan-disallowed-ips", "unified-delay", "ipv6",
    "external-controller", "external-controller-routing-mark", "external-controller-pipe",
    "external-controller-unix", "external-controller-tls", "external-controller-cors",
    "external-ui", "external-ui-url", "external-ui-name", "external-doh-server", "secret",
    "interface-name", "routing-mark", "tunnels", "tcp-concurrent", "find-process-mode",
    "global-client-fingerprint", "global-ua", "etag-support", "keep-alive-idle",
    "keep-alive-interval", "disable-keep-alive",
    "proxy-groups", "listeners", "hosts", "dns", "ntp", "tun", "tuic-server",
    "iptables", "experimental", "profile", "geox-url", "sniffer", "clash-for-android"
];

/// Rule types understood by the kernel. `IP-ASN` needs `ASN.mmdb`; the other
/// types only need the destination metadata the inbound already knows.
pub const SUPPORTED_RULE_TYPES: &[&str] = &[
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "DOMAIN-WILDCARD",
    "GEOSITE",
    "GEOIP",
    "SRC-GEOIP",
    "IP-ASN",
    "SRC-IP-ASN",
    "IP-CIDR",
    "IP-CIDR6",
    "SRC-IP-CIDR",
    "IP-SUFFIX",
    "SRC-IP-SUFFIX",
    "SRC-PORT",
    "DST-PORT",
    "IN-PORT",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "PROCESS-NAME-REGEX",
    "PROCESS-PATH-REGEX",
    "PROCESS-NAME-WILDCARD",
    "PROCESS-PATH-WILDCARD",
    "NETWORK",
    "IN-TYPE",
    "SUB-RULE",
    "AND",
    "OR",
    "NOT",
    "RULE-SET",
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
    /// A referenced item (a `dialer-proxy` target) does not exist in the
    /// configuration: Mihomo also rejects such a file.
    #[error("configuration error: {0}")]
    ConfigFailed(String),
}

impl ConfigError {
    /// Stable machine-readable tag: `invalid_yaml`, `invalid_value` or `unsupported`.
    pub fn tag(&self) -> &'static str {
        match self {
            ConfigError::Invalid(_) => "invalid_yaml",
            ConfigError::InvalidValue(_) => "invalid_value",
            ConfigError::Unsupported(_) => "unsupported",
            ConfigError::ConfigFailed(_) => "invalid_value",
        }
    }
}

/// One parsed rule. `Matcher` is evaluated against the destination host (lowercased),
/// the destination IP (if known before connecting) and the geosite database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub matcher: Matcher,
    pub action: Action,
    /// Kept for callers that inspect `no-resolve`; the boolean is also part of
    /// the IP/GEOIP/IP-ASN/RULE-SET matcher.
    pub no_resolve: bool,
}

/// Connection network as reported by the inbound (`NETWORK` rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKind {
    Tcp,
    Udp,
}

impl NetworkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkKind::Tcp => "tcp",
            NetworkKind::Udp => "udp",
        }
    }
}

/// Inbound listener type used by `IN-TYPE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InType {
    /// Plain HTTP proxy requests; the pinned mixed listener reports CONNECT as
    /// `HTTPS`, so this variant only matches a non-CONNECT request.
    Http,
    /// HTTP CONNECT (`listener/http` reports `C.HTTPS` for it).
    Https,
    Socks5,
}

impl InType {
    pub fn as_str(self) -> &'static str {
        match self {
            InType::Http => "HTTP",
            InType::Https => "HTTPS",
            InType::Socks5 => "SOCKS5",
        }
    }
}

/// Which port a port rule inspects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortKind {
    Dst,
    Src,
    In,
}

/// One inclusive range of a port rule payload (`200`, `200-400`, `200/302`).
pub type PortRange = (u16, u16);

/// Process metadata matched by PROCESS-NAME/PROCESS-PATH and their regex forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessKind {
    Name,
    Path,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matcher {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(String),
    DomainWildcard(String),
    GeoSite(String),
    GeoIp {
        country: String,
        source: bool,
        no_resolve: bool,
    },
    IpAsn {
        asn: String,
        source: bool,
        no_resolve: bool,
    },
    IpCidr {
        net: ipnet_like::IpNet,
        source: bool,
        no_resolve: bool,
    },
    IpSuffix {
        net: ipnet_like::IpNet,
        source: bool,
        no_resolve: bool,
    },
    Port {
        kind: PortKind,
        ranges: Vec<PortRange>,
    },
    Network(NetworkKind),
    InType(Vec<InType>),
    Process {
        kind: ProcessKind,
        pattern: String,
        regex: bool,
    },
    /// `PROCESS-NAME-WILDCARD`/`PROCESS-PATH-WILDCARD`: the pinned
    /// `component/wildcard` semantics (`*` any run, `?` one byte), compared
    /// case-insensitively like `PROCESS-NAME`.
    ProcessWildcard {
        kind: ProcessKind,
        pattern: String,
    },
    RuleSet {
        name: String,
        source: bool,
        no_resolve: bool,
    },
    /// `SUB-RULE,(<gate>),<name>`: the gate decides whether the named sub-rule
    /// list is consulted, and that list selects the outbound.
    SubRule {
        gate: Box<Rule>,
        name: String,
    },
    And(Vec<Rule>),
    Or(Vec<Rule>),
    Not(Box<Rule>),
    /// Unconditional final rule (`MATCH`).
    Match,
}

impl fmt::Display for Matcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Matcher::Domain(v) => write!(f, "DOMAIN,{v}"),
            Matcher::DomainSuffix(v) => write!(f, "DOMAIN-SUFFIX,{v}"),
            Matcher::DomainKeyword(v) => write!(f, "DOMAIN-KEYWORD,{v}"),
            Matcher::DomainRegex(v) => write!(f, "DOMAIN-REGEX,{v}"),
            Matcher::DomainWildcard(v) => write!(f, "DOMAIN-WILDCARD,{v}"),
            Matcher::GeoSite(v) => write!(f, "GEOSITE,{v}"),
            Matcher::GeoIp {
                country,
                source,
                no_resolve,
            } => write!(
                f,
                "{}{country}{}",
                if *source { "SRC-GEOIP," } else { "GEOIP," },
                if *no_resolve { ",no-resolve" } else { "" }
            ),
            Matcher::IpAsn {
                asn,
                source,
                no_resolve,
            } => write!(
                f,
                "{}{asn}{}",
                if *source { "SRC-IP-ASN," } else { "IP-ASN," },
                if *no_resolve { ",no-resolve" } else { "" }
            ),
            Matcher::IpCidr {
                net,
                source,
                no_resolve,
            } => write!(
                f,
                "{}{net}{}",
                if *source { "SRC-IP-CIDR," } else { "IP-CIDR," },
                if *no_resolve { ",no-resolve" } else { "" }
            ),
            Matcher::IpSuffix {
                net,
                source,
                no_resolve,
            } => write!(
                f,
                "{}{net}{}",
                if *source { "SRC-IP-SUFFIX," } else { "IP-SUFFIX," },
                if *no_resolve { ",no-resolve" } else { "" }
            ),
            Matcher::Port { kind, ranges } => {
                let list = ranges
                    .iter()
                    .map(|(start, end)| {
                        if start == end {
                            start.to_string()
                        } else {
                            format!("{start}-{end}")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("/");
                let name = match kind {
                    PortKind::Dst => "DST-PORT",
                    PortKind::Src => "SRC-PORT",
                    PortKind::In => "IN-PORT",
                };
                write!(f, "{name},{list}")
            }
            Matcher::Network(kind) => write!(f, "NETWORK,{}", kind.as_str().to_ascii_uppercase()),
            Matcher::InType(types) => write!(
                f,
                "IN-TYPE,{}",
                types
                    .iter()
                    .map(|kind| kind.as_str())
                    .collect::<Vec<_>>()
                    .join("/")
            ),
            Matcher::Process {
                kind,
                pattern,
                regex,
            } => write!(
                f,
                "{}{pattern}",
                match (kind, regex) {
                    (ProcessKind::Name, false) => "PROCESS-NAME,",
                    (ProcessKind::Path, false) => "PROCESS-PATH,",
                    (ProcessKind::Name, true) => "PROCESS-NAME-REGEX,",
                    (ProcessKind::Path, true) => "PROCESS-PATH-REGEX,",
                }
            ),
            Matcher::ProcessWildcard { kind, pattern } => write!(
                f,
                "{}{pattern}",
                match kind {
                    ProcessKind::Name => "PROCESS-NAME-WILDCARD,",
                    ProcessKind::Path => "PROCESS-PATH-WILDCARD,",
                }
            ),
            Matcher::RuleSet {
                name,
                source,
                no_resolve,
            } => write!(
                f,
                "RULE-SET,{name}{}{}",
                if *source { ",src" } else { "" },
                if *no_resolve { ",no-resolve" } else { "" }
            ),
            Matcher::SubRule { gate, name } => write!(f, "SUB-RULE,({}),{name}", gate.matcher),
            Matcher::And(rules) => write!(
                f,
                "AND,({})",
                rules
                    .iter()
                    .map(|rule| rule.matcher.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Matcher::Or(rules) => write!(
                f,
                "OR,({})",
                rules
                    .iter()
                    .map(|rule| rule.matcher.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Matcher::Not(rule) => write!(f, "NOT,({})", rule.matcher),
            Matcher::Match => write!(f, "MATCH"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Direct,
    Reject,
    /// `REJECT-DROP`: close without sending an inbound failure reply.
    RejectDrop,
    /// Index into [`Config::proxies`].
    Proxy(usize),
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Direct => "DIRECT",
            Action::Reject => "REJECT",
            Action::RejectDrop => "REJECT-DROP",
            // The name is not known here; callers with a Config use `Proxy::name`.
            Action::Proxy(_) => "PROXY",
        }
    }
}

/// Behaviour of a rule provider, as `rule-providers.<name>.behavior`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleBehavior {
    Domain,
    IpCidr,
    Classical,
}

impl RuleBehavior {
    pub fn as_str(self) -> &'static str {
        match self {
            RuleBehavior::Domain => "domain",
            RuleBehavior::IpCidr => "ipcidr",
            RuleBehavior::Classical => "classical",
        }
    }
}

/// Encoding of a rule provider payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleFormat {
    Yaml,
    Text,
    Mrs,
}

impl RuleFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            RuleFormat::Yaml => "yaml",
            RuleFormat::Text => "text",
            RuleFormat::Mrs => "mrs",
        }
    }
}

/// Where a provider's bytes come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderVehicle {
    File { path: std::path::PathBuf },
    Http {
        url: String,
        path: Option<std::path::PathBuf>,
    },
    Inline,
}

impl ProviderVehicle {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProviderVehicle::File { .. } => "file",
            ProviderVehicle::Http { .. } => "http",
            ProviderVehicle::Inline => "inline",
        }
    }
}

/// `health-check` of a proxy provider. Parsed and exposed; scheduling the
/// probes is part of T23 (group selection/latency), which owns the health data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthCheckConfig {
    pub enable: bool,
    pub url: Option<String>,
    pub interval: u64,
    pub timeout: u64,
    pub lazy: bool,
    pub expected_status: String,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        HealthCheckConfig {
            enable: false,
            url: None,
            interval: 300,
            timeout: 0,
            lazy: true,
            expected_status: String::new(),
        }
    }
}

/// One `rule-providers` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleProviderConfig {
    pub name: String,
    pub behavior: RuleBehavior,
    pub format: RuleFormat,
    pub vehicle: ProviderVehicle,
    pub interval: Option<Duration>,
    pub payload: Vec<String>,
    pub header: Vec<(String, String)>,
    pub proxy: Option<String>,
    pub size_limit: Option<u64>,
}

/// One `proxy-providers` entry.
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyProviderConfig {
    pub name: String,
    pub vehicle: ProviderVehicle,
    pub interval: Option<Duration>,
    pub filter: Option<String>,
    pub exclude_filter: Option<String>,
    pub exclude_type: Vec<String>,
    pub proxy: Option<String>,
    pub dialer_proxy: Option<String>,
    pub overrides: ProxyOverride,
    pub size_limit: Option<u64>,
    pub header: Vec<(String, String)>,
    pub health_check: HealthCheckConfig,
    pub payload: Vec<serde_yaml::Value>,
}

/// A `proxy-name` rewrite from a proxy provider's `override` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyNameRewrite {
    pub pattern: String,
    pub target: String,
}

/// The `override` block of a `proxy-providers` entry. The fields the kernel
/// can apply are kept; the remaining pinned fields are rejected by name in
/// [`parse_proxy_providers`], never silently ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyOverride {
    pub udp: Option<bool>,
    pub skip_cert_verify: Option<bool>,
    pub dialer_proxy: Option<String>,
    pub additional_prefix: Option<String>,
    pub additional_suffix: Option<String>,
    pub proxy_name: Vec<ProxyNameRewrite>,
}

/// Geodata files that the configured rules need. Computed from inline rules,
/// sub-rules and inline rule-provider payloads; file/http provider entries add
/// their own references before the geodata directory is read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeodataRequirements {
    pub geosite_keys: BTreeSet<String>,
    pub geoip: bool,
    pub asn: bool,
}

impl GeodataRequirements {
    fn visit_matcher(&mut self, matcher: &Matcher) {
        match matcher {
            Matcher::GeoSite(value) => {
                self.geosite_keys.insert(value.clone());
            }
            Matcher::GeoIp { country, .. } => {
                if country.trim_start_matches('!').to_ascii_lowercase() != "lan" {
                    self.geoip = true;
                }
            }
            Matcher::IpAsn { .. } => self.asn = true,
            Matcher::And(rules) | Matcher::Or(rules) => {
                for rule in rules {
                    self.visit_matcher(&rule.matcher);
                }
            }
            Matcher::Not(rule) | Matcher::SubRule { gate: rule, .. } => {
                self.visit_matcher(&rule.matcher);
            }
            _ => {}
        }
    }

    pub fn merge(&mut self, other: GeodataRequirements) {
        self.geosite_keys.extend(other.geosite_keys);
        self.geoip |= other.geoip;
        self.asn |= other.asn;
    }

    /// Visit one rule, used by provider payloads after they are read.
    pub fn collect_rule(&mut self, rule: &Rule) {
        self.visit_matcher(&rule.matcher);
    }
}

/// Parsed, validated configuration.
#[derive(Debug, Clone, PartialEq)]
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
    /// Protocol outbounds usable as a rule target (DIRECT/REJECT stay built in).
    pub proxies: Vec<crate::proxies::Proxy>,
    /// `rule-providers` entries in declaration order.
    pub rule_providers: Vec<RuleProviderConfig>,
    /// `proxy-providers` entries in declaration order.
    pub proxy_providers: Vec<ProxyProviderConfig>,
    /// `sub-rules` used by `SUB-RULE`.
    pub sub_rules: BTreeMap<String, Vec<Rule>>,
    /// `geodata-mode: true` reads GeoIP.dat; false reads Country.mmdb.
    pub geodata_mode: bool,
    pub geodata_loader: String,
    pub geosite_matcher: String,
    pub geo_auto_update: bool,
    /// Global `authentication: ["user:pass", ...]` accepted by the inbound.
    pub inbound_users: Vec<(String, String)>,
    /// Extra root certificates (`tls.custom-cert` or the `custom-cert` directory
    /// of `tls.certificate`) used to verify outbound TLS instead of / besides
    /// the platform store.
    pub tls_roots: Vec<rustls_pki_types::CertificateDer<'static>>,
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
    /// Geodata files referenced by the inline rule list and sub-rules. Rule
    /// provider payloads add their own references when the providers are read.
    pub fn geodata_requirements(&self) -> GeodataRequirements {
        let mut requirements = GeodataRequirements::default();
        for rule in &self.rules {
            requirements.visit_matcher(&rule.matcher);
        }
        for rules in self.sub_rules.values() {
            for rule in rules {
                requirements.visit_matcher(&rule.matcher);
            }
        }
        for provider in &self.rule_providers {
            if provider.behavior == RuleBehavior::Classical {
                for line in &provider.payload {
                    // Invalid fallback entries are reported by the provider
                    // loader; collect only the references they mention.
                    if let Ok(rule) = parse_rule(line) {
                        requirements.visit_matcher(&rule.matcher);
                    }
                }
            }
        }
        requirements
    }

    /// Honest label of what this configuration enables; used by identity output.
    pub fn feature_summary(&self) -> String {
        let protocols = if self.proxies.is_empty() {
            "none".to_string()
        } else {
            self.proxies
                .iter()
                .map(|p| format!("{}={}", p.name, p.type_name()))
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "mixed-inbound(tcp,http-connect,socks5); rules=inline({} entries); rule-providers={}; proxy-providers={}; sub-rules={}; outbounds=DIRECT,REJECT; protocols={protocols}; dns=none",
            self.rules.len(),
            self.rule_providers.len(),
            self.proxy_providers.len(),
            self.sub_rules.len()
        )
    }

    /// Display name of a rule action (proxy names come from the list).
    pub fn action_name(&self, action: Action) -> String {
        match action {
            Action::Direct | Action::Reject | Action::RejectDrop => action.as_str().to_string(),
            Action::Proxy(index) => self
                .proxies
                .get(index)
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "<missing proxy>".to_string()),
        }
    }
}

/// Result of `load_config`: the configuration plus warnings for values that
/// are accepted only in their non-default form.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: Config,
    pub warnings: Vec<String>,
}

/// `tun`/`sniffer` enabled flag. A missing `enable` is false in both pinned
/// schemas; a non-mapping value is an invalid configuration.
fn block_enabled(
    value: &serde_yaml::Value,
    path: &str,
    key: &str,
) -> Result<bool, ConfigError> {
    match value {
        serde_yaml::Value::Null => Ok(false),
        serde_yaml::Value::Bool(flag) => Ok(*flag),
        serde_yaml::Value::Mapping(mapping) => {
            optional_bool(mapping, "enable")
                .map(|flag| flag.unwrap_or(false))
                .map_err(|error| config_error_with_prefix(error, &format!("{path}: {key}")))
        }
        other => Err(ConfigError::InvalidValue(format!(
            "{path}: {key} must be a mapping or boolean, found {}",
            kind_of(other)
        ))),
    }
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
    let mut proxies_value = None;
    let mut rule_providers_value = None;
    let mut proxy_providers_value = None;
    let mut sub_rules_value = None;
    let mut authentication = Vec::new();
    let mut tls_roots: Vec<rustls_pki_types::CertificateDer<'static>> = Vec::new();
    let mut listen_port: Option<u16> = None;
    let mut requested_port: Option<u16> = None;
    // Mihomo treats port 0 as "this listener is disabled". Remember that so a
    // configuration whose only ports are 0 fails by name instead of binding an
    // ephemeral port the app never saw.
    let mut listener_disabled = false;
    let mut allow_lan: Option<bool> = None;
    let mut bind: Option<String> = None;
    let mut mode = None;
    let mut log_level = None;
    let mut geodata_mode = false;
    let mut geodata_loader = "memconservative".to_string();
    let mut geosite_matcher = "succinct".to_string();
    let mut geo_auto_update = false;

    for (key, value) in mapping.iter() {
        let key = key.as_str().ok_or_else(|| {
            ConfigError::Invalid(format!(
                "{path}: top-level key must be a string, found {key:?}"
            ))
        })?;
        match key {
            "mixed-port" => {
                let port = parse_port(value, path, key)?;
                if port == 0 {
                    listener_disabled = true;
                    listen_port = None;
                    warnings.push("mixed-port 0 disables the listener".to_string());
                } else {
                    listen_port = Some(port);
                }
            }
            "port" => {
                let port = parse_port(value, path, key)?;
                if port == 0 {
                    listener_disabled = true;
                } else {
                    requested_port.get_or_insert(port);
                }
            }
            "socks-port" => {
                // Legacy alias is only honoured when nothing else set the listener.
                let port = parse_port(value, path, key)?;
                if port == 0 {
                    listener_disabled = true;
                    warnings.push("socks-port 0 disables the legacy listener".to_string());
                } else if listen_port.is_none() {
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
            "proxies" => proxies_value = Some(value),
            "rule-providers" => rule_providers_value = Some(value),
            "proxy-providers" => proxy_providers_value = Some(value),
            "sub-rules" => sub_rules_value = Some(value),
            "geodata-mode" => geodata_mode = parse_bool(value, path, key)?,
            "geodata-loader" => {
                let loader = parse_string(value, path, key)?.to_ascii_lowercase();
                match loader.as_str() {
                    "standard" | "memconservative" => geodata_loader = loader,
                    "memc" => geodata_loader = "memconservative".to_string(),
                    other => {
                        return Err(ConfigError::Unsupported(format!(
                            "geodata-loader '{other}' (standard and memconservative are implemented)"
                        )))
                    }
                }
            }
            "geosite-matcher" => {
                let matcher = parse_string(value, path, key)?.to_ascii_lowercase();
                match matcher.as_str() {
                    "succinct" | "mph" | "hybrid" => geosite_matcher = matcher,
                    // The pinned engine silently falls back to succinct for an
                    // unknown name; keep that behaviour but say so.
                    other => warnings.push(format!(
                        "geosite-matcher '{other}' is not a pinned value; using succinct"
                    )),
                }
            }
            "geo-auto-update" => {
                geo_auto_update = parse_bool(value, path, key)?;
                if geo_auto_update {
                    return Err(ConfigError::Unsupported(
                        "geo-auto-update: true (automatic geodata download is not implemented; update providers through the kernel API and restart with the new files)"
                            .to_string(),
                    ));
                }
            }
            "geo-update-interval" => {
                let interval = value
                    .as_u64()
                    .ok_or_else(|| {
                        ConfigError::InvalidValue(format!(
                            "{path}: geo-update-interval must be a non-negative integer"
                        ))
                    })?;
                if interval > 0 && !geo_auto_update {
                    warnings.push(
                        "geo-update-interval has no effect while geo-auto-update is false"
                            .to_string(),
                    );
                }
            }
            "authentication" => authentication = parse_authentication(value, path)?,
            "tls" => tls_roots = parse_tls(value, path)?,
            // Inert forms of blocks the native kernel does not serve. Billow's
            // effective YAML commonly carries `tun: {enable: false}`,
            // `sniffer: {enable: false}` and `geox-url`; accepting the
            // do-nothing form keeps a valid upstream file loadable, but an
            // enabled block is a named rejection instead of a silent no-op.
            "tun" | "sniffer" => {
                if block_enabled(value, path, key)? {
                    let owner = if key == "tun" { "device/TUN is T6/T7" } else { "sniffer is T22" };
                    return Err(ConfigError::Unsupported(format!(
                        "top-level key '{key}' with enable: true is not implemented ({owner})"
                    )));
                }
                warnings.push(format!(
                    "'{key}' is present but disabled; this kernel has no {key} implementation, so the block is inert"
                ));
            }
            "geox-url" => {
                let mapping = value.as_mapping().ok_or_else(|| {
                    ConfigError::InvalidValue(format!("{path}: geox-url must be a mapping"))
                })?;
                if mapping.is_empty() {
                    warnings.push("geox-url is empty and inert".to_string());
                } else {
                    warnings.push(
                        "geox-url is recorded but no downloader runs (geo-auto-update: true is rejected by name)"
                            .to_string(),
                    );
                }
            }
            _ => {
                if KNOWN_UNSUPPORTED_TOP_LEVEL_KEYS.contains(&key) {
                    let boundary = match key {
                        "proxy-groups" => " (proxy groups and selection are T23)",
                        "dns" | "hosts" => " (DNS/hosts are T22)",
                        "external-controller" | "external-controller-unix"
                        | "external-controller-tls" | "external-controller-pipe" => {
                            " (the control API is T25)"
                        }
                        "find-process-mode" => " (process lookup is T22/T6)",
                        _ => "",
                    };
                    return Err(ConfigError::Unsupported(format!(
                        "top-level key '{key}' is not implemented by the Rust kernel slice{boundary}"
                    )));
                }
                // Not a Mihomo top-level key: Mihomo's decoder tolerates extra
                // keys (fixtures carry `x-kernel-compat`, newer versions add
                // keys), so the same file must load here.
                warnings.push(format!("ignored unknown top-level key '{key}'"));
            }
        }
    }

    let port = match listen_port {
        Some(port) => port,
        None if listener_disabled => {
            return Err(ConfigError::Unsupported(
                "no listener port is enabled: mixed-port/port/socks-port are 0 or unset while a 0 value disabled the default (this kernel has no TUN/redirect path yet)"
                    .to_string(),
            ))
        }
        None => DEFAULT_PORT,
    };
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

    let proxies = match proxies_value {
        None => Vec::new(),
        Some(value) => crate::proxies::parse_proxies(value)?,
    };
    let proxy_providers = match proxy_providers_value {
        None => Vec::new(),
        Some(value) => parse_proxy_providers(value, path)?,
    };
    let rule_providers = match rule_providers_value {
        None => Vec::new(),
        Some(value) => parse_rule_providers(value, path)?,
    };
    let provider_names = rule_providers
        .iter()
        .map(|provider| provider.name.clone())
        .collect::<BTreeSet<_>>();

    let sub_rule_names = match sub_rules_value {
        None => BTreeSet::new(),
        Some(value) => {
            let mapping = value.as_mapping().ok_or_else(|| {
                ConfigError::InvalidValue(format!("{path}: sub-rules must be a mapping"))
            })?;
            let mut names = BTreeSet::new();
            for key in mapping.keys() {
                let name = key.as_str().ok_or_else(|| {
                    ConfigError::InvalidValue(format!("{path}: sub-rules keys must be strings"))
                })?;
                if name.is_empty() {
                    return Err(ConfigError::InvalidValue(format!(
                        "{path}: sub-rules name must not be empty"
                    )));
                }
                names.insert(name.to_string());
            }
            names
        }
    };

    let context = RuleContext {
        proxies: &proxies,
        providers: &provider_names,
        sub_rules: &sub_rule_names,
    };
    let sub_rules = match sub_rules_value {
        None => BTreeMap::new(),
        Some(value) => parse_sub_rules(value, path, &context)?,
    };
    verify_sub_rule_cycles(&sub_rules)?;

    let (rules, rules_source) = match rules_value {
        None => (Vec::new(), RulesSource::None),
        Some(value) => (parse_rules(value, path, &context, "rules")?, RulesSource::Inline),
    };

    // A warning, not a rejection: the pinned engine resolves names for these
    // rules, while this kernel only sees the request metadata (DNS is T22).
    if rules.iter().any(rule_needs_resolution) || sub_rules.values().flatten().any(rule_needs_resolution) {
        warnings.push(
            "GEOIP/IP-ASN/IP-CIDR rules match the destination only when it is already an IP; name resolution is T22 (DNS/hosts)".to_string(),
        );
    }

    let config = Config {
        listen: SocketAddr::new(host, port),
        port_rebound_from: requested_port.filter(|p| Some(*p) != listen_port),
        mode,
        log_level,
        empty_rules: rules.is_empty() && rules_source == RulesSource::None,
        rules,
        rules_source,
        proxies,
        rule_providers,
        proxy_providers,
        sub_rules,
        geodata_mode,
        geodata_loader,
        geosite_matcher,
        geo_auto_update,
        inbound_users: authentication,
        tls_roots,
        digest,
    };
    Ok(LoadedConfig { config, warnings })
}

fn rule_needs_resolution(rule: &Rule) -> bool {
    match &rule.matcher {
        Matcher::GeoIp {
            country, no_resolve, ..
        } => {
            country.trim_start_matches('!').to_ascii_lowercase() != "lan" && !no_resolve
        }
        Matcher::IpAsn { no_resolve, .. } => !no_resolve,
        Matcher::IpCidr { no_resolve, .. } => !no_resolve,
        Matcher::IpSuffix { no_resolve, .. } => !no_resolve,
        Matcher::RuleSet { no_resolve, .. } => !no_resolve,
        Matcher::And(rules) | Matcher::Or(rules) => rules.iter().any(rule_needs_resolution),
        Matcher::Not(rule) | Matcher::SubRule { gate: rule, .. } => rule_needs_resolution(rule),
        _ => false,
    }
}

/// Names visible to a rule line while it is parsed.
struct RuleContext<'a> {
    proxies: &'a [crate::proxies::Proxy],
    providers: &'a BTreeSet<String>,
    sub_rules: &'a BTreeSet<String>,
}

impl RuleContext<'_> {
    fn empty() -> RuleContext<'static> {
        static EMPTY: std::sync::OnceLock<(BTreeSet<String>, BTreeSet<String>)> =
            std::sync::OnceLock::new();
        let (providers, sub_rules) = EMPTY.get_or_init(|| (BTreeSet::new(), BTreeSet::new()));
        RuleContext {
            proxies: &[],
            providers,
            sub_rules,
        }
    }
}

fn parse_rules(
    value: &serde_yaml::Value,
    path: &str,
    context: &RuleContext<'_>,
    label: &str,
) -> Result<Vec<Rule>, ConfigError> {
    let seq = value
        .as_sequence()
        .ok_or_else(|| ConfigError::Invalid(format!("{path}: {label} must be a list")))?;
    let mut rules = Vec::with_capacity(seq.len());
    for (index, item) in seq.iter().enumerate() {
        let line = item.as_str().ok_or_else(|| {
            ConfigError::Invalid(format!(
                "{path}: {label}[{index}] must be a string, found {}",
                kind_of(item)
            ))
        })?;
        rules.push(parse_rule_line(line, true, context).map_err(|e| {
            let prefix = format!("{label}[{index}] ('{line}')");
            config_error_with_prefix(e, &prefix)
        })?);
    }
    if let Some(match_index) = rules
        .iter()
        .position(|rule| rule.matcher == Matcher::Match)
    {
        if match_index != rules.len() - 1 {
            return Err(ConfigError::InvalidValue(format!(
                "{path}: MATCH must be the last rule (found at {label}[{match_index}] of {})",
                rules.len()
            )));
        }
    }
    Ok(rules)
}

fn parse_sub_rules(
    value: &serde_yaml::Value,
    path: &str,
    context: &RuleContext<'_>,
) -> Result<BTreeMap<String, Vec<Rule>>, ConfigError> {
    let mapping = value
        .as_mapping()
        .ok_or_else(|| ConfigError::InvalidValue(format!("{path}: sub-rules must be a mapping")))?;
    let mut out = BTreeMap::new();
    for (key, rules) in mapping {
        let name = key.as_str().ok_or_else(|| {
            ConfigError::InvalidValue(format!("{path}: sub-rules keys must be strings"))
        })?;
        out.insert(
            name.to_string(),
            parse_rules(rules, path, context, &format!("sub-rules[{name}]"))?,
        );
    }
    Ok(out)
}

fn verify_sub_rule_cycles(sub_rules: &BTreeMap<String, Vec<Rule>>) -> Result<(), ConfigError> {
    fn visit(
        name: &str,
        sub_rules: &BTreeMap<String, Vec<Rule>>,
        stack: &mut Vec<String>,
    ) -> Result<(), ConfigError> {
        if stack.iter().any(|entry| entry == name) {
            return Err(ConfigError::InvalidValue(format!(
                "sub-rules contain a circular reference: {} -> {name}",
                stack.join(" -> ")
            )));
        }
        stack.push(name.to_string());
        if let Some(rules) = sub_rules.get(name) {
            for rule in rules {
                visit_matcher_rules(&rule.matcher, &mut |matcher| match matcher {
                    Matcher::SubRule { name, .. } => visit(name, sub_rules, stack),
                    _ => Ok(()),
                })?;
            }
        }
        stack.pop();
        Ok(())
    }
    for name in sub_rules.keys() {
        visit(name, sub_rules, &mut Vec::new())?;
    }
    Ok(())
}

fn visit_matcher_rules(
    matcher: &Matcher,
    visit: &mut dyn FnMut(&Matcher) -> Result<(), ConfigError>,
) -> Result<(), ConfigError> {
    visit(matcher)?;
    match matcher {
        Matcher::And(rules) | Matcher::Or(rules) => {
            for rule in rules {
                visit_matcher_rules(&rule.matcher, visit)?;
            }
        }
        Matcher::Not(rule) | Matcher::SubRule { gate: rule, .. } => {
            visit_matcher_rules(&rule.matcher, visit)?;
        }
        _ => {}
    }
    Ok(())
}

fn config_error_with_prefix(error: ConfigError, prefix: &str) -> ConfigError {
    match error {
        ConfigError::Unsupported(message) => {
            ConfigError::Unsupported(format!("{prefix}: {message}"))
        }
        ConfigError::InvalidValue(message) => {
            ConfigError::InvalidValue(format!("{prefix}: {message}"))
        }
        ConfigError::Invalid(message) => ConfigError::Invalid(format!("{prefix}: {message}")),
        ConfigError::ConfigFailed(message) => {
            ConfigError::ConfigFailed(format!("{prefix}: {message}"))
        }
    }
}

/// Parse one clash rule line such as `DOMAIN-SUFFIX,example.com,REJECT` or
/// `IP-CIDR,10.0.0.0/8,DIRECT,no-resolve`.
pub fn parse_rule(line: &str) -> Result<Rule, ConfigError> {
    parse_rule_line(line, true, &RuleContext::empty())
}

/// Like [`parse_rule`] but resolves a rule outbound against the configured proxy names.
pub fn parse_rule_with_proxies(
    line: &str,
    proxies: &[crate::proxies::Proxy],
) -> Result<Rule, ConfigError> {
    let context = RuleContext {
        proxies,
        ..RuleContext::empty()
    };
    parse_rule_line(line, true, &context)
}

/// Parse a provider entry (no target field). `PROCESS-*-REGEX`, `DOMAIN-REGEX`
/// and the logic types keep commas in their payload.
/// Provider entries may themselves reference another provider with RULE-SET;
/// pass the registry names so those entries are not skipped as malformed.
pub(crate) fn parse_rule_without_target_in(
    line: &str,
    providers: &BTreeSet<String>,
) -> Result<Rule, ConfigError> {
    let context = RuleContext {
        providers,
        ..RuleContext::empty()
    };
    parse_rule_line(line, false, &context)
}

fn split_rule_fields(line: &str) -> Vec<String> {
    line.split(',')
        .map(|field| {
            field
                .trim()
                .trim_matches(|c| c == '"' || c == '\'')
                .to_string()
        })
        .collect()
}

fn parse_rule_line(
    line: &str,
    need_target: bool,
    context: &RuleContext<'_>,
) -> Result<Rule, ConfigError> {
    let parts = split_rule_fields(line);
    let rule_type = parts
        .first()
        .map(|part| part.to_ascii_uppercase())
        .unwrap_or_default();
    if !SUPPORTED_RULE_TYPES.contains(&rule_type.as_str()) {
        return Err(ConfigError::Unsupported(format!(
            "rule type '{rule_type}'"
        )));
    }
    let len = parts.len();
    let comma_payload = matches!(
        rule_type.as_str(),
        "AND"
            | "OR"
            | "NOT"
            | "SUB-RULE"
            | "DOMAIN-REGEX"
            | "PROCESS-NAME-REGEX"
            | "PROCESS-PATH-REGEX"
    );
    let (payload, target, params): (String, Option<&str>, &[String]) =
        if rule_type == "MATCH" {
            if len != 2 {
                return Err(ConfigError::InvalidValue(format!(
                    "MATCH takes <action>, got '{line}'"
                )));
            }
            (String::new(), need_target.then_some(parts[1].as_str()), &[])
        } else if comma_payload {
            if len < 2 {
                return Err(ConfigError::InvalidValue(format!(
                    "{rule_type} takes <payload>{}, got '{line}'",
                    if need_target { ",<action>" } else { "" }
                )));
            }
            if need_target {
                (
                    parts[1..len - 1].join(","),
                    Some(parts[len - 1].as_str()),
                    &[],
                )
            } else {
                (parts[1..].join(","), None, &[])
            }
        } else {
            if len < 2 || (need_target && len < 3) {
                return Err(ConfigError::InvalidValue(format!(
                    "{rule_type} takes <value>{}, got '{line}'",
                    if need_target { ",<action>" } else { "" }
                )));
            }
            let payload = parts[1].clone();
            if need_target {
                (
                    payload,
                    Some(parts[2].as_str()),
                    if len > 3 { &parts[3..] } else { &[] },
                )
            } else {
                (payload, None, if len > 2 { &parts[2..] } else { &[] })
            }
        };

    let action_params = match rule_type.as_str() {
        "GEOIP" | "IP-ASN" | "IP-CIDR" | "IP-CIDR6" | "IP-SUFFIX" | "RULE-SET" => true,
        _ => false,
    };
    let (is_src, no_resolve) = parse_rule_params(&rule_type, params, action_params)?;
    let action = match target {
        None => Action::Direct,
        // SUB-RULE's target is the sub-rule list name; the list selects the
        // outbound, so the outer action field is unused.
        Some(_) if rule_type == "SUB-RULE" => Action::Direct,
        Some(target) => parse_action_with(target, context.proxies)?,
    };

    let matcher = match rule_type.as_str() {
        "MATCH" => Matcher::Match,
        "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "DOMAIN-WILDCARD" => {
            if payload.is_empty() {
                return Err(ConfigError::InvalidValue(format!(
                    "{rule_type} needs a non-empty domain"
                )));
            }
            let value = payload.to_ascii_lowercase();
            match rule_type.as_str() {
                "DOMAIN" => Matcher::Domain(value),
                "DOMAIN-SUFFIX" => Matcher::DomainSuffix(value),
                "DOMAIN-KEYWORD" => Matcher::DomainKeyword(value),
                _ => Matcher::DomainWildcard(value),
            }
        }
        "DOMAIN-REGEX" => {
            validate_regex(&payload)?;
            Matcher::DomainRegex(payload)
        }
        "GEOSITE" => {
            if payload.is_empty() {
                return Err(ConfigError::InvalidValue(
                    "GEOSITE needs a list name".to_string(),
                ));
            }
            Matcher::GeoSite(payload)
        }
        "GEOIP" | "SRC-GEOIP" => {
            if payload.is_empty() {
                return Err(ConfigError::InvalidValue(
                    "GEOIP needs a country code".to_string(),
                ));
            }
            Matcher::GeoIp {
                country: payload.to_ascii_lowercase(),
                source: rule_type == "SRC-GEOIP" || is_src,
                no_resolve: no_resolve || rule_type == "SRC-GEOIP",
            }
        }
        "IP-ASN" | "SRC-IP-ASN" => {
            if !payload.chars().all(|c| c.is_ascii_digit()) || payload.is_empty() {
                return Err(ConfigError::InvalidValue(format!(
                    "{rule_type} needs a numeric ASN, got '{payload}'"
                )));
            }
            Matcher::IpAsn {
                asn: payload,
                source: rule_type == "SRC-IP-ASN" || is_src,
                no_resolve: no_resolve || rule_type == "SRC-IP-ASN",
            }
        }
        "IP-CIDR" | "IP-CIDR6" | "SRC-IP-CIDR" => {
            let net = ipnet_like::IpNet::from_str(&payload).map_err(|e| {
                ConfigError::InvalidValue(format!("{rule_type} '{payload}': {e}"))
            })?;
            if rule_type == "IP-CIDR6" && net.is_v4() {
                return Err(ConfigError::InvalidValue(format!(
                    "IP-CIDR6 '{payload}' must be an IPv6 CIDR"
                )));
            }
            Matcher::IpCidr {
                net,
                source: rule_type == "SRC-IP-CIDR" || is_src,
                no_resolve: no_resolve || rule_type == "SRC-IP-CIDR",
            }
        }
        "IP-SUFFIX" | "SRC-IP-SUFFIX" => {
            let net = ipnet_like::IpNet::from_str(&payload).map_err(|e| {
                ConfigError::InvalidValue(format!("{rule_type} '{payload}': {e}"))
            })?;
            Matcher::IpSuffix {
                net,
                source: rule_type == "SRC-IP-SUFFIX" || is_src,
                no_resolve: no_resolve || rule_type == "SRC-IP-SUFFIX",
            }
        }
        "SRC-PORT" | "DST-PORT" | "IN-PORT" => {
            let kind = match rule_type.as_str() {
                "SRC-PORT" => PortKind::Src,
                "DST-PORT" => PortKind::Dst,
                _ => PortKind::In,
            };
            Matcher::Port {
                kind,
                ranges: parse_port_ranges(&payload)?,
            }
        }
        "NETWORK" => {
            let network = match payload.to_ascii_uppercase().as_str() {
                "TCP" => NetworkKind::Tcp,
                "UDP" => NetworkKind::Udp,
                other => {
                    return Err(ConfigError::Unsupported(format!(
                        "NETWORK '{other}' (only TCP and UDP are implemented)"
                    )))
                }
            };
            Matcher::Network(network)
        }
        "IN-TYPE" => Matcher::InType(parse_in_types(&payload)?),
        "PROCESS-NAME" | "PROCESS-PATH" => Matcher::Process {
            kind: if rule_type == "PROCESS-NAME" {
                ProcessKind::Name
            } else {
                ProcessKind::Path
            },
            pattern: payload,
            regex: false,
        },
        "PROCESS-NAME-REGEX" | "PROCESS-PATH-REGEX" => {
            validate_regex(&payload)?;
            Matcher::Process {
                kind: if rule_type == "PROCESS-NAME-REGEX" {
                    ProcessKind::Name
                } else {
                    ProcessKind::Path
                },
                pattern: payload,
                regex: true,
            }
        }
        "PROCESS-NAME-WILDCARD" | "PROCESS-PATH-WILDCARD" => {
            if payload.is_empty() {
                return Err(ConfigError::InvalidValue(format!(
                    "{rule_type} needs a non-empty pattern"
                )));
            }
            Matcher::ProcessWildcard {
                kind: if rule_type == "PROCESS-NAME-WILDCARD" {
                    ProcessKind::Name
                } else {
                    ProcessKind::Path
                },
                pattern: payload,
            }
        }
        "RULE-SET" => {
            if !context.providers.contains(&payload) {
                return Err(ConfigError::ConfigFailed(format!(
                    "RULE-SET references undefined rule-provider '{payload}'"
                )));
            }
            Matcher::RuleSet {
                name: payload,
                source: is_src,
                no_resolve,
            }
        }
        "SUB-RULE" => {
            let name = target.ok_or_else(|| {
                ConfigError::InvalidValue("SUB-RULE needs a target action".to_string())
            })?;
            if !context.sub_rules.contains(name) {
                return Err(ConfigError::ConfigFailed(format!(
                    "SUB-RULE references undefined sub-rule '{name}'"
                )));
            }
            let gate_source = payload
                .strip_prefix('(')
                .and_then(|rest| rest.strip_suffix(')'))
                .unwrap_or(payload.as_str());
            let gate = parse_rule_line(gate_source, false, context)?;
            if matches!(gate.matcher, Matcher::Match | Matcher::SubRule { .. }) {
                return Err(ConfigError::Unsupported(
                    "SUB-RULE gate must be a non-MATCH, non-SUB-RULE rule".to_string(),
                ));
            }
            Matcher::SubRule {
                gate: Box::new(gate),
                name: name.to_string(),
            }
        }
        "AND" | "OR" | "NOT" => {
            let groups = parse_logic_groups(&payload)?;
            let mut rules = Vec::with_capacity(groups.len());
            for group in &groups {
                let inner = parse_rule_line(group, false, context)?;
                if matches!(inner.matcher, Matcher::Match | Matcher::SubRule { .. }) {
                    return Err(ConfigError::Unsupported(format!(
                        "{rule_type} cannot contain MATCH or SUB-RULE"
                    )));
                }
                rules.push(inner);
            }
            match rule_type.as_str() {
                "NOT" => {
                    if rules.len() != 1 {
                        return Err(ConfigError::InvalidValue(format!(
                            "NOT must contain exactly one rule, got {}",
                            rules.len()
                        )));
                    }
                    Matcher::Not(Box::new(rules.remove(0)))
                }
                "AND" => Matcher::And(rules),
                _ => Matcher::Or(rules),
            }
        }
        _ => unreachable!("rule type checked above"),
    };

    Ok(Rule {
        matcher,
        action,
        no_resolve,
    })
}

fn parse_rule_params(
    rule_type: &str,
    params: &[String],
    action_params: bool,
) -> Result<(bool, bool), ConfigError> {
    let mut is_src = false;
    let mut no_resolve = false;
    let mut names = Vec::new();
    for param in params {
        match param.as_str() {
            "" => {}
            "src" if action_params => is_src = true,
            "no-resolve" if action_params => no_resolve = true,
            other => names.push(other.to_string()),
        }
    }
    if !names.is_empty() {
        return Err(ConfigError::Unsupported(format!(
            "rule parameter(s) {} on {rule_type}",
            names.join(", ")
        )));
    }
    if is_src {
        no_resolve = true;
    }
    Ok((is_src, no_resolve))
}

fn validate_regex(pattern: &str) -> Result<(), ConfigError> {
    regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        // The pinned engine's regexp2 supports look-around; Rust's regex does
        // not. Reject those constructs with the pattern named rather than load
        // a rule that can never match.
        .build()
        .map(|_| ())
        .map_err(|e| {
            ConfigError::Unsupported(format!("rule regex {pattern:?} is not supported: {e}"))
        })
}

/// Port payloads accept `200`, `200-400`, `200/302`, comma lists and `*`.
fn parse_port_ranges(payload: &str) -> Result<Vec<PortRange>, ConfigError> {
    let text = payload.trim();
    if text.is_empty() {
        return Err(ConfigError::InvalidValue(
            "port rule needs a port or range".to_string(),
        ));
    }
    if text == "*" {
        return Ok(Vec::new());
    }
    let normalized = text.replace(',', "/");
    let mut ranges = Vec::new();
    for part in normalized.split('/') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (start, end) = match part.split_once('-') {
            Some((start, end)) => (
                parse_port_number(start)?,
                parse_port_number(end)?,
            ),
            None => {
                let value = parse_port_number(part)?;
                (value, value)
            }
        };
        if start > end {
            return Err(ConfigError::InvalidValue(format!(
                "port range '{part}' starts after it ends"
            )));
        }
        ranges.push((start, end));
    }
    if ranges.is_empty() {
        return Err(ConfigError::InvalidValue(format!(
            "port rule '{payload}' has no range"
        )));
    }
    if ranges.len() > 28 {
        return Err(ConfigError::InvalidValue(
            "port rule has more than 28 ranges".to_string(),
        ));
    }
    Ok(ranges)
}

fn parse_port_number(text: &str) -> Result<u16, ConfigError> {
    text.trim().parse::<u16>().map_err(|_| {
        ConfigError::InvalidValue(format!("port '{text}' is not an integer 0..=65535"))
    })
}

fn parse_in_types(payload: &str) -> Result<Vec<InType>, ConfigError> {
    let mut types = Vec::new();
    for part in payload.split('/') {
        let name = part.trim().to_ascii_uppercase();
        match name.as_str() {
            "HTTP" => types.push(InType::Http),
            "HTTPS" => types.push(InType::Https),
            "SOCKS5" => types.push(InType::Socks5),
            "SOCKS" => {
                types.push(InType::Socks5);
            }
            other => {
                return Err(ConfigError::Unsupported(format!(
                    "IN-TYPE '{other}' (this kernel serves HTTP CONNECT and SOCKS5 on the mixed listener; TUN/redir/tproxy and other listeners are T6/T25)"
                )))
            }
        }
    }
    if types.is_empty() {
        return Err(ConfigError::InvalidValue(
            "IN-TYPE needs at least one listener type".to_string(),
        ));
    }
    Ok(types)
}

/// Split `((DOMAIN,a.com),(DOMAIN,b.com))` into its top-level parenthesized
/// groups, rejecting unbalanced input.
fn parse_logic_groups(payload: &str) -> Result<Vec<String>, ConfigError> {
    let payload = payload.trim();
    if !payload.starts_with('(') || !payload.ends_with(')') {
        return Err(ConfigError::InvalidValue(format!(
            "logic rule payload must be parenthesized: '{payload}'"
        )));
    }
    let mut groups = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (index, ch) in payload.char_indices() {
        match ch {
            '(' => {
                depth += 1;
                if depth == 2 {
                    start = index + 1;
                }
            }
            ')' => {
                depth = depth.checked_sub(1).ok_or_else(|| {
                    ConfigError::InvalidValue(format!("logic rule '{payload}' has an extra ')'"))
                })?;
                if depth == 1 {
                    groups.push(payload[start..index].to_string());
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(ConfigError::InvalidValue(format!(
            "logic rule '{payload}' is missing ')'"
        )));
    }
    if groups.is_empty() {
        return Err(ConfigError::InvalidValue(format!(
            "logic rule '{payload}' contains no sub-rule"
        )));
    }
    Ok(groups)
}

fn parse_action_with(raw: &str, proxies: &[crate::proxies::Proxy]) -> Result<Action, ConfigError> {
    match raw {
        "DIRECT" => Ok(Action::Direct),
        "REJECT" => Ok(Action::Reject),
        // Mihomo closes a REJECT-DROP connection without an inbound failure
        // reply; the engine maps this variant accordingly.
        "REJECT-DROP" => Ok(Action::RejectDrop),
        "" => Err(ConfigError::InvalidValue(
            "missing outbound in rule".to_string(),
        )),
        "PASS" | "PASS-RULE" => Err(ConfigError::Unsupported(format!(
            "outbound '{raw}' (PASS markers are not implemented)"
        ))),
        other => match proxies.iter().position(|p| p.name == other) {
            Some(index) => Ok(Action::Proxy(index)),
            // A named outbound that is not a configured proxy (groups, providers,
            // built-ins of other tasks) is outside this task's scope.
            None => Err(ConfigError::Unsupported(format!(
                "outbound '{other}' is not a configured proxy (proxy groups are T23; DIRECT, REJECT, REJECT-DROP and inline proxies are available)"
            ))),
        },
    }
}

fn parse_rule_providers(
    value: &serde_yaml::Value,
    path: &str,
) -> Result<Vec<RuleProviderConfig>, ConfigError> {
    let mapping = value.as_mapping().ok_or_else(|| {
        ConfigError::InvalidValue(format!("{path}: rule-providers must be a mapping"))
    })?;
    let mut providers = Vec::with_capacity(mapping.len());
    for (key, entry) in mapping {
        let name = key.as_str().ok_or_else(|| {
            ConfigError::InvalidValue(format!("{path}: rule-providers keys must be strings"))
        })?;
        if name.is_empty() {
            return Err(ConfigError::InvalidValue(format!(
                "{path}: rule-providers name must not be empty"
            )));
        }
        let location = format!("{path}: rule-providers.{name}");
        let fields = entry.as_mapping().ok_or_else(|| {
            ConfigError::InvalidValue(format!("{location} must be a mapping"))
        })?;
        let behavior = match optional_string(fields, "behavior")?.as_deref() {
            Some("domain") => RuleBehavior::Domain,
            Some("ipcidr") => RuleBehavior::IpCidr,
            Some("classical") => RuleBehavior::Classical,
            Some(other) => {
                return Err(ConfigError::Unsupported(format!(
                    "{location}: behavior '{other}' (domain, ipcidr and classical are implemented)"
                )))
            }
            None => {
                return Err(ConfigError::InvalidValue(format!(
                    "{location}: behavior is required"
                )))
            }
        };
        let format = match optional_string(fields, "format")?.as_deref() {
            None | Some("") | Some("yaml") => RuleFormat::Yaml,
            Some("text") => RuleFormat::Text,
            Some("mrs") => RuleFormat::Mrs,
            Some(other) => {
                return Err(ConfigError::Unsupported(format!(
                    "{location}: format '{other}' (yaml, text and mrs are implemented)"
                )))
            }
        };
        let vehicle = parse_provider_vehicle(fields, &location)?;
        // The pinned schema has `path-in-bundle` (a 7z bundle entry). This
        // kernel has no bundle reader, so a set value is a named rejection
        // rather than a silently ignored key.
        if let Some(path_in_bundle) = optional_string(fields, "path-in-bundle")? {
            if !path_in_bundle.trim().is_empty() {
                return Err(ConfigError::Unsupported(format!(
                    "{location}: path-in-bundle '{path_in_bundle}' is not implemented (no BundleMRS.7z reader)"
                )));
            }
        }
        let interval = optional_seconds(fields, "interval")?;
        let payload = optional_string_list(fields, "payload")?;
        let header = parse_provider_header(fields, &location)?;
        let proxy = optional_string(fields, "proxy")?;
        let size_limit = optional_positive_int(fields, "size-limit")?;
        providers.push(RuleProviderConfig {
            name: name.to_string(),
            behavior,
            format,
            vehicle,
            interval,
            payload,
            header,
            proxy,
            size_limit,
        });
    }
    Ok(providers)
}

fn parse_proxy_providers(
    value: &serde_yaml::Value,
    path: &str,
) -> Result<Vec<ProxyProviderConfig>, ConfigError> {
    let mapping = value.as_mapping().ok_or_else(|| {
        ConfigError::InvalidValue(format!("{path}: proxy-providers must be a mapping"))
    })?;
    let mut providers = Vec::with_capacity(mapping.len());
    for (key, entry) in mapping {
        let name = key.as_str().ok_or_else(|| {
            ConfigError::InvalidValue(format!("{path}: proxy-providers keys must be strings"))
        })?;
        if name.is_empty() {
            return Err(ConfigError::InvalidValue(format!(
                "{path}: proxy-providers name must not be empty"
            )));
        }
        let location = format!("{path}: proxy-providers.{name}");
        let fields = entry.as_mapping().ok_or_else(|| {
            ConfigError::InvalidValue(format!("{location} must be a mapping"))
        })?;
        let vehicle = parse_provider_vehicle(fields, &location)?;
        let interval = optional_seconds(fields, "interval")?;
        // Pinned `NewProxiesParser` splits both filters on a backtick and
        // compiles every piece as its own regexp.
        let filter = optional_string(fields, "filter")?;
        if let Some(pattern) = &filter {
            validate_provider_filter(pattern, &location, "filter")?;
        }
        let exclude_filter = optional_string(fields, "exclude-filter")?;
        if let Some(pattern) = &exclude_filter {
            validate_provider_filter(pattern, &location, "exclude-filter")?;
        }
        // `exclude-type` is a `|`-separated list in the pinned schema.
        let exclude_type = optional_string(fields, "exclude-type")?
            .map(|types| {
                types
                    .split('|')
                    .map(|value| value.trim().to_ascii_lowercase())
                    .filter(|value| !value.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if let Some(secret) = optional_string(fields, "age-secret-key")? {
            if !secret.trim().is_empty() {
                return Err(ConfigError::Unsupported(format!(
                    "{location}: age-secret-key is not implemented (age-encrypted provider payloads cannot be decrypted)"
                )));
            }
        }
        let overrides = parse_proxy_override(fields, &location)?;
        let health_check = parse_health_check(fields, &location)?;
        let payload = match optional_value(fields, "payload")? {
            None => Vec::new(),
            Some(value) => value
                .as_sequence()
                .ok_or_else(|| {
                    ConfigError::InvalidValue(format!("{location}: payload must be a list"))
                })?
                .clone(),
        };
        providers.push(ProxyProviderConfig {
            name: name.to_string(),
            vehicle,
            interval,
            filter,
            exclude_filter,
            exclude_type,
            proxy: optional_string(fields, "proxy")?,
            dialer_proxy: optional_string(fields, "dialer-proxy")?,
            overrides,
            size_limit: optional_positive_int(fields, "size-limit")?,
            header: parse_provider_header(fields, &location)?,
            health_check,
            payload,
        });
    }
    Ok(providers)
}

fn validate_provider_filter(
    patterns: &str,
    location: &str,
    key: &str,
) -> Result<(), ConfigError> {
    for pattern in patterns.split('`') {
        if pattern.is_empty() {
            continue;
        }
        validate_regex(pattern).map_err(|e| {
            config_error_with_prefix(e, &format!("{location}: {key} {pattern:?}"))
        })?;
    }
    Ok(())
}

fn parse_proxy_override(
    fields: &serde_yaml::Mapping,
    location: &str,
) -> Result<ProxyOverride, ConfigError> {
    let mut overrides = ProxyOverride::default();
    let Some(value) = optional_value(fields, "override")? else {
        return Ok(overrides);
    };
    let mapping = value.as_mapping().ok_or_else(|| {
        ConfigError::InvalidValue(format!("{location}: override must be a mapping"))
    })?;
    for (key, value) in mapping {
        let key = key.as_str().ok_or_else(|| {
            ConfigError::InvalidValue(format!("{location}: override keys must be strings"))
        })?;
        match key {
            "udp" => overrides.udp = Some(yaml_bool(value, location, "override.udp")?),
            "skip-cert-verify" => {
                overrides.skip_cert_verify =
                    Some(yaml_bool(value, location, "override.skip-cert-verify")?)
            }
            "dialer-proxy" => {
                overrides.dialer_proxy =
                    Some(yaml_string(value, location, "override.dialer-proxy")?)
            }
            "additional-prefix" => {
                overrides.additional_prefix =
                    Some(yaml_string(value, location, "override.additional-prefix")?)
            }
            "additional-suffix" => {
                overrides.additional_suffix =
                    Some(yaml_string(value, location, "override.additional-suffix")?)
            }
            "proxy-name" => {
                let items = value.as_sequence().ok_or_else(|| {
                    ConfigError::InvalidValue(format!(
                        "{location}: override.proxy-name must be a list"
                    ))
                })?;
                for item in items {
                    let item = item.as_mapping().ok_or_else(|| {
                        ConfigError::InvalidValue(format!(
                            "{location}: override.proxy-name entries must be mappings"
                        ))
                    })?;
                    let pattern = optional_string(item, "pattern")?.ok_or_else(|| {
                        ConfigError::InvalidValue(format!(
                            "{location}: override.proxy-name entries need a pattern"
                        ))
                    })?;
                    validate_regex(&pattern).map_err(|e| {
                        config_error_with_prefix(
                            e,
                            &format!("{location}: override.proxy-name {pattern:?}"),
                        )
                    })?;
                    let target = optional_string(item, "target")?.unwrap_or_default();
                    overrides.proxy_name.push(ProxyNameRewrite { pattern, target });
                }
            }
            // Every other field in the pinned `overrideSchema` (tfo, mptcp,
            // udp-over-tcp, up/down, name-cert-verify, interface-name,
            // routing-mark, ip-version, override-expr) changes a proxy option
            // this kernel cannot apply here; name it instead of ignoring it.
            other => {
                return Err(ConfigError::Unsupported(format!(
                    "{location}: override.{other} is not implemented (supported: udp, skip-cert-verify, dialer-proxy, additional-prefix, additional-suffix, proxy-name)"
                )))
            }
        }
    }
    Ok(overrides)
}

fn yaml_bool(
    value: &serde_yaml::Value,
    location: &str,
    key: &str,
) -> Result<bool, ConfigError> {
    match value {
        serde_yaml::Value::Bool(flag) => Ok(*flag),
        other => Err(ConfigError::InvalidValue(format!(
            "{location}: {key} must be a boolean, found {}",
            kind_of(other)
        ))),
    }
}

fn yaml_string(
    value: &serde_yaml::Value,
    location: &str,
    key: &str,
) -> Result<String, ConfigError> {
    match value {
        serde_yaml::Value::String(text) => Ok(text.clone()),
        serde_yaml::Value::Number(number) => Ok(number.to_string()),
        other => Err(ConfigError::InvalidValue(format!(
            "{location}: {key} must be a string, found {}",
            kind_of(other)
        ))),
    }
}

fn parse_health_check(
    fields: &serde_yaml::Mapping,
    location: &str,
) -> Result<HealthCheckConfig, ConfigError> {
    let mut config = HealthCheckConfig::default();
    let Some(value) = optional_value(fields, "health-check")? else {
        return Ok(config);
    };
    let mapping = value.as_mapping().ok_or_else(|| {
        ConfigError::InvalidValue(format!("{location}: health-check must be a mapping"))
    })?;
    config.enable = optional_bool(mapping, "enable")?.unwrap_or(false);
    config.url = optional_string(mapping, "url")?;
    config.interval = optional_seconds(mapping, "interval")?
        .map(|duration| duration.as_secs())
        .unwrap_or(300);
    config.timeout = optional_seconds(mapping, "timeout")?
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    config.lazy = optional_bool(mapping, "lazy")?.unwrap_or(true);
    config.expected_status = match optional_value(mapping, "expected-status")? {
        None | Some(serde_yaml::Value::Null) => String::new(),
        Some(serde_yaml::Value::String(value)) => value.clone(),
        // The pinned schema is a string but the decoder is weakly typed;
        // `expected-status: 204` is the common spelling.
        Some(serde_yaml::Value::Number(value)) => value.to_string(),
        Some(other) => {
            return Err(ConfigError::InvalidValue(format!(
                "{location}: expected-status must be a string or number, found {}",
                kind_of(other)
            )))
        }
    };
    if config.enable && config.url.as_deref().unwrap_or("").is_empty() {
        return Err(ConfigError::InvalidValue(format!(
            "{location}: health-check.enable needs a url"
        )));
    }
    // Validate the expected-status syntax even though T23 owns probing, so a
    // typo fails here instead of being discovered by a later task.
    if !config.expected_status.trim().is_empty() {
        parse_port_ranges(&config.expected_status)
            .map_err(|e| config_error_with_prefix(e, location))?;
    }
    Ok(config)
}

fn parse_provider_vehicle(
    fields: &serde_yaml::Mapping,
    location: &str,
) -> Result<ProviderVehicle, ConfigError> {
    let kind = optional_string(fields, "type")?.unwrap_or_default();
    match kind.as_str() {
        "file" => {
            let path = optional_string(fields, "path")?.ok_or_else(|| {
                ConfigError::InvalidValue(format!("{location}: file provider needs a path"))
            })?;
            if path.is_empty() {
                return Err(ConfigError::InvalidValue(format!(
                    "{location}: file provider path must not be empty"
                )));
            }
            Ok(ProviderVehicle::File {
                path: std::path::PathBuf::from(path),
            })
        }
        "http" => {
            let url = optional_string(fields, "url")?.ok_or_else(|| {
                ConfigError::InvalidValue(format!("{location}: http provider needs a url"))
            })?;
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(ConfigError::InvalidValue(format!(
                    "{location}: provider url '{url}' must be http(s)"
                )));
            }
            let path = optional_string(fields, "path")?
                .filter(|path| !path.is_empty())
                .map(std::path::PathBuf::from);
            Ok(ProviderVehicle::Http { url, path })
        }
        "inline" => Ok(ProviderVehicle::Inline),
        other => Err(ConfigError::Unsupported(format!(
            "{location}: provider type '{other}' (file, http and inline are implemented)"
        ))),
    }
}

fn parse_provider_header(
    fields: &serde_yaml::Mapping,
    location: &str,
) -> Result<Vec<(String, String)>, ConfigError> {
    let Some(value) = optional_value(fields, "header")? else {
        return Ok(Vec::new());
    };
    let mapping = value
        .as_mapping()
        .ok_or_else(|| ConfigError::InvalidValue(format!("{location}: header must be a mapping")))?;
    let mut header = Vec::new();
    for (name, value) in mapping {
        let name = name.as_str().ok_or_else(|| {
            ConfigError::InvalidValue(format!("{location}: header names must be strings"))
        })?;
        let values: Vec<String> = match value {
            serde_yaml::Value::String(value) => vec![value.clone()],
            serde_yaml::Value::Sequence(items) => items
                .iter()
                .map(|item| {
                    item.as_str().map(str::to_string).ok_or_else(|| {
                        ConfigError::InvalidValue(format!(
                            "{location}: header '{name}' values must be strings"
                        ))
                    })
                })
                .collect::<Result<_, _>>()?,
            _ => {
                return Err(ConfigError::InvalidValue(format!(
                    "{location}: header '{name}' must be a string or a list of strings"
                )))
            }
        };
        for value in values {
            header.push((name.to_string(), value));
        }
    }
    Ok(header)
}

fn optional_value<'a>(
    fields: &'a serde_yaml::Mapping,
    key: &str,
) -> Result<Option<&'a serde_yaml::Value>, ConfigError> {
    Ok(fields.get(&serde_yaml::Value::String(key.to_string())))
}

fn optional_string(fields: &serde_yaml::Mapping, key: &str) -> Result<Option<String>, ConfigError> {
    match optional_value(fields, key)? {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::String(value)) => Ok(Some(value.clone())),
        Some(other) => Err(ConfigError::InvalidValue(format!(
            "'{key}' must be a string, found {}",
            kind_of(other)
        ))),
    }
}

fn optional_bool(fields: &serde_yaml::Mapping, key: &str) -> Result<Option<bool>, ConfigError> {
    match optional_value(fields, key)? {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::Bool(value)) => Ok(Some(*value)),
        Some(other) => Err(ConfigError::InvalidValue(format!(
            "'{key}' must be a boolean, found {}",
            kind_of(other)
        ))),
    }
}

fn optional_positive_int(
    fields: &serde_yaml::Mapping,
    key: &str,
) -> Result<Option<u64>, ConfigError> {
    match optional_value(fields, key)? {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(value) => {
            let parsed = value.as_u64().or_else(|| {
                value
                    .as_str()
                    .and_then(|text| text.trim().parse::<u64>().ok())
            });
            parsed.map(Some).ok_or_else(|| {
                ConfigError::InvalidValue(format!("'{key}' must be a non-negative integer"))
            })
        }
    }
}

fn optional_seconds(
    fields: &serde_yaml::Mapping,
    key: &str,
) -> Result<Option<Duration>, ConfigError> {
    optional_positive_int(fields, key).map(|value| value.map(Duration::from_secs))
}

fn optional_string_list(
    fields: &serde_yaml::Mapping,
    key: &str,
) -> Result<Vec<String>, ConfigError> {
    match optional_value(fields, key)? {
        None | Some(serde_yaml::Value::Null) => Ok(Vec::new()),
        Some(serde_yaml::Value::Sequence(items)) => items
            .iter()
            .map(|item| {
                item.as_str().map(str::to_string).ok_or_else(|| {
                    ConfigError::InvalidValue(format!("'{key}' entries must be strings"))
                })
            })
            .collect(),
        Some(other) => Err(ConfigError::InvalidValue(format!(
            "'{key}' must be a list, found {}",
            kind_of(other)
        ))),
    }
}
fn parse_tls(
    value: &serde_yaml::Value,
    path: &str,
) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, ConfigError> {
    let map = value
        .as_mapping()
        .ok_or_else(|| ConfigError::InvalidValue(format!("{path}: tls must be a mapping")))?;
    let base = std::path::Path::new(path).parent().map(|p| p.to_path_buf());
    let mut pems = Vec::new();
    let resolve = |raw: &str| -> std::path::PathBuf {
        let candidate = std::path::PathBuf::from(raw);
        match (&base, candidate.is_absolute()) {
            (Some(dir), false) if !dir.as_os_str().is_empty() => dir.join(candidate),
            _ => candidate,
        }
    };
    for (key, item) in map {
        match key.as_str() {
            Some("custom-cert") => {
                let list = item.as_sequence().ok_or_else(|| {
                    ConfigError::InvalidValue(format!("{path}: tls.custom-cert must be a list of PEM strings"))
                })?;
                for entry in list {
                    let raw = entry.as_str().ok_or_else(|| {
                        ConfigError::InvalidValue(format!("{path}: tls.custom-cert entries must be strings"))
                    })?;
                    let text = if raw.contains("-----BEGIN") {
                        raw.to_string()
                    } else {
                        std::fs::read_to_string(resolve(raw)).map_err(|e| {
                            ConfigError::InvalidValue(format!("{path}: tls.custom-cert {}: {e}", resolve(raw).display()))
                        })?
                    };
                    pems.push(text);
                }
            }
            Some("certificate") => {
                let raw = item.as_str().ok_or_else(|| {
                    ConfigError::InvalidValue(format!("{path}: tls.certificate must be a directory or PEM string"))
                })?;
                let dir = if raw.contains("-----BEGIN") {
                    return Err(ConfigError::Unsupported(format!(
                        "{path}: tls.certificate as an inline PEM is not implemented; list PEM files under tls.custom-cert"
                    )));
                } else {
                    resolve(raw)
                };
                let entries = std::fs::read_dir(&dir).map_err(|e| {
                    ConfigError::InvalidValue(format!("{path}: tls.certificate directory {}: {e}", dir.display()))
                })?;
                for entry in entries.flatten() {
                    let file = entry.path();
                    if file.is_file() {
                        if let Ok(text) = std::fs::read_to_string(&file) {
                            if text.contains("-----BEGIN CERTIFICATE-----") {
                                pems.push(text);
                            }
                        }
                    }
                }
            }
            Some(other) => {
                return Err(ConfigError::Unsupported(format!(
                    "{path}: tls.{other} is not implemented (only custom-cert and certificate are honoured)"
                )))
            }
            None => return Err(ConfigError::InvalidValue(format!("{path}: tls keys must be strings"))),
        }
    }
    let mut roots = Vec::new();
    for pem in pems {
        roots.extend(crate::outbound::tls::parse_pem_certs(&pem)?);
    }
    Ok(roots)
}

/// `authentication: ["user:pass", ...]` (Mihomo `authentication []string`).
fn parse_authentication(
    value: &serde_yaml::Value,
    path: &str,
) -> Result<Vec<(String, String)>, ConfigError> {
    let seq = value.as_sequence().ok_or_else(|| {
        ConfigError::InvalidValue(format!(
            "{path}: authentication must be a list of user:pass"
        ))
    })?;
    let mut users = Vec::with_capacity(seq.len());
    for (index, item) in seq.iter().enumerate() {
        let line = item.as_str().ok_or_else(|| {
            ConfigError::InvalidValue(format!("{path}: authentication[{index}] must be a string"))
        })?;
        let (user, pass) = line.split_once(':').ok_or_else(|| {
            ConfigError::InvalidValue(format!(
                "{path}: authentication[{index}] must be 'user:password'"
            ))
        })?;
        if user.is_empty() || pass.is_empty() || user.len() > 255 || pass.len() > 255 {
            return Err(ConfigError::InvalidValue(format!(
                "{path}: authentication[{index}] needs a non-empty user and password of at most 255 bytes"
            )));
        }
        users.push((user.to_string(), pass.to_string()));
    }
    Ok(users)
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
    // Mihomo uses 0 to mean "this listener is disabled"; the caller records
    // that and never binds an ephemeral port by accident.
    if port > u16::MAX as u64 {
        return Err(ConfigError::InvalidValue(format!(
            "{path}: {key} {port} is out of range 0..=65535"
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

/// Human-readable YAML kind, used by the proxy parser's error text too.
pub(crate) fn kind_name(value: &serde_yaml::Value) -> &'static str {
    kind_of(value)
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
        pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, String> {
            let max = if addr.is_ipv4() { 32 } else { 128 };
            if prefix > max {
                return Err(format!("prefix {prefix} exceeds {max}"));
            }
            Ok(IpNet { addr, prefix })
        }

        pub fn is_v4(&self) -> bool {
            self.addr.is_ipv4()
        }

        /// Bit length of the network part (0..=32/128).
        pub fn prefix(&self) -> u8 {
            self.prefix
        }

        /// Address with all host bits cleared, as stored in the file.
        pub fn network(&self) -> IpAddr {
            self.addr
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

/// The geosite database now lives in [`crate::geodata`]; the re-export keeps
/// existing hosts and tests that import it from `config`.
pub use crate::geodata::GeoSiteDatabase;

/// Duration helper kept here so tests share one place with defaults.
pub fn default_handshake_timeout() -> Duration {
    Duration::from_secs(10)
}
