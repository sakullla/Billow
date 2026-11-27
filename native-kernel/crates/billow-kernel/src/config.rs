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
    "proxy-groups",
    "profile",
    "sub-rules",
    "geodata-mode",
    "geodata-loader",
    "geosite-matcher",
    "geo-auto-update",
    "geo-update-interval",
    "hosts",
    "dns",
    "ipv6",
    "external-controller",
    "external-controller-unix",
    "external-controller-tls",
    "external-controller-cors",
    "secret",
    "tun",
];
/// Top-level keys the pinned `RawConfig` declares but this kernel does not
/// implement. They fail with `[unsupported]`; a key outside both lists is not a
/// Mihomo key at all and is ignored exactly as Mihomo's decoder ignores it (R2:
/// a valid configuration must load).
pub const KNOWN_UNSUPPORTED_TOP_LEVEL_KEYS: &[&str] = &[
    "ss-config", "vmess-config", "inbound-tfo", "inbound-mptcp",
    "skip-auth-prefixes", "lan-allowed-ips", "lan-disallowed-ips",
    "external-controller-routing-mark", "external-controller-pipe",
    "external-ui", "external-ui-url", "external-ui-name", "external-doh-server",
    "interface-name", "routing-mark", "tunnels",
    "global-client-fingerprint", "global-ua", "etag-support", "keep-alive-idle",
    "listeners", "ntp", "tuic-server",
    "iptables", "experimental", "geox-url", "sniffer", "clash-for-android"
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
    /// A device TUN / Packet Tunnel (the pinned `C.TUN`, matched by the
    /// `device-vpn` iOS Packet Tunnel and Android VpnService data planes;
    /// desktop TUN is T6).
    Tun,
}

impl InType {
    pub fn as_str(self) -> &'static str {
        match self {
            InType::Http => "HTTP",
            InType::Https => "HTTPS",
            InType::Socks5 => "SOCKS5",
            InType::Tun => "TUN",
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
    /// Index into [`Config::proxy_groups`] (T23). The group decides the actual
    /// leaf outbound at dial time.
    Group(usize),
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Direct => "DIRECT",
            Action::Reject => "REJECT",
            Action::RejectDrop => "REJECT-DROP",
            // The name is not known here; callers with a Config use `Proxy::name`.
            Action::Proxy(_) => "PROXY",
            Action::Group(_) => "GROUP",
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

/// `url-test`, `fallback`, `load-balance` or `select` (T23). `relay` was
/// removed from the pinned engine (v1.19.34 rejects it with "using
/// dialer-proxy instead"), so it is a named rejection rather than a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
}

impl GroupKind {
    pub fn as_str(self) -> &'static str {
        match self {
            GroupKind::Select => "select",
            GroupKind::UrlTest => "url-test",
            GroupKind::Fallback => "fallback",
            GroupKind::LoadBalance => "load-balance",
        }
    }
}

/// `load-balance.strategy` (default `consistent-hashing`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalanceStrategy {
    ConsistentHashing,
    RoundRobin,
    StickySessions,
}

impl LoadBalanceStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            LoadBalanceStrategy::ConsistentHashing => "consistent-hashing",
            LoadBalanceStrategy::RoundRobin => "round-robin",
            LoadBalanceStrategy::StickySessions => "sticky-sessions",
        }
    }
}

/// `load-balance.hash-key` (default empty = the strategy's own key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKey {
    Default,
    InUser,
}

/// `expected-status`: a `/` or `,` separated list of HTTP status codes and
/// inclusive ranges, e.g. `200/204/301-308`. Empty or `*` accepts every status.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExpectedStatus {
    segments: Vec<(u16, u16)>,
}

impl ExpectedStatus {
    /// Parse the pinned `utils.NewUnsignedRanges` syntax.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.is_empty() || text == "*" {
            return Ok(ExpectedStatus::default());
        }
        let normalized = text.replace(',', "/");
        let list: Vec<&str> = normalized.split('/').collect();
        if list.len() > 28 {
            return Err("too many ranges to use, maximum support 28 ranges".to_string());
        }
        let mut segments = Vec::new();
        for item in list {
            if item.is_empty() {
                continue;
            }
            let item = item.trim();
            let parts: Vec<&str> = item.split('-').collect();
            match parts.len() {
                1 => {
                    let value = parse_status(parts[0])?;
                    segments.push((value, value));
                }
                2 => {
                    let start = parse_status(parts[0])?;
                    let end = parse_status(parts[1])?;
                    segments.push((start, end));
                }
                _ => return Err(format!("invalid range: {item}")),
            }
        }
        Ok(ExpectedStatus { segments })
    }

    /// A status is accepted when the list is empty (any) or one segment contains it.
    pub fn check(&self, status: u16) -> bool {
        self.segments.is_empty()
            || self
                .segments
                .iter()
                .any(|(start, end)| (*start..=*end).contains(&status))
    }

    /// The pinned display form: `*` or `200/204/301-308`.
    pub fn as_spec(&self) -> String {
        if self.segments.is_empty() {
            return "*".to_string();
        }
        self.segments
            .iter()
            .map(|(start, end)| {
                if start == end {
                    start.to_string()
                } else {
                    format!("{start}-{end}")
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    }
}

fn parse_status(text: &str) -> Result<u16, String> {
    let trimmed = text.trim().trim_matches(|c| c == '[' || c == ']').trim();
    let value: u64 = trimmed
        .parse()
        .map_err(|_| format!("invalid range: {text}"))?;
    Ok(value as u16)
}

/// `empty-fallback`: the proxy a group selects when its resolved member list is
/// empty. `COMPATIBLE` is the pinned default and behaves like DIRECT for a
/// routing decision; a configured proxy name is resolved at load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyFallback {
    /// The pinned default: the `COMPATIBLE` builtin (routes like DIRECT but
    /// keeps its own member name).
    Compatible,
    /// An explicit `empty-fallback: DIRECT`.
    Direct,
    Reject,
    RejectDrop,
    Proxy(usize),
}

/// One `proxy-groups` entry (T23).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyGroup {
    pub name: String,
    pub kind: GroupKind,
    /// `proxies` in declaration order (includes the include-all expansion).
    pub proxies: Vec<String>,
    /// `use` proxy providers, in declaration order.
    pub use_providers: Vec<String>,
    pub url: String,
    /// Whether `url` was written in the configuration (pinned registers that
    /// URL as an extra health check on every `use` provider).
    pub url_explicit: bool,
    /// Auto health-check interval in seconds; 0 means no scheduled check
    /// (`select` and `relay` keep their declared value, others default to 300).
    pub interval: u64,
    /// The `interval` exactly as written (0 when omitted). Pinned
    /// `addTestUrlToProviders` runs before the 300 s default is applied to a
    /// group with inline members, so provider registration keeps this value.
    pub registration_interval: u64,
    /// `timeout` in milliseconds (0 becomes 5000).
    pub timeout: u64,
    pub lazy: bool,
    /// `max-failed-times` (0 becomes 5).
    pub max_failed_times: usize,
    pub expected_status: ExpectedStatus,
    /// `filter` split on backticks, compiled by the group runtime.
    pub filter: Vec<String>,
    pub exclude_filter: Vec<String>,
    /// `exclude-type` split on `|`, lowercased.
    pub exclude_type: Vec<String>,
    pub tolerance: u16,
    pub strategy: LoadBalanceStrategy,
    pub hash_key: HashKey,
    pub default_selected: Option<String>,
    pub disable_udp: bool,
    pub hidden: bool,
    pub icon: String,
    pub empty_fallback: EmptyFallback,
}

/// `profile` (the selection cache switch; `store-fake-ip` belongs to DNS/T22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileConfig {
    pub store_selected: bool,
    pub store_fake_ip: bool,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        // Pinned `DefaultRawConfig` sets StoreSelected: true, StoreFakeIP: false.
        ProfileConfig {
            store_selected: true,
            store_fake_ip: false,
        }
    }
}

/// `external-controller-cors` (pinned `RawCors`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsConfig {
    pub allow_origins: Vec<String>,
    pub allow_private_network: bool,
}

impl Default for CorsConfig {
    fn default() -> Self {
        // Pinned `DefaultRawConfig` defaults.
        CorsConfig {
            allow_origins: vec!["*".to_string()],
            allow_private_network: true,
        }
    }
}

/// `external-controller`, `external-controller-unix`,
/// `external-controller-tls`, `external-controller-cors` and `secret` (T25).
///
/// Addresses stay as written so a host name resolves at bind time exactly like
/// the pinned `net.Listen` call. A controller listener is optional; when none
/// is configured no server is started. `certificate`/`private_key` are the PEM
/// bytes of the pinned top-level `tls.certificate`/`tls.private-key` and are
/// only used by `external-controller-tls`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControllerConfig {
    pub external_controller: Option<String>,
    pub external_controller_unix: Option<std::path::PathBuf>,
    pub external_controller_tls: Option<String>,
    pub secret: String,
    pub cors: CorsConfig,
    pub certificate: Option<Vec<u8>>,
    pub private_key: Option<Vec<u8>>,
}

impl ControllerConfig {
    /// `true` when any controller listener is configured.
    pub fn enabled(&self) -> bool {
        self.external_controller.is_some()
            || self.external_controller_unix.is_some()
            || self.external_controller_tls.is_some()
    }

    /// Fields that require the controller to be bound again. A reload that
    /// changes them is rejected by name instead of silently keeping the old
    /// listener (`Kernel::reload`).
    pub fn same_listeners(&self, other: &Self) -> bool {
        self.external_controller == other.external_controller
            && self.external_controller_unix == other.external_controller_unix
            && self.external_controller_tls == other.external_controller_tls
            && self.secret == other.secret
            && self.cors == other.cors
            && self.certificate == other.certificate
            && self.private_key == other.private_key
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

/// `tun:` block. The desktop runner (feature `desktop-tun`) creates the device
/// and routes from it; the config loader only records and validates the shape.
///
/// `stack: mips`, `mixed` and `gvisor` are all served by the in-tree userspace
/// IP stack in [`crate::tunnel`]. The field keeps the requested name so evidence
/// can state plainly that this is not the pinned MipsSoft/gVisor implementation;
/// `system` (the OS stack) is rejected by name because this kernel terminates
/// TCP/UDP itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    pub enable: bool,
    /// Interface/adapter name; empty means the platform picks one.
    pub device: String,
    /// Accepted `stack` value (`mips`, `mixed` or `gvisor`).
    pub stack: String,
    /// Requested MTU; 0 keeps the platform default (9000 for this stack).
    pub mtu: u32,
    pub auto_route: bool,
    pub auto_detect_interface: bool,
    pub strict_route: bool,
    /// Parsed `dns-hijack` address ports. The userspace stack answers a target
    /// only when it equals an entry, or when an entry is unspecified and the
    /// target port is 53 (pinned `ShouldHijackDns`).
    pub dns_hijack: Vec<SocketAddr>,
    /// `dns-mode`; empty/disabled keeps the OS DNS untouched.
    pub dns_mode: TunDnsMode,
    /// `inet6-address` prefixes; pinned default `fdfe:dcba:9876::1/126`.
    pub inet6_address: Vec<String>,
    /// Linux policy-routing table for the TUN routes (pinned default 2022).
    pub iproute2_table_index: u32,
    /// Linux policy-routing rule priority (pinned default 9000).
    pub iproute2_rule_index: u32,
    pub route_address: Vec<String>,
    pub route_exclude_address: Vec<String>,
}

/// Pinned `tun.dns-mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunDnsMode {
    /// `""` or `disabled`: never touch the system resolver.
    Disabled,
    /// `native`: point the system resolver at the TUN DNS address.
    Native,
    /// `hijack`: as native; the stack also owns the DNS redirect path.
    Hijack,
}

impl TunDnsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            TunDnsMode::Disabled => "disabled",
            TunDnsMode::Native => "native",
            TunDnsMode::Hijack => "hijack",
        }
    }

    pub fn touches_system_resolver(self) -> bool {
        !matches!(self, TunDnsMode::Disabled)
    }
}

impl Default for TunConfig {
    fn default() -> Self {
        // Pinned `RawTun` defaults that matter for the accepted shape.
        TunConfig {
            enable: false,
            device: String::new(),
            stack: "mips".to_string(),
            mtu: 0,
            auto_route: true,
            auto_detect_interface: true,
            strict_route: false,
            dns_hijack: vec![SocketAddr::from(([0, 0, 0, 0], 53))],
            dns_mode: TunDnsMode::Disabled,
            inet6_address: vec!["fdfe:dcba:9876::1/126".to_string()],
            iproute2_table_index: 2022,
            iproute2_rule_index: 9000,
            route_address: Vec::new(),
            route_exclude_address: Vec::new(),
        }
    }
}

impl TunConfig {
    /// The MTU the userspace stack advertises. Pinned sing-tun uses 9000 when
    /// `tun.mtu` is absent (the iOS/Android entries keep their own defaults).
    pub fn effective_mtu(&self) -> usize {
        const PINNED_DEFAULT_MTU: usize = 9000;
        if self.mtu == 0 {
            PINNED_DEFAULT_MTU
        } else {
            self.mtu as usize
        }
    }

    /// Pinned `ShouldHijackDns`: exact target match, or an unspecified entry
    /// matching any target on port 53.
    pub fn should_hijack_dns(&self, target: SocketAddr) -> bool {
        self.dns_hijack
            .iter()
            .any(|entry| *entry == target || (entry.ip().is_unspecified() && target.port() == 53))
    }

    pub fn hijack_dns(&self) -> bool {
        !self.dns_hijack.is_empty()
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
    /// `proxy-groups` entries in declaration order (T23).
    pub proxy_groups: Vec<ProxyGroup>,
    /// `profile` selection-cache switches.
    pub profile: ProfileConfig,
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
    /// `dns:` block (pinned `RawDNS`/`config.DNS`); `enable: false` keeps the
    /// system resolver for rule-time lookups, like the pinned engine.
    pub dns: crate::dns::DnsConfig,
    /// Top-level `hosts:` (always active, pinned `updateHosts`).
    pub hosts: crate::dns::HostsConfig,
    /// Top-level `ipv6` (pinned default `true`); combined with `dns.ipv6`.
    pub ipv6: bool,
    /// `tun:` block (desktop TUN data plane, feature `desktop-tun`).
    pub tun: TunConfig,
    /// Control-API listeners and auth (T25).
    pub controller: ControllerConfig,
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
        // DNS fallback filters and nameserver policies can reference geosite
        // lists and the GEOIP database too (pinned `parseDNS` loads them).
        if self.dns.enable {
            let filter = &self.dns.fallback_filter;
            if !self.dns.fallback.is_empty() {
                if filter.geoip
                    && filter.geoip_code.trim_start_matches('!').to_ascii_lowercase() != "lan"
                {
                    requirements.geoip = true;
                }
                for key in &filter.geosite {
                    requirements.geosite_keys.insert(key.clone());
                }
            }
            for policy in self
                .dns
                .nameserver_policy
                .iter()
                .chain(self.dns.proxy_server_nameserver_policy.iter())
            {
                if let Some(list) = policy.key.to_ascii_lowercase().strip_prefix("geosite:") {
                    requirements.geosite_keys.insert(list.to_string());
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
        let dns = if self.dns.enable {
            let listen = self
                .dns
                .listen
                .map(|addr| format!(",listen={addr}"))
                .unwrap_or_default();
            format!(
                "dns={}(nameserver={},default={},fallback={},policy={}{})",
                self.dns.enhanced_mode.as_str(),
                self.dns.nameserver.len(),
                self.dns.default_nameserver.len(),
                self.dns.fallback.len(),
                self.dns.nameserver_policy.len(),
                listen
            )
        } else {
            "dns=off".to_string()
        };
        format!(
            "mixed-inbound(tcp,http-connect,socks5); rules=inline({} entries); rule-providers={}; proxy-providers={}; proxy-groups={}; sub-rules={}; outbounds=DIRECT,REJECT; protocols={protocols}; hosts={}; {dns}",
            self.rules.len(),
            self.rule_providers.len(),
            self.proxy_providers.len(),
            self.proxy_groups.len(),
            self.sub_rules.len(),
            self.hosts.entries.len()
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
            Action::Group(index) => self
                .proxy_groups
                .get(index)
                .map(|g| g.name.clone())
                .unwrap_or_else(|| "<missing group>".to_string()),
        }
    }

    /// Names addressable as a rule target: proxy names, then proxy groups.
    pub fn outbound_name(&self, name: &str) -> Option<Action> {
        if let Some(index) = self.proxies.iter().position(|proxy| proxy.name == name) {
            return Some(Action::Proxy(index));
        }
        self.proxy_groups
            .iter()
            .position(|group| group.name == name)
            .map(Action::Group)
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

/// Parse the `tun:` block strictly (T34). Unknown keys and behaviour-changing
/// shapes that this kernel cannot honour fail with their name instead of being
/// silently ignored.
fn parse_tun(
    value: &serde_yaml::Value,
    path: &str,
    warnings: &mut Vec<String>,
) -> Result<TunConfig, ConfigError> {
    let mut tun = TunConfig::default();
    let mapping = match value {
        serde_yaml::Value::Null => {
            warnings.push("'tun' is empty; the block is inert".to_string());
            return Ok(tun);
        }
        serde_yaml::Value::Bool(flag) => {
            tun.enable = *flag;
            if *flag {
                warnings.push(
                    "tun.enable is true; the desktop runner creates the device only with --tun (feature desktop-tun), and --check still only validates"
                        .to_string(),
                );
            } else {
                warnings.push("'tun' is disabled; no device is created".to_string());
            }
            return Ok(tun);
        }
        serde_yaml::Value::Mapping(mapping) => mapping,
        other => {
            return Err(ConfigError::InvalidValue(format!(
                "{path}: tun must be a mapping or boolean, found {}",
                kind_of(other)
            )))
        }
    };
    for (key, item) in mapping {
        let key = key
            .as_str()
            .ok_or_else(|| ConfigError::InvalidValue(format!("{path}: tun keys must be strings")))?;
        let label = format!("tun.{key}");
        match key {
            "enable" => tun.enable = parse_bool(item, path, &label)?,
            "device" => {
                // Platform name limits differ (Unix IFNAMSIZ vs Windows
                // adapter alias); the device backend validates its own shape.
                tun.device = parse_string(item, path, &label)?;
            }
            "stack" => {
                let stack = parse_string(item, path, &label)?.to_ascii_lowercase();
                match stack.as_str() {
                    "mips" | "mixed" | "gvisor" => {
                        if stack != "mixed" {
                            warnings.push(format!(
                                "tun.stack '{stack}' is served by this kernel's in-tree userspace IP stack, not the pinned {stack} implementation"
                            ));
                        }
                        tun.stack = stack;
                    }
                    "system" => {
                        return Err(ConfigError::Unsupported(format!(
                            "{path}: tun.stack 'system' is not implemented (this kernel terminates TCP/UDP in userspace; mips/mixed/gvisor all run that stack)"
                        )))
                    }
                    other => {
                        return Err(ConfigError::Unsupported(format!(
                            "{path}: tun.stack '{other}' is not a pinned value (accepted: mips, mixed, gvisor)"
                        )))
                    }
                }
            }
            "mtu" => {
                let mtu = match item {
                    serde_yaml::Value::Number(number) => number.as_u64(),
                    serde_yaml::Value::String(text) => text.parse::<u64>().ok(),
                    _ => None,
                }
                .ok_or_else(|| {
                    ConfigError::InvalidValue(format!(
                        "{path}: tun.mtu must be a non-negative integer, found {item:?}"
                    ))
                })?;
                if mtu > 65_535 {
                    return Err(ConfigError::InvalidValue(format!(
                        "{path}: tun.mtu {mtu} exceeds 65535"
                    )));
                }
                tun.mtu = mtu as u32;
                if mtu == 0 {
                    warnings.push("tun.mtu 0 keeps the userspace stack default (9000)".to_string());
                }
            }
            "auto-route" => tun.auto_route = parse_bool(item, path, &label)?,
            "auto-detect-interface" => tun.auto_detect_interface = parse_bool(item, path, &label)?,
            "strict-route" => tun.strict_route = parse_bool(item, path, &label)?,
            "dns-mode" => {
                let mode = parse_string(item, path, &label)?.to_ascii_lowercase();
                tun.dns_mode = match mode.as_str() {
                    "" | "disabled" => TunDnsMode::Disabled,
                    "native" => TunDnsMode::Native,
                    "hijack" => TunDnsMode::Hijack,
                    other => {
                        return Err(ConfigError::Unsupported(format!(
                            "{path}: tun.dns-mode '{other}' is not a pinned value (accepted: '', disabled, native, hijack)"
                        )))
                    }
                };
            }
            "dns-hijack" => {
                let entries = parse_tun_string_list(item, path, &label)?;
                tun.dns_hijack = parse_dns_hijack_entries(&entries, path)?;
            }
            "inet6-address" => {
                let prefixes = parse_tun_prefix_list(item, path, &label)?;
                if let Some(bad) = prefixes.iter().find(|prefix| !prefix.contains(':')) {
                    return Err(ConfigError::InvalidValue(format!(
                        "{path}: tun.inet6-address '{bad}' is not an IPv6 prefix"
                    )));
                }
                tun.inet6_address = prefixes;
                if tun.inet6_address.is_empty() {
                    warnings.push("tun.inet6-address is empty; no IPv6 device address is assigned".to_string());
                }
            }
            "iproute2-table-index" => {
                let value = parse_tun_u32(item, &label, path)?;
                if value == 0 || (253..=255).contains(&value) {
                    return Err(ConfigError::InvalidValue(format!(
                        "{path}: tun.iproute2-table-index {value} is reserved (local/main/default tables); use a dedicated table such as 2022"
                    )));
                }
                tun.iproute2_table_index = value;
            }
            "iproute2-rule-index" => {
                let value = parse_tun_u32(item, &label, path)?;
                if value == 0 {
                    return Err(ConfigError::InvalidValue(format!(
                        "{path}: tun.iproute2-rule-index must be non-zero"
                    )));
                }
                tun.iproute2_rule_index = value;
            }
            "route-address" => {
                tun.route_address = parse_tun_prefix_list(item, path, &label)?;
            }
            "route-exclude-address" => {
                tun.route_exclude_address = parse_tun_prefix_list(item, path, &label)?;
            }
            "file-descriptor" => {
                return Err(ConfigError::Unsupported(format!(
                    "{path}: tun.file-descriptor is a Mihomo launch parameter; the Android host hands the VpnService fd as --tun-fd and desktop TUN is created by the kernel itself"
                )))
            }
            other => {
                return Err(ConfigError::Unsupported(format!(
                    "{path}: tun.{other} is not implemented (accepted keys: enable, device, stack, mtu, auto-route, auto-detect-interface, strict-route, dns-hijack, dns-mode, inet6-address, iproute2-table-index, iproute2-rule-index, route-address, route-exclude-address)"
                )))
            }
        }
    }
    if tun.enable {
        warnings.push(
            "tun.enable is true; the desktop runner creates the device only with --tun (feature desktop-tun), and --check still only validates"
                .to_string(),
        );
    } else {
        warnings.push("'tun' is present but disabled; no device is created".to_string());
    }
    if tun.strict_route {
        warnings.push(
            "tun.strict-route is implemented as requiring a detected physical interface and binding kernel-originated sockets to it; pinned fwmark/rule/table details are not applied"
                .to_string(),
        );
    }
    Ok(tun)
}

fn parse_tun_u32(
    value: &serde_yaml::Value,
    key: &str,
    path: &str,
) -> Result<u32, ConfigError> {
    let number = match value {
        serde_yaml::Value::Number(number) => number.as_u64(),
        serde_yaml::Value::String(text) => text.parse::<u64>().ok(),
        _ => None,
    }
    .ok_or_else(|| {
        ConfigError::InvalidValue(format!(
            "{path}: {key} must be a non-negative integer, found {value:?}"
        ))
    })?;
    u32::try_from(number).map_err(|_| {
        ConfigError::InvalidValue(format!("{path}: {key} {number} exceeds u32"))
    })
}

fn parse_dns_hijack_entries(
    entries: &[String],
    path: &str,
) -> Result<Vec<SocketAddr>, ConfigError> {
    let mut parsed = Vec::with_capacity(entries.len());
    for raw in entries {
        let text = raw.split_once("://").map(|(_, rest)| rest).unwrap_or(raw);
        // Pinned `parseTun` replaces the first "any" with 0.0.0.0.
        let text = text.replacen("any", "0.0.0.0", 1);
        let target: SocketAddr = text.parse().map_err(|error| {
            ConfigError::InvalidValue(format!(
                "{path}: tun.dns-hijack '{raw}' is not an ip:port address: {error}"
            ))
        })?;
        if target.port() != 53 {
            return Err(ConfigError::Unsupported(format!(
                "{path}: tun.dns-hijack '{raw}' targets port {}, but the userspace stack only answers port 53",
                target.port()
            )));
        }
        if !parsed.contains(&target) {
            parsed.push(target);
        }
    }
    Ok(parsed)
}

fn parse_tun_string_list(
    value: &serde_yaml::Value,
    path: &str,
    key: &str,
) -> Result<Vec<String>, ConfigError> {
    let sequence = match value {
        serde_yaml::Value::Sequence(sequence) => sequence,
        serde_yaml::Value::Null => return Ok(Vec::new()),
        other => {
            return Err(ConfigError::InvalidValue(format!(
                "{path}: {key} must be a list, found {}",
                kind_of(other)
            )))
        }
    };
    let mut out = Vec::with_capacity(sequence.len());
    for item in sequence {
        let text = match item {
            serde_yaml::Value::String(text) => text.clone(),
            serde_yaml::Value::Number(number) => number.to_string(),
            other => {
                return Err(ConfigError::InvalidValue(format!(
                    "{path}: {key} entries must be strings, found {}",
                    kind_of(other)
                )))
            }
        };
        if text.trim().is_empty() {
            return Err(ConfigError::InvalidValue(format!(
                "{path}: {key} entries must not be empty"
            )));
        }
        out.push(text);
    }
    Ok(out)
}

fn parse_tun_prefix_list(
    value: &serde_yaml::Value,
    path: &str,
    key: &str,
) -> Result<Vec<String>, ConfigError> {
    let entries = parse_tun_string_list(value, path, key)?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let network: ipnet_like::IpNet = entry.parse().map_err(|error| {
            ConfigError::InvalidValue(format!("{path}: {key} '{entry}' is not a CIDR: {error}"))
        })?;
        out.push(network.to_string());
    }
    Ok(out)
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
    let mut proxy_groups_value = None;
    let mut profile = ProfileConfig::default();
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
    let mut dns = crate::dns::DnsConfig::default();
    let mut hosts = crate::dns::HostsConfig::default();
    let mut general_ipv6 = true;
    let mut tun = TunConfig::default();
    let mut controller = ControllerConfig::default();

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
            "redir-port" | "tproxy-port" => {
                // Billow's Android artifact disables the legacy listeners with
                // `0`; the kernel has no redir/tproxy path (T6/T7 own device
                // routing), so only the disabled form is inert.
                let port = parse_port(value, path, key)?;
                if port == 0 {
                    warnings.push(format!("{key} 0 disables a listener this kernel never starts"));
                } else {
                    return Err(ConfigError::Unsupported(format!(
                        "top-level key '{key}' is set to {port} (redir/tproxy listeners belong to the device/TUN layer, T6/T7)"
                    )));
                }
            }
            "keep-alive-interval" => {
                let secs = value.as_u64().ok_or_else(|| {
                    ConfigError::InvalidValue(format!(
                        "{path}: keep-alive-interval must be a non-negative integer"
                    ))
                })?;
                warnings.push(format!(
                    "keep-alive-interval {secs}s is recorded but each outbound keeps its own default (a global TCP keep-alive default is not threaded yet)"
                ));
            }
            "disable-keep-alive" => {
                let _ = parse_bool(value, path, key)?;
                warnings.push(
                    "disable-keep-alive is recorded but outbounds keep their own keep-alive defaults"
                        .to_string(),
                );
            }
            "unified-delay" => {
                // Accepted because every Billow profile carries the user's
                // toggle; the delay probes here report the full round trip, so
                // the pinned handshake subtraction has no effect to apply.
                let _ = parse_bool(value, path, key)?;
                warnings.push(
                    "unified-delay is recorded but delay probes report the full round trip (handshake subtraction is not implemented)"
                        .to_string(),
                );
            }
            "tcp-concurrent" => {
                let _ = parse_bool(value, path, key)?;
                warnings.push(
                    "tcp-concurrent is recorded but dials use one ordered address attempt (hedged concurrent dialing is not implemented)"
                        .to_string(),
                );
            }
            "find-process-mode" => {
                let mode = parse_string(value, path, key)?;
                if mode != "off" {
                    return Err(ConfigError::Unsupported(format!(
                        "find-process-mode '{mode}' (process lookup is not implemented; 'off' is accepted as inert)"
                    )));
                }
                warnings.push("find-process-mode is off; process matching rules stay unsupported".to_string());
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
            "proxy-groups" => proxy_groups_value = Some(value),
            "profile" => profile = parse_profile(value, path, &mut warnings)?,
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
            "tls" => {
                let parsed = parse_tls(value, path)?;
                tls_roots = parsed.roots;
                controller.certificate = parsed.server_certificate;
                controller.private_key = parsed.server_private_key;
            }
            "external-controller" => {
                controller.external_controller = Some(parse_controller_addr(value, path, key)?)
            }
            "external-controller-unix" => {
                let raw = parse_string(value, path, key)?;
                if raw.trim().is_empty() {
                    return Err(ConfigError::InvalidValue(format!(
                        "{path}: {key} must not be empty"
                    )));
                }
                controller.external_controller_unix = Some(std::path::PathBuf::from(raw));
            }
            "external-controller-tls" => {
                controller.external_controller_tls = Some(parse_controller_addr(value, path, key)?)
            }
            "external-controller-cors" => {
                controller.cors = parse_cors(value, path, &mut warnings)?
            }
            "secret" => controller.secret = parse_string(value, path, key)?,
            "hosts" => hosts = crate::dns::HostsConfig::parse(value, path)?,
            "dns" => dns = crate::dns::DnsConfig::parse(value, path, &mut warnings)?,
            "ipv6" => general_ipv6 = parse_bool(value, path, key)?,
            // `tun` is parsed strictly (T34); `sniffer` remains an inert block
            // because this kernel does not implement sniffing at all.
            "tun" => tun = parse_tun(value, path, &mut warnings)?,
            "sniffer" => {
                if block_enabled(value, path, key)? {
                    return Err(ConfigError::Unsupported(format!(
                        "top-level key '{key}' with enable: true is not implemented (sniffing is T7)"
                    )));
                }
                warnings.push(
                    "'sniffer' is present but disabled; this kernel has no sniffer implementation, so the block is inert"
                        .to_string(),
                );
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
                        "dns" | "hosts" => " (DNS/hosts are T22)",
                        "external-controller-pipe" => {
                            " (the control API is T25; a Windows named pipe is not implemented, use external-controller, external-controller-unix or external-controller-tls)"
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
                "no listener port is enabled: mixed-port/port/socks-port are 0 or unset while a 0 value disabled the default (the mixed listener is always started; TUN does not replace it)"
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
    let proxy_groups = match proxy_groups_value {
        None => Vec::new(),
        Some(value) => parse_proxy_groups(
            value,
            path,
            &proxies,
            &proxy_providers,
            &mut warnings,
        )?,
    };

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
        groups: &proxy_groups,
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

    if !general_ipv6 && tun.enable {
        warnings.push(
            "ipv6: false clears the TUN IPv6 address, routes and DNS entries".to_string(),
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
        proxy_groups,
        profile,
        sub_rules,
        geodata_mode,
        geodata_loader,
        geosite_matcher,
        geo_auto_update,
        inbound_users: authentication,
        tls_roots,
        dns,
        hosts,
        ipv6: general_ipv6,
        tun,
        controller,
        digest,
    };
    Ok(LoadedConfig { config, warnings })
}


/// Names visible to a rule line while it is parsed.
struct RuleContext<'a> {
    proxies: &'a [crate::proxies::Proxy],
    groups: &'a [ProxyGroup],
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
            groups: &[],
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

pub(crate) fn trim_rule_field(field: &str) -> &str {
    field.trim().trim_matches(['"', '\''])
}

fn split_rule_fields(line: &str) -> Vec<String> {
    line.split(',').map(|field| trim_rule_field(field).to_string()).collect()
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
        Some(target) => parse_action_with(target, context)?,
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
            "TUN" => types.push(InType::Tun),
            other => {
                return Err(ConfigError::Unsupported(format!(
                    "IN-TYPE '{other}' (this kernel serves HTTP CONNECT and SOCKS5 on the mixed listener and TUN for the iOS packet tunnel; redir/tproxy and other listeners are T6/T25)"
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

fn parse_action_with(raw: &str, context: &RuleContext<'_>) -> Result<Action, ConfigError> {
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
        other => match context.proxies.iter().position(|p| p.name == other) {
            Some(index) => Ok(Action::Proxy(index)),
            None => match context.groups.iter().position(|group| group.name == other) {
                Some(index) => Ok(Action::Group(index)),
                // A named outbound that is not a configured proxy or group
                // (providers, built-ins of other tasks) is named explicitly.
                None => Err(ConfigError::Unsupported(format!(
                    "outbound '{other}' is not a configured proxy or proxy group (DIRECT, REJECT, REJECT-DROP, inline proxies and proxy groups are available)"
                ))),
            },
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

/// `profile`: `store-selected` gates the selection cache (T23);
/// `store-fake-ip` belongs to the DNS/fake-ip store (T22) and is recorded only.
fn parse_profile(
    value: &serde_yaml::Value,
    path: &str,
    warnings: &mut Vec<String>,
) -> Result<ProfileConfig, ConfigError> {
    if value.is_null() {
        return Ok(ProfileConfig::default());
    }
    let mapping = value.as_mapping().ok_or_else(|| {
        ConfigError::InvalidValue(format!("{path}: profile must be a mapping"))
    })?;
    let mut profile = ProfileConfig::default();
    for (key, item) in mapping {
        let key = key.as_str().ok_or_else(|| {
            ConfigError::InvalidValue(format!("{path}: profile keys must be strings"))
        })?;
        match key {
            "store-selected" => {
                profile.store_selected = yaml_bool(item, path, "profile.store-selected")?
            }
            "store-fake-ip" => {
                profile.store_fake_ip = yaml_bool(item, path, "profile.store-fake-ip")?
            }
            // Pinned `RawProfile` declares exactly these two keys; its decoder
            // tolerates extra keys, so they are ignored the same way.
            _ => {}
        }
    }
    if profile.store_fake_ip {
        warnings.push(
            "profile.store-fake-ip is true but the fake-ip pool and its IP->host mapping are in-memory only: the pinned cache.db persistence of allocations across restarts is not implemented"
                .to_string(),
        );
    }
    Ok(profile)
}

/// The pinned default test URL for groups and proxies.
pub const DEFAULT_TEST_URL: &str = "https://www.gstatic.com/generate_204";

/// `proxy-groups` (T23). Groups are validated as a DAG so a nested reference
/// may point at a group declared later (the pinned engine topological-sorts
/// `proxy-groups` before constructing them).
fn parse_proxy_groups(
    value: &serde_yaml::Value,
    path: &str,
    proxies: &[crate::proxies::Proxy],
    providers: &[ProxyProviderConfig],
    warnings: &mut Vec<String>,
) -> Result<Vec<ProxyGroup>, ConfigError> {
    let seq = match value.as_sequence() {
        Some(seq) => seq,
        None if value.is_null() => return Ok(Vec::new()),
        None => {
            return Err(ConfigError::InvalidValue(format!(
                "{path}: proxy-groups must be a list"
            )))
        }
    };
    let provider_names = providers
        .iter()
        .map(|provider| provider.name.clone())
        .collect::<BTreeSet<_>>();
    let mut all_proxy_names = proxies
        .iter()
        .map(|proxy| proxy.name.clone())
        .collect::<Vec<_>>();
    all_proxy_names.sort();
    let group_names = seq
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let mapping = item.as_mapping().ok_or_else(|| {
                ConfigError::InvalidValue(format!(
                    "{path}: proxy-groups[{index}] must be a mapping"
                ))
            })?;
            let name = optional_string(mapping, "name")?.ok_or_else(|| {
                ConfigError::InvalidValue(format!("{path}: proxy group {index}: missing name"))
            })?;
            if name.is_empty() {
                return Err(ConfigError::InvalidValue(format!(
                    "{path}: proxy group {index}: name must not be empty"
                )));
            }
            Ok(name)
        })
        .collect::<Result<Vec<_>, ConfigError>>()?;
    let mut seen = BTreeSet::new();
    for name in &group_names {
        if !seen.insert(name.clone()) {
            return Err(ConfigError::InvalidValue(format!(
                "{path}: ProxyGroup {name}: duplicate group name"
            )));
        }
        if matches!(
            name.as_str(),
            "DIRECT" | "REJECT" | "REJECT-DROP" | "COMPATIBLE" | "PASS" | "PASS-RULE" | "GLOBAL"
        ) || proxies.iter().any(|proxy| &proxy.name == name)
        {
            return Err(ConfigError::InvalidValue(format!(
                "{path}: proxy group {name}: the duplicate name"
            )));
        }
    }
    let group_set = seen.clone();
    verify_group_cycles(seq, &group_names, &group_set)?;

    let mut groups = Vec::with_capacity(seq.len());
    for (index, item) in seq.iter().enumerate() {
        let mapping = item.as_mapping().expect("checked above");
        let location = format!("{path}: proxy group[{index}]");
        let name = group_names[index].clone();
        let location = format!("{location} ({name})");
        let kind_raw = optional_string(mapping, "type")?.unwrap_or_default();
        let kind = match kind_raw.as_str() {
            "select" => GroupKind::Select,
            "url-test" => GroupKind::UrlTest,
            "fallback" => GroupKind::Fallback,
            "load-balance" => GroupKind::LoadBalance,
            // Pinned v1.19.34 removed the relay group type with this message.
            "relay" => {
                return Err(ConfigError::Unsupported(format!(
                    "{location}: unsupported type: The group [{name}] with relay type was removed, please using dialer-proxy instead"
                )))
            }
            "" => {
                return Err(ConfigError::InvalidValue(format!(
                    "{location}: format error (type is required)"
                )))
            }
            other => {
                return Err(ConfigError::Unsupported(format!(
                    "{location}: unsupported type: {other}"
                )))
            }
        };
        // The pinned decoder reads these keys but only logs a removal notice.
        for (key, message) in [
            ("routing-mark", "routing-mark"),
            ("interface-name", "interface-name"),
            ("dialer-proxy", "dialer-proxy"),
        ] {
            if optional_value(mapping, key)?.is_some() {
                warnings.push(format!(
                    "{location}: '{message}' is not allowed on a group; set it on the proxy instead (pinned logs the same and continues)"
                ));
            }
        }
        let mut proxies_list = optional_string_list(mapping, "proxies")?;
        let mut use_providers = optional_string_list(mapping, "use")?;
        let empty_fallback_name = optional_string(mapping, "empty-fallback")?
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "COMPATIBLE".to_string());
        let include_all = optional_bool(mapping, "include-all")?.unwrap_or(false);
        let mut include_all_proxies = optional_bool(mapping, "include-all-proxies")?.unwrap_or(false);
        let mut include_all_providers =
            optional_bool(mapping, "include-all-providers")?.unwrap_or(false);
        if include_all {
            include_all_providers = true;
            include_all_proxies = true;
        }
        if include_all_providers {
            use_providers = provider_names.iter().cloned().collect();
        }
        let filter = split_backtick(optional_string(mapping, "filter")?);
        let exclude_filter = split_backtick(optional_string(mapping, "exclude-filter")?);
        for (key, patterns) in [("filter", &filter), ("exclude-filter", &exclude_filter)] {
            for pattern in patterns {
                validate_regex(pattern).map_err(|e| {
                    config_error_with_prefix(e, &format!("{location}: {key} {pattern:?}"))
                })?;
            }
        }
        if include_all_proxies {
            if filter.is_empty() {
                proxies_list.extend(all_proxy_names.iter().cloned());
            } else {
                for pattern in &filter {
                    let regex = regex::Regex::new(pattern).expect("validated above");
                    for candidate in &all_proxy_names {
                        if regex.is_match(candidate) {
                            proxies_list.push(candidate.clone());
                        }
                    }
                }
            }
            if proxies_list.is_empty() && use_providers.is_empty() {
                // Pinned `parser.go`: the empty expansion falls back to the
                // configured `empty-fallback` name, not a hard-coded
                // COMPATIBLE. `empty-fallback: REJECT` therefore blocks the
                // group instead of turning it into a direct route.
                proxies_list.push(empty_fallback_name.clone());
            }
        }
        if proxies_list.is_empty() && use_providers.is_empty() {
            return Err(ConfigError::InvalidValue(format!(
                "{location}: `use` or `proxies` missing"
            )));
        }
        for member in &proxies_list {
            if member == "PASS" || member == "PASS-RULE" {
                return Err(ConfigError::Unsupported(format!(
                    "{location}: group member '{member}' (PASS markers are not implemented)"
                )));
            }
            let known = member == "DIRECT"
                || member == "REJECT"
                || member == "REJECT-DROP"
                || member == "COMPATIBLE"
                || proxies.iter().any(|proxy| &proxy.name == member)
                || group_set.contains(member);
            if !known {
                return Err(ConfigError::InvalidValue(format!(
                    "{location}: '{member}' not found"
                )));
            }
        }
        for provider in &use_providers {
            if !provider_names.contains(provider) {
                return Err(ConfigError::InvalidValue(format!(
                    "{location}: '{provider}' not found"
                )));
            }
        }
        let explicit_url = optional_string(mapping, "url")?
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty());
        let url = match &explicit_url {
            Some(url) => url.clone(),
            None => {
                // Pinned uses the first `use` provider's health-check URL when
                // the group has no URL; otherwise the built-in default.
                let from_provider = use_providers.iter().find_map(|name| {
                    providers
                        .iter()
                        .find(|provider| &provider.name == name)
                        .and_then(|provider| provider.health_check.url.clone())
                        .filter(|url| !url.trim().is_empty())
                });
                from_provider.unwrap_or_else(|| DEFAULT_TEST_URL.to_string())
            }
        };
        let mut interval = optional_positive_int(mapping, "interval")?.unwrap_or(0);
        let registration_interval = interval;
        let timeout = optional_positive_int(mapping, "timeout")?.unwrap_or(0);
        let max_failed_times = optional_positive_int(mapping, "max-failed-times")?.unwrap_or(0)
            as usize;
        let lazy = optional_bool(mapping, "lazy")?.unwrap_or(true);
        let expected_status = ExpectedStatus::parse(
            &optional_string_or_number(mapping, "expected-status")?.unwrap_or_default(),
        )
        .map_err(|e| ConfigError::InvalidValue(format!("{location}: {e}")))?;
        let exclude_type = optional_string(mapping, "exclude-type")?
            .map(|types| {
                types
                    .split('|')
                    .map(|value| value.trim().to_ascii_lowercase())
                    .filter(|value| !value.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        // A `select` group has no automatic health check; every other type
        // defaults to 300 s, but only when the group owns an inline member
        // provider (the pinned parser sets it inside that branch).
        if kind != GroupKind::Select && interval == 0 && !proxies_list.is_empty() {
            interval = 300;
        }
        let tolerance = optional_positive_int(mapping, "tolerance")?.unwrap_or(0);
        if tolerance > u64::from(u16::MAX) {
            return Err(ConfigError::InvalidValue(format!(
                "{location}: tolerance {tolerance} exceeds 65535"
            )));
        }
        let tolerance = tolerance as u16;
        let strategy = match optional_string(mapping, "strategy")?.as_deref() {
            None | Some("") | Some("consistent-hashing") => {
                LoadBalanceStrategy::ConsistentHashing
            }
            Some("round-robin") => LoadBalanceStrategy::RoundRobin,
            Some("sticky-sessions") => LoadBalanceStrategy::StickySessions,
            Some(other) => {
                return Err(ConfigError::Unsupported(format!(
                    "{location}: unsupported strategy: {other}"
                )))
            }
        };
        let hash_key = match optional_string(mapping, "hash-key")?.as_deref() {
            None | Some("") => HashKey::Default,
            Some("in-user") => {
                return Err(ConfigError::Unsupported(format!(
                    "{location}: hash-key 'in-user' is not implemented (the authenticated inbound user is not propagated to the outbound in this kernel)"
                )))
            }
            Some(other) => {
                return Err(ConfigError::Unsupported(format!(
                    "{location}: unsupported hash-key: {other}"
                )))
            }
        };
        if strategy == LoadBalanceStrategy::RoundRobin && hash_key != HashKey::Default {
            return Err(ConfigError::Unsupported(format!(
                "{location}: hash-key with round-robin is not implemented (round-robin does not hash)"
            )));
        }
        let default_selected = optional_string(mapping, "default-selected")?;
        let empty_fallback = match empty_fallback_name.as_str() {
            "COMPATIBLE" => EmptyFallback::Compatible,
            "DIRECT" => EmptyFallback::Direct,
            "REJECT" => EmptyFallback::Reject,
            "REJECT-DROP" => EmptyFallback::RejectDrop,
            other => match proxies.iter().position(|proxy| proxy.name == other) {
                Some(index) => EmptyFallback::Proxy(index),
                None => {
                    return Err(ConfigError::InvalidValue(format!(
                        "{location}: empty fallback proxy '{other}' not found"
                    )))
                }
            },
        };
        groups.push(ProxyGroup {
            name,
            kind,
            proxies: proxies_list,
            use_providers,
            url,
            url_explicit: explicit_url.is_some(),
            interval,
            registration_interval,
            timeout,
            lazy,
            max_failed_times,
            expected_status,
            filter,
            exclude_filter,
            exclude_type,
            tolerance,
            strategy,
            hash_key,
            default_selected: default_selected.filter(|name| !name.is_empty()),
            disable_udp: optional_bool(mapping, "disable-udp")?.unwrap_or(false),
            hidden: optional_bool(mapping, "hidden")?.unwrap_or(false),
            icon: optional_string(mapping, "icon")?.unwrap_or_default(),
            empty_fallback,
        });
    }
    Ok(groups)
}

fn split_backtick(raw: Option<String>) -> Vec<String> {
    match raw {
        None => Vec::new(),
        Some(text) => {
            // Pinned `strings.Split(filter, "`")` after a non-empty check: an
            // empty piece is a valid regexp that matches every name.
            if text.is_empty() {
                Vec::new()
            } else {
                text.split('`').map(str::to_string).collect()
            }
        }
    }
}

/// Reject group cycles (including self references) with the pinned "loop"
/// wording. Nested references may point forwards; only cycles fail.
fn verify_group_cycles(
    seq: &[serde_yaml::Value],
    names: &[String],
    group_set: &BTreeSet<String>,
) -> Result<(), ConfigError> {
    let mut edges: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (index, item) in seq.iter().enumerate() {
        let mapping = item.as_mapping().expect("checked by the caller");
        let members = optional_string_list(mapping, "proxies")?;
        edges.insert(
            names[index].clone(),
            members
                .into_iter()
                .filter(|member| group_set.contains(member))
                .collect(),
        );
    }
    fn visit(
        name: &str,
        edges: &BTreeMap<String, Vec<String>>,
        stack: &mut Vec<String>,
    ) -> Result<(), ConfigError> {
        if let Some(position) = stack.iter().position(|entry| entry == name) {
            let mut chain = stack[position..].to_vec();
            chain.push(name.to_string());
            return Err(ConfigError::InvalidValue(format!(
                "ProxyGroup {name}: loop detected: {}",
                chain.join(" -> ")
            )));
        }
        stack.push(name.to_string());
        if let Some(children) = edges.get(name) {
            for child in children {
                visit(child, edges, stack)?;
            }
        }
        stack.pop();
        Ok(())
    }
    for name in names {
        visit(name, &edges, &mut Vec::new())?;
    }
    Ok(())
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
    // Pinned `NewHealthCheck` reads this as milliseconds (`time.Duration(t) *
    // time.Millisecond`), like the group `timeout` key.
    config.timeout = optional_positive_int(mapping, "timeout")?.unwrap_or(0);
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
    // Validate the expected-status syntax now so a typo fails at load instead
    // of being discovered by the health scheduler.
    if !config.expected_status.trim().is_empty() {
        ExpectedStatus::parse(&config.expected_status)
            .map_err(|e| config_error_with_prefix(ConfigError::InvalidValue(e), location))?;
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

/// Strings that the pinned weakly-typed decoder also accepts as numbers
/// (e.g. `expected-status: 204`).
fn optional_string_or_number(
    fields: &serde_yaml::Mapping,
    key: &str,
) -> Result<Option<String>, ConfigError> {
    match optional_value(fields, key)? {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::String(value)) => Ok(Some(value.clone())),
        Some(serde_yaml::Value::Number(value)) => Ok(Some(value.to_string())),
        Some(other) => Err(ConfigError::InvalidValue(format!(
            "'{key}' must be a string or number, found {}",
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
struct ParsedTls {
    roots: Vec<rustls_pki_types::CertificateDer<'static>>,
    /// Top-level `tls.certificate` when it names a file (pinned uses it for
    /// `external-controller-tls`); a directory is read as client trust roots.
    server_certificate: Option<Vec<u8>>,
    /// Top-level `tls.private-key` (controller TLS).
    server_private_key: Option<Vec<u8>>,
}

fn parse_tls(
    value: &serde_yaml::Value,
    path: &str,
) -> Result<ParsedTls, ConfigError> {
    let map = value
        .as_mapping()
        .ok_or_else(|| ConfigError::InvalidValue(format!("{path}: tls must be a mapping")))?;
    let base = std::path::Path::new(path).parent().map(|p| p.to_path_buf());
    let mut pems = Vec::new();
    let mut server_certificate = None;
    let mut server_private_key = None;
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
                    ConfigError::InvalidValue(format!("{path}: tls.certificate must be a file, directory or PEM string"))
                })?;
                if raw.contains("-----BEGIN") {
                    // Pinned expects a path; an inline certificate keeps the
                    // controller listener usable without a file.
                    server_certificate = Some(raw.as_bytes().to_vec());
                    continue;
                }
                let candidate = resolve(raw);
                if candidate.is_file() {
                    server_certificate = Some(std::fs::read(&candidate).map_err(|e| {
                        ConfigError::InvalidValue(format!(
                            "{path}: tls.certificate {}: {e}",
                            candidate.display()
                        ))
                    })?);
                    continue;
                }
                let entries = std::fs::read_dir(&candidate).map_err(|e| {
                    ConfigError::InvalidValue(format!("{path}: tls.certificate directory {}: {e}", candidate.display()))
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
            Some("private-key") => {
                let raw = item.as_str().ok_or_else(|| {
                    ConfigError::InvalidValue(format!("{path}: tls.private-key must be a file or PEM string"))
                })?;
                server_private_key = Some(if raw.contains("-----BEGIN") {
                    raw.as_bytes().to_vec()
                } else {
                    let candidate = resolve(raw);
                    std::fs::read(&candidate).map_err(|e| {
                        ConfigError::InvalidValue(format!(
                            "{path}: tls.private-key {}: {e}",
                            candidate.display()
                        ))
                    })?
                });
            }
            Some(other) => {
                return Err(ConfigError::Unsupported(format!(
                    "{path}: tls.{other} is not implemented (only custom-cert, certificate and private-key are honoured)"
                )))
            }
            None => return Err(ConfigError::InvalidValue(format!("{path}: tls keys must be strings"))),
        }
    }
    let mut roots = Vec::new();
    for pem in pems {
        roots.extend(crate::outbound::tls::parse_pem_certs(&pem)?);
    }
    Ok(ParsedTls {
        roots,
        server_certificate,
        server_private_key,
    })
}

/// `external-controller: 127.0.0.1:9090` (pinned `net.Listen` address).
fn parse_controller_addr(
    value: &serde_yaml::Value,
    path: &str,
    key: &str,
) -> Result<String, ConfigError> {
    let raw = parse_string(value, path, key)?;
    let text = raw.trim();
    if text.is_empty() {
        return Err(ConfigError::InvalidValue(format!("{path}: {key} must not be empty")));
    }
    let (_, port) = text.rsplit_once(':').ok_or_else(|| {
        ConfigError::InvalidValue(format!("{path}: {key} '{raw}' must be host:port"))
    })?;
    // Pinned hands the string to `net.Listen`, where a hostless `:9090`
    // binds every interface; accept it here and let the listener map it to
    // `[::]:9090` (IPv4 wildcard fallback).
    port.parse::<u16>().map_err(|_| {
        ConfigError::InvalidValue(format!("{path}: {key} '{raw}' has an invalid port"))
    })?;
    Ok(text.to_string())
}

/// `external-controller-cors` (pinned `RawCors`).
fn parse_cors(
    value: &serde_yaml::Value,
    path: &str,
    warnings: &mut Vec<String>,
) -> Result<CorsConfig, ConfigError> {
    let mut cors = CorsConfig::default();
    if value.is_null() {
        return Ok(cors);
    }
    let mapping = value.as_mapping().ok_or_else(|| {
        ConfigError::InvalidValue(format!("{path}: external-controller-cors must be a mapping"))
    })?;
    for (key, item) in mapping {
        match key.as_str() {
            Some("allow-origins") => {
                let list = item.as_sequence().ok_or_else(|| {
                    ConfigError::InvalidValue(format!(
                        "{path}: external-controller-cors.allow-origins must be a list"
                    ))
                })?;
                let mut origins = Vec::with_capacity(list.len());
                for (index, entry) in list.iter().enumerate() {
                    let origin = entry.as_str().ok_or_else(|| {
                        ConfigError::InvalidValue(format!(
                            "{path}: external-controller-cors.allow-origins[{index}] must be a string"
                        ))
                    })?;
                    origins.push(origin.to_string());
                }
                cors.allow_origins = origins;
            }
            Some("allow-private-network") => {
                cors.allow_private_network =
                    yaml_bool(item, path, "external-controller-cors.allow-private-network")?;
            }
            Some(other) => warnings.push(format!(
                "external-controller-cors.{other} is not a pinned key and is ignored"
            )),
            None => {
                return Err(ConfigError::InvalidValue(format!(
                    "{path}: external-controller-cors keys must be strings"
                )))
            }
        }
    }
    Ok(cors)
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

        /// The network prefix with host bits cleared.
        pub fn masked(&self) -> IpNet {
            let addr = match self.addr {
                IpAddr::V4(addr) => IpAddr::V4(std::net::Ipv4Addr::from(
                    u32::from(addr) & v4_mask(self.prefix),
                )),
                IpAddr::V6(addr) => IpAddr::V6(std::net::Ipv6Addr::from(
                    u128::from(addr) & v6_mask(self.prefix),
                )),
            };
            IpNet {
                addr,
                prefix: self.prefix,
            }
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
