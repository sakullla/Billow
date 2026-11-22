//! DNS and `hosts` for the local kernel, mirroring the pinned Mihomo
//! v1.19.34 `dns`/`component/resolver`/`component/fakeip` behaviour that a
//! configuration can observe.
//!
//! Scope, in the terms of the pinned source:
//!
//! - `hosts` is a domain trie (`component/trie/domain.go`) with the pinned
//!   exact / `*.x` / `.x` / `+.x` / `sub.*.x` semantics and domain-valued
//!   entries; `use-hosts`/`use-system-hosts` gate the DNS-server middleware,
//!   while rule-time resolution always consults the configured hosts (pinned
//!   `resolver.LookupIPWithResolver` does the same).
//! - `nameserver`, `default-nameserver`, `fallback`, `fallback-filter`,
//!   `nameserver-policy`, `proxy-server-nameserver`, `direct-nameserver` and
//!   their policies; `respect-rules` routes TCP/TLS/HTTPS upstreams through
//!   the rule/proxy path.
//! - upstream transports: UDP, TCP, DoT and DoH over HTTP/1.1, with the pinned
//!   default ports, SNI/certificate verification and `skip-cert-verify`.
//! - `enhanced-mode` normal / redir-host / fake-ip, `fake-ip-range`(6),
//!   `fake-ip-filter`(mode blacklist/whitelist), `fake-ip-ttl`, fake-ip pool
//!   allocation and the IP→host mapping used to rebuild a connection from a
//!   fake destination.
//! - the optional DNS server on `dns.listen` (UDP and TCP) implements the
//!   pinned middleware order hosts → fake-ip → mapping → resolver.
//!
//! Everything a configuration asks for that this module does not implement is
//! rejected by name at load time (DoQ, DHCP/Tailscale/EasyTier/rcode/system
//! upstreams, fake-ip-filter `rule` mode, a `#proxy` suffix, EDNS client
//! subnet, `name-cert-verify`, `profile.store-fake-ip` persistence); see
//! `native-kernel/README.md` and `tool/kernel-compat/evidence/rust-mapping.json`.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde_yaml::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;

use crate::config::ipnet_like::IpNet;
use crate::config::ConfigError;
use crate::geodata::{self, DomainSet, GeoIpMatcher};
use crate::outbound::tls::ClientTls;

/// Pinned `resolver.DefaultDNSTimeout`.
pub const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest DNS message this module builds or accepts.
pub const DNS_MAX_MESSAGE: usize = 65535;
/// Pinned minimum fake-ip TTL (`NewEnhancer` clamps `fake-ip-ttl` to 1).
pub const FAKE_IP_MIN_TTL: u32 = 1;
/// Pinned cache size when `cache-max-size` is 0.
pub const DEFAULT_CACHE_SIZE: usize = 4096;
/// Pinned server-failure cache TTL.
const SERVER_FAILURE_TTL: u32 = 5;
/// Pinned fake-ip host mapping LRU size (`lru.WithSize(4096)`).
const MAPPING_SIZE: usize = 4096;
/// Pinned `fakeip.New(Options{Size: 1000})` in-memory store bound.
const FAKE_IP_STORE_SIZE: usize = 1000;

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const TYPE_HTTPS: u16 = 65;
const TYPE_SVCB: u16 = 64;
const CLASS_IN: u16 = 1;

// ---------------------------------------------------------------------------
// Configuration model (parsed in `config.rs` through `DnsConfig::parse`)
// ---------------------------------------------------------------------------

/// Pinned `constant.DNSMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnhancedMode {
    /// `normal`
    Normal,
    /// `redir-host`: record IP→host for every answer.
    RedirHost,
    /// `fake-ip`: answer A/AAAA from the fake pool.
    FakeIp,
}

impl EnhancedMode {
    fn parse(value: &str) -> Option<EnhancedMode> {
        match value.to_ascii_lowercase().as_str() {
            "normal" => Some(EnhancedMode::Normal),
            "redir-host" => Some(EnhancedMode::RedirHost),
            "fake-ip" => Some(EnhancedMode::FakeIp),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            EnhancedMode::Normal => "normal",
            EnhancedMode::RedirHost => "redir-host",
            EnhancedMode::FakeIp => "fake-ip",
        }
    }
}

/// Pinned `constant.FilterMode` (the `rule` mode is rejected by name).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeIpFilterMode {
    Blacklist,
    Whitelist,
}

/// One upstream transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameServerNet {
    Udp,
    Tcp,
    Tls,
    Https,
}

impl NameServerNet {
    fn scheme(&self) -> &'static str {
        match self {
            NameServerNet::Udp => "udp",
            NameServerNet::Tcp => "tcp",
            NameServerNet::Tls => "tls",
            NameServerNet::Https => "https",
        }
    }
}

/// One parsed `nameserver` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameServer {
    pub net: NameServerNet,
    /// Host name or literal IP (no brackets); DoH keeps its path separately.
    pub host: String,
    pub port: u16,
    /// DoH request path (`https://host/path`).
    pub path: String,
    /// `#key=value` parameters, pinned `NameServer.Params`.
    pub params: BTreeMap<String, String>,
    /// Explicit `#proxy` name. Pinned also injects `RULES` here for
    /// `respect-rules`; [`NameServer::respect_rules`] marks that case.
    pub proxy: Option<String>,
    /// `http://` (plain HTTP DoH, no TLS) rather than `https://`.
    pub plain_http: bool,
    /// `true` when `respect-rules` applies (pinned's `RULES` sentinel).
    pub respect_rules: bool,
    pub prefer_h3: bool,
}

impl NameServer {
    /// Pinned `NameServer.Address()`-style label used in logs and errors.
    pub fn address(&self) -> String {
        match self.net {
            NameServerNet::Https => format!("https://{}:{}{}", self.host, self.port, self.path),
            other => format!("{}://{}:{}", other.scheme(), self.host, self.port),
        }
    }

    fn param(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(String::as_str)
    }

    fn skip_cert_verify(&self) -> bool {
        self.param("skip-cert-verify") == Some("true")
    }

    fn disabled_types(&self) -> Vec<u16> {
        let mut out = Vec::new();
        if self.param("disable-ipv4") == Some("true") {
            out.push(TYPE_A);
        }
        if self.param("disable-ipv6") == Some("true") {
            out.push(TYPE_AAAA);
        }
        for (key, value) in &self.params {
            if value != "true" {
                continue;
            }
            if let Some(raw) = key.strip_prefix("disable-qtype-") {
                if let Ok(qtype) = raw.parse::<u16>() {
                    out.push(qtype);
                }
            }
        }
        out
    }
}

/// `154.1.2.3` (pinned `RawFallbackFilter`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackFilter {
    pub geoip: bool,
    pub geoip_code: String,
    pub ipcidr: Vec<IpNet>,
    /// Plain domain patterns (`fallback-filter.domain`).
    pub domain: Vec<String>,
    /// `geosite:` references.
    pub geosite: Vec<String>,
}

impl FallbackFilter {
    fn default_pinned() -> FallbackFilter {
        FallbackFilter {
            geoip: true,
            geoip_code: "CN".to_string(),
            ipcidr: Vec::new(),
            domain: Vec::new(),
            geosite: Vec::new(),
        }
    }
}

/// One `nameserver-policy` pair; the key is kept raw because `geosite:` and
/// `rule-set:` keys are resolved against the loaded providers at start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameServerPolicy {
    pub key: String,
    pub servers: Vec<NameServer>,
}

/// Parsed `dns:` block (pinned `RawDNS` + `config.DNS` validated form).
#[derive(Debug, Clone, PartialEq)]
pub struct DnsConfig {
    pub enable: bool,
    pub prefer_h3: bool,
    pub ipv6: bool,
    pub ipv6_timeout: Duration,
    pub use_hosts: bool,
    pub use_system_hosts: bool,
    pub respect_rules: bool,
    pub nameserver: Vec<NameServer>,
    pub fallback: Vec<NameServer>,
    pub fallback_filter: FallbackFilter,
    pub fallback_lazy_query: bool,
    pub listen: Option<SocketAddr>,
    pub enhanced_mode: EnhancedMode,
    pub fake_ip_range: Option<IpNet>,
    pub fake_ip_range6: Option<IpNet>,
    pub fake_ip_filter: Vec<String>,
    pub fake_ip_filter_mode: FakeIpFilterMode,
    pub fake_ip_ttl: u32,
    pub default_nameserver: Vec<NameServer>,
    pub cache_algorithm: String,
    pub cache_max_size: usize,
    pub nameserver_policy: Vec<NameServerPolicy>,
    pub proxy_server_nameserver: Vec<NameServer>,
    pub proxy_server_nameserver_policy: Vec<NameServerPolicy>,
    pub direct_nameserver: Vec<NameServer>,
    pub direct_nameserver_follow_policy: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        // Pinned `DefaultRawConfig().DNS`; parsing replaces only keys present
        // in the YAML, so an omitted `dns:` block behaves like this too.
        DnsConfig {
            enable: false,
            prefer_h3: false,
            ipv6: false,
            ipv6_timeout: Duration::from_millis(100),
            use_hosts: true,
            use_system_hosts: true,
            respect_rules: false,
            nameserver: Vec::new(),
            fallback: Vec::new(),
            fallback_filter: FallbackFilter::default_pinned(),
            fallback_lazy_query: false,
            listen: None,
            enhanced_mode: EnhancedMode::RedirHost,
            fake_ip_range: Some("198.18.0.0/16".parse().expect("valid default fake-ip range")),
            fake_ip_range6: None,
            fake_ip_filter: vec![
                "dns.msftnsci.com".to_string(),
                "www.msftnsci.com".to_string(),
                "www.msftconnecttest.com".to_string(),
            ],
            fake_ip_filter_mode: FakeIpFilterMode::Blacklist,
            fake_ip_ttl: 1,
            default_nameserver: Vec::new(),
            cache_algorithm: "lru".to_string(),
            cache_max_size: DEFAULT_CACHE_SIZE,
            nameserver_policy: Vec::new(),
            proxy_server_nameserver: Vec::new(),
            proxy_server_nameserver_policy: Vec::new(),
            direct_nameserver: Vec::new(),
            direct_nameserver_follow_policy: false,
        }
    }
}

impl DnsConfig {
    /// Effective IPv6 switch: pinned `ipv6 := c.IPv6 && generalIPv6`.
    pub fn effective_ipv6(&self, general_ipv6: bool) -> bool {
        self.ipv6 && general_ipv6
    }

    /// Parse the `dns:` mapping. Unknown keys are ignored exactly like the
    /// pinned decoder; every declared key is either honoured or rejected by
    /// name through [`NameServer`] parsing.
    pub fn parse(value: &Value, path: &str, warnings: &mut Vec<String>) -> Result<DnsConfig, ConfigError> {
        if value.is_null() {
            return Ok(DnsConfig::default());
        }
        let mapping = value.as_mapping().ok_or_else(|| {
            ConfigError::InvalidValue(format!("{path}: dns must be a mapping"))
        })?;
        let mut cfg = DnsConfig::default();
        let mut default_nameserver_present = false;
        for (key, item) in mapping {
            let key = key.as_str().ok_or_else(|| {
                ConfigError::InvalidValue(format!("{path}: dns keys must be strings"))
            })?;
            let at = format!("{path}.dns.{key}");
            match key {
                "enable" => cfg.enable = yaml_bool(item, &at)?,
                "prefer-h3" => cfg.prefer_h3 = yaml_bool(item, &at)?,
                "ipv6" => cfg.ipv6 = yaml_bool(item, &at)?,
                "ipv6-timeout" => {
                    cfg.ipv6_timeout = Duration::from_millis(yaml_u64(item, &at)?)
                }
                "use-hosts" => cfg.use_hosts = yaml_bool(item, &at)?,
                "use-system-hosts" => cfg.use_system_hosts = yaml_bool(item, &at)?,
                "respect-rules" => cfg.respect_rules = yaml_bool(item, &at)?,
                "nameserver" => {
                    cfg.nameserver = parse_nameserver_list(item, &at, cfg.respect_rules, cfg.prefer_h3)?
                }
                "fallback" => {
                    cfg.fallback = parse_nameserver_list(item, &at, cfg.respect_rules, cfg.prefer_h3)?
                }
                "fallback-filter" => {
                    cfg.fallback_filter = parse_fallback_filter(item, &at)?
                }
                "fallback-lazy-query" => cfg.fallback_lazy_query = yaml_bool(item, &at)?,
                "listen" => {
                    let text = yaml_string(item, &at)?;
                    let addr: SocketAddr = text.parse().map_err(|e| {
                        ConfigError::InvalidValue(format!(
                            "{at}: '{text}' is not an IP:port address ({e})"
                        ))
                    })?;
                    cfg.listen = Some(addr);
                }
                "enhanced-mode" => {
                    let text = yaml_string(item, &at)?;
                    cfg.enhanced_mode = EnhancedMode::parse(&text).ok_or_else(|| {
                        ConfigError::Unsupported(format!(
                            "{at}: enhanced-mode '{text}' (normal, redir-host and fake-ip are implemented)"
                        ))
                    })?;
                }
                "fake-ip-range" => {
                    cfg.fake_ip_range = Some(parse_prefix(item, &at)?);
                }
                "fake-ip-range6" => {
                    cfg.fake_ip_range6 = Some(parse_prefix(item, &at)?);
                }
                "fake-ip-filter" => {
                    cfg.fake_ip_filter = parse_string_list(item, &at)?;
                }
                "fake-ip-filter-mode" => {
                    let text = yaml_string(item, &at)?.to_ascii_lowercase();
                    cfg.fake_ip_filter_mode = match text.as_str() {
                        "blacklist" => FakeIpFilterMode::Blacklist,
                        "whitelist" => FakeIpFilterMode::Whitelist,
                        "rule" => {
                            return Err(ConfigError::Unsupported(format!(
                                "{at}: rule mode (fake-ip-filter rule lines are not implemented; blacklist and whitelist are)"
                            )))
                        }
                        other => {
                            return Err(ConfigError::InvalidValue(format!(
                                "{at}: unknown fake-ip-filter-mode '{other}'"
                            )))
                        }
                    };
                }
                "fake-ip-ttl" => {
                    let ttl = yaml_u64(item, &at)?;
                    cfg.fake_ip_ttl = u32::try_from(ttl).map_err(|_| {
                        ConfigError::InvalidValue(format!("{at}: fake-ip-ttl is too large"))
                    })?;
                }
                "default-nameserver" => {
                    default_nameserver_present = true;
                    cfg.default_nameserver =
                        parse_nameserver_list(item, &at, false, cfg.prefer_h3)?;
                }
                "cache-algorithm" => {
                    cfg.cache_algorithm = yaml_string(item, &at)?.to_ascii_lowercase()
                }
                "cache-max-size" => {
                    cfg.cache_max_size = usize::try_from(yaml_u64(item, &at)?)
                        .map_err(|_| ConfigError::InvalidValue(format!("{at}: too large")))?
                }
                "nameserver-policy" => {
                    cfg.nameserver_policy =
                        parse_policy(item, &at, cfg.respect_rules, cfg.prefer_h3)?
                }
                "proxy-server-nameserver" => {
                    cfg.proxy_server_nameserver =
                        parse_nameserver_list(item, &at, false, cfg.prefer_h3)?
                }
                "proxy-server-nameserver-policy" => {
                    cfg.proxy_server_nameserver_policy =
                        parse_policy(item, &at, false, cfg.prefer_h3)?
                }
                "direct-nameserver" => {
                    cfg.direct_nameserver =
                        parse_nameserver_list(item, &at, false, cfg.prefer_h3)?
                }
                "direct-nameserver-follow-policy" => {
                    cfg.direct_nameserver_follow_policy = yaml_bool(item, &at)?
                }
                // Pinned `RawDNS` declares these; the DNS listener implements
                // the policy they name, and a binding route mark is
                // `iptables`-level (not a proxy-engine capability).
                "listen-routing-mark" => {
                    let mark = yaml_u64(item, &at)?;
                    if mark != 0 {
                        return Err(ConfigError::Unsupported(format!(
                            "{at}: non-zero listen-routing-mark is not implemented"
                        )));
                    }
                }
                other => warnings.push(format!(
                    "ignored unknown dns key '{other}' (the pinned RawDNS type does not declare it)"
                )),
            }
        }
        // `respect-rules` applies to every main/fallback/policy server,
        // regardless of the YAML key order (pinned parses the struct first).
        if cfg.respect_rules {
            for ns in cfg
                .nameserver
                .iter_mut()
                .chain(cfg.fallback.iter_mut())
            {
                ns.respect_rules = true;
            }
            for policy in cfg.nameserver_policy.iter_mut() {
                for ns in policy.servers.iter_mut() {
                    ns.respect_rules = true;
                }
            }
        }
        if cfg.enable {
            if cfg.nameserver.is_empty() {
                return Err(ConfigError::InvalidValue(
                    "dns.nameserver cannot be empty while dns.enable is true".to_string(),
                ));
            }
            if cfg.respect_rules && cfg.proxy_server_nameserver.is_empty() {
                return Err(ConfigError::InvalidValue(
                    "dns.respect-rules requires dns.proxy-server-nameserver".to_string(),
                ));
            }
            if !cfg.proxy_server_nameserver_policy.is_empty()
                && cfg.proxy_server_nameserver.is_empty()
            {
                return Err(ConfigError::InvalidValue(
                    "dns.proxy-server-nameserver-policy requires dns.proxy-server-nameserver"
                        .to_string(),
                ));
            }
            if default_nameserver_present && cfg.default_nameserver.is_empty() {
                return Err(ConfigError::InvalidValue(
                    "dns.default-nameserver must have at least one nameserver".to_string(),
                ));
            }
            if !default_nameserver_present {
                // Pinned `DefaultRawConfig` defaults.
                cfg.default_nameserver = [
                    "114.114.114.114",
                    "223.5.5.5",
                    "8.8.8.8",
                    "1.0.0.1",
                ]
                .iter()
                .map(|raw| parse_nameserver(raw, false, false, "dns.default-nameserver"))
                .collect::<Result<Vec<_>, _>>()?;
            }
            for ns in &cfg.default_nameserver {
                if ns.net == NameServerNet::Https && !ns.host.parse::<IpAddr>().is_ok() {
                    return Err(ConfigError::InvalidValue(format!(
                        "dns.default-nameserver '{}' must be a pure IP address",
                        ns.address()
                    )));
                }
                if ns.host.parse::<IpAddr>().is_err() {
                    return Err(ConfigError::InvalidValue(format!(
                        "dns.default-nameserver '{}' must be a pure IP address",
                        ns.address()
                    )));
                }
            }
            if let Some(range) = cfg.fake_ip_range {
                if !range.is_v4() {
                    return Err(ConfigError::InvalidValue(
                        "dns.fake-ip-range must be an IPv4 prefix".to_string(),
                    ));
                }
            }
            if let Some(range) = cfg.fake_ip_range6 {
                if range.is_v4() {
                    return Err(ConfigError::InvalidValue(
                        "dns.fake-ip-range6 must be an IPv6 prefix".to_string(),
                    ));
                }
            }
            if cfg.enhanced_mode == EnhancedMode::FakeIp
                && cfg.fake_ip_range.is_none()
                && cfg.fake_ip_range6.is_none()
            {
                return Err(ConfigError::InvalidValue(
                    "dns.fake-ip-range and dns.fake-ip-range6 are both empty with enhanced-mode fake-ip"
                        .to_string(),
                ));
            }
            if cfg.respect_rules {
                for ns in cfg
                    .nameserver
                    .iter()
                    .chain(cfg.fallback.iter())
                    .filter(|ns| ns.respect_rules)
                {
                    if ns.net == NameServerNet::Udp {
                        return Err(ConfigError::Unsupported(format!(
                            "dns.respect-rules with the UDP nameserver '{}' is not implemented: UDP upstream traffic cannot be routed through a proxy yet; use tcp://, tls:// or https:// for respect-rules",
                            ns.address()
                        )));
                    }
                }
                for policy in &cfg.nameserver_policy {
                    if policy.servers.iter().any(|ns| ns.net == NameServerNet::Udp) {
                        return Err(ConfigError::Unsupported(format!(
                            "dns.respect-rules with the UDP nameserver in dns.nameserver-policy '{}' is not implemented; use tcp://, tls:// or https://",
                            policy.key
                        )));
                    }
                }
            }
            if cfg.cache_algorithm != "lru" && cfg.cache_algorithm != "arc" {
                return Err(ConfigError::InvalidValue(format!(
                    "dns.cache-algorithm '{}' (lru and arc are accepted)",
                    cfg.cache_algorithm
                )));
            }
            if cfg.cache_algorithm == "arc" {
                warnings.push(
                    "dns.cache-algorithm: arc is served by the LRU cache; the eviction order differs but answers and TTLs are unchanged"
                        .to_string(),
                );
            }
        }
        Ok(cfg)
    }
}

fn yaml_bool(value: &Value, at: &str) -> Result<bool, ConfigError> {
    match value {
        Value::Bool(flag) => Ok(*flag),
        other => Err(ConfigError::InvalidValue(format!(
            "{at} must be a boolean, found {other:?}"
        ))),
    }
}

fn yaml_u64(value: &Value, at: &str) -> Result<u64, ConfigError> {
    match value {
        Value::Number(number) => number.as_u64().ok_or_else(|| {
            ConfigError::InvalidValue(format!("{at} must be a non-negative integer"))
        }),
        other => Err(ConfigError::InvalidValue(format!(
            "{at} must be a non-negative integer, found {other:?}"
        ))),
    }
}

fn yaml_string(value: &Value, at: &str) -> Result<String, ConfigError> {
    match value {
        Value::String(text) => Ok(text.clone()),
        Value::Number(number) => Ok(number.to_string()),
        other => Err(ConfigError::InvalidValue(format!(
            "{at} must be a string, found {other:?}"
        ))),
    }
}

fn parse_string_list(value: &Value, at: &str) -> Result<Vec<String>, ConfigError> {
    match value {
        Value::Null => Ok(Vec::new()),
        Value::String(text) => Ok(vec![text.clone()]),
        Value::Sequence(items) => items
            .iter()
            .map(|item| yaml_string(item, at))
            .collect(),
        other => Err(ConfigError::InvalidValue(format!(
            "{at} must be a string or a list of strings, found {other:?}"
        ))),
    }
}

fn parse_prefix(value: &Value, at: &str) -> Result<IpNet, ConfigError> {
    let text = yaml_string(value, at)?;
    text.parse::<IpNet>().map_err(|e| {
        ConfigError::InvalidValue(format!("{at}: '{text}' is not a CIDR prefix ({e})"))
    })
}

fn parse_nameserver_list(
    value: &Value,
    at: &str,
    respect_rules: bool,
    prefer_h3: bool,
) -> Result<Vec<NameServer>, ConfigError> {
    let raw = parse_string_list(value, at)?;
    let mut servers = Vec::with_capacity(raw.len());
    for (index, entry) in raw.iter().enumerate() {
        let ns = parse_nameserver(entry, respect_rules, prefer_h3, &format!("{at}[{index}]"))?;
        if !servers.contains(&ns) {
            servers.push(ns);
        }
    }
    Ok(servers)
}

pub(crate) fn parse_nameserver(
    raw: &str,
    respect_rules: bool,
    prefer_h3: bool,
    at: &str,
) -> Result<NameServer, ConfigError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(ConfigError::InvalidValue(format!("{at}: empty nameserver")));
    }
    // Pinned `parsePureDNSServer` + `url.Parse`: a bare IP or host gets
    // `udp://`, `system` is its own scheme.
    let with_scheme = if raw == "system" {
        "system://".to_string()
    } else if raw.contains("://") {
        raw.to_string()
    } else if let Ok(ip) = raw.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(_) => format!("udp://{raw}"),
            IpAddr::V6(_) => format!("udp://[{raw}]"),
        }
    } else {
        format!("udp://{raw}")
    };
    let (scheme, rest) = with_scheme
        .split_once("://")
        .expect("scheme inserted above");
    let rest = rest.split('#').next().unwrap_or(rest);
    let fragment = with_scheme.split_once('#').map(|(_, f)| f).unwrap_or("");
    let mut params = BTreeMap::new();
    let mut proxy = None;
    for part in fragment.split('&').filter(|part| !part.is_empty()) {
        match part.split_once('=') {
            Some((key, value)) => {
                params.insert(key.to_string(), value.to_string());
            }
            None => proxy = Some(part.to_string()),
        }
    }
    let net = match scheme {
        "udp" => NameServerNet::Udp,
        "tcp" => NameServerNet::Tcp,
        "tls" => NameServerNet::Tls,
        "http" | "https" => NameServerNet::Https,
        "quic" => {
            return Err(ConfigError::Unsupported(format!(
                "{at}: DoQ (quic://) is not implemented (udp, tcp, tls and https are)"
            )))
        }
        "system" => {
            return Err(ConfigError::Unsupported(format!(
                "{at}: system:// nameservers are not implemented (udp, tcp, tls and https are)"
            )))
        }
        "dhcp" => {
            return Err(ConfigError::Unsupported(format!(
                "{at}: dhcp:// nameservers are not implemented"
            )))
        }
        "ts" | "tailscale" | "et" | "easytier" => {
            return Err(ConfigError::Unsupported(format!(
                "{at}: {scheme}:// overlay nameservers are not implemented"
            )))
        }
        "rcode" => {
            return Err(ConfigError::Unsupported(format!(
                "{at}: rcode:// nameservers are not implemented"
            )))
        }
        other => {
            return Err(ConfigError::Unsupported(format!(
                "{at}: nameserver scheme '{other}' is not implemented"
            )))
        }
    };
    let (host_port, path) = match rest.split_once('/') {
        Some((host, path)) => (host, format!("/{path}")),
        None => (rest, String::new()),
    };
    let (host, port) = split_host_port(host_port).map_err(|e| {
        ConfigError::InvalidValue(format!("{at}: nameserver '{raw}' has an invalid host: {e}"))
    })?;
    if host.is_empty() {
        return Err(ConfigError::InvalidValue(format!(
            "{at}: nameserver '{raw}' has no host"
        )));
    }
    let default_port = match net {
        NameServerNet::Udp | NameServerNet::Tcp => 53,
        NameServerNet::Tls => 853,
        NameServerNet::Https if scheme == "http" => 80,
        NameServerNet::Https => 443,
    };
    let port = port.unwrap_or(default_port);
    let path = if net == NameServerNet::Https {
        if path.is_empty() {
            "/".to_string()
        } else {
            path
        }
    } else {
        String::new()
    };
    // Reject the parameters this module cannot honour, and keep the rest
    // (pinned accepts arbitrary params, unknown ones have no effect).
    for key in params.keys() {
        match key.as_str() {
            "skip-cert-verify" | "disable-ipv4" | "disable-ipv6" | "disable-reuse" => {}
            _ if key.starts_with("disable-qtype-") => {
                let raw = key.trim_start_matches("disable-qtype-");
                if raw.parse::<u16>().is_err() {
                    return Err(ConfigError::InvalidValue(format!(
                        "{at}: '{key}' does not name a DNS qtype"
                    )));
                }
            }
            "h3" if params.get("h3").map(String::as_str) == Some("true") => {
                return Err(ConfigError::Unsupported(format!(
                    "{at}: h3=true forces DoH over HTTP/3, which is not implemented (DoH uses HTTP/1.1); drop the parameter or set h3=false"
                )))
            }
            "h3" => {}
            "ecs" | "ecs-override" => {
                return Err(ConfigError::Unsupported(format!(
                    "{at}: EDNS client subnet ('{key}') is not implemented"
                )))
            }
            "name-cert-verify" => {
                return Err(ConfigError::Unsupported(format!(
                    "{at}: name-cert-verify is not implemented (skip-cert-verify is)"
                )))
            }
            _ => {}
        }
    }
    if let Some(name) = &proxy {
        return Err(ConfigError::Unsupported(format!(
            "{at}: nameserver routing through proxy '{name}' (#{name}) is not implemented; use respect-rules with tcp://, tls:// or https:// nameservers"
        )));
    }
    Ok(NameServer {
        net,
        host,
        port,
        path,
        params,
        proxy: None,
        plain_http: scheme == "http",
        respect_rules: respect_rules,
        prefer_h3,
    })
}

/// `host[:port]` with `[v6]` support; the pinned `hostWithDefaultPort`.
fn split_host_port(input: &str) -> Result<(String, Option<u16>), String> {
    if let Some(rest) = input.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| "missing closing ']'".to_string())?;
        host.parse::<Ipv6Addr>()
            .map_err(|e| format!("bad IPv6 address: {e}"))?;
        let port = match tail.strip_prefix(':') {
            Some(port) => Some(port.parse::<u16>().map_err(|e| format!("bad port: {e}"))?),
            None if tail.is_empty() => None,
            None => return Err("unexpected text after ']'".to_string()),
        };
        return Ok((host.to_string(), port));
    }
    match input.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            let port: u16 = port.parse().map_err(|e| format!("bad port: {e}"))?;
            if host.is_empty() {
                return Err("empty host".to_string());
            }
            Ok((host.to_string(), Some(port)))
        }
        _ => {
            if input.contains(':') {
                // A bare IPv6 literal without brackets was handled by the
                // caller's bracket insertion; reaching here means a malformed
                // authority.
                return Err("IPv6 addresses need brackets".to_string());
            }
            Ok((input.to_string(), None))
        }
    }
}

fn parse_fallback_filter(value: &Value, at: &str) -> Result<FallbackFilter, ConfigError> {
    if value.is_null() {
        return Ok(FallbackFilter::default_pinned());
    }
    let mapping = value.as_mapping().ok_or_else(|| {
        ConfigError::InvalidValue(format!("{at} must be a mapping"))
    })?;
    let mut filter = FallbackFilter::default_pinned();
    for (key, item) in mapping {
        let key = key.as_str().ok_or_else(|| {
            ConfigError::InvalidValue(format!("{at} keys must be strings"))
        })?;
        match key {
            "geoip" => filter.geoip = yaml_bool(item, &format!("{at}.geoip"))?,
            "geoip-code" => filter.geoip_code = yaml_string(item, &format!("{at}.geoip-code"))?,
            "ipcidr" => {
                let list = parse_string_list(item, &format!("{at}.ipcidr"))?;
                filter.ipcidr = list
                    .iter()
                    .enumerate()
                    .map(|(index, cidr)| {
                        cidr.parse::<IpNet>().map_err(|e| {
                            ConfigError::InvalidValue(format!(
                                "{at}.ipcidr[{index}]: '{cidr}' is not a CIDR ({e})"
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
            }
            "domain" => filter.domain = parse_string_list(item, &format!("{at}.domain"))?,
            "geosite" => filter.geosite = parse_string_list(item, &format!("{at}.geosite"))?,
            other => {
                return Err(ConfigError::Unsupported(format!(
                    "{at}: unknown fallback-filter key '{other}'"
                )))
            }
        }
    }
    Ok(filter)
}

fn parse_policy(
    value: &Value,
    at: &str,
    respect_rules: bool,
    prefer_h3: bool,
) -> Result<Vec<NameServerPolicy>, ConfigError> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    let mapping = value.as_mapping().ok_or_else(|| {
        ConfigError::InvalidValue(format!("{at} must be a mapping of domain -> nameservers"))
    })?;
    let mut policies = Vec::new();
    for (key, item) in mapping {
        let key = key.as_str().ok_or_else(|| {
            ConfigError::InvalidValue(format!("{at} keys must be strings"))
        })?;
        let servers = parse_nameserver_list(
            item,
            &format!("{at}.{key}"),
            respect_rules,
            prefer_h3,
        )?;
        // Pinned expands comma-separated keys (geosite:/rule-set: groups and
        // plain domain lists) into one policy per entry, preserving order.
        for expanded in expand_policy_key(key) {
            policies.push(NameServerPolicy {
                key: expanded,
                servers: servers.clone(),
            });
        }
    }
    Ok(policies)
}

/// Pinned `parseNameServerPolicy` key expansion.
fn expand_policy_key(key: &str) -> Vec<String> {
    let lower = key.to_ascii_lowercase();
    if lower.contains(',') {
        for prefix in ["geosite:", "rule-set:"] {
            if let Some(rest) = lower.strip_prefix(prefix) {
                let _ = rest;
                let subkeys = key.split(':').nth(1).unwrap_or("");
                return subkeys
                    .split(',')
                    .map(|sub| format!("{prefix}{}", sub.trim()))
                    .collect();
            }
        }
        key.split(',').map(|part| part.trim().to_string()).collect()
    } else {
        vec![key.to_string()]
    }
}

// ---------------------------------------------------------------------------
// hosts
// ---------------------------------------------------------------------------

/// One resolved `hosts` value, pinned `resolver.HostValue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostValue {
    Ips(Vec<IpAddr>),
    Domain(String),
}

impl HostValue {
    pub fn is_domain(&self) -> bool {
        matches!(self, HostValue::Domain(_))
    }

    pub fn domain(&self) -> Option<&str> {
        match self {
            HostValue::Domain(domain) => Some(domain),
            HostValue::Ips(_) => None,
        }
    }

    pub fn ips(&self) -> &[IpAddr] {
        match self {
            HostValue::Ips(ips) => ips,
            HostValue::Domain(_) => &[],
        }
    }
}

/// Parsed top-level `hosts:` (the pinned `RawConfig.Hosts`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostsConfig {
    pub entries: Vec<(String, HostValue)>,
}

impl HostsConfig {
    pub fn parse(value: &Value, path: &str) -> Result<HostsConfig, ConfigError> {
        if value.is_null() {
            return Ok(HostsConfig::default());
        }
        let mapping = value.as_mapping().ok_or_else(|| {
            ConfigError::InvalidValue(format!("{path}: hosts must be a mapping"))
        })?;
        let mut entries = Vec::new();
        for (key, item) in mapping {
            let domain = key.as_str().ok_or_else(|| {
                ConfigError::InvalidValue(format!("{path}: hosts keys must be strings"))
            })?;
            let raw = match item {
                Value::String(text) => vec![text.clone()],
                Value::Sequence(items) => items
                    .iter()
                    .map(|item| yaml_string(item, &format!("{path}.hosts.{domain}")))
                    .collect::<Result<Vec<_>, _>>()?,
                Value::Number(number) => vec![number.to_string()],
                other => {
                    return Err(ConfigError::InvalidValue(format!(
                        "{path}: hosts.{domain} must be an IP, a domain or a list, found {other:?}"
                    )))
                }
            };
            if raw.len() == 1 && raw[0] == "lan" {
                return Err(ConfigError::Unsupported(format!(
                    "{path}: hosts.{domain}: 'lan' (interface addresses) is not implemented; list the addresses explicitly"
                )));
            }
            let value = if raw.len() == 1 {
                match raw[0].parse::<IpAddr>() {
                    Ok(ip) => HostValue::Ips(vec![ip]),
                    Err(_) => {
                        let domain = raw[0].trim().trim_matches('.').to_ascii_lowercase();
                        if domain.split('.').count() < 2 {
                            return Err(ConfigError::InvalidValue(format!(
                                "{path}: hosts.{domain}: '{}' is not a valid domain",
                                raw[0]
                            )));
                        }
                        HostValue::Domain(domain)
                    }
                }
            } else {
                let mut ips = Vec::with_capacity(raw.len());
                for entry in &raw {
                    let ip = entry.parse::<IpAddr>().map_err(|_| {
                        ConfigError::InvalidValue(format!(
                            "{path}: hosts.{domain}: '{entry}' is not an IP address (a value list must contain only IPs)"
                        ))
                    })?;
                    ips.push(ip);
                }
                HostValue::Ips(ips)
            };
            entries.push((domain.to_string(), value));
        }
        // Pinned `parseHosts` rejects a cycle in domain-valued entries during
        // parsing, before any listener starts.
        for (domain, value) in &entries {
            let mut cursor = value.domain().map(str::to_string);
            let mut seen = 0usize;
            while let Some(name) = cursor {
                if name == *domain {
                    return Err(ConfigError::InvalidValue(format!(
                        "{path}: hosts.{domain}: there is a cycle in domain name mapping"
                    )));
                }
                seen += 1;
                if seen > entries.len() + 1 {
                    break;
                }
                cursor = entries
                    .iter()
                    .find(|(candidate, _)| candidate == &name)
                    .and_then(|(_, next)| next.domain().map(str::to_string));
            }
        }
        Ok(HostsConfig { entries })
    }
}

/// The runtime hosts table: the built-in `localhost` entry, the configured
/// entries and (when the resolver allows it) the platform hosts file.
pub struct HostsTable {
    trie: DomainTrie<HostValue>,
    system: bool,
    system_cache: Mutex<Option<(Instant, HashMap<String, Vec<IpAddr>>)>>,
}

impl HostsTable {
    /// Pinned `parseHosts`: always inserts `localhost -> 127.0.0.1`, warns and
    /// skips an invalid trie key, and rejects a domain-mapping cycle.
    pub fn build(config: &HostsConfig, system: bool) -> Result<HostsTable, ConfigError> {
        let mut trie = DomainTrie::default();
        trie.insert("localhost", HostValue::Ips(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]))
            .expect("localhost is a valid domain");
        for (domain, value) in &config.entries {
            if let Some(target) = value.domain() {
                // Pinned checks the chain reachable through existing entries.
                let mut cursor = Some(target.to_string());
                let mut seen = 0usize;
                while let Some(name) = cursor {
                    if name == *domain {
                        return Err(ConfigError::InvalidValue(format!(
                            "{domain}: there is a cycle in domain name mapping"
                        )));
                    }
                    seen += 1;
                    if seen > 64 {
                        break;
                    }
                    cursor = trie.search(&name).and_then(|v| v.domain()).map(str::to_string);
                }
            }
            if let Err(error) = trie.insert(domain, value.clone()) {
                // Pinned logs `skip invalid hosts entry` and continues.
                tracing::warn!(domain, %error, "skip invalid hosts entry");
            }
        }
        Ok(HostsTable {
            trie,
            system,
            system_cache: Mutex::new(None),
        })
    }

    pub fn empty() -> HostsTable {
        HostsTable::build(&HostsConfig::default(), false).expect("built-in localhost only")
    }

    /// Pinned `resolver.Hosts.Search(domain, isDomain)`: follow domain-valued
    /// entries until the result kind matches the request, then report whether
    /// the returned value did (the pinned second return value).
    pub fn search(&self, domain: &str, is_domain: bool) -> Option<(HostValue, bool)> {
        if let Some(found) = self.trie.search(domain) {
            let mut value = found.clone();
            loop {
                if is_domain && value.is_domain() {
                    return Some((value, true));
                }
                let Some(next) = value.domain() else {
                    break;
                };
                match self.trie.search(next) {
                    Some(node) => value = node.clone(),
                    None => break,
                }
            }
            return Some((value.clone(), is_domain == value.is_domain()));
        }
        if !is_domain && self.system {
            if let Some(ips) = self.system_lookup(domain) {
                return Some((HostValue::Ips(ips), true));
            }
        }
        None
    }

    /// All IPs known for `domain` (only the IP-valued form).
    pub fn lookup_ips(&self, domain: &str) -> Vec<IpAddr> {
        match self.search(domain, false) {
            Some((value, true)) => value.ips().to_vec(),
            _ => Vec::new(),
        }
    }

    /// Pinned `LookupStaticAddr`-equivalent reverse lookup used by redir-host
    /// mapping when a host has several addresses.
    fn system_lookup(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let now = Instant::now();
        let mut cache = self
            .system_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let refresh = cache
            .as_ref()
            .is_none_or(|(stamp, _)| now.duration_since(*stamp) > Duration::from_secs(5));
        if refresh {
            *cache = Some((now, read_system_hosts()));
        }
        let table = &cache.as_ref().expect("filled above").1;
        table.get(&domain.to_ascii_lowercase()).cloned()
    }
}

/// Minimal `/etc/hosts` reader matching Go's `net` package rules: comments,
/// whitespace-separated fields, literal IP first, names case-insensitive.
fn read_system_hosts() -> HashMap<String, Vec<IpAddr>> {
    let mut table: HashMap<String, Vec<IpAddr>> = HashMap::new();
    let Ok(text) = std::fs::read_to_string("/etc/hosts") else {
        return table;
    };
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut fields = line.split_whitespace();
        let Some(addr) = fields.next() else { continue };
        let Ok(ip) = addr.parse::<IpAddr>() else { continue };
        for name in fields {
            table
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(ip);
        }
    }
    table
}

// ---------------------------------------------------------------------------
// Domain trie (pinned `component/trie/domain.go`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct TrieNode<T> {
    children: HashMap<String, TrieNode<T>>,
    data: Option<T>,
}

impl<T> Default for TrieNode<T> {
    fn default() -> Self {
        TrieNode {
            children: HashMap::new(),
            data: None,
        }
    }
}

/// Domain trie with the pinned insert/search priority: a static label wins over
/// a `*` label, and the `.`/`+` suffix node is the last fallback.
#[derive(Debug, Clone)]
pub(crate) struct DomainTrie<T> {
    root: TrieNode<T>,
}

impl<T> Default for DomainTrie<T> {
    fn default() -> Self {
        DomainTrie {
            root: TrieNode::default(),
        }
    }
}

impl<T: Clone> DomainTrie<T> {
    pub(crate) fn insert(&mut self, domain: &str, value: T) -> Result<(), String> {
        let parts = valid_and_split_domain(domain)?;
        if parts[0] == "+" {
            self.insert_parts(&parts[1..], &value);
            let mut with_dot = parts.clone();
            with_dot[0] = String::new();
            self.insert_parts(&with_dot, &value);
        } else {
            self.insert_parts(&parts, &value);
        }
        Ok(())
    }

    fn insert_parts(&mut self, parts: &[String], value: &T) {
        let mut node = &mut self.root;
        for part in parts.iter().rev() {
            node = node.children.entry(part.clone()).or_default();
        }
        node.data = Some(value.clone());
    }

    pub(crate) fn search(&self, domain: &str) -> Option<&T> {
        let parts = valid_and_split_domain(domain).ok()?;
        if parts[0].is_empty() {
            return None;
        }
        self.search_parts(&self.root, &parts)
    }

    fn search_parts<'a>(&'a self, node: &'a TrieNode<T>, parts: &[String]) -> Option<&'a T> {
        if parts.is_empty() {
            return node.data.as_ref();
        }
        let last = &parts[parts.len() - 1];
        if let Some(child) = node.children.get(last) {
            if let Some(found) = self.search_parts(child, &parts[..parts.len() - 1]) {
                return Some(found);
            }
        }
        if let Some(child) = node.children.get("*") {
            if let Some(found) = self.search_parts(child, &parts[..parts.len() - 1]) {
                return Some(found);
            }
        }
        node.children.get("").and_then(|child| child.data.as_ref())
    }
}

/// Pinned `ValidAndSplitDomain`: lower-case labels, no trailing dot/space,
/// `+` only as the first of several labels, `*` only as a whole label.
pub(crate) fn valid_and_split_domain(domain: &str) -> Result<Vec<String>, String> {
    if domain.is_empty() {
        return Err("domain is empty".to_string());
    }
    if domain.ends_with('.') {
        return Err("trailing dot is not allowed".to_string());
    }
    if domain.starts_with(char::is_whitespace) || domain.ends_with(char::is_whitespace) {
        return Err("leading/trailing whitespace is not allowed".to_string());
    }
    let lower = domain.to_ascii_lowercase();
    let parts = lower.split('.').map(str::to_string).collect::<Vec<_>>();
    if parts.len() == 1 {
        if parts[0].is_empty() {
            return Err("domain is empty".to_string());
        }
    } else if parts[1..].iter().any(|part| part.is_empty()) {
        return Err("empty domain label".to_string());
    }
    for (index, part) in parts.iter().enumerate() {
        if part.contains('+') {
            if part != "+" {
                return Err("'+' wildcard must occupy the entire label".to_string());
            }
            if index != 0 {
                return Err("'+' wildcard is only allowed in the first label".to_string());
            }
            if parts.len() == 1 {
                return Err("'+' wildcard must be followed by another label".to_string());
            }
        }
        if part.contains('*') && part != "*" {
            return Err("'*' wildcard must occupy the entire label".to_string());
        }
    }
    Ok(parts)
}

// ---------------------------------------------------------------------------
// DNS wire format (the subset this kernel needs: A, AAAA, CNAME)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Question {
    pub name: String,
    pub qtype: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RrData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    /// A parsed record this kernel does not interpret (kept with its raw
    /// payload so the response keeps the pinned answer count).
    Other(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    name: String,
    rtype: u16,
    ttl: u32,
    data: RrData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Message {
    id: u16,
    rcode: u8,
    truncated: bool,
    question: Option<Question>,
    answers: Vec<Record>,
    /// Authority records (the SOA of an NXDOMAIN/NODATA reply). They are not
    /// re-encoded for the local server but their minimal TTL is what the
    /// pinned cache uses for a negative answer.
    authority: Vec<Record>,
}

impl Message {
    fn ips(&self) -> Vec<IpAddr> {
        self.answers
            .iter()
            .filter_map(|record| match record.data {
                RrData::A(ip) => Some(IpAddr::V4(ip)),
                RrData::Aaaa(ip) => Some(IpAddr::V6(ip)),
                _ => None,
            })
            .collect()
    }

    fn empty_answer(id: u16, question: &Question) -> Message {
        Message {
            id,
            rcode: 0,
            truncated: false,
            question: Some(question.clone()),
            answers: Vec::new(),
            authority: Vec::new(),
        }
    }
}

fn build_query(id: u16, question: &Question) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + question.name.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(&mut out, &question.name);
    out.extend_from_slice(&question.qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        let len = bytes.len().min(63) as u8;
        out.push(len);
        out.extend_from_slice(&bytes[..len as usize]);
    }
    out.push(0);
}

fn parse_message(raw: &[u8]) -> Result<Message, String> {
    if raw.len() < 12 {
        return Err("DNS message is shorter than its header".to_string());
    }
    let id = u16::from_be_bytes([raw[0], raw[1]]);
    let flags = u16::from_be_bytes([raw[2], raw[3]]);
    if flags & 0x8000 == 0 {
        return Err("DNS message is not a response".to_string());
    }
    let qdcount = u16::from_be_bytes([raw[4], raw[5]]) as usize;
    let ancount = u16::from_be_bytes([raw[6], raw[7]]) as usize;
    let nscount = u16::from_be_bytes([raw[8], raw[9]]) as usize;
    let mut offset = 12usize;
    let mut question = None;
    for index in 0..qdcount {
        let name = read_name(raw, &mut offset)?;
        if offset + 4 > raw.len() {
            return Err("DNS question is truncated".to_string());
        }
        let qtype = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
        let _class = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
        offset += 4;
        if index == 0 {
            question = Some(Question { name, qtype });
        }
    }
    let mut answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        answers.push(parse_record(raw, &mut offset)?);
    }
    let mut authority = Vec::with_capacity(nscount);
    for _ in 0..nscount {
        authority.push(parse_record(raw, &mut offset)?);
    }
    let rcode = (flags & 0x000f) as u8;
    Ok(Message {
        id,
        rcode,
        truncated: flags & 0x0200 != 0,
        question,
        answers,
        authority,
    })
}

fn parse_record(raw: &[u8], offset: &mut usize) -> Result<Record, String> {
    let name = read_name(raw, offset)?;
    if *offset + 10 > raw.len() {
        return Err("DNS record is truncated".to_string());
    }
    let rtype = u16::from_be_bytes([raw[*offset], raw[*offset + 1]]);
    let _class = u16::from_be_bytes([raw[*offset + 2], raw[*offset + 3]]);
    let ttl = u32::from_be_bytes([
        raw[*offset + 4],
        raw[*offset + 5],
        raw[*offset + 6],
        raw[*offset + 7],
    ]);
    let rdlength = u16::from_be_bytes([raw[*offset + 8], raw[*offset + 9]]) as usize;
    *offset += 10;
    if *offset + rdlength > raw.len() {
        return Err("DNS record data is truncated".to_string());
    }
    let data_start = *offset;
    let data = match rtype {
        TYPE_A if rdlength == 4 => RrData::A(Ipv4Addr::new(
            raw[*offset],
            raw[*offset + 1],
            raw[*offset + 2],
            raw[*offset + 3],
        )),
        TYPE_AAAA if rdlength == 16 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&raw[*offset..*offset + 16]);
            RrData::Aaaa(Ipv6Addr::from(bytes))
        }
        TYPE_CNAME => {
            let mut inner = data_start;
            RrData::Cname(read_name(raw, &mut inner)?)
        }
        _ => RrData::Other(raw[*offset..*offset + rdlength].to_vec()),
    };
    *offset += rdlength;
    Ok(Record {
        name,
        rtype,
        ttl,
        data,
    })
}

fn read_name(raw: &[u8], offset: &mut usize) -> Result<String, String> {
    let mut labels: Vec<String> = Vec::new();
    let mut cursor = *offset;
    let mut jumped = false;
    let mut jumps = 0usize;
    loop {
        if cursor >= raw.len() {
            return Err("DNS name is truncated".to_string());
        }
        let len = raw[cursor];
        if len == 0 {
            if !jumped {
                *offset = cursor + 1;
            }
            return Ok(labels.join("."));
        }
        if len & 0xc0 == 0xc0 {
            if cursor + 1 >= raw.len() {
                return Err("DNS compression pointer is truncated".to_string());
            }
            let pointer = (((len & 0x3f) as usize) << 8) | raw[cursor + 1] as usize;
            if !jumped {
                *offset = cursor + 2;
            }
            jumped = true;
            jumps += 1;
            if jumps > 16 || pointer >= raw.len() {
                return Err("DNS compression pointer loops".to_string());
            }
            cursor = pointer;
            continue;
        }
        let end = cursor + 1 + len as usize;
        if end > raw.len() {
            return Err("DNS label is truncated".to_string());
        }
        let label = std::str::from_utf8(&raw[cursor + 1..end])
            .map_err(|_| "DNS label is not UTF-8".to_string())?
            .to_ascii_lowercase();
        labels.push(label);
        cursor = end;
    }
}

fn encode_message(message: &Message, question: &Question) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&message.id.to_be_bytes());
    let mut flags = 0x8000u16 | 0x0400; // QR, AA
    flags |= 0x0080; // RA, like the pinned DNS server's answers
    flags |= (message.rcode as u16) & 0x000f;
    if message.truncated {
        flags |= 0x0200;
    }
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(message.answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    encode_name(&mut out, &question.name);
    out.extend_from_slice(&question.qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    for record in &message.answers {
        encode_name(&mut out, &record.name);
        out.extend_from_slice(&record.rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&record.ttl.to_be_bytes());
        let mut data = Vec::new();
        match &record.data {
            RrData::A(ip) => data.extend_from_slice(&ip.octets()),
            RrData::Aaaa(ip) => data.extend_from_slice(&ip.octets()),
            RrData::Cname(target) => encode_name(&mut data, target),
            RrData::Other(raw) => data.extend_from_slice(raw),
        }
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
    }
    out
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("DNS query '{name}' failed: {reason}")]
    Query { name: String, reason: String },
    #[error("DNS query '{0}' timed out after {1:?}")]
    Timeout(String, Duration),
    #[error("no IP found for '{0}'")]
    NotFound(String),
    #[error("DNS name '{0}' is not valid")]
    InvalidName(String),
}

impl DnsError {
    pub fn is_timeout(&self) -> bool {
        matches!(self, DnsError::Timeout(..))
    }
}

// ---------------------------------------------------------------------------
// Fake-IP pool and mapping
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PoolRange {
    network: IpAddr,
    prefix: u8,
    gateway: IpAddr,
    first: IpAddr,
    last: IpAddr,
}

fn prefix_last(network: IpAddr, prefix: u8) -> IpAddr {
    match network {
        IpAddr::V4(base) => {
            let host = if prefix == 0 { u32::MAX } else { u32::MAX >> prefix };
            IpAddr::V4(Ipv4Addr::from(u32::from(base) | host))
        }
        IpAddr::V6(base) => {
            let host = if prefix == 0 { u128::MAX } else { u128::MAX >> prefix };
            IpAddr::V6(Ipv6Addr::from(u128::from(base) | host))
        }
    }
}

fn add_offset(ip: IpAddr, offset: u128) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(
            u32::from(v4).wrapping_add(offset as u32),
        )),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6).wrapping_add(offset))),
    }
}

fn ip_less(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => u32::from(a) < u32::from(b),
        (IpAddr::V6(a), IpAddr::V6(b)) => u128::from(a) < u128::from(b),
        _ => false,
    }
}

impl PoolRange {
    fn new(prefix: &IpNet) -> Result<PoolRange, DnsError> {
        let network = masked(prefix);
        let gateway = add_offset(network, 1);
        let first = add_offset(network, 4);
        let last = prefix_last(network, prefix.prefix());
        if !ip_less(first, last) {
            return Err(DnsError::Query {
                name: prefix.to_string(),
                reason: "fake-ip range has no usable addresses".to_string(),
            });
        }
        Ok(PoolRange {
            network,
            prefix: prefix.prefix(),
            gateway,
            first,
            last,
        })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        if self.network.is_ipv4() != ip.is_ipv4() {
            return false;
        }
        IpNet::new(self.network, self.prefix)
            .map(|net| net.contains(ip))
            .unwrap_or(false)
    }
}

fn masked(prefix: &IpNet) -> IpAddr {
    let addr = prefix.network();
    match (addr, prefix.prefix()) {
        (IpAddr::V4(v4), bits) => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
        }
        (IpAddr::V6(v6), bits) => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

/// Pinned `component/fakeip.Pool`: gateway = network+1, allocation starts at
/// network+4 and wraps at the broadcast address, evicting the reused slot.
#[derive(Debug)]
pub(crate) struct FakeIpPool {
    range: PoolRange,
    offset: IpAddr,
    cycle: bool,
    by_host: HashMap<String, IpAddr>,
    by_ip: HashMap<IpAddr, String>,
}

impl FakeIpPool {
    fn new(prefix: &IpNet) -> Result<FakeIpPool, DnsError> {
        let range = PoolRange::new(prefix)?;
        Ok(FakeIpPool {
            offset: add_offset(range.first, u128::MAX), // first - 1
            cycle: false,
            by_host: HashMap::new(),
            by_ip: HashMap::new(),
            range,
        })
    }

    fn lookup(&mut self, host: &str) -> IpAddr {
        let host = host.to_ascii_lowercase();
        if let Some(ip) = self.by_host.get(&host) {
            return *ip;
        }
        // Pinned memory store: at most 1000 host entries. Under pressure an
        // arbitrary entry is dropped instead of the LRU tail; the bound (and
        // therefore memory) is the same, only the eviction order differs.
        if self.by_host.len() >= FAKE_IP_STORE_SIZE {
            if let Some(oldest) = self.by_host.keys().next().cloned() {
                if let Some(ip) = self.by_host.remove(&oldest) {
                    self.by_ip.remove(&ip);
                }
            }
        }
        let next = add_offset(self.offset, 1);
        let (offset, cycle) = if !ip_less(next, self.range.last) {
            (self.range.first, true)
        } else {
            (next, self.cycle)
        };
        if cycle || self.by_ip.contains_key(&offset) {
            if let Some(previous) = self.by_ip.remove(&offset) {
                self.by_host.remove(&previous);
            }
        }
        self.offset = offset;
        self.cycle = cycle;
        self.by_host.insert(host.clone(), offset);
        self.by_ip.insert(offset, host);
        offset
    }

    fn look_back(&self, ip: IpAddr) -> Option<&str> {
        self.by_ip.get(&ip).map(String::as_str)
    }

    fn exists(&self, ip: IpAddr) -> bool {
        self.by_ip.contains_key(&ip)
    }

    fn ranges(&self) -> PoolRange {
        self.range
    }
}

/// Pinned `ResolverEnhancer`: fake pools plus the IP→host mapping (an
/// insertion-ordered map bounded like `lru.WithSize(4096)`).
#[derive(Debug)]
struct Enhancer {
    mode: EnhancedMode,
    pool4: Option<FakeIpPool>,
    pool6: Option<FakeIpPool>,
    filter: DomainSet,
    filter_mode: FakeIpFilterMode,
    ttl: u32,
    mapping: std::collections::VecDeque<(IpAddr, String, Instant)>,
    use_hosts: bool,
}

impl Enhancer {
    fn fake_enabled(&self) -> bool {
        self.mode == EnhancedMode::FakeIp
    }

    fn mapping_enabled(&self) -> bool {
        self.mode != EnhancedMode::Normal
    }

    fn pool_for(&self, ip: IpAddr) -> Option<&FakeIpPool> {
        match ip {
            IpAddr::V4(_) => self.pool4.as_ref(),
            IpAddr::V6(_) => self.pool6.as_ref(),
        }
    }

    fn is_fake_ip(&self, ip: IpAddr) -> bool {
        if !self.fake_enabled() {
            return false;
        }
        let Some(pool) = self.pool_for(ip) else {
            return false;
        };
        let range = pool.ranges();
        range.contains(ip) && ip != range.gateway && ip != range.last
    }

    fn is_fake_broadcast(&self, ip: IpAddr) -> bool {
        if !self.fake_enabled() {
            return false;
        }
        self.pool_for(ip)
            .is_some_and(|pool| pool.ranges().last == ip)
    }

    fn is_exist_fake_ip(&self, ip: IpAddr) -> bool {
        if !self.fake_enabled() {
            return false;
        }
        self.pool_for(ip).is_some_and(|pool| pool.exists(ip))
    }

    fn find_host_by_ip(&self, ip: IpAddr) -> Option<String> {
        if let Some(pool) = self.pool_for(ip) {
            if let Some(host) = pool.look_back(ip) {
                return Some(host.to_string());
            }
        }
        let now = Instant::now();
        self.mapping
            .iter()
            .rev()
            .find(|(mapped, _, expires)| *mapped == ip && *expires > now)
            .map(|(_, host, _)| host.clone())
    }

    fn insert_mapping(&mut self, ip: IpAddr, host: &str, ttl: Duration) {
        let now = Instant::now();
        self.mapping.retain(|(_, _, expires)| *expires > now);
        if let Some(index) = self
            .mapping
            .iter()
            .position(|(mapped, _, _)| *mapped == ip)
        {
            self.mapping.remove(index);
        }
        if self.mapping.len() >= MAPPING_SIZE {
            self.mapping.pop_front();
        }
        self.mapping
            .push_back((ip, host.to_string(), now + ttl));
    }

    fn should_skip(&self, host: &str) -> bool {
        let matched = self.filter.matches(host);
        match self.filter_mode {
            FakeIpFilterMode::Whitelist => !matched,
            FakeIpFilterMode::Blacklist => matched,
        }
    }
}

// ---------------------------------------------------------------------------
// Route hook for `respect-rules` upstreams
// ---------------------------------------------------------------------------

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Established stream to a DNS upstream, handed back by a [`DnsRoute`].
/// One established stream to a DNS upstream (DIRECT or through a proxy).
pub type RouteStreamBox = crate::outbound::BoxStream;

/// The rule/proxy path used by `respect-rules`: the engine evaluates the
/// upstream destination and returns the outbound stream (DIRECT or a proxy).
pub trait DnsRoute: Send + Sync {
    fn connect<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<RouteStreamBox>>;
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

struct CacheEntry {
    answers: Vec<Record>,
    rcode: u8,
    expires: Instant,
}

struct Cached {
    answers: Vec<Record>,
    rcode: u8,
}

#[derive(Debug, Clone)]
enum PolicyMatcher {
    Trie(DomainTrie<Vec<NameServer>>),
    Domains(DomainSet),
}

struct PolicyGroup {
    matcher: PolicyMatcher,
    /// `None` for a trie group (the clients live in the trie data).
    servers: Vec<NameServer>,
}

impl PolicyGroup {
    fn match_servers(&self, host: &str) -> Option<&[NameServer]> {
        match &self.matcher {
            PolicyMatcher::Trie(trie) => trie.search(host).map(Vec::as_slice),
            PolicyMatcher::Domains(set) => {
                if set.matches(host) {
                    Some(self.servers.as_slice())
                } else {
                    None
                }
            }
        }
    }
}

/// The DNS runtime. Constructed only when `dns.enable` is true.
pub struct DnsService {
    ipv6: bool,
    ipv6_timeout: Duration,
    main: Vec<NameServer>,
    fallback: Vec<NameServer>,
    default: Vec<NameServer>,
    proxy_server: Vec<NameServer>,
    direct: Vec<NameServer>,
    direct_follow_policy: bool,
    fallback_geoip: Option<GeoIpMatcher>,
    fallback_cidr: Vec<IpNet>,
    fallback_domain: DomainSet,
    fallback_lazy: bool,
    policies: Vec<PolicyGroup>,
    proxy_policies: Vec<PolicyGroup>,
    cache: Mutex<HashMap<(String, u16), CacheEntry>>,
    cache_max: usize,
    enhancer: Mutex<Enhancer>,
    hosts: Arc<HostsTable>,
    tls: Arc<ClientTls>,
    route: RwLock<Option<Arc<dyn DnsRoute>>>,
    listen: Option<SocketAddr>,
}

impl fmt::Debug for DnsService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsService")
            .field("ipv6", &self.ipv6)
            .field("main", &self.main)
            .field("fallback", &self.fallback)
            .field("listen", &self.listen)
            .finish_non_exhaustive()
    }
}

impl DnsService {
    /// Build the runtime from the validated `dns` block. `geodata` supplies
    /// `fallback-filter.geoip`/`geosite` and `nameserver-policy` matchers;
    /// `rule_sets` resolves `rule-set:` policies.
    pub fn build(
        config: &DnsConfig,
        general_ipv6: bool,
        hosts: Arc<HostsTable>,
        tls: Arc<ClientTls>,
        providers: &Arc<crate::provider::RuleProviders>,
        warnings: &mut Vec<String>,
    ) -> Result<DnsService, ConfigError> {
        let ipv6 = config.effective_ipv6(general_ipv6);
        let geodata = providers.geodata();
        let fallback_geoip = if config.fallback.is_empty() || !config.fallback_filter.geoip {
            None
        } else {
            let code = config.fallback_filter.geoip_code.trim_start_matches('!');
            let matcher = geodata.geoip_matcher(code)?;
            Some(matcher)
        };
        let mut fallback_domain = DomainSet::default();
        for domain in &config.fallback_filter.domain {
            let parts = valid_and_split_domain(domain).map_err(|e| {
                ConfigError::InvalidValue(format!("dns.fallback-filter.domain '{domain}': {e}"))
            })?;
            let _ = parts;
            fallback_domain.insert(geodata::DomainPattern::parse(domain));
        }
        for key in &config.fallback_filter.geosite {
            let (set, negate) = geodata.geosite_matcher(key)?;
            if negate {
                return Err(ConfigError::Unsupported(format!(
                    "dns.fallback-filter.geosite '{key}': negated geosite is not implemented"
                )));
            }
            for pattern in domain_set_patterns(&set) {
                fallback_domain.insert(pattern);
            }
        }
        let policies = build_policies(&config.nameserver_policy, providers, "dns.nameserver-policy")?;
        let proxy_policies = build_policies(
            &config.proxy_server_nameserver_policy,
            providers,
            "dns.proxy-server-nameserver-policy",
        )?;

        let mut filter = DomainSet::default();
        if config.enhanced_mode == EnhancedMode::FakeIp {
            for domain in &config.fake_ip_filter {
                let lower = domain.to_ascii_lowercase();
                let parts = valid_and_split_domain(&lower).map_err(|e| {
                    ConfigError::InvalidValue(format!("dns.fake-ip-filter '{domain}': {e}"))
                })?;
                let _ = parts;
                filter.insert(geodata::DomainPattern::parse(&lower));
            }
            // Pinned `parseDNS` adds hostnames of fallback nameservers to the
            // fake-ip filter so their own lookups get real answers.
            if config.fake_ip_filter_mode != FakeIpFilterMode::Whitelist {
                for ns in &config.fallback {
                    if ns.host.parse::<IpAddr>().is_err() {
                        filter.insert(geodata::DomainPattern::parse(&ns.host));
                    }
                }
            }
        }

        let pool4 = match config.fake_ip_range {
            Some(range) if config.enhanced_mode == EnhancedMode::FakeIp => {
                Some(FakeIpPool::new(&range).map_err(|e| ConfigError::InvalidValue(e.to_string()))?)
            }
            _ => None,
        };
        let pool6 = match config.fake_ip_range6 {
            Some(range) if config.enhanced_mode == EnhancedMode::FakeIp => {
                Some(FakeIpPool::new(&range).map_err(|e| ConfigError::InvalidValue(e.to_string()))?)
            }
            _ => None,
        };

        if config.enhanced_mode == EnhancedMode::FakeIp && config.fake_ip_filter_mode == FakeIpFilterMode::Whitelist {
            warnings.push(
                "dns.fake-ip-filter-mode: whitelist answers only the listed domains from the fake-ip pool; an empty whitelist sends every name to the real upstreams"
                    .to_string(),
            );
        }
        if !config.prefer_h3 {
            // no warning: prefer-h3 only changes DoH HTTP version preference
        } else {
            warnings.push(
                "dns.prefer-h3 is recorded but DoH uses HTTP/1.1: HTTP/3 is not implemented for DNS upstreams"
                    .to_string(),
            );
        }
        let enhancer = Enhancer {
            mode: config.enhanced_mode,
            pool4,
            pool6,
            filter,
            filter_mode: config.fake_ip_filter_mode,
            ttl: config.fake_ip_ttl.max(FAKE_IP_MIN_TTL),
            mapping: std::collections::VecDeque::new(),
            use_hosts: config.use_hosts,
        };
        Ok(DnsService {
            ipv6,
            ipv6_timeout: config.ipv6_timeout,
            main: config.nameserver.clone(),
            fallback: config.fallback.clone(),
            default: config.default_nameserver.clone(),
            proxy_server: config.proxy_server_nameserver.clone(),
            direct: config.direct_nameserver.clone(),
            direct_follow_policy: config.direct_nameserver_follow_policy,
            fallback_geoip,
            fallback_cidr: config.fallback_filter.ipcidr.clone(),
            fallback_domain,
            fallback_lazy: config.fallback_lazy_query,
            policies,
            proxy_policies,
            cache: Mutex::new(HashMap::new()),
            cache_max: config.cache_max_size.max(1),
            enhancer: Mutex::new(enhancer),
            hosts,
            tls,
            route: RwLock::new(None),
            listen: config.listen,
        })
    }

    pub fn set_route(&self, route: Arc<dyn DnsRoute>) {
        if let Ok(mut slot) = self.route.write() {
            *slot = Some(route);
        }
    }

    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.listen
    }

    pub fn ipv6_enabled(&self) -> bool {
        self.ipv6
    }

    pub fn enhanced_mode(&self) -> EnhancedMode {
        self.enhancer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .mode
    }

    /// Pinned `ResolverEnhancer.IsFakeIP`.
    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        self.enhancer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_fake_ip(ip)
    }

    pub fn is_fake_broadcast_ip(&self, ip: IpAddr) -> bool {
        self.enhancer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_fake_broadcast(ip)
    }

    pub fn is_exist_fake_ip(&self, ip: IpAddr) -> bool {
        self.enhancer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_exist_fake_ip(ip)
    }

    pub fn find_host_by_ip(&self, ip: IpAddr) -> Option<String> {
        self.enhancer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .find_host_by_ip(ip)
    }

    pub fn flush_fake_ip(&self) {
        let mut enhancer = self
            .enhancer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(pool) = enhancer.pool4.as_mut() {
            pool.by_host.clear();
            pool.by_ip.clear();
            pool.cycle = false;
            pool.offset = add_offset(pool.range.first, u128::MAX);
        }
        if let Some(pool) = enhancer.pool6.as_mut() {
            pool.by_host.clear();
            pool.by_ip.clear();
            pool.cycle = false;
            pool.offset = add_offset(pool.range.first, u128::MAX);
        }
        enhancer.mapping.clear();
    }

    pub fn clear_cache(&self) {
        self.cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    /// Pinned `preHandleMetadata`: rebuild the destination from a mapped IP
    /// (redir-host) or fake IP, and follow a domain-valued hosts entry.
    pub fn pre_handle(
        &self,
        host: &str,
        ip: Option<IpAddr>,
    ) -> Result<(String, Option<IpAddr>), String> {
        let mut host = host.to_string();
        let mut ip = ip;
        let enhancer = self
            .enhancer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if enhancer.mapping_enabled() && host.is_empty() {
            let current_ip = ip;
            let mapped = current_ip.and_then(|ip| enhancer.find_host_by_ip(ip));
            if let Some(mapped) = mapped {
                host = mapped;
                let is_fake = current_ip.is_some_and(|ip| enhancer.is_fake_ip(ip));
                if is_fake {
                    ip = None;
                } else if let Some((HostValue::Ips(ips), true)) = self.hosts.search(&host, false) {
                    if let Some(chosen) = ips.first() {
                        ip = Some(*chosen);
                    }
                } else if let Some((HostValue::Domain(domain), _)) = self.hosts.search(&host, true) {
                    host = domain;
                }
            } else if let Some(ip_value) = current_ip {
                if enhancer.is_fake_ip(ip_value) {
                    return Err(format!("fake DNS record {ip_value} missing"));
                }
            }
        } else if let Some((HostValue::Domain(domain), _)) = self.hosts.search(&host, true) {
            host = domain;
        }
        Ok((host, ip))
    }

    /// Pinned `resolver.LookupIPWithResolver` (hosts first, then main).
    pub async fn lookup_ip(&self, host: &str) -> Vec<IpAddr> {
        if let Some((HostValue::Ips(ips), true)) = self.hosts.search(host, false) {
            if !ips.is_empty() {
                return ips;
            }
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return vec![ip];
        }
        if !self.ipv6 {
            return self.lookup_type(host, TYPE_A).await.unwrap_or_default();
        }
        // Pinned `LookupIP`: A is awaited in full, AAAA is joined for at most
        // `ipv6-timeout` (default 100ms).
        let ipv6_timeout = self.ipv6_timeout;
        let (a_result, aaaa_result) = tokio::join!(
            self.lookup_type(host, TYPE_A),
            async {
                match tokio::time::timeout(ipv6_timeout, self.lookup_type(host, TYPE_AAAA)).await {
                    Ok(result) => result.ok(),
                    Err(_) => None,
                }
            }
        );
        let mut ips = a_result.unwrap_or_default();
        if let Some(mut aaaa) = aaaa_result {
            ips.append(&mut aaaa);
        }
        ips
    }

    /// One address preferring IPv4 (pinned `ResolveIP`).
    pub async fn resolve_one(&self, host: &str) -> Option<IpAddr> {
        let ips = self.lookup_ip(host).await;
        ips.iter().find(|ip| ip.is_ipv4()).copied().or_else(|| ips.first().copied())
    }

    /// Direct-outbound resolver (`direct-nameserver` when configured).
    pub async fn resolve_direct(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Some((HostValue::Ips(ips), true)) = self.hosts.search(host, false) {
            if !ips.is_empty() {
                return Ok(ips);
            }
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        if self.direct_follow_policy {
            if let Some(servers) = self.policy_for(&self.policies, host) {
                return self.lookup_with(servers, host).await;
            }
        }
        let servers = if self.direct.is_empty() {
            &self.main
        } else {
            &self.direct
        };
        self.lookup_with(servers, host).await
    }

    /// Proxy-server resolver (`proxy-server-nameserver` when configured).
    pub async fn resolve_proxy_server(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Some((HostValue::Ips(ips), true)) = self.hosts.search(host, false) {
            if !ips.is_empty() {
                return Ok(ips);
            }
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        if let Some(servers) = self.policy_for(&self.proxy_policies, host) {
            return self.lookup_with(servers, host).await;
        }
        let servers = if self.proxy_server.is_empty() {
            &self.main
        } else {
            &self.proxy_server
        };
        self.lookup_with(servers, host).await
    }

    /// Resolve `host` against an explicit server list (used by
    /// `proxy-server-nameserver-policy` too).
    async fn lookup_with(
        &self,
        servers: &[NameServer],
        host: &str,
    ) -> Result<Vec<IpAddr>, DnsError> {
        let a = self.query_servers(servers, host, TYPE_A);
        let qtype = if self.ipv6 { TYPE_AAAA } else { TYPE_A };
        if !self.ipv6 {
            return a.await.map(|message| message.ips());
        }
        let aaaa = self.query_servers(servers, host, qtype);
        let (first, second) = tokio::join!(a, aaaa);
        let mut ips = first.map(|m| m.ips())?;
        if let Ok(message) = second {
            ips.extend(message.ips());
        }
        Ok(ips)
    }

    async fn lookup_type(&self, host: &str, qtype: u16) -> Result<Vec<IpAddr>, DnsError> {
        let message = self.exchange_question(host, qtype).await?;
        Ok(message.ips())
    }

    /// Pinned `Resolver.exchangeWithoutCache` for one question: policies, then
    /// the IP fallback logic, then the main servers.
    async fn exchange_question(&self, host: &str, qtype: u16) -> Result<Message, DnsError> {
        let name = host.trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty() {
            return Err(DnsError::InvalidName(host.to_string()));
        }
        if let Some(cached) = self.cache_get(&name, qtype) {
            return Ok(Message {
                id: 0,
                rcode: cached.rcode,
                truncated: false,
                question: Some(Question { name: name.clone(), qtype }),
                answers: cached.answers,
                authority: Vec::new(),
            });
        }
        let is_ip_request = matches!(qtype, TYPE_A | TYPE_AAAA | TYPE_CNAME);
        let message = if let Some(servers) = self.policy_for(&self.policies, &name) {
            self.query_servers(servers, &name, qtype).await?
        } else if is_ip_request && !self.fallback.is_empty() {
            self.ip_exchange(&name, qtype).await?
        } else {
            self.query_servers(&self.main, &name, qtype).await?
        };
        self.cache_put(&name, qtype, &message);
        Ok(Message {
            id: 0,
            rcode: message.rcode,
            truncated: message.truncated,
            question: Some(Question { name, qtype }),
            answers: message.answers,
            authority: message.authority,
        })
    }

    fn policy_for<'a>(&self, groups: &'a [PolicyGroup], host: &str) -> Option<&'a [NameServer]> {
        groups.iter().find_map(|group| group.match_servers(host))
    }

    /// Pinned `Resolver.ipExchange`: a domain filter sends the query to the
    /// fallback only; otherwise main and fallback race, and an answer that is
    /// not in the fallback IP filters wins without waiting for the fallback.
    async fn ip_exchange(&self, name: &str, qtype: u16) -> Result<Message, DnsError> {
        let only_fallback = !self.fallback_domain.is_empty() && self.fallback_domain.matches(name);
        if only_fallback {
            return self.query_servers(&self.fallback, name, qtype).await;
        }
        if self.fallback_lazy {
            // `fallback-lazy-query`: the fallback request starts only when the
            // main answer suggests it.
            let main_result = self.query_servers(&self.main, name, qtype).await;
            if let Ok(message) = &main_result {
                if !self.needs_fallback(message) {
                    return Ok(message.clone());
                }
            }
            return self.query_servers(&self.fallback, name, qtype).await;
        }
        let (main_result, fallback_result) = tokio::join!(
            self.query_servers(&self.main, name, qtype),
            self.query_servers(&self.fallback, name, qtype)
        );
        if let Ok(message) = &main_result {
            if !self.needs_fallback(message) {
                return Ok(message.clone());
            }
        }
        fallback_result
    }

    fn needs_fallback(&self, message: &Message) -> bool {
        let ips = message.ips();
        if ips.is_empty() {
            return true;
        }
        ips.iter().any(|ip| self.ip_falls_back(*ip))
    }

    fn ip_falls_back(&self, ip: IpAddr) -> bool {
        if geodata::is_lan(ip) {
            return false;
        }
        if self
            .fallback_cidr
            .iter()
            .any(|cidr| cidr.contains(ip))
        {
            return true;
        }
        self.fallback_geoip
            .as_ref()
            .is_some_and(|matcher| !matcher.matches(ip))
    }

    fn cache_get(&self, name: &str, qtype: u16) -> Option<Cached> {
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = cache.get(&(name.to_string(), qtype))?;
        if entry.expires <= Instant::now() {
            cache.remove(&(name.to_string(), qtype));
            return None;
        }
        let remaining = entry.expires.duration_since(Instant::now()).as_secs() as u32;
        let answers = entry
            .answers
            .iter()
            .map(|record| Record {
                ttl: record.ttl.min(remaining.max(1)),
                ..record.clone()
            })
            .collect();
        Some(Cached {
            answers,
            rcode: entry.rcode,
        })
    }

    fn cache_put(&self, name: &str, qtype: u16, message: &Message) {
        let ttl = if message.rcode == 2 {
            SERVER_FAILURE_TTL
        } else {
            message
                .answers
                .iter()
                .chain(message.authority.iter())
                .map(|record| record.ttl)
                .min()
                .unwrap_or(0)
        };
        if ttl == 0 {
            return;
        }
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if cache.len() >= self.cache_max {
            // Evict one arbitrary entry: the pinned LRU evicts the least
            // recently used, which differs only under cache pressure.
            if let Some(key) = cache.keys().next().cloned() {
                cache.remove(&key);
            }
        }
        let now = Instant::now();
        cache.insert(
            (name.to_string(), qtype),
            CacheEntry {
                answers: message.answers.clone(),
                rcode: message.rcode,
                expires: now + Duration::from_secs(u64::from(ttl)),
            },
        );
    }

    /// Pinned `batchExchange`: all servers race, the first successful message
    /// wins; a server-failure/refused answer counts as a failed attempt.
    async fn query_servers(
        &self,
        servers: &[NameServer],
        name: &str,
        qtype: u16,
    ) -> Result<Message, DnsError> {
        let id: u16 = rand::random();
        let question = Question {
            name: name.to_string(),
            qtype,
        };
        let raw = build_query(id, &question);
        let owned_name = name.to_string();
        let mut set = tokio::task::JoinSet::new();
        for server in servers {
            let server = server.clone();
            let raw = raw.clone();
            let name = owned_name.clone();
            let context = self.exchange_context();
            set.spawn(async move { context.exchange(&server, &raw, &name, qtype).await });
        }
        let mut first_error: Option<DnsError> = None;
        let mut join_errors = 0usize;
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(Ok(message)) => {
                    set.abort_all();
                    return Ok(message);
                }
                Ok(Err(error)) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
                Err(_) => join_errors += 1,
            }
        }
        let _ = join_errors;
        set.abort_all();
        Err(first_error.unwrap_or_else(|| DnsError::Query {
            name: name.to_string(),
            reason: "all DNS requests failed".to_string(),
        }))
    }

    fn exchange_context(&self) -> ExchangeContext {
        ExchangeContext {
            default: self.default.clone(),
            tls: self.tls.clone(),
            route: self.route.read().ok().and_then(|slot| slot.clone()),
        }
    }

    /// Pinned `withResolver` + `ipv6` gate: an AAAA query while IPv6 is off
    /// gets an empty successful answer.
    async fn exchange_question_via_middleware(
        &self,
        question: &Question,
        raw: &[u8],
    ) -> Message {
        let host = question.name.trim_end_matches('.').to_string();
        if question.qtype == TYPE_AAAA && !self.ipv6 {
            return Message::empty_answer(0, question);
        }
        let _ = raw;
        match self.exchange_question(&host, question.qtype).await {
            Ok(mut message) => {
                message.question = Some(question.clone());
                if self.mapping_enabled() {
                    for record in &message.answers {
                        let ip = match record.data {
                            RrData::A(ip) => IpAddr::V4(ip),
                            RrData::Aaaa(ip) => IpAddr::V6(ip),
                            _ => continue,
                        };
                        if is_global_unicast(ip) {
                            let mut enhancer = self
                                .enhancer
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            enhancer.insert_mapping(ip, &host, Duration::from_secs(u64::from(record.ttl.max(1))));
                        }
                    }
                }
                message
            }
            Err(_) => Message {
                id: 0,
                rcode: 2,
                truncated: false,
                question: Some(question.clone()),
                answers: Vec::new(),
                authority: Vec::new(),
            },
        }
    }

    fn mapping_enabled(&self) -> bool {
        self.enhancer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .mapping_enabled()
    }

    /// Answer one raw DNS query for the `dns.listen` server (pinned
    /// `newHandler`: hosts → fake-ip → mapping → resolver).
    pub async fn answer_query(&self, raw: &[u8]) -> Vec<u8> {
        let Ok(query) = parse_query(raw) else {
            // Pinned miekg/dns answers FORMERR for an unparsable query.
            return form_error(raw);
        };
        let q = match query.question.clone() {
            Some(q) => q,
            None => return form_error(raw),
        };
        if !matches!(q.qtype, TYPE_A | TYPE_AAAA | TYPE_CNAME) {
            // Pinned fake-ip answers HTTPS/SVCB with an empty successful reply.
            let fake_mode = self
                .enhancer
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .fake_enabled();
            if fake_mode && matches!(q.qtype, TYPE_HTTPS | TYPE_SVCB) {
                return encode_message(&Message::empty_answer(query.id, &q), &q);
            }
            // Pinned forwards every other type; this kernel only decodes
            // A/AAAA/CNAME, so the gap is named as NOTIMP.
            let message = Message {
                id: query.id,
                rcode: 4, // NOTIMP
                truncated: false,
                question: Some(q.clone()),
                answers: Vec::new(),
                authority: Vec::new(),
            };
            return encode_message(&message, &q);
        }
        let is_ip_request = matches!(q.qtype, TYPE_A | TYPE_AAAA | TYPE_CNAME);
        if !is_ip_request {
            return encode_message(&Message::empty_answer(query.id, &q), &q);
        }
        let host = q.name.trim_end_matches('.').to_ascii_lowercase();

        // hosts
        let mut message: Option<Message> = None;
        {
            let enhancer = self
                .enhancer
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if enhancer.use_hosts {
                if let Some((value, matched)) = self.hosts.search(&host, q.qtype != TYPE_A && q.qtype != TYPE_AAAA) {
                    if matched {
                        let mut answers = Vec::new();
                        for ip in value.ips() {
                            match (ip, q.qtype) {
                                (IpAddr::V4(v4), TYPE_A) => answers.push(Record {
                                    name: q.name.clone(),
                                    rtype: TYPE_A,
                                    ttl: 10,
                                    data: RrData::A(*v4),
                                }),
                                (IpAddr::V6(v6), TYPE_AAAA) => answers.push(Record {
                                    name: q.name.clone(),
                                    rtype: TYPE_AAAA,
                                    ttl: 10,
                                    data: RrData::Aaaa(*v6),
                                }),
                                _ => {}
                            }
                            if enhancer.mapping_enabled() {
                                if let Ok(mut enhancer) = self.enhancer.lock() {
                                    enhancer.insert_mapping(*ip, &host, Duration::from_secs(600));
                                }
                            }
                        }
                        if q.qtype == TYPE_CNAME {
                            if let Some(domain) = value.domain() {
                                answers.push(Record {
                                    name: q.name.clone(),
                                    rtype: TYPE_CNAME,
                                    ttl: 10,
                                    data: RrData::Cname(domain.to_string()),
                                });
                            }
                        }
                        message = Some(Message {
                            id: query.id,
                            rcode: 0,
                            truncated: false,
                            question: Some(q.clone()),
                            answers,
                            authority: Vec::new(),
                        });
                    }
                }
            }
        }
        // fake-ip
        if message.is_none() {
            let mut enhancer = self
                .enhancer
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if enhancer.fake_enabled() && !enhancer.should_skip(&host) {
                match q.qtype {
                    TYPE_A => {
                        message = Some(match enhancer.pool4.as_mut() {
                            Some(pool) => {
                                let ip = pool.lookup(&host);
                                fake_answer(query.id, &q, ip, enhancer.ttl)
                            }
                            None => Message::empty_answer(query.id, &q),
                        });
                    }
                    TYPE_AAAA => {
                        message = Some(match enhancer.pool6.as_mut() {
                            Some(pool) => {
                                let ip = pool.lookup(&host);
                                fake_answer(query.id, &q, ip, enhancer.ttl)
                            }
                            None => Message::empty_answer(query.id, &q),
                        });
                    }
                    TYPE_HTTPS | TYPE_SVCB => {
                        message = Some(Message::empty_answer(query.id, &q))
                    }
                    _ => {}
                }
            }
        }
        let mut message = match message {
            Some(message) => message,
            None => self.exchange_question_via_middleware(&q, raw).await,
        };
        message.id = query.id;
        encode_message(&message, &q)
    }

    /// `servers` for a policy key; exposed for diagnostics/tests.
    pub fn policy_servers_for(&self, host: &str) -> Vec<String> {
        self.policy_for(&self.policies, host)
            .map(|servers| servers.iter().map(NameServer::address).collect())
            .unwrap_or_default()
    }
}

fn fake_answer(id: u16, question: &Question, ip: IpAddr, ttl: u32) -> Message {
    let data = match ip {
        IpAddr::V4(ip) => RrData::A(ip),
        IpAddr::V6(ip) => RrData::Aaaa(ip),
    };
    Message {
        id,
        rcode: 0,
        truncated: false,
        question: Some(question.clone()),
        answers: vec![Record {
            name: question.name.clone(),
            rtype: if ip.is_ipv4() { TYPE_A } else { TYPE_AAAA },
            ttl,
            data,
        }],
        authority: Vec::new(),
    }
}

fn is_global_unicast(ip: IpAddr) -> bool {
    match ip {
        // Go's `IsGlobalUnicast` (pinned `withMapping`) counts private and
        // unique-local addresses as global unicast; only these are excluded.
        IpAddr::V4(ip) => !(ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
            || ip.is_link_local()
            || ip.is_broadcast()),
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unicast_link_local())
        }
    }
}

fn domain_set_patterns(set: &DomainSet) -> Vec<geodata::DomainPattern> {
    set.patterns().to_vec()
}

fn build_policies(
    policies: &[NameServerPolicy],
    providers: &Arc<crate::provider::RuleProviders>,
    location: &str,
) -> Result<Vec<PolicyGroup>, ConfigError> {
    let geodata = providers.geodata();
    let mut groups: Vec<PolicyGroup> = Vec::new();
    let mut trie: Option<DomainTrie<Vec<NameServer>>> = None;
    let flush = |trie: &mut Option<DomainTrie<Vec<NameServer>>>, groups: &mut Vec<PolicyGroup>| {
        if let Some(trie) = trie.take() {
            groups.push(PolicyGroup {
                matcher: PolicyMatcher::Trie(trie),
                servers: Vec::new(),
            });
        }
    };
    for policy in policies {
        let lower = policy.key.to_ascii_lowercase();
        if let Some(list) = lower.strip_prefix("geosite:") {
            flush(&mut trie, &mut groups);
            let (set, negate) = geodata.geosite_matcher(list)?;
            if negate {
                return Err(ConfigError::Unsupported(format!(
                    "{location}: negated geosite key '{}' is not implemented",
                    policy.key
                )));
            }
            groups.push(PolicyGroup {
                matcher: PolicyMatcher::Domains(set),
                servers: policy.servers.clone(),
            });
        } else if let Some(name) = lower.strip_prefix("rule-set:") {
            flush(&mut trie, &mut groups);
            let slot = providers.rule_provider(name).ok_or_else(|| {
                ConfigError::InvalidValue(format!(
                    "{location}: rule-set '{name}' not found"
                ))
            })?;
            let snapshot = slot.snapshot();
            match snapshot.compiled.behavior {
                crate::config::RuleBehavior::Domain => {}
                crate::config::RuleBehavior::IpCidr => {
                    return Err(ConfigError::InvalidValue(format!(
                        "{location}: rule-set '{name}' is an ipcidr provider; a domain matcher needs behavior: domain"
                    )))
                }
                crate::config::RuleBehavior::Classical => {
                    return Err(ConfigError::Unsupported(format!(
                        "{location}: rule-set '{name}' is a classical provider; only domain-behavior providers are implemented in DNS policies"
                    )))
                }
            }
            groups.push(PolicyGroup {
                matcher: PolicyMatcher::Domains(snapshot.compiled.domain.clone()),
                servers: policy.servers.clone(),
            });
        } else {
            let domain = policy.key.trim();
            valid_and_split_domain(domain).map_err(|e| {
                ConfigError::InvalidValue(format!("{location}: '{}': {e}", policy.key))
            })?;
            trie.get_or_insert_with(DomainTrie::default)
                .insert(domain, policy.servers.clone())
                .map_err(|e| ConfigError::InvalidValue(format!("{location}: '{domain}': {e}")))?;
        }
    }
    flush(&mut trie, &mut groups);
    Ok(groups)
}

fn parse_query(raw: &[u8]) -> Result<Message, String> {
    if raw.len() < 12 {
        return Err("DNS query is shorter than its header".to_string());
    }
    let id = u16::from_be_bytes([raw[0], raw[1]]);
    let flags = u16::from_be_bytes([raw[2], raw[3]]);
    if flags & 0x8000 != 0 {
        return Err("not a query".to_string());
    }
    let qdcount = u16::from_be_bytes([raw[4], raw[5]]) as usize;
    if qdcount == 0 {
        return Ok(Message {
            id,
            rcode: 0,
            truncated: false,
            question: None,
            answers: Vec::new(),
            authority: Vec::new(),
        });
    }
    let mut offset = 12;
    let name = read_name(raw, &mut offset)?;
    if offset + 4 > raw.len() {
        return Err("DNS query is truncated".to_string());
    }
    let qtype = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
    Ok(Message {
        id,
        rcode: 0,
        truncated: false,
        question: Some(Question { name, qtype }),
        answers: Vec::new(),
        authority: Vec::new(),
    })
}

fn form_error(raw: &[u8]) -> Vec<u8> {
    let id = if raw.len() >= 2 {
        u16::from_be_bytes([raw[0], raw[1]])
    } else {
        0
    };
    let question = Question {
        name: ".".to_string(),
        qtype: TYPE_A,
    };
    let mut message = Message::empty_answer(id, &question);
    message.rcode = 1;
    encode_message(&message, &question)
}

// ---------------------------------------------------------------------------
// Upstream exchanges (UDP/TCP/DoT/DoH)
// ---------------------------------------------------------------------------

struct ExchangeContext {
    default: Vec<NameServer>,
    tls: Arc<ClientTls>,
    route: Option<Arc<dyn DnsRoute>>,
}

impl ExchangeContext {
    async fn exchange(
        &self,
        server: &NameServer,
        raw: &[u8],
        name: &str,
        qtype: u16,
    ) -> Result<Message, DnsError> {
        let disabled = server.disabled_types();
        if disabled.contains(&qtype) {
            return Ok(Message {
                id: 0,
                rcode: 0,
                truncated: false,
                question: Some(Question {
                    name: name.to_string(),
                    qtype,
                }),
                answers: Vec::new(),
                authority: Vec::new(),
            });
        }
        let result = tokio::time::timeout(DNS_TIMEOUT, self.exchange_once(server, raw)).await;
        let bytes = match result {
            Err(_) => {
                return Err(DnsError::Timeout(
                    name.to_string(),
                    DNS_TIMEOUT,
                ))
            }
            Ok(Err(reason)) => {
                return Err(DnsError::Query {
                    name: name.to_string(),
                    reason,
                })
            }
            Ok(Ok(bytes)) => bytes,
        };
        let mut message = parse_message(&bytes).map_err(|reason| DnsError::Query {
            name: name.to_string(),
            reason,
        })?;
        if message
            .question
            .as_ref()
            .is_some_and(|question| question.qtype != qtype)
        {
            return Err(DnsError::Query {
                name: name.to_string(),
                reason: "response question does not match".to_string(),
            });
        }
        message.question = Some(Question {
            name: name.to_string(),
            qtype,
        });
        Ok(message)
    }

    async fn exchange_once(&self, server: &NameServer, raw: &[u8]) -> Result<Vec<u8>, String> {
        let addr = self
            .resolve_server(server)
            .await
            .map_err(|e| format!("resolve upstream {}: {e}", server.address()))?;
        match server.net {
            NameServerNet::Udp => self.exchange_udp(server, addr, raw).await,
            NameServerNet::Tcp => self.exchange_tcp(server, addr, raw).await,
            NameServerNet::Tls => self.exchange_tls(server, addr, raw).await,
            NameServerNet::Https => self.exchange_doh(server, addr, raw).await,
        }
    }

    async fn resolve_server(&self, server: &NameServer) -> Result<SocketAddr, String> {
        if let Ok(ip) = server.host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, server.port));
        }
        // Pinned dials a nameserver hostname through `default-nameserver`;
        // those entries are pure IPs, so the bootstrap query is a plain
        // UDP/TCP exchange and cannot recurse.
        let question = Question {
            name: server.host.clone(),
            qtype: TYPE_A,
        };
        let raw = build_query(rand::random(), &question);
        for default in &self.default {
            let Ok(ip) = default.host.parse::<IpAddr>() else {
                continue;
            };
            let addr = SocketAddr::new(ip, default.port);
            let result = tokio::time::timeout(
                DNS_TIMEOUT,
                bootstrap_exchange(default, addr, &raw),
            )
            .await;
            let Ok(Ok(bytes)) = result else { continue };
            let Ok(message) = parse_message(&bytes) else {
                continue;
            };
            if let Some(ip) = message.ips().into_iter().next() {
                return Ok(SocketAddr::new(ip, server.port));
            }
        }
        Err("default-nameserver returned no address".to_string())
    }

    async fn stream_for(
        &self,
        server: &NameServer,
        addr: SocketAddr,
    ) -> Result<RouteStreamBox, String> {
        if server.respect_rules {
            let route = self
                .route
                .as_ref()
                .ok_or_else(|| "respect-rules has no rule route".to_string())?;
            return route
                .connect(&addr.ip().to_string(), addr.port())
                .await
                .map_err(|e| format!("route upstream: {e}"));
        }
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("connect {addr}: {e}"))?;
        let _ = stream.set_nodelay(true);
        Ok(Box::new(stream))
    }

    async fn exchange_udp(
        &self,
        server: &NameServer,
        addr: SocketAddr,
        raw: &[u8],
    ) -> Result<Vec<u8>, String> {
        let bind = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|e| format!("bind UDP: {e}"))?;
        socket
            .connect(addr)
            .await
            .map_err(|e| format!("connect UDP {addr}: {e}"))?;
        socket
            .send(raw)
            .await
            .map_err(|e| format!("send UDP: {e}"))?;
        let mut buf = vec![0u8; 4096];
        let read = socket
            .recv(&mut buf)
            .await
            .map_err(|e| format!("receive UDP: {e}"))?;
        let message = parse_message(&buf[..read])?;
        if message.truncated {
            // Pinned retries a truncated UDP reply over TCP.
            return self.exchange_tcp(server, addr, raw).await;
        }
        Ok(buf[..read].to_vec())
    }

    async fn exchange_tcp(
        &self,
        server: &NameServer,
        addr: SocketAddr,
        raw: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mut stream = self.stream_for(server, addr).await?;
        write_dns_stream(&mut stream, raw).await?;
        read_dns_stream(&mut stream).await
    }

    async fn exchange_tls(
        &self,
        server: &NameServer,
        addr: SocketAddr,
        raw: &[u8],
    ) -> Result<Vec<u8>, String> {
        let stream = self.stream_for(server, addr).await?;
        let settings = crate::proxies::TlsSettings {
            sni: Some(server.host.clone()),
            skip_cert_verify: server.skip_cert_verify(),
            alpn: Vec::new(),
        };
        let mut stream = crate::outbound::tls::wrap_stream(
            WrapStream(stream),
            &server.host,
            &settings,
            &self.tls,
        )
        .await
        .map_err(|e| format!("TLS to {}: {e}", server.address()))?;
        write_dns_stream(&mut stream, raw).await?;
        read_dns_stream(&mut stream).await
    }

    async fn exchange_doh(
        &self,
        server: &NameServer,
        addr: SocketAddr,
        raw: &[u8],
    ) -> Result<Vec<u8>, String> {
        let stream = self.stream_for(server, addr).await?;
        let mut stream: RouteStreamBox = if server.plain_http {
            stream
        } else {
            let settings = crate::proxies::TlsSettings {
                sni: Some(server.host.clone()),
                skip_cert_verify: server.skip_cert_verify(),
                alpn: vec!["http/1.1".to_string()],
            };
            Box::new(
                crate::outbound::tls::wrap_stream(
                    WrapStream(stream),
                    &server.host,
                    &settings,
                    &self.tls,
                )
                .await
                .map_err(|e| format!("TLS to {}: {e}", server.address()))?,
            )
        };
        let encoded = base64_url(raw);
        let host_header = if server.port == if server.plain_http { 80 } else { 443 } {
            server.host.clone()
        } else {
            format!("{}:{}", server.host, server.port)
        };
        // Keep the upstream path but replace any query with `dns=`, like the
        // pinned client (`requestUrl.RawQuery`).
        let path = server.path.split('?').next().unwrap_or("/");
        let request = format!(
            "GET {path}?dns={encoded} HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/dns-message\r\nUser-Agent:\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("DoH request: {e}"))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|e| format!("DoH response: {e}"))?;
        parse_http_body(&response)
    }
}

/// Bootstrap UDP query to a `default-nameserver` (always a literal IP).
async fn bootstrap_exchange(
    server: &NameServer,
    addr: SocketAddr,
    raw: &[u8],
) -> Result<Vec<u8>, String> {
    if server.net == NameServerNet::Tcp {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("connect {addr}: {e}"))?;
        write_dns_stream(&mut stream, raw).await?;
        return read_dns_stream(&mut stream).await;
    }
    let bind = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("bind UDP: {e}"))?;
    socket
        .connect(addr)
        .await
        .map_err(|e| format!("connect UDP {addr}: {e}"))?;
    socket.send(raw).await.map_err(|e| format!("send UDP: {e}"))?;
    let mut buf = vec![0u8; 4096];
    let read = socket
        .recv(&mut buf)
        .await
        .map_err(|e| format!("receive UDP: {e}"))?;
    Ok(buf[..read].to_vec())
}

/// Adapter so a boxed route stream can be passed to `wrap_stream`.
struct WrapStream(RouteStreamBox);

impl tokio::io::AsyncRead for WrapStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for WrapStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

async fn write_dns_stream<S>(stream: &mut S, raw: &[u8]) -> Result<(), String>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let len = u16::try_from(raw.len()).map_err(|_| "DNS message too long".to_string())?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| format!("write DNS length: {e}"))?;
    stream
        .write_all(raw)
        .await
        .map_err(|e| format!("write DNS message: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))
}

async fn read_dns_stream<S>(stream: &mut S) -> Result<Vec<u8>, String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut len = [0u8; 2];
    stream
        .read_exact(&mut len)
        .await
        .map_err(|e| format!("read DNS length: {e}"))?;
    let len = u16::from_be_bytes(len) as usize;
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| format!("read DNS body: {e}"))?;
    Ok(body)
}

fn base64_url(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(triple >> 18) as usize & 63] as char);
        out.push(TABLE[(triple >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(triple >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[triple as usize & 63] as char);
        }
    }
    out
}

fn parse_http_body(response: &[u8]) -> Result<Vec<u8>, String> {
    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "DoH response has no header terminator".to_string())?;
    let head = String::from_utf8_lossy(&response[..head_end]);
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| "DoH response has no status line".to_string())?;
    if status != 200 {
        return Err(format!("DoH server answered HTTP {status}"));
    }
    let mut chunked = false;
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "transfer-encoding" if value.trim().eq_ignore_ascii_case("chunked") => chunked = true,
            "content-length" => content_length = value.trim().parse::<usize>().ok(),
            _ => {}
        }
    }
    let body = &response[head_end + 4..];
    if chunked {
        return decode_chunked(body);
    }
    match content_length {
        Some(length) if body.len() >= length => Ok(body[..length].to_vec()),
        Some(_) => Err("DoH response body is shorter than Content-Length".to_string()),
        None => Ok(body.to_vec()),
    }
}

fn decode_chunked(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    loop {
        let line_end = body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| "chunked body has no size line".to_string())?
            + cursor;
        let line = std::str::from_utf8(&body[cursor..line_end])
            .map_err(|_| "chunked size is not ASCII".to_string())?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|e| format!("bad chunk size: {e}"))?;
        cursor = line_end + 2;
        if size == 0 {
            return Ok(out);
        }
        if cursor + size + 2 > body.len() {
            return Err("chunked body is truncated".to_string());
        }
        out.extend_from_slice(&body[cursor..cursor + size]);
        cursor += size + 2;
    }
}

// ---------------------------------------------------------------------------
// DNS listener (dns.listen)
// ---------------------------------------------------------------------------

/// Run the UDP and TCP DNS listeners until `stop` fires. Binding happens in
/// [`bind_dns_listeners`] so a bad address fails kernel start, not a task.
pub fn bind_dns_listeners(addr: SocketAddr) -> io::Result<(std::net::UdpSocket, std::net::TcpListener)> {
    let udp = std::net::UdpSocket::bind(addr)?;
    udp.set_nonblocking(true)?;
    let tcp = std::net::TcpListener::bind(addr)?;
    tcp.set_nonblocking(true)?;
    Ok((udp, tcp))
}

/// Serve DNS until the stop channel fires. Queries with more than one question
/// and types other than A/AAAA/CNAME get NOTIMP (registered gap).
pub async fn serve_dns(
    service: Arc<DnsService>,
    udp: std::net::UdpSocket,
    tcp: std::net::TcpListener,
    mut stop: watch::Receiver<bool>,
) {
    let udp = match UdpSocket::from_std(udp) {
        Ok(udp) => udp,
        Err(error) => {
            tracing::warn!("DNS UDP listener: {error}");
            return;
        }
    };
    let tcp = match tokio::net::TcpListener::from_std(tcp) {
        Ok(tcp) => tcp,
        Err(error) => {
            tracing::warn!("DNS TCP listener: {error}");
            return;
        }
    };
    let udp_task = tokio::spawn(dns_udp_loop(service.clone(), udp, stop.clone()));
    let tcp_task = tokio::spawn(dns_tcp_loop(service, tcp, stop.clone()));
    let _ = stop.changed().await;
    udp_task.abort();
    tcp_task.abort();
    let _ = udp_task.await;
    let _ = tcp_task.await;
}

async fn dns_udp_loop(service: Arc<DnsService>, socket: UdpSocket, mut stop: watch::Receiver<bool>) {
    let mut buf = vec![0u8; DNS_MAX_MESSAGE];
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            read = socket.recv_from(&mut buf) => {
                let (len, peer) = match read {
                    Ok(pair) => pair,
                    Err(error) => {
                        tracing::debug!("DNS UDP read: {error}");
                        continue;
                    }
                };
                let answer = service.answer_query(&buf[..len]).await;
                let _ = socket.send_to(&answer, peer).await;
            }
        }
    }
}

async fn dns_tcp_loop(service: Arc<DnsService>, listener: tokio::net::TcpListener, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            accepted = listener.accept() => {
                let Ok((mut stream, _)) = accepted else { continue };
                let service = service.clone();
                tokio::spawn(async move {
                    loop {
                        let Ok(raw) = read_dns_stream(&mut stream).await else { return };
                        let answer = service.answer_query(&raw).await;
                        let Ok(len) = u16::try_from(answer.len()) else { return };
                        let _ = stream.write_all(&len.to_be_bytes()).await;
                        let _ = stream.write_all(&answer).await;
                        let _ = stream.flush().await;
                    }
                });
            }
        }
    }
}
