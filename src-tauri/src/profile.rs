use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

use crate::age_key;
use crate::diagnostics::{self, ConnectionView, LogView, TrafficTotals};
use crate::engine::{Engine, EngineIdentity};
use crate::nodes::{
    self, ControllerEndpoint, KERNEL_DOWN, NEED_PROFILE, NO_MATCH, NO_NODES, NOT_MANUAL, NodeDelay,
    NodeGroupView, ParsedGroup, SELECT_FAILED,
};
use crate::takeover::{
    self, ClientPlatform, PlatformRelease, ProxyEndpoint, SystemProxy, TunGrant, VpnGrant,
};

const BODY_LIMIT: u64 = 2_000_000;
const CONTENT_ERROR: &str = "配置无法应用";
const OVERRIDE_ERROR: &str = "覆写无法应用";
const FETCH_ERROR: &str = "订阅没有取回";
const KERNEL_ERROR: &str = "内核没有启动";
const MISSING_KERNEL: &str = "没有本地内核";
const LINK_ERROR: &str = "不支持这个导入链接";
const ONE_LINK_ERROR: &str = "需要一条订阅链接";
const URL_ERROR: &str = "订阅链接不可用";
const DUPLICATE_ERROR: &str = "该订阅已存在";
const MISSING_PROFILE: &str = "没有这份配置";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ProfileKind {
    Subscription,
    Local,
}

impl ProfileKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Subscription => "subscription",
            Self::Local => "local",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Usage {
    used: Option<u64>,
    total: Option<u64>,
    expire: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Profile {
    id: String,
    name: String,
    kind: ProfileKind,
    source: String,
    user_agent: String,
    content: String,
    override_text: String,
    /// Override included in the last successful apply. Editor text can be newer.
    applied_override: String,
    override_error: Option<String>,
    failure: Option<String>,
    last_success_ms: Option<u64>,
    usage: Option<Usage>,
    selected: BTreeMap<String, String>,
    /// Nodes fixed on `url-test` / `fallback` groups, replayed after each reload.
    /// Kept apart from `selected` so auto-group member order is never rewritten.
    fixed: BTreeMap<String, String>,
    interval_hours: u32,
    /// age X25519 identities, one per line, for subscriptions published encrypted.
    age_key: String,
    updated_ms: Option<u64>,
    proxy_count: usize,
    refresh_revision: u64,
    node_metadata: OnceLock<Option<NodeMetadata>>,
}

/// Cache only display metadata, not the full YAML tree or subscription credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeMetadata {
    groups: Vec<ParsedGroup>,
    types: BTreeMap<String, nodes::ProxyInfo>,
    config: ConfigValues,
}

impl Profile {
    fn node_metadata(&self) -> Option<&NodeMetadata> {
        self.node_metadata.get_or_init(|| {
            let value = document_value(self)?;
            let flag = |name: &str| mapping_get(&value, name).and_then(Value::as_bool);
            Some(NodeMetadata {
                groups: nodes::parse_proxy_groups(&value),
                types: nodes::proxy_infos(&value),
                config: ConfigValues {
                    mixed_port: read_i64(&value, "mixed-port").or_else(|| read_i64(&value, "port")),
                    allow_lan: flag("allow-lan"), ipv6: flag("ipv6"),
                    log_level: read_string(&value, "log-level"),
                    unified_delay: flag("unified-delay"), tcp_concurrent: flag("tcp-concurrent"),
                    find_process_mode: read_string(&value, "find-process-mode"),
                    keep_alive_interval: read_i64(&value, "keep-alive-interval"),
                    disable_keep_alive: flag("disable-keep-alive"),
                    socks_port: read_i64(&value, "socks-port"),
                    http_port: read_i64(&value, "port"),
                    redir_port: read_i64(&value, "redir-port"),
                    tproxy_port: read_i64(&value, "tproxy-port"),
                    interface_name: read_string(&value, "interface-name"),
                    routing_mark: read_i64(&value, "routing-mark"),
                    sniffer: mapping_get(&value, "sniffer").and_then(|s| mapping_get(s, "enable")).and_then(Value::as_bool),
                    sniff_http_ports: sniff_config_ports(&value, "HTTP"),
                    sniff_tls_ports: sniff_config_ports(&value, "TLS"),
                    sniff_quic_ports: sniff_config_ports(&value, "QUIC"),
                    sniff_force_domain: mapping_get(&value, "sniffer").and_then(|s| yaml_strings(mapping_get(s, "force-domain"))),
                    sniff_skip_domain: mapping_get(&value, "sniffer").and_then(|s| yaml_strings(mapping_get(s, "skip-domain"))),
                    sniff_override_destination: mapping_get(&value, "sniffer")
                        .and_then(|s| mapping_get(s, "override-destination"))
                        .and_then(Value::as_bool),
                    tun_route_address: mapping_get(&value, "tun").and_then(|t| yaml_strings(mapping_get(t, "route-address"))),
                    tun_route_exclude_address: mapping_get(&value, "tun")
                        .and_then(|t| yaml_strings(mapping_get(t, "route-exclude-address"))),
                },
            })
        }).as_ref()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeoUrls {
    pub geoip: String,
    pub mmdb: String,
    pub geosite: String,
    pub asn: String,
}

fn clean_http_url(raw: &str) -> String {
    let trimmed: String = raw
        .trim()
        .chars()
        .filter(|ch| !ch.is_control() && !ch.is_whitespace())
        .take(1000)
        .collect();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed
    } else {
        String::new()
    }
}

impl GeoUrls {
    pub fn normalized(mut self) -> Self {
        self.geoip = clean_http_url(&self.geoip);
        self.mmdb = clean_http_url(&self.mmdb);
        self.geosite = clean_http_url(&self.geosite);
        self.asn = clean_http_url(&self.asn);
        self
    }

    pub fn get(&self, key: &str) -> &str {
        match key {
            "geoip" => &self.geoip,
            "mmdb" => &self.mmdb,
            "geosite" => &self.geosite,
            "asn" => &self.asn,
            _ => "",
        }
    }

    pub fn has_any(&self) -> bool {
        !self.geoip.is_empty()
            || !self.mmdb.is_empty()
            || !self.geosite.is_empty()
            || !self.asn.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KernelSettings {
    /// Start the kernel and connect automatically when Billow opens, guarded against crash loops.
    #[serde(default)]
    pub auto_connect: bool,
    /// None preserves the default: switch existing sessions to the new route.
    #[serde(default)]
    pub close_connections_on_switch: Option<bool>,
    #[serde(default)]
    pub subscription_user_agent: String,
    #[serde(default)]
    pub mixed_port: Option<u16>,
    #[serde(default)]
    pub allow_lan: Option<bool>,
    #[serde(default)]
    pub ipv6: Option<bool>,
    #[serde(default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub unified_delay: Option<bool>,
    #[serde(default)]
    pub tcp_concurrent: Option<bool>,
    #[serde(default)]
    pub find_process_mode: Option<String>,
    #[serde(default)]
    pub test_url: String,
    #[serde(default)]
    pub test_timeout_ms: u64,
    /// Domain sniffing; `None` follows the profile.
    #[serde(default)]
    pub sniffer: Option<bool>,
    /// TCP keep-alive interval in seconds; `Some(0)` turns keep-alive off, `None` follows the profile.
    #[serde(default)]
    pub keep_alive_interval: Option<u32>,
    /// Inbound `user:pass` pairs for LAN clients. Loopback is always exempt so local apps keep working.
    #[serde(default)]
    pub lan_auth: Vec<String>,
    /// Source ranges allowed to use the inbound ports; empty keeps the profile's list.
    #[serde(default)]
    pub lan_allowed_ips: Vec<String>,
    /// System proxy host, mode (`manual` / `pac`), PAC script and bypass list.
    #[serde(default)]
    pub system_proxy: takeover::SystemProxySettings,
    /// When on, the app's `dns` block replaces the profile's.
    #[serde(default)]
    pub dns_override: bool,
    #[serde(default)]
    pub dns: DnsSettings,
    #[serde(default)]
    pub tun: TunSettings,
    /// GEO databases: `None` follows the profile (`false` = MMDB `db`, `true` = GeoIP `dat`).
    #[serde(default)]
    pub geodata_mode: Option<bool>,
    #[serde(default)]
    pub geodata_loader: Option<String>,
    #[serde(default)]
    pub geo_auto_update: Option<bool>,
    #[serde(default)]
    pub geo_update_interval: Option<u32>,
    /// Download source for GEO databases: `""` follows the profile's `geox-url`.
    #[serde(default)]
    pub geo_source: String,
    /// Per-database URL overrides (`geoip`, `mmdb`, `geosite`, `asn`).
    #[serde(default)]
    pub geo_urls: GeoUrls,
    /// Per-protocol sniff ports layered on the final sniffer block; `None` keeps what it has.
    #[serde(default)]
    pub sniff_ports: SniffPorts,
    #[serde(default)]
    pub sniff_force_domain: Option<Vec<String>>,
    #[serde(default)]
    pub sniff_skip_domain: Option<Vec<String>>,
    #[serde(default)]
    pub sniff_override_destination: Option<bool>,
    /// Extra inbound ports; `Some(0)` turns the listener off, `None` follows the profile.
    #[serde(default)]
    pub socks_port: Option<u16>,
    /// mihomo's `port` (HTTP-only listener).
    #[serde(default)]
    pub http_port: Option<u16>,
    #[serde(default)]
    pub redir_port: Option<u16>,
    #[serde(default)]
    pub tproxy_port: Option<u16>,
    /// Outbound interface; `Some("")` removes the profile's, `None` follows it.
    #[serde(default)]
    pub interface_name: Option<String>,
    /// Linux `routing-mark`; `Some(0)` removes the profile's.
    #[serde(default)]
    pub routing_mark: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SniffPorts {
    pub http: Option<Vec<String>>,
    pub tls: Option<Vec<String>>,
    pub quic: Option<Vec<String>>,
}

/// `geox-url` for a named GEO source; `None` leaves the profile's own value.
pub fn geo_source_urls(source: &str) -> Option<[(&'static str, String); 4]> {
    let base = match source {
        "github" => "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest",
        "jsdelivr" => "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release",
        "testingcf" => "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release",
        _ => return None,
    };
    Some([
        ("geoip", format!("{base}/geoip.dat")),
        ("geosite", format!("{base}/geosite.dat")),
        ("mmdb", format!("{base}/geoip.metadb")),
        ("asn", format!("{base}/GeoLite2-ASN.mmdb")),
    ])
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsSettings {
    pub listen: String,
    pub enhanced_mode: String,
    pub fake_ip_range: String,
    pub fake_ip_filter_mode: String,
    pub fake_ip_filter: Vec<String>,
    pub ipv6: bool,
    pub prefer_h3: bool,
    pub cache_algorithm: String,
    pub use_hosts: bool,
    pub use_system_hosts: bool,
    pub respect_rules: bool,
    pub direct_nameserver_follow_policy: bool,
    pub default_nameserver: Vec<String>,
    pub nameserver: Vec<String>,
    pub fallback: Vec<String>,
    pub proxy_server_nameserver: Vec<String>,
    pub direct_nameserver: Vec<String>,
    pub nameserver_policy: BTreeMap<String, Vec<String>>,
    pub hosts: BTreeMap<String, Vec<String>>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        let list = |items: &[&str]| items.iter().map(|item| item.to_string()).collect();
        Self {
            listen: String::new(),
            enhanced_mode: "fake-ip".to_string(),
            fake_ip_range: "198.18.0.1/16".to_string(),
            fake_ip_filter_mode: "blacklist".to_string(),
            fake_ip_filter: list(&[
                "*.lan",
                "*.local",
                "*.localdomain",
                "localhost.ptlogin2.qq.com",
                "+.msftconnecttest.com",
                "+.msftncsi.com",
                "+.stun.*.*",
                "+.stun.*.*.*",
                "time.*.com",
                "ntp.*.com",
                "+.market.xiaomi.com",
            ]),
            ipv6: false,
            prefer_h3: false,
            cache_algorithm: "lru".to_string(),
            use_hosts: true,
            use_system_hosts: true,
            respect_rules: false,
            direct_nameserver_follow_policy: false,
            default_nameserver: list(&["223.5.5.5", "119.29.29.29"]),
            nameserver: list(&["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"]),
            fallback: Vec::new(),
            proxy_server_nameserver: list(&["https://doh.pub/dns-query"]),
            direct_nameserver: Vec::new(),
            nameserver_policy: BTreeMap::new(),
            hosts: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TunSettings {
    pub stack: String,
    pub auto_route: bool,
    pub auto_detect_interface: bool,
    pub strict_route: bool,
    pub dns_hijack: Vec<String>,
    pub mtu: u32,
    pub device: String,
    /// `tun.route-address`; `None` follows the profile. Desktop only.
    pub route_address: Option<Vec<String>>,
    /// `tun.route-exclude-address`; `None` follows the profile. Desktop only.
    pub route_exclude_address: Option<Vec<String>>,
}

impl Default for TunSettings {
    fn default() -> Self {
        Self {
            // Empty leaves `stack` to the profile, then the kernel (mips since v1.19.32,
            // gvisor before), so an older kernel never receives a stack it cannot start.
            stack: String::new(),
            auto_route: true,
            auto_detect_interface: true,
            strict_route: false,
            dns_hijack: vec!["any:53".to_string(), "tcp://any:53".to_string()],
            mtu: 1500,
            device: String::new(),
            route_address: None,
            route_exclude_address: None,
        }
    }
}

fn clean_list(items: Vec<String>, limit: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in items {
        let item: String = item.trim().chars().filter(|ch| !ch.is_control()).take(300).collect();
        if !item.is_empty() && !out.contains(&item) {
            out.push(item);
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

impl DnsSettings {
    fn normalized(mut self) -> Self {
        let fallback = Self::default();
        self.listen = self
            .listen
            .trim()
            .chars()
            .filter(|ch| !ch.is_control() && !ch.is_whitespace())
            .take(128)
            .collect();
        if !self.listen.is_empty() && !self.listen.contains(':') {
            self.listen.clear();
        }
        self.enhanced_mode = match self.enhanced_mode.trim().to_ascii_lowercase().as_str() {
            "redir-host" => "redir-host".to_string(),
            "normal" => "normal".to_string(),
            _ => "fake-ip".to_string(),
        };
        self.fake_ip_range = self.fake_ip_range.trim().to_string();
        if self.fake_ip_range.is_empty() || !self.fake_ip_range.contains('/') {
            self.fake_ip_range = fallback.fake_ip_range;
        }
        self.fake_ip_filter_mode = match self.fake_ip_filter_mode.trim().to_ascii_lowercase().as_str() {
            "whitelist" => "whitelist".to_string(),
            "rule" => "rule".to_string(),
            _ => "blacklist".to_string(),
        };
        self.fake_ip_filter = clean_list(self.fake_ip_filter, 500);
        self.cache_algorithm = match self.cache_algorithm.trim().to_ascii_lowercase().as_str() {
            "arc" => "arc".to_string(),
            _ => "lru".to_string(),
        };
        self.default_nameserver = clean_list(self.default_nameserver, 20);
        self.nameserver = clean_list(self.nameserver, 20);
        self.fallback = clean_list(self.fallback, 20);
        self.proxy_server_nameserver = clean_list(self.proxy_server_nameserver, 20);
        self.direct_nameserver = clean_list(self.direct_nameserver, 20);
        if self.nameserver.is_empty() {
            self.nameserver = fallback.nameserver;
        }
        if self.default_nameserver.is_empty() {
            self.default_nameserver = fallback.default_nameserver;
        }
        if self.respect_rules && self.proxy_server_nameserver.is_empty() {
            self.proxy_server_nameserver = fallback.proxy_server_nameserver;
        }
        let mut policy = BTreeMap::new();
        for (pattern, servers) in self.nameserver_policy {
            let pattern: String = pattern
                .trim()
                .chars()
                .filter(|ch| !ch.is_control())
                .take(300)
                .collect();
            let servers = clean_list(servers, 20);
            if !pattern.is_empty() && !servers.is_empty() && policy.len() < 300 {
                policy.insert(pattern, servers);
            }
        }
        self.nameserver_policy = policy;

        let mut hosts = BTreeMap::new();
        for (domain, targets) in self.hosts {
            let domain: String = domain
                .trim()
                .chars()
                .filter(|ch| !ch.is_control() && !ch.is_whitespace())
                .take(255)
                .collect();
            let targets = clean_list(targets, 16);
            if !domain.is_empty() && !targets.is_empty() && hosts.len() < 500 {
                hosts.insert(domain, targets);
            }
        }
        self.hosts = hosts;
        self
    }

    fn to_value(&self) -> Value {
        let key = |name: &str| Value::String(name.to_string());
        let strings =
            |items: &[String]| Value::Sequence(items.iter().map(|item| Value::String(item.clone())).collect());
        let mut map = serde_yaml::Mapping::new();
        map.insert(key("enable"), Value::Bool(true));
        if !self.listen.is_empty() {
            map.insert(key("listen"), Value::String(self.listen.clone()));
        }
        map.insert(key("ipv6"), Value::Bool(self.ipv6));
        map.insert(key("prefer-h3"), Value::Bool(self.prefer_h3));
        map.insert(key("cache-algorithm"), Value::String(self.cache_algorithm.clone()));
        map.insert(key("use-hosts"), Value::Bool(self.use_hosts));
        map.insert(key("use-system-hosts"), Value::Bool(self.use_system_hosts));
        map.insert(key("respect-rules"), Value::Bool(self.respect_rules));
        map.insert(
            key("direct-nameserver-follow-policy"),
            Value::Bool(self.direct_nameserver_follow_policy),
        );
        map.insert(key("enhanced-mode"), Value::String(self.enhanced_mode.clone()));
        if self.enhanced_mode == "fake-ip" {
            map.insert(key("fake-ip-range"), Value::String(self.fake_ip_range.clone()));
            map.insert(
                key("fake-ip-filter-mode"),
                Value::String(self.fake_ip_filter_mode.clone()),
            );
            map.insert(key("fake-ip-filter"), strings(&self.fake_ip_filter));
        }
        map.insert(key("default-nameserver"), strings(&self.default_nameserver));
        map.insert(key("nameserver"), strings(&self.nameserver));
        if !self.fallback.is_empty() {
            map.insert(key("fallback"), strings(&self.fallback));
        }
        if !self.proxy_server_nameserver.is_empty() {
            map.insert(key("proxy-server-nameserver"), strings(&self.proxy_server_nameserver));
        }
        if !self.direct_nameserver.is_empty() {
            map.insert(key("direct-nameserver"), strings(&self.direct_nameserver));
        }
        if !self.nameserver_policy.is_empty() {
            let mut policy = serde_yaml::Mapping::new();
            for (pattern, servers) in &self.nameserver_policy {
                let value = if servers.len() == 1 {
                    Value::String(servers[0].clone())
                } else {
                    strings(servers)
                };
                policy.insert(Value::String(pattern.clone()), value);
            }
            map.insert(key("nameserver-policy"), Value::Mapping(policy));
        }
        Value::Mapping(map)
    }
}

impl TunSettings {
    fn normalized(mut self) -> Self {
        self.stack = match self.stack.trim().to_ascii_lowercase().as_str() {
            "system" => "system".to_string(),
            "gvisor" => "gvisor".to_string(),
            "mixed" => "mixed".to_string(),
            "mips" => "mips".to_string(),
            _ => String::new(),
        };
        self.dns_hijack = clean_list(self.dns_hijack, 20);
        self.mtu = if self.mtu == 0 { 0 } else { self.mtu.clamp(576, 9000) };
        self.device = self
            .device
            .trim()
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
            .take(32)
            .collect();
        self.route_address = self.route_address.map(|items| normalize_cidrs(&items)).filter(|items| !items.is_empty());
        self.route_exclude_address =
            self.route_exclude_address.map(|items| normalize_cidrs(&items)).filter(|items| !items.is_empty());
        self
    }

    fn validate(&self) -> Result<(), String> {
        for (label, items) in [("只让这些地址走 TUN", &self.route_address), ("不走 TUN 的地址", &self.route_exclude_address)] {
            if let Some(bad) = items.as_deref().and_then(invalid_cidr) {
                return Err(format!("{label}中的「{bad}」不是有效的 IP 或网段，例如 192.168.0.0/16"));
            }
        }
        Ok(())
    }
}

/// What the active profile itself says, so the settings page can show "follow profile" values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct ConfigValues {
    pub mixed_port: Option<i64>,
    pub allow_lan: Option<bool>,
    pub ipv6: Option<bool>,
    pub log_level: Option<String>,
    pub unified_delay: Option<bool>,
    pub tcp_concurrent: Option<bool>,
    pub find_process_mode: Option<String>,
    pub keep_alive_interval: Option<i64>,
    pub disable_keep_alive: Option<bool>,
    pub socks_port: Option<i64>,
    /// The profile's own `port`, unlike `mixed_port` which falls back to it.
    pub http_port: Option<i64>,
    pub redir_port: Option<i64>,
    pub tproxy_port: Option<i64>,
    pub interface_name: Option<String>,
    pub routing_mark: Option<i64>,
    /// `sniffer.enable`, so the switch can show the profile's value while following it.
    pub sniffer: Option<bool>,
    pub sniff_http_ports: Option<Vec<String>>,
    pub sniff_tls_ports: Option<Vec<String>>,
    pub sniff_quic_ports: Option<Vec<String>>,
    pub sniff_force_domain: Option<Vec<String>>,
    pub sniff_skip_domain: Option<Vec<String>>,
    pub sniff_override_destination: Option<bool>,
    pub tun_route_address: Option<Vec<String>>,
    pub tun_route_exclude_address: Option<Vec<String>>,
}

/// Read-only view of the running config for the overview screen. Long lists
/// (proxies, rules, providers) are reduced to counts and secrets are masked, so
/// the payload stays small and never carries credentials.
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct ConfigOverview {
    /// Top-level options of the config the kernel runs (or would run next).
    pub effective: serde_json::Value,
    /// The profile with its 覆写 merged, before Billow's own settings.
    pub prepared: serde_json::Value,
    /// The profile file alone.
    pub profile: serde_json::Value,
    /// Sizes of the list sections in the effective config.
    pub counts: BTreeMap<String, usize>,
    /// Proxy group count per `type`.
    pub group_types: BTreeMap<String, usize>,
    pub running: bool,
}

/// Sections summarized as counts instead of being shipped whole.
const OVERVIEW_LISTS: &[&str] = &[
    "proxies",
    "proxy-groups",
    "proxy-providers",
    "rules",
    "rule-providers",
    "sub-rules",
    "listeners",
    "tunnels",
];

/// Keys whose values are credentials at any depth.
const OVERVIEW_SECRETS: &[&str] = &["secret", "password", "private-key", "passphrase", "token"];

fn overview_json(value: &Value, depth: usize) -> serde_json::Value {
    use serde_json::Value as Json;
    match value {
        Value::Null => Json::Null,
        Value::Bool(flag) => Json::Bool(*flag),
        Value::Number(number) => number
            .as_i64()
            .map(Json::from)
            .or_else(|| number.as_u64().map(Json::from))
            .or_else(|| number.as_f64().and_then(serde_json::Number::from_f64).map(Json::Number))
            .unwrap_or(Json::Null),
        Value::String(text) => Json::String(text.clone()),
        Value::Sequence(items) => Json::Array(items.iter().take(200).map(|item| overview_json(item, depth + 1)).collect()),
        Value::Mapping(map) => {
            let mut out = serde_json::Map::new();
            for (key, item) in map.iter().take(500) {
                let name = match key {
                    Value::String(text) => text.clone(),
                    other => serde_yaml::to_string(other).unwrap_or_default().trim().to_string(),
                };
                let masked = OVERVIEW_SECRETS.contains(&name.to_ascii_lowercase().as_str());
                let json = if masked {
                    Json::String("••••".to_string())
                } else if depth >= 6 {
                    Json::String("…".to_string())
                } else {
                    overview_json(item, depth + 1)
                };
                out.insert(name, json);
            }
            Json::Object(out)
        }
        Value::Tagged(tagged) => overview_json(&tagged.value, depth),
    }
}

/// Top-level options with list sections removed and credentials masked.
fn overview_options(value: &Value) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    let Some(map) = value.as_mapping() else { return serde_json::Value::Object(out) };
    for (key, item) in map {
        let Some(name) = key.as_str() else { continue };
        if OVERVIEW_LISTS.contains(&name) || name == "secret" {
            continue;
        }
        let json = if name == "authentication" {
            // Show who can sign in, never the password.
            let users = item
                .as_sequence()
                .map(|seq| {
                    seq.iter()
                        .filter_map(Value::as_str)
                        .map(|entry| format!("{}:••••", entry.split_once(':').map_or(entry, |(user, _)| user)))
                        .map(serde_json::Value::String)
                        .collect()
                })
                .unwrap_or_default();
            serde_json::Value::Array(users)
        } else {
            overview_json(item, 0)
        };
        out.insert(name.to_string(), json);
    }
    serde_json::Value::Object(out)
}

fn overview_counts(value: &Value) -> (BTreeMap<String, usize>, BTreeMap<String, usize>) {
    let mut counts = BTreeMap::new();
    for name in OVERVIEW_LISTS {
        if let Some(item) = mapping_get(value, name) {
            let size = item
                .as_sequence()
                .map(Vec::len)
                .or_else(|| item.as_mapping().map(serde_yaml::Mapping::len))
                .unwrap_or(0);
            counts.insert((*name).to_string(), size);
        }
    }
    let mut types = BTreeMap::new();
    if let Some(groups) = mapping_get(value, "proxy-groups").and_then(Value::as_sequence) {
        for group in groups {
            let kind = read_string(group, "type").unwrap_or_default().to_ascii_lowercase();
            if !kind.is_empty() {
                *types.entry(kind).or_insert(0) += 1;
            }
        }
    }
    (counts, types)
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProvidersSnapshot {
    pub providers: Vec<diagnostics::ProviderView>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RulesSnapshot {
    pub rules: Vec<diagnostics::RuleRowView>,
    pub error: Option<String>,
    /// Rule keys disabled for this run; cleared when the app restarts or the config changes.
    pub disabled: Vec<String>,
}

/// One runtime rule toggle from the rules page.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleToggle {
    pub key: String,
    pub disabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Takeover {
    system_proxy: bool,
    tun: bool,
    vpn: bool,
}

impl Default for Takeover {
    fn default() -> Self {
        Self {
            system_proxy: false,
            tun: false,
            vpn: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct ProfileView {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub source: String,
    pub user_agent: String,
    pub current: bool,
    pub failure: Option<String>,
    pub override_text: String,
    pub override_error: Option<String>,
    pub used: Option<u64>,
    pub total: Option<u64>,
    pub expire: Option<u64>,
    pub last_success_ms: Option<u64>,
    pub interval_hours: u32,
    pub updated_ms: Option<u64>,
    pub proxy_count: usize,
    /// Public keys of the configured age identities; the secret is never sent to the UI.
    pub age_recipients: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct ProfileSnapshot {
    pub profiles: Vec<ProfileView>,
    pub active_id: Option<String>,
    pub mixed_port: Option<i64>,
    pub mode: Option<String>,
    pub system_proxy: bool,
    pub tun: bool,
    pub vpn: bool,
    pub pending_url: Option<String>,
    pub failure: Option<String>,
    pub input_error: Option<String>,
    pub connected: bool,
    pub platform: String,
    pub tun_wanted: bool,
    pub excluded: Vec<String>,
    /// Apps that use the VPN when `app_mode` is `include`.
    pub included: Vec<String>,
    /// `exclude` (listed apps bypass the VPN) or `include` (only listed apps use it).
    pub app_mode: String,
    pub installed: Vec<crate::takeover::InstalledApp>,
    pub node_catalog: Vec<NodeGroupView>,
    pub node_query: String,
    pub nodes_notice: Option<String>,
    pub nodes_error: Option<String>,
    pub nodes_profile_id: Option<String>,
    pub kernel_running: bool,
    /// Engine selected for the next connection (`mihomo` / `rust`).
    pub engine: String,
    /// Engine of the process actually running, or `None` when none runs.
    pub running_engine: Option<String>,
    /// Version reported by the running engine, when it reports one.
    pub engine_version: Option<String>,
    /// Identity line of the running instance (native kernel), for restart evidence.
    pub engine_identity: Option<String>,
    /// Kernel memory in bytes; `None` when the kernel does not report it.
    pub kernel_memory: Option<u64>,
    /// Seconds since the kernel process started; `None` while it is not running.
    pub kernel_uptime_secs: Option<u64>,
    pub connections: Vec<ConnectionView>,
    /// Open connections the kernel reported, even when the list keeps only 500 rows.
    pub connection_total: usize,
    /// Set when `/connections` could not be read; empty results are not failures.
    pub connections_error: Option<String>,
    pub connection_query: String,
    pub logs: Vec<LogView>,
    pub log_filter: String,
    pub upload: Option<u64>,
    pub download: Option<u64>,
    pub upload_total: Option<u64>,
    pub download_total: Option<u64>,
    pub settings: KernelSettings,
    pub config_values: ConfigValues,
    pub notice: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedSubscription {
    pub content: String,
    pub userinfo: Option<String>,
}

pub struct RefreshRequest {
    id: String,
    source: String,
    user_agent: String,
    age_key: String,
    revision: u64,
}

pub struct DownloadedProfile {
    content: String,
    proxy_count: usize,
    usage: Option<Usage>,
}

impl FetchedSubscription {
    fn into_profile(self, age_key: &str) -> Result<DownloadedProfile, String> {
        let plain = if age_key::is_encrypted_text(&self.content) {
            age_key::decrypt_if_needed(&self.content, age_key)?
        } else {
            self.content
        };
        let (content, proxy_count) = parse_subscription_content(plain)?;
        Ok(DownloadedProfile { content, proxy_count, usage: parse_userinfo(self.userinfo.as_deref()) })
    }
}

impl RefreshRequest {
    pub fn fetch(&self, source: &dyn SubscriptionSource) -> Result<DownloadedProfile, String> {
        source.fetch_with_user_agent(&self.source, &self.user_agent)
            .map_err(|_| FETCH_ERROR.to_string())?
            .into_profile(&self.age_key)
    }
}

pub const DEFAULT_SUBSCRIPTION_USER_AGENT: &str = "clash.meta";

fn default_subscription_user_agent(version: Option<&str>) -> String {
    match version.map(str::trim).filter(|version| !version.is_empty()) {
        Some(version) => format!("{DEFAULT_SUBSCRIPTION_USER_AGENT}/{version}"),
        None => DEFAULT_SUBSCRIPTION_USER_AGENT.to_string(),
    }
}

fn normalize_subscription_user_agent(raw: &str) -> Result<String, String> {
    if raw.len() > 256 || raw.bytes().any(|byte| byte < 32 || byte > 126) {
        return Err("User-Agent 只能包含可打印的 ASCII 字符，长度不能超过 256，不能含换行".to_string());
    }
    let value = raw.trim();
    Ok(value.to_string())
}

pub trait SubscriptionSource {
    fn fetch(&self, url: &str) -> Result<FetchedSubscription, String>;
    fn fetch_with_user_agent(&self, url: &str, _user_agent: &str) -> Result<FetchedSubscription, String> {
        self.fetch(url)
    }
}

pub trait KernelLaunch {
    fn start_or_reload(&mut self, config_yaml: &str) -> Result<(), String>;

    /// `force` stops the running process and spawns a new one even when the YAML
    /// is unchanged (内核重启); otherwise identical to [`Self::start_or_reload`].
    fn start_or_reload_with(&mut self, config_yaml: &str, force: bool) -> Result<(), String> {
        let _ = force;
        self.start_or_reload(config_yaml)
    }

    /// Which engine the next launch uses. Older fakes keep Mihomo semantics.
    fn engine(&self) -> Engine {
        Engine::Mihomo
    }

    /// Selects the engine for the next launch. The caller stops the previous
    /// process first; the engine never changes underneath a running instance.
    fn set_engine(&mut self, _engine: Engine) {}

    /// The Android VpnService fd the next Rust launch inherits. The fd is
    /// passed as `--tun-fd`, never written into the YAML; `None` clears it.
    fn set_tun_fd(&mut self, _fd: Option<i32>) {}

    /// Identity of the process actually started, or `None` while none runs.
    fn identity(&self) -> Option<EngineIdentity> {
        None
    }

    /// Stops the running process without touching OS takeover (the caller
    /// releases that separately so the failure path stays ordered).
    fn stop_kernel(&mut self) {}

    /// Validates the YAML with the selected engine before any live session is
    /// torn down. `Ok(())` means the target engine accepted it.
    fn validate_config(&mut self, _config_yaml: &str) -> Result<(), String> {
        Ok(())
    }

    /// Applies a filtered runtime config without restarting the process, so the
    /// rule list can be toggled while TUN/VPN stays up.
    fn reload_config(&mut self, config_yaml: &str) -> Result<(), String> {
        self.start_or_reload(config_yaml)
    }

    fn running(&mut self) -> bool {
        false
    }

    fn select_proxy(&mut self, _group: &str, _node: &str) -> Result<(), String> {
        Err(KERNEL_DOWN.to_string())
    }

    /// Clears the fixed node of a `url-test` / `fallback` group (`DELETE /proxies/{group}`).
    fn unfix_proxy(&mut self, _group: &str) -> Result<(), String> {
        Err(KERNEL_DOWN.to_string())
    }

    fn close_previous_group_connections(&mut self, _group: &str, _selected: &str) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }

    fn probe_delays(&mut self, _group: &str, _nodes: &[String]) -> Result<Vec<NodeDelay>, String> {
        Err(KERNEL_DOWN.to_string())
    }

    /// Reports each finished node as it returns, then the ordered results.
    fn probe_delays_with_progress(
        &mut self,
        group: &str,
        nodes: &[String],
        on_result: &mut dyn FnMut(&str, Option<u64>, bool),
    ) -> Result<Vec<NodeDelay>, String> {
        let results = self.probe_delays(group, nodes)?;
        for item in &results {
            on_result(&item.name, item.delay_ms, item.delay_ms.is_none());
        }
        Ok(results)
    }

    fn auto_now(&mut self) -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    fn node_catalog(&mut self) -> nodes::RuntimeCatalog {
        nodes::RuntimeCatalog { now: self.auto_now(), ..Default::default() }
    }

    fn connections(&mut self) -> Vec<ConnectionView> {
        Vec::new()
    }

    /// Open connections counted by the last `/connections` read, before the view keeps 500 rows.
    fn connection_total(&mut self) -> Option<usize> {
        None
    }

    /// Why the last `/connections` read failed, if it did.
    fn connections_error(&mut self) -> Option<String> {
        None
    }

    /// Kernel memory in bytes, from `/memory`. `None` when the kernel does not report it.
    fn kernel_memory(&mut self) -> Option<u64> {
        None
    }

    /// Seconds since this kernel process started, tracked by the app.
    fn kernel_uptime_secs(&mut self) -> Option<u64> {
        None
    }

    fn pull_logs(&mut self) -> Vec<LogView> {
        Vec::new()
    }

    fn set_mode(&mut self, _mode: &str) -> Result<(), String> {
        Ok(())
    }

    fn traffic(&mut self) -> Option<(u64, u64)> {
        None
    }

    /// Byte totals from the last `/connections` read.
    fn connection_totals(&mut self) -> Option<TrafficTotals> {
        None
    }

    /// Loopback controller of the running kernel, for one-off reads such as rules.
    fn controller(&mut self) -> Option<ControllerEndpoint> {
        None
    }

    /// Consumes the exit status recorded when a running kernel process died unexpectedly.
    fn take_exit_detail(&mut self) -> Option<String> {
        None
    }
}

pub struct HttpSubscriptionClient {
    agent: ureq::Agent,
    default_user_agent: String,
}

impl HttpSubscriptionClient {
    pub fn new() -> Self { Self::with_kernel_version(None) }

    pub fn with_kernel_version(version: Option<&str>) -> Self {
        static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
        let agent = AGENT.get_or_init(|| ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(30))
            .build()).clone();
        Self { agent, default_user_agent: default_subscription_user_agent(version) }
    }
}

impl Default for HttpSubscriptionClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SubscriptionSource for HttpSubscriptionClient {
    fn fetch(&self, url: &str) -> Result<FetchedSubscription, String> {
        self.fetch_with_user_agent(url, "")
    }

    fn fetch_with_user_agent(&self, url: &str, user_agent: &str) -> Result<FetchedSubscription, String> {
        let custom = normalize_subscription_user_agent(user_agent)?;
        let user_agent = if custom.is_empty() { &self.default_user_agent } else { &custom };
        if validate_subscription_url(url).is_err() {
            return Err(FETCH_ERROR.to_string());
        }
        let response = self
            .agent
            .get(url)
            .set("User-Agent", user_agent)
            .call()
            .map_err(|_| FETCH_ERROR.to_string())?;
        let userinfo = response.header("subscription-userinfo").map(str::to_string);
        let mut body = Vec::new();
        response
            .into_reader()
            .take(BODY_LIMIT + 1)
            .read_to_end(&mut body)
            .map_err(|_| FETCH_ERROR.to_string())?;
        if body.len() as u64 > BODY_LIMIT {
            return Err(FETCH_ERROR.to_string());
        }
        // Binary age files are armored so the rest of the pipeline stays textual.
        let text = if age_key::is_encrypted_bytes(&body) {
            age_key::armor_binary(&body)
        } else {
            String::from_utf8(body).map_err(|_| FETCH_ERROR.to_string())?
        };
        Ok(FetchedSubscription {
            content: text,
            userinfo,
        })
    }
}

/// Kernel listener failures arrive as raw Go errors; say what is wrong and what to do.
fn friendly_listen_error(message: &str) -> String {
    let lower = message.to_lowercase();
    let in_use = lower.contains("only one usage of each socket address")
        || lower.contains("address already in use")
        || lower.contains("10048");
    let kind = [
        ("Start Mixed", "混合端口"),
        ("Start HTTP", "HTTP 端口"),
        ("Start SOCKS", "SOCKS 端口"),
        ("Start Redir", "redir 端口"),
        ("Start TProxy", "tproxy 端口"),
        ("RESTful API", "混合端口"),
    ]
    .into_iter()
    .find(|(marker, _)| message.contains(marker))
    .map(|(_, kind)| kind);
    if let Some(kind) = kind.filter(|_| in_use) {
        let address = message
            .split("listen tcp ")
            .nth(1)
            .and_then(|rest| rest.split(": bind").next())
            .map(str::trim)
            .filter(|address| !address.is_empty())
            .unwrap_or("混合端口");
        return format!(
            "端口 {address} 已被其他程序占用，内核无法启动。请关闭占用它的程序（例如另一个 Clash / mihomo 客户端），或在设置中更换{kind}后重试"
        );
    }
    if message.contains("Start TUN") || lower.contains("configure tun") {
        if lower.contains("access is denied")
            || lower.contains("operation not permitted")
            || lower.contains("permission denied")
        {
            #[cfg(target_os = "macos")]
            return "TUN 启动失败：需要系统管理员权限授权内核，请重新开启 TUN 并在弹出的系统授权窗口中确认".to_string();
            #[cfg(target_os = "linux")]
            return "TUN 启动失败：需要管理员权限（root 或 CAP_NET_ADMIN）后才能创建虚拟网卡".to_string();
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            return "TUN 启动失败：需要管理员权限。请以管理员身份运行 Billow 后重试".to_string();
        }
        if lower.contains("already exists") || in_use {
            return "TUN 启动失败：系统里已有同名虚拟网卡或地址冲突，通常是另一个代理客户端的 TUN 模式仍在运行。请先关闭它，或在 TUN 设置中更换网卡名称".to_string();
        }
        return format!("TUN 启动失败：{message}");
    }
    message.to_string()
}

/// The kernels directory: `…/kernels/files/<hash>/core.exe` → `…/kernels`.
/// Only app-managed kernels qualify; a kernel elsewhere never triggers a sweep.
#[cfg(target_os = "windows")]
fn kernel_root(kernel: &std::path::Path) -> Option<PathBuf> {
    kernel
        .ancestors()
        .find(|dir| dir.file_name().is_some_and(|name| name.eq_ignore_ascii_case("kernels")))
        .map(std::path::Path::to_path_buf)
}

/// Orphaned kernels leave their `runtime-*.yaml` behind; only the new one stays.
#[cfg(not(target_os = "android"))]
fn remove_stale_runtime_configs(work_dir: &std::path::Path, keep: &std::path::Path) {
    let Ok(entries) = fs::read_dir(work_dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path != keep && name.starts_with("runtime-") && name.ends_with(".yaml") {
            let _ = fs::remove_file(path);
        }
    }
}

/// Reap a stray kernel left behind on macOS/Linux by an earlier crashed or force-quit session.
#[cfg(all(unix, not(target_os = "android")))]
fn reap_stale_unix_kernel(work_dir: &std::path::Path, kernel_path: &std::path::Path) {
    let pid_file = work_dir.join("kernel.pid");
    let Ok(raw) = fs::read_to_string(&pid_file) else { return };
    let _ = fs::remove_file(&pid_file);
    let Some(pid) = raw.lines().next().and_then(|line| line.trim().parse::<u32>().ok()) else {
        return;
    };
    if pid <= 1 || pid == std::process::id() {
        return;
    }
    let check = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "args="])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let Ok(out) = check else { return };
    if !out.status.success() {
        return;
    }
    let cmdline = String::from_utf8_lossy(&out.stdout);
    let work_str = work_dir.to_string_lossy();
    let kern_str = kernel_path.to_string_lossy();
    if !cmdline.contains(work_str.as_ref()) && !cmdline.contains(kern_str.as_ref()) {
        return;
    }
    let _ = Command::new("kill")
        .args(["-KILL", "--", &format!("-{pid}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    for _ in 0..10 {
        let alive = Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !alive {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// If the configured loopback controller port is already held by another client, pick an open one.
fn ensure_free_controller_port(yaml: &str) -> String {
    let Some(endpoint) = nodes::controller_from_yaml(yaml) else {
        return yaml.to_string();
    };
    if std::net::TcpListener::bind((endpoint.host.as_str(), endpoint.port)).is_ok() {
        return yaml.to_string();
    }
    let Ok(mut value) = serde_yaml::from_str::<Value>(yaml) else {
        return yaml.to_string();
    };
    let mixed = read_i64(&value, "mixed-port")
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p > 0);
    let tun = value
        .get("tun")
        .and_then(|t| t.get("enable"))
        .and_then(Value::as_bool)
        == Some(true);
    if !endpoint.secret.is_empty() && nodes::listeners_ready(&endpoint, mixed, tun) {
        return yaml.to_string();
    }
    let Ok(free) = std::net::TcpListener::bind(("127.0.0.1", 0)) else {
        return yaml.to_string();
    };
    let Ok(addr) = free.local_addr() else {
        return yaml.to_string();
    };
    let port = addr.port();
    drop(free);
    if let Some(map) = value.as_mapping_mut() {
        map.insert(
            Value::String("external-controller".to_string()),
            Value::String(format!("127.0.0.1:{port}")),
        );
        if let Ok(rewritten) = serde_yaml::to_string(&value) {
            return rewritten;
        }
    }
    yaml.to_string()
}

fn kernel_file_privileged(path: &std::path::Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        takeover::macos_kernel_has_setuid_root(path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        false
    }
}

/// Whether `fd` is still a live descriptor in this process. Android hands the
/// VpnService TUN to the Rust child as an inherited number, and the number is
/// only meaningful while the host VpnService owns it: after `onRevoke` closed
/// it, a later launch must not pass the stale number (it may have been reused
/// by an unrelated descriptor). `/proc/self/fd` (Linux/Android) and `/dev/fd`
/// (Darwin) expose one entry per open descriptor without touching its contents.
#[cfg(unix)]
fn descriptor_is_open(fd: i32) -> bool {
    if fd < 0 {
        return false;
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    let path = format!("/proc/self/fd/{fd}");
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let path = format!("/dev/fd/{fd}");
    std::fs::symlink_metadata(path).is_ok()
}

#[cfg(not(unix))]
fn descriptor_is_open(_fd: i32) -> bool {
    false
}

/// Spawns the already installed kernel. Tests inject [`KernelLaunch`] instead.
pub struct ProcessRuntime {
    /// Engine the next launch uses; kept in sync with the profile book selection.
    engine: Engine,
    /// Mihomo binary installed by [`crate::kernel::KernelManager`].
    kernel_path: Option<PathBuf>,
    /// Packaged native Rust kernel (`billow-kernel` / `libbillow_kernel.so`).
    rust_path: Option<PathBuf>,
    work_dir: PathBuf,
    home_dir: PathBuf,
    bundled_resources: Option<PathBuf>,
    child: Option<Child>,
    #[cfg(target_os = "windows")]
    elevated: Option<crate::elevation::ElevatedKernel>,
    config_path: Option<PathBuf>,
    last_requested_yaml: Option<String>,
    controller: Option<ControllerEndpoint>,
    cached_catalog: nodes::RuntimeCatalog,
    provider_catalog: Option<(Instant, nodes::RuntimeCatalog)>,
    launched_kernel: Option<PathBuf>,
    launched_engine: Option<Engine>,
    /// Instance identity line reported by the native Rust kernel.
    launched_identity: Option<String>,
    launched_version: Option<String>,
    launched_privileged: bool,
    tun_active: bool,
    /// Android TUN fd the next Rust launch inherits (`--tun-fd`). The Android
    /// VpnService hand-off never writes it into the YAML.
    tun_fd: Option<i32>,
    log_buffer: Option<CapturedLogs>,
    pending_logs: Vec<LogView>,
    exit_detail: Option<String>,
    traffic_watch: Option<MetricWatch<(u64, u64)>>,
    memory_watch: Option<MetricWatch<u64>>,
    totals: Option<TrafficTotals>,
    connection_total: Option<usize>,
    connections_error: Option<String>,
    started: Option<Instant>,
}

struct MetricWatch<T> {
    latest: Arc<Mutex<Option<T>>>,
    stop: Arc<AtomicBool>,
}

impl<T: Copy + Send + 'static> MetricWatch<T> {
    fn spawn(
        endpoint: ControllerEndpoint,
        watch: impl FnOnce(ControllerEndpoint, Arc<Mutex<Option<T>>>, Arc<AtomicBool>) + Send + 'static,
    ) -> Self {
        let latest = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let shared = Arc::clone(&latest);
        let flag = Arc::clone(&stop);
        std::thread::spawn(move || watch(endpoint, shared, flag));
        Self {
            latest,
            stop,
        }
    }

    fn latest(&self) -> Option<T> {
        *self
            .latest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn halt(self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl ProcessRuntime {
    pub fn new(work_dir: impl Into<PathBuf>) -> Self {
        let work_dir = work_dir.into();
        #[cfg(target_os = "android")]
        let home_dir = work_dir.clone();
        #[cfg(not(target_os = "android"))]
        let home_dir = crate::resources::kernel_home().unwrap_or_else(|| work_dir.clone());
        Self {
            engine: Engine::Mihomo,
            kernel_path: None,
            rust_path: None,
            work_dir,
            home_dir,
            bundled_resources: None,
            child: None,
            #[cfg(target_os = "windows")]
            elevated: None,
            config_path: None,
            last_requested_yaml: None,
            controller: None,
            cached_catalog: nodes::RuntimeCatalog::default(),
            provider_catalog: None,
            launched_kernel: None,
            launched_engine: None,
            launched_identity: None,
            launched_version: None,
            launched_privileged: false,
            tun_active: false,
            tun_fd: None,
            log_buffer: None,
            pending_logs: Vec::new(),
            exit_detail: None,
            traffic_watch: None,
            memory_watch: None,
            totals: None,
            connection_total: None,
            connections_error: None,
            started: None,
        }
    }

    pub fn set_kernel_path(&mut self, path: Option<PathBuf>) {
        self.kernel_path = path;
    }

    pub fn set_rust_kernel_path(&mut self, path: Option<PathBuf>) {
        self.rust_path = path;
    }

    /// The binary the selected engine launches.
    fn engine_path(&self) -> Option<PathBuf> {
        match self.engine {
            Engine::Mihomo => self.kernel_path.clone(),
            Engine::Rust => self.rust_path.clone(),
        }
    }

    pub fn set_bundled_resources(&mut self, resources: PathBuf) {
        self.bundled_resources = Some(resources);
    }

    pub fn shutdown(&mut self) {
        self.stop();
    }

    pub fn running_kernel_path(&mut self) -> Option<PathBuf> {
        if self.running() { self.launched_kernel.clone() } else { None }
    }

    fn stop(&mut self) {
        self.halt_metrics();
        if self.tun_active {
            if let Some(endpoint) = self.controller.as_ref() {
                nodes::patch_tun_disable(endpoint);
            }
        }
        if let Some(mut child) = self.child.take() {
            #[cfg(unix)]
            {
                let pid = child.id();
                // procps 3.3.x can interpret a bare negative PID as options and
                // signal process group 0 (the app/runner) instead of this child.
                let _ = Command::new("kill")
                    .args(["-TERM", "--", &format!("-{pid}")])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                let _ = Command::new("kill")
                    .args(["-TERM", &pid.to_string()])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                for _ in 0..15 {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                if matches!(child.try_wait(), Ok(None)) {
                    let _ = Command::new("kill")
                        .args(["-KILL", "--", &format!("-{pid}")])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
            }
            if matches!(child.try_wait(), Ok(None)) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        #[cfg(target_os = "windows")]
        drop(self.elevated.take());
        if let Some(path) = self.config_path.take() {
            let _ = fs::remove_file(path);
        }
        #[cfg(all(unix, not(target_os = "android")))]
        let _ = fs::remove_file(self.work_dir.join("kernel.pid"));
        self.last_requested_yaml = None;
        self.controller = None;
        self.launched_kernel = None;
        self.launched_engine = None;
        self.launched_identity = None;
        self.launched_version = None;
        self.launched_privileged = false;
        self.tun_active = false;
        // `launch` calls `stop` before spawning and must still see the fd the
        // caller handed over for this launch; only `set_tun_fd(None)` clears it.
        self.cached_catalog = nodes::RuntimeCatalog::default();
        self.provider_catalog = None;
        self.log_buffer = None;
        self.exit_detail = None;
        self.totals = None;
        self.connection_total = None;
        self.connections_error = None;
        self.started = None;
    }

    fn fail_start(&mut self, reason: Option<String>) -> String {
        let logs = self.log_buffer.take();
        let exit_detail = self.exit_detail.clone();
        self.stop();
        let lines = logs.map(|buffer| buffer.drain_after_exit()).unwrap_or_default();
        let message = reason.unwrap_or_else(|| {
            let detail = lines.iter().rev().find(|line| line.level == "error")
                .map(|line| friendly_listen_error(&line.message));
            let status = exit_detail.map(|status| format!("（{status}）")).unwrap_or_default();
            match detail {
                Some(detail) => format!("内核启动失败{status}：{detail}"),
                None => format!("内核进程提前退出{status}，请检查系统崩溃或安全日志"),
            }
        });
        diagnostics::push_logs(&mut self.pending_logs, lines);
        message
    }

    fn halt_metrics(&mut self) {
        if let Some(watch) = self.traffic_watch.take() {
            watch.halt();
        }
        if let Some(watch) = self.memory_watch.take() {
            watch.halt();
        }
    }
}

type LogReader = (Box<dyn Read + Send>, bool);

struct CapturedLogs {
    lines: Arc<Mutex<Vec<LogView>>>,
    finished: Arc<AtomicUsize>,
    readers: usize,
}

impl CapturedLogs {
    fn drain_after_exit(&self) -> Vec<LogView> {
        // try_wait can observe exit before the reader threads consume the final
        // fatal line. Bound the wait in case a descendant still holds a pipe.
        let deadline = Instant::now() + Duration::from_millis(200);
        while self.finished.load(Ordering::Acquire) < self.readers && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        std::mem::take(&mut *self.lines.lock().unwrap_or_else(|p| p.into_inner()))
    }
}

fn spawn_log_buffer(streams: Vec<LogReader>) -> CapturedLogs {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let finished = Arc::new(AtomicUsize::new(0));
    let readers = streams.len();
    for (stream, stderr) in streams {
        let shared = Arc::clone(&lines);
        let done = Arc::clone(&finished);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stream);
            let mut chunk = Vec::new();
            let mut truncated = false;
            loop {
                chunk.clear();
                // Bound a single unstructured panic/dyld line as well as the log count.
                match (&mut reader).take(8192).read_until(b'\n', &mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                let complete = chunk.last() == Some(&b'\n');
                if !truncated {
                    let text = String::from_utf8_lossy(&chunk);
                    let text = text.trim();
                    if !text.is_empty() {
                        let item = diagnostics::parse_log_line(text).unwrap_or_else(|| LogView {
                            level: if stderr { "error" } else { "info" }.to_string(),
                            message: text.to_string(),
                            time_ms: now_ms(),
                        });
                        let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
                        diagnostics::push_logs(&mut guard, vec![item]);
                    }
                }
                truncated = !complete;
            }
            done.fetch_add(1, Ordering::Release);
        });
    }
    CapturedLogs { lines, finished, readers }
}

/// Parses the native kernel's identity line:
/// `instance=<uuid> pid=<n> version=<v> listen=<addr> …`.
fn parse_kernel_identity(message: &str) -> Option<(String, Option<String>, std::net::SocketAddr)> {
    let field = |name: &str| {
        let token = format!("{name}=");
        message.split_whitespace().find_map(|item| item.strip_prefix(token.as_str()))
    };
    let instance = field("instance")?.to_string();
    if instance.is_empty() || instance == "-" {
        return None;
    }
    let version = field("version").filter(|value| !value.is_empty() && *value != "-").map(str::to_string);
    let listen = field("listen")?.parse().ok()?;
    Some((instance, version, listen))
}

fn listener_accepts(addr: std::net::SocketAddr) -> bool {
    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(150)).is_ok()
}

impl Drop for ProcessRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}

impl ProcessRuntime {
    fn launch(&mut self, config_yaml: &str, force: bool) -> Result<(), String> {
        let Some(path) = self.engine_path() else {
            return Err(MISSING_KERNEL.to_string());
        };
        if !path.is_file() {
            return Err(MISSING_KERNEL.to_string());
        }
        if let Some(resources) = &self.bundled_resources {
            crate::bundled_geo::seed_directory(&resources.join("geo"), &self.home_dir)?;
        }
        let priv_now = kernel_file_privileged(&path);
        #[cfg(target_os = "windows")]
        let needs_elevation = self.engine == Engine::Mihomo
            && serde_yaml::from_str::<Value>(config_yaml).ok()
            .and_then(|value| value.get("tun")?.get("enable")?.as_bool()) == Some(true)
            && !crate::elevation::is_admin();
        #[cfg(target_os = "windows")]
        let can_reload = !needs_elevation || self.elevated.is_some();
        #[cfg(not(target_os = "windows"))]
        let can_reload = true;
        // A forced restart skips both the no-op and the hot-reload path.
        if !force && can_reload && self.running()
            && self.launched_kernel.as_ref() == Some(&path)
            && self.launched_engine == Some(self.engine)
            && self.launched_privileged == priv_now
        {
            if self.last_requested_yaml.as_deref() == Some(config_yaml) {
                let config: Value = serde_yaml::from_str(config_yaml).unwrap_or(Value::Null);
                let mixed = read_i64(&config, "mixed-port")
                    .and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0);
                let tun = config.get("tun").and_then(|t| t.get("enable")).and_then(Value::as_bool) == Some(true);
                if self.controller.as_ref().is_none_or(|endpoint| nodes::listeners_ready(endpoint, mixed, tun)) {
                    return Ok(());
                }
            }
            #[cfg(not(target_os = "android"))]
            if self.engine == Engine::Mihomo
                && let Some(endpoint) = self.controller.clone()
            {
                let _ = fs::create_dir_all(&self.work_dir);
                let effective_yaml = nodes::rewrite_controller_endpoint(config_yaml, &endpoint);
                let config: Value = serde_yaml::from_str(&effective_yaml).unwrap_or(Value::Null);
                let mixed = read_i64(&config, "mixed-port")
                    .and_then(|p| u16::try_from(p).ok())
                    .filter(|p| *p > 0);
                let tun = config
                    .get("tun")
                    .and_then(|t| t.get("enable")
                    .and_then(Value::as_bool))
                    == Some(true);
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                let next_path = self.work_dir.join(format!("runtime-{nanos}.yaml"));
                let _ = fs::write(&next_path, &effective_yaml);
                match nodes::put_config(&endpoint, &effective_yaml) {
                    Ok(()) => {
                        let deadline = Instant::now() + Duration::from_secs(5);
                        let mut ready = false;
                        while Instant::now() < deadline {
                            if !self.running() {
                                break;
                            }
                            if nodes::listeners_ready(&endpoint, mixed, tun) {
                                ready = true;
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        if ready {
                            remove_stale_runtime_configs(&self.work_dir, &next_path);
                            self.config_path = Some(next_path);
                            self.last_requested_yaml = Some(config_yaml.to_string());
                            self.tun_active = tun;
                            self.cached_catalog = nodes::RuntimeCatalog::default();
                            self.provider_catalog = None;
                            return Ok(());
                        }
                        let _ = fs::remove_file(&next_path);
                    }
                    Err(err) => {
                        let _ = fs::remove_file(&next_path);
                        let lower = err.to_ascii_lowercase();
                        if self.running()
                            && (err.contains("Start TUN")
                                || lower.contains("configure tun")
                                || err.contains("listen tcp "))
                        {
                            return Err(friendly_listen_error(&err));
                        }
                    }
                }
            }
        }
        fs::create_dir_all(&self.work_dir).map_err(|_| "配置没有写入".to_string())?;
        // A live elevated helper starts the next kernel itself, so a restart with TUN needs no
        // second UAC prompt. It keeps the old kernel until the new launch request arrives, and
        // its stdout reader keeps feeding the existing log buffer.
        #[cfg(target_os = "windows")]
        let mut reused = if needs_elevation {
            self.elevated.take().filter(|helper| helper.running())
        } else { None };
        #[cfg(target_os = "windows")]
        let reused_logs = if reused.is_some() { self.log_buffer.take() } else { None };
        #[cfg(not(target_os = "windows"))]
        let reused_logs: Option<CapturedLogs> = None;
        // Consent/handshake precedes shutdown, so cancelling UAC leaves the old session intact.
        #[cfg(target_os = "windows")]
        let mut elevated = if needs_elevation && reused.is_none() {
            Some(crate::elevation::ElevatedKernel::prepare()?)
        } else { None };
        self.stop();
        #[cfg(all(unix, not(target_os = "android")))]
        reap_stale_unix_kernel(&self.work_dir, &path);
        let effective_yaml = ensure_free_controller_port(config_yaml);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let config_path = self.work_dir.join(format!("runtime-{nanos}.yaml"));
        fs::write(&config_path, &effective_yaml).map_err(|_| "配置没有写入".to_string())?;
        let controller = nodes::controller_from_yaml(&effective_yaml);
        #[cfg(target_os = "android")]
        {
            let apk = crate::kernel::android_app_dir("sourceDir")
                .ok_or_else(|| "无法读取安装包中的 GEO 数据".to_string())?;
            crate::bundled_geo::seed(&apk, &self.work_dir)?;
        }
        let mut command = Command::new(&path);
        match self.engine {
            Engine::Mihomo => {
                command.arg("-d").arg(&self.home_dir);
                command.arg("-f").arg(&config_path);
            }
            Engine::Rust => {
                // The native kernel takes the YAML positionally; Mihomo's
                // `-d`/`-f` flags and controller API do not apply to it.
                command.arg(&config_path);
            }
        }
        // Android hands the established VpnService TUN to the Rust process as
        // an inherited fd (`BillowVpnService.establishTun` clears FD_CLOEXEC),
        // never as a `tun.file-descriptor` YAML key. Desktop has no such fd.
        if self.engine == Engine::Rust {
            if let Some(fd) = self.tun_fd {
                // A child that exited on its own leaves the number behind; the
                // VpnService may also have released it on revoke. Only a live
                // descriptor can be inherited, otherwise the next process would
                // poll a reused number (or fail on a closed one).
                if descriptor_is_open(fd) {
                    command.arg("--tun-fd").arg(fd.to_string());
                } else {
                    self.tun_fd = None;
                }
            }
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // Own process group so stopping the kernel does not signal this app.
            command.process_group(0);
        }
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }
        // A kernel orphaned by an earlier app process still holds the mixed and
        // controller ports; every new start would fail with "address in use".
        // A reused helper still runs the previous kernel here and replaces it itself.
        #[cfg(target_os = "windows")]
        if reused.is_none() {
            let stuck = kernel_root(&path)
                .map(|root| crate::win_process::end_stray_kernels(&root, None))
                .unwrap_or_default();
            if !stuck.is_empty() {
                let _ = fs::remove_file(&config_path);
                let pids = stuck.iter().map(|stray| stray.pid.to_string()).collect::<Vec<_>>().join("、");
                return Err(format!(
                    "上次运行留下的内核（PID {pids}）仍占用端口，结束它需要管理员权限。请在任务管理器中结束该进程，或以管理员身份重新打开 Billow 后重试"
                ));
            }
        }
        #[cfg(not(target_os = "android"))]
        remove_stale_runtime_configs(&self.work_dir, &config_path);
        let mut spawn_normal = || -> Result<Vec<LogReader>, String> {
            let mut child = command.spawn().map_err(|error| {
                let _ = fs::remove_file(&config_path);
                format!("{KERNEL_ERROR}：{error}")
            })?;
            #[cfg(target_os = "windows")]
            crate::win_process::bind_to_app_lifetime(&child);
            #[cfg(all(unix, not(target_os = "android")))]
            let _ = fs::write(self.work_dir.join("kernel.pid"), format!("{}\n{}", child.id(), path.display()));
            let mut streams: Vec<LogReader> = Vec::new();
            if let Some(stdout) = child.stdout.take() { streams.push((Box::new(stdout), false)); }
            if let Some(stderr) = child.stderr.take() { streams.push((Box::new(stderr), true)); }
            self.child = Some(child);
            Ok(streams)
        };
        #[cfg(target_os = "windows")]
        let streams = if let Some(mut helper) = reused.take() {
            // The helper stops the previous kernel before starting this one.
            helper.start(&path, &self.home_dir, &config_path).map_err(|error| {
                let _ = fs::remove_file(&config_path);
                format!("{KERNEL_ERROR}：{error}")
            })?;
            self.elevated = Some(helper);
            Vec::new()
        } else if let Some(mut helper) = elevated.take() {
            helper.start(&path, &self.home_dir, &config_path).map_err(|error| {
                let _ = fs::remove_file(&config_path);
                format!("{KERNEL_ERROR}：{error}")
            })?;
            let streams: Vec<LogReader> = helper.take_stdout().into_iter()
                .map(|stdout| (Box::new(stdout) as Box<dyn Read + Send>, true)).collect();
            self.elevated = Some(helper);
            streams
        } else { spawn_normal()? };
        #[cfg(not(target_os = "windows"))]
        let streams = spawn_normal()?;
        let config: Value = serde_yaml::from_str(&effective_yaml).unwrap_or(Value::Null);
        let mixed = read_i64(&config, "mixed-port").and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0);
        let tun = config.get("tun").and_then(|t| t.get("enable")).and_then(Value::as_bool) == Some(true);
        self.started = Some(Instant::now());
        self.exit_detail = None;
        self.launched_kernel = Some(path);
        self.launched_engine = Some(self.engine);
        self.launched_identity = None;
        self.launched_version = None;
        self.launched_privileged = priv_now;
        self.tun_active = tun;
        self.config_path = Some(config_path);
        self.last_requested_yaml = Some(config_yaml.to_string());
        self.controller = controller;
        self.cached_catalog = nodes::RuntimeCatalog::default();
        self.log_buffer = Some(match reused_logs {
            // Same pipe, new kernel: start from an empty log like a fresh spawn would.
            Some(logs) => {
                logs.lines.lock().unwrap_or_else(|p| p.into_inner()).clear();
                logs
            }
            None => spawn_log_buffer(streams),
        });
        let wait = if self.engine == Engine::Rust || self.controller.is_some() {
            Duration::from_secs(25)
        } else {
            Duration::from_millis(300)
        };
        let deadline = Instant::now() + wait;
        loop {
            if self.engine == Engine::Rust {
                let state = self.log_buffer.as_ref().map(|logs| {
                    let lines = logs.lines.lock().unwrap_or_else(|p| p.into_inner());
                    let identity = lines
                        .iter()
                        .find_map(|line| parse_kernel_identity(&line.message));
                    let failure = identity.is_none().then(|| {
                        lines.iter().find(|line| line.level == "error").map(|line| line.message.clone())
                    }).flatten();
                    (identity, failure)
                });
                if let Some((Some((instance, version, listen)), _)) = &state {
                    self.launched_identity = Some(instance.clone());
                    self.launched_version = version.clone();
                    if listener_accepts(*listen) {
                        break;
                    }
                }
                if let Some((_, Some(message))) = state {
                    return Err(self.fail_start(Some(friendly_listen_error(&message))));
                }
                if !self.running() {
                    return Err(self.fail_start(None));
                }
                if Instant::now() >= deadline {
                    let reason = self.log_buffer.as_ref().and_then(|logs| logs.lines.lock().ok()?.last().map(|line| line.message.clone()));
                    let message = format!("内核初始化超时：{}", reason.as_deref().unwrap_or("请检查配置、端口占用和权限"));
                    return Err(self.fail_start(Some(message)));
                }
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            let failure = self.log_buffer.as_ref().and_then(|logs| {
                let lines = logs.lines.lock().unwrap_or_else(|p| p.into_inner());
                lines.iter().find(|line| line.level == "error" &&
                    (line.message.contains("Start Mixed")
                        || line.message.contains("Start HTTP")
                        || line.message.contains("Start SOCKS")
                        || line.message.contains("RESTful API")
                        || line.message.contains("Start TUN")))
                    .map(|line| line.message.clone())
            });
            if let Some(message) = failure {
                return Err(self.fail_start(Some(friendly_listen_error(&message))));
            }
            if !self.running() {
                return Err(self.fail_start(None));
            }
            if let Some(endpoint) = self.controller.as_ref() {
                if nodes::listeners_ready(endpoint, mixed, tun) { break; }
                if Instant::now() >= deadline {
                    let reason = self.log_buffer.as_ref().and_then(|logs| logs.lines.lock().ok()?.last().map(|line| line.message.clone()));
                    let message = format!("内核初始化超时：{}", reason.as_deref().unwrap_or("请检查网络、端口占用和 TUN 权限"));
                    return Err(self.fail_start(Some(message)));
                }
            } else if Instant::now() >= deadline { break; }
            std::thread::sleep(Duration::from_millis(20));
        }
        if let Some(endpoint) = self.controller.clone() {
            self.traffic_watch = Some(MetricWatch::spawn(endpoint.clone(), diagnostics::watch_traffic));
            self.memory_watch = Some(MetricWatch::spawn(endpoint, diagnostics::watch_memory));
        }
        Ok(())
    }
}

impl KernelLaunch for ProcessRuntime {
    fn start_or_reload(&mut self, config_yaml: &str) -> Result<(), String> {
        self.launch(config_yaml, false)
    }

    fn start_or_reload_with(&mut self, config_yaml: &str, force: bool) -> Result<(), String> {
        self.launch(config_yaml, force)
    }

    fn engine(&self) -> Engine {
        self.engine
    }

    fn set_engine(&mut self, engine: Engine) {
        self.engine = engine;
    }

    fn set_tun_fd(&mut self, fd: Option<i32>) {
        self.tun_fd = fd;
    }

    fn identity(&self) -> Option<EngineIdentity> {
        let engine = self.launched_engine?;
        Some(EngineIdentity {
            engine,
            version: self.launched_version.clone(),
            instance: self.launched_identity.clone(),
        })
    }

    fn stop_kernel(&mut self) {
        self.stop();
    }

    /// The native kernel has no hot reload: every config change restarts it.
    fn reload_config(&mut self, config_yaml: &str) -> Result<(), String> {
        if self.engine == Engine::Rust {
            return self.launch(config_yaml, true);
        }
        if !self.running() {
            return Err(KERNEL_DOWN.to_string());
        }
        let Some(endpoint) = self.controller.clone() else {
            return Err(KERNEL_DOWN.to_string());
        };
        let effective_yaml = nodes::rewrite_controller_endpoint(config_yaml, &endpoint);
        nodes::put_config(&endpoint, &effective_yaml)
    }

    /// Runs the target binary in its own validation mode before the caller
    /// releases a live session. Mihomo uses `-t`; the native kernel `--check`.
    fn validate_config(&mut self, config_yaml: &str) -> Result<(), String> {
        let Some(path) = self.engine_path() else {
            return Err(MISSING_KERNEL.to_string());
        };
        if !path.is_file() {
            return Err(MISSING_KERNEL.to_string());
        }
        fs::create_dir_all(&self.work_dir).map_err(|_| "配置没有写入".to_string())?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let config_path = self.work_dir.join(format!("validate-{nanos}.yaml"));
        fs::write(&config_path, config_yaml).map_err(|_| "配置没有写入".to_string())?;
        let mut command = Command::new(&path);
        match self.engine {
            Engine::Mihomo => {
                command.arg("-t").arg("-d").arg(&self.home_dir).arg("-f").arg(&config_path);
            }
            Engine::Rust => {
                // `--check` binds its listener before exiting; port 0 keeps the
                // validation off the live session's port.
                command.arg(&config_path).arg("--check").arg("--port").arg("0");
            }
        }
        let output = command.stdin(Stdio::null()).output();
        let _ = fs::remove_file(&config_path);
        let output = output.map_err(|error| format!("{KERNEL_ERROR}：{error}"))?;
        if output.status.success() {
            return Ok(());
        }
        let mut text = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if text.is_empty() {
            text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
        let detail = text
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("配置未通过内核校验")
            .chars()
            .take(400)
            .collect::<String>();
        Err(detail)
    }

    fn running(&mut self) -> bool {
        let alive = match self.child.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(None) => true,
                Ok(Some(status)) => {
                    self.exit_detail = Some(status.code().map(|code| format!("退出码 {code}"))
                        .unwrap_or_else(|| status.to_string()));
                    false
                }
                Err(error) => {
                    self.exit_detail = Some(format!("读取进程状态失败：{error}"));
                    false
                }
            },
            None => false,
        };
        #[cfg(target_os = "windows")]
        let alive = alive || self.elevated.as_ref().is_some_and(|helper| helper.running());
        if !alive {
            #[cfg(target_os = "windows")]
            { self.elevated = None; }
            self.child = None;
            self.controller = None;
            self.launched_kernel = None;
            self.launched_engine = None;
            self.launched_identity = None;
            self.launched_version = None;
            self.cached_catalog = nodes::RuntimeCatalog::default();
            self.halt_metrics();
        }
        alive
    }

    fn select_proxy(&mut self, group: &str, node: &str) -> Result<(), String> {
        if !self.running() {
            return Err(KERNEL_DOWN.to_string());
        }
        let Some(endpoint) = self.controller.clone() else {
            return Err(KERNEL_DOWN.to_string());
        };
        nodes::put_selection(&endpoint, group, node)
    }

    fn unfix_proxy(&mut self, group: &str) -> Result<(), String> {
        if !self.running() {
            return Err(KERNEL_DOWN.to_string());
        }
        let Some(endpoint) = self.controller.clone() else {
            return Err(KERNEL_DOWN.to_string());
        };
        nodes::delete_selection(&endpoint, group)
    }

    fn close_previous_group_connections(&mut self, group: &str, selected: &str) -> Result<Vec<String>, String> {
        let endpoint = self.controller().ok_or_else(|| KERNEL_DOWN.to_string())?;
        diagnostics::close_previous_group_connections(&endpoint, group, selected)
    }

    fn probe_delays(&mut self, _group: &str, names: &[String]) -> Result<Vec<NodeDelay>, String> {
        if !self.running() {
            return Err(KERNEL_DOWN.to_string());
        }
        let Some(endpoint) = self.controller.clone() else {
            return Err(KERNEL_DOWN.to_string());
        };
        nodes::fetch_provider_delays(&endpoint, names, &self.cached_catalog.providers, &mut |_, _, _| {})
    }

    fn probe_delays_with_progress(
        &mut self,
        _group: &str,
        names: &[String],
        on_result: &mut dyn FnMut(&str, Option<u64>, bool),
    ) -> Result<Vec<NodeDelay>, String> {
        if !self.running() {
            return Err(KERNEL_DOWN.to_string());
        }
        let Some(endpoint) = self.controller.clone() else {
            return Err(KERNEL_DOWN.to_string());
        };
        nodes::fetch_provider_delays(&endpoint, names, &self.cached_catalog.providers, on_result)
    }

    fn node_catalog(&mut self) -> nodes::RuntimeCatalog {
        if !self.running() {
            return nodes::RuntimeCatalog::default();
        }
        if let Some(endpoint) = self.controller.clone() {
            if let Ok(mut catalog) = nodes::fetch_catalog(&endpoint) {
                if self.provider_catalog.as_ref().is_none_or(|(at, _)| at.elapsed() >= Duration::from_secs(30)) {
                    if let Ok(providers) = nodes::fetch_provider_catalog(&endpoint) {
                        self.provider_catalog = Some((Instant::now(), providers));
                    }
                }
                if let Some((_, providers)) = &self.provider_catalog {
                    catalog.merge_providers(providers);
                }
                self.cached_catalog = catalog;
            }
        }
        self.cached_catalog.clone()
    }

    fn connections(&mut self) -> Vec<ConnectionView> {
        if !self.running() {
            return Vec::new();
        }
        let Some(endpoint) = self.controller.clone() else {
            return Vec::new();
        };
        let reading = diagnostics::fetch_connections_with_totals(&endpoint);
        self.totals = reading.totals;
        self.connection_total = Some(reading.total);
        self.connections_error = reading.error;
        reading.rows
    }

    fn connection_total(&mut self) -> Option<usize> {
        self.connection_total
    }

    fn connections_error(&mut self) -> Option<String> {
        self.connections_error.clone()
    }

    fn kernel_memory(&mut self) -> Option<u64> {
        if !self.running() {
            return None;
        }
        self.memory_watch.as_ref().and_then(MetricWatch::latest)
    }

    fn kernel_uptime_secs(&mut self) -> Option<u64> {
        if !self.running() {
            return None;
        }
        self.started.map(|start| start.elapsed().as_secs())
    }

    fn connection_totals(&mut self) -> Option<TrafficTotals> {
        self.totals
    }

    fn controller(&mut self) -> Option<ControllerEndpoint> {
        if !self.running() {
            return None;
        }
        self.controller.clone()
    }

    fn take_exit_detail(&mut self) -> Option<String> {
        let detail = self.exit_detail.take()?;
        if let Some(buffer) = self.log_buffer.take() {
            diagnostics::push_logs(&mut self.pending_logs, buffer.drain_after_exit());
        }
        Some(detail)
    }

    fn pull_logs(&mut self) -> Vec<LogView> {
        let mut lines = std::mem::take(&mut self.pending_logs);
        if let Some(buffer) = &self.log_buffer {
            let mut guard = buffer.lines.lock().unwrap_or_else(|p| p.into_inner());
            diagnostics::push_logs(&mut lines, std::mem::take(&mut *guard));
        }
        lines
    }

    fn set_mode(&mut self, mode: &str) -> Result<(), String> {
        if !self.running() {
            return Ok(());
        }
        let Some(endpoint) = self.controller.clone() else {
            return Ok(());
        };
        nodes::patch_mode(&endpoint, mode)
    }

    fn traffic(&mut self) -> Option<(u64, u64)> {
        if !self.running() {
            return None;
        }
        let Some(watch) = self.traffic_watch.as_mut() else {
            return None;
        };
        if let Some(sample) = watch.latest() {
            return Some(sample);
        }
        // Sampling runs in the background; never stall an IPC response waiting for a tick.
        watch.latest()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DiskState<'a> {
    #[serde(default)]
    next_id: u64,
    #[serde(default)]
    active_id: Option<String>,
    #[serde(default)]
    home_failure: Option<String>,
    #[serde(default)]
    tun_wanted: bool,
    #[serde(default)]
    excluded_packages: Vec<String>,
    /// Allowlist for the include app mode.
    #[serde(default)]
    included_packages: Vec<String>,
    #[serde(default)]
    app_mode: String,
    #[serde(default)]
    proxy_host: Option<String>,
    #[serde(default)]
    proxy_port: Option<u16>,
    #[serde(default)]
    profiles: Vec<DiskProfile<'a>>,
    #[serde(default)]
    chosen_mode: Option<String>,
    #[serde(default)]
    settings: KernelSettings,
    /// Absent in older installations; those keep Mihomo.
    #[serde(default)]
    engine: Engine,
}

#[derive(Debug, Serialize, Deserialize)]
struct DiskProfile<'a> {
    id: String,
    name: String,
    kind: ProfileKind,
    source: String,
    #[serde(default)]
    user_agent: String,
    #[serde(default)]
    content: Cow<'a, str>,
    #[serde(default)]
    proxy_count: Option<usize>,
    #[serde(default)]
    override_text: Cow<'a, str>,
    #[serde(default)]
    applied_override: Cow<'a, str>,
    #[serde(default)]
    override_error: Option<String>,
    #[serde(default)]
    failure: Option<String>,
    #[serde(default)]
    last_success_ms: Option<u64>,
    #[serde(default)]
    used: Option<u64>,
    #[serde(default)]
    total: Option<u64>,
    #[serde(default)]
    expire: Option<u64>,
    #[serde(default)]
    selected: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    fixed: BTreeMap<String, String>,
    #[serde(default)]
    interval_hours: u32,
    #[serde(default)]
    age_key: String,
    #[serde(default)]
    updated_ms: Option<u64>,
}

pub struct ProfileBook {
    path: PathBuf,
    next_id: u64,
    active_id: Option<String>,
    profiles: Vec<Profile>,
    takeover: Takeover,
    pending_url: Option<String>,
    home_failure: Option<String>,
    input_error: Option<String>,
    mixed_port: Option<i64>,
    mode: Option<String>,
    platform: ClientPlatform,
    /// User-selected engine; persisted and defaults to Mihomo for old installs.
    engine: Engine,
    /// Identity of the process actually running, refreshed from the runtime.
    engine_runtime: Option<EngineIdentity>,
    tun_wanted: bool,
    excluded: Vec<String>,
    included: Vec<String>,
    app_mode: String,
    installed: Vec<crate::takeover::InstalledApp>,
    installed_checked_at: Option<Instant>,
    connected: bool,
    our_endpoint: Option<ProxyEndpoint>,
    pending_release: Option<PlatformRelease>,
    node_query: String,
    node_sort: BTreeMap<String, String>,
    delays: BTreeMap<String, BTreeMap<String, BTreeMap<String, DelayMark>>>,
    auto_now: BTreeMap<String, String>,
    runtime_catalog: nodes::RuntimeCatalog,
    nodes_error: Option<String>,
    kernel_running: bool,
    kernel_memory: Option<u64>,
    kernel_uptime_secs: Option<u64>,
    connections: Vec<ConnectionView>,
    connection_total: usize,
    connections_error: Option<String>,
    connection_query: String,
    logs: Vec<LogView>,
    log_filter: String,
    /// Runtime-only disabled rule keys; never persisted, so a restart re-enables rules.
    disabled_rules: BTreeSet<String>,
    /// Last unfiltered runtime config, kept so later toggles filter the full rule
    /// list (stable occurrence keys) while preserving TUN fd and settings.
    runtime_base: Option<String>,
    chosen_mode: Option<String>,
    upload: Option<u64>,
    download: Option<u64>,
    totals: Option<TrafficTotals>,
    settings: KernelSettings,
    notice: Option<String>,
    startup_guard_active: bool,
    shutting_down: bool,
    crash_recoveries: u8,
    last_crash_ms: Option<u64>,
    /// Set only while [`ProfileBook::restart_kernel`] runs: the next launch stops
    /// and respawns the process even for an unchanged YAML.
    force_launch: bool,
}

pub const RESTART_NEEDS_CONNECTION: &str = "请先连接，再重启内核";

const STARTUP_GUARD_FILE: &str = "auto-connect.guard";
const STARTUP_STABLE_SECS: u64 = 8;
const CRASH_WINDOW_MS: u64 = 60_000;

struct DelayMark {
    delay_ms: Option<u64>,
    failed: bool,
}

impl ProfileBook {
    pub fn open(directory: impl Into<PathBuf>) -> Self {
        let directory = directory.into();
        let path = directory.join("profiles.json");
        let mut book = Self {
            path,
            next_id: 1,
            active_id: None,
            profiles: Vec::new(),
            takeover: Takeover::default(),
            pending_url: None,
            home_failure: None,
            input_error: None,
            mixed_port: None,
            mode: None,
            platform: ClientPlatform::current(),
            engine: Engine::Mihomo,
            engine_runtime: None,
            tun_wanted: false,
            excluded: Vec::new(),
            included: Vec::new(),
            app_mode: takeover::APP_MODE_EXCLUDE.to_string(),
            installed: Vec::new(),
            installed_checked_at: None,
            connected: false,
            our_endpoint: None,
            pending_release: None,
            node_query: String::new(),
            node_sort: BTreeMap::new(),
            delays: BTreeMap::new(),
            auto_now: BTreeMap::new(),
            runtime_catalog: nodes::RuntimeCatalog::default(),
            nodes_error: None,
            kernel_running: false,
            kernel_memory: None,
            kernel_uptime_secs: None,
            connections: Vec::new(),
            connection_total: 0,
            connections_error: None,
            connection_query: String::new(),
            logs: Vec::new(),
            log_filter: "all".to_string(),
            disabled_rules: BTreeSet::new(),
            runtime_base: None,
            chosen_mode: None,
            upload: None,
            download: None,
            totals: None,
            settings: KernelSettings::default(),
            notice: None,
            startup_guard_active: false,
            shutting_down: false,
            crash_recoveries: 0,
            last_crash_ms: None,
            force_launch: false,
        };
        book.load();
        book
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn set_platform(&mut self, platform: ClientPlatform) {
        self.platform = platform;
    }

    pub fn snapshot(&self) -> ProfileSnapshot {
        let profiles = self
            .profiles
            .iter()
            .map(|profile| ProfileView {
                id: profile.id.clone(),
                name: profile.name.clone(),
                kind: profile.kind.as_str().to_string(),
                source: profile.source.clone(),
                user_agent: profile.user_agent.clone(),
                current: self.active_id.as_deref() == Some(profile.id.as_str()),
                failure: profile.failure.clone(),
                override_text: profile.override_text.clone(),
                override_error: profile.override_error.clone(),
                used: profile.usage.as_ref().and_then(|usage| usage.used),
                total: profile.usage.as_ref().and_then(|usage| usage.total),
                expire: profile.usage.as_ref().and_then(|usage| usage.expire),
                last_success_ms: profile.last_success_ms,
                interval_hours: profile.interval_hours,
                updated_ms: profile.updated_ms,
                proxy_count: profile.proxy_count,
                age_recipients: age_key::recipients(&profile.age_key),
            })
            .collect();
        let (node_catalog, nodes_notice, nodes_profile_id) = self.node_views();
        ProfileSnapshot {
            profiles,
            active_id: self.active_id.clone(),
            mixed_port: self.mixed_port,
            mode: self.mode.clone(),
            system_proxy: self.takeover.system_proxy,
            tun: self.takeover.tun,
            vpn: self.takeover.vpn,
            pending_url: self.pending_url.clone(),
            failure: self.home_failure.clone(),
            input_error: self.input_error.clone(),
            connected: self.connected,
            platform: self.platform.as_str().to_string(),
            tun_wanted: self.tun_wanted,
            excluded: self.excluded.clone(),
            included: self.included.clone(),
            app_mode: self.app_mode.clone(),
            installed: self.installed.clone(),
            node_catalog,
            node_query: self.node_query.clone(),
            nodes_notice,
            nodes_error: self.nodes_error.clone(),
            nodes_profile_id,
            kernel_running: self.kernel_running,
            engine: self.engine.as_str().to_string(),
            running_engine: self
                .engine_runtime
                .as_ref()
                .map(|identity| identity.engine.as_str().to_string()),
            engine_version: self
                .engine_runtime
                .as_ref()
                .and_then(|identity| identity.version.clone()),
            engine_identity: self
                .engine_runtime
                .as_ref()
                .and_then(|identity| identity.instance.clone()),
            kernel_memory: self.kernel_memory,
            kernel_uptime_secs: self.kernel_uptime_secs,
            connections: if self.connected {
                diagnostics::filter_connections(&self.connections, &self.connection_query)
            } else {
                Vec::new()
            },
            connection_total: if self.connected { self.connection_total } else { 0 },
            connections_error: if self.connected {
                self.connections_error.clone()
            } else {
                None
            },
            connection_query: self.connection_query.clone(),
            logs: diagnostics::filter_logs(&self.logs, &self.log_filter),
            log_filter: self.log_filter.clone(),
            upload: self.upload,
            download: self.download,
            upload_total: self.totals.map(|item| item.upload),
            download_total: self.totals.map(|item| item.download),
            settings: self.settings.clone(),
            config_values: self.config_values(),
            notice: self.notice.clone(),
        }
    }

    pub fn set_installed(&mut self, apps: Vec<crate::takeover::InstalledApp>) {
        self.installed = apps;
    }

    /// Android home reads installed apps into the snapshot. Desktop has no per-app exclusion.
    pub fn refresh_installed(&mut self, source: &mut dyn takeover::InstalledApps) {
        if self.platform != ClientPlatform::Android {
            self.installed.clear();
            self.installed_checked_at = None;
            return;
        }
        // PackageManager crosses JNI and enumerates every installed app. It must
        // not run on each one-second traffic poll, including after a failed read.
        if self.installed_checked_at.is_some_and(|at| at.elapsed() < Duration::from_secs(60)) {
            return;
        }
        self.installed_checked_at = Some(Instant::now());
        if let Ok(apps) = source.list() {
            self.installed = takeover::normalize_installed(apps);
        }
    }

    pub fn matching_installed(&self, query: &str) -> Vec<&crate::takeover::InstalledApp> {
        takeover::filter_installed(&self.installed, query)
    }

    /// On exit and the next launch, clear a system proxy that still points at our last port.
    pub fn release_lingering_proxy(&mut self, proxy: &mut dyn SystemProxy) {
        let Some(endpoint) = self.our_endpoint.clone() else {
            return;
        };
        match proxy.clear_if_pointing_at(&endpoint) {
            Ok(()) => {
                self.takeover.system_proxy = false;
                self.connected = false;
                self.our_endpoint = None;
                if self.home_failure.as_deref() == Some("系统代理没有关闭") {
                    self.home_failure = None;
                }
                self.persist();
            }
            Err(message) => {
                self.takeover.system_proxy = true;
                self.connected = false;
                self.home_failure = Some(if message.is_empty() {
                    "系统代理没有关闭".to_string()
                } else {
                    message
                });
                self.persist();
            }
        }
    }

    pub fn add_subscription(&mut self, url: &str) -> ProfileSnapshot {
        match validate_subscription_url(url.trim()) {
            Ok(url) => {
                // Trimmed comparison against existing sources: deep links and other
                // entry points cannot silently add a duplicate card (R27).
                if self
                    .profiles
                    .iter()
                    .any(|profile| profile.kind == ProfileKind::Subscription && profile.source.trim() == url)
                {
                    self.input_error = Some(DUPLICATE_ERROR.to_string());
                } else {
                    self.push_profile(
                        ProfileKind::Subscription,
                        subscription_name(&url),
                        url,
                        String::new(),
                    );
                    self.input_error = None;
                    self.persist();
                }
            }
            Err(message) => self.input_error = Some(message),
        }
        self.snapshot()
    }

    pub fn add_local(&mut self, name: &str, content: &str) -> ProfileSnapshot {
        if content.trim().is_empty() {
            self.input_error = Some(CONTENT_ERROR.to_string());
            return self.snapshot();
        }
        let name = clean_name(name, "本地配置");
        self.push_profile(ProfileKind::Local, name, String::new(), content.to_string());
        self.input_error = None;
        self.persist();
        self.snapshot()
    }

    pub fn stage_install_link(&mut self, raw: &str) -> ProfileSnapshot {
        match parse_install_link(raw) {
            Ok(url) => {
                self.pending_url = Some(url);
                self.input_error = None;
            }
            Err(message) => self.input_error = Some(message),
        }
        self.snapshot()
    }

    pub fn confirm_pending(&mut self) -> ProfileSnapshot {
        let Some(url) = self.pending_url.clone() else {
            return self.snapshot();
        };
        let before = self.profiles.len();
        let snapshot = self.add_subscription(&url);
        if self.profiles.len() == before + 1 {
            self.pending_url = None;
            self.input_error = None;
            self.persist();
        }
        if self.pending_url.is_none() {
            return self.snapshot();
        }
        snapshot
    }

    pub fn cancel_pending(&mut self) -> ProfileSnapshot {
        self.pending_url = None;
        self.input_error = None;
        self.snapshot()
    }

    pub fn save_override(&mut self, id: &str, text: &str) -> ProfileSnapshot {
        if let Some(profile) = self.profiles.iter_mut().find(|profile| profile.id == id) {
            profile.override_text = text.to_string();
            // Judge the draft right away so the editor can show why it would not apply.
            profile.override_error = if text.trim().is_empty() || profile.content.trim().is_empty() {
                None
            } else {
                match prepare_named(&profile.content, text, &profile.name) {
                    Err(PrepareError::Override(reason)) => Some(format!("{OVERRIDE_ERROR}：{reason}")),
                    _ => None,
                }
            };
            self.input_error = None;
            self.persist();
        } else {
            self.input_error = Some(MISSING_PROFILE.to_string());
        }
        self.snapshot()
    }

    pub fn enable(
        &mut self,
        id: &str,
        source: &dyn SubscriptionSource,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        // Switching runs the last downloaded copy: it must work offline and stay instant.
        // Only a subscription that was never downloaded has to be fetched first.
        self.activate(id, source, kernel, false)
    }

    pub fn update(
        &mut self,
        id: &str,
        source: &dyn SubscriptionSource,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        self.activate(id, source, kernel, true)
    }

    pub fn connect(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        // A new connection attempt retires the previous home failure and crash counter. Switches do not.
        self.home_failure = None;
        self.crash_recoveries = 0;
        self.last_crash_ms = None;
        if self.platform == ClientPlatform::Android {
            return self.connect_android(kernel, vpn);
        }
        self.connect_desktop(kernel, proxy, tun, vpn)
    }

    pub fn disconnect(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        self.clear_startup_guard();
        self.crash_recoveries = 0;
        self.last_crash_ms = None;
        if self.takeover.tun || self.takeover.vpn {
            if self.platform == ClientPlatform::Android && self.engine == Engine::Rust {
                // The Rust child owns a copy of the VpnService fd through
                // `--tun-fd`; a reload of the same stripped YAML is a no-op, so
                // stop it explicitly before the host closes its descriptor.
                self.stop_android_rust_kernel(kernel);
            } else {
                let _ = self.reload(kernel, false, None);
            }
        }
        let mut model = self.link_model();
        takeover::disconnect(&mut model, proxy, tun, vpn);
        self.apply_model(model);
        self.connections.clear();
        self.publish(kernel)
    }

    fn startup_guard_path(&self) -> PathBuf {
        self.path.with_file_name(STARTUP_GUARD_FILE)
    }

    fn clear_startup_guard(&mut self) {
        self.startup_guard_active = false;
        let _ = fs::remove_file(self.startup_guard_path());
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    pub fn startup_guard_pending(&self) -> bool {
        self.startup_guard_active
    }

    pub fn prepare_exit(&mut self) {
        self.shutting_down = true;
        if self.startup_guard_active {
            self.clear_startup_guard();
        }
    }

    pub fn check_startup_uptime(&mut self, uptime: Option<u64>) {
        if self.startup_guard_active && uptime.is_some_and(|secs| secs >= STARTUP_STABLE_SECS) {
            self.clear_startup_guard();
        }
    }

    fn should_auto_connect(&self) -> bool {
        !self.shutting_down && self.settings.auto_connect && !self.connected && self.active_id.is_some()
    }

    /// Runs at most once on app launch when `settings.auto_connect` is enabled.
    /// A leftover guard file from an earlier aborted startup pauses auto-connect
    /// instead of re-entering a crash loop.
    pub fn auto_connect_on_launch(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) -> Option<ProfileSnapshot> {
        if !self.should_auto_connect() {
            return None;
        }
        let guard = self.startup_guard_path();
        let create_guard = || -> std::io::Result<()> {
            if let Some(parent) = guard.parent().filter(|p| !p.as_os_str().is_empty()) {
                fs::create_dir_all(parent)?;
            }
            fs::File::create_new(&guard)?;
            Ok(())
        };
        if let Err(error) = create_guard() {
            let message = if error.kind() == std::io::ErrorKind::AlreadyExists {
                self.clear_startup_guard();
                "上次自动启动内核时异常退出，本次已暂停自动连接；请检查配置后手动连接".to_string()
            } else {
                format!("无法创建自动启动保护文件，已暂停自动连接：{error}")
            };
            self.release_lingering_proxy(proxy);
            self.home_failure = Some(message);
            self.remember_current_failure();
            self.persist();
            return Some(self.snapshot());
        }
        self.startup_guard_active = true;
        let snapshot = self.connect(kernel, proxy, tun, vpn);
        if !self.connected {
            // A configuration, listener or permission error was handled cleanly; do not
            // mistake the next launch for a native crash.
            self.clear_startup_guard();
        }
        Some(snapshot)
    }

    /// Handles an unexpected kernel process exit observed at runtime: attempts at most
    /// one silent restart for a desktop proxy session, otherwise releases OS traffic
    /// takeover so user networking is never blackholed and surfaces a calm explanation.
    pub fn recover_crashed_kernel(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) -> Option<ProfileSnapshot> {
        if self.shutting_down { return None; }
        let exit_status = kernel.take_exit_detail()?;
        self.append_logs(kernel.pull_logs());
        if !self.connected && !self.takeover.system_proxy && !self.takeover.tun && !self.takeover.vpn {
            return None;
        }
        let now = now_ms();
        if self
            .last_crash_ms
            .is_none_or(|last| now.saturating_sub(last) > CRASH_WINDOW_MS)
        {
            self.crash_recoveries = 0;
        }
        self.last_crash_ms = Some(now);
        let can_silent_restart = self.crash_recoveries == 0
            && !self.startup_guard_active
            && self.platform == ClientPlatform::Desktop
            && !self.takeover.tun;
        if can_silent_restart {
            self.crash_recoveries = 1;
            if self.reload(kernel, false, None).is_ok() && kernel.running() {
                self.kernel_running = true;
                self.reconcile_system_proxy(proxy);
                self.connected = self.takeover.system_proxy || self.takeover.tun;
                self.append_logs(vec![diagnostics::failure_log(&format!(
                    "内核异常退出（{exit_status}），已自动恢复运行"
                ))]);
                return Some(self.publish(kernel));
            }
        }
        let repeated = self.crash_recoveries >= 1;
        self.clear_startup_guard();
        let detail = self
            .logs
            .iter()
            .rev()
            .find(|line| line.level == "error")
            .map(|line| friendly_listen_error(&line.message));
        let base = if repeated {
            format!("内核连续异常退出（{exit_status}），已停止自动重启并关闭系统代理")
        } else {
            format!("内核异常退出（{exit_status}），已自动关闭系统代理以免断网")
        };
        let message = match detail {
            Some(reason) if !reason.is_empty() && !base.contains(&reason) => format!("{base}：{reason}"),
            _ => format!("{base}，请检查配置或查看日志"),
        };
        let mut model = self.link_model();
        takeover::fail_kernel(&mut model, proxy, tun, vpn, message);
        self.apply_model(model);
        self.remember_current_failure();
        Some(self.publish(kernel))
    }

    /// 重启内核 (R35): stops the process and respawns it with the current effective
    /// YAML instead of mihomo's `/restart`. System proxy, TUN / VPN and the outbound
    /// mode come back as they were; a failed respawn releases takeover through
    /// [`takeover::fail_kernel`] like any other failed launch.
    pub fn restart_kernel(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) -> Result<ProfileSnapshot, String> {
        if !self.connected || !kernel.running() {
            return Err(RESTART_NEEDS_CONNECTION.to_string());
        }
        self.home_failure = None;
        self.crash_recoveries = 0;
        self.last_crash_ms = None;
        self.force_launch = true;
        let snapshot = if self.platform == ClientPlatform::Android {
            self.restart_android(kernel, vpn)
        } else {
            self.restart_desktop(kernel, proxy, tun, vpn)
        };
        self.force_launch = false;
        Ok(snapshot)
    }

    fn restart_android(&mut self, kernel: &mut dyn KernelLaunch, vpn: &mut dyn VpnGrant) -> ProfileSnapshot {
        // The respawned kernel needs a live TUN fd, so the VPN is established again.
        // Stop the Rust child first: `establish` replaces the host descriptor, and
        // the old process must not keep polling the one it inherits via `--tun-fd`.
        self.stop_android_rust_kernel(kernel);
        let model = self.link_model();
        match vpn.establish(&model.app_filter()) {
            Ok(fd) => self.finish_android_fd(kernel, vpn, model, fd),
            Err(_) => {
                // Dropping TUN is a plain hot reload; the forced respawn was meant for the new fd.
                self.force_launch = false;
                self.stop_android_rust_kernel(kernel);
                let _ = self.reload(kernel, false, None);
                let _ = vpn.close();
                let mut model = self.link_model();
                model.vpn = false;
                model.connected = false;
                model.failure = Some("VPN 没有建立".to_string());
                self.apply_model(model);
                self.remember_current_failure();
                self.publish(kernel)
            }
        }
    }

    fn restart_desktop(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        let tun_on = self.takeover.tun;
        match self.reload(kernel, tun_on, None) {
            Ok(port) => {
                if self.takeover.system_proxy {
                    let mut model = self.link_model();
                    takeover::set_system_proxy_with_settings(
                        &mut model,
                        true,
                        Some(port),
                        &self.settings.system_proxy,
                        proxy,
                    );
                    self.apply_model(model);
                }
            }
            Err(StartError::Idle(message)) => {
                self.home_failure = Some(message);
                self.connected = false;
                self.remember_current_failure();
            }
            // The config was rejected before the old process was stopped: nothing changed.
            Err(StartError::Failed(message)) if kernel.running() => {
                self.home_failure = Some(message);
                self.remember_current_failure();
            }
            Err(StartError::Failed(message)) => {
                let mut model = self.link_model();
                takeover::fail_kernel(&mut model, proxy, tun, vpn, message);
                self.apply_model(model);
                self.remember_current_failure();
            }
        }
        self.publish(kernel)
    }

    /// Switches the engine that carries traffic.
    ///
    /// The whole operation runs under the caller's profile-session lock, so the
    /// settings UI, tray, connect and restart can never start an engine at the
    /// same time. Order: prepare and validate the target config, release the old
    /// instance's exclusive takeover, start the target, then confirm by the
    /// process identity/listener before committing the selection. A failed
    /// target launch is cleaned up and the previous engine is restored; if that
    /// restore also fails, takeover is released and the reason is surfaced.
    pub fn switch_engine(
        &mut self,
        target: Engine,
        kernel: &mut dyn KernelLaunch,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) -> Result<ProfileSnapshot, String> {
        let previous = self.engine;
        if target == previous {
            if kernel.engine() != target {
                kernel.set_engine(target);
            }
            return Ok(self.publish(kernel));
        }
        let running = kernel.running();
        if !self.connected || self.active_id.is_none() {
            // Nothing to migrate: record the choice for the next connection.
            if running {
                kernel.stop_kernel();
            }
            self.engine = target;
            kernel.set_engine(target);
            self.home_failure = None;
            self.persist();
            return Ok(self.publish(kernel));
        }
        // 1. Prepare the target configuration and have the target binary accept
        //    it before any live session is touched.
        let android = self.platform == ClientPlatform::Android;
        let tun_active = self.takeover.tun || self.takeover.vpn;
        let (yaml, _port) = self
            .kernel_yaml_for(target, tun_active, None)
            .map_err(|error| match error {
                StartError::Idle(message) | StartError::Failed(message) => message,
            })?;
        kernel.set_engine(target);
        if let Err(message) = kernel.validate_config(&yaml) {
            kernel.set_engine(previous);
            return Err(format!(
                "{}内核未接受当前配置，仍使用{}：{message}",
                target.label(),
                previous.label()
            ));
        }
        // 2. Release the old instance's exclusive resources (system proxy, TUN,
        //    VPN fd). A new instance must never inherit another's takeover. An
        //    Android Rust child holds the fd through `--tun-fd`, so stop it
        //    before the host closes the descriptor it inherits.
        self.stop_android_rust_kernel(kernel);
        let mut model = self.link_model();
        takeover::disconnect(&mut model, proxy, tun, vpn);
        self.apply_model(model);
        // 3. Start the target.
        self.engine = target;
        self.home_failure = None;
        self.crash_recoveries = 0;
        if android {
            self.connect_android(kernel, vpn);
        } else {
            self.connect_desktop(kernel, proxy, tun, vpn);
        }
        if self.connected {
            self.persist();
            return Ok(self.publish(kernel));
        }
        // 4. The target failed: stop it, restore the previous engine session.
        let reason = self
            .home_failure
            .clone()
            .unwrap_or_else(|| format!("{}内核没有建立连接", target.label()));
        kernel.set_engine(previous);
        self.engine = previous;
        self.home_failure = None;
        if android {
            self.connect_android(kernel, vpn);
        } else {
            self.connect_desktop(kernel, proxy, tun, vpn);
        }
        let message = if self.connected {
            format!(
                "切换到{}内核失败（{reason}），已恢复{}内核连接",
                target.label(),
                previous.label()
            )
        } else {
            format!(
                "切换到{}内核失败（{reason}），且未能恢复{}内核连接，已断开系统接管",
                target.label(),
                previous.label()
            )
        };
        if self.connected {
            self.home_failure = Some(message.clone());
        } else {
            let mut model = self.link_model();
            takeover::fail_kernel(&mut model, proxy, tun, vpn, message.clone());
            self.apply_model(model);
        }
        self.remember_current_failure();
        Err(message)
    }

    pub fn engine(&self) -> Engine {
        self.engine
    }

    pub fn set_system_proxy(
        &mut self,
        enabled: bool,
        kernel: &mut dyn KernelLaunch,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        if self.platform != ClientPlatform::Desktop {
            return self.snapshot();
        }
        if !enabled {
            let mut model = self.link_model();
            takeover::set_system_proxy_with_settings(
                &mut model,
                false,
                None,
                &self.settings.system_proxy,
                proxy,
            );
            self.apply_model(model);
            return self.publish(kernel);
        }
        let previous = self.takeover.system_proxy;
        let tun_enable = if self.tun_wanted {
            match tun.authorize() {
                Ok(true) => true,
                _ => {
                    let _ = self.reload(kernel, false, None);
                    let mut model = self.link_model();
                    model.tun = false;
                    model.system_proxy = previous;
                    model.connected = false;
                    model.failure = Some(takeover::TUN_DENIED.to_string());
                    self.apply_model(model);
                    self.remember_current_failure();
                    return self.publish(kernel);
                }
            }
        } else {
            false
        };
        match self.reload(kernel, tun_enable, None) {
            Ok(port) => {
                let mut model = self.link_model();
                takeover::set_system_proxy_with_settings(
                    &mut model,
                    true,
                    Some(port),
                    &self.settings.system_proxy,
                    proxy,
                );
                if tun_enable {
                    model.tun = true;
                }
                model.connected = model.system_proxy || model.tun;
                self.apply_model(model);
            }
            Err(StartError::Idle(message)) => {
                self.home_failure = Some(message);
                self.connected = false;
                self.remember_current_failure();
            }
            Err(StartError::Failed(message)) if message.starts_with(takeover::TUN_AUTHORIZATION_FAILED) => {
                self.home_failure = Some(message);
                self.remember_current_failure();
            }
            Err(StartError::Failed(message)) => {
                let mut model = self.link_model();
                takeover::fail_kernel(&mut model, proxy, tun, vpn, message);
                self.apply_model(model);
                self.remember_current_failure();
            }
        }
        self.publish(kernel)
    }

    pub fn set_tun(
        &mut self,
        enabled: bool,
        kernel: &mut dyn KernelLaunch,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        if self.platform != ClientPlatform::Desktop {
            return self.snapshot();
        }
        if !enabled {
            let _ = self.reload(kernel, false, None);
            let mut model = self.link_model();
            takeover::set_tun(&mut model, false, tun);
            self.apply_model(model);
            return self.publish(kernel);
        }
        let grant = tun.authorize();
        if !matches!(grant, Ok(true)) {
            self.home_failure = Some(grant.err().unwrap_or_else(|| takeover::TUN_DENIED.to_string()));
            self.remember_current_failure();
            return self.publish(kernel);
        }
        match self.reload(kernel, true, None) {
            Ok(_) => {
                let _ = tun.set_enabled(true);
                let mut model = self.link_model();
                model.tun = true;
                model.tun_wanted = true;
                model.connected = true;
                self.apply_model(model);
            }
            Err(StartError::Idle(message)) => {
                self.home_failure = Some(message);
                self.connected = false;
                self.remember_current_failure();
            }
            Err(StartError::Failed(message)) if message.starts_with(takeover::TUN_AUTHORIZATION_FAILED) => {
                self.home_failure = Some(message);
                self.remember_current_failure();
            }
            Err(StartError::Failed(message)) => {
                let mut model = self.link_model();
                takeover::fail_kernel(&mut model, proxy, tun, vpn, message);
                self.apply_model(model);
                self.remember_current_failure();
            }
        }
        self.publish(kernel)
    }

    fn connect_desktop(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        let previous = self.takeover.system_proxy;
        let tun_enable = if self.tun_wanted {
            match tun.authorize() {
                Ok(true) => true,
                _ => {
                    let _ = self.reload(kernel, false, None);
                    let _ = tun.set_enabled(false);
                    let mut model = self.link_model();
                    model.tun = false;
                    model.system_proxy = previous;
                    model.connected = false;
                    model.failure = Some(takeover::TUN_DENIED.to_string());
                    self.apply_model(model);
                    self.remember_current_failure();
                    return self.publish(kernel);
                }
            }
        } else {
            false
        };
        match self.reload(kernel, tun_enable, None) {
            Ok(port) => {
                let _ = tun.set_enabled(tun_enable);
                let mut model = self.link_model();
                takeover::set_system_proxy_with_settings(
                    &mut model,
                    true,
                    Some(port),
                    &self.settings.system_proxy,
                    proxy,
                );
                model.tun = tun_enable;
                model.connected = model.system_proxy || model.tun;
                let _ = vpn.close();
                model.vpn = false;
                self.apply_model(model);
            }
            Err(StartError::Idle(message)) => {
                self.home_failure = Some(message);
                self.connected = false;
                self.remember_current_failure();
            }
            Err(StartError::Failed(message)) if message.starts_with(takeover::TUN_AUTHORIZATION_FAILED) => {
                self.home_failure = Some(message);
                self.remember_current_failure();
            }
            Err(StartError::Failed(message)) => {
                let mut model = self.link_model();
                takeover::fail_kernel(&mut model, proxy, tun, vpn, message);
                self.apply_model(model);
                self.remember_current_failure();
            }
        }
        self.publish(kernel)
    }

    fn connect_android(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        if self.active_id.is_none() {
            self.home_failure = Some(takeover::NO_PROFILE.to_string());
            self.connected = false;
            self.remember_current_failure();
            return self.publish(kernel);
        }
        if !matches!(vpn.authorize(), Ok(true)) {
            // Same order as every other branch: no Rust child may outlive the
            // descriptor the host is about to close.
            self.stop_android_rust_kernel(kernel);
            let _ = vpn.close();
            let mut model = self.link_model();
            model.vpn = false;
            model.connected = false;
            model.system_proxy = false;
            model.tun = false;
            model.failure = Some(takeover::VPN_DENIED.to_string());
            self.apply_model(model);
            self.remember_current_failure();
            return self.publish(kernel);
        }
        // `establish` replaces the host descriptor (Kotlin closes the previous
        // ParcelFileDescriptor), so stop an Android Rust child before its
        // inherited copy loses the peer.
        self.stop_android_rust_kernel(kernel);
        let fd = match vpn.establish(&self.link_model().app_filter()) {
            Ok(fd) => fd,
            Err(_) => {
                // A re-connect replaces the host descriptor first; keep no Rust
                // child polling the inherited copy of the old one.
                self.stop_android_rust_kernel(kernel);
                let _ = vpn.close();
                let mut model = self.link_model();
                model.vpn = false;
                model.connected = false;
                model.failure = Some("VPN 没有建立".to_string());
                self.apply_model(model);
                self.remember_current_failure();
                return self.publish(kernel);
            }
        };
        let model = self.link_model();
        self.finish_android_fd(kernel, vpn, model, fd)
    }

    pub fn exclude_package(
        &mut self,
        package_name: &str,
        kernel: &mut dyn KernelLaunch,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        self.change_exclusion(package_name, true, kernel, vpn)
    }

    pub fn include_package(
        &mut self,
        package_name: &str,
        kernel: &mut dyn KernelLaunch,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        self.change_exclusion(package_name, false, kernel, vpn)
    }

    /// Replace one mode's app list and make it current (Android access control).
    pub fn set_app_rules(
        &mut self,
        mode: &str,
        packages: &[String],
        kernel: &mut dyn KernelLaunch,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        let mut model = self.link_model();
        // Stopping the Rust child must happen only when the fd is actually
        // replaced; see `takeover::set_app_rules`. Stopping earlier kills the
        // kernel even when the effective filter is unchanged and nothing is
        // re-established, leaving the host PFD open with nobody reading it.
        let fd = {
            let mut before_replace = || self.stop_android_rust_kernel(kernel);
            takeover::set_app_rules(&mut model, mode, packages, vpn, &mut before_replace)
        };
        if let Some(fd) = fd {
            return self.finish_android_fd(kernel, vpn, model, fd);
        }
        self.apply_model(model);
        self.persist();
        self.snapshot()
    }

    fn change_exclusion(
        &mut self,
        package_name: &str,
        exclude: bool,
        kernel: &mut dyn KernelLaunch,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        let mut model = self.link_model();
        // `refresh_vpn` replaces the descriptor; the stop is deferred to that
        // decision point so a no-op change cannot kill the running child.
        let fd = {
            let mut before_replace = || self.stop_android_rust_kernel(kernel);
            if exclude {
                takeover::exclude_package(&mut model, package_name, vpn, &mut before_replace)
            } else {
                takeover::include_package(&mut model, package_name, vpn, &mut before_replace)
            }
        };
        if let Some(fd) = fd {
            return self.finish_android_fd(kernel, vpn, model, fd);
        }
        self.apply_model(model);
        self.snapshot()
    }

    fn finish_android_fd(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        vpn: &mut dyn VpnGrant,
        mut model: takeover::LinkModel,
        fd: i32,
    ) -> ProfileSnapshot {
        match self.reload(kernel, true, Some(fd)) {
            Ok(_) => {
                model.vpn = true;
                model.connected = true;
                model.system_proxy = false;
                model.tun = false;
                // connect() already retires the home failure. Package changes do not.
                self.apply_model(model);
            }
            Err(StartError::Failed(message)) | Err(StartError::Idle(message)) => {
                // The launch may have failed before `stop()` ran (config or
                // staging error); no Rust child may outlive the fd.
                self.stop_android_rust_kernel(kernel);
                let _ = vpn.close();
                model.vpn = false;
                model.connected = false;
                model.system_proxy = false;
                model.tun = false;
                model.failure = Some(message);
                self.apply_model(model);
                self.remember_current_failure();
            }
        }
        self.publish(kernel)
    }

    fn activate(
        &mut self,
        id: &str,
        source: &dyn SubscriptionSource,
        kernel: &mut dyn KernelLaunch,
        refresh: bool,
    ) -> ProfileSnapshot {
        let Some(index) = self.profiles.iter().position(|profile| profile.id == id) else {
            self.home_failure = Some(MISSING_PROFILE.to_string());
            return self.snapshot();
        };
        let needs_fetch = self.profiles[index].kind == ProfileKind::Subscription
            && (refresh || self.profiles[index].content.trim().is_empty());
        let fetched = if needs_fetch {
            self.profiles[index].refresh_revision += 1;
            match source.fetch_with_user_agent(&self.profiles[index].source, self.subscription_user_agent(index))
                .map_err(|_| FETCH_ERROR.to_string())
                .and_then(|fetched| fetched.into_profile(&self.profiles[index].age_key))
            {
                Ok(profile) => Some(profile),
                Err(message) => {
                    self.fail_activation(index, message);
                    return self.publish(kernel);
                }
            }
        } else {
            None
        };
        let content = fetched
            .as_ref()
            .map(|item| item.content.as_str())
            .unwrap_or(self.profiles[index].content.as_str());
        let override_text = self.profiles[index].override_text.clone();
        let prepared = match prepare_named(content, &override_text, &self.profiles[index].name) {
            Ok(prepared) => prepared,
            Err(PrepareError::Content) => {
                self.fail_activation(index, CONTENT_ERROR.to_string());
                return self.publish(kernel);
            }
            Err(PrepareError::Override(reason)) => {
                // Judged before the running config changes, so takeover and the active id stay.
                self.profiles[index].override_error = Some(format!("{OVERRIDE_ERROR}：{reason}"));
                self.persist();
                return self.snapshot();
            }
        };
        let selected = self.profiles[index].selected.clone();
        let desktop = self.platform == ClientPlatform::Desktop;
        let (settled, settled_port) = match apply_settings(&prepared.yaml, &self.settings, desktop)
            .and_then(|(yaml, port)| {
                // Subscription TUN settings must not replace the authorized session.
                // In particular, an omitted enable flag disables Mihomo's TUN on reload.
                // The native kernel never serves a `tun` block: the desktop route
                // is the launcher's and Android passes the VpnService fd as argv.
                if desktop && self.engine == Engine::Rust {
                    strip_tun(&yaml).map(|yaml| (yaml, port))
                } else if desktop {
                    force_tun(&yaml, self.takeover.tun, None).map(|yaml| (yaml, port))
                } else {
                    Ok((yaml, port))
                }
            })
            .and_then(|(yaml, port)| ensure_tun_dns(&yaml, &self.settings).map(|yaml| (yaml, port)))
        {
            Ok(result) => result,
            Err(message) => {
                self.fail_activation(index, message);
                return self.publish(kernel);
            }
        };
        let yaml = self.finish_yaml(&settled, &selected);
        self.runtime_catalog = nodes::RuntimeCatalog::default();
        self.auto_now.clear();
        kernel.set_engine(self.engine);
        if let Err(message) = kernel.start_or_reload(&yaml) {
            let message = if message.is_empty() {
                KERNEL_ERROR.to_string()
            } else {
                message
            };
            if message.starts_with(takeover::TUN_AUTHORIZATION_FAILED) {
                self.profiles[index].failure = Some(message.clone());
                self.home_failure = Some(message);
                self.remember_current_failure();
            } else {
                self.fail_activation(index, message);
            }
            return self.publish(kernel);
        }
        self.runtime_base = Some(yaml);
        self.disabled_rules.clear();
        let now = now_ms();
        {
            let profile = &mut self.profiles[index];
            if let Some(fetched) = fetched {
                profile.node_metadata.take();
                profile.content = fetched.content;
                profile.usage = fetched.usage;
                profile.updated_ms = Some(now);
                profile.proxy_count = fetched.proxy_count;
            }
            if profile.applied_override != profile.override_text {
                profile.node_metadata.take();
                profile.applied_override.clone_from(&profile.override_text);
            }
            profile.override_error = None;
            profile.failure = None;
            profile.last_success_ms = Some(now);
            self.active_id = Some(profile.id.clone());
        }
        self.mixed_port = settled_port.or(prepared.mixed_port);
        self.mode = prepared.mode.clone();
        self.chosen_mode = prepared.mode;
        self.home_failure = None;
        self.input_error = None;
        self.apply_live_selections(kernel);
        self.persist();
        self.publish(kernel)
    }

    fn fail_activation(&mut self, index: usize, message: String) {
        self.profiles[index].failure = Some(message.clone());
        self.home_failure = Some(message);
        let endpoint = self.our_endpoint.clone();
        self.pending_release = Some(PlatformRelease {
            endpoint: endpoint.clone(),
            close_tun: self.takeover.tun,
            close_vpn: self.takeover.vpn,
        });
        self.takeover.tun = false;
        self.takeover.vpn = false;
        self.connected = false;
        if endpoint.is_none() {
            self.takeover.system_proxy = false;
        }
        self.persist();
        self.remember_current_failure();
    }

    fn publish(&mut self, kernel: &mut dyn KernelLaunch) -> ProfileSnapshot {
        self.sync_runtime(kernel);
        self.snapshot()
    }

    pub fn report_failure(&mut self, message: String) -> ProfileSnapshot {
        self.home_failure = Some(message);
        self.remember_current_failure();
        self.snapshot()
    }

    fn remember_current_failure(&mut self) {
        let Some(message) = self.home_failure.clone() else {
            return;
        };
        if !self.connected { self.connections.clear(); }
        self.append_logs(vec![diagnostics::failure_log(&message)]);
    }

    fn append_logs(&mut self, lines: Vec<LogView>) {
        diagnostics::push_logs(&mut self.logs, lines);
    }

    /// Runs a deferred proxy clear. The flag and port are dropped only when the clear succeeds.
    pub fn apply_release(
        &mut self,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) {
        let Some(release) = self.pending_release.take() else {
            return;
        };
        let cleared = takeover::release_platform(proxy, tun, vpn, &release);
        if cleared {
            self.takeover.system_proxy = false;
            self.our_endpoint = None;
        } else if release.endpoint.is_some() {
            self.our_endpoint = release.endpoint;
            self.takeover.system_proxy = true;
        }
        self.persist();
    }

    /// A profile reload can change the listener port while system proxy stays on.
    /// Follow the successfully loaded config, never an unapplied settings preview.
    pub fn reconcile_system_proxy(&mut self, proxy: &mut dyn SystemProxy) {
        if self.platform != ClientPlatform::Desktop || !self.kernel_running || !self.takeover.system_proxy {
            return;
        }
        let port = self.runtime_base.as_deref()
            .and_then(|yaml| serde_yaml::from_str::<Value>(yaml).ok())
            .and_then(|value| read_i64(&value, "mixed-port"))
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port > 0);
        let Some(port) = port else { return; };
        let endpoint = ProxyEndpoint { host: self.settings.system_proxy.effective_host(), port };
        if self.our_endpoint.as_ref() == Some(&endpoint) { return; }
        let mut model = self.link_model();
        takeover::set_system_proxy_with_settings(&mut model, true, Some(port), &self.settings.system_proxy, proxy);
        self.apply_model(model);
    }

    /// Stops an Android Rust kernel that inherited the VpnService TUN fd via
    /// `--tun-fd` before the host closes its own `ParcelFileDescriptor`.
    ///
    /// The Rust config never carries the fd (its `tun` block is stripped for
    /// every platform), so unloading TUN is not a YAML change: reloading the
    /// same bytes is a no-op and the child would keep polling a descriptor the
    /// host released. Mihomo keeps `tun.file-descriptor` semantics and desktop
    /// has no fd argument, so both stay on their existing reload path.
    fn stop_android_rust_kernel(&self, kernel: &mut dyn KernelLaunch) {
        if self.platform == ClientPlatform::Android && self.engine == Engine::Rust {
            // Never hand this fd to the next launch either. Clearing it must not
            // depend on `running()`: a child that already exited still leaves a
            // stale fd number behind for the next spawn to inherit.
            kernel.set_tun_fd(None);
            if kernel.running() {
                kernel.stop_kernel();
            }
        }
    }

    fn reload(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        tun_enable: bool,
        fd: Option<i32>,
    ) -> Result<u16, StartError> {
        let mut force = std::mem::take(&mut self.force_launch);
        let (base, port) = self.kernel_yaml(tun_enable, fd)?;
        let filtered;
        let yaml = if self.disabled_rules.is_empty() {
            &base
        } else {
            filtered = diagnostics::filter_disabled_rules(&base, &self.disabled_rules)
                .map_err(StartError::Failed)?;
            &filtered
        };
        self.runtime_catalog = nodes::RuntimeCatalog::default();
        self.auto_now.clear();
        kernel.set_engine(self.engine);
        // Only the Android Rust launch takes the VpnService fd as an argument.
        // Every other path clears it so a restarted process never inherits a
        // descriptor the host is about to close.
        let android_fd = match (self.platform, self.engine, fd) {
            (ClientPlatform::Android, Engine::Rust, Some(fd)) => Some(fd),
            _ => None,
        };
        kernel.set_tun_fd(android_fd);
        // A fresh VpnService descriptor means the previous TUN session ended.
        // Even if the host reuses the fd number and the YAML text is
        // identical, the Rust process must be respawned to inherit the new fd.
        if android_fd.is_some() {
            force = true;
        }
        kernel.start_or_reload_with(yaml, force).map_err(|message| {
            StartError::Failed(if message.is_empty() {
                KERNEL_ERROR.to_string()
            } else {
                message
            })
        })?;
        if self.home_failure.as_deref().is_some_and(|message| message.starts_with(takeover::TUN_AUTHORIZATION_FAILED)) {
            self.home_failure = None;
        }
        self.runtime_base = Some(base);
        self.mixed_port = Some(i64::from(port));
        self.apply_live_selections(kernel);
        Ok(port)
    }

    /// The YAML the kernel runs (or would run) for the active profile: content,
    /// applied override, kernel settings, TUN, mode and controller, in launch order.
    /// While a kernel config is loaded this is exactly that YAML (with rules
    /// disabled at runtime removed); otherwise it previews the next launch.
    pub fn effective_config(&self) -> Result<String, String> {
        if let Some(base) = &self.runtime_base {
            if self.disabled_rules.is_empty() {
                return Ok(base.clone());
            }
            return diagnostics::filter_disabled_rules(base, &self.disabled_rules);
        }
        self.kernel_yaml(self.takeover.tun, None)
            .map(|(yaml, _)| yaml)
            .map_err(|error| match error {
                StartError::Idle(message) | StartError::Failed(message) => message,
            })
    }

    /// Structured summary of [`Self::effective_config`], with the profile and its 覆写
    /// alongside so the UI can tell where each value comes from.
    pub fn config_overview(&self) -> Result<ConfigOverview, String> {
        let effective_yaml = self.effective_config()?;
        let effective: Value = serde_yaml::from_str(&effective_yaml).map_err(|_| CONTENT_ERROR.to_string())?;
        let profile = self
            .active_id
            .as_ref()
            .and_then(|id| self.profiles.iter().find(|profile| &profile.id == id))
            .ok_or_else(|| takeover::NO_PROFILE.to_string())?;
        let raw = parse_config(&profile.content).unwrap_or(Value::Null);
        let prepared = prepare(&profile.content, &profile.applied_override)
            .ok()
            .and_then(|prepared| serde_yaml::from_str::<Value>(&prepared.yaml).ok())
            .unwrap_or_else(|| raw.clone());
        let (counts, group_types) = overview_counts(&effective);
        Ok(ConfigOverview {
            effective: overview_options(&effective),
            prepared: overview_options(&prepared),
            profile: overview_options(&raw),
            counts,
            group_types,
            running: self.runtime_base.is_some(),
        })
    }

    fn kernel_yaml(&self, tun_enable: bool, fd: Option<i32>) -> Result<(String, u16), StartError> {
        self.kernel_yaml_for(self.engine, tun_enable, fd)
    }

    /// Same as [`Self::kernel_yaml`] but for a prospective engine, so a switch can
    /// validate the target configuration before releasing the live session.
    fn kernel_yaml_for(&self, engine: Engine, tun_enable: bool, fd: Option<i32>) -> Result<(String, u16), StartError> {
        let Some(active) = self.active_id.clone() else {
            return Err(StartError::Idle(takeover::NO_PROFILE.to_string()));
        };
        let Some(profile) = self.profiles.iter().find(|profile| profile.id == active) else {
            return Err(StartError::Idle(takeover::NO_PROFILE.to_string()));
        };
        let prepared = match prepare_named(&profile.content, &profile.applied_override, &profile.name) {
            Ok(prepared) => prepared,
            Err(PrepareError::Override(reason)) => return Err(StartError::Failed(format!("{OVERRIDE_ERROR}：{reason}"))),
            Err(PrepareError::Content) => return Err(StartError::Failed(CONTENT_ERROR.to_string())),
        };
        let (settled, settled_port) =
            apply_settings(&prepared.yaml, &self.settings, self.platform == ClientPlatform::Desktop)
                .map_err(StartError::Failed)?;
        let prepared = Prepared {
            mixed_port: settled_port.or(prepared.mixed_port),
            mode: prepared.mode,
            yaml: settled,
        };
        let Some(port) = prepared
            .mixed_port
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| *value > 0)
        else {
            return Err(StartError::Failed("没有本地端口".to_string()));
        };
        let selected = profile.selected.clone();
        // TUN is a Mihomo launch parameter. The concrete route belongs to the
        // launcher: desktop TUN for Mihomo, the iOS Packet Tunnel or the
        // Android VpnService fd for the native kernel. The Rust engine never
        // reads `tun` from YAML (an enabled block is rejected by name), and on
        // Android its fd travels as `--tun-fd`, so the block is always
        // stripped for that engine — including a user-written one.
        let yaml = if engine == Engine::Rust {
            strip_tun(&prepared.yaml).map_err(StartError::Failed)?
        } else {
            force_tun(&prepared.yaml, tun_enable, fd).map_err(StartError::Failed)?
        };
        let yaml = ensure_tun_dns(&yaml, &self.settings).map_err(StartError::Failed)?;
        let yaml = match self.mode.as_deref().and_then(normalize_outbound) {
            Some(mode) => force_mode(&yaml, mode).map_err(StartError::Failed)?,
            None => yaml,
        };
        let yaml = self.finish_yaml_for(engine, &yaml, &selected);
        Ok((yaml, port))
    }

    /// Adds only the launch-time keys the selected engine actually serves.
    /// `external-controller` is Billow's own control adapter for Mihomo; the
    /// native kernel has no controller yet and rejects unknown keys, so it must
    /// receive the user's configuration unchanged (T5 owns its control layer).
    fn finish_yaml(&self, yaml: &str, selected: &BTreeMap<String, String>) -> String {
        self.finish_yaml_for(self.engine, yaml, selected)
    }

    fn finish_yaml_for(&self, engine: Engine, yaml: &str, selected: &BTreeMap<String, String>) -> String {
        let prioritized = nodes::prioritize_selections(yaml, selected);
        match engine {
            Engine::Mihomo => nodes::ensure_controller(&prioritized),
            Engine::Rust => prioritized,
        }
    }

    fn link_model(&self) -> takeover::LinkModel {
        takeover::LinkModel {
            platform: self.platform,
            tun_wanted: self.tun_wanted,
            excluded: self.excluded.clone(),
            included: self.included.clone(),
            app_mode: self.app_mode.clone(),
            system_proxy: self.takeover.system_proxy,
            tun: self.takeover.tun,
            vpn: self.takeover.vpn,
            connected: self.connected,
            failure: self.home_failure.clone(),
            endpoint: self.our_endpoint.clone(),
        }
    }

    fn apply_model(&mut self, model: takeover::LinkModel) {
        self.platform = model.platform;
        self.tun_wanted = model.tun_wanted;
        self.excluded = model.excluded;
        self.included = model.included;
        self.app_mode = model.app_mode;
        self.takeover.system_proxy = model.system_proxy;
        self.takeover.tun = model.tun;
        self.takeover.vpn = model.vpn;
        self.connected = model.connected;
        self.home_failure = model.failure;
        self.our_endpoint = model.endpoint;
        self.pending_release = None;
        self.persist();
    }

    fn push_profile(&mut self, kind: ProfileKind, name: String, source: String, content: String) {
        let id = format!("p{}", self.next_id);
        self.next_id += 1;
        self.profiles.push(Profile {
            id,
            name,
            kind,
            source,
            user_agent: String::new(),
            content,
            override_text: String::new(),
            applied_override: String::new(),
            override_error: None,
            failure: None,
            last_success_ms: None,
            usage: None,
            selected: BTreeMap::new(),
            fixed: BTreeMap::new(),
            interval_hours: 0,
            age_key: String::new(),
            updated_ms: None,
            proxy_count: 0,
            refresh_revision: 0,
            node_metadata: OnceLock::new(),
        });
        if let Some(profile) = self.profiles.last_mut() {
            profile.proxy_count = count_proxies(&profile.content);
            if profile.kind == ProfileKind::Local {
                profile.updated_ms = Some(now_ms());
            }
        }
    }

    fn load(&mut self) {
        let Ok(text) = fs::read_to_string(&self.path) else {
            return;
        };
        let Ok(disk) = serde_json::from_str::<DiskState>(&text) else {
            return;
        };
        self.next_id = disk.next_id.max(1);
        self.home_failure = disk.home_failure;
        self.profiles = disk
            .profiles
            .into_iter()
            .filter(|profile| !profile.id.is_empty())
            .map(|profile| {
                let usage = usage_from_parts(profile.used, profile.total, profile.expire);
                let proxy_count = profile.proxy_count.unwrap_or_else(|| count_proxies(&profile.content));
                Profile {
                    id: profile.id,
                    name: profile.name,
                    kind: profile.kind,
                    source: profile.source,
                    user_agent: normalize_subscription_user_agent(&profile.user_agent).unwrap_or_default(),
                    content: profile.content.into_owned(),
                    override_text: profile.override_text.into_owned(),
                    applied_override: profile.applied_override.into_owned(),
                    override_error: profile.override_error,
                    failure: profile.failure,
                    last_success_ms: profile.last_success_ms,
                    usage,
                    proxy_count,
                    refresh_revision: 0,
                    node_metadata: OnceLock::new(),
                    selected: profile.selected,
                    fixed: profile.fixed,
                    interval_hours: profile.interval_hours,
                    age_key: profile.age_key,
                    updated_ms: profile.updated_ms,
                }
            })
            .collect();
        self.settings = disk.settings;
        self.engine = disk.engine;
        nodes::set_probe(&self.settings.test_url, self.settings.test_timeout_ms_or_default());
        let known = self
            .profiles
            .iter()
            .any(|profile| disk.active_id.as_deref() == Some(profile.id.as_str()));
        self.active_id = if known { disk.active_id } else { None };
        self.tun_wanted = disk.tun_wanted;
        self.excluded = disk
            .excluded_packages
            .into_iter()
            .map(|package| package.trim().to_string())
            .filter(|package| !package.is_empty())
            .collect();
        self.included = takeover::clean_packages(&disk.included_packages);
        self.app_mode = takeover::normalize_app_mode(&disk.app_mode).to_string();
        self.our_endpoint = match (disk.proxy_host, disk.proxy_port) {
            (Some(host), Some(port)) if !host.is_empty() && port > 0 => {
                Some(ProxyEndpoint { host, port })
            }
            _ => None,
        };
        self.next_id = self.next_id.max(
            self.profiles
                .iter()
                .filter_map(|profile| profile.id.strip_prefix('p')?.parse::<u64>().ok())
                .max()
                .unwrap_or(0)
                + 1,
        );
        self.chosen_mode = disk
            .chosen_mode
            .and_then(|mode| normalize_outbound(&mode).map(|mode| mode.to_string()));
        self.recompute_effective();
        if let Some(mode) = self.chosen_mode.clone() {
            self.mode = Some(mode);
        }
        if let Some(message) = self.home_failure.clone() {
            self.append_logs(vec![diagnostics::failure_log(&message)]);
        }
    }

    fn recompute_effective(&mut self) {
        self.mixed_port = None;
        self.mode = None;
        let Some(active) = self.active_id.as_deref() else {
            return;
        };
        let Some(profile) = self.profiles.iter().find(|profile| profile.id == active) else {
            return;
        };
        if let Ok(prepared) = prepare(&profile.content, &profile.applied_override) {
            let configured = apply_settings(&prepared.yaml, &self.settings, self.platform == ClientPlatform::Desktop)
                .ok().and_then(|(_, port)| port);
            // Proxy-only edits must not replace the live port with the subscription's
            // original value. A successful reload publishes its new port separately.
            let running = self.runtime_base.as_deref().filter(|_| self.kernel_running)
                .and_then(|yaml| serde_yaml::from_str::<Value>(yaml).ok())
                .and_then(|value| read_i64(&value, "mixed-port"));
            self.mixed_port = running.or(configured);
            self.mode = self.chosen_mode.clone().or(prepared.mode);
        }
    }

    fn persist(&self) {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
            && fs::create_dir_all(parent).is_err()
        {
            return;
        }
        let disk = DiskState {
            next_id: self.next_id,
            active_id: self.active_id.clone(),
            home_failure: self.home_failure.clone(),
            tun_wanted: self.tun_wanted,
            excluded_packages: self.excluded.clone(),
            included_packages: self.included.clone(),
            app_mode: self.app_mode.clone(),
            proxy_host: self
                .our_endpoint
                .as_ref()
                .map(|endpoint| endpoint.host.clone()),
            proxy_port: self.our_endpoint.as_ref().map(|endpoint| endpoint.port),
            chosen_mode: self.chosen_mode.clone(),
            settings: self.settings.clone(),
            engine: self.engine,
            profiles: self
                .profiles
                .iter()
                .map(|profile| DiskProfile {
                    id: profile.id.clone(),
                    name: profile.name.clone(),
                    kind: profile.kind,
                    source: profile.source.clone(),
                    user_agent: profile.user_agent.clone(),
                    content: Cow::Borrowed(&profile.content),
                    proxy_count: Some(profile.proxy_count),
                    override_text: Cow::Borrowed(&profile.override_text),
                    applied_override: Cow::Borrowed(&profile.applied_override),
                    override_error: profile.override_error.clone(),
                    failure: profile.failure.clone(),
                    last_success_ms: profile.last_success_ms,
                    used: profile.usage.as_ref().and_then(|usage| usage.used),
                    total: profile.usage.as_ref().and_then(|usage| usage.total),
                    expire: profile.usage.as_ref().and_then(|usage| usage.expire),
                    selected: profile.selected.clone(),
                    fixed: profile.fixed.clone(),
                    interval_hours: profile.interval_hours,
                    age_key: profile.age_key.clone(),
                    updated_ms: profile.updated_ms,
                })
                .collect(),
        };
        let temporary = self.path.with_extension("json.tmp");
        let write = || -> std::io::Result<()> {
            let mut writer = BufWriter::new(fs::File::create(&temporary)?);
            serde_json::to_writer_pretty(&mut writer, &disk)?;
            writer.flush()
        };
        if write().and_then(|()| fs::rename(&temporary, &self.path)).is_err() {
            let _ = fs::remove_file(&temporary);
        }
    }

    pub fn sync_runtime(&mut self, kernel: &mut dyn KernelLaunch) {
        let running = kernel.running();
        self.kernel_running = running;
        self.append_logs(kernel.pull_logs());
        self.engine_runtime = if running { kernel.identity() } else { None };
        if running {
            self.runtime_catalog = kernel.node_catalog();
            self.auto_now = self.runtime_catalog.now.clone();
            self.kernel_memory = kernel.kernel_memory();
            self.kernel_uptime_secs = kernel.kernel_uptime_secs();
            self.check_startup_uptime(self.kernel_uptime_secs);
            if self.kernel_uptime_secs.is_some_and(|secs| secs >= 60) {
                self.crash_recoveries = 0;
            }
            if self.connected {
                self.connections = diagnostics::accept_connections(kernel.connections());
                if let Some(totals) = kernel.connection_totals() {
                    self.totals = Some(totals);
                }
                self.connection_total = kernel
                    .connection_total()
                    .unwrap_or(self.connections.len());
                self.connections_error = kernel.connections_error();
            } else {
                self.connections.clear();
                self.connection_total = 0;
                self.connections_error = None;
            }
        } else {
            self.auto_now.clear();
            self.runtime_catalog = nodes::RuntimeCatalog::default();
            self.connections.clear();
            self.kernel_memory = None;
            self.kernel_uptime_secs = None;
            self.connection_total = 0;
            self.connections_error = None;
            self.runtime_base = None;
            // A stopped kernel is not connected. The system-proxy switch may stay on.
            self.connected = false;
        }
        if self.connected {
            // None is not a zero reading. A later sample still replaces the last one.
            if let Some((upload, download)) = kernel.traffic() {
                self.upload = Some(upload);
                self.download = Some(download);
            }
        } else {
            self.upload = None;
            self.download = None;
            self.totals = None;
        }
    }

    pub fn set_outbound_mode(
        &mut self,
        mode: &str,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        let Some(next) = normalize_outbound(mode) else {
            self.home_failure = Some("模式没有切换".to_string());
            self.remember_current_failure();
            return self.snapshot();
        };
        if self.active_id.is_none() {
            self.home_failure = Some("没有生效配置".to_string());
            self.remember_current_failure();
            return self.snapshot();
        }
        let runtime_base = match self.runtime_base.as_deref().map(|base| force_mode(base, next)).transpose() {
            Ok(base) => base,
            Err(message) => return self.report_failure(message),
        };
        if kernel.running() {
            if let Err(message) = kernel.set_mode(next) {
                self.home_failure = Some(if message.is_empty() {
                    "模式没有切换".to_string()
                } else {
                    message
                });
                self.remember_current_failure();
                return self.publish(kernel);
            }
        }
        self.runtime_base = runtime_base;
        self.mode = Some(next.to_string());
        self.chosen_mode = Some(next.to_string());
        self.persist();
        self.publish(kernel)
    }

    pub fn set_connection_query(
        &mut self,
        query: &str,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        self.connection_query = query.chars().take(200).collect();
        self.publish(kernel)
    }

    pub fn set_log_filter(
        &mut self,
        filter: &str,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        self.log_filter = diagnostics::normalize_log_filter(filter).to_string();
        self.publish(kernel)
    }

    pub fn set_node_query(&mut self, query: &str) -> ProfileSnapshot {
        self.node_query = query.chars().take(200).collect();
        self.snapshot()
    }

    pub fn set_node_sort(&mut self, group: &str, sort: &str) -> ProfileSnapshot {
        let group = group.trim();
        if !group.is_empty() {
            self.node_sort
                .insert(group.to_string(), nodes::normalize_sort(sort).to_string());
        }
        self.snapshot()
    }

    /// Interactive node actions only need liveness and the catalog. Reading the
    /// full connections/statistics snapshot before a selector PUT or a probe
    /// adds avoidable controller round trips and delays the requested action.
    fn sync_nodes(&mut self, kernel: &mut dyn KernelLaunch) {
        if !kernel.running() {
            self.sync_runtime(kernel);
            return;
        }
        self.kernel_running = true;
        self.append_logs(kernel.pull_logs());
        self.runtime_catalog = kernel.node_catalog();
        self.auto_now = self.runtime_catalog.now.clone();
    }

    pub fn select_node(
        &mut self,
        group: &str,
        node: &str,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        self.sync_nodes(kernel);
        let group_name = group.trim();
        let node_name = node.trim();
        let Some(index) = self.nodes_profile_index() else {
            self.nodes_error = Some(NEED_PROFILE.to_string());
            return self.snapshot();
        };
        if self.profiles[index].content.trim().is_empty() {
            self.nodes_error = Some(NEED_PROFILE.to_string());
            return self.snapshot();
        }
        let Some(document) = document_value(&self.profiles[index]) else {
            self.nodes_error = Some(NO_NODES.to_string());
            return self.snapshot();
        };
        let parsed = nodes::resolved_groups(&document, &self.runtime_catalog);
        let Some(found) = parsed.iter().find(|item| item.name == group_name) else {
            self.nodes_error = Some("没有这个代理组".to_string());
            return self.snapshot();
        };
        if found.pinnable {
            let found = found.clone();
            return self.fix_node(index, &found, node_name, kernel);
        }
        if !found.manual {
            self.nodes_error = Some(NOT_MANUAL.to_string());
            return self.snapshot();
        }
        if !found.proxies.iter().any(|item| item.as_str() == node_name) {
            self.nodes_error = Some("没有这个节点".to_string());
            return self.snapshot();
        }
        let previous = self.auto_now.get(group_name)
            .or_else(|| self.profiles[index].selected.get(group_name))
            .or_else(|| found.proxies.first());
        let changed = previous.map(String::as_str) != Some(node_name);
        if self.kernel_running && changed {
            if let Err(message) = kernel.select_proxy(group_name, node_name) {
                self.nodes_error = Some(if message.is_empty() {
                    SELECT_FAILED.to_string()
                } else {
                    message
                });
                return self.snapshot();
            }
        }
        self.profiles[index]
            .selected
            .insert(group_name.to_string(), node_name.to_string());
        if self.kernel_running {
            self.auto_now.insert(group_name.to_string(), node_name.to_string());
        }
        self.nodes_error = None;
        if self.notice.as_deref().is_some_and(|notice| notice.starts_with("节点已切换，但")) {
            self.notice = None;
        }
        if self.kernel_running && changed {
            self.close_switched_group(group_name, node_name, kernel);
        }
        self.persist();
        self.snapshot()
    }

    fn close_switched_group(&mut self, group: &str, node: &str, kernel: &mut dyn KernelLaunch) {
        if !self.settings.close_connections_on_switch.unwrap_or(true) {
            return;
        }
        match kernel.close_previous_group_connections(group, node) {
            Ok(ids) => {
                let closed: BTreeSet<_> = ids.into_iter().collect();
                self.connections.retain(|connection| !closed.contains(&connection.id));
                self.connection_total = self.connection_total.saturating_sub(closed.len());
            }
            Err(message) => self.notice = Some(format!("节点已切换，但{message}")),
        }
    }

    /// Pins a node on a `url-test` / `fallback` group. Needs a running kernel: the
    /// pin lives in the controller, and Billow only replays it after reloads.
    fn fix_node(
        &mut self,
        index: usize,
        group: &ParsedGroup,
        node: &str,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        if !self.kernel_running {
            self.nodes_error = Some(KERNEL_DOWN.to_string());
            return self.snapshot();
        }
        let current = self.auto_now.get(&group.name).cloned();
        if !group.proxies.iter().any(|item| item == node) && current.as_deref() != Some(node) {
            self.nodes_error = Some("没有这个节点".to_string());
            return self.snapshot();
        }
        if let Err(message) = kernel.select_proxy(&group.name, node) {
            self.nodes_error = Some(if message.is_empty() { SELECT_FAILED.to_string() } else { message });
            return self.snapshot();
        }
        self.profiles[index].fixed.insert(group.name.clone(), node.to_string());
        self.runtime_catalog.fixed.insert(group.name.clone(), node.to_string());
        self.runtime_catalog.now.insert(group.name.clone(), node.to_string());
        self.auto_now.insert(group.name.clone(), node.to_string());
        self.nodes_error = None;
        if self.notice.as_deref().is_some_and(|notice| notice.starts_with("节点已切换，但")) {
            self.notice = None;
        }
        if current.as_deref() != Some(node) {
            self.close_switched_group(&group.name, node, kernel);
        }
        self.persist();
        self.snapshot()
    }

    /// Releases a fixed `url-test` / `fallback` group back to its own strategy.
    pub fn unfix_group(&mut self, group: &str, kernel: &mut dyn KernelLaunch) -> ProfileSnapshot {
        self.sync_nodes(kernel);
        let group_name = group.trim();
        let Some(index) = self.nodes_profile_index() else {
            self.nodes_error = Some(NEED_PROFILE.to_string());
            return self.snapshot();
        };
        let Some(document) = document_value(&self.profiles[index]) else {
            self.nodes_error = Some(NO_NODES.to_string());
            return self.snapshot();
        };
        let parsed = nodes::resolved_groups(&document, &self.runtime_catalog);
        let Some(found) = parsed.iter().find(|item| item.name == group_name) else {
            self.nodes_error = Some("没有这个代理组".to_string());
            return self.snapshot();
        };
        if !found.pinnable {
            self.nodes_error = Some(NOT_MANUAL.to_string());
            return self.snapshot();
        }
        if !self.kernel_running {
            self.nodes_error = Some(KERNEL_DOWN.to_string());
            return self.snapshot();
        }
        if let Err(message) = kernel.unfix_proxy(group_name) {
            self.nodes_error = Some(if message.is_empty() { nodes::UNFIX_FAILED.to_string() } else { message });
            return self.snapshot();
        }
        self.profiles[index].fixed.remove(group_name);
        self.nodes_error = None;
        // The group picks again by its own strategy; read what it chose.
        self.runtime_catalog = kernel.node_catalog();
        self.runtime_catalog.fixed.remove(group_name);
        self.auto_now = self.runtime_catalog.now.clone();
        self.persist();
        self.snapshot()
    }

    pub fn test_group(&mut self, group: &str, kernel: &mut dyn KernelLaunch) -> ProfileSnapshot {
        self.test_group_with_progress(group, kernel, &mut |_, _, _, _, _| {})
    }

    pub fn test_group_with_progress(
        &mut self,
        group: &str,
        kernel: &mut dyn KernelLaunch,
        on_progress: &mut dyn FnMut(&str, Option<u64>, bool, usize, usize),
    ) -> ProfileSnapshot {
        self.sync_nodes(kernel);
        if !self.kernel_running {
            self.nodes_error = Some(KERNEL_DOWN.to_string());
            return self.snapshot();
        }
        let Some(index) = self.nodes_profile_index() else {
            self.nodes_error = Some(NEED_PROFILE.to_string());
            return self.snapshot();
        };
        let Some(document) = document_value(&self.profiles[index]) else {
            self.nodes_error = Some(NO_NODES.to_string());
            return self.snapshot();
        };
        let parsed = nodes::resolved_groups(&document, &self.runtime_catalog);
        let Some(found) = parsed.iter().find(|item| item.name == group.trim()) else {
            self.nodes_error = Some("没有这个代理组".to_string());
            return self.snapshot();
        };
        let manual = found.manual;
        let group_key = found.name.clone();
        let mut members = found.proxies.clone();
        if !manual {
            if let Some(now) = self.auto_now.get(&group_key).cloned() {
                if !members.iter().any(|item| item == &now) {
                    members.push(now);
                }
            }
        }
        let mut seen = BTreeSet::new();
        members.retain(|name| seen.insert(name.clone()));
        let profile_id = self.profiles[index].id.clone();
        let mut tested = 0;
        let total = members.len();
        match kernel.probe_delays_with_progress(&group_key, &members, &mut |name, delay, failed| {
            tested += 1;
            on_progress(name, delay, failed, tested, total);
        }) {
            Ok(results) => {
                // A named proxy has one result for the chosen test URL, even
                // when several groups list it. Keep the final snapshot aligned
                // with the streamed per-node overlay.
                let groups = self.tested_groups(index).unwrap_or_default();
                self.record_delays(&profile_id, &groups, results);
                self.nodes_error = None;
            }
            Err(message) => {
                self.nodes_error = Some(if message.is_empty() {
                    KERNEL_DOWN.to_string()
                } else {
                    message
                });
            }
        }
        self.snapshot()
    }

    fn nodes_profile_index(&self) -> Option<usize> {
        if let Some(id) = self.active_id.as_deref() {
            if let Some(index) = self.profiles.iter().position(|profile| profile.id == id) {
                return Some(index);
            }
        }
        self.profiles
            .iter()
            .rposition(|profile| !profile.content.trim().is_empty())
    }

    fn node_views(&self) -> (Vec<NodeGroupView>, Option<String>, Option<String>) {
        let Some(index) = self.nodes_profile_index() else {
            return (Vec::new(), Some(NEED_PROFILE.to_string()), None);
        };
        let profile = &self.profiles[index];
        let profile_id = profile.id.clone();
        if profile.content.trim().is_empty() {
            return (Vec::new(), Some(NEED_PROFILE.to_string()), Some(profile_id));
        }
        let Some(metadata) = profile.node_metadata() else {
            return (Vec::new(), Some(NO_NODES.to_string()), Some(profile_id));
        };
        if metadata.groups.is_empty() {
            return (Vec::new(), Some(NO_NODES.to_string()), Some(profile_id));
        }
        // Borrow provider members and protocol maps. The UI owns sorting and
        // filtering, so a second full catalog would only create unused copies.
        let catalog: Vec<NodeGroupView> = metadata.groups.iter().map(|group| {
            let members = self.runtime_catalog.members.get(&group.name)
                .map(Vec::as_slice).unwrap_or(&group.proxies);
            self.present_group(profile, group, members, &metadata.types)
        }).collect();
        let query = self.node_query.trim().to_lowercase();
        let unmatched = !query.is_empty() && !catalog.iter().any(|group| {
            group.nodes.iter().any(|node| node.name.to_lowercase().contains(&query))
        });
        (catalog, unmatched.then(|| NO_MATCH.to_string()), Some(profile_id))
    }

    fn present_group(
        &self,
        profile: &Profile,
        group: &ParsedGroup,
        members: &[String],
        types: &BTreeMap<String, nodes::ProxyInfo>,
    ) -> NodeGroupView {
        let sort = self.sort_of(&group.name);
        let hidden = self.runtime_catalog.hidden.get(&group.name).copied().unwrap_or(group.hidden);
        if !group.manual {
            // A running controller reports the live pin (it can drop a dead node by
            // itself); a stopped kernel shows the pin Billow will replay on start.
            let fixed = if !group.pinnable {
                None
            } else if self.kernel_running {
                self.runtime_catalog.fixed.get(&group.name).cloned()
            } else {
                profile.fixed.get(&group.name).cloned()
            };
            let now = self.auto_now.get(&group.name).cloned()
                .or_else(|| fixed.clone())
                .unwrap_or_default();
            let extra = (!now.is_empty() && !members.contains(&now)).then_some(&now);
            let nodes = members
                .iter().chain(extra)
                .map(|name| self.node_item(profile, &group.name, name, !now.is_empty() && *name == now, types))
                .collect();
            return NodeGroupView {
                name: group.name.clone(),
                kind: "auto".to_string(),
                now,
                sort,
                nodes,
                group_type: group.group_type.clone(),
                icon: group.icon.clone(),
                pinnable: group.pinnable,
                fixed,
                hidden,
            };
        }
        let chosen = self.auto_now.get(&group.name)
            .or_else(|| profile.selected.get(&group.name))
            .filter(|name| members.iter().any(|item| item == *name))
            .cloned();
        let now = chosen
            .clone()
            .or_else(|| members.first().cloned())
            .unwrap_or_default();
        let nodes = members.iter()
            .map(|name| {
                let selected = match &chosen {
                    Some(choice) => choice == name,
                    None => members.first() == Some(name),
                };
                self.node_item(profile, &group.name, name, selected, types)
            })
            .collect();
        NodeGroupView {
            name: group.name.clone(),
            kind: "manual".to_string(),
            now,
            sort,
            nodes,
            group_type: group.group_type.clone(),
            icon: group.icon.clone(),
            pinnable: false,
            fixed: None,
            hidden,
        }
    }

    fn node_item(
        &self,
        profile: &Profile,
        group: &str,
        name: &str,
        selected: bool,
        types: &BTreeMap<String, nodes::ProxyInfo>,
    ) -> nodes::NodeItemView {
        let mark = self
            .delays
            .get(&profile.id)
            .and_then(|groups| groups.get(group))
            .and_then(|nodes| nodes.get(name));
        let mut tags = types.get(name).map(|info| info.tags.clone()).unwrap_or_default();
        if let Some(runtime_tags) = self.runtime_catalog.tags.get(name) {
            for tag in runtime_tags {
                if !tags.contains(tag) { tags.push(tag.clone()); }
            }
        }
        let dialer_proxy = self
            .runtime_catalog
            .dialers
            .get(name)
            .cloned()
            .or_else(|| types.get(name).and_then(|info| info.dialer_proxy.clone()));
        nodes::NodeItemView {
            name: name.to_string(),
            delay_ms: mark.and_then(|item| item.delay_ms),
            failed: mark.is_some_and(|item| item.failed),
            selected,
            node_type: self.runtime_catalog.types.get(name).cloned()
                .or_else(|| types.get(name).map(|info| info.kind.clone())).unwrap_or_default(),
            tags,
            dialer_proxy,
        }
    }

    fn sort_of(&self, group: &str) -> String {
        nodes::normalize_sort(
            self.node_sort
                .get(group)
                .map(String::as_str)
                .unwrap_or("default"),
        )
        .to_string()
    }

    fn apply_live_selections(&mut self, kernel: &mut dyn KernelLaunch) {
        if !kernel.running() {
            return;
        }
        let Some(id) = self.active_id.as_deref() else {
            return;
        };
        let Some(profile) = self.profiles.iter().find(|profile| profile.id == id) else {
            return;
        };
        if profile.selected.is_empty() && profile.fixed.is_empty() {
            return;
        }
        self.runtime_catalog = kernel.node_catalog();
        self.auto_now = self.runtime_catalog.now.clone();
        let Some(document) = document_value(profile) else {
            return;
        };
        let mut pinned = Vec::new();
        for group in nodes::resolved_groups(&document, &self.runtime_catalog) {
            let saved = if group.manual {
                &profile.selected
            } else if group.pinnable {
                &profile.fixed
            } else {
                continue;
            };
            let Some(node) = saved.get(&group.name) else {
                continue;
            };
            if group.proxies.iter().any(|item| item == node)
                && kernel.select_proxy(&group.name, node).is_ok()
                && group.pinnable
            {
                pinned.push((group.name.clone(), node.clone()));
            }
        }
        // Keep the saved pin even when the kernel refuses it now; the next reload tries again.
        for (group, node) in pinned {
            self.runtime_catalog.fixed.insert(group.clone(), node.clone());
            self.runtime_catalog.now.insert(group.clone(), node.clone());
            self.auto_now.insert(group, node);
        }
    }

    #[cfg(test)]
    fn set_takeover(&mut self, system_proxy: bool, tun: bool, vpn: bool) {
        self.takeover = Takeover {
            system_proxy,
            tun,
            vpn,
        };
    }
}

impl KernelSettings {
    pub fn test_timeout_ms_or_default(&self) -> u64 {
        if self.test_timeout_ms == 0 {
            5000
        } else {
            self.test_timeout_ms
        }
    }

    fn normalized(mut self) -> Self {
        self.mixed_port = self.mixed_port.filter(|port| *port > 0);
        self.log_level = self
            .log_level
            .map(|level| level.trim().to_ascii_lowercase())
            .filter(|level| matches!(level.as_str(), "debug" | "info" | "warning" | "error" | "silent"));
        self.find_process_mode = self
            .find_process_mode
            .map(|mode| mode.trim().to_ascii_lowercase())
            .filter(|mode| matches!(mode.as_str(), "always" | "strict" | "off"));
        self.test_url = self.test_url.trim().chars().take(500).collect();
        if !self.test_url.is_empty()
            && !(self.test_url.starts_with("http://") || self.test_url.starts_with("https://"))
        {
            self.test_url.clear();
        }
        if self.test_timeout_ms != 0 {
            self.test_timeout_ms = self.test_timeout_ms.clamp(1000, 30000);
        }
        self.system_proxy = self.system_proxy.normalized();
        self.dns = self.dns.normalized();
        self.tun = self.tun.normalized();
        self.geodata_loader = self
            .geodata_loader
            .map(|loader| loader.trim().to_ascii_lowercase())
            .filter(|loader| matches!(loader.as_str(), "standard" | "memconservative"));
        self.geo_source = match self.geo_source.trim().to_ascii_lowercase().as_str() {
            "github" => "github".to_string(),
            "jsdelivr" => "jsdelivr".to_string(),
            "testingcf" => "testingcf".to_string(),
            _ => String::new(),
        };
        self.geo_urls = self.geo_urls.normalized();
        self.keep_alive_interval = self.keep_alive_interval.map(|secs| if secs == 0 { 0 } else { secs.clamp(5, 3600) });
        self.lan_auth = normalize_lan_auth(&self.lan_auth);
        self.lan_allowed_ips = normalize_cidrs(&self.lan_allowed_ips);
        let ports = |items: Option<Vec<String>>| {
            items
                .map(|items| {
                    let mut out: Vec<String> = Vec::new();
                    for entry in items.iter().filter_map(|item| sniff_port_entry(item)) {
                        if !out.contains(&entry) && out.len() < 64 {
                            out.push(entry);
                        }
                    }
                    out
                })
                .filter(|items| !items.is_empty())
        };
        self.sniff_ports = SniffPorts {
            http: ports(self.sniff_ports.http),
            tls: ports(self.sniff_ports.tls),
            quic: ports(self.sniff_ports.quic),
        };
        let domains = |items: Option<Vec<String>>| {
            items
                .map(|items| clean_list(items, 500))
                .filter(|items| !items.is_empty())
        };
        self.sniff_force_domain = domains(self.sniff_force_domain);
        self.sniff_skip_domain = domains(self.sniff_skip_domain);
        self.interface_name = self
            .interface_name
            .map(|name| name.trim().chars().filter(|ch| !ch.is_control()).take(64).collect());
        self
    }

    /// Entries Billow cannot write faithfully are refused with the offending item named.
    /// `mixed` is the mixed port the kernel would actually bind.
    fn validate(&self, mixed: Option<i64>) -> Result<(), String> {
        self.tun.validate()?;
        for (label, items) in [
            ("HTTP 嗅探端口", &self.sniff_ports.http),
            ("TLS 嗅探端口", &self.sniff_ports.tls),
            ("QUIC 嗅探端口", &self.sniff_ports.quic),
        ] {
            if let Some(bad) = items.iter().flatten().find(|item| sniff_port_entry(item).is_none()) {
                return Err(format!("{label}中的「{}」无效，请填 1–65535 的端口或“起-止”范围", bad.trim()));
            }
        }
        if let Some(name) = &self.interface_name {
            if name.trim().contains(char::is_whitespace) {
                return Err("出口网卡名称不能包含空格".to_string());
            }
        }
        let mut taken: Vec<(&str, i64)> = Vec::new();
        if let Some(port) = mixed.filter(|port| *port > 0) {
            taken.push(("混合端口", port));
        }
        for (label, port) in [
            ("SOCKS 端口", self.socks_port),
            ("HTTP 端口", self.http_port),
            ("redir 端口", self.redir_port),
            ("tproxy 端口", self.tproxy_port),
        ] {
            let Some(port) = port.map(i64::from).filter(|port| *port > 0) else { continue };
            if let Some((other, _)) = taken.iter().find(|(_, used)| *used == port) {
                return Err(format!("{label} {port} 与{other}重复，请换一个端口"));
            }
            taken.push((label, port));
        }
        Ok(())
    }

    fn listener_ports(&self) -> [Option<u16>; 5] {
        [self.mixed_port, self.socks_port, self.http_port, self.redir_port, self.tproxy_port]
    }

    fn sniff_details_set(&self) -> bool {
        self.sniff_ports != SniffPorts::default()
            || self.sniff_force_domain.is_some()
            || self.sniff_skip_domain.is_some()
            || self.sniff_override_destination.is_some()
    }

    /// Everything except UI/startup preferences, the delay probe and OS system-proxy settings, which never need a kernel restart.
    fn kernel_part(&self) -> Self {
        let mut copy = self.clone();
        copy.auto_connect = false;
        copy.close_connections_on_switch = None;
        copy.subscription_user_agent.clear();
        copy.test_url.clear();
        copy.test_timeout_ms = 0;
        copy.system_proxy = Default::default();
        copy
    }

    pub fn resolve_geo_download_urls(&self, effective_yaml: Option<&str>) -> Vec<(String, Vec<String>)> {
        let parsed: Option<Value> = effective_yaml.and_then(|raw| serde_yaml::from_str(raw).ok());
        let yaml_geox = parsed.as_ref().and_then(|v| mapping_get(v, "geox-url"));
        let source_preset = geo_source_urls(&self.geo_source);
        let mut out = Vec::new();
        for (key_name, _, _, _) in crate::resources::GEO_SPECS {
            let custom = self.geo_urls.get(key_name);
            if !custom.is_empty() {
                out.push((key_name.to_string(), vec![custom.to_string()]));
                continue;
            }
            let mut candidates: Vec<String> = Vec::new();
            let mut push_unique = |url: String| {
                let cleaned = clean_http_url(&url);
                if !cleaned.is_empty() && !candidates.contains(&cleaned) {
                    candidates.push(cleaned);
                }
            };
            if let Some(preset) = &source_preset {
                if let Some((_, url)) = preset.iter().find(|(k, _)| *k == key_name) {
                    push_unique(url.clone());
                }
            } else if let Some(geox) = yaml_geox {
                if let Some(url) = read_string(geox, key_name) {
                    push_unique(url);
                }
            }
            for mirror in ["jsdelivr", "testingcf", "github"] {
                if let Some(preset) = geo_source_urls(mirror) {
                    if let Some((_, url)) = preset.iter().find(|(k, _)| *k == key_name) {
                        push_unique(url.clone());
                    }
                }
            }
            out.push((key_name.to_string(), candidates));
        }
        out
    }
}

/// Default port written when neither the profile nor settings name one.
const FALLBACK_MIXED_PORT: i64 = 7890;

fn apply_settings(
    yaml: &str,
    settings: &KernelSettings,
    desktop: bool,
) -> Result<(String, Option<i64>), String> {
    let mut value: Value = serde_yaml::from_str(yaml).map_err(|_| CONTENT_ERROR.to_string())?;
    let Some(map) = value.as_mapping_mut() else {
        return Err(CONTENT_ERROR.to_string());
    };
    let key = |name: &str| Value::String(name.to_string());
    if let Some(port) = settings.mixed_port {
        map.insert(key("mixed-port"), Value::Number(i64::from(port).into()));
        if desktop {
            // Explicit mixed-port override replaces legacy separate HTTP/SOCKS listeners
            // so a profile's occupied `port: 7890` / `socks-port: 7891` never keeps failing.
            map.remove(key("port"));
            map.remove(key("socks-port"));
        }
    } else if !map.contains_key(key("mixed-port")) && !map.contains_key(key("port")) {
        map.insert(key("mixed-port"), Value::Number(FALLBACK_MIXED_PORT.into()));
    } else if !map.contains_key(key("mixed-port")) {
        // Only an HTTP `port`: reuse it as the mixed listener so system proxy has a target,
        // and remove `port` so mihomo does not bind the same port twice and fail against itself.
        if let Some(port) = map.get(key("port")).and_then(Value::as_i64) {
            map.insert(key("mixed-port"), Value::Number(port.into()));
            if desktop {
                map.remove(key("port"));
            }
        }
    }
    if desktop {
        if let Some(mixed) = map.get(key("mixed-port")).and_then(Value::as_i64).filter(|p| *p > 0) {
            for name in ["port", "socks-port", "redir-port", "tproxy-port"] {
                if map.get(key(name)).and_then(Value::as_i64) == Some(mixed) {
                    map.remove(key(name));
                }
            }
        }
        // Explicit ports win over the cleanup above; a profile port they would collide with goes.
        let explicit = [
            ("socks-port", settings.socks_port),
            ("port", settings.http_port),
            ("redir-port", settings.redir_port),
            ("tproxy-port", settings.tproxy_port),
        ];
        let taken: Vec<i64> = explicit.iter().filter_map(|(_, port)| port.map(i64::from)).filter(|port| *port > 0).collect();
        for (name, port) in explicit {
            match port {
                Some(port) => {
                    map.insert(key(name), Value::Number(i64::from(port).into()));
                }
                None => {
                    if map.get(key(name)).and_then(Value::as_i64).is_some_and(|port| taken.contains(&port)) {
                        map.remove(key(name));
                    }
                }
            }
        }
        match settings.interface_name.as_deref() {
            Some("") => {
                map.remove(key("interface-name"));
            }
            Some(name) => {
                map.insert(key("interface-name"), Value::String(name.to_string()));
            }
            None => {}
        }
        match settings.routing_mark {
            Some(0) => {
                map.remove(key("routing-mark"));
            }
            Some(mark) => {
                map.insert(key("routing-mark"), Value::Number(u64::from(mark).into()));
            }
            None => {}
        }
    }
    if !desktop {
        // Keep the user-facing mixed port (normally 7890) for apps such as Telegram.
        // Only the private controller needs an independent port.
        static CONTROLLER: std::sync::OnceLock<u16> = std::sync::OnceLock::new();
        let controller_port = if let Some(port) = CONTROLLER.get() { *port } else {
            let controller = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|error| error.to_string())?;
            *CONTROLLER.get_or_init(|| controller.local_addr().unwrap().port())
        };
        for name in ["port", "socks-port", "redir-port", "tproxy-port"] { map.insert(key(name), Value::Number(0.into())); }
        map.insert(key("external-controller"), Value::String(format!("127.0.0.1:{controller_port}")));
        let mut tun = map.get(key("tun")).and_then(Value::as_mapping).cloned().unwrap_or_default();
        tun.insert(key("enable"), Value::Bool(false));
        tun.insert(key("auto-route"), Value::Bool(false));
        tun.insert(key("auto-detect-interface"), Value::Bool(false));
        tun.insert(key("dns-hijack"), Value::Sequence(vec![Value::String("any:53".to_string())]));
        map.insert(key("tun"), Value::Mapping(tun));
    }
    if let Some(flag) = settings.allow_lan {
        map.insert(key("allow-lan"), Value::Bool(flag));
    }
    if let Some(flag) = settings.ipv6 {
        map.insert(key("ipv6"), Value::Bool(flag));
    }
    if let Some(level) = &settings.log_level {
        map.insert(key("log-level"), Value::String(level.clone()));
    }
    if let Some(flag) = settings.unified_delay {
        map.insert(key("unified-delay"), Value::Bool(flag));
    }
    if let Some(flag) = settings.tcp_concurrent {
        map.insert(key("tcp-concurrent"), Value::Bool(flag));
    }
    if let Some(mode) = &settings.find_process_mode {
        map.insert(key("find-process-mode"), Value::String(mode.clone()));
    }
    if settings.dns_override {
        map.insert(key("dns"), settings.dns.to_value());
        if settings.dns.use_hosts && !settings.dns.hosts.is_empty() {
            let mut hosts = map
                .get(key("hosts"))
                .and_then(Value::as_mapping)
                .cloned()
                .unwrap_or_default();
            for (domain, targets) in &settings.dns.hosts {
                let entry = if targets.len() == 1 {
                    Value::String(targets[0].clone())
                } else {
                    Value::Sequence(targets.iter().map(|t| Value::String(t.clone())).collect())
                };
                hosts.insert(Value::String(domain.clone()), entry);
            }
            map.insert(key("hosts"), Value::Mapping(hosts));
        }
    }
    if let Some(flag) = settings.geodata_mode {
        map.insert(key("geodata-mode"), Value::Bool(flag));
    }
    if let Some(loader) = &settings.geodata_loader {
        map.insert(key("geodata-loader"), Value::String(loader.clone()));
    }
    if let Some(flag) = settings.geo_auto_update {
        map.insert(key("geo-auto-update"), Value::Bool(flag));
    }
    if let Some(hours) = settings.geo_update_interval.filter(|hours| *hours > 0) {
        map.insert(key("geo-update-interval"), Value::Number(i64::from(hours).into()));
    }
    let source_urls = geo_source_urls(&settings.geo_source);
    if source_urls.is_some() || settings.geo_urls.has_any() {
        let mut geox = map
            .get(key("geox-url"))
            .and_then(Value::as_mapping)
            .cloned()
            .unwrap_or_default();
        if let Some(urls) = source_urls {
            for (name, url) in urls {
                geox.insert(key(name), Value::String(url));
            }
        }
        for (name, _, _, _) in crate::resources::GEO_SPECS {
            let custom = settings.geo_urls.get(name);
            if !custom.is_empty() {
                geox.insert(key(name), Value::String(custom.to_string()));
            }
        }
        map.insert(key("geox-url"), Value::Mapping(geox));
    }
    match settings.keep_alive_interval {
        Some(0) => {
            map.insert(key("disable-keep-alive"), Value::Bool(true));
        }
        Some(secs) => {
            map.insert(key("disable-keep-alive"), Value::Bool(false));
            map.insert(key("keep-alive-interval"), Value::Number(u64::from(secs).into()));
        }
        None => {}
    }
    if !settings.lan_auth.is_empty() {
        map.insert(
            key("authentication"),
            Value::Sequence(settings.lan_auth.iter().cloned().map(Value::String).collect()),
        );
        let skip = with_loopback(map.get(key("skip-auth-prefixes")), &[]);
        map.insert(key("skip-auth-prefixes"), skip);
    }
    if !settings.lan_allowed_ips.is_empty() {
        // Replace the profile's list, but never lock out the machine itself.
        let allowed = with_loopback(None, &settings.lan_allowed_ips);
        map.insert(key("lan-allowed-ips"), allowed);
    }
    if let Some(flag) = settings.sniffer {
        if flag {
            map.insert(key("sniffer"), default_sniffer());
        } else {
            let mut off = serde_yaml::Mapping::new();
            off.insert(key("enable"), Value::Bool(false));
            map.insert(key("sniffer"), Value::Mapping(off));
        }
    }
    if settings.sniff_details_set() {
        // Details ride on whatever sniffer block ends up enabled; while sniffing is off they wait.
        if let Some(sniffer) = map.get_mut(key("sniffer")).and_then(Value::as_mapping_mut) {
            if sniffer.get(key("enable")).and_then(Value::as_bool) == Some(true) {
                overlay_sniffer(sniffer, settings);
            }
        }
    }
    if desktop {
        // Android hands the kernel a VPN fd; routing options there belong to the system.
        let mut tun = map
            .get(key("tun"))
            .and_then(Value::as_mapping)
            .cloned()
            .unwrap_or_default();
        let tun_settings = &settings.tun;
        if !tun_settings.stack.is_empty() {
            tun.insert(key("stack"), Value::String(tun_settings.stack.clone()));
        }
        tun.insert(key("auto-route"), Value::Bool(tun_settings.auto_route));
        tun.insert(key("auto-detect-interface"), Value::Bool(tun_settings.auto_detect_interface));
        tun.insert(key("strict-route"), Value::Bool(tun_settings.strict_route));
        tun.insert(
            key("dns-hijack"),
            Value::Sequence(tun_settings.dns_hijack.iter().map(|item| Value::String(item.clone())).collect()),
        );
        if tun_settings.mtu > 0 {
            tun.insert(key("mtu"), Value::Number(u64::from(tun_settings.mtu).into()));
        }
        if !tun_settings.device.is_empty() {
            tun.insert(key("device"), Value::String(tun_settings.device.clone()));
        }
        let strings = |items: &[String]| Value::Sequence(items.iter().map(|item| Value::String(item.clone())).collect());
        if let Some(items) = &tun_settings.route_address {
            tun.insert(key("route-address"), strings(items));
        }
        if let Some(items) = &tun_settings.route_exclude_address {
            tun.insert(key("route-exclude-address"), strings(items));
        }
        map.insert(key("tun"), Value::Mapping(tun));
    }
    let port = map.get(key("mixed-port")).and_then(Value::as_i64);
    let text = serde_yaml::to_string(&value).map_err(|_| CONTENT_ERROR.to_string())?;
    Ok((text, port))
}

fn overlay_sniffer(sniffer: &mut serde_yaml::Mapping, settings: &KernelSettings) {
    let key = |name: &str| Value::String(name.to_string());
    let ports = [
        ("HTTP", &settings.sniff_ports.http),
        ("TLS", &settings.sniff_ports.tls),
        ("QUIC", &settings.sniff_ports.quic),
    ];
    if ports.iter().any(|(_, items)| items.is_some()) {
        let mut sniff = sniffer.get(key("sniff")).and_then(Value::as_mapping).cloned().unwrap_or_default();
        for (protocol, items) in ports {
            let Some(items) = items else { continue };
            let mut entry = sniff.get(key(protocol)).and_then(Value::as_mapping).cloned().unwrap_or_default();
            entry.insert(key("ports"), sniff_ports_value(items));
            sniff.insert(key(protocol), Value::Mapping(entry));
        }
        sniffer.insert(key("sniff"), Value::Mapping(sniff));
    }
    let strings = |items: &[String]| Value::Sequence(items.iter().map(|item| Value::String(item.clone())).collect());
    if let Some(items) = &settings.sniff_force_domain {
        sniffer.insert(key("force-domain"), strings(items));
    }
    if let Some(items) = &settings.sniff_skip_domain {
        sniffer.insert(key("skip-domain"), strings(items));
    }
    if let Some(flag) = settings.sniff_override_destination {
        sniffer.insert(key("override-destination"), Value::Bool(flag));
        // A per-protocol value would win over the global one, so keep them in step.
        if let Some(sniff) = sniffer.get_mut(key("sniff")).and_then(Value::as_mapping_mut) {
            for (_, entry) in sniff.iter_mut() {
                if let Some(entry) = entry.as_mapping_mut() {
                    if entry.contains_key(key("override-destination")) {
                        entry.insert(key("override-destination"), Value::Bool(flag));
                    }
                }
            }
        }
    }
}

/// Loopback ranges stay exempt from LAN authentication and allow-lists, so the
/// system proxy and local apps never need credentials.
const LOOPBACK_RANGES: [&str; 2] = ["127.0.0.1/8", "::1/128"];

/// `user:pass` lines with a non-empty user and no whitespace; duplicates and junk dropped.
fn normalize_lan_auth(items: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in items {
        let entry = item.trim();
        let Some((user, pass)) = entry.split_once(':') else { continue };
        if user.is_empty() || pass.is_empty() || entry.len() > 128 || entry.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
            continue;
        }
        if !out.iter().any(|existing| existing.split_once(':').map(|(u, _)| u) == Some(user)) {
            out.push(entry.to_string());
        }
        if out.len() >= 16 {
            break;
        }
    }
    out
}

/// The first entry `normalize_cidrs` would drop, so the user hears which one is wrong.
fn invalid_cidr(items: &[String]) -> Option<String> {
    items
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .find(|item| normalize_cidrs(&[item.to_string()]).is_empty())
        .map(str::to_string)
}

/// A sniff port entry as `443` or `8080-8880`, each end within 1–65535.
fn sniff_port_entry(raw: &str) -> Option<String> {
    let text: String = raw.chars().filter(|ch| !ch.is_whitespace()).collect();
    let port = |part: &str| part.parse::<u16>().ok().filter(|port| *port > 0 && part.chars().all(|ch| ch.is_ascii_digit()));
    match text.split_once('-') {
        Some((start, end)) => {
            let (start, end) = (port(start)?, port(end)?);
            (start <= end).then(|| format!("{start}-{end}"))
        }
        None => port(&text).map(|port| port.to_string()),
    }
}

/// Sniff ports as YAML: single ports stay numbers, ranges are strings.
fn sniff_ports_value(items: &[String]) -> Value {
    Value::Sequence(
        items
            .iter()
            .map(|item| match item.parse::<u16>() {
                Ok(port) => Value::Number(u64::from(port).into()),
                Err(_) => Value::String(item.clone()),
            })
            .collect(),
    )
}

/// IP or CIDR entries in canonical `ip/prefix` form; a bare address becomes a host range.
fn normalize_cidrs(items: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in items {
        let entry = item.trim();
        let (addr, prefix) = match entry.split_once('/') {
            Some((addr, prefix)) => (addr, prefix.parse::<u8>().ok()),
            None => (entry, None),
        };
        let Ok(ip) = addr.parse::<std::net::IpAddr>() else { continue };
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = match (entry.contains('/'), prefix) {
            (false, _) => max,
            (true, Some(bits)) if bits <= max => bits,
            _ => continue,
        };
        let text = format!("{ip}/{prefix}");
        if !out.contains(&text) {
            out.push(text);
        }
        if out.len() >= 64 {
            break;
        }
    }
    out
}

/// Append loopback ranges to a YAML list without duplicating what the profile already has.
fn with_loopback(existing: Option<&Value>, extra: &[String]) -> Value {
    let mut items: Vec<String> = existing
        .and_then(Value::as_sequence)
        .map(|seq| seq.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    for item in extra.iter().map(String::as_str).chain(LOOPBACK_RANGES) {
        if !items.iter().any(|existing| existing == item) {
            items.push(item.to_string());
        }
    }
    Value::Sequence(items.into_iter().map(Value::String).collect())
}

fn default_sniffer() -> Value {
    serde_yaml::from_str(
        "enable: true\nforce-dns-mapping: true\nparse-pure-ip: true\nsniff:\n  HTTP:\n    ports: [80, 8080-8880]\n    override-destination: true\n  TLS:\n    ports: [443, 8443]\n  QUIC:\n    ports: [443, 8443]\nskip-domain:\n  - Mijia Cloud\n  - +.push.apple.com\n",
    )
    .unwrap_or(Value::Null)
}

/// Whether the profile carries a `tun` block (used by tests that pin the
/// staging boundary).
#[cfg(test)]
fn config_has_tun(yaml: &str) -> bool {
    serde_yaml::from_str::<Value>(yaml)
        .ok()
        .and_then(|value| mapping_get(&value, "tun").cloned())
        .is_some()
}

/// Removes a `tun` block unconditionally. The native kernel takes its device
/// route from the launcher (iOS Packet Tunnel / Android VpnService fd), so a
/// user-written or launcher-injected block must never reach its config loader.
fn strip_tun(yaml: &str) -> Result<String, String> {
    strip_launcher_tun(yaml, false)
}

fn strip_launcher_tun(yaml: &str, user_had_tun: bool) -> Result<String, String> {
    if user_had_tun {
        return Ok(yaml.to_string());
    }
    let mut value: Value = serde_yaml::from_str(yaml).map_err(|_| CONTENT_ERROR.to_string())?;
    if let Some(map) = value.as_mapping_mut() {
        map.remove(Value::String("tun".to_string()));
    }
    serde_yaml::to_string(&value).map_err(|_| CONTENT_ERROR.to_string())
}

fn ensure_tun_dns(yaml: &str, settings: &KernelSettings) -> Result<String, String> {
    let mut value: Value = serde_yaml::from_str(yaml).map_err(|_| CONTENT_ERROR.to_string())?;
    let Some(map) = value.as_mapping_mut() else {
        return Err(CONTENT_ERROR.to_string());
    };
    let key = |name: &str| Value::String(name.to_string());
    let tun_on = map
        .get(key("tun"))
        .and_then(|tun| tun.get("enable"))
        .and_then(Value::as_bool)
        == Some(true);
    if !tun_on {
        return Ok(yaml.to_string());
    }
    let dns_on = map
        .get(key("dns"))
        .and_then(|dns| dns.get("enable"))
        .and_then(Value::as_bool)
        == Some(true);
    if dns_on {
        return Ok(yaml.to_string());
    }
    map.insert(key("dns"), settings.dns.clone().normalized().to_value());
    serde_yaml::to_string(&value).map_err(|_| CONTENT_ERROR.to_string())
}

fn subscription_proxy_count(text: &str) -> Option<usize> {
    let value = parse_config(text).ok()?;
    Some(mapping_get(&value, "proxies").and_then(Value::as_sequence).map_or(0, Vec::len))
}

fn count_proxies(content: &str) -> usize {
    subscription_proxy_count(content).unwrap_or(0)
}

const REFRESH_SLACK_MS: u64 = 60_000;

impl ProfileBook {
    fn config_values(&self) -> ConfigValues {
        let Some(profile) = self
            .active_id
            .as_deref()
            .and_then(|id| self.profiles.iter().find(|profile| profile.id == id))
        else {
            return ConfigValues::default();
        };
        profile.node_metadata().map(|metadata| metadata.config.clone()).unwrap_or_default()
    }

    fn index_of(&self, id: &str) -> Option<usize> {
        self.profiles.iter().position(|profile| profile.id == id)
    }

    pub fn clear_notice(&mut self) -> ProfileSnapshot {
        self.notice = None;
        self.snapshot()
    }

    /// Removes a profile. The active one can go only while nothing is connected.
    pub fn delete_profile(&mut self, id: &str) -> ProfileSnapshot {
        let Some(index) = self.index_of(id) else {
            self.input_error = Some(MISSING_PROFILE.to_string());
            return self.snapshot();
        };
        let active = self.active_id.as_deref() == Some(id);
        if active && (self.connected || self.kernel_running) {
            self.notice = Some("请先断开连接再删除当前配置".to_string());
            return self.snapshot();
        }
        self.profiles.remove(index);
        self.delays.remove(id);
        if active {
            self.active_id = None;
            self.disabled_rules.clear();
            self.runtime_base = None;
            self.recompute_effective();
        }
        self.notice = None;
        self.persist();
        self.snapshot()
    }

    pub fn rename_profile(&mut self, id: &str, name: &str) -> ProfileSnapshot {
        let Some(index) = self.index_of(id) else {
            self.input_error = Some(MISSING_PROFILE.to_string());
            return self.snapshot();
        };
        let name = clean_name(name, &self.profiles[index].name.clone());
        self.profiles[index].name = name;
        self.persist();
        self.snapshot()
    }

    pub fn set_profile_source(&mut self, id: &str, url: &str) -> ProfileSnapshot {
        let Some(index) = self.index_of(id) else {
            self.input_error = Some(MISSING_PROFILE.to_string());
            return self.snapshot();
        };
        if self.profiles[index].kind != ProfileKind::Subscription {
            return self.snapshot();
        }
        match validate_subscription_url(url.trim()) {
            Ok(url) => {
                self.profiles[index].source = url;
                self.input_error = None;
                self.persist();
            }
            Err(message) => self.input_error = Some(message),
        }
        self.snapshot()
    }

    fn subscription_user_agent(&self, index: usize) -> &str {
        let custom = self.profiles[index].user_agent.trim();
        if custom.is_empty() { self.settings.subscription_user_agent.trim() } else { custom }
    }

    pub fn set_profile_user_agent(&mut self, id: &str, user_agent: &str) -> ProfileSnapshot {
        let Some(index) = self.index_of(id) else {
            self.input_error = Some(MISSING_PROFILE.to_string());
            return self.snapshot();
        };
        if self.profiles[index].kind != ProfileKind::Subscription { return self.snapshot(); }
        match normalize_subscription_user_agent(user_agent) {
            Ok(value) => {
                self.profiles[index].user_agent = value;
                self.input_error = None;
                self.persist();
            }
            Err(message) => self.input_error = Some(message),
        }
        self.snapshot()
    }

    /// Store (or clear, with empty text) the age identities used to decrypt this subscription.
    pub fn set_profile_age_key(&mut self, id: &str, keys: &str) -> ProfileSnapshot {
        let Some(index) = self.index_of(id) else {
            self.input_error = Some(MISSING_PROFILE.to_string());
            return self.snapshot();
        };
        if self.profiles[index].kind != ProfileKind::Subscription {
            return self.snapshot();
        }
        match age_key::normalize_keys(keys) {
            Ok(normalized) => {
                self.profiles[index].age_key = normalized;
                self.input_error = None;
                self.persist();
            }
            Err(message) => self.input_error = Some(message),
        }
        self.snapshot()
    }

    pub fn set_profile_interval(&mut self, id: &str, hours: u32) -> ProfileSnapshot {
        if let Some(index) = self.index_of(id) {
            self.profiles[index].interval_hours = hours.min(24 * 30);
            self.persist();
        }
        self.snapshot()
    }

    /// Apply an unsaved 覆写 to a profile, returning the merged YAML and script logs.
    pub fn preview_override(&self, id: &str, text: &str) -> Result<OverridePreview, String> {
        let profile = self
            .profiles
            .iter()
            .find(|profile| profile.id == id)
            .ok_or_else(|| MISSING_PROFILE.to_string())?;
        let (yaml, logs) = preview_override(&profile.content, text, &profile.name)?;
        Ok(OverridePreview { yaml, logs })
    }

    pub fn profile_content(&self, id: &str) -> Option<String> {
        self.profiles
            .iter()
            .find(|profile| profile.id == id)
            .map(|profile| profile.content.clone())
    }

    /// Replaces a profile's saved YAML after checking it is a usable config.
    pub fn save_profile_content(
        &mut self,
        id: &str,
        content: &str,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        let Some(index) = self.index_of(id) else {
            self.input_error = Some(MISSING_PROFILE.to_string());
            return self.snapshot();
        };
        let Some(proxy_count) = subscription_proxy_count(content) else {
            self.profiles[index].failure = Some(CONTENT_ERROR.to_string());
            self.input_error = Some(CONTENT_ERROR.to_string());
            return self.snapshot();
        };
        let profile = &mut self.profiles[index];
        profile.node_metadata.take();
        profile.refresh_revision += 1;
        profile.content = content.to_string();
        profile.proxy_count = proxy_count;
        profile.updated_ms = Some(now_ms());
        profile.failure = None;
        self.input_error = None;
        let active = self.active_id.as_deref() == Some(id);
        self.persist();
        if active {
            self.disabled_rules.clear();
            self.recompute_effective();
            if kernel.running() && self.platform == ClientPlatform::Desktop {
                let tun = self.takeover.tun;
                if let Err(StartError::Failed(message)) | Err(StartError::Idle(message)) =
                    self.reload(kernel, tun, None)
                {
                    self.notice = Some(message);
                }
            }
        }
        self.publish(kernel)
    }

    pub fn prepare_refresh(&mut self, id: &str) -> Option<RefreshRequest> {
        let Some(index) = self.index_of(id) else {
            self.input_error = Some(MISSING_PROFILE.to_string());
            return None;
        };
        let user_agent = self.subscription_user_agent(index).to_string();
        let profile = &mut self.profiles[index];
        if profile.kind != ProfileKind::Subscription {
            return None;
        }
        profile.refresh_revision += 1;
        Some(RefreshRequest {
            id: profile.id.clone(),
            source: profile.source.clone(),
            user_agent,
            age_key: profile.age_key.clone(),
            revision: profile.refresh_revision,
        })
    }

    /// Commit only the latest request made with the current download settings.
    /// Returns true when a live config was reloaded and its proxy port needs checking.
    pub fn finish_refresh(
        &mut self,
        request: &RefreshRequest,
        fetched: Result<DownloadedProfile, String>,
        kernel: &mut dyn KernelLaunch,
    ) -> bool {
        let Some(index) = self.index_of(&request.id) else { return false };
        if self.subscription_user_agent(index) != request.user_agent {
            return false;
        }
        let profile = &mut self.profiles[index];
        if profile.refresh_revision != request.revision || profile.source != request.source
            || profile.age_key != request.age_key
        {
            return false;
        }
        let now = now_ms();
        profile.updated_ms = Some(now);
        let fetched = match fetched {
            Ok(fetched) => fetched,
            Err(message) => {
                profile.failure = Some(message);
                self.persist();
                return false;
            }
        };
        let previous_content = if profile.content == fetched.content {
            None
        } else {
            profile.node_metadata.take();
            Some(std::mem::replace(&mut profile.content, fetched.content))
        };
        let active = self.active_id.as_deref() == Some(&request.id);
        let live = active && self.platform == ClientPlatform::Desktop && kernel.running();
        if active {
            let disabled = std::mem::take(&mut self.disabled_rules);
            self.recompute_effective();
            if live {
                let result = self.reload(kernel, self.takeover.tun, None);
                if let Err(StartError::Failed(message) | StartError::Idle(message)) = result {
                    if let Some(previous) = previous_content {
                        self.profiles[index].content = previous;
                        self.profiles[index].node_metadata.take();
                    }
                    self.disabled_rules = disabled;
                    self.notice = Some(message.clone());
                    self.recompute_effective();
                    if kernel.running() {
                        self.profiles[index].failure = Some(message);
                        self.persist();
                    } else {
                        self.fail_activation(index, message);
                    }
                    self.sync_runtime(kernel);
                    return false;
                }
                self.sync_runtime(kernel);
            }
        }
        let profile = &mut self.profiles[index];
        profile.usage = fetched.usage;
        profile.proxy_count = fetched.proxy_count;
        profile.last_success_ms = Some(now);
        profile.failure = None;
        self.persist();
        live
    }

    #[cfg(test)]
    fn refresh_profile(
        &mut self,
        id: &str,
        source: &dyn SubscriptionSource,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        if let Some(request) = self.prepare_refresh(id) {
            let result = request.fetch(source);
            self.finish_refresh(&request, result, kernel);
        }
        self.snapshot()
    }

    /// Subscriptions whose update interval has passed.
    pub fn due_profiles(&self, now: u64) -> Vec<String> {
        self.profiles
            .iter()
            .filter(|profile| profile.kind == ProfileKind::Subscription && profile.interval_hours > 0)
            .filter(|profile| {
                let every = u64::from(profile.interval_hours) * 3_600_000;
                match profile.updated_ms.or(profile.last_success_ms) {
                    Some(last) => now.saturating_add(REFRESH_SLACK_MS) >= last.saturating_add(every),
                    None => true,
                }
            })
            .map(|profile| profile.id.clone())
            .collect()
    }

    pub fn subscription_ids(&self) -> Vec<String> {
        self.profiles
            .iter()
            .filter(|profile| profile.kind == ProfileKind::Subscription)
            .map(|profile| profile.id.clone())
            .collect()
    }

    pub fn geo_download_context(
        &mut self,
        kernel: &mut dyn KernelLaunch,
    ) -> (
        Vec<(String, Vec<String>)>,
        Option<String>,
        Option<ControllerEndpoint>,
        Option<String>,
    ) {
        let effective = self.effective_config().ok();
        let urls = self.settings.resolve_geo_download_urls(effective.as_deref());
        let running = kernel.running();
        let controller = if running { kernel.controller() } else { None };
        let local_proxy = if running && self.connected {
            self.mixed_port
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port > 0)
                .map(|port| format!("http://127.0.0.1:{port}"))
        } else {
            None
        };
        (urls, local_proxy, controller, effective)
    }

    pub fn save_settings(
        &mut self,
        settings: KernelSettings,
        kernel: &mut dyn KernelLaunch,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        let user_agent = match normalize_subscription_user_agent(&settings.subscription_user_agent) {
            Ok(value) => value,
            Err(message) => { self.input_error = Some(message); return self.snapshot(); }
        };
        // The mixed-port clash is only checked when a listener port changes, so a port that
        // collides after a profile switch never blocks unrelated saves (the kernel still reports the bind).
        let ports_changed = settings.listener_ports() != self.settings.listener_ports();
        let mixed = if ports_changed {
            let config = self.config_values();
            Some(
                settings
                    .mixed_port
                    .filter(|port| *port > 0)
                    .map(i64::from)
                    .or(config.mixed_port)
                    .unwrap_or(FALLBACK_MIXED_PORT),
            )
        } else {
            None
        };
        if let Err(message) = settings.validate(mixed) {
            self.input_error = Some(message);
            return self.snapshot();
        }
        let mut settings = settings.normalized();
        settings.subscription_user_agent = user_agent;
        self.input_error = None;
        let restart = settings.kernel_part() != self.settings.kernel_part();
        let proxy_changed = settings.system_proxy != self.settings.system_proxy;
        self.settings = settings;
        nodes::set_probe(&self.settings.test_url, self.settings.test_timeout_ms_or_default());
        self.recompute_effective();
        self.persist();
        if self.platform != ClientPlatform::Desktop || !kernel.running() {
            return self.publish(kernel);
        }
        if !restart {
            if proxy_changed && self.takeover.system_proxy {
                let port = self
                    .mixed_port
                    .and_then(|p| u16::try_from(p).ok())
                    .filter(|p| *p > 0);
                if let Some(port) = port {
                    let mut model = self.link_model();
                    takeover::set_system_proxy_with_settings(
                        &mut model,
                        true,
                        Some(port),
                        &self.settings.system_proxy,
                        proxy,
                    );
                    self.apply_model(model);
                }
            }
            return self.publish(kernel);
        }
        let tun_on = self.takeover.tun;
        match self.reload(kernel, tun_on, None) {
            Ok(port) => {
                if self.takeover.system_proxy {
                    let mut model = self.link_model();
                    takeover::set_system_proxy_with_settings(
                        &mut model,
                        true,
                        Some(port),
                        &self.settings.system_proxy,
                        proxy,
                    );
                    self.apply_model(model);
                }
            }
            Err(StartError::Idle(message)) => {
                self.home_failure = Some(message);
                self.connected = false;
                self.remember_current_failure();
            }
            Err(StartError::Failed(message)) => {
                if kernel.running() {
                    self.home_failure = Some(message);
                    self.remember_current_failure();
                } else {
                    let mut model = self.link_model();
                    takeover::fail_kernel(&mut model, proxy, tun, vpn, message);
                    self.apply_model(model);
                    self.remember_current_failure();
                }
            }
        }
        self.publish(kernel)
    }

    fn record_delays(&mut self, profile_id: &str, groups: &[(String, Vec<String>)], results: Vec<NodeDelay>) {
        let marks: BTreeMap<String, Option<u64>> = results
            .into_iter()
            .map(|item| (item.name, item.delay_ms))
            .collect();
        let profile_slot = self.delays.entry(profile_id.to_string()).or_default();
        for (group, members) in groups {
            let slot = profile_slot.entry(group.clone()).or_default();
            for name in members {
                let Some(delay) = marks.get(name) else {
                    continue;
                };
                slot.insert(
                    name.clone(),
                    DelayMark {
                        delay_ms: *delay,
                        failed: delay.is_none(),
                    },
                );
            }
        }
    }

    fn tested_groups(&self, index: usize) -> Option<Vec<(String, Vec<String>)>> {
        let document = document_value(&self.profiles[index])?;
        Some(
            nodes::resolved_groups(&document, &self.runtime_catalog)
                .into_iter()
                .map(|group| {
                    let mut members = group.proxies;
                    if let Some(now) = self.auto_now.get(&group.name) {
                        if !members.iter().any(|item| item == now) {
                            members.push(now.clone());
                        }
                    }
                    (group.name, members)
                })
                .collect(),
        )
    }

    /// Tests every distinct node once and writes the result into every group that lists it.
    /// Each finished node is reported with its `tested`/`total` counters for the
    /// `node-test` progress event.
    pub fn test_all_with_progress(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        on_progress: &mut dyn FnMut(&str, Option<u64>, bool, usize, usize),
    ) -> ProfileSnapshot {
        self.sync_nodes(kernel);
        if !self.kernel_running {
            self.nodes_error = Some(KERNEL_DOWN.to_string());
            return self.snapshot();
        }
        let Some(index) = self.nodes_profile_index() else {
            self.nodes_error = Some(NEED_PROFILE.to_string());
            return self.snapshot();
        };
        let Some(groups) = self.tested_groups(index) else {
            self.nodes_error = Some(NO_NODES.to_string());
            return self.snapshot();
        };
        let mut unique: Vec<String> = Vec::new();
        let mut seen = BTreeSet::new();
        for (_, members) in &groups {
            for name in members {
                if seen.insert(name.as_str()) {
                    unique.push(name.clone());
                }
            }
        }
        let total = unique.len();
        let profile_id = self.profiles[index].id.clone();
        let mut tested = 0usize;
        match kernel.probe_delays_with_progress("", &unique, &mut |name, delay, failed| {
            tested += 1;
            on_progress(name, delay, failed, tested, total);
        }) {
            Ok(results) => {
                self.record_delays(&profile_id, &groups, results);
                self.nodes_error = None;
            }
            Err(message) => {
                self.nodes_error = Some(if message.is_empty() { KERNEL_DOWN.to_string() } else { message });
            }
        }
        self.snapshot()
    }

    pub fn test_node(&mut self, node: &str, kernel: &mut dyn KernelLaunch) -> ProfileSnapshot {
        self.sync_nodes(kernel);
        if !self.kernel_running {
            self.nodes_error = Some(KERNEL_DOWN.to_string());
            return self.snapshot();
        }
        let Some(index) = self.nodes_profile_index() else {
            self.nodes_error = Some(NEED_PROFILE.to_string());
            return self.snapshot();
        };
        let Some(groups) = self.tested_groups(index) else {
            self.nodes_error = Some(NO_NODES.to_string());
            return self.snapshot();
        };
        let node = node.trim().to_string();
        let profile_id = self.profiles[index].id.clone();
        match kernel.probe_delays("", std::slice::from_ref(&node)) {
            Ok(results) => {
                self.record_delays(&profile_id, &groups, results);
                self.nodes_error = None;
            }
            Err(message) => {
                self.nodes_error = Some(if message.is_empty() { KERNEL_DOWN.to_string() } else { message });
            }
        }
        self.snapshot()
    }

    pub fn close_connections(&mut self, id: Option<&str>, kernel: &mut dyn KernelLaunch) -> ProfileSnapshot {
        if let Some(endpoint) = kernel.controller() {
            if let Err(message) = diagnostics::close_connections(&endpoint, id) {
                self.notice = Some(message);
            }
        }
        self.publish(kernel)
    }

    /// Closes every connection (`None`) or exactly the listed ones (R30). Failed
    /// ids are counted in the notice; closed ones leave the next snapshot.
    pub fn close_connection_set(&mut self, ids: Option<&[String]>, kernel: &mut dyn KernelLaunch) -> ProfileSnapshot {
        let Some(endpoint) = kernel.controller() else {
            self.notice = Some(KERNEL_DOWN.to_string());
            return self.snapshot();
        };
        let outcome = match ids {
            None => diagnostics::close_connections(&endpoint, None),
            Some(ids) => diagnostics::close_connection_list(&endpoint, ids).and_then(|failed| match failed {
                0 => Ok(()),
                failed => Err(format!("{failed} 条连接没有关闭")),
            }),
        };
        // Each call reports its own outcome, so a later success clears an earlier failure count.
        self.notice = outcome.err();
        self.publish(kernel)
    }

    /// Full rule list from the active profile, keys computed over the original order.
    fn active_config_rules(&self) -> Vec<diagnostics::ConfigRule> {
        let Some(profile) = self
            .active_id
            .as_deref()
            .and_then(|id| self.profiles.iter().find(|profile| profile.id == id))
        else {
            return Vec::new();
        };
        let Some(value) = document_value(profile) else {
            return Vec::new();
        };
        diagnostics::config_rules(&value)
    }

    pub fn rules(&mut self, kernel: &mut dyn KernelLaunch) -> RulesSnapshot {
        let disabled = self.disabled_rules.iter().cloned().collect();
        let config = self.active_config_rules();
        match kernel.controller() {
            Some(endpoint) => match diagnostics::fetch_rules(&endpoint) {
                Ok(kernel_rules) => RulesSnapshot {
                    rules: diagnostics::rule_rows(&config, &kernel_rules, &self.disabled_rules),
                    error: None,
                    disabled,
                },
                Err(message) => RulesSnapshot {
                    rules: diagnostics::rule_rows(&config, &[], &self.disabled_rules),
                    error: Some(message),
                    disabled,
                },
            },
            None => RulesSnapshot {
                rules: Vec::new(),
                error: Some(KERNEL_DOWN.to_string()),
                disabled,
            },
        }
    }

    /// Temporarily disables or re-enables one rule. The filtered runtime config is
    /// hot-reloaded; unknown keys and failed reloads leave the previous key set.
    pub fn set_rule_disabled(
        &mut self,
        command: RuleToggle,
        kernel: &mut dyn KernelLaunch,
    ) -> Result<RulesSnapshot, String> {
        self.sync_runtime(kernel);
        if !self.kernel_running {
            return Err(KERNEL_DOWN.to_string());
        }
        let key = command.key.trim().to_string();
        if !self.active_config_rules().iter().any(|rule| rule.key == key) {
            return Err("没有这条规则".to_string());
        }
        let previous = self.disabled_rules.clone();
        let changed = if command.disabled {
            self.disabled_rules.insert(key)
        } else {
            self.disabled_rules.remove(&key)
        };
        if !changed {
            return Ok(self.rules(kernel));
        }
        let tun = self.takeover.tun;
        let outcome = match self.runtime_base.clone() {
            Some(base) => diagnostics::filter_disabled_rules(&base, &self.disabled_rules)
                .and_then(|yaml| kernel.reload_config(&yaml)),
            None => match self.kernel_yaml(tun, None) {
                Ok((base, _)) => diagnostics::filter_disabled_rules(&base, &self.disabled_rules)
                    .and_then(|yaml| kernel.reload_config(&yaml)),
                Err(StartError::Idle(message)) | Err(StartError::Failed(message)) => Err(message),
            },
        };
        if let Err(message) = outcome {
            self.disabled_rules = previous;
            return Err(message);
        }
        Ok(self.rules(kernel))
    }

    pub fn providers(&mut self, kernel: &mut dyn KernelLaunch) -> ProvidersSnapshot {
        let Some(endpoint) = kernel.controller() else {
            return ProvidersSnapshot { providers: Vec::new(), error: Some(KERNEL_DOWN.to_string()) };
        };
        match diagnostics::fetch_providers(&endpoint) {
            Ok(providers) => ProvidersSnapshot { providers, error: None },
            Err(message) => ProvidersSnapshot { providers: Vec::new(), error: Some(message) },
        }
    }

    /// The controller endpoint for slow calls made without holding the session lock.
    pub fn controller_of(kernel: &mut dyn KernelLaunch) -> Option<ControllerEndpoint> {
        kernel.controller()
    }

    /// Drops the kernel's fake-ip mapping or DNS cache.
    pub fn flush_cache(&mut self, which: &str, kernel: &mut dyn KernelLaunch) -> ProfileSnapshot {
        let Some(endpoint) = kernel.controller() else {
            self.notice = Some(KERNEL_DOWN.to_string());
            return self.snapshot();
        };
        let result = match which {
            "fakeip" => diagnostics::flush_cache(&endpoint, "fakeip"),
            _ => diagnostics::flush_cache(&endpoint, "dns"),
        };
        self.notice = result.err();
        self.publish(kernel)
    }

    pub fn clear_logs(&mut self) -> ProfileSnapshot {
        self.logs.clear();
        self.snapshot()
    }
}

struct Prepared {
    yaml: String,
    mixed_port: Option<i64>,
    mode: Option<String>,
}

enum StartError {
    Idle(String),
    Failed(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct OverridePreview {
    pub yaml: String,
    pub logs: Vec<String>,
}

enum PrepareError {
    Content,
    Override(String),
}

fn normalize_outbound(mode: &str) -> Option<&'static str> {
    match mode.trim().to_ascii_lowercase().as_str() {
        "rule" | "规则" => Some("rule"),
        "global" | "全局" => Some("global"),
        "direct" | "直连" => Some("direct"),
        _ => None,
    }
}

fn force_mode(yaml: &str, mode: &str) -> Result<String, String> {
    let mut value: Value = serde_yaml::from_str(yaml).map_err(|_| CONTENT_ERROR.to_string())?;
    let Some(map) = value.as_mapping_mut() else {
        return Err(CONTENT_ERROR.to_string());
    };
    map.insert(
        Value::String("mode".to_string()),
        Value::String(mode.to_string()),
    );
    serde_yaml::to_string(&value).map_err(|_| CONTENT_ERROR.to_string())
}

fn force_tun(yaml: &str, enable: bool, fd: Option<i32>) -> Result<String, String> {
    let mut value: Value = serde_yaml::from_str(yaml).map_err(|_| CONTENT_ERROR.to_string())?;
    let Some(map) = value.as_mapping_mut() else {
        return Err(CONTENT_ERROR.to_string());
    };
    let tun_key = Value::String("tun".to_string());
    let mut tun = map
        .get(&tun_key)
        .and_then(|item| item.as_mapping())
        .cloned()
        .unwrap_or_default();
    tun.insert(Value::String("enable".to_string()), Value::Bool(enable));
    let fd_key = Value::String("file-descriptor".to_string());
    if let Some(fd) = fd {
        tun.insert(fd_key, Value::Number(i64::from(fd).into()));
    } else {
        tun.remove(&fd_key);
    }
    map.insert(tun_key, Value::Mapping(tun));
    serde_yaml::to_string(&value).map_err(|_| CONTENT_ERROR.to_string())
}

fn document_value(profile: &Profile) -> Option<Value> {
    if profile.content.trim().is_empty() {
        return None;
    }
    let prepared = match prepare(&profile.content, &profile.applied_override) {
        Ok(prepared) => prepared,
        Err(_) => prepare(&profile.content, "").ok()?,
    };
    serde_yaml::from_str(&prepared.yaml).ok()
}

fn prepare(content: &str, override_text: &str) -> Result<Prepared, PrepareError> {
    prepare_named(content, override_text, "")
}

/// Profile content with its 覆写 applied (YAML merge or `main(config, name)` script).
fn prepare_named(content: &str, override_text: &str, name: &str) -> Result<Prepared, PrepareError> {
    let mut base = parse_config(content).map_err(|_| PrepareError::Content)?;
    if !override_text.trim().is_empty() {
        crate::override_engine::apply(&mut base, override_text, name, parse_yaml)
            .map_err(PrepareError::Override)?;
        if !is_config(&base) {
            return Err(PrepareError::Override("覆写后配置为空".to_string()));
        }
    }
    let yaml = serde_yaml::to_string(&base).map_err(|_| PrepareError::Content)?;
    Ok(Prepared {
        mixed_port: read_i64(&base, "mixed-port"),
        mode: read_string(&base, "mode"),
        yaml,
    })
}

/// Apply `override_text` to `content` without saving, for the editor's preview.
pub fn preview_override(content: &str, override_text: &str, name: &str) -> Result<(String, Vec<String>), String> {
    let mut base = parse_config(content).map_err(|_| CONTENT_ERROR.to_string())?;
    let applied = crate::override_engine::apply(&mut base, override_text, name, parse_yaml)?;
    if !is_config(&base) {
        return Err("覆写后配置为空".to_string());
    }
    let yaml = serde_yaml::to_string(&base).map_err(|_| CONTENT_ERROR.to_string())?;
    Ok((yaml, applied.logs))
}

/// Parse YAML the way the kernel reads it: `<<` merge keys (usually `<<: *anchor`)
/// are resolved, so fields such as a provider's `type` or a group's `type` are
/// visible to the app and stay intact once the config is re-serialized.
fn parse_yaml(text: &str) -> Result<Value, serde_yaml::Error> {
    let mut value = serde_yaml::from_str::<Value>(text)?;
    // A malformed merge is left for the kernel to report; the app keeps the raw value.
    if value.apply_merge().is_err() {
        return serde_yaml::from_str(text);
    }
    Ok(value)
}

fn parse_config(text: &str) -> Result<Value, ()> {
    let value = parse_yaml(text).map_err(|_| ())?;
    if is_config(&value) {
        Ok(value)
    } else {
        Err(())
    }
}

fn is_config(value: &Value) -> bool {
    match value.as_mapping() {
        Some(map) => !map.is_empty(),
        None => false,
    }
}

fn read_i64(value: &Value, key: &str) -> Option<i64> {
    mapping_get(value, key).and_then(Value::as_i64)
}

fn read_string(value: &Value, key: &str) -> Option<String> {
    mapping_get(value, key)
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn mapping_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_mapping()?
        .iter()
        .find(|(candidate, _)| candidate.as_str() == Some(key))
        .map(|(_, item)| item)
}

/// A YAML list (or a lone scalar) of strings and numbers as text, for "配置中为 …" hints.
fn yaml_strings(value: Option<&Value>) -> Option<Vec<String>> {
    let scalar = |item: &Value| match item {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    };
    match value? {
        Value::Sequence(items) => Some(items.iter().filter_map(scalar).collect()),
        other => scalar(other).map(|text| vec![text]),
    }
}

fn sniff_config_ports(value: &Value, protocol: &str) -> Option<Vec<String>> {
    let sniff = mapping_get(mapping_get(value, "sniffer")?, "sniff")?;
    yaml_strings(mapping_get(mapping_get(sniff, protocol)?, "ports"))
}

fn parse_userinfo(header: Option<&str>) -> Option<Usage> {
    let header = header?.trim();
    if header.is_empty() {
        return None;
    }
    let mut upload = None;
    let mut download = None;
    let mut total = None;
    let mut expire = None;
    for part in header.split(';') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let Ok(number) = value.trim().parse::<u64>() else {
            continue;
        };
        match key {
            "upload" => upload = Some(number),
            "download" => download = Some(number),
            "total" => total = Some(number),
            "expire" => expire = Some(number),
            _ => {}
        }
    }
    usage_from_parts(
        total
            .filter(|value| *value > 0)
            .map(|_| upload.unwrap_or(0).saturating_add(download.unwrap_or(0))),
        total.filter(|value| *value > 0),
        expire.filter(|value| *value > 0),
    )
}

fn usage_from_parts(used: Option<u64>, total: Option<u64>, expire: Option<u64>) -> Option<Usage> {
    let total = total.filter(|value| *value > 0);
    let used = if total.is_some() {
        used.or(Some(0))
    } else {
        None
    };
    let expire = expire.filter(|value| *value > 0);
    if used.is_none() && total.is_none() && expire.is_none() {
        None
    } else {
        Some(Usage {
            used,
            total,
            expire,
        })
    }
}

fn parse_install_link(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.to_ascii_lowercase().starts_with("clash://") {
        return Err(LINK_ERROR.to_string());
    }
    let Some(rest) = strip_prefix_ignore_ascii_case(raw, "billow://") else {
        return Err(LINK_ERROR.to_string());
    };
    let Some((host, query)) = rest.split_once('?') else {
        return Err(ONE_LINK_ERROR.to_string());
    };
    if !host
        .trim_end_matches('/')
        .eq_ignore_ascii_case("install-config")
    {
        return Err(LINK_ERROR.to_string());
    }
    let mut urls = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key.eq_ignore_ascii_case("url") {
            urls.push(percent_decode(value));
        }
    }
    if urls.len() != 1 {
        return Err(ONE_LINK_ERROR.to_string());
    }
    validate_subscription_url(&urls[0])
}

fn validate_subscription_url(url: &str) -> Result<String, String> {
    let url = url.trim();
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err(URL_ERROR.to_string());
    }
    if url.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err(URL_ERROR.to_string());
    }
    let host = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or("")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() || !host.contains('.') && host != "localhost" {
        return Err(URL_ERROR.to_string());
    }
    Ok(url.to_string())
}

fn strip_prefix_ignore_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    if value.len() < prefix.len() {
        return None;
    }
    let (head, tail) = value.split_at(prefix.len());
    if head.eq_ignore_ascii_case(prefix) {
        Some(tail)
    } else {
        None
    }
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[index + 1..index + 3]) {
                if let Ok(value) = u8::from_str_radix(hex, 16) {
                    out.push(value);
                    index += 3;
                    continue;
                }
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn subscription_name(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        "订阅".to_string()
    } else {
        host.to_string()
    }
}

fn clean_name(name: &str, fallback: &str) -> String {
    let name: String = name
        .trim()
        .chars()
        .filter(|ch| *ch != '/' && *ch != '\\' && *ch != '\n' && *ch != '\r')
        .take(80)
        .collect();
    if name.is_empty() {
        fallback.to_string()
    } else {
        name
    }
}

fn parse_subscription_content(mut content: String) -> Result<(String, usize), String> {
    fn trim_body(text: &mut String) {
        text.truncate(text.trim_end().len());
        let start = text.len() - text.trim_start().trim_start_matches('\u{feff}').len();
        text.drain(..start);
    }
    trim_body(&mut content);
    if let Some(count) = subscription_proxy_count(&content) {
        return Ok((content, count));
    }
    content.retain(|ch| !ch.is_whitespace());
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    for engine in [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(&content) {
            let mut decoded = String::from_utf8(bytes).map_err(|_| CONTENT_ERROR.to_string())?;
            trim_body(&mut decoded);
            if let Some(count) = subscription_proxy_count(&decoded) {
                return Ok((decoded, count));
            }
            break;
        }
    }
    Err(CONTENT_ERROR.to_string())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::nodes::{KERNEL_DOWN, NEED_PROFILE, NO_MATCH, NO_NODES, NOT_MANUAL, NodeDelay};
    use crate::takeover::{MemoryProxy, MemoryTun, MemoryVpn};

    #[cfg(not(target_os = "android"))]
    #[test]
    #[ignore = "requires BILLOW_TEST_RESOURCES pointing to the built desktop runtime bundle"]
    fn desktop_packaged_runtime_starts_offline() {
        let resources = PathBuf::from(std::env::var_os("BILLOW_TEST_RESOURCES").expect("BILLOW_TEST_RESOURCES"));
        let dir = temp_dir("offline-package");
        let home = dir.0.join("home");
        let mut manager = crate::kernel::KernelManager::open(dir.0.join("kernels"), crate::kernel::PlatformTarget::current());
        assert!(!manager.status().ready);
        manager.seed_desktop(&resources).unwrap();
        crate::bundled_geo::seed_directory(&resources.join("geo"), &home).unwrap();
        let port_socket = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = port_socket.local_addr().unwrap().port();
        let api_socket = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let api_port = api_socket.local_addr().unwrap().port();
        drop((port_socket, api_socket));
        // Refuse any GEO download: these rules must load from the installer snapshot.
        let yaml = format!("mixed-port: {port}\nexternal-controller: 127.0.0.1:{api_port}\nsecret: billow-offline-test\nmode: rule\ngeodata-mode: true\ngeox-url:\n  geoip: http://127.0.0.1:9/unavailable\n  geosite: http://127.0.0.1:9/unavailable\n  mmdb: http://127.0.0.1:9/unavailable\n  asn: http://127.0.0.1:9/unavailable\nrules:\n  - GEOIP,CN,DIRECT\n  - GEOSITE,cn,DIRECT\n  - IP-ASN,13335,DIRECT\n  - MATCH,DIRECT\n");
        let mut runtime = ProcessRuntime::new(dir.0.join("profiles"));
        runtime.home_dir = home;
        runtime.set_bundled_resources(resources);
        runtime.set_kernel_path(manager.connect().kernel_path);
        runtime.start_or_reload(&yaml).unwrap();
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
        runtime.start_or_reload(&yaml.replace("geodata-mode: true", "geodata-mode: false")).unwrap();
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
        runtime.stop();
        assert!(!runtime.running());
    }

    /// Local TCP target that answers each marker line with `pong:<marker>`.
    fn spawn_marker_target(expected: usize) -> (u16, std::thread::JoinHandle<Vec<String>>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..expected {
                let Ok((mut stream, _)) = listener.accept() else { break };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut marker = String::new();
                if reader.read_line(&mut marker).is_err() {
                    break;
                }
                let marker = marker.trim().to_string();
                let _ = write!(stream, "pong:{marker}\n");
                let _ = stream.flush();
                seen.push(marker);
            }
            seen
        });
        (port, handle)
    }

    /// Sends one HTTP CONNECT through the proxy and returns the target's reply.
    fn marker_through_proxy(proxy_port: u16, target_port: u16, marker: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut stream = loop {
            match std::net::TcpStream::connect(("127.0.0.1", proxy_port)) {
                Ok(stream) => break stream,
                Err(error) if Instant::now() < deadline => {
                    let _ = error;
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(error) => panic!("proxy listener never came up: {error}"),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            stream,
            "CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
        )
        .unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut status = String::new();
        reader.read_line(&mut status).unwrap();
        assert!(status.contains(" 200"), "CONNECT failed: {status}");
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).unwrap();
            if header == "\r\n" || header.is_empty() {
                break;
            }
        }
        write!(stream, "{marker}\n").unwrap();
        stream.flush().unwrap();
        let mut reply = String::new();
        reader.read_line(&mut reply).unwrap();
        reply.trim().to_string()
    }

    /// Opt-in host proof: both packaged engines carry a marked request, and a
    /// switch in each direction keeps the session usable. Never touches the OS
    /// proxy or TUN; all listeners are loopback.
    #[cfg(not(target_os = "android"))]
    #[test]
    #[ignore = "requires BILLOW_TEST_RESOURCES with packaged Mihomo and billow-kernel; loopback listeners only, no system proxy/TUN"]
    fn packaged_engines_switch_both_ways_with_a_marked_request() {
        let resources = PathBuf::from(std::env::var_os("BILLOW_TEST_RESOURCES").expect("BILLOW_TEST_RESOURCES"));
        let rust = resources.join(if cfg!(target_os = "windows") { "billow-kernel.exe" } else { "billow-kernel" });
        assert!(rust.is_file(), "run tool/prepare_desktop_runtime.mjs to package billow-kernel");
        let dir = temp_dir("engine-package");
        let home = dir.0.join("home");
        let mut manager = crate::kernel::KernelManager::open(dir.0.join("kernels"), crate::kernel::PlatformTarget::current());
        manager.seed_desktop(&resources).unwrap();
        crate::bundled_geo::seed_directory(&resources.join("geo"), &home).unwrap();
        let port_socket = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = port_socket.local_addr().unwrap().port();
        drop(port_socket);
        let yaml = format!("mixed-port: {port}\nmode: rule\nrules:\n  - MATCH,DIRECT\n");
        let mut runtime = ProcessRuntime::new(dir.0.join("profiles"));
        runtime.home_dir = home;
        runtime.set_bundled_resources(resources.clone());
        runtime.set_kernel_path(manager.installed_path());
        runtime.set_rust_kernel_path(Some(rust));
        let mut book = ProfileBook::open(dir.0.join("book"));
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("direct.yaml", &yaml);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let (target, server) = spawn_marker_target(4);

        book.enable("p1", &RejectSource, &mut runtime);
        let connected = book.connect(&mut runtime, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.system_proxy, "mihomo session failed: {:?}", connected.failure);
        assert_eq!(connected.running_engine.as_deref(), Some("mihomo"));
        assert_eq!(marker_through_proxy(port, target, "mihomo-1"), "pong:mihomo-1");

        let switched = book
            .switch_engine(Engine::Rust, &mut runtime, &mut proxy, &mut tun, &mut vpn)
            .unwrap_or_else(|error| panic!("mihomo -> rust failed: {error}"));
        assert_eq!(switched.engine, "rust");
        assert_eq!(switched.running_engine.as_deref(), Some("rust"));
        assert!(switched.engine_identity.is_some(), "native instance identity is required");
        assert!(switched.system_proxy);
        assert_eq!(marker_through_proxy(port, target, "rust-1"), "pong:rust-1");

        let back = book
            .switch_engine(Engine::Mihomo, &mut runtime, &mut proxy, &mut tun, &mut vpn)
            .unwrap_or_else(|error| panic!("rust -> mihomo failed: {error}"));
        assert_eq!(back.engine, "mihomo");
        assert_eq!(back.running_engine.as_deref(), Some("mihomo"));
        assert!(back.system_proxy);
        assert_eq!(marker_through_proxy(port, target, "mihomo-2"), "pong:mihomo-2");

        // A configuration the native kernel cannot accept is refused before the
        // live Mihomo session is released. `sniffer.enable` stays a named
        // rejection (proxy groups became supported in T23, so they are no
        // longer a valid negative case).
        let grouped = format!(
            "mixed-port: {port}\nmode: rule\nsniffer:\n  enable: true\nrules:\n  - MATCH,DIRECT\n"
        );
        book.save_profile_content("p1", &grouped, &mut runtime);
        let refused = book
            .switch_engine(Engine::Rust, &mut runtime, &mut proxy, &mut tun, &mut vpn)
            .unwrap_err();
        assert!(refused.contains("未接受当前配置"), "{refused}");
        let snapshot = book.snapshot();
        assert_eq!(snapshot.engine, "mihomo");
        assert_eq!(snapshot.running_engine.as_deref(), Some("mihomo"));
        assert!(snapshot.connected);
        assert_eq!(marker_through_proxy(port, target, "mihomo-3"), "pong:mihomo-3");

        book.disconnect(&mut runtime, &mut proxy, &mut tun, &mut vpn);
        runtime.shutdown();
        let markers = server.join().unwrap();
        assert_eq!(markers, ["mihomo-1", "rust-1", "mihomo-2", "mihomo-3"]);
    }

    /// Use a private local fixture to compare the downloaded YAML with the exact
    /// configuration transformation used by activate(). Never embeds subscription data.
    #[cfg(not(target_os = "android"))]
    #[test]
    #[ignore = "requires BILLOW_TEST_PROFILE_DIR and BILLOW_TEST_KERNEL; isolated loopback listeners, no system proxy/TUN"]
    fn external_profile_survives_runtime_preparation() {
        let directory = PathBuf::from(std::env::var_os("BILLOW_TEST_PROFILE_DIR").expect("fixture directory"));
        let kernel = PathBuf::from(std::env::var_os("BILLOW_TEST_KERNEL").expect("test kernel"));
        let content = fs::read_to_string(directory.join("input.yaml")).unwrap();
        let prepared = prepare(&content, "").unwrap_or_else(|_| panic!("fixture could not be prepared"));
        let settings = KernelSettings::default();
        let (yaml, _) = apply_settings(&prepared.yaml, &settings, true).unwrap();
        let yaml = ensure_tun_dns(&yaml, &settings).unwrap();
        let yaml = nodes::ensure_controller(&nodes::prioritize_selections(&yaml, &BTreeMap::new()));
        let path = directory.join("prepared.yaml");
        fs::write(&path, &yaml).unwrap();
        let output = Command::new(&kernel).arg("-t").arg("-d").arg(directory.join("home"))
            .arg("-f").arg(path).output().unwrap();
        let mut logs = output.stdout;
        logs.extend(output.stderr);
        fs::write(directory.join("prepared-validation.log"), logs).unwrap();
        assert!(output.status.success(), "kernel validation failed; inspect the private fixture's prepared-validation.log");
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let controller = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let controller_port = controller.local_addr().unwrap().port();
        let mut config: Value = serde_yaml::from_str(&yaml).unwrap();
        let map = config.as_mapping_mut().unwrap();
        map.insert(Value::String("mixed-port".into()), Value::Number(port.into()));
        map.insert(Value::String("allow-lan".into()), Value::Bool(false));
        map.insert(Value::String("bind-address".into()), Value::String("127.0.0.1".into()));
        map.insert(Value::String("external-controller".into()), Value::String(format!("127.0.0.1:{controller_port}")));
        for name in ["port", "socks-port", "redir-port", "tproxy-port"] {
            map.insert(Value::String(name.into()), Value::Number(0.into()));
        }
        if let Some(dns) = map.get_mut(Value::String("dns".into())).and_then(Value::as_mapping_mut) {
            dns.insert(Value::String("listen".into()), Value::String("127.0.0.1:0".into()));
        }
        let yaml = force_tun(&serde_yaml::to_string(&config).unwrap(), false, None).unwrap();
        drop((listener, controller));
        let mut runtime = ProcessRuntime::new(directory.join("runtime"));
        runtime.home_dir = directory.join("home");
        runtime.set_kernel_path(Some(kernel));
        let result = runtime.start_or_reload(&yaml);
        if let Err(message) = &result { fs::write(directory.join("startup-error.log"), message).unwrap(); }
        assert!(result.is_ok(), "kernel startup failed; inspect the private fixture's startup-error.log");
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
        runtime.stop();
    }

    /// Opt-in host smoke test: uses an installed Mihomo, never writes system proxy settings.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires BILLOW_TEST_KERNEL; BILLOW_TEST_TUN=1 requests macOS administrator consent"]
    fn macos_real_kernel_listens_and_reloads() {
        use crate::takeover::TunGrant;
        let path = PathBuf::from(std::env::var_os("BILLOW_TEST_KERNEL").expect("BILLOW_TEST_KERNEL"));
        let dir = temp_dir("macos-real-kernel");
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let api = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let api_port = api.local_addr().unwrap().port();
        drop(api);
        let yaml = format!("mixed-port: {port}\nexternal-controller: 127.0.0.1:{api_port}\nsecret: billow-local-smoke\nmode: direct\ntun:\n  enable: false\n  auto-route: false\n");
        let mut runtime = ProcessRuntime::new(&dir.0);
        runtime.set_kernel_path(Some(path.clone()));
        runtime.start_or_reload(&yaml).unwrap();
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
        let pid = runtime.child.as_ref().unwrap().id();
        runtime.start_or_reload(&yaml.replace("mode: direct", "mode: rule")).unwrap();
        assert_eq!(runtime.child.as_ref().unwrap().id(), pid);
        nodes::put_config(runtime.controller.as_ref().unwrap(), &yaml.replace(&format!("mixed-port: {port}"), "mixed-port: 0")).unwrap();
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
        runtime.start_or_reload(&yaml.replace("mode: direct", "mode: rule")).unwrap();
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok(), "reconnect must restore a lost listener even when YAML is unchanged");
        if std::env::var("BILLOW_TEST_TUN").as_deref() == Ok("1") {
            let mut grant = takeover::HostTun::host();
            grant.set_kernel_path(Some(path));
            assert!(grant.authorize().unwrap(), "macOS authorization was cancelled");
            runtime.start_or_reload(&yaml.replace("enable: false", "enable: true")).unwrap();
            assert!(nodes::listeners_ready(runtime.controller.as_ref().unwrap(), Some(port), true));
            assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
            runtime.start_or_reload(&yaml).unwrap();
        }
        runtime.stop();
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
        // Rust YAML parsing accepts this, but the real core exits on an unsupported
        // protocol. The UI must receive that reason, not just "内核没有启动".
        let invalid = format!("{yaml}proxies:\n  - {{name: invalid-test, type: billow-invalid-test}}\n");
        let error = runtime.start_or_reload(&invalid).unwrap_err();
        assert!(error.contains("billow-invalid-test"), "kernel reason was lost: {error}");
        assert!(runtime.pull_logs().iter().any(|line| line.message.contains("billow-invalid-test")));
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires BILLOW_TEST_KERNEL; uses isolated loopback streams without OS proxy/TUN changes"]
    fn real_selector_switch_reconnects_old_streams_and_keeps_other_groups() {
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};
        fn tunnel(port: u16, destination: u16) -> TcpStream {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            write!(stream, "CONNECT 127.0.0.1:{destination} HTTP/1.1\r\nHost: 127.0.0.1:{destination}\r\n\r\n").unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new(); reader.read_line(&mut line).unwrap();
            assert!(line.contains("200"), "CONNECT was rejected");
            loop { line.clear(); reader.read_line(&mut line).unwrap(); if line == "\r\n" || line.is_empty() { break; } }
            stream
        }
        fn echo(stream: &mut TcpStream) {
            stream.write_all(b"ping").unwrap();
            let mut data = [0; 4]; stream.read_exact(&mut data).unwrap();
            assert_eq!(&data, b"ping");
        }
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let first_port = first.local_addr().unwrap().port();
        let second_port = second.local_addr().unwrap().port();
        first.set_nonblocking(true).unwrap(); second.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            std::thread::scope(|scope| {
                while !server_stop.load(Ordering::Relaxed) {
                    for listener in [&first, &second] {
                        if let Ok((mut stream, _)) = listener.accept() {
                            let stop = Arc::clone(&server_stop);
                            scope.spawn(move || {
                                stream.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
                                let mut bytes = [0; 64];
                                while !stop.load(Ordering::Relaxed) {
                                    match stream.read(&mut bytes) {
                                        Ok(0) => break,
                                        Ok(n) => { if stream.write_all(&bytes[..n]).is_err() { break; } }
                                        Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                                        Err(_) => break,
                                    }
                                }
                            });
                        }
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            });
        });
        struct StopOnDrop(Arc<AtomicBool>);
        impl Drop for StopOnDrop { fn drop(&mut self) { self.0.store(true, Ordering::Relaxed); } }
        let guard = StopOnDrop(Arc::clone(&stop));
        let mixed = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = mixed.local_addr().unwrap().port();
        let dir = temp_dir("real-node-switch");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        let config = format!("mixed-port: {port}\nmode: rule\nproxies:\n  - {{name: old, type: direct}}\n  - {{name: new, type: direct}}\n  - {{name: other, type: direct}}\nproxy-groups:\n  - {{name: Switching, type: select, proxies: [old, new]}}\n  - {{name: Unrelated, type: select, proxies: [other]}}\nrules:\n  - DST-PORT,{first_port},Switching\n  - MATCH,Unrelated\n");
        book.add_local("test", &config);
        let mut runtime = ProcessRuntime::new(&dir.0);
        runtime.home_dir = dir.0.join("home");
        runtime.set_kernel_path(Some(PathBuf::from(std::env::var_os("BILLOW_TEST_KERNEL").expect("test kernel"))));
        drop(mixed);
        let initial = book.enable("p1", &RejectSource, &mut runtime);
        assert!(initial.failure.is_none(), "isolated core did not start");
        let mut old = tunnel(port, first_port);
        let mut other = tunnel(port, second_port);
        echo(&mut old); echo(&mut other);
        let selected = book.select_node("Switching", "new", &mut runtime);
        assert!(selected.nodes_error.is_none() && selected.notice.is_none());
        let mut byte = [0];
        match old.read(&mut byte) {
            Ok(0) => {}
            Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted) => {}
            other => panic!("old stream was not closed: {other:?}"),
        }
        echo(&mut other);
        let mut new = tunnel(port, first_port); echo(&mut new);
        let connections = runtime.connections();
        assert!(connections.iter().any(|connection| connection.chains.iter().any(|name| name == "new")));
        drop((old, other, new));
        runtime.stop();
        drop(guard);
        server.join().unwrap();
    }

    #[test]
    fn repeated_anchor_names_do_not_rebind_urls_to_an_unrelated_mapping() {
        let content = "base: &BaseProvider {type: http}\nproxy-providers:\n  first: {<<: *BaseProvider, url: &Subscription 'https://example.com/first'}\n  second: {<<: *BaseProvider, url: &Subscription 'https://example.com/second'}\n  chained: {<<: *BaseProvider, url: *Subscription}\nother: &Other {type: select}\n";
        let config = parse_yaml(content).unwrap();
        assert_eq!(config["proxy-providers"]["chained"]["url"].as_str(), Some("https://example.com/second"));
        assert_eq!(config["proxy-providers"]["first"]["url"].as_str(), Some("https://example.com/first"));
        for (first, second) in [("one", "two"), ("[one]", "[two]"), ("{key: one}", "{key: two}")] {
            let text = format!("first: &same {first}\nbefore: *same\nsecond: &same {second}\nafter: *same\nother: &other {{kind: unrelated}}\n");
            let parsed = parse_yaml(&text).unwrap();
            assert_eq!(parsed["before"], parsed["first"], "earlier aliases retain their original definition");
            assert_eq!(parsed["after"], parsed["second"], "later aliases follow the nearest preceding definition");
        }
        let prepared = prepare(content, "").unwrap_or_else(|_| panic!("valid repeated anchors"));
        let (yaml, _) = apply_settings(&prepared.yaml, &KernelSettings::default(), true).unwrap();
        let final_config: Value = serde_yaml::from_str(&nodes::ensure_controller(&yaml)).unwrap();
        assert_eq!(final_config["proxy-providers"]["chained"]["url"].as_str(), Some("https://example.com/second"));
    }

    #[test]
    fn provider_urls_keep_scalar_types_through_aliases_overrides_and_runtime_settings() {
        let content = "provider-url: &provider-url 'https://example.com/sub?token=test'\nhttp-provider: &http-provider\n  type: http\n  url: *provider-url\nproxy-providers:\n  inherited:\n    <<: *http-provider\n  explicit:\n    <<: *http-provider\n    url: 'https://example.org/other'\nproxy-groups:\n  - {name: Select, type: select, use: [inherited, explicit]}\n";
        for overlay in ["", "proxy-providers:\n  inherited:\n    url: 'https://example.net/override'\n"] {
            let prepared = prepare(content, overlay).unwrap_or_else(|_| panic!("valid provider YAML"));
            let (yaml, _) = apply_settings(&prepared.yaml, &KernelSettings::default(), true).unwrap();
            let yaml = ensure_tun_dns(&yaml, &KernelSettings::default()).unwrap();
            let yaml = nodes::ensure_controller(&nodes::prioritize_selections(&yaml, &BTreeMap::new()));
            let final_config: Value = serde_yaml::from_str(&yaml).unwrap();
            let expected = if overlay.is_empty() { "https://example.com/sub?token=test" } else { "https://example.net/override" };
            assert_eq!(final_config["proxy-providers"]["inherited"]["url"].as_str(), Some(expected));
            assert_eq!(final_config["proxy-providers"]["explicit"]["url"].as_str(), Some("https://example.org/other"));
        }
        // A URL mapping has no unambiguous string value; rewriting it would invent
        // an address. Preserve the input for the kernel's explicit type diagnostic.
        let invalid = "proxy-providers:\n  broken:\n    type: http\n    url: {subscription: null}\n";
        let prepared = prepare(invalid, "").unwrap_or_else(|_| panic!("syntactically valid YAML"));
        let output: Value = serde_yaml::from_str(&prepared.yaml).unwrap();
        assert!(output["proxy-providers"]["broken"]["url"].is_mapping());
    }

    #[test]
    fn prepared_configs_resolve_merge_keys_like_the_kernel() {
        let content = "p: &p {type: http, interval: 86400, behavior: classical}
proxies: []
rule-providers:
  a: {<<: *p, url: 'https://x/a.yaml'}
proxy-groups:
  - {<<: {type: select}, name: G, proxies: [DIRECT]}
";
        let Ok(prepared) = prepare(content, "") else { panic!("config should prepare") };
        let value: Value = serde_yaml::from_str(&prepared.yaml).unwrap();
        assert_eq!(value["rule-providers"]["a"]["type"].as_str(), Some("http"));
        assert_eq!(value["rule-providers"]["a"]["url"].as_str(), Some("https://x/a.yaml"));
        assert_eq!(value["proxy-groups"][0]["type"].as_str(), Some("select"));
        assert!(!prepared.yaml.contains("<<"), "{}", prepared.yaml);
    }

    #[test]
    fn listener_failures_explain_the_port_or_tun_conflict() {
        let mixed = friendly_listen_error(
            "Start Mixed(http+socks) server error: listen tcp 127.0.0.1:7890: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted.",
        );
        assert!(mixed.starts_with("端口 127.0.0.1:7890 已被其他程序占用"), "{mixed}");
        let unix = friendly_listen_error("Start Mixed(http+socks) server error: listen tcp 127.0.0.1:7891: bind: address already in use");
        assert!(unix.contains("127.0.0.1:7891"));
        let denied = friendly_listen_error("Start TUN listening error: configure tun interface: Access is denied.");
        assert!(denied.contains("管理员权限"));
        let clash = friendly_listen_error("Start TUN listening error: Cannot create a file when that file already exists.");
        assert!(clash.contains("另一个代理客户端"));
        assert_eq!(friendly_listen_error("something else"), "something else");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn only_app_managed_kernels_are_swept() {
        let kernel = PathBuf::from(r"C:\Users\a\AppData\Roaming\app.billow.client\kernels\files\abc\core.exe");
        assert_eq!(kernel_root(&kernel), Some(PathBuf::from(r"C:\Users\a\AppData\Roaming\app.billow.client\kernels")));
        assert_eq!(kernel_root(&PathBuf::from(r"C:\tools\mihomo.exe")), None);
    }

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(name: &str) -> TempDir {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "billow-profile-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    struct MapSource {
        items: HashMap<String, Result<FetchedSubscription, String>>,
    }

    impl SubscriptionSource for MapSource {
        fn fetch(&self, url: &str) -> Result<FetchedSubscription, String> {
            self.items
                .get(url)
                .cloned()
                .unwrap_or(Err(FETCH_ERROR.to_string()))
        }
    }

    struct RejectSource;

    impl SubscriptionSource for RejectSource {
        fn fetch(&self, _url: &str) -> Result<FetchedSubscription, String> {
            Err(FETCH_ERROR.to_string())
        }
    }

    struct FakeKernel {
        running: Option<String>,
        fail: bool,
        calls: u32,
    }

    impl KernelLaunch for FakeKernel {
        fn start_or_reload(&mut self, config_yaml: &str) -> Result<(), String> {
            self.calls += 1;
            if self.fail {
                return Err(KERNEL_ERROR.to_string());
            }
            self.running = Some(config_yaml.to_string());
            Ok(())
        }
    }

    fn config(port: i64) -> String {
        format!("mixed-port: {port}\nmode: rule\nproxies: []\n")
    }

    #[test]
    fn activating_profiles_preserves_the_desktop_tun_session() {
        for action in ["enable", "update", "refresh"] {
            for enabled in [false, true] {
                for incoming in ["", "tun:\n  enable: false\n", "tun:\n  enable: true\n  file-descriptor: 42\n"] {
                    let dir = temp_dir("activate-tun");
                    let mut book = ProfileBook::open(&dir.0);
                    book.set_platform(ClientPlatform::Desktop);
                    book.add_local("initial.yaml", &config(7890));
                    book.add_subscription("https://example.com/sub");
                    let source = MapSource { items: HashMap::from([(
                        "https://example.com/sub".to_string(),
                        Ok(FetchedSubscription { content: format!("{}{incoming}", config(7890)), userinfo: None }),
                    )]) };
                    let mut kernel = ModeKernel { alive: false, fail_mode: false, last: String::new(), up: 0, down: 0 };
                    let mut proxy = MemoryProxy::default();
                    let mut tun = MemoryTun::default();
                    let mut vpn = MemoryVpn::default();
                    book.enable("p1", &RejectSource, &mut kernel);
                    if action == "refresh" {
                        book.enable("p2", &source, &mut kernel);
                    }
                    if enabled {
                        book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
                    } else {
                        // A remembered preference must not reconnect a disconnected session.
                        book.tun_wanted = true;
                    }
                    let next = match action {
                        "enable" => book.enable("p2", &source, &mut kernel),
                        "update" => book.update("p2", &source, &mut kernel),
                        _ => book.refresh_profile("p2", &source, &mut kernel),
                    };
                    let value: Value = serde_yaml::from_str(&kernel.last).unwrap();
                    assert_eq!(value["tun"]["enable"].as_bool(), Some(enabled), "{action}, incoming: {incoming:?}");
                    assert!(value["tun"].get("file-descriptor").is_none());
                    assert_eq!(next.tun, enabled);
                    assert_eq!(next.connected, enabled);
                    assert!(!next.system_proxy);
                    assert!(next.failure.is_none());
                    assert_eq!(book.effective_config().unwrap(), kernel.last);
                    if enabled {
                        assert_eq!(value["dns"]["enable"].as_bool(), Some(true));
                    }
                }
            }
        }
    }

    #[test]
    fn profile_changes_keep_the_system_proxy_on_the_live_listener() {
        for action in ["enable", "update", "refresh", "edit"] {
            let dir = temp_dir("reload-proxy-port");
            let mut book = ProfileBook::open(&dir.0);
            book.set_platform(ClientPlatform::Desktop);
            book.add_subscription("https://example.com/sub");
            let mut source = MapSource { items: HashMap::from([(
                "https://example.com/sub".to_string(),
                Ok(FetchedSubscription { content: config(7890), userinfo: None }),
            )]) };
            let mut kernel = ModeKernel { alive: false, fail_mode: false, last: String::new(), up: 0, down: 0 };
            let mut proxy = MemoryProxy::default();
            let mut tun = MemoryTun::default();
            let mut vpn = MemoryVpn::default();
            book.enable("p1", &source, &mut kernel);
            book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
            source.items.insert("https://example.com/sub".to_string(), Ok(FetchedSubscription { content: config(7891), userinfo: None }));
            match action {
                "enable" => {
                    book.add_local("next.yaml", &config(7891));
                    book.enable("p2", &source, &mut kernel);
                }
                "update" => { book.update("p1", &source, &mut kernel); }
                "refresh" => { book.refresh_profile("p1", &source, &mut kernel); }
                _ => { book.save_profile_content("p1", &config(7891), &mut kernel); }
            }
            book.reconcile_system_proxy(&mut proxy);
            assert_eq!(proxy.http.as_ref().unwrap().port, 7891, "{action}");
            assert_eq!(proxy.https.as_ref().unwrap().port, 7891);
            let sets = proxy.sets;
            book.reconcile_system_proxy(&mut proxy);
            assert_eq!(proxy.sets, sets, "unchanged endpoints need no OS writes");
            book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
            book.reconcile_system_proxy(&mut proxy);
            assert!(proxy.http.is_none() && proxy.https.is_none());
        }
    }

    #[test]
    fn refresh_settings_and_rule_reload_preserve_the_selected_mode() {
        let dir = temp_dir("reload-mode");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_subscription("https://example.com/sub");
        let source = MapSource { items: HashMap::from([(
            "https://example.com/sub".to_string(),
            Ok(FetchedSubscription { content: format!("{}rules:\n  - MATCH,DIRECT\n", config(7890)), userinfo: None }),
        )]) };
        let mut kernel = ModeKernel { alive: false, fail_mode: false, last: String::new(), up: 0, down: 0 };
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        book.enable("p1", &source, &mut kernel);
        book.set_outbound_mode("global", &mut kernel);
        assert_eq!(yaml_mode(&book.effective_config().unwrap()).as_deref(), Some("global"));
        book.set_rule_disabled(RuleToggle { key: diagnostics::rule_key("Match", "", "DIRECT", 0), disabled: true }, &mut kernel).unwrap();
        assert_eq!(yaml_mode(&kernel.last).as_deref(), Some("global"));
        book.refresh_profile("p1", &source, &mut kernel);
        assert_eq!(yaml_mode(&kernel.last).as_deref(), Some("global"));
        let mut settings = book.settings.clone();
        settings.log_level = Some("debug".to_string());
        let next = book.save_settings(settings, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert_eq!(next.mode.as_deref(), Some("global"));
        assert_eq!(yaml_mode(&kernel.last).as_deref(), Some("global"));
        kernel.fail_mode = true;
        book.set_outbound_mode("direct", &mut kernel);
        assert_eq!(yaml_mode(&book.effective_config().unwrap()).as_deref(), Some("global"));
    }

    #[test]
    fn desktop_mixed_port_never_collides_with_legacy_listeners() {
        // Subscription with `port: 7890` + `socks-port: 7891` and no `mixed-port`:
        // promoting `port` to `mixed-port` must drop `port` so mihomo does not bind 7890 twice.
        let source = "port: 7890\nsocks-port: 7891\nmode: rule\n";
        let (yaml, mixed) = apply_settings(source, &KernelSettings::default(), true).unwrap();
        let value: Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(mixed, Some(7890));
        assert_eq!(value["mixed-port"].as_i64(), Some(7890));
        assert!(mapping_get(&value, "port").is_none());
        assert_eq!(value["socks-port"].as_i64(), Some(7891));

        // Explicit `settings.mixed_port` override replaces both `port` and `socks-port`.
        let override_settings = KernelSettings {
            mixed_port: Some(7891),
            ..Default::default()
        };
        let (overridden, over_mixed) = apply_settings(source, &override_settings, true).unwrap();
        let over_val: Value = serde_yaml::from_str(&overridden).unwrap();
        assert_eq!(over_mixed, Some(7891));
        assert_eq!(over_val["mixed-port"].as_i64(), Some(7891));
        assert!(mapping_get(&over_val, "port").is_none());
        assert!(mapping_get(&over_val, "socks-port").is_none());
    }

    #[test]
    fn mobile_runtime_owns_its_listeners_and_leaves_routing_to_vpn_service() {
        let source = "mixed-port: 7890\nport: 7891\nexternal-controller: 127.0.0.1:9090\ntun: {enable: true, auto-route: true, auto-detect-interface: true}\n";
        let (yaml, mixed) = apply_settings(source, &KernelSettings::default(), false).unwrap();
        let value: Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(mixed, Some(7890));
        assert_eq!(value["port"].as_i64(), Some(0));
        assert_eq!(value["tun"]["enable"].as_bool(), Some(false));
        assert_eq!(value["tun"]["auto-route"].as_bool(), Some(false));
        assert_eq!(value["tun"]["auto-detect-interface"].as_bool(), Some(false));
        assert!(value["external-controller"].as_str().unwrap().starts_with("127.0.0.1:"));
        let again = apply_settings(source, &KernelSettings::default(), false).unwrap();
        assert_eq!(again, (yaml, mixed));
    }

    #[test]
    fn cached_metadata_tracks_saved_content_and_only_applied_overrides() {
        let dir = temp_dir("metadata");
        let mut book = ProfileBook::open(&dir.0);
        let yaml = |port, node: &str| format!(
            "mixed-port: {port}\nproxies: [{{name: {node}, type: ss}}]\nproxy-groups: [{{name: manual, type: select, proxies: [{node}]}}]\n"
        );
        book.add_local("a.yaml", &yaml(7890, "first"));
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };
        book.enable("p1", &RejectSource, &mut kernel);
        let before = book.snapshot();
        assert_eq!(before.config_values.mixed_port, Some(7890));
        assert_eq!(before.node_catalog[0].nodes[0].name, "first");
        assert!(book.profiles[0].node_metadata.get().is_some());

        let edited = book.save_profile_content("p1", &yaml(7999, "second"), &mut kernel);
        assert_eq!(edited.config_values.mixed_port, Some(7999));
        assert_eq!(edited.node_catalog[0].nodes[0].name, "second");
        let draft = book.save_override("p1", "mixed-port: 8001\n");
        assert_eq!(draft.config_values.mixed_port, Some(7999), "draft is not applied yet");
        let applied = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(applied.config_values.mixed_port, Some(8001));
        book.save_override("p1", "[\n");
        let rejected = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(rejected.config_values.mixed_port, Some(8001));

        let payload = serde_json::to_value(book.snapshot()).unwrap();
        assert!(payload.get("node_groups").is_none(), "IPC sends one catalog, not two copies");
        assert_eq!(payload["node_catalog"][0]["nodes"][0]["name"], "second");
    }

    #[test]
    fn android_package_list_is_cached_between_traffic_polls_and_retries_after_expiry() {
        struct Apps { reads: usize, fail: bool }
        impl takeover::InstalledApps for Apps {
            fn list(&mut self) -> Result<Vec<takeover::InstalledApp>, String> {
                self.reads += 1;
                if self.fail { return Err("unavailable".to_string()); }
                Ok(vec![takeover::InstalledApp { name: "Browser".to_string(), package_name: "app.browser".to_string(), system: false }])
            }
        }
        let dir = temp_dir("package-cache");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Android);
        let mut apps = Apps { reads: 0, fail: false };
        for _ in 0..60 { book.refresh_installed(&mut apps); }
        assert_eq!(apps.reads, 1);
        assert_eq!(book.snapshot().installed.len(), 1);
        book.installed_checked_at = Some(Instant::now() - Duration::from_secs(61));
        apps.fail = true;
        for _ in 0..60 { book.refresh_installed(&mut apps); }
        assert_eq!(apps.reads, 2);
        assert_eq!(book.snapshot().installed.len(), 1, "a failed refresh preserves the last list");
        book.installed_checked_at = Some(Instant::now() - Duration::from_secs(61));
        apps.fail = false;
        book.refresh_installed(&mut apps);
        assert_eq!(apps.reads, 3);
    }

    #[test]
    #[ignore = "manual subscription refresh and reopen benchmark"]
    fn benchmark_subscription_refresh_and_reopen() {
        let dir = temp_dir("refresh-bench");
        let mut book = ProfileBook::open(&dir.0);
        let mut content = String::from("mixed-port: 7890\nproxies:\n");
        for i in 0..3000 {
            content.push_str(&format!("  - {{name: node-{i}, type: ss, server: node-{i}.example, port: 443}}\n"));
        }
        let mut source = MapSource { items: HashMap::new() };
        for i in 0..8 {
            let url = format!("https://s{i}.example/sub");
            book.add_subscription(&url);
            source.items.insert(url, Ok(FetchedSubscription { content: content.clone(), userinfo: None }));
        }
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };
        let start = Instant::now();
        for i in 1..=8 {
            let result = book.refresh_profile(&format!("p{i}"), &source, &mut kernel);
            assert_eq!(result.profiles[i - 1].proxy_count, 3000);
        }
        let refresh_ms = start.elapsed().as_millis();
        drop(book);
        let start = Instant::now();
        let opened = ProfileBook::open(&dir.0);
        assert_eq!(opened.profiles.iter().map(|p| p.proxy_count).sum::<usize>(), 24000);
        eprintln!("refresh_ms={refresh_ms} open_ms={}", start.elapsed().as_millis());
    }

    #[test]
    #[ignore = "manual snapshot benchmark; no timing assertion on shared runners"]
    fn benchmark_cached_snapshot() {
        let dir = temp_dir("snapshot-bench");
        let mut book = ProfileBook::open(&dir.0);
        let names: Vec<String> = (0..500).map(|i| format!("node-{i}")).collect();
        let mut yaml = String::from("mixed-port: 7890\nproxies:\n");
        for name in &names { yaml.push_str(&format!("  - {{name: {name}, type: ss}}\n")); }
        yaml.push_str("proxy-groups:\n");
        for i in 0..16 {
            yaml.push_str(&format!("  - {{name: group-{i}, type: select, proxies: [{}]}}\n", names.join(", ")));
        }
        book.add_local("benchmark.yaml", &yaml);
        let start = Instant::now();
        let mut bytes = 0;
        for _ in 0..100 {
            bytes = serde_json::to_vec(&book.snapshot()).unwrap().len();
        }
        eprintln!("8000-node snapshot+JSON: {:.2} ms/op, {bytes} bytes", start.elapsed().as_secs_f64() * 10.0);
        let start = Instant::now();
        for _ in 0..100 {
            book.profiles[0].node_metadata.take();
            std::hint::black_box(serde_json::to_vec(&book.snapshot()).unwrap());
        }
        eprintln!("8000-node snapshot+JSON with YAML reparse: {:.2} ms/op", start.elapsed().as_secs_f64() * 10.0);
    }

    #[test]
    fn delete_rename_and_edit_manage_saved_profiles() {
        let dir = temp_dir("manage");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", &config(7890));
        book.add_local("b.yaml", &config(7891));
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };
        book.enable("p1", &RejectSource, &mut kernel);

        let renamed = book.rename_profile("p2", "  办公  ");
        assert_eq!(renamed.profiles[1].name, "办公");

        let bad = book.save_profile_content("p2", "- not a map", &mut kernel);
        assert!(bad.input_error.is_some());
        assert_eq!(book.profile_content("p2").unwrap(), config(7891));
        book.save_profile_content("p2", "mixed-port: 7000\nproxies:\n  - {name: a, type: ss}\n", &mut kernel);
        let listed = book.snapshot();
        assert_eq!(listed.profiles[1].proxy_count, 1);

        let removed = book.delete_profile("p2");
        assert_eq!(removed.profiles.len(), 1);
        let reopened = ProfileBook::open(&dir.0).snapshot();
        assert_eq!(reopened.profiles.len(), 1);
        assert_eq!(reopened.profiles[0].id, "p1");
    }

    #[test]
    fn kernel_settings_overwrite_the_profile_and_a_missing_port_gets_a_default() {
        let dir = temp_dir("settings");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", "mode: rule\nproxies: []\n");
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };
        let enabled = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(enabled.mixed_port, Some(7890));

        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let settings = KernelSettings {
            mixed_port: Some(7999),
            allow_lan: Some(true),
            log_level: Some("WARNING".to_string()),
            test_url: "ftp://nope".to_string(),
            ..Default::default()
        };
        let saved = book.save_settings(settings, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert_eq!(saved.settings.log_level.as_deref(), Some("warning"));
        assert!(saved.settings.test_url.is_empty());
        let again = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(again.mixed_port, Some(7999));
        let running: Value = serde_yaml::from_str(kernel.running.as_deref().unwrap()).unwrap();
        assert_eq!(read_i64(&running, "mixed-port"), Some(7999));
        assert_eq!(mapping_get(&running, "allow-lan").and_then(Value::as_bool), Some(true));
        assert_eq!(ProfileBook::open(&dir.0).snapshot().settings.mixed_port, Some(7999));
    }

    #[test]
    fn geo_settings_override_auto_update_interval_and_source() {
        let base = "mixed-port: 7890\ngeox-url:\n  geoip: https://mine/geoip.dat\n";
        let (kept, _) = apply_settings(base, &KernelSettings::default(), true).unwrap();
        let kept: Value = serde_yaml::from_str(&kept).unwrap();
        assert_eq!(read_string(mapping_get(&kept, "geox-url").unwrap(), "geoip").as_deref(), Some("https://mine/geoip.dat"));
        assert!(mapping_get(&kept, "geo-auto-update").is_none());

        let settings = KernelSettings {
            geo_auto_update: Some(true),
            geo_update_interval: Some(72),
            geo_source: "jsdelivr".to_string(),
            ..Default::default()
        };
        let (yaml, _) = apply_settings(base, &settings, true).unwrap();
        let value: Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(mapping_get(&value, "geo-auto-update").and_then(Value::as_bool), Some(true));
        assert_eq!(read_i64(&value, "geo-update-interval"), Some(72));
        let geox = mapping_get(&value, "geox-url").unwrap();
        assert_eq!(
            read_string(geox, "geosite").as_deref(),
            Some("https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat")
        );
        assert!(read_string(geox, "asn").unwrap().ends_with("GeoLite2-ASN.mmdb"));
    }

    #[test]
    fn lan_access_fingerprint_and_keep_alive_reach_the_running_config() {
        let dir = temp_dir("lan-access");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\nproxies: []\nskip-auth-prefixes: [10.0.0.0/8]\n");
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun_grant = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let settings = KernelSettings {
            keep_alive_interval: Some(2),
            lan_auth: vec!["alice:pw".into(), "broken".into(), "alice:again".into(), "bob:has space".into()],
            lan_allowed_ips: vec!["192.168.1.0/24".into(), "10.0.0.5".into(), "nope".into(), "1.2.3.4/40".into()],
            ..Default::default()
        };
        let saved = book.save_settings(settings, &mut kernel, &mut proxy, &mut tun_grant, &mut vpn);
        assert_eq!(saved.settings.keep_alive_interval, Some(5), "intervals below 5 s are clamped");
        assert_eq!(saved.settings.lan_auth, ["alice:pw"]);
        assert_eq!(saved.settings.lan_allowed_ips, ["192.168.1.0/24", "10.0.0.5/32"]);

        let (yaml, _) = book.kernel_yaml(false, None).ok().unwrap();
        let running: Value = serde_yaml::from_str(&yaml).unwrap();
        let strings = |name: &str| -> Vec<String> {
            mapping_get(&running, name)
                .and_then(Value::as_sequence)
                .map(|seq| seq.iter().filter_map(Value::as_str).map(str::to_string).collect())
                .unwrap_or_default()
        };
        assert!(mapping_get(&running, "global-client-fingerprint").is_none(), "removed from mihomo; never written");
        assert_eq!(read_i64(&running, "keep-alive-interval"), Some(5));
        assert_eq!(mapping_get(&running, "disable-keep-alive").and_then(Value::as_bool), Some(false));
        assert_eq!(strings("authentication"), ["alice:pw"]);
        // The profile's own exemptions survive; loopback is added so local apps never need a password.
        assert_eq!(strings("skip-auth-prefixes"), ["10.0.0.0/8", "127.0.0.1/8", "::1/128"]);
        assert_eq!(strings("lan-allowed-ips"), ["192.168.1.0/24", "10.0.0.5/32", "127.0.0.1/8", "::1/128"]);

        let off = KernelSettings { keep_alive_interval: Some(0), lan_auth: Vec::new(), ..saved.settings.clone() };
        book.save_settings(off, &mut kernel, &mut proxy, &mut tun_grant, &mut vpn);
        let (yaml, _) = book.kernel_yaml(false, None).ok().unwrap();
        let running: Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(mapping_get(&running, "disable-keep-alive").and_then(Value::as_bool), Some(true));
        assert!(mapping_get(&running, "keep-alive-interval").is_none());
        assert!(mapping_get(&running, "authentication").is_none(), "clearing the users drops the block");
    }

    #[test]
    fn tun_stack_accepts_mips_and_empty_follows_the_kernel() {
        let normalized = |stack: &str| TunSettings { stack: stack.to_string(), ..TunSettings::default() }.normalized().stack;
        assert_eq!(TunSettings::default().stack, "");
        assert_eq!(normalized("MIPS"), "mips");
        assert_eq!(normalized("mixed"), "mixed");
        assert_eq!(normalized("bogus"), "", "unknown stacks fall back to the kernel default");
    }

    fn save_with(book: &mut ProfileBook, kernel: &mut FakeKernel, settings: KernelSettings) -> ProfileSnapshot {
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        book.save_settings(settings, kernel, &mut proxy, &mut tun, &mut vpn)
    }

    fn yaml_list(value: Option<&Value>) -> Vec<String> {
        yaml_strings(value).unwrap_or_default()
    }

    #[test]
    fn tun_route_addresses_reach_desktop_and_bad_entries_are_named() {
        let dir = temp_dir("tun-route");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("a.yaml", "mixed-port: 7890\nproxies: []\ntun:\n  route-exclude-address: [10.0.0.0/8]\n");
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };
        let enabled = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(enabled.config_values.tun_route_exclude_address, Some(vec!["10.0.0.0/8".to_string()]));

        let tun = TunSettings { route_exclude_address: Some(vec!["192.168.0.0/16".into(), "1.1.1.1".into()]), ..TunSettings::default() };
        let saved = save_with(&mut book, &mut kernel, KernelSettings { tun, ..Default::default() });
        assert_eq!(saved.input_error, None);
        assert_eq!(saved.settings.tun.route_exclude_address, Some(vec!["192.168.0.0/16".to_string(), "1.1.1.1/32".to_string()]));
        assert_eq!(saved.settings.tun.route_address, None);
        let (yaml, _) = book.kernel_yaml(false, None).ok().unwrap();
        let running: Value = serde_yaml::from_str(&yaml).unwrap();
        let tun_block = mapping_get(&running, "tun").unwrap();
        assert_eq!(yaml_list(mapping_get(tun_block, "route-exclude-address")), ["192.168.0.0/16", "1.1.1.1/32"]);
        assert!(mapping_get(tun_block, "route-address").is_none(), "None follows the profile");

        let bad = TunSettings { route_exclude_address: Some(vec!["300.1.1.0/24".into()]), ..TunSettings::default() };
        let refused = save_with(&mut book, &mut kernel, KernelSettings { tun: bad, ..Default::default() });
        assert!(refused.input_error.as_deref().unwrap().contains("300.1.1.0/24"), "{:?}", refused.input_error);
        assert_eq!(refused.settings.tun.route_exclude_address.as_ref().unwrap()[0], "192.168.0.0/16", "nothing saved");

        // Android hands routing to the VPN service; the lists are never written there.
        let settings = KernelSettings {
            tun: TunSettings { route_address: Some(vec!["1.0.0.0/8".into()]), ..TunSettings::default() },
            ..Default::default()
        };
        let (android, _) = apply_settings("mixed-port: 7890\n", &settings, false).unwrap();
        assert!(!android.contains("route-address"), "{android}");
        let (desktop, _) = apply_settings("mixed-port: 7890\n", &settings, true).unwrap();
        assert!(desktop.contains("route-address"), "{desktop}");
    }

    #[test]
    fn sniff_details_layer_on_the_final_sniffer_block_only_while_it_is_on() {
        let profile = "mixed-port: 7890\nsniffer:\n  enable: true\n  sniff:\n    HTTP:\n      ports: [80]\n      override-destination: true\n    TLS:\n      ports: [443]\n  skip-domain: [a.example]\n";
        let settings = KernelSettings {
            sniff_ports: SniffPorts { tls: Some(vec!["443".into(), " 8443 ".into()]), quic: Some(vec!["443".into(), "8000-9000".into()]), http: None },
            sniff_force_domain: Some(vec!["+.force.example".into(), "".into()]),
            sniff_override_destination: Some(false),
            ..Default::default()
        }
        .normalized();
        assert_eq!(settings.sniff_ports.tls, Some(vec!["443".to_string(), "8443".to_string()]));
        assert_eq!(settings.sniff_force_domain, Some(vec!["+.force.example".to_string()]));

        // Following the profile's enabled block: details are added, the rest is kept.
        let (yaml, _) = apply_settings(profile, &settings, true).unwrap();
        let value: Value = serde_yaml::from_str(&yaml).unwrap();
        let sniffer = mapping_get(&value, "sniffer").unwrap();
        let sniff = mapping_get(sniffer, "sniff").unwrap();
        let tls = mapping_get(mapping_get(sniff, "TLS").unwrap(), "ports").and_then(Value::as_sequence).unwrap();
        assert_eq!(tls.iter().filter_map(Value::as_i64).collect::<Vec<_>>(), [443, 8443]);
        assert_eq!(yaml_list(mapping_get(mapping_get(sniff, "QUIC").unwrap(), "ports")), ["443", "8000-9000"]);
        assert_eq!(yaml_list(mapping_get(mapping_get(sniff, "HTTP").unwrap(), "ports")), ["80"], "unset protocols keep the profile's");
        assert_eq!(yaml_list(mapping_get(sniffer, "force-domain")), ["+.force.example"]);
        assert_eq!(yaml_list(mapping_get(sniffer, "skip-domain")), ["a.example"]);
        assert_eq!(mapping_get(sniffer, "override-destination").and_then(Value::as_bool), Some(false));
        assert_eq!(
            mapping_get(mapping_get(sniff, "HTTP").unwrap(), "override-destination").and_then(Value::as_bool),
            Some(false),
            "per-protocol value follows the override"
        );

        // Billow's own default block takes the details too.
        let on = KernelSettings { sniffer: Some(true), ..settings.clone() };
        let (yaml, _) = apply_settings("mixed-port: 7890\n", &on, true).unwrap();
        let value: Value = serde_yaml::from_str(&yaml).unwrap();
        let sniffer = mapping_get(&value, "sniffer").unwrap();
        assert_eq!(yaml_list(mapping_get(mapping_get(mapping_get(sniffer, "sniff").unwrap(), "TLS").unwrap(), "ports")), ["443", "8443"]);

        // Switched off, or a profile without sniffing: details stay saved but are not written.
        let off = KernelSettings { sniffer: Some(false), ..settings.clone() };
        let (yaml, _) = apply_settings(profile, &off, true).unwrap();
        assert!(!yaml.contains("force-domain") && !yaml.contains("8443"), "{yaml}");
        let (yaml, _) = apply_settings("mixed-port: 7890\n", &settings, true).unwrap();
        assert!(!yaml.contains("sniffer"), "{yaml}");

        let bad = KernelSettings { sniff_ports: SniffPorts { tls: Some(vec!["70000".into()]), ..Default::default() }, ..Default::default() };
        assert!(bad.validate(Some(7890)).unwrap_err().contains("70000"));
        for entry in ["0", "9000-8000", "abc", "1-"] {
            assert_eq!(sniff_port_entry(entry), None, "{entry}");
        }
        assert_eq!(sniff_port_entry("8080 - 8880").as_deref(), Some("8080-8880"));
    }

    #[test]
    fn extra_inbound_ports_interface_and_routing_mark() {
        let dir = temp_dir("inbound");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("a.yaml", "mixed-port: 7890\nsocks-port: 7891\ninterface-name: en0\nrouting-mark: 6666\nsniffer: {enable: true}\nproxies: []\n");
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };
        let enabled = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(enabled.config_values.socks_port, Some(7891));
        assert_eq!(enabled.config_values.interface_name.as_deref(), Some("en0"));
        assert_eq!(enabled.config_values.routing_mark, Some(6666));
        assert_eq!(enabled.config_values.sniffer, Some(true));

        // HTTP on the old SOCKS port: explicit wins, the profile's colliding listener goes.
        let settings = KernelSettings {
            http_port: Some(7891),
            redir_port: Some(0),
            interface_name: Some("".into()),
            routing_mark: Some(0),
            ..Default::default()
        };
        let saved = save_with(&mut book, &mut kernel, settings);
        assert_eq!(saved.input_error, None);
        let (yaml, _) = book.kernel_yaml(false, None).ok().unwrap();
        let running: Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(read_i64(&running, "port"), Some(7891));
        assert_eq!(read_i64(&running, "socks-port"), None);
        assert_eq!(read_i64(&running, "redir-port"), Some(0));
        assert!(mapping_get(&running, "interface-name").is_none());
        assert!(mapping_get(&running, "routing-mark").is_none());

        // An explicit mixed port no longer strips an explicit SOCKS port.
        let settings = KernelSettings {
            mixed_port: Some(7990),
            socks_port: Some(7891),
            interface_name: Some("eth0".into()),
            routing_mark: Some(255),
            ..Default::default()
        };
        let saved = save_with(&mut book, &mut kernel, settings);
        assert_eq!(saved.input_error, None);
        let (yaml, _) = book.kernel_yaml(false, None).ok().unwrap();
        let running: Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(read_i64(&running, "socks-port"), Some(7891));
        assert_eq!(read_string(&running, "interface-name").as_deref(), Some("eth0"));
        assert_eq!(read_i64(&running, "routing-mark"), Some(255));

        // Conflicts are refused and name both sides; nothing is saved.
        let clash = save_with(&mut book, &mut kernel, KernelSettings { http_port: Some(7890), ..Default::default() });
        let message = clash.input_error.clone().unwrap();
        assert!(message.contains("HTTP 端口 7890") && message.contains("混合端口"), "{message}");
        assert_eq!(clash.settings.socks_port, Some(7891), "previous settings kept");

        // A saved port that later clashes (e.g. after a profile switch) does not block unrelated saves.
        let saved_ports = KernelSettings { socks_port: Some(7890), ..Default::default() };
        book.settings = saved_ports.clone();
        let unrelated = save_with(&mut book, &mut kernel, KernelSettings { log_level: Some("debug".into()), ..saved_ports });
        assert_eq!(unrelated.input_error, None, "unchanged ports are not re-checked against the mixed port");
        let touched = save_with(&mut book, &mut kernel, KernelSettings { socks_port: Some(7890), http_port: Some(8080), ..Default::default() });
        assert!(touched.input_error.unwrap().contains("混合端口"), "changing a port re-checks the clash");
        let pair = KernelSettings { socks_port: Some(1080), tproxy_port: Some(1080), ..Default::default() };
        let message = pair.validate(Some(7890)).unwrap_err();
        assert!(message.contains("tproxy 端口 1080") && message.contains("SOCKS 端口"), "{message}");
        let zeros = KernelSettings { socks_port: Some(0), http_port: Some(0), ..Default::default() };
        assert!(zeros.validate(Some(7890)).is_ok(), "0 turns a listener off and never conflicts");
        let spaced = KernelSettings { interface_name: Some("Wi Fi".into()), ..Default::default() };
        assert!(spaced.validate(Some(7890)).unwrap_err().contains("空格"));

        // Android keeps every extra listener off whatever is saved.
        let android = KernelSettings { socks_port: Some(1080), http_port: Some(8080), interface_name: Some("wlan0".into()), ..Default::default() };
        let (yaml, _) = apply_settings("mixed-port: 7890\n", &android, false).unwrap();
        let value: Value = serde_yaml::from_str(&yaml).unwrap();
        for name in ["port", "socks-port", "redir-port", "tproxy-port"] {
            assert_eq!(read_i64(&value, name), Some(0), "{name}");
        }
        assert!(mapping_get(&value, "interface-name").is_none());
    }

    #[test]
    fn listener_failures_name_the_port_kind() {
        let socks = friendly_listen_error("Start SOCKS server error: listen tcp 127.0.0.1:7891: bind: address already in use");
        assert!(socks.contains("127.0.0.1:7891") && socks.contains("更换SOCKS 端口"), "{socks}");
        let tproxy = friendly_listen_error("Start TProxy server error: listen tcp 0.0.0.0:7895: bind: address already in use");
        assert!(tproxy.contains("tproxy 端口"), "{tproxy}");
    }

    #[test]
    fn config_overview_reports_each_layer_and_masks_credentials() {
        let dir = temp_dir("overview");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local(
            "a.yaml",
            "mixed-port: 7890\nmode: rule\nlog-level: info\nallow-lan: false\nsecret: hunter2\n\
proxies:\n  - { name: a, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: sspass }\n  - { name: b, type: trojan, server: 1.1.1.1, port: 2, password: trpass }\n\
proxy-groups:\n  - { name: pick, type: select, proxies: [auto, a] }\n  - { name: auto, type: url-test, proxies: [a, b] }\n\
rules:\n  - MATCH,pick\n",
        );
        book.save_override("p1", "log-level: debug\n");
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun_grant = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let settings = KernelSettings { allow_lan: Some(true), lan_auth: vec!["alice:pw-secret".into()], ..Default::default() };
        book.save_settings(settings, &mut kernel, &mut proxy, &mut tun_grant, &mut vpn);

        let overview = book.config_overview().unwrap();
        assert_eq!(overview.profile["log-level"], "info");
        assert_eq!(overview.prepared["log-level"], "debug", "覆写 shows up before Billow's settings");
        assert_eq!(overview.effective["log-level"], "debug");
        assert_eq!(overview.prepared["allow-lan"], false);
        assert_eq!(overview.effective["allow-lan"], true, "Billow's setting wins in the running config");
        assert_eq!(overview.effective["authentication"], serde_json::json!(["alice:••••"]));
        assert!(overview.effective.get("proxies").is_none() && overview.effective.get("secret").is_none());
        assert_eq!(overview.counts.get("proxies"), Some(&2));
        assert_eq!(overview.counts.get("proxy-groups"), Some(&2));
        assert_eq!(overview.counts.get("rules"), Some(&1));
        assert_eq!(overview.group_types.get("select"), Some(&1));
        assert_eq!(overview.group_types.get("url-test"), Some(&1));
        let wire = serde_json::to_string(&overview).unwrap();
        for secret in ["hunter2", "sspass", "trpass", "pw-secret"] {
            assert!(!wire.contains(secret), "{secret} must not leave the backend");
        }
    }

    #[test]
    fn tun_gets_routing_and_dns_and_dns_override_replaces_the_profile_block() {
        let dir = temp_dir("tun-dns");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\nproxies: []\ndns:\n  enable: false\n  nameserver: [1.1.1.1]\n");
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };
        book.enable("p1", &RejectSource, &mut kernel);
        let (yaml, _) = book.kernel_yaml(true, None).ok().unwrap();
        let running: Value = serde_yaml::from_str(&yaml).unwrap();
        let tun = mapping_get(&running, "tun").unwrap();
        assert_eq!(mapping_get(tun, "enable").and_then(Value::as_bool), Some(true));
        assert_eq!(mapping_get(tun, "auto-route").and_then(Value::as_bool), Some(true));
        assert_eq!(read_string(tun, "stack"), None, "the default leaves the stack to the kernel (mips)");
        let dns = mapping_get(&running, "dns").unwrap();
        assert_eq!(mapping_get(dns, "enable").and_then(Value::as_bool), Some(true), "TUN turns DNS on");

        let (plain, _) = book.kernel_yaml(false, None).ok().unwrap();
        let plain: Value = serde_yaml::from_str(&plain).unwrap();
        assert_eq!(
            mapping_get(mapping_get(&plain, "dns").unwrap(), "enable").and_then(Value::as_bool),
            Some(false),
            "without TUN the profile's DNS stays as written"
        );

        let mut proxy = MemoryProxy::default();
        let mut tun_grant = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let mut settings = KernelSettings { dns_override: true, sniffer: Some(true), ..Default::default() };
        settings.dns.enhanced_mode = "redir-host".to_string();
        settings.dns.nameserver = vec![" https://1.1.1.1/dns-query ".to_string(), String::new()];
        settings.tun.stack = "GVISOR".to_string();
        let saved = book.save_settings(settings, &mut kernel, &mut proxy, &mut tun_grant, &mut vpn);
        assert_eq!(saved.settings.tun.stack, "gvisor");
        assert_eq!(saved.settings.dns.nameserver, ["https://1.1.1.1/dns-query"]);
        let (yaml, _) = book.kernel_yaml(false, None).ok().unwrap();
        let running: Value = serde_yaml::from_str(&yaml).unwrap();
        let dns = mapping_get(&running, "dns").unwrap();
        assert_eq!(read_string(dns, "enhanced-mode").as_deref(), Some("redir-host"));
        assert!(mapping_get(dns, "fake-ip-range").is_none());
        assert_eq!(mapping_get(mapping_get(&running, "sniffer").unwrap(), "enable").and_then(Value::as_bool), Some(true));
        assert_eq!(read_string(mapping_get(&running, "tun").unwrap(), "stack").as_deref(), Some("gvisor"));
    }

    #[test]
    fn subscriptions_with_an_interval_become_due_after_it_passes() {
        let dir = temp_dir("due");
        let mut book = ProfileBook::open(&dir.0);
        book.add_subscription("https://example.com/sub");
        book.add_local("a.yaml", &config(7890));
        assert!(book.due_profiles(now_ms()).is_empty());
        book.set_profile_interval("p1", 6);
        assert_eq!(book.due_profiles(now_ms()), ["p1"]);
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };
        let failed = book.refresh_profile("p1", &RejectSource, &mut kernel);
        assert_eq!(failed.profiles[0].failure.as_deref(), Some(FETCH_ERROR));
        assert!(book.due_profiles(now_ms()).is_empty());
        assert_eq!(book.due_profiles(now_ms() + 6 * 3_600_000), ["p1"]);
        assert_eq!(book.subscription_ids(), ["p1"]);
    }

    #[test]
    fn age_encrypted_subscriptions_need_a_matching_key_that_persists() {
        use age::secrecy::ExposeSecret;
        let dir = temp_dir("age");
        let url = "https://example.com/encrypted";
        let identity = age::x25519::Identity::generate();
        let armored = age::encrypt_and_armor(&identity.to_public(), config(7891).as_bytes()).unwrap();
        let source = MapSource {
            items: HashMap::from([(
                url.to_string(),
                Ok(FetchedSubscription { content: armored, userinfo: None }),
            )]),
        };
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };
        let mut book = ProfileBook::open(&dir.0);
        book.add_subscription(url);

        let missing = book.refresh_profile("p1", &source, &mut kernel);
        assert_eq!(missing.profiles[0].failure.as_deref(), Some(age_key::KEY_MISSING_ERROR));

        let bad = book.set_profile_age_key("p1", "AGE-SECRET-KEY-1NOPE");
        assert_eq!(bad.input_error.as_deref(), Some(age_key::KEY_FORMAT_ERROR));
        assert!(bad.profiles[0].age_recipients.is_empty());

        let secret = identity.to_string().expose_secret().to_string();
        let saved = book.set_profile_age_key("p1", &format!("# public key: {}\n{secret}\n", identity.to_public()));
        assert!(saved.input_error.is_none());
        assert_eq!(saved.profiles[0].age_recipients, [identity.to_public().to_string()]);

        let ok = book.refresh_profile("p1", &source, &mut kernel);
        assert!(ok.profiles[0].failure.is_none());
        assert_eq!(book.profile_content("p1").as_deref(), Some(config(7891).trim()));

        // The key survives a restart; the UI only ever sees the public key.
        let reopened = ProfileBook::open(&dir.0).snapshot();
        assert_eq!(reopened.profiles[0].age_recipients, [identity.to_public().to_string()]);
        let json = serde_json::to_string(&reopened).unwrap();
        assert!(!json.contains(&secret));

        // Clearing the key brings the explanation back on the next update.
        book.set_profile_age_key("p1", "");
        let cleared = book.refresh_profile("p1", &source, &mut kernel);
        assert_eq!(cleared.profiles[0].failure.as_deref(), Some(age_key::KEY_MISSING_ERROR));
    }

    fn current_ids(snapshot: &ProfileSnapshot) -> Vec<&str> {
        snapshot
            .profiles
            .iter()
            .filter(|profile| profile.current)
            .map(|profile| profile.id.as_str())
            .collect()
    }

    fn port_of(yaml: &str) -> i64 {
        let value: Value = serde_yaml::from_str(yaml).unwrap();
        read_i64(&value, "mixed-port").unwrap()
    }

    #[test]
    fn enabling_two_profiles_keeps_one_current_mark() {
        let dir = temp_dir("two");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", &config(7890));
        book.add_local("b.yaml", &config(7891));
        let mut kernel = FakeKernel {
            running: None,
            fail: false,
            calls: 0,
        };
        let first = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(current_ids(&first), ["p1"]);
        assert_eq!(first.active_id.as_deref(), Some("p1"));
        assert_eq!(first.mixed_port, Some(7890));
        assert!(
            first
                .profiles
                .iter()
                .all(|profile| profile.failure.is_none())
        );

        let second = book.enable("p2", &RejectSource, &mut kernel);
        assert_eq!(current_ids(&second), ["p2"]);
        assert_eq!(second.active_id.as_deref(), Some("p2"));
        assert_eq!(second.mixed_port, Some(7891));
        assert_eq!(port_of(kernel.running.as_deref().unwrap()), 7891);
        assert_eq!(kernel.calls, 2);

        let reopened = ProfileBook::open(&dir.0);
        let snapshot = reopened.snapshot();
        assert_eq!(current_ids(&snapshot), ["p2"]);
        assert_eq!(snapshot.mixed_port, Some(7891));
    }

    #[test]
    fn userinfo_records_usage_only_when_total_is_positive_and_skips_zero_expiry() {
        assert!(parse_userinfo(None).is_none());
        assert!(parse_userinfo(Some("")).is_none());
        assert!(parse_userinfo(Some("not a header")).is_none());
        assert!(parse_userinfo(Some("upload=1; download=2; total=0; expire=0")).is_none());

        let usage = parse_userinfo(Some(
            " upload = 10 ; download = 20 ; total = 100 ; expire = 0 ",
        ))
        .unwrap();
        assert_eq!(usage.used, Some(30));
        assert_eq!(usage.total, Some(100));
        assert_eq!(usage.expire, None);

        let expire_only = parse_userinfo(Some("total=0; expire=1700000000")).unwrap();
        assert_eq!(expire_only.used, None);
        assert_eq!(expire_only.total, None);
        assert_eq!(expire_only.expire, Some(1700000000));

        let dir = temp_dir("userinfo");
        let mut book = ProfileBook::open(&dir.0);
        book.add_subscription("https://example.com/sub");
        let mut source = MapSource {
            items: HashMap::new(),
        };
        source.items.insert(
            "https://example.com/sub".to_string(),
            Ok(FetchedSubscription {
                content: config(7890),
                userinfo: Some("upload=10; download=20; total=100; expire=0".to_string()),
            }),
        );
        let mut kernel = FakeKernel {
            running: None,
            fail: false,
            calls: 0,
        };
        let snapshot = book.enable("p1", &source, &mut kernel);
        let profile = &snapshot.profiles[0];
        assert_eq!(profile.used, Some(30));
        assert_eq!(profile.total, Some(100));
        assert_eq!(profile.expire, None);
        assert!(profile.current);

        source.items.insert(
            "https://example.com/plain".to_string(),
            Ok(FetchedSubscription {
                content: config(7892),
                userinfo: None,
            }),
        );
        book.add_subscription("https://example.com/plain");
        let snapshot = book.enable("p2", &source, &mut kernel);
        let plain = snapshot
            .profiles
            .iter()
            .find(|profile| profile.id == "p2")
            .unwrap();
        assert!(plain.used.is_none() && plain.total.is_none() && plain.expire.is_none());
        let encoded = base64::engine::general_purpose::STANDARD.encode(config(7001));
        source.items.insert(
            "https://example.com/b64".to_string(),
            Ok(FetchedSubscription {
                content: encoded,
                userinfo: Some("total=5; expire=9".to_string()),
            }),
        );
        book.add_subscription("https://example.com/b64");
        let snapshot = book.update("p3", &source, &mut kernel);
        assert_eq!(snapshot.mixed_port, Some(7001));
        let encoded_profile = snapshot
            .profiles
            .iter()
            .find(|profile| profile.id == "p3")
            .unwrap();
        assert_eq!(encoded_profile.used, Some(0));
        assert_eq!(encoded_profile.total, Some(5));
        assert_eq!(encoded_profile.expire, Some(9));
    }

    #[test]
    fn install_link_adds_only_after_confirm_and_does_not_enable() {
        let dir = temp_dir("link");
        let mut book = ProfileBook::open(&dir.0);
        let link = "billow://install-config?url=https%3A%2F%2Fexample.com%2Fsub";
        let staged = book.stage_install_link(link);
        assert_eq!(
            staged.pending_url.as_deref(),
            Some("https://example.com/sub")
        );
        assert!(staged.profiles.is_empty());
        assert!(staged.active_id.is_none());

        let cancelled = book.cancel_pending();
        assert!(cancelled.pending_url.is_none());
        assert!(cancelled.profiles.is_empty());

        book.stage_install_link(link);
        let confirmed = book.confirm_pending();
        assert!(confirmed.pending_url.is_none());
        assert_eq!(confirmed.profiles.len(), 1);
        assert_eq!(confirmed.profiles[0].kind, "subscription");
        assert_eq!(confirmed.profiles[0].source, "https://example.com/sub");
        assert!(!confirmed.profiles[0].current);
        assert!(confirmed.active_id.is_none());
        assert!(book.confirm_pending().profiles.len() == 1);

        let before = book.snapshot();
        let rejected =
            book.stage_install_link("clash://install-config?url=https://example.com/other");
        assert_eq!(rejected.input_error.as_deref(), Some(LINK_ERROR));
        assert_eq!(rejected.profiles.len(), before.profiles.len());
        assert!(rejected.pending_url.is_none());

        let doubled = book.stage_install_link(
            "billow://install-config?url=https://a.example/x&url=https://b.example/y",
        );
        assert_eq!(doubled.input_error.as_deref(), Some(ONE_LINK_ERROR));
        assert_eq!(doubled.profiles.len(), 1);
        assert!(
            book.stage_install_link("billow://install-config?url=ftp://example.com/a")
                .input_error
                .is_some()
        );
        assert_eq!(book.snapshot().profiles.len(), 1);

        let manual = book.add_subscription("https://manual.example/a");
        assert_eq!(manual.profiles.len(), 2);
        assert!(manual.profiles.iter().all(|profile| !profile.current));
        let local = book.add_local("home.yaml", &config(1));
        assert_eq!(local.profiles.len(), 3);
        assert_eq!(local.profiles[2].kind, "local");
    }

    #[test]
    fn duplicate_subscription_urls_are_rejected_without_adding() {
        let dir = temp_dir("duplicate");
        let mut book = ProfileBook::open(&dir.0);
        let first = book.add_subscription(" https://example.com/sub ");
        assert_eq!(first.profiles.len(), 1);
        assert_eq!(first.profiles[0].source, "https://example.com/sub");
        assert_eq!(first.input_error, None);

        let doubled = book.add_subscription("https://example.com/sub");
        assert_eq!(doubled.profiles.len(), 1);
        assert_eq!(doubled.input_error.as_deref(), Some(DUPLICATE_ERROR));

        let spaced = book.add_subscription("  https://example.com/sub  ");
        assert_eq!(spaced.profiles.len(), 1);
        assert_eq!(spaced.input_error.as_deref(), Some(DUPLICATE_ERROR));

        let other = book.add_subscription("https://example.com/other");
        assert_eq!(other.profiles.len(), 2);
        assert_eq!(other.input_error, None);

        // A deep link reaches the same guard and keeps the pending link for a retry.
        book.stage_install_link(
            "billow://install-config?url=https%3A%2F%2Fexample.com%2Fsub",
        );
        let confirmed = book.confirm_pending();
        assert_eq!(confirmed.profiles.len(), 2);
        assert_eq!(confirmed.input_error.as_deref(), Some(DUPLICATE_ERROR));
        assert_eq!(
            confirmed.pending_url.as_deref(),
            Some("https://example.com/sub")
        );
    }

    #[test]
    fn enabling_a_downloaded_subscription_works_offline_and_only_update_fetches() {
        let dir = temp_dir("offline-enable");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("local.yaml", &config(7890));
        book.add_subscription("https://sub.example/a");
        let mut online = MapSource { items: HashMap::new() };
        online.items.insert(
            "https://sub.example/a".to_string(),
            Ok(FetchedSubscription { content: config(7891), userinfo: None }),
        );
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };
        // Never downloaded: the first enable still has to fetch.
        let first = book.enable("p2", &online, &mut kernel);
        assert_eq!(first.active_id.as_deref(), Some("p2"));
        let updated_ms = first.profiles.iter().find(|p| p.id == "p2").unwrap().updated_ms;
        book.enable("p1", &RejectSource, &mut kernel);

        // Offline switch back: the cached copy runs, nothing is fetched or marked failed.
        let back = book.enable("p2", &RejectSource, &mut kernel);
        assert_eq!(back.active_id.as_deref(), Some("p2"));
        assert_eq!(back.mixed_port, Some(7891));
        let p2 = back.profiles.iter().find(|p| p.id == "p2").unwrap();
        assert!(p2.failure.is_none());
        assert_eq!(p2.updated_ms, updated_ms, "a switch must not pretend the subscription was refreshed");

        // An explicit update still goes to the network and reports its failure.
        let update = book.update("p2", &RejectSource, &mut kernel);
        assert_eq!(
            update.profiles.iter().find(|p| p.id == "p2").unwrap().failure.as_deref(),
            Some(FETCH_ERROR)
        );
    }

    #[test]
    fn unreachable_subscription_enable_closes_takeover_and_keeps_the_reason() {
        let dir = temp_dir("unreachable");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("ok.yaml", &config(7890));
        let mut kernel = FakeKernel {
            running: None,
            fail: false,
            calls: 0,
        };
        book.enable("p1", &RejectSource, &mut kernel);
        book.set_takeover(true, true, true);
        book.add_subscription("https://down.example/sub");
        let mut missing = MapSource {
            items: HashMap::new(),
        };
        missing.items.insert(
            "https://down.example/sub".to_string(),
            Err(FETCH_ERROR.to_string()),
        );
        let snapshot = book.enable("p2", &missing, &mut kernel);
        assert_eq!(snapshot.active_id.as_deref(), Some("p1"));
        assert_eq!(current_ids(&snapshot), ["p1"]);
        assert!(!snapshot.system_proxy && !snapshot.tun && !snapshot.vpn);
        let failed = snapshot
            .profiles
            .iter()
            .find(|profile| profile.id == "p2")
            .unwrap();
        assert_eq!(failed.failure.as_deref(), Some(FETCH_ERROR));
        assert!(!failed.current);
        assert_eq!(kernel.calls, 1);
        assert_eq!(snapshot.mixed_port, Some(7890));
        assert_eq!(snapshot.failure.as_deref(), Some(FETCH_ERROR));

        let again = book.enable("p2", &missing, &mut kernel);
        assert_eq!(
            again
                .profiles
                .iter()
                .find(|profile| profile.id == "p2")
                .unwrap()
                .failure
                .as_deref(),
            Some(FETCH_ERROR)
        );
        assert!(!again.system_proxy && !again.tun && !again.vpn);

        missing.items.insert(
            "https://down.example/sub".to_string(),
            Ok(FetchedSubscription {
                content: config(7900),
                userinfo: None,
            }),
        );
        let recovered = book.enable("p2", &missing, &mut kernel);
        assert_eq!(current_ids(&recovered), ["p2"]);
        assert!(recovered.failure.is_none());
        assert!(
            recovered
                .profiles
                .iter()
                .all(|profile| profile.id != "p2" || profile.failure.is_none())
        );
    }

    #[test]
    fn prefixed_override_rules_reach_the_kernel_and_bad_drafts_report_why() {
        let dir = temp_dir("override-plus");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\nrules:\n  - MATCH,DIRECT\n");
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };
        book.enable("p1", &RejectSource, &mut kernel);
        let saved = book.save_override("p1", "+rules:\n  - DOMAIN-SUFFIX,corp.example,DIRECT\n");
        assert!(saved.profiles[0].override_error.is_none());
        book.enable("p1", &RejectSource, &mut kernel);
        let running: Value = serde_yaml::from_str(kernel.running.as_deref().unwrap()).unwrap();
        let rules: Vec<&str> = running["rules"].as_sequence().unwrap().iter().filter_map(Value::as_str).collect();
        assert_eq!(rules, ["DOMAIN-SUFFIX,corp.example,DIRECT", "MATCH,DIRECT"]);
        assert!(running.get("+rules").is_none());

        let script = book.save_override("p1", "function main(config) {\n  config.mode = 'global'\n  return config\n}\n");
        assert!(script.profiles[0].override_error.is_none());
        let preview = book.preview_override("p1", "function main(config) { console.log(config.mode); return config }").unwrap();
        assert_eq!(preview.logs, ["rule"]);
        let broken = book.save_override("p1", "function main(config) {\n  return config.a.b\n}\n");
        let error = broken.profiles[0].override_error.clone().unwrap();
        assert!(error.starts_with(OVERRIDE_ERROR) && error.contains("第 2 行"), "{error}");
    }

    #[test]
    fn unusable_override_does_not_replace_the_active_config() {
        let dir = temp_dir("override");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local(
            "a.yaml",
            "mixed-port: 7890\nmode: rule\ndns:\n  enable: true\n  listen: 127.0.0.1:53\n",
        );
        book.add_local("b.yaml", &config(7891));
        let mut kernel = FakeKernel {
            running: None,
            fail: false,
            calls: 0,
        };
        book.enable("p1", &RejectSource, &mut kernel);
        book.set_takeover(true, false, true);
        book.save_override("p1", ":\n  -");
        let calls_before = kernel.calls;
        let rejected = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(rejected.active_id.as_deref(), Some("p1"));
        assert_eq!(current_ids(&rejected), ["p1"]);
        assert_eq!(rejected.mixed_port, Some(7890));
        assert_eq!(rejected.mode.as_deref(), Some("rule"));
        assert!(rejected.system_proxy && !rejected.tun && rejected.vpn);
        assert!(rejected.profiles[0].override_error.as_deref().is_some_and(|error| error.starts_with(OVERRIDE_ERROR)));
        assert!(rejected.profiles[0].failure.is_none());
        assert_eq!(kernel.calls, calls_before);
        assert_eq!(port_of(kernel.running.as_deref().unwrap()), 7890);

        book.save_override("p2", "[\n");
        let switched = book.enable("p2", &RejectSource, &mut kernel);
        assert_eq!(switched.active_id.as_deref(), Some("p1"));
        assert_eq!(switched.mixed_port, Some(7890));
        assert!(switched.system_proxy && switched.vpn && !switched.tun);
        assert_eq!(kernel.calls, calls_before);
        assert!(switched
            .profiles
            .iter()
            .find(|profile| profile.id == "p2")
            .unwrap()
            .override_error
            .as_deref()
            .is_some_and(|error| error.starts_with(OVERRIDE_ERROR)));

        book.save_override("p1", "mixed-port: 8000\ndns:\n  enable: false\n");
        let applied = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(applied.mixed_port, Some(8000));
        assert!(applied.profiles[0].override_error.is_none());
        assert!(applied.profiles[0].failure.is_none());
        assert!(applied.system_proxy && applied.vpn);
        let running: Value = serde_yaml::from_str(kernel.running.as_deref().unwrap()).unwrap();
        assert_eq!(read_i64(&running, "mixed-port"), Some(8000));
        // The effective-config view shows exactly what the kernel was given.
        let effective: Value = serde_yaml::from_str(&book.effective_config().unwrap()).unwrap();
        assert_eq!(read_i64(&effective, "mixed-port"), Some(8000));
        assert_eq!(
            mapping_get(mapping_get(&effective, "dns").unwrap(), "enable").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(read_string(&effective, "external-controller").as_deref(), Some("127.0.0.1:17690"));
        let dns = mapping_get(&running, "dns").unwrap();
        assert_eq!(read_string(dns, "listen").as_deref(), Some("127.0.0.1:53"));
        assert_eq!(
            mapping_get(dns, "enable").and_then(Value::as_bool),
            Some(false)
        );

        book.save_override("p2", "mixed-port: 8001\nmode: global\n");
        let other = book.enable("p2", &RejectSource, &mut kernel);
        assert_eq!(current_ids(&other), ["p2"]);
        assert_eq!(other.mixed_port, Some(8001));
        assert_eq!(other.mode.as_deref(), Some("global"));
        let back = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(current_ids(&back), ["p1"]);
        assert_eq!(back.mixed_port, Some(8000));
        assert_eq!(back.mode.as_deref(), Some("rule"));

        book.save_override("p1", "");
        assert_eq!(book.snapshot().mixed_port, Some(8000));
        // A saved but not yet applied override is not what runs.
        let effective: Value = serde_yaml::from_str(&book.effective_config().unwrap()).unwrap();
        assert_eq!(read_i64(&effective, "mixed-port"), Some(8000));
        assert_eq!(kernel.calls, 4);
        let cleared = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(cleared.mixed_port, Some(7890));
    }

    #[test]
    fn kernel_start_failure_does_not_take_effect_and_closes_takeover() {
        let dir = temp_dir("kernel-fail");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", &config(7890));
        book.add_local("b.yaml", &config(7891));
        let mut kernel = FakeKernel {
            running: None,
            fail: false,
            calls: 0,
        };
        book.enable("p1", &RejectSource, &mut kernel);
        book.set_takeover(true, true, false);
        kernel.fail = true;
        let failed = book.enable("p2", &RejectSource, &mut kernel);
        assert_eq!(failed.active_id.as_deref(), Some("p1"));
        assert_eq!(failed.mixed_port, Some(7890));
        assert!(!failed.system_proxy && !failed.tun && !failed.vpn);
        assert_eq!(
            failed
                .profiles
                .iter()
                .find(|profile| profile.id == "p2")
                .unwrap()
                .failure
                .as_deref(),
            Some(KERNEL_ERROR)
        );
        assert_eq!(port_of(kernel.running.as_deref().unwrap()), 7890);

        book.add_local("bad.yaml", "[]\n");
        kernel.fail = false;
        let calls = kernel.calls;
        book.set_takeover(true, false, false);
        let invalid = book.enable("p3", &RejectSource, &mut kernel);
        assert_eq!(invalid.active_id.as_deref(), Some("p1"));
        assert!(!invalid.system_proxy && !invalid.tun && !invalid.vpn);
        assert_eq!(
            invalid
                .profiles
                .iter()
                .find(|profile| profile.id == "p3")
                .unwrap()
                .failure
                .as_deref(),
            Some(CONTENT_ERROR)
        );
        assert_eq!(kernel.calls, calls);
    }

    #[test]
    fn subscription_user_agents_inherit_persist_and_reach_enable_and_refresh() {
        use std::cell::RefCell;
        struct Source { seen: RefCell<Vec<String>> }
        impl SubscriptionSource for Source {
            fn fetch(&self, _url: &str) -> Result<FetchedSubscription, String> { panic!("UA must be resolved") }
            fn fetch_with_user_agent(&self, _url: &str, ua: &str) -> Result<FetchedSubscription, String> {
                self.seen.borrow_mut().push(ua.to_string());
                Ok(FetchedSubscription { content: config(7890), userinfo: None })
            }
        }
        assert_eq!(default_subscription_user_agent(Some("v1.19.34")), "clash.meta/v1.19.34");
        assert_eq!(default_subscription_user_agent(Some("alpha-test")), "clash.meta/alpha-test");
        assert_eq!(default_subscription_user_agent(None), "clash.meta");
        assert_eq!(default_subscription_user_agent(Some("  ")), "clash.meta");
        let dir = temp_dir("subscription-ua");
        let mut book = ProfileBook::open(&dir.0);
        book.add_subscription("https://example.com/sub");
        assert_eq!(book.snapshot().profiles[0].user_agent, "");
        let source = Source { seen: RefCell::new(Vec::new()) };
        let mut kernel = node_kernel();
        book.enable("p1", &source, &mut kernel);
        book.settings.subscription_user_agent = "global-client/1".into();
        book.refresh_profile("p1", &source, &mut kernel);
        book.set_profile_user_agent("p1", " custom-client/2 ");
        book.update("p1", &source, &mut kernel);
        assert_eq!(*source.seen.borrow(), ["", "global-client/1", "custom-client/2"]);
        let mut reopened = ProfileBook::open(&dir.0);
        assert_eq!(reopened.snapshot().profiles[0].user_agent, "custom-client/2");
        for invalid in ["client\r\nX-Injected: yes".to_string(), "x".repeat(257), "客户端".into()] {
            let denied = reopened.set_profile_user_agent("p1", &invalid);
            assert!(denied.input_error.is_some());
            assert_eq!(denied.profiles[0].user_agent, "custom-client/2");
        }
        reopened.set_profile_user_agent("p1", " ");
        assert_eq!(reopened.subscription_user_agent(0), "global-client/1");
        let calls = kernel.calls;
        let mut settings = reopened.settings.clone();
        settings.subscription_user_agent = "another-client".into();
        let saved = reopened.save_settings(settings, &mut kernel, &mut MemoryProxy::default(), &mut MemoryTun::default(), &mut MemoryVpn::default());
        assert!(saved.input_error.is_none());
        assert_eq!(saved.settings.subscription_user_agent, "another-client");
        assert_eq!(kernel.calls, calls, "saving the global UA must not reload the running kernel");
        let path = dir.0.join("profiles.json");
        let mut legacy: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        legacy["profiles"][0].as_object_mut().unwrap().remove("user_agent");
        fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert_eq!(ProfileBook::open(&dir.0).snapshot().profiles[0].user_agent, "");
    }

    #[test]
    fn subscription_http_requests_use_the_actual_kernel_version_or_custom_header() {
        use std::io::Write;
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut agents = Vec::new();
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() { break; }
                    if line.to_ascii_lowercase().starts_with("user-agent:") {
                        agents.push(line.split_once(':').unwrap().1.trim().to_string());
                    }
                }
                let body = "mixed-port: 7890\n";
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            agents
        });
        let client = HttpSubscriptionClient {
            agent: ureq::AgentBuilder::new().try_proxy_from_env(false).build(),
            default_user_agent: default_subscription_user_agent(Some("v1.19.34")),
        };
        let url = format!("http://{address}/subscription");
        client.fetch(&url).unwrap();
        client.fetch_with_user_agent(&url, "other-client/2").unwrap();
        client.fetch_with_user_agent(&url, " ").unwrap();
        assert_eq!(server.join().unwrap(), ["clash.meta/v1.19.34", "other-client/2", "clash.meta/v1.19.34"]);
    }

    #[test]
    fn saved_override_is_not_applied_until_enable() {
        let dir = temp_dir("draft");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", &config(7890));
        let mut kernel = FakeKernel {
            running: None,
            fail: false,
            calls: 0,
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let saved = book.save_override("p1", "mixed-port: 8010\n");
        assert_eq!(saved.mixed_port, Some(7890));
        assert_eq!(saved.profiles[0].override_text, "mixed-port: 8010\n");
        assert_eq!(kernel.calls, 1);
        assert_eq!(port_of(kernel.running.as_deref().unwrap()), 7890);
    }

    #[cfg(unix)]
    #[test]
    fn startup_exit_keeps_fatal_stdout_stderr_and_exit_status_for_the_ui() {
        use std::os::unix::fs::PermissionsExt;
        for (name, script, expected) in [
            ("fatal", "#!/bin/sh\nprintf '%s\\n' 'level=fatal msg=\"unsupported proxy type: test-invalid\"'\nexit 7\n", "unsupported proxy type: test-invalid"),
            ("stderr", "#!/bin/sh\nprintf '%s\\n' 'dyld: Library not loaded: test-missing-library' >&2\nexit 8\n", "test-missing-library"),
            ("signal", "#!/bin/sh\nkill -KILL $$\n", "signal: 9"),
        ] {
            let dir = temp_dir(name);
            let path = dir.0.join("core.sh");
            fs::write(&path, script).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            let mut runtime = ProcessRuntime::new(&dir.0);
            runtime.home_dir = dir.0.join("home");
            runtime.set_kernel_path(Some(path));
            // Use the production controller-readiness path. The no-controller
            // stand-in grace period is not a reliable process-exit deadline on busy CI.
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            let error = runtime.start_or_reload(&format!("mixed-port: 0\nexternal-controller: 127.0.0.1:{port}\n")).unwrap_err();
            assert!(error.contains(expected), "{name}: lost startup reason: {error}");
            assert!(!runtime.running());
            if name != "signal" {
                let logs = runtime.pull_logs();
                assert!(logs.iter().any(|line| line.level == "error" && line.message.contains(expected)), "{name}: startup logs were discarded");
                assert!(runtime.pull_logs().is_empty(), "startup logs must be drained once");
            }
            assert!(!dir.0.join("kernel.pid").exists());
        }
    }

    #[test]
    fn missing_kernel_binary_fails_enable_without_opening_takeover() {
        let dir = temp_dir("runtime");
        let mut runtime = ProcessRuntime::new(&dir.0);
        let error = runtime.start_or_reload("mixed-port: 1\n").unwrap_err();
        assert_eq!(error, MISSING_KERNEL);
        runtime.set_kernel_path(Some(dir.0.join("missing-core")));
        assert_eq!(
            runtime.start_or_reload("mixed-port: 1\n").unwrap_err(),
            MISSING_KERNEL
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let stand_in = dir.0.join("stand-in.sh");
            fs::write(&stand_in, "#!/bin/sh\nsleep 30\n").unwrap();
            fs::set_permissions(&stand_in, fs::Permissions::from_mode(0o755)).unwrap();
            runtime.set_kernel_path(Some(stand_in));
            runtime.start_or_reload(&config(7890)).unwrap();
            runtime.set_kernel_path(Some(PathBuf::from("/usr/bin/false")));
            assert!(runtime.start_or_reload(&config(1)).unwrap_err().contains("退出码 1"));
            runtime.stop();
        }
    }

    #[cfg(unix)]
    #[test]
    fn forced_launch_respawns_even_for_an_unchanged_config() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("forced-launch");
        let stand_in = dir.0.join("stand-in.sh");
        fs::write(&stand_in, "#!/bin/sh\nsleep 30\n").unwrap();
        fs::set_permissions(&stand_in, fs::Permissions::from_mode(0o755)).unwrap();
        let mut runtime = ProcessRuntime::new(&dir.0);
        runtime.home_dir = dir.0.join("home");
        runtime.set_kernel_path(Some(stand_in));
        runtime.start_or_reload(&config(7890)).unwrap();
        let first = runtime.child.as_ref().unwrap().id();
        runtime.start_or_reload(&config(7890)).unwrap();
        assert_eq!(runtime.child.as_ref().unwrap().id(), first, "an unchanged config must not respawn");
        runtime.start_or_reload_with(&config(7890), true).unwrap();
        let second = runtime.child.as_ref().unwrap().id();
        assert_ne!(second, first, "a forced launch must stop and respawn");
        assert!(runtime.running());
        runtime.stop();
    }

    #[test]
    fn deep_link_scheme_is_billow_only() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(
            config["plugins"]["deep-link"]["desktop"]["schemes"],
            serde_json::json!(["billow"])
        );
        assert_eq!(
            config["plugins"]["deep-link"]["mobile"][0]["scheme"],
            serde_json::json!(["billow"])
        );
        assert!(
            !include_str!("../tauri.conf.json")
                .to_ascii_lowercase()
                .contains("clash")
        );
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let permissions = capability["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>();
        for permission in [
            "allow-profile-state",
            "allow-add-subscription-profile",
            "allow-add-local-profile",
            "allow-stage-install-link",
            "allow-confirm-install-link",
            "allow-cancel-install-link",
            "allow-enable-profile",
            "allow-update-profile",
            "allow-save-profile-override",
            "allow-preview-profile-override",
            "allow-set-profile-age-key",
            "allow-export-logs",
        ] {
            assert!(permissions.contains(&permission), "{permission}");
        }
    }

    struct NodeKernel {
        report_running: bool,
        yaml: Option<String>,
        calls: u32,
        applied: Vec<(String, String)>,
        delay_calls: u32,
        scripts: HashMap<String, Vec<NodeDelay>>,
        auto: BTreeMap<String, String>,
        reject_select: bool,
        closed_groups: Vec<(String, String)>,
        fail_close: bool,
        stats_reads: usize,
        catalog: nodes::RuntimeCatalog,
        /// Groups the fake kernel treats as `SelectAble` auto groups: a PUT pins them.
        pin_groups: Vec<String>,
        unfixed: Vec<String>,
        reject_unfix: bool,
    }

    impl KernelLaunch for NodeKernel {
        fn start_or_reload(&mut self, config_yaml: &str) -> Result<(), String> {
            self.calls += 1;
            self.yaml = Some(config_yaml.to_string());
            self.report_running = true;
            // A fresh process forgets pins; Billow must replay them.
            self.catalog.fixed.clear();
            Ok(())
        }

        fn unfix_proxy(&mut self, group: &str) -> Result<(), String> {
            if !self.report_running {
                return Err(KERNEL_DOWN.to_string());
            }
            if self.reject_unfix {
                return Err("没有恢复自动选择：busy".to_string());
            }
            self.unfixed.push(group.to_string());
            self.catalog.fixed.remove(group);
            Ok(())
        }

        fn running(&mut self) -> bool {
            self.report_running
        }

        fn select_proxy(&mut self, group: &str, node: &str) -> Result<(), String> {
            if !self.report_running || self.reject_select {
                return Err("节点没有切换".to_string());
            }
            self.applied.push((group.to_string(), node.to_string()));
            if self.pin_groups.iter().any(|name| name == group) {
                self.catalog.fixed.insert(group.to_string(), node.to_string());
                self.auto.insert(group.to_string(), node.to_string());
            }
            Ok(())
        }

        fn close_previous_group_connections(&mut self, group: &str, selected: &str) -> Result<Vec<String>, String> {
            self.closed_groups.push((group.into(), selected.into()));
            if self.fail_close { Err("旧连接未能关闭".into()) } else { Ok(Vec::new()) }
        }

        fn connections(&mut self) -> Vec<ConnectionView> {
            self.stats_reads += 1;
            Vec::new()
        }

        fn probe_delays(
            &mut self,
            group: &str,
            nodes: &[String],
        ) -> Result<Vec<NodeDelay>, String> {
            self.delay_calls += 1;
            if !self.report_running {
                return Err(KERNEL_DOWN.to_string());
            }
            Ok(self
                .scripts
                .get(group)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|item| nodes.iter().any(|name| name == &item.name))
                .collect())
        }

        fn node_catalog(&mut self) -> nodes::RuntimeCatalog {
            let mut catalog = self.catalog.clone();
            catalog.now.extend(self.auto_now());
            catalog
        }

        fn auto_now(&mut self) -> BTreeMap<String, String> {
            if self.report_running {
                self.auto.clone()
            } else {
                BTreeMap::new()
            }
        }
    }

    fn node_kernel() -> NodeKernel {
        NodeKernel {
            report_running: false,
            yaml: None,
            calls: 0,
            applied: Vec::new(),
            delay_calls: 0,
            scripts: HashMap::new(),
            auto: BTreeMap::new(),
            reject_select: false,
            closed_groups: Vec::new(),
            fail_close: false,
            stats_reads: 0,
            catalog: nodes::RuntimeCatalog::default(),
            pin_groups: Vec::new(),
            unfixed: Vec::new(),
            reject_unfix: false,
        }
    }

    fn pinnable_config() -> String {
        grouped_config()
            + "  - name: backup\n    type: fallback\n    hidden: true\n    proxies: [z-node, m-node]\n"
            + "  - name: spread\n    type: load-balance\n    proxies: [z-node, m-node]\n"
    }

    #[test]
    fn auto_groups_can_be_fixed_replayed_after_reload_and_released() {
        let dir = temp_dir("pin-auto");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("nodes", &pinnable_config());
        let mut kernel = node_kernel();
        kernel.pin_groups = vec!["auto".into(), "backup".into()];

        let listed = book.snapshot();
        let auto = group(&listed.node_catalog, "auto");
        assert!(auto.pinnable && auto.fixed.is_none() && !auto.hidden);
        assert!(group(&listed.node_catalog, "backup").pinnable);
        assert!(group(&listed.node_catalog, "backup").hidden, "YAML hidden applies while the kernel is down");
        assert!(!group(&listed.node_catalog, "spread").pinnable);
        assert!(!group(&listed.node_catalog, "manual").pinnable);

        let offline = book.select_node("auto", "m-node", &mut kernel);
        assert_eq!(offline.nodes_error.as_deref(), Some(KERNEL_DOWN));
        assert!(kernel.applied.is_empty());
        let offline = book.unfix_group("auto", &mut kernel);
        assert_eq!(offline.nodes_error.as_deref(), Some(KERNEL_DOWN));
        assert!(kernel.unfixed.is_empty());

        book.enable("p1", &RejectSource, &mut kernel);
        kernel.auto.insert("auto".into(), "z-node".into());
        let pinned = book.select_node("auto", "m-node", &mut kernel);
        assert!(pinned.nodes_error.is_none(), "{:?}", pinned.nodes_error);
        assert_eq!(kernel.applied.last(), Some(&("auto".to_string(), "m-node".to_string())));
        let auto = group(&pinned.node_catalog, "auto");
        assert_eq!(auto.now, "m-node");
        assert_eq!(auto.fixed.as_deref(), Some("m-node"));
        assert!(auto.nodes.iter().any(|node| node.name == "m-node" && node.selected));
        let yaml = kernel.yaml.clone().unwrap();
        assert_eq!(proxies_of(&yaml, "auto"), ["z-node", "m-node", "a-node"], "auto member order stays untouched");
        let stored = fs::read_to_string(dir.0.join("profiles.json")).unwrap();
        assert!(stored.contains("\"fixed\"") && stored.contains("m-node"));

        // A rejected pin leaves the shown node as it was.
        kernel.reject_select = true;
        let refused = book.select_node("auto", "a-node", &mut kernel);
        assert_eq!(refused.nodes_error.as_deref(), Some("节点没有切换"));
        assert_eq!(group(&refused.node_catalog, "auto").now, "m-node");
        kernel.reject_select = false;

        let spread = book.select_node("spread", "m-node", &mut kernel);
        assert_eq!(spread.nodes_error.as_deref(), Some(NOT_MANUAL));
        assert_eq!(book.unfix_group("spread", &mut kernel).nodes_error.as_deref(), Some(NOT_MANUAL));

        // A reload starts a process without the pin; Billow puts it back.
        kernel.applied.clear();
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        let reconnected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(reconnected.connected);
        book.enable("p1", &RejectSource, &mut kernel);
        assert!(kernel.applied.contains(&("auto".to_string(), "m-node".to_string())));
        book.sync_runtime(&mut kernel);
        let replayed = book.snapshot();
        assert_eq!(group(&replayed.node_catalog, "auto").fixed.as_deref(), Some("m-node"));
        assert_eq!(group(&replayed.node_catalog, "auto").now, "m-node");

        // The kernel drops a pin on its own (dead node): show it as automatic, keep the saved value.
        kernel.catalog.fixed.clear();
        kernel.auto.insert("auto".into(), "z-node".into());
        book.sync_runtime(&mut kernel);
        let dropped = book.snapshot();
        assert!(group(&dropped.node_catalog, "auto").fixed.is_none());
        assert!(book.profiles[0].fixed.contains_key("auto"));
        kernel.catalog.fixed.insert("auto".into(), "m-node".into());
        kernel.auto.insert("auto".into(), "m-node".into());

        // Controller hidden wins over YAML while running.
        kernel.catalog.hidden.insert("backup".into(), false);
        kernel.catalog.hidden.insert("auto".into(), true);
        book.sync_runtime(&mut kernel);
        let live = book.snapshot();
        assert!(!group(&live.node_catalog, "backup").hidden);
        assert!(group(&live.node_catalog, "auto").hidden);
        kernel.catalog.hidden.clear();

        kernel.reject_unfix = true;
        let busy = book.unfix_group("auto", &mut kernel);
        assert!(busy.nodes_error.as_deref().is_some_and(|message| message.contains("busy")));
        assert_eq!(group(&busy.node_catalog, "auto").fixed.as_deref(), Some("m-node"));
        kernel.reject_unfix = false;

        kernel.auto.insert("auto".into(), "z-node".into());
        let released = book.unfix_group("auto", &mut kernel);
        assert!(released.nodes_error.is_none());
        assert_eq!(kernel.unfixed, ["auto"]);
        let auto = group(&released.node_catalog, "auto");
        assert!(auto.fixed.is_none());
        assert_eq!(auto.now, "z-node");
        assert!(book.profiles[0].fixed.is_empty());
        kernel.applied.clear();
        book.enable("p1", &RejectSource, &mut kernel);
        assert!(!kernel.applied.iter().any(|(group, _)| group == "auto"), "a released group is not pinned again");
    }

    #[test]
    fn switching_closes_old_group_connections_only_after_success_and_respects_the_setting() {
        let dir = temp_dir("switch-connections");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("nodes", &grouped_config());
        let mut kernel = node_kernel();
        book.enable("p1", &RejectSource, &mut kernel);
        book.connected = true;
        let chosen = book.select_node("manual", "a-node", &mut kernel);
        assert!(chosen.nodes_error.is_none());
        assert_eq!(kernel.closed_groups, [("manual".into(), "a-node".into())]);
        assert_eq!(kernel.stats_reads, 0, "selection must not fetch a full stats snapshot first");
        book.select_node("manual", "a-node", &mut kernel);
        assert_eq!(kernel.closed_groups.len(), 1, "reselecting the current node must not drop connections");
        kernel.reject_select = true;
        let failed = book.select_node("manual", "m-node", &mut kernel);
        assert!(failed.nodes_error.is_some());
        assert_eq!(kernel.closed_groups.len(), 1, "a failed switch must keep the existing route alive");
        kernel.reject_select = false;
        let calls = kernel.calls;
        let mut settings = book.settings.clone();
        settings.close_connections_on_switch = Some(false);
        book.save_settings(settings, &mut kernel, &mut MemoryProxy::default(), &mut MemoryTun::default(), &mut MemoryVpn::default());
        assert_eq!(kernel.calls, calls, "this preference must not reload the core");
        book.select_node("manual", "m-node", &mut kernel);
        assert_eq!(kernel.closed_groups.len(), 1);
        book.settings.close_connections_on_switch = Some(true);
        kernel.fail_close = true;
        let partial = book.select_node("manual", "z-node", &mut kernel);
        assert!(partial.nodes_error.is_none());
        assert_eq!(group(&partial.node_catalog, "manual").now, "z-node");
        assert!(partial.notice.unwrap().contains("节点已切换，但"));
        kernel.report_running = false;
        book.select_node("manual", "a-node", &mut kernel);
        assert_eq!(kernel.closed_groups.len(), 2, "offline preferences cannot close connections");
    }

    #[test]
    fn group_tests_emit_each_node_and_keep_final_results_in_shared_groups() {
        let dir = temp_dir("group-progress");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("nodes", &grouped_config());
        let mut kernel = node_kernel();
        kernel.report_running = true;
        kernel.scripts.insert("manual".into(), vec![
            NodeDelay { name: "a-node".into(), delay_ms: Some(12) },
            NodeDelay { name: "m-node".into(), delay_ms: None },
        ]);
        let mut progress = Vec::new();
        let next = book.test_group_with_progress("manual", &mut kernel, &mut |name, delay, failed, done, total| {
            progress.push((name.to_string(), delay, failed, done, total));
        });
        assert_eq!(progress.len(), 2);
        assert_eq!(progress[0].0, "a-node");
        assert_eq!(progress[0].1, Some(12));
        assert_eq!(progress[0].3, 1);
        assert!(progress[1].2);
        assert_eq!(progress[1].3, 2);
        assert!(next.nodes_error.is_none());
        for group in &next.node_catalog {
            if let Some(node) = group.nodes.iter().find(|node| node.name == "a-node") {
                assert_eq!(node.delay_ms, Some(12));
            }
        }
    }

    #[test]
    fn provider_members_can_be_selected_tested_and_are_cleared_on_stop() {
        let dir = temp_dir("provider-members");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("provider", "mixed-port: 7890\nproxy-groups:\n  - {name: Available, type: select, use: [remote]}\n");
        let mut kernel = node_kernel();
        kernel.catalog = nodes::runtime_catalog(&serde_json::json!({"proxies": {
            "Available": {"all":["HK", "JP"], "now":"JP", "type":"Selector"},
            "HK":{"type":"Shadowsocks"}, "JP":{"type":"VLESS"}
        }})).unwrap();
        let ready = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(ready.node_catalog[0].nodes.len(), 2);
        assert_eq!(ready.node_catalog[0].now, "JP");
        assert!(ready.node_catalog[0].nodes[1].selected);
        assert_eq!(ready.node_catalog[0].nodes[1].node_type, "VLESS");
        let selected = book.select_node("Available", "HK", &mut kernel);
        assert!(selected.nodes_error.is_none());
        assert_eq!(selected.node_catalog[0].now, "HK");
        assert_eq!(kernel.applied.last(), Some(&("Available".to_string(), "HK".to_string())));
        kernel.scripts.insert("Available".to_string(), vec![NodeDelay { name:"HK".to_string(), delay_ms:Some(20) }]);
        let tested = book.test_group("Available", &mut kernel);
        assert_eq!(tested.node_catalog[0].nodes[0].delay_ms, Some(20));
        kernel.report_running = false;
        book.sync_runtime(&mut kernel);
        assert!(book.snapshot().node_catalog[0].nodes.is_empty());
    }

    #[test]
    fn disconnect_without_tun_does_not_restart_the_kernel() {
        let dir = temp_dir("warm-disconnect");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("local", "mixed-port: 7890\nmode: rule\n");
        let mut kernel = node_kernel();
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        let starts = kernel.calls;
        let next = book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!next.connected && !next.system_proxy);
        assert_eq!(kernel.calls, starts);
    }

    fn grouped_config() -> String {
        r#"mixed-port: 7890
mode: rule
proxies:
  - name: z-node
    type: ss
    server: 127.0.0.1
    port: 1
  - name: m-node
    type: ss
    server: 127.0.0.1
    port: 2
  - name: a-node
    type: ss
    server: 127.0.0.1
    port: 3
proxy-groups:
  - name: manual
    type: select
    icon: https://icons.example.com/manual.png
    proxies:
      - z-node
      - m-node
      - a-node
  - name: auto
    type: url-test
    icon: file:///tmp/local.png
    proxies:
      - z-node
      - m-node
      - a-node
"#
        .to_string()
    }

    fn group<'a>(
        groups: &'a [crate::nodes::NodeGroupView],
        name: &str,
    ) -> &'a crate::nodes::NodeGroupView {
        groups.iter().find(|group| group.name == name).unwrap()
    }

    fn node_names(group: &crate::nodes::NodeGroupView) -> Vec<&str> {
        group.nodes.iter().map(|node| node.name.as_str()).collect()
    }

    fn proxies_of(yaml: &str, name: &str) -> Vec<String> {
        let value: Value = serde_yaml::from_str(yaml).unwrap();
        crate::nodes::parse_proxy_groups(&value)
            .into_iter()
            .find(|group| group.name == name)
            .unwrap()
            .proxies
    }

    #[test]
    fn saved_config_lists_groups_while_kernel_is_stopped_and_keeps_manual_choice() {
        let dir = temp_dir("nodes-saved");
        let mut book = ProfileBook::open(&dir.0);
        assert_eq!(book.snapshot().nodes_notice.as_deref(), Some(NEED_PROFILE));
        book.add_subscription("https://example.com/sub");
        let mut kernel = node_kernel();
        let missing = book.select_node("manual", "a-node", &mut kernel);
        assert_eq!(missing.nodes_error.as_deref(), Some(NEED_PROFILE));
        assert!(missing.node_catalog.is_empty());
        assert!(kernel.applied.is_empty());

        book.add_local("nodes.yaml", &grouped_config());
        book.sync_runtime(&mut kernel);
        let listed = book.snapshot();
        assert!(listed.nodes_notice.is_none());
        assert!(!listed.kernel_running);
        assert_eq!(listed.nodes_profile_id.as_deref(), Some("p2"));
        assert_eq!(
            node_names(group(&listed.node_catalog, "manual")),
            ["z-node", "m-node", "a-node"]
        );
        assert!(group(&listed.node_catalog, "manual").nodes[0].selected);
        // Auto groups list their members for viewing; none is marked while the kernel is down.
        assert!(group(&listed.node_catalog, "auto").nodes.iter().all(|node| !node.selected));
        assert_eq!(group(&listed.node_catalog, "auto").kind, "auto");
        assert_eq!(
            group(&listed.node_catalog, "manual").icon.as_deref(),
            Some("https://icons.example.com/manual.png")
        );
        assert!(
            group(&listed.node_catalog, "auto").icon.is_none(),
            "a local file icon is not passed through"
        );
        assert_eq!(kernel.delay_calls, 0);
        assert!(listed.node_catalog.iter().all(|item| {
            item.nodes
                .iter()
                .all(|node| node.delay_ms.is_none() && !node.failed)
        }));

        let chosen = book.select_node("manual", "a-node", &mut kernel);
        assert!(chosen.nodes_error.is_none());
        assert!(kernel.applied.is_empty());
        assert_eq!(kernel.calls, 0);
        let manual = group(&chosen.node_catalog, "manual");
        assert!(
            manual
                .nodes
                .iter()
                .any(|node| node.name == "a-node" && node.selected)
        );
        assert!(
            !manual
                .nodes
                .iter()
                .any(|node| node.name == "z-node" && node.selected)
        );
        assert_eq!(manual.now, "a-node");

        let rejected = book.select_node("auto", "m-node", &mut kernel);
        assert_eq!(rejected.nodes_error.as_deref(), Some(KERNEL_DOWN), "fixing an auto group needs a running kernel");
        assert!(kernel.applied.is_empty());
        let reopened = ProfileBook::open(&dir.0);
        let stored = fs::read_to_string(dir.0.join("profiles.json")).unwrap();
        assert!(stored.contains("\"manual\""));
        assert!(stored.contains("a-node"));
        assert!(!stored.contains("\"auto\""));
        let reopened_view = reopened.snapshot();
        let manual = group(&reopened_view.node_catalog, "manual");
        assert!(
            manual
                .nodes
                .iter()
                .any(|node| node.name == "a-node" && node.selected)
        );
        assert!(
            reopened_view
                .node_catalog
                .iter()
                .all(|item| { item.nodes.iter().all(|node| node.delay_ms.is_none()) })
        );
    }

    #[test]
    fn next_successful_connect_applies_the_saved_manual_choice() {
        let dir = temp_dir("nodes-connect");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("nodes.yaml", &grouped_config());
        let mut kernel = node_kernel();
        book.select_node("manual", "a-node", &mut kernel);
        assert!(kernel.applied.is_empty());
        book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(
            kernel.applied,
            [("manual".to_string(), "a-node".to_string())]
        );
        assert_eq!(
            proxies_of(kernel.yaml.as_deref().unwrap(), "manual")[0],
            "a-node"
        );
        assert_eq!(
            proxies_of(kernel.yaml.as_deref().unwrap(), "auto"),
            ["z-node", "m-node", "a-node"]
        );
        assert!(kernel.yaml.as_deref().unwrap().contains("127.0.0.1:"));

        kernel.report_running = false;
        kernel.applied.clear();
        let marked = book.select_node("manual", "m-node", &mut kernel);
        assert!(kernel.applied.is_empty());
        assert_eq!(group(&marked.node_catalog, "manual").now, "m-node");
        kernel.reject_select = false;
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.connected);
        assert_eq!(
            kernel.applied,
            [("manual".to_string(), "m-node".to_string())]
        );
        assert_eq!(
            proxies_of(kernel.yaml.as_deref().unwrap(), "manual")[0],
            "m-node"
        );
        assert_eq!(
            proxy.http.as_ref().map(|endpoint| endpoint.host.as_str()),
            Some("127.0.0.1")
        );
        assert!(!tun.enabled && !vpn.open);

        kernel.report_running = true;
        kernel.reject_select = true;
        let kept = book.select_node("manual", "z-node", &mut kernel);
        assert_eq!(kept.nodes_error.as_deref(), Some("节点没有切换"));
        assert_eq!(group(&kept.node_catalog, "manual").now, "m-node");
        kernel.auto.insert("auto".to_string(), "z-node".to_string());
        book.sync_runtime(&mut kernel);
        let current = book.snapshot();
        let auto = group(&current.node_catalog, "auto");
        assert_eq!(auto.now, "z-node");
        assert!(auto.nodes.iter().any(|node| node.name == "z-node" && node.selected));
    }

    #[test]
    fn delay_results_arrive_only_after_an_explicit_test_and_a_failure_stays_local() {
        let dir = temp_dir("nodes-delay");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("nodes.yaml", &grouped_config());
        let mut kernel = node_kernel();
        book.sync_runtime(&mut kernel);
        assert_eq!(book.snapshot().nodes_notice, None);
        assert_eq!(kernel.delay_calls, 0);

        let idle = book.test_group("manual", &mut kernel);
        assert_eq!(idle.nodes_error.as_deref(), Some(KERNEL_DOWN));
        assert_eq!(kernel.delay_calls, 0);
        assert!(
            group(&idle.node_catalog, "manual")
                .nodes
                .iter()
                .all(|node| node.delay_ms.is_none() && !node.failed)
        );

        kernel.report_running = true;
        kernel.scripts.insert(
            "manual".to_string(),
            vec![
                NodeDelay {
                    name: "z-node".to_string(),
                    delay_ms: Some(20),
                },
                NodeDelay {
                    name: "m-node".to_string(),
                    delay_ms: None,
                },
                NodeDelay {
                    name: "a-node".to_string(),
                    delay_ms: Some(5),
                },
            ],
        );
        let tested = book.test_group("manual", &mut kernel);
        assert!(tested.nodes_error.is_none());
        assert_eq!(kernel.delay_calls, 1);
        let manual = group(&tested.node_catalog, "manual");
        assert_eq!(
            manual
                .nodes
                .iter()
                .find(|node| node.name == "z-node")
                .unwrap()
                .delay_ms,
            Some(20)
        );
        assert!(
            manual
                .nodes
                .iter()
                .find(|node| node.name == "m-node")
                .unwrap()
                .failed
        );
        assert_eq!(
            manual
                .nodes
                .iter()
                .find(|node| node.name == "a-node")
                .unwrap()
                .delay_ms,
            Some(5)
        );

        kernel.scripts.insert(
            "manual".to_string(),
            vec![NodeDelay {
                name: "z-node".to_string(),
                delay_ms: None,
            }],
        );
        let partial = book.test_group("manual", &mut kernel);
        let manual = group(&partial.node_catalog, "manual");
        assert!(
            manual
                .nodes
                .iter()
                .find(|node| node.name == "z-node")
                .unwrap()
                .failed
        );
        assert_eq!(
            manual
                .nodes
                .iter()
                .find(|node| node.name == "z-node")
                .unwrap()
                .delay_ms,
            None
        );
        assert!(
            manual
                .nodes
                .iter()
                .find(|node| node.name == "m-node")
                .unwrap()
                .failed
        );
        assert_eq!(
            manual
                .nodes
                .iter()
                .find(|node| node.name == "a-node")
                .unwrap()
                .delay_ms,
            Some(5)
        );
        assert!(
            !manual
                .nodes
                .iter()
                .find(|node| node.name == "a-node")
                .unwrap()
                .failed
        );

        let by_delay = book.set_node_sort("manual", "delay");
        assert_eq!(group(&by_delay.node_catalog, "manual").sort, "delay");
        assert_eq!(node_names(group(&by_delay.node_catalog, "manual")), ["z-node", "m-node", "a-node"]);
        let by_name = book.set_node_sort("manual", "name");
        assert_eq!(group(&by_name.node_catalog, "manual").sort, "name");
        let original = book.set_node_sort("manual", "default");
        assert_eq!(
            node_names(group(&original.node_catalog, "manual")),
            ["z-node", "m-node", "a-node"]
        );
        assert!(
            group(&original.node_catalog, "manual")
                .nodes
                .iter()
                .find(|node| node.name == "a-node")
                .unwrap()
                .delay_ms
                == Some(5)
        );
    }

    #[test]
    fn name_filter_hides_rows_without_clearing_the_saved_profile() {
        let dir = temp_dir("nodes-filter");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("plain.yaml", "mixed-port: 7890\nmode: rule\n");
        assert_eq!(book.snapshot().nodes_notice.as_deref(), Some(NO_NODES));
        book.add_local("nodes.yaml", &grouped_config());
        let mut kernel = node_kernel();
        book.select_node("manual", "a-node", &mut kernel);
        let path = dir.0.join("profiles.json");
        let before = fs::read(&path).unwrap();
        let missed = book.set_node_query("missing-node");
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(missed.nodes_notice.as_deref(), Some(NO_MATCH));
        assert_eq!(missed.node_catalog.len(), 2);
        assert_eq!(
            node_names(group(&missed.node_catalog, "manual")),
            ["z-node", "m-node", "a-node"]
        );
        let matched = book.set_node_query("a-n");
        assert!(matched.nodes_notice.is_none());
        assert_eq!(matched.node_query, "a-n");
        assert!(group(&matched.node_catalog, "manual").nodes.len() == 3);
        let restored = book.set_node_query("  ");
        assert!(restored.nodes_notice.is_none());
        assert_eq!(node_names(group(&restored.node_catalog, "manual")).len(), 3);
        assert_eq!(fs::read(&path).unwrap(), before);
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let permissions = capability["permissions"].as_array().unwrap();
        for permission in [
            "allow-select-profile-node",
            "allow-unfix-profile-group",
            "allow-test-profile-group",
            "allow-set-node-query",
            "allow-set-node-sort",
        ] {
            assert!(
                permissions
                    .iter()
                    .any(|item| item.as_str() == Some(permission)),
                "{permission}"
            );
        }
    }

    struct TrafficKernel {
        running: bool,
        fail: bool,
        connections: Vec<ConnectionView>,
        logs: Vec<LogView>,
    }

    impl KernelLaunch for TrafficKernel {
        fn start_or_reload(&mut self, _config_yaml: &str) -> Result<(), String> {
            if self.fail {
                self.running = false;
                return Err(KERNEL_ERROR.to_string());
            }
            self.running = true;
            Ok(())
        }

        fn running(&mut self) -> bool {
            self.running
        }

        fn connections(&mut self) -> Vec<ConnectionView> {
            if self.running {
                self.connections.clone()
            } else {
                Vec::new()
            }
        }

        fn pull_logs(&mut self) -> Vec<LogView> {
            if self.running {
                std::mem::take(&mut self.logs)
            } else {
                Vec::new()
            }
        }
    }

    #[test]
    fn tun_only_session_publishes_connections_without_a_system_proxy() {
        let dir = temp_dir("tun-only-connections");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("local", &config(7890));
        let mut kernel = TrafficKernel { running: false, fail: false,
            connections: vec![ConnectionView { host: "example.com".into(), outbound: "DIRECT".into(), ..Default::default() }], logs: Vec::new() };
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let next = book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(next.connected && next.tun && !next.system_proxy);
        assert_eq!(next.connections.len(), 1);
        let next = book.set_system_proxy(false, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(next.connected);
        assert_eq!(next.connections.len(), 1);
        kernel.running = false;
        book.sync_runtime(&mut kernel);
        assert!(!book.snapshot().connected);
    }

    #[test]
    fn injected_connections_filter_by_host_and_disappear_when_the_kernel_stops() {
        let dir = temp_dir("traffic");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", &config(7890));
        let mut kernel = TrafficKernel {
            running: false,
            fail: false,
            connections: vec![
                ConnectionView {
                    host: "Example.COM".to_string(),
                    outbound: "香港节点".to_string(),
    ..Default::default()
},
                ConnectionView {
                    host: "other.test".to_string(),
                    outbound: "直连".to_string(),
    ..Default::default()
},
            ],
            logs: vec![
                LogView {
                    level: "info".to_string(),
                    message: "普通记录".to_string(),
    ..Default::default()
},
                LogView {
                    level: "warning".to_string(),
                    message: "注意一下".to_string(),
    ..Default::default()
},
            ],
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let live = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(live.connected);
        assert!(!live.tun);
        assert_eq!(live.connections.len(), 2);
        assert_eq!(
            proxy.http.as_ref().map(|endpoint| endpoint.host.as_str()),
            Some("127.0.0.1")
        );
        let filtered = book.set_connection_query("example", &mut kernel);
        assert_eq!(filtered.connections.len(), 1);
        assert_eq!(filtered.connections[0].host, "Example.COM");
        assert_eq!(filtered.connections[0].outbound, "香港节点");
        let encoded = serde_json::to_value(&filtered.connections[0]).unwrap();
        assert_eq!(encoded["host"], "Example.COM");
        assert!(
            book.set_connection_query("直连", &mut kernel)
                .connections
                .is_empty()
        );
        let warned = book.set_log_filter("warning", &mut kernel);
        assert_eq!(warned.logs.len(), 1);
        assert_eq!(warned.logs[0].message, "注意一下");

        kernel.running = false;
        book.sync_runtime(&mut kernel);
        let stopped = book.snapshot();
        assert!(stopped.connections.is_empty());
        assert!(!stopped.connected);
        assert!(!stopped.kernel_running);

        kernel.running = true;
        kernel.connections.push(ConnectionView {
            host: "example.com".to_string(),
            outbound: "香港节点".to_string(),
    ..Default::default()
});
        let disconnected = book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!disconnected.connected);
        assert!(disconnected.connections.is_empty());
        assert!(
            disconnected
                .logs
                .iter()
                .any(|line| line.message == "注意一下")
        );
    }

    struct StatusKernel {
        running: bool,
        memory: Option<u64>,
        uptime: Option<u64>,
        total: usize,
        error: Option<String>,
        connections: Vec<ConnectionView>,
    }

    impl KernelLaunch for StatusKernel {
        fn start_or_reload(&mut self, _config_yaml: &str) -> Result<(), String> {
            self.running = true;
            Ok(())
        }

        fn running(&mut self) -> bool {
            self.running
        }

        fn connections(&mut self) -> Vec<ConnectionView> {
            self.connections.clone()
        }

        fn connection_total(&mut self) -> Option<usize> {
            Some(self.total)
        }

        fn connections_error(&mut self) -> Option<String> {
            self.error.clone()
        }

        fn kernel_memory(&mut self) -> Option<u64> {
            self.memory
        }

        fn kernel_uptime_secs(&mut self) -> Option<u64> {
            self.uptime
        }
    }

    #[test]
    fn snapshot_reports_kernel_memory_uptime_connection_count_and_read_errors() {
        let dir = temp_dir("status");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", &config(7890));
        let mut kernel = StatusKernel {
            running: false,
            memory: None,
            uptime: None,
            total: 0,
            error: None,
            connections: Vec::new(),
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let idle = book.snapshot();
        assert!(idle.kernel_running);
        assert!(idle.kernel_memory.is_none());
        assert!(idle.kernel_uptime_secs.is_none());
        assert_eq!(idle.connection_total, 0);
        assert!(idle.connections_error.is_none());

        kernel.memory = Some(128 * 1024 * 1024);
        kernel.uptime = Some(90);
        kernel.total = 620;
        kernel.connections = vec![ConnectionView {
            host: "example.com".to_string(),
            outbound: "香港节点".to_string(),
            ..Default::default()
        }];
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let live = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert_eq!(live.kernel_memory, Some(128 * 1024 * 1024));
        assert_eq!(live.kernel_uptime_secs, Some(90));
        assert_eq!(live.connection_total, 620, "the count keeps the rows the view drops");
        assert_eq!(live.connections.len(), 1);
        assert!(live.connections_error.is_none());

        kernel.error = Some("连接没有读取".to_string());
        kernel.total = 0;
        kernel.connections.clear();
        kernel.memory = None;
        book.sync_runtime(&mut kernel);
        let failed = book.snapshot();
        assert!(failed.connections.is_empty());
        assert_eq!(failed.connection_total, 0);
        assert_eq!(failed.connections_error.as_deref(), Some("连接没有读取"));
        assert!(failed.kernel_memory.is_none());
        assert_eq!(failed.kernel_uptime_secs, Some(90));

        kernel.running = false;
        book.sync_runtime(&mut kernel);
        let stopped = book.snapshot();
        assert!(stopped.kernel_memory.is_none());
        assert!(stopped.kernel_uptime_secs.is_none());
        assert_eq!(stopped.connection_total, 0);
        assert!(stopped.connections_error.is_none());
    }

    #[test]
    fn a_start_failure_is_kept_in_the_log_and_level_filters_do_not_drop_it() {
        let dir = temp_dir("start-log");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", &config(7890));
        let mut kernel = TrafficKernel {
            running: false,
            fail: true,
            connections: vec![ConnectionView {
                host: "stale.example".to_string(),
                outbound: "旧出站".to_string(),
    ..Default::default()
}],
            logs: Vec::new(),
        };
        let failed = book.enable("p1", &RejectSource, &mut kernel);
        assert!(failed.active_id.is_none());
        assert!(!failed.connected);
        assert!(!failed.system_proxy && !failed.tun && !failed.vpn);
        assert!(failed.connections.is_empty());
        assert!(
            failed
                .logs
                .iter()
                .any(|line| { line.level == "error" && line.message.contains(KERNEL_ERROR) })
        );
        kernel.fail = false;
        kernel.running = true;
        kernel.logs.push(LogView {
            level: "info".to_string(),
            message: "普通记录".to_string(),
    ..Default::default()
});
        book.sync_runtime(&mut kernel);
        let info = book.set_log_filter("info", &mut kernel);
        assert!(info.logs.iter().all(|line| line.level == "info"));
        assert!(info.logs.iter().any(|line| line.message == "普通记录"));
        let errors = book.set_log_filter("error", &mut kernel);
        assert!(
            errors
                .logs
                .iter()
                .any(|line| line.message.contains(KERNEL_ERROR))
        );
        assert!(errors.logs.iter().all(|line| line.level == "error"));
        assert!(!book.snapshot().connected);
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let permissions = capability["permissions"].as_array().unwrap();
        for permission in ["allow-set-connection-query", "allow-set-log-filter"] {
            assert!(
                permissions
                    .iter()
                    .any(|item| item.as_str() == Some(permission)),
                "{permission}"
            );
        }
    }

    struct ReplacingKernel {
        running: bool,
        stay_up: bool,
        rows: Vec<ConnectionView>,
        pending_logs: Vec<LogView>,
    }

    impl KernelLaunch for ReplacingKernel {
        fn start_or_reload(&mut self, _config_yaml: &str) -> Result<(), String> {
            self.rows.clear();
            self.pending_logs.clear();
            self.running = self.stay_up;
            if self.stay_up {
                Ok(())
            } else {
                Err(KERNEL_ERROR.to_string())
            }
        }

        fn running(&mut self) -> bool {
            self.running
        }

        fn connections(&mut self) -> Vec<ConnectionView> {
            if self.running {
                self.rows.clone()
            } else {
                Vec::new()
            }
        }

        fn pull_logs(&mut self) -> Vec<LogView> {
            std::mem::take(&mut self.pending_logs)
        }
    }

    #[test]
    fn cancelled_kernel_elevation_preserves_the_running_session_and_can_retry() {
        struct ConsentKernel { running: bool, cancelled: bool, calls: usize }
        impl KernelLaunch for ConsentKernel {
            fn start_or_reload(&mut self, _yaml: &str) -> Result<(), String> {
                self.calls += 1;
                if self.cancelled {
                    return Err(format!("{}：cancelled", takeover::TUN_AUTHORIZATION_FAILED));
                }
                self.running = true;
                Ok(())
            }
            fn running(&mut self) -> bool { self.running }
        }
        for action in ["tun", "connect", "proxy", "activate"] {
            let dir = temp_dir("cancel-elevation");
            let mut book = ProfileBook::open(&dir.0);
            book.set_platform(ClientPlatform::Desktop);
            book.add_local("local", &config(7890));
            let mut kernel = ConsentKernel { running: false, cancelled: false, calls: 0 };
            book.enable("p1", &RejectSource, &mut kernel);
            let mut proxy = MemoryProxy::default();
            let mut tun = MemoryTun::default();
            let mut vpn = MemoryVpn::default();
            let before = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
            assert!(before.connected && before.system_proxy);
            let proxy_before = proxy.http.clone();
            kernel.cancelled = true;
            let cancelled = match action {
                "tun" => book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn),
                "connect" => {
                    book.tun_wanted = true;
                    book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn)
                }
                "proxy" => {
                    book.tun_wanted = true;
                    book.set_system_proxy(true, &mut kernel, &mut proxy, &mut tun, &mut vpn)
                }
                _ => {
                    book.add_local("other", &config(7891));
                    book.enable("p2", &RejectSource, &mut kernel)
                }
            };
            assert_eq!(cancelled.active_id, before.active_id);
            assert!(cancelled.connected && cancelled.system_proxy && cancelled.kernel_running);
            assert!(!cancelled.tun);
            assert_eq!(proxy.http, proxy_before);
            assert!(cancelled.failure.unwrap().starts_with(takeover::TUN_AUTHORIZATION_FAILED));
            kernel.cancelled = false;
            let calls = kernel.calls;
            let ready = book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
            assert!(ready.tun && ready.connected);
            assert!(ready.failure.is_none());
            assert_eq!(kernel.calls, calls + 1, "TUN starts in a single pass");
        }
    }

    #[test]
    fn closing_tun_drops_the_replaced_kernels_connections_and_a_later_sample_sees_new_traffic() {
        let dir = temp_dir("tun-replace");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("a.yaml", &config(7890));
        let mut kernel = ReplacingKernel {
            running: false,
            stay_up: true,
            rows: Vec::new(),
            pending_logs: Vec::new(),
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.connected && connected.system_proxy && !connected.tun);
        let enabled = book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(enabled.tun && enabled.connected);

        kernel.rows.push(ConnectionView {
            host: "example.com".to_string(),
            outbound: "香港节点".to_string(),
    ..Default::default()
});
        let opened = book.set_log_filter("all", &mut kernel);
        assert_eq!(opened.connections.len(), 1);
        assert_eq!(opened.connections[0].host, "example.com");

        kernel.stay_up = false;
        let closed = book.set_tun(false, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!closed.tun);
        assert!(!closed.connected);
        assert!(closed.connections.is_empty());

        kernel.stay_up = true;
        let again = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(again.connected);
        kernel.rows.push(ConnectionView {
            host: "fresh.example".to_string(),
            outbound: "日本节点".to_string(),
    ..Default::default()
});
        kernel.pending_logs.push(LogView {
            level: "info".to_string(),
            message: "新的流量".to_string(),
    ..Default::default()
});
        let sampled = book.set_log_filter("info", &mut kernel);
        assert!(
            sampled
                .connections
                .iter()
                .any(|row| row.host == "fresh.example")
        );
        assert!(sampled.logs.iter().any(|line| line.message == "新的流量"));

        kernel.running = false;
        let exited = book.set_log_filter("all", &mut kernel);
        assert!(!exited.connected);
        assert!(exited.connections.is_empty());
        assert!(!exited.kernel_running);
    }

    #[test]
    fn closing_tun_after_a_sampled_exit_stays_disconnected_while_the_proxy_switch_stays_on() {
        let dir = temp_dir("tun-after-sample");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("a.yaml", &config(7890));
        let mut kernel = ReplacingKernel {
            running: false,
            stay_up: true,
            rows: Vec::new(),
            pending_logs: Vec::new(),
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.connected && connected.system_proxy);
        let enabled = book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(enabled.tun && enabled.connected && enabled.kernel_running);
        kernel.rows.push(ConnectionView {
            host: "stale.example".to_string(),
            outbound: "香港节点".to_string(),
    ..Default::default()
});
        let live = book.set_log_filter("all", &mut kernel);
        assert_eq!(live.connections.len(), 1);

        kernel.running = false;
        book.sync_runtime(&mut kernel);
        let sampled = book.snapshot();
        assert!(!sampled.kernel_running);
        assert!(sampled.system_proxy);
        assert!(!sampled.connected);
        assert!(sampled.connections.is_empty());

        kernel.stay_up = false;
        let closed = book.set_tun(false, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!kernel.running);
        assert!(!closed.connected);
        assert!(!closed.kernel_running);
        assert!(closed.connections.is_empty());
        assert!(closed.system_proxy);
        assert!(!closed.tun);
        assert_eq!(
            proxy.http.as_ref().map(|endpoint| endpoint.port),
            Some(7890)
        );
    }

    struct ModeKernel {
        fail_mode: bool,
        alive: bool,
        last: String,
        up: u64,
        down: u64,
    }

    impl KernelLaunch for ModeKernel {
        fn start_or_reload(&mut self, config_yaml: &str) -> Result<(), String> {
            self.last = config_yaml.to_string();
            self.alive = true;
            Ok(())
        }

        fn running(&mut self) -> bool {
            self.alive
        }

        fn set_mode(&mut self, _mode: &str) -> Result<(), String> {
            if self.fail_mode {
                Err("模式没有切换".to_string())
            } else {
                Ok(())
            }
        }

        fn traffic(&mut self) -> Option<(u64, u64)> {
            Some((self.up, self.down))
        }
    }

    fn yaml_mode(yaml: &str) -> Option<String> {
        let value: Value = serde_yaml::from_str(yaml).ok()?;
        value
            .get("mode")
            .and_then(|item| item.as_str())
            .map(str::to_string)
    }

    #[test]
    fn direct_mode_keeps_the_system_proxy_and_a_failed_switch_keeps_the_mode() {
        let dir = temp_dir("mode");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\n");
        let mut kernel = ModeKernel {
            fail_mode: false,
            alive: false,
            last: String::new(),
            up: 11,
            down: 22,
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.system_proxy);
        assert!(!connected.tun);
        assert!(!connected.vpn);
        assert_eq!(connected.mode.as_deref(), Some("rule"));
        assert_eq!(connected.upload, Some(11));
        assert_eq!(connected.download, Some(22));
        assert_eq!(
            proxy.http.as_ref().map(|endpoint| endpoint.port),
            Some(7890)
        );
        let sets = proxy.sets;

        let switched = book.set_outbound_mode("direct", &mut kernel);
        assert_eq!(switched.mode.as_deref(), Some("direct"));
        assert!(switched.failure.is_none());
        assert!(switched.system_proxy);
        assert!(!switched.tun);
        assert_eq!(proxy.sets, sets);
        assert_eq!(
            proxy.http.as_ref().map(|endpoint| endpoint.port),
            Some(7890)
        );

        let again = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert_eq!(yaml_mode(&kernel.last).as_deref(), Some("direct"));
        assert!(again.system_proxy);
        assert!(!again.tun);
        let sets_after = proxy.sets;

        kernel.fail_mode = true;
        let failed = book.set_outbound_mode("global", &mut kernel);
        assert_eq!(failed.mode.as_deref(), Some("direct"));
        assert_eq!(failed.failure.as_deref(), Some("模式没有切换"));
        assert!(failed.system_proxy);
        assert_eq!(proxy.sets, sets_after);

        let disconnected = book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!disconnected.system_proxy && !disconnected.tun && !disconnected.vpn);
        assert!(disconnected.upload.is_none() && disconnected.download.is_none());
    }

    /// Records every launch with its `force` flag; `fail_forced` makes a forced respawn die.
    #[derive(Default)]
    struct RestartKernel {
        alive: bool,
        fail_forced: bool,
        launches: Vec<(String, bool)>,
    }

    impl KernelLaunch for RestartKernel {
        fn start_or_reload(&mut self, config_yaml: &str) -> Result<(), String> {
            self.start_or_reload_with(config_yaml, false)
        }

        fn start_or_reload_with(&mut self, config_yaml: &str, force: bool) -> Result<(), String> {
            self.launches.push((config_yaml.to_string(), force));
            if force && self.fail_forced {
                self.alive = false;
                return Err("内核启动失败：test-restart".to_string());
            }
            self.alive = true;
            Ok(())
        }

        fn running(&mut self) -> bool {
            self.alive
        }

        fn set_mode(&mut self, _mode: &str) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn restart_kernel_respawns_and_keeps_takeover_and_mode() {
        let dir = temp_dir("restart-kernel");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\n");
        let mut kernel = RestartKernel::default();
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun { grant: true, ..MemoryTun::default() };
        let mut vpn = MemoryVpn::default();
        book.enable("p1", &RejectSource, &mut kernel);
        // Not connected: the request is refused without touching the kernel.
        let launches = kernel.launches.len();
        assert_eq!(
            book.restart_kernel(&mut kernel, &mut proxy, &mut tun, &mut vpn).unwrap_err(),
            RESTART_NEEDS_CONNECTION
        );
        assert_eq!(kernel.launches.len(), launches);

        book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        book.set_outbound_mode("global", &mut kernel);
        assert!(kernel.launches.iter().all(|(_, force)| !force));
        let before = kernel.launches.last().unwrap().0.clone();

        let restarted = book.restart_kernel(&mut kernel, &mut proxy, &mut tun, &mut vpn).unwrap();
        let (yaml, force) = kernel.launches.last().unwrap().clone();
        assert!(force, "restart must force a respawn");
        let config: Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(config["tun"]["enable"].as_bool(), Some(true));
        assert_eq!(config["mode"].as_str(), Some("global"));
        // The respawn reuses the running YAML; only the mode switched live is carried over.
        assert_eq!(yaml, before.replace("mode: rule", "mode: global"));
        assert!(restarted.connected && restarted.tun && restarted.system_proxy);
        assert_eq!(restarted.mode.as_deref(), Some("global"));
        assert!(restarted.failure.is_none());
        assert!(tun.enabled);
        assert_eq!(proxy.http.as_ref().map(|endpoint| endpoint.port), Some(7890));

        // The force flag is consumed by the restart alone.
        book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!kernel.launches.last().unwrap().1);
    }

    #[test]
    fn failed_restart_releases_takeover_like_a_failed_launch() {
        let dir = temp_dir("restart-kernel-fail");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\n");
        let mut kernel = RestartKernel::default();
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun { grant: true, ..MemoryTun::default() };
        let mut vpn = MemoryVpn::default();
        book.enable("p1", &RejectSource, &mut kernel);
        book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        kernel.fail_forced = true;
        let failed = book.restart_kernel(&mut kernel, &mut proxy, &mut tun, &mut vpn).unwrap();
        assert!(!failed.connected && !failed.tun && !failed.system_proxy);
        assert_eq!(failed.failure.as_deref(), Some("内核启动失败：test-restart"));
        assert!(proxy.http.is_none());
        assert!(!tun.enabled);
    }

    #[test]
    fn android_restart_reestablishes_the_vpn_and_forces_a_respawn() {
        let dir = temp_dir("restart-kernel-android");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Android);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\n");
        let mut kernel = RestartKernel::default();
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn { grant: true, ..MemoryVpn::default() };
        book.enable("p1", &RejectSource, &mut kernel);
        assert!(book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn).vpn);
        let establishes = vpn.establish_calls;
        let restarted = book.restart_kernel(&mut kernel, &mut proxy, &mut tun, &mut vpn).unwrap();
        assert_eq!(vpn.establish_calls, establishes + 1);
        assert!(kernel.launches.last().unwrap().1);
        assert!(restarted.connected && restarted.vpn && vpn.open);
    }

    /// Grants the first VPN, then refuses to establish again.
    #[derive(Default)]
    struct OnceVpn {
        inner: MemoryVpn,
    }

    impl VpnGrant for OnceVpn {
        fn authorize(&mut self) -> Result<bool, String> {
            Ok(true)
        }

        fn establish(&mut self, filter: &crate::takeover::AppFilter) -> Result<i32, String> {
            if self.inner.establish_calls > 0 {
                return Err("refused".to_string());
            }
            self.inner.establish(filter)
        }

        fn close(&mut self) -> Result<(), String> {
            self.inner.close()
        }
    }

    #[test]
    fn android_restart_without_a_vpn_drops_tun_by_hot_reload() {
        let dir = temp_dir("restart-kernel-android-novpn");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Android);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\n");
        let mut kernel = RestartKernel::default();
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = OnceVpn::default();
        book.enable("p1", &RejectSource, &mut kernel);
        assert!(book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn).vpn);
        let launches = kernel.launches.len();
        let failed = book.restart_kernel(&mut kernel, &mut proxy, &mut tun, &mut vpn).unwrap();
        // The fallback that removes TUN is a hot reload, not a forced respawn.
        assert_eq!(kernel.launches.len(), launches + 1);
        assert!(!kernel.launches.last().unwrap().1);
        assert!(!failed.connected && !failed.vpn && !vpn.inner.open);
        assert_eq!(failed.failure.as_deref(), Some("VPN 没有建立"));
    }

    struct SampleKernel {
        alive: bool,
        sample: Option<(u64, u64)>,
    }

    impl KernelLaunch for SampleKernel {
        fn start_or_reload(&mut self, _config_yaml: &str) -> Result<(), String> {
            self.alive = true;
            Ok(())
        }

        fn running(&mut self) -> bool {
            self.alive
        }

        fn traffic(&mut self) -> Option<(u64, u64)> {
            self.sample
        }
    }

    #[test]
    fn connected_rates_follow_samples_and_a_missing_sample_is_not_stuck_at_zero() {
        let dir = temp_dir("rates");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\n");
        let mut kernel = SampleKernel {
            alive: false,
            sample: None,
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.connected);
        assert!(connected.upload.is_none() && connected.download.is_none());

        kernel.sample = Some((7, 8));
        book.sync_runtime(&mut kernel);
        let sampled = book.snapshot();
        assert_eq!(sampled.upload, Some(7));
        assert_eq!(sampled.download, Some(8));

        kernel.sample = None;
        book.sync_runtime(&mut kernel);
        let held = book.snapshot();
        assert_eq!(held.upload, Some(7));
        assert_eq!(held.download, Some(8));

        kernel.sample = Some((1, 2));
        book.sync_runtime(&mut kernel);
        let replaced = book.snapshot();
        assert_eq!(replaced.upload, Some(1));
        assert_eq!(replaced.download, Some(2));

        let disconnected = book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!disconnected.connected);
        assert!(disconnected.upload.is_none() && disconnected.download.is_none());
    }

    #[test]
    fn outbound_mode_keeps_the_previous_failure_until_the_next_connect() {
        let dir = temp_dir("mode-keeps-failure");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\n");
        let mut kernel = ModeKernel {
            fail_mode: false,
            alive: false,
            last: String::new(),
            up: 11,
            down: 22,
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.connected && connected.failure.is_none());
        assert!(connected.system_proxy);
        let sets = proxy.sets;

        kernel.fail_mode = true;
        let denied = book.set_outbound_mode("global", &mut kernel);
        assert_eq!(denied.mode.as_deref(), Some("rule"));
        assert_eq!(denied.failure.as_deref(), Some("模式没有切换"));
        assert_eq!(proxy.sets, sets);
        assert!(denied.system_proxy);

        kernel.fail_mode = false;
        let switched = book.set_outbound_mode("direct", &mut kernel);
        assert_eq!(switched.mode.as_deref(), Some("direct"));
        assert_eq!(switched.failure.as_deref(), Some("模式没有切换"));
        assert!(switched.system_proxy && !switched.tun);
        assert_eq!(proxy.sets, sets);

        kernel.alive = false;
        let recorded = book.set_outbound_mode("global", &mut kernel);
        assert_eq!(recorded.mode.as_deref(), Some("global"));
        assert_eq!(recorded.failure.as_deref(), Some("模式没有切换"));
        assert_eq!(recorded.system_proxy, switched.system_proxy);
        assert_eq!(proxy.sets, sets);

        kernel.alive = true;
        let again = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(again.connected);
        assert!(again.failure.is_none());
        assert!(again.system_proxy);
        assert_eq!(yaml_mode(&kernel.last).as_deref(), Some("global"));
        assert_eq!(
            proxy.http.as_ref().map(|endpoint| endpoint.port),
            Some(7890)
        );
    }

    #[test]
    fn home_failure_survives_disconnect_proxy_close_and_tun_until_connect() {
        let dir = temp_dir("keep-home-failure");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\n");
        let mut kernel = ModeKernel {
            fail_mode: false,
            alive: false,
            last: String::new(),
            up: 1,
            down: 2,
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.connected && connected.failure.is_none());

        kernel.fail_mode = true;
        let denied = book.set_outbound_mode("global", &mut kernel);
        assert_eq!(denied.mode.as_deref(), Some("rule"));
        assert_eq!(denied.failure.as_deref(), Some("模式没有切换"));
        assert!(denied.system_proxy && denied.connected);
        kernel.fail_mode = false;

        let closed_proxy =
            book.set_system_proxy(false, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!closed_proxy.system_proxy);
        assert_eq!(closed_proxy.failure.as_deref(), Some("模式没有切换"));

        let opened_tun = book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(opened_tun.tun);
        assert_eq!(opened_tun.failure.as_deref(), Some("模式没有切换"));

        let disconnected = book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!disconnected.connected);
        assert!(!disconnected.system_proxy && !disconnected.tun && !disconnected.vpn);
        assert_eq!(disconnected.failure.as_deref(), Some("模式没有切换"));

        let again = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(again.connected);
        assert!(again.failure.is_none());
        assert!(again.system_proxy);
    }

    #[cfg(unix)]
    #[test]
    fn process_runtime_reads_injected_controller_traffic_without_touching_system_proxy() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::mpsc;
        use std::thread;

        let dir = temp_dir("runtime-traffic");
        let mixed_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mixed_port = mixed_listener.local_addr().unwrap().port();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (gate_tx, gate_rx) = mpsc::channel::<()>();
        let server = thread::spawn(move || {
            fn accept_for(listener: &std::net::TcpListener) -> std::net::TcpStream {
                let deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => return stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                panic!("controller client did not connect");
                            }
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Err(error) => panic!("{error}"),
                    }
                }
            }
            fn read_headers(stream: &mut std::net::TcpStream) -> String {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 2048];
                loop {
                    match stream.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(count) => {
                            buf.extend_from_slice(&tmp[..count]);
                            if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                String::from_utf8_lossy(&buf).into_owned()
            }
            fn write_json(stream: &mut std::net::TcpStream, body: &str) {
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
            listener.set_nonblocking(true).unwrap();
            let (mut first_stream, first_seen) = loop {
                let mut stream = accept_for(&listener);
                stream.set_nonblocking(false).unwrap();
                let headers = read_headers(&mut stream);
                if headers.contains("GET /configs") {
                    write_json(&mut stream, &format!(r#"{{"mixed-port":{mixed_port},"tun":{{"enable":false}}}}"#));
                } else if headers.contains("GET /memory") {
                    write_json(&mut stream, "{\"inuse\":12345}\n");
                } else { break (stream, headers); }
            };
            write_json(&mut first_stream, "{\"up\":4,\"down\":5}");
            drop(first_stream);
            let (mut second_stream, second_seen) = loop {
                let mut stream = accept_for(&listener);
                stream.set_nonblocking(false).unwrap();
                let headers = read_headers(&mut stream);
                if headers.contains("GET /memory") {
                    write_json(&mut stream, "{\"inuse\":12345}\n");
                } else { break (stream, headers); }
            };
            let _ = gate_rx.recv_timeout(Duration::from_secs(3));
            write_json(&mut second_stream, "{\"up\":8,\"down\":9}");
            format!("{first_seen}\n{second_seen}")
        });
        let script = dir.0.join("stand-in.sh");
        fs::write(&script, "#!/bin/sh\nsleep 30\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let mut runtime = ProcessRuntime::new(&dir.0);
        runtime.set_kernel_path(Some(script));
        runtime
            .start_or_reload(&format!(
                "mixed-port: {mixed_port}\nexternal-controller: 127.0.0.1:{port}\nsecret: billow-local\n"
            ))
            .unwrap();
        let first = wait_traffic(&mut runtime, Some((4, 5)));
        assert_eq!(first, Some((4, 5)));
        gate_tx.send(()).unwrap();
        let second = wait_traffic(&mut runtime, Some((8, 9)));
        assert_eq!(second, Some((8, 9)));
        runtime.stop();
        assert!(runtime.traffic().is_none());
        let seen = server.join().unwrap();
        assert!(seen.contains("GET /traffic"), "{seen}");
        assert!(seen.contains("Bearer billow-local"), "{seen}");
        assert!(!seen.contains("networksetup"), "{seen}");
    }

    #[cfg(unix)]
    fn wait_traffic(runtime: &mut ProcessRuntime, want: Option<(u64, u64)>) -> Option<(u64, u64)> {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut last = None;
        while Instant::now() < deadline {
            last = runtime.traffic();
            if last == want {
                return last;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        last
    }

    #[test]
    fn rule_toggle_filters_the_runtime_config_and_rolls_back_a_failed_reload() {
        struct RuleKernel {
            running: bool,
            reloaded: Vec<String>,
            fail: bool,
        }

        impl KernelLaunch for RuleKernel {
            fn start_or_reload(&mut self, _config_yaml: &str) -> Result<(), String> {
                self.running = true;
                Ok(())
            }

            fn running(&mut self) -> bool {
                self.running
            }

            fn reload_config(&mut self, config_yaml: &str) -> Result<(), String> {
                if self.fail {
                    return Err("规则没有切换".to_string());
                }
                self.reloaded.push(config_yaml.to_string());
                Ok(())
            }
        }

        let dir = temp_dir("rule-toggle");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local(
            "rules.yaml",
            "mixed-port: 7890\nmode: rule\nproxies: []\nrules:\n  - DOMAIN-SUFFIX,google.com,PROXY\n  - DOMAIN-SUFFIX,google.com,PROXY\n  - MATCH,DIRECT\n",
        );
        let mut kernel = RuleKernel {
            running: false,
            reloaded: Vec::new(),
            fail: false,
        };
        book.enable("p1", &RejectSource, &mut kernel);

        let disabled_key = diagnostics::rule_key("DomainSuffix", "google.com", "PROXY", 0);
        let second_key = diagnostics::rule_key("DomainSuffix", "google.com", "PROXY", 1);
        let other = diagnostics::rule_key("Match", "", "DIRECT", 0);

        // An unknown identity is rejected without changing the set.
        let unknown = book
            .set_rule_disabled(
                RuleToggle {
                    key: "domainsuffix|missing.example|PROXY|0".to_string(),
                    disabled: true,
                },
                &mut kernel,
            )
            .unwrap_err();
        assert_eq!(unknown, "没有这条规则");
        assert!(book.rules(&mut kernel).disabled.is_empty());
        assert!(kernel.reloaded.is_empty());

        let snapshot = book
            .set_rule_disabled(
                RuleToggle {
                    key: disabled_key.clone(),
                    disabled: true,
                },
                &mut kernel,
            )
            .unwrap();
        assert_eq!(snapshot.disabled, vec![disabled_key.clone()]);
        assert_eq!(kernel.reloaded.len(), 1);
        assert_eq!(
            kernel.reloaded[0].matches("google.com,PROXY").count(),
            1,
            "one of two identical rules is hidden"
        );
        assert!(kernel.reloaded[0].contains("MATCH,DIRECT"));

        // The second identical rule keeps its own identity even though the kernel
        // now only returns the remaining occurrence.
        let both = book
            .set_rule_disabled(
                RuleToggle {
                    key: second_key.clone(),
                    disabled: true,
                },
                &mut kernel,
            )
            .unwrap();
        assert_eq!(both.disabled, vec![disabled_key.clone(), second_key.clone()]);
        assert_eq!(kernel.reloaded.len(), 2);
        assert_eq!(
            kernel.reloaded[1].matches("google.com,PROXY").count(),
            0,
            "the second occurrence is removed from the full config, not the filtered one"
        );

        let first_back = book
            .set_rule_disabled(
                RuleToggle {
                    key: disabled_key.clone(),
                    disabled: false,
                },
                &mut kernel,
            )
            .unwrap();
        assert_eq!(first_back.disabled, vec![second_key.clone()]);
        assert_eq!(
            kernel.reloaded[2].matches("google.com,PROXY").count(),
            1,
            "re-enabling the first occurrence restores exactly one"
        );

        kernel.fail = true;
        let error = book
            .set_rule_disabled(
                RuleToggle {
                    key: other.clone(),
                    disabled: true,
                },
                &mut kernel,
            )
            .unwrap_err();
        assert_eq!(error, "规则没有切换");
        let after_failure = book.rules(&mut kernel);
        assert_eq!(after_failure.disabled, vec![second_key.clone()]);
        assert!(!after_failure.disabled.contains(&other));
        assert_eq!(kernel.reloaded.len(), 3, "a failed reload does not push a config");

        kernel.fail = false;
        let enabled = book
            .set_rule_disabled(
                RuleToggle {
                    key: second_key.clone(),
                    disabled: false,
                },
                &mut kernel,
            )
            .unwrap();
        assert!(enabled.disabled.is_empty());
        assert_eq!(
            kernel.reloaded.last().unwrap().matches("google.com,PROXY").count(),
            2,
            "re-enabling restores every occurrence"
        );

        // Activating a config starts from a clean runtime rule set.
        book.set_rule_disabled(
            RuleToggle {
                key: disabled_key.clone(),
                disabled: true,
            },
            &mut kernel,
        )
        .unwrap();
        book.enable("p1", &RejectSource, &mut kernel);
        assert!(book.rules(&mut kernel).disabled.is_empty());

        // The set lives only in memory, so reopening the app starts with no disabled rules.
        book.set_rule_disabled(
            RuleToggle {
                key: disabled_key.clone(),
                disabled: true,
            },
            &mut kernel,
        )
        .unwrap();
        let mut reopened = ProfileBook::open(&dir.0);
        let mut idle = RuleKernel {
            running: true,
            reloaded: Vec::new(),
            fail: false,
        };
        assert!(reopened.rules(&mut idle).disabled.is_empty());
    }

    #[test]
    fn test_all_reports_each_node_with_tested_and_total() {
        let dir = temp_dir("test-all-progress");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("nodes.yaml", &grouped_config());
        let mut kernel = node_kernel();
        kernel.report_running = true;
        kernel.scripts.insert(
            String::new(),
            vec![
                NodeDelay {
                    name: "z-node".to_string(),
                    delay_ms: Some(20),
                },
                NodeDelay {
                    name: "m-node".to_string(),
                    delay_ms: None,
                },
                NodeDelay {
                    name: "a-node".to_string(),
                    delay_ms: Some(5),
                },
            ],
        );
        let mut events: Vec<(String, Option<u64>, bool, usize, usize)> = Vec::new();
        let snapshot = book.test_all_with_progress(&mut kernel, &mut |node, delay, failed, tested, total| {
            events.push((node.to_string(), delay, failed, tested, total));
        });
        assert!(snapshot.nodes_error.is_none());
        assert_eq!(events.len(), 3);
        assert_eq!(
            events.iter().map(|event| event.3).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert!(events.iter().all(|event| event.4 == 3));
        assert!(events.iter().any(|event| event.0 == "m-node" && event.2 && event.1.is_none()));
        assert!(events.iter().any(|event| event.0 == "a-node" && !event.2 && event.1 == Some(5)));
    }

    #[test]
    fn dns_override_emits_mapping_policy_hosts_and_geo_overrides() {
        let base = "mixed-port: 7890\ngeox-url:\n  geoip: https://profile.example/geoip.dat\nhosts:\n  existing.local: 10.0.0.1\n";
        let mut settings = KernelSettings {
            dns_override: true,
            geodata_mode: Some(true),
            geodata_loader: Some("MEMCONSERVATIVE".to_string()),
            geo_source: "jsdelivr".to_string(),
            ..Default::default()
        };
        settings.geo_urls.geosite = "https://custom.example/geosite.dat".to_string();
        settings.dns.listen = " 127.0.0.1:1053 ".to_string();
        settings.dns.enhanced_mode = "FAKE-IP".to_string();
        settings.dns.fake_ip_filter_mode = "WHITELIST".to_string();
        settings.dns.prefer_h3 = true;
        settings.dns.cache_algorithm = "ARC".to_string();
        settings.dns.use_hosts = true;
        settings.dns.use_system_hosts = false;
        settings.dns.respect_rules = true;
        settings.dns.direct_nameserver_follow_policy = true;
        settings.dns.nameserver_policy.insert(
            "geosite:cn,private".to_string(),
            vec!["https://223.5.5.5/dns-query".to_string(), "119.29.29.29".to_string()],
        );
        settings.dns.nameserver_policy.insert(
            "+.corp.internal".to_string(),
            vec!["10.0.0.53".to_string()],
        );
        settings.dns.hosts.insert(
            "router.local".to_string(),
            vec!["192.168.1.1".to_string()],
        );
        settings.dns.hosts.insert(
            "dual.local".to_string(),
            vec!["192.168.1.2".to_string(), "fe80::1".to_string()],
        );
        let normalized = settings.normalized();
        let (yaml, _) = apply_settings(base, &normalized, true).unwrap();
        let value: Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(mapping_get(&value, "geodata-mode").and_then(Value::as_bool), Some(true));
        assert_eq!(read_string(&value, "geodata-loader").as_deref(), Some("memconservative"));
        let geox = mapping_get(&value, "geox-url").unwrap();
        assert_eq!(
            read_string(geox, "geosite").as_deref(),
            Some("https://custom.example/geosite.dat")
        );
        assert_eq!(
            read_string(geox, "mmdb").as_deref(),
            Some("https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb")
        );

        let dns = mapping_get(&value, "dns").unwrap();
        assert_eq!(read_string(dns, "listen").as_deref(), Some("127.0.0.1:1053"));
        assert_eq!(read_string(dns, "enhanced-mode").as_deref(), Some("fake-ip"));
        assert_eq!(read_string(dns, "fake-ip-filter-mode").as_deref(), Some("whitelist"));
        assert_eq!(mapping_get(dns, "prefer-h3").and_then(Value::as_bool), Some(true));
        assert_eq!(read_string(dns, "cache-algorithm").as_deref(), Some("arc"));
        assert_eq!(mapping_get(dns, "use-hosts").and_then(Value::as_bool), Some(true));
        assert_eq!(mapping_get(dns, "use-system-hosts").and_then(Value::as_bool), Some(false));
        assert_eq!(
            mapping_get(dns, "direct-nameserver-follow-policy").and_then(Value::as_bool),
            Some(true)
        );
        let policy = mapping_get(dns, "nameserver-policy").unwrap();
        assert_eq!(read_string(policy, "+.corp.internal").as_deref(), Some("10.0.0.53"));
        assert_eq!(
            mapping_get(policy, "geosite:cn,private")
                .and_then(Value::as_sequence)
                .map(|s| s.len()),
            Some(2)
        );

        let hosts = mapping_get(&value, "hosts").unwrap();
        assert_eq!(read_string(hosts, "existing.local").as_deref(), Some("10.0.0.1"));
        assert_eq!(read_string(hosts, "router.local").as_deref(), Some("192.168.1.1"));
        assert_eq!(
            mapping_get(hosts, "dual.local")
                .and_then(Value::as_sequence)
                .map(|s| s.len()),
            Some(2)
        );

        let resolved = normalized.resolve_geo_download_urls(Some(&yaml));
        let geosite_urls = resolved.iter().find(|(k, _)| k == "geosite").unwrap();
        assert_eq!(geosite_urls.1, vec!["https://custom.example/geosite.dat".to_string()]);
        let mmdb_urls = resolved.iter().find(|(k, _)| k == "mmdb").unwrap();
        assert!(mmdb_urls.1[0].contains("cdn.jsdelivr.net"));
        assert!(mmdb_urls.1.len() >= 2);
    }

    #[test]
    fn saving_system_proxy_or_geo_settings_keeps_session_smooth_without_spurious_tun_prompts() {
        struct LiveKernel {
            running: Option<String>,
            calls: u32,
        }
        impl KernelLaunch for LiveKernel {
            fn start_or_reload(&mut self, config_yaml: &str) -> Result<(), String> {
                self.calls += 1;
                self.running = Some(config_yaml.to_string());
                Ok(())
            }
            fn running(&mut self) -> bool {
                self.running.is_some()
            }
        }

        let dir = temp_dir("proxy-settings-live");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\nproxies: []\n");
        let mut kernel = LiveKernel { running: None, calls: 0 };
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun { grant: true, ..Default::default() };
        let mut vpn = MemoryVpn::default();
        book.enable("p1", &RejectSource, &mut kernel);
        let mut overridden = book.snapshot().settings;
        overridden.mixed_port = Some(7891);
        book.save_settings(overridden, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        let initial_calls = kernel.calls;

        // Updating only system proxy host/bypass applies immediately without restarting kernel.
        let mut next = book.snapshot().settings;
        next.system_proxy.host = "127.0.0.2".to_string();
        next.system_proxy.bypass = vec!["localhost".to_string(), "*.lan".to_string()];
        let snap = book.save_settings(next, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(snap.connected);
        assert_eq!(snap.mixed_port, Some(7891));
        assert_eq!(kernel.calls, initial_calls, "system_proxy-only edits must not reload kernel");
        assert_eq!(
            proxy.http,
            Some(takeover::ProxyEndpoint {
                host: "127.0.0.2".to_string(),
                port: 7891,
            })
        );
        assert_eq!(
            proxy.settings.as_ref().unwrap().bypass,
            vec!["localhost".to_string(), "*.lan".to_string()]
        );

        // Even if tun_wanted was remembered while TUN is currently off, saving GEO source
        // reloads the config cleanly without prompting tun.authorize().
        book.tun_wanted = true;
        tun.grant = false;
        let auth_before = tun.authorize_calls;
        let mut geo_next = book.snapshot().settings;
        geo_next.geo_source = "testingcf".to_string();
        let snap2 = book.save_settings(geo_next, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(snap2.connected);
        assert!(snap2.failure.is_none());
        assert_eq!(tun.authorize_calls, auth_before);
        assert_eq!(kernel.calls, initial_calls + 1);
        assert_eq!(snap2.mixed_port, Some(7891));

        // Restoring the default must move both the real listener config and all UI/proxy endpoints.
        let mut defaults = snap2.settings;
        defaults.mixed_port = None;
        let restored = book.save_settings(defaults, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert_eq!(restored.mixed_port, Some(7890));
        assert_eq!(proxy.http.as_ref().unwrap().port, 7890);
        let running: Value = serde_yaml::from_str(kernel.running.as_deref().unwrap()).unwrap();
        assert_eq!(read_i64(&running, "mixed-port"), Some(7890));
        assert_eq!(ProfileBook::open(&dir.0).snapshot().mixed_port, Some(7890));
    }

    #[cfg(unix)]
    #[test]
    fn process_runtime_hot_reloads_in_place_without_killing_child_process() {
        use std::io::{Read, Write};
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("hot-reload-runtime");
        let mixed_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mixed_port = mixed_listener.local_addr().unwrap().port();
        let api_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let api_port = api_listener.local_addr().unwrap().port();
        let stop_server = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop_server);
        let put_payloads: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let put_shared = Arc::clone(&put_payloads);

        api_listener.set_nonblocking(true).unwrap();
        mixed_listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                while mixed_listener.accept().is_ok() {}
                if let Ok((mut stream, _)) = api_listener.accept() {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                    let mut buf = vec![0u8; 16384];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        continue;
                    }
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let first_line = req.lines().next().unwrap_or("");
                    if first_line.starts_with("PUT /configs?force=true") {
                        let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
                        put_shared.lock().unwrap().push(body);
                        let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    } else if first_line.starts_with("GET /configs") {
                        let body = format!("{{\"mixed-port\":{mixed_port},\"tun\":{{\"enable\":false}}}}");
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    } else {
                        let body = "{}";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            drop(mixed_listener);
        });

        let script = dir.0.join("stand-in.sh");
        fs::write(&script, "#!/bin/sh\nsleep 30\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

        let mut runtime = ProcessRuntime::new(&dir.0);
        runtime.set_kernel_path(Some(script));
        let yaml1 = format!(
            "mixed-port: {mixed_port}\nmode: rule\nexternal-controller: 127.0.0.1:{api_port}\nsecret: s1\n"
        );
        let endpoint = nodes::controller_from_yaml(&yaml1).unwrap();
        let ready_deadline = Instant::now() + Duration::from_secs(3);
        while !nodes::listeners_ready(&endpoint, Some(mixed_port), false) {
            assert!(Instant::now() < ready_deadline, "test controller must be ready before runtime port selection");
            std::thread::sleep(Duration::from_millis(10));
        }
        runtime.start_or_reload(&yaml1).unwrap();
        let pid_before = runtime.child.as_ref().unwrap().id();

        let yaml2 = format!(
            "mixed-port: {mixed_port}\nmode: global\ngeodata-mode: true\nexternal-controller: 127.0.0.1:9090\nsecret: other\n"
        );
        runtime.start_or_reload(&yaml2).unwrap();
        let pid_after = runtime.child.as_ref().unwrap().id();
        assert_eq!(pid_before, pid_after, "hot reload must keep existing child PID alive");

        let payloads = put_payloads.lock().unwrap().clone();
        assert_eq!(payloads.len(), 1);
        let sent: serde_json::Value = serde_json::from_str(&payloads[0]).unwrap();
        let sent_yaml = sent["payload"].as_str().unwrap();
        assert!(sent_yaml.contains("mode: global"));
        assert!(sent_yaml.contains(&format!("127.0.0.1:{api_port}")));

        runtime.stop();
        stop_server.store(true, Ordering::Relaxed);
        let _ = server.join();
    }

    #[test]
    fn auto_connect_starts_once_clears_guard_when_stable_and_pauses_after_crashed_launch() {
        struct GuardKernel {
            alive: bool,
            fail: bool,
            uptime: u64,
            starts: usize,
        }
        impl KernelLaunch for GuardKernel {
            fn start_or_reload(&mut self, _yaml: &str) -> Result<(), String> {
                self.starts += 1;
                if self.fail {
                    self.alive = false;
                    return Err("端口占用".to_string());
                }
                self.alive = true;
                Ok(())
            }
            fn running(&mut self) -> bool {
                self.alive
            }
            fn kernel_uptime_secs(&mut self) -> Option<u64> {
                self.alive.then_some(self.uptime)
            }
        }

        let dir = temp_dir("auto-connect-guard");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local(
            "chain.yaml",
            "mixed-port: 7890\nmode: rule\nproxies:\n  - {name: front, type: ss}\n  - {name: landing, type: vless, dialer-proxy: front}\nproxy-groups:\n  - {name: manual, type: select, proxies: [landing, front]}\n",
        );
        let mut kernel = GuardKernel { alive: false, fail: false, uptime: 1, starts: 0 };
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        book.enable("p1", &RejectSource, &mut kernel);
        let snap0 = book.snapshot();
        assert_eq!(snap0.node_catalog[0].nodes[0].dialer_proxy.as_deref(), Some("front"));
        assert!(snap0.node_catalog[0].nodes[0].tags.iter().any(|tag| tag == "链式"));

        // Off by default: launch hook is a no-op.
        assert!(book.auto_connect_on_launch(&mut kernel, &mut proxy, &mut tun, &mut vpn).is_none());

        let mut settings = book.settings.clone();
        settings.auto_connect = true;
        let prev_starts = kernel.starts;
        book.save_settings(settings, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert_eq!(kernel.starts, prev_starts, "toggling auto_connect must not restart a running kernel");
        book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        kernel.alive = false;

        // Simulated launch 1: auto-connect succeeds, guard stays until uptime >= 8s.
        let launched = book
            .auto_connect_on_launch(&mut kernel, &mut proxy, &mut tun, &mut vpn)
            .expect("auto_connect should run");
        assert!(launched.connected && launched.system_proxy);
        assert!(book.startup_guard_path().exists());

        // Simulated crash BEFORE 8s stabilization: next launch finds the guard, skips
        // auto-connect, removes the guard and clears any lingering system proxy.
        let mut after_crash = ProfileBook::open(&dir.0);
        after_crash.set_platform(ClientPlatform::Desktop);
        let mut fresh_kernel = GuardKernel { alive: false, fail: false, uptime: 0, starts: 0 };
        let paused = after_crash
            .auto_connect_on_launch(&mut fresh_kernel, &mut proxy, &mut tun, &mut vpn)
            .expect("guard should report paused state");
        assert!(!paused.connected);
        assert_eq!(fresh_kernel.starts, 0, "must not spawn kernel after aborted startup");
        assert!(!after_crash.startup_guard_path().exists(), "guard is consumed once");
        assert!(paused.failure.as_deref().unwrap_or_default().contains("暂停自动连接"));
        assert!(proxy.http.is_none());

        // Subsequent normal launch succeeds and clears the guard once uptime >= 8s.
        let recovered = after_crash
            .auto_connect_on_launch(&mut fresh_kernel, &mut proxy, &mut tun, &mut vpn)
            .expect("next launch resumes normally");
        assert!(recovered.connected);
        assert!(after_crash.startup_guard_path().exists());
        fresh_kernel.uptime = STARTUP_STABLE_SECS;
        after_crash.sync_runtime(&mut fresh_kernel);
        assert!(!after_crash.startup_guard_path().exists(), "stable uptime clears guard");

        after_crash.disconnect(&mut fresh_kernel, &mut proxy, &mut tun, &mut vpn);
        fresh_kernel.uptime = 0;
        after_crash.auto_connect_on_launch(&mut fresh_kernel, &mut proxy, &mut tun, &mut vpn).unwrap();
        assert!(after_crash.startup_guard_path().exists());
        after_crash.prepare_exit();
        assert!(!after_crash.startup_guard_path().exists());
        after_crash.release_lingering_proxy(&mut proxy);
        assert!(!after_crash.should_auto_connect(), "a queued launch cannot start during exit");
        let mut after_crash = ProfileBook::open(&dir.0);

        // Cleanly handled start failure clears the guard immediately without looping.
        after_crash.disconnect(&mut fresh_kernel, &mut proxy, &mut tun, &mut vpn);
        fresh_kernel.alive = false;
        fresh_kernel.fail = true;
        let failed = after_crash
            .auto_connect_on_launch(&mut fresh_kernel, &mut proxy, &mut tun, &mut vpn)
            .expect("handled error still returns snapshot");
        assert!(!failed.connected);
        assert!(!after_crash.startup_guard_path().exists());
    }

    #[test]
    fn runtime_crash_recovers_once_then_trips_circuit_breaker_and_releases_proxy() {
        struct CrashKernel {
            alive: bool,
            fail_restart: bool,
            exit: Option<String>,
            starts: usize,
        }
        impl KernelLaunch for CrashKernel {
            fn start_or_reload(&mut self, _yaml: &str) -> Result<(), String> {
                self.starts += 1;
                if self.fail_restart {
                    self.alive = false;
                    return Err("配置语法错误".to_string());
                }
                self.alive = true;
                Ok(())
            }
            fn running(&mut self) -> bool {
                self.alive
            }
            fn take_exit_detail(&mut self) -> Option<String> {
                self.exit.take()
            }
        }

        let dir = temp_dir("crash-breaker");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("a.yaml", &config(7890));
        let mut kernel = CrashKernel { alive: false, fail_restart: false, exit: None, starts: 0 };
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        book.enable("p1", &RejectSource, &mut kernel);
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.connected && proxy.http.is_some());

        // First unexpected crash: silent 1-shot restart keeps connection & proxy alive.
        kernel.alive = false;
        kernel.exit = Some("退出码 2".to_string());
        let healed = book
            .recover_crashed_kernel(&mut kernel, &mut proxy, &mut tun, &mut vpn)
            .expect("first crash should self-heal");
        assert!(healed.connected && healed.kernel_running);
        assert!(proxy.http.is_some());

        // Second crash within 60s window: circuit breaker trips, stops restarting, and
        // releases OS system proxy so user traffic is not blackholed.
        let starts_before = kernel.starts;
        kernel.alive = false;
        kernel.exit = Some("退出码 2".to_string());
        let tripped = book
            .recover_crashed_kernel(&mut kernel, &mut proxy, &mut tun, &mut vpn)
            .expect("second crash trips circuit breaker");
        assert_eq!(kernel.starts, starts_before, "circuit breaker must not restart again");
        assert!(!tripped.connected);
        assert!(!tripped.system_proxy);
        assert!(proxy.http.is_none(), "system proxy must be cleared on repeated crash");
        assert!(tripped.failure.as_deref().unwrap_or_default().contains("连续异常退出"));
    }

    #[test]
    fn stored_proxy_counts_survive_refresh_and_load_from_legacy_files() {
        let dir = temp_dir("proxy-count");
        let mut book = ProfileBook::open(&dir.0);
        book.add_subscription("https://example.com/test");
        let request = book.prepare_refresh("p1").unwrap();
        let content = "mixed-port: 7890\nproxies: [{name: n1}, {name: n2}]";
        let data = FetchedSubscription { content: content.into(), userinfo: None }.into_profile("").unwrap();
        book.finish_refresh(&request, Ok(data), &mut FakeKernel { running: None, fail: false, calls: 0 });
        let path = dir.0.join("profiles.json");
        let mut disk: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(disk["profiles"][0]["proxy_count"], 2);
        assert_eq!(ProfileBook::open(&dir.0).profiles[0].proxy_count, 2);
        disk["profiles"][0].as_object_mut().unwrap().remove("proxy_count");
        fs::write(path, serde_json::to_vec(&disk).unwrap()).unwrap();
        assert_eq!(ProfileBook::open(&dir.0).profiles[0].proxy_count, 2);
    }

    #[test]
    fn rejected_live_refresh_preserves_the_last_working_subscription_on_disk() {
        let dir = temp_dir("refresh-rejected");
        let mut book = ProfileBook::open(&dir.0);
        let url = "https://example.com/sub";
        book.add_subscription(url);
        let mut source = MapSource { items: HashMap::new() };
        source.items.insert(url.into(), Ok(FetchedSubscription { content: config(7890), userinfo: None }));
        let mut kernel = node_kernel();
        book.enable("p1", &source, &mut kernel);
        let original = book.profile_content("p1").unwrap();
        let last_success = book.profiles[0].last_success_ms;
        source.items.insert(url.into(), Ok(FetchedSubscription { content: config(7891), userinfo: None }));
        struct RejectReload { alive: bool, stop_on_reload: bool }
        impl KernelLaunch for RejectReload {
            fn running(&mut self) -> bool { self.alive }
            fn start_or_reload(&mut self, _: &str) -> Result<(), String> {
                self.alive = !self.stop_on_reload;
                Err("kernel rejected reload".into())
            }
        }
        let mut reject = RejectReload { alive: true, stop_on_reload: false };
        let failed = book.refresh_profile("p1", &source, &mut reject);
        assert!(failed.profiles[0].failure.is_some());
        assert_eq!(failed.profiles[0].last_success_ms, last_success);
        assert_eq!(ProfileBook::open(&dir.0).profile_content("p1"), Some(original));
        assert!(book.pending_release.is_none());

        reject.stop_on_reload = true;
        book.refresh_profile("p1", &source, &mut reject);
        assert!(book.pending_release.is_some(), "a dead listener must release its traffic takeover");
    }

    #[test]
    fn concurrent_refreshes_discard_results_after_edits_or_newer_requests() {
        let dir = temp_dir("split-refresh");
        let mut book = ProfileBook::open(&dir.0);
        book.add_subscription("https://a.example/sub");
        book.add_subscription("https://b.example/sub");
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };

        let first = book.prepare_refresh("p1").unwrap();
        let old_url = book.prepare_refresh("p2").unwrap();
        assert_eq!(first.source, "https://a.example/sub");
        assert!(first.user_agent.is_empty());

        book.set_profile_source("p2", "https://new-b.example/sub");
        book.finish_refresh(&old_url, Err("obsolete".into()), &mut kernel);
        assert!(book.profiles[1].updated_ms.is_none());

        let current = book.prepare_refresh("p1").unwrap();
        let data = FetchedSubscription {
            content: "mixed-port: 7890\nproxies:\n  - {name: hk, type: ss}\n".into(),
            userinfo: None,
        }.into_profile("").unwrap();
        book.finish_refresh(&current, Ok(data), &mut kernel);
        book.finish_refresh(&first, Err("late response".into()), &mut kernel);
        assert_eq!(book.profiles[0].proxy_count, 1);
        assert!(book.profiles[0].failure.is_none());

        let changed = book.prepare_refresh("p1").unwrap();
        book.settings.subscription_user_agent = "new-client".into();
        book.finish_refresh(&changed, Err("obsolete UA".into()), &mut kernel);
        assert!(book.profiles[0].failure.is_none());

        let edited = book.prepare_refresh("p1").unwrap();
        book.save_profile_content("p1", &config(7899), &mut kernel);
        book.finish_refresh(&edited, Err("obsolete content".into()), &mut kernel);
        assert!(book.profiles[0].failure.is_none());

        let current_b = book.prepare_refresh("p2").unwrap();
        book.finish_refresh(&current_b, Err("timeout".into()), &mut kernel);
        assert_eq!(book.profiles[1].failure.as_deref(), Some("timeout"));
    }

    #[test]
    fn closing_a_connection_set_reports_failures_and_offline_kernels() {
        use std::io::{BufRead, BufReader as Lines, Write};
        struct ControllerKernel(Option<ControllerEndpoint>);
        impl KernelLaunch for ControllerKernel {
            fn start_or_reload(&mut self, _config_yaml: &str) -> Result<(), String> { Ok(()) }
            fn running(&mut self) -> bool { self.0.is_some() }
            fn controller(&mut self) -> Option<ControllerEndpoint> { self.0.clone() }
        }
        let dir = temp_dir("close-connection-set");
        let mut book = ProfileBook::open(&dir.0);

        let offline = book.close_connection_set(Some(&["a".to_string()]), &mut ControllerKernel(None));
        assert_eq!(offline.notice.as_deref(), Some(KERNEL_DOWN));

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let mut lines = Vec::new();
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = Lines::new(stream.try_clone().unwrap());
                let mut first = String::new();
                reader.read_line(&mut first).unwrap();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() { break; }
                }
                let code = if first.contains("/connections/kept ") { 500 } else { 204 };
                write!(stream, "HTTP/1.1 {code} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                lines.push(first);
            }
            lines
        });
        let mut kernel = ControllerKernel(Some(ControllerEndpoint { host: "127.0.0.1".into(), port, secret: String::new() }));
        let partial = book.close_connection_set(Some(&["closed".to_string(), "kept".to_string()]), &mut kernel);
        assert_eq!(partial.notice.as_deref(), Some("1 条连接没有关闭"));
        // A later successful close clears the earlier failure count.
        let cleared = book.close_connection_set(Some(&["closed".to_string()]), &mut kernel);
        assert_eq!(cleared.notice, None);
        let lines = server.join().unwrap();
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|line| line.starts_with("DELETE /connections/")));

        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let permissions = capability["permissions"].as_array().unwrap();
        for permission in ["allow-close-connections", "allow-dns-query"] {
            assert!(permissions.iter().any(|item| item.as_str() == Some(permission)), "{permission}");
        }
    }

    /// Test kernel that records the selected engine and can refuse a config.
    struct EngineKernel {
        engine: Engine,
        alive: bool,
        launched: Option<Engine>,
        last: String,
        starts: u32,
        stops: u32,
        refuse: Option<String>,
        fail_engine: Option<Engine>,
        tun_fd: Option<i32>,
        last_force: bool,
    }

    impl EngineKernel {
        fn new() -> Self {
            Self {
                engine: Engine::Mihomo,
                alive: false,
                launched: None,
                last: String::new(),
                starts: 0,
                stops: 0,
                refuse: None,
                fail_engine: None,
                tun_fd: None,
                last_force: false,
            }
        }
    }

    impl KernelLaunch for EngineKernel {
        fn start_or_reload(&mut self, config_yaml: &str) -> Result<(), String> {
            self.starts += 1;
            if self.fail_engine == Some(self.engine) {
                self.alive = false;
                return Err("目标内核启动失败".to_string());
            }
            self.last = config_yaml.to_string();
            self.alive = true;
            self.launched = Some(self.engine);
            Ok(())
        }

        fn start_or_reload_with(&mut self, config_yaml: &str, force: bool) -> Result<(), String> {
            self.last_force = force;
            self.start_or_reload(config_yaml)
        }

        fn running(&mut self) -> bool {
            self.alive
        }

        fn engine(&self) -> Engine {
            self.engine
        }

        fn set_engine(&mut self, engine: Engine) {
            self.engine = engine;
        }

        fn set_tun_fd(&mut self, fd: Option<i32>) {
            self.tun_fd = fd;
        }

        fn identity(&self) -> Option<EngineIdentity> {
            self.launched.map(|engine| EngineIdentity {
                engine,
                version: Some("test".to_string()),
                instance: Some(format!("instance-{}", engine.as_str())),
            })
        }

        fn stop_kernel(&mut self) {
            self.stops += 1;
            self.alive = false;
            self.launched = None;
        }

        fn validate_config(&mut self, _config_yaml: &str) -> Result<(), String> {
            match &self.refuse {
                Some(message) => Err(message.clone()),
                None => Ok(()),
            }
        }
    }

    #[test]
    fn legacy_profile_book_without_an_engine_stays_on_mihomo() {
        let dir = temp_dir("engine-legacy");
        fs::write(dir.0.join("profiles.json"), br#"{"next_id":1,"profiles":[]}"#).unwrap();
        let book = ProfileBook::open(&dir.0);
        assert_eq!(book.engine(), Engine::Mihomo);
    }

    #[test]
    fn engine_selection_is_persisted_and_used_by_the_next_connection() {
        let dir = temp_dir("engine-select");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("direct.yaml", "mixed-port: 7890\nmode: rule\nrules:\n  - MATCH,DIRECT\n");
        let mut kernel = EngineKernel::new();
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let snapshot = book
            .switch_engine(Engine::Rust, &mut kernel, &mut proxy, &mut tun, &mut vpn)
            .unwrap();
        assert_eq!(snapshot.engine, "rust");
        assert_eq!(kernel.engine(), Engine::Rust);
        // Nothing ran, so no connection was fabricated.
        assert!(!snapshot.connected);
        assert!(!kernel.alive);
        assert_eq!(ProfileBook::open(&dir.0).engine(), Engine::Rust);

        book.enable("p1", &RejectSource, &mut kernel);
        book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(kernel.alive);
        assert_eq!(book.snapshot().running_engine.as_deref(), Some("rust"));
        assert!(!kernel.last.contains("external-controller"), "{}", kernel.last);
    }

    #[test]
    fn a_target_that_rejects_the_config_leaves_the_live_session_untouched() {
        let dir = temp_dir("engine-refuse");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("direct.yaml", "mixed-port: 7890\nmode: rule\nrules:\n  - MATCH,DIRECT\n");
        let mut kernel = EngineKernel::new();
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        book.enable("p1", &RejectSource, &mut kernel);
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.system_proxy);
        let starts = kernel.starts;

        kernel.refuse = Some("[unsupported] proxy-groups".to_string());
        let error = book
            .switch_engine(Engine::Rust, &mut kernel, &mut proxy, &mut tun, &mut vpn)
            .unwrap_err();
        assert!(error.contains("未接受当前配置"), "{error}");
        assert_eq!(kernel.starts, starts, "the running instance must not be restarted");
        assert_eq!(book.engine(), Engine::Mihomo);
        assert_eq!(kernel.engine(), Engine::Mihomo);
        assert!(kernel.alive);
        let snapshot = book.snapshot();
        assert!(snapshot.connected);
        assert_eq!(snapshot.running_engine.as_deref(), Some("mihomo"));
        assert!(proxy.http.is_some(), "system proxy must still be ours");
    }

    #[test]
    fn a_failed_target_launch_restores_the_previous_engine_session() {
        let dir = temp_dir("engine-restore");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("direct.yaml", "mixed-port: 7890\nmode: rule\nrules:\n  - MATCH,DIRECT\n");
        let mut kernel = EngineKernel::new();
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        book.enable("p1", &RejectSource, &mut kernel);
        book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        kernel.fail_engine = Some(Engine::Rust);

        let error = book
            .switch_engine(Engine::Rust, &mut kernel, &mut proxy, &mut tun, &mut vpn)
            .unwrap_err();
        assert!(error.contains("已恢复Mihomo"), "{error}");
        assert_eq!(book.engine(), Engine::Mihomo);
        assert_eq!(kernel.engine(), Engine::Mihomo);
        assert_eq!(kernel.launched, Some(Engine::Mihomo));
        let snapshot = book.snapshot();
        assert!(snapshot.connected);
        assert_eq!(snapshot.running_engine.as_deref(), Some("mihomo"));
        assert!(proxy.http.is_some());
        assert!(snapshot.failure.as_deref().is_some_and(|message| message.contains("已恢复")));
    }

    #[test]
    fn controller_injection_belongs_to_the_mihomo_engine_only() {
        let dir = temp_dir("engine-yaml");
        let book = ProfileBook::open(&dir.0);
        let yaml = "mixed-port: 7890\nmode: rule\nrules:\n  - MATCH,DIRECT\n";
        let selected = BTreeMap::new();
        let mihomo = book.finish_yaml_for(Engine::Mihomo, yaml, &selected);
        let rust = book.finish_yaml_for(Engine::Rust, yaml, &selected);
        assert!(mihomo.contains("external-controller"));
        assert!(!rust.contains("external-controller"));
        assert!(!rust.contains("secret:"));
    }

    #[test]
    fn the_native_kernel_never_receives_the_launcher_tun_block() {
        let yaml = "mixed-port: 7890\ntun:\n  auto-route: true\n  mtu: 1500\n";
        // The Rust engine always strips tun, including a user-written block:
        // its device route is the launcher's (iOS Packet Tunnel / Android
        // VpnService fd), so an enabled block must not reach the config loader.
        let stripped = strip_tun(yaml).unwrap();
        assert!(!stripped.contains("tun:"), "{stripped}");
        assert!(stripped.contains("mixed-port"));
        // The conditional helper remains for callers that want to preserve a
        // user block explicitly.
        assert!(strip_launcher_tun(yaml, true).unwrap().contains("tun:"));
        assert!(config_has_tun(yaml));
        assert!(!config_has_tun("mixed-port: 7890\n"));
    }

    #[test]
    fn android_rust_connect_passes_the_vpn_fd_to_the_launcher_not_yaml() {
        let dir = temp_dir("engine-android-fd");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Android);
        book.add_local(
            "direct.yaml",
            "mixed-port: 7890\ntun:\n  enable: true\nmode: rule\nrules:\n  - MATCH,DIRECT\n",
        );
        let mut kernel = EngineKernel::new();
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn { grant: true, ..MemoryVpn::default() };
        book.enable("p1", &RejectSource, &mut kernel);
        book.switch_engine(Engine::Rust, &mut kernel, &mut proxy, &mut tun, &mut vpn)
            .unwrap();
        let snapshot = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(snapshot.connected && snapshot.vpn, "{snapshot:?}");
        assert_eq!(
            kernel.tun_fd,
            Some(1),
            "the VpnService fd is a launch argument for the Rust engine"
        );
        assert!(
            kernel.last_force,
            "a fresh VpnService fd always respawns the Rust process"
        );
        let yaml: Value = serde_yaml::from_str(&kernel.last).unwrap();
        assert!(yaml.get("tun").is_none(), "{}", kernel.last);
        assert!(yaml.get("file-descriptor").is_none(), "{}", kernel.last);
    }

    #[test]
    fn android_rust_noop_app_rule_saves_keep_the_child_and_tunnel() {
        let dir = temp_dir("android-noop-app-rules");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Android);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\nrules:\n  - MATCH,DIRECT\n");
        let mut kernel = EngineKernel::new();
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn { grant: true, ..MemoryVpn::default() };
        book.enable("p1", &RejectSource, &mut kernel);
        book.switch_engine(Engine::Rust, &mut kernel, &mut proxy, &mut tun, &mut vpn)
            .unwrap();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.vpn && connected.connected, "{connected:?}");
        assert!(kernel.alive);
        let (stops, starts, establishes) = (kernel.stops, kernel.starts, vpn.establish_calls);

        // An empty allowlist degrades to "bypass nothing", which is the same
        // filter as an empty exclusion list. Switching between the two modes
        // changes nothing, so the running Rust child and the live tunnel stay.
        let include = book.set_app_rules("include", &[], &mut kernel, &mut vpn);
        assert!(include.vpn && include.connected, "{include:?}");
        assert_eq!(include.app_mode, "include");
        assert!(kernel.alive, "a no-op save must not kill the child");
        assert!(vpn.open);
        assert_eq!(kernel.tun_fd, Some(1), "the child still reads the same fd");
        assert_eq!(
            (kernel.stops, kernel.starts, vpn.establish_calls),
            (stops, starts, establishes)
        );

        let exclude = book.set_app_rules("exclude", &[], &mut kernel, &mut vpn);
        assert!(exclude.vpn && exclude.connected, "{exclude:?}");
        assert_eq!(exclude.app_mode, "exclude");
        assert!(kernel.alive && vpn.open);
        assert_eq!(kernel.tun_fd, Some(1));
        assert_eq!(
            (kernel.stops, kernel.starts, vpn.establish_calls),
            (stops, starts, establishes)
        );

        // Saving an unchanged non-empty allowlist is likewise a no-op.
        book.set_app_rules("include", &["com.a".to_string()], &mut kernel, &mut vpn);
        let (stops, starts, establishes) = (kernel.stops, kernel.starts, vpn.establish_calls);
        let again = book.set_app_rules("include", &["com.a".to_string()], &mut kernel, &mut vpn);
        assert!(again.vpn && again.connected);
        assert!(kernel.alive && vpn.open);
        assert_eq!(
            (kernel.stops, kernel.starts, vpn.establish_calls),
            (stops, starts, establishes)
        );
        // A blank package is not a change either.
        let blank = book.include_package("  ", &mut kernel, &mut vpn);
        assert!(blank.vpn && blank.connected);
        assert!(kernel.alive);
        assert_eq!(
            (kernel.stops, kernel.starts, vpn.establish_calls),
            (stops, starts, establishes)
        );
    }

    #[test]
    fn android_rust_repeated_package_changes_keep_the_child_and_tunnel() {
        let dir = temp_dir("android-idempotent-package");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Android);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\nrules:\n  - MATCH,DIRECT\n");
        let mut kernel = EngineKernel::new();
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn { grant: true, ..MemoryVpn::default() };
        book.enable("p1", &RejectSource, &mut kernel);
        book.switch_engine(Engine::Rust, &mut kernel, &mut proxy, &mut tun, &mut vpn)
            .unwrap();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.vpn && connected.connected, "{connected:?}");
        // Make the exclusion list current (this one is a real change).
        book.set_app_rules("exclude", &["com.bank".to_string()], &mut kernel, &mut vpn);
        assert!(kernel.alive);
        let (stops, starts, establishes) = (kernel.stops, kernel.starts, vpn.establish_calls);

        // The same package again, and a package that is not excluded, change
        // nothing: the live tunnel and the Android Rust child must survive.
        let repeated = book.exclude_package("com.bank", &mut kernel, &mut vpn);
        assert!(repeated.vpn && repeated.connected, "{repeated:?}");
        assert!(kernel.alive && vpn.open);
        assert_eq!(kernel.tun_fd, Some(1), "the child still reads the same fd");
        assert_eq!(
            (kernel.stops, kernel.starts, vpn.establish_calls),
            (stops, starts, establishes),
            "a no-op exclude must not stop the child or rebuild the fd"
        );

        let absent = book.include_package("com.absent", &mut kernel, &mut vpn);
        assert!(absent.vpn && absent.connected, "{absent:?}");
        assert!(kernel.alive && vpn.open);
        assert_eq!(kernel.tun_fd, Some(1));
        assert_eq!(
            (kernel.stops, kernel.starts, vpn.establish_calls),
            (stops, starts, establishes),
            "including a package that was not excluded is a no-op"
        );
    }

    #[cfg(unix)]
    #[test]
    fn only_live_descriptors_pass_the_android_tun_fd_check() {
        use std::os::unix::io::AsRawFd;
        assert!(!descriptor_is_open(-1));
        // A number above the open-file limit is never a live descriptor.
        assert!(!descriptor_is_open(i32::MAX));
        let dir = temp_dir("android-tun-fd-check");
        let path = dir.0.join("probe");
        fs::write(&path, b"ok").unwrap();
        let file = fs::File::open(&path).unwrap();
        assert!(
            descriptor_is_open(file.as_raw_fd()),
            "an open file descriptor must be passed to the child"
        );
    }

    #[test]
    fn android_rust_changed_app_rules_stop_the_child_before_the_new_fd_is_established() {
        use std::sync::{Arc, Mutex};

        struct LogKernel {
            log: Arc<Mutex<Vec<&'static str>>>,
            alive: bool,
            fd: Option<i32>,
        }
        impl KernelLaunch for LogKernel {
            fn start_or_reload(&mut self, _config_yaml: &str) -> Result<(), String> {
                self.log.lock().unwrap().push("start");
                self.alive = true;
                Ok(())
            }
            fn running(&mut self) -> bool {
                self.alive
            }
            fn set_tun_fd(&mut self, fd: Option<i32>) {
                self.log.lock().unwrap().push("fd");
                self.fd = fd;
            }
            fn stop_kernel(&mut self) {
                self.log.lock().unwrap().push("stop");
                self.alive = false;
            }
        }
        struct LogVpn {
            log: Arc<Mutex<Vec<&'static str>>>,
            open: bool,
        }
        impl VpnGrant for LogVpn {
            fn authorize(&mut self) -> Result<bool, String> {
                Ok(true)
            }
            fn establish(&mut self, _filter: &crate::takeover::AppFilter) -> Result<i32, String> {
                self.log.lock().unwrap().push("establish");
                self.open = true;
                Ok(9)
            }
            fn close(&mut self) -> Result<(), String> {
                self.open = false;
                Ok(())
            }
        }

        let dir = temp_dir("android-app-rules-order");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Android);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\nrules:\n  - MATCH,DIRECT\n");
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut kernel = LogKernel { log: log.clone(), alive: false, fd: None };
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = LogVpn { log: log.clone(), open: false };
        book.enable("p1", &RejectSource, &mut kernel);
        book.switch_engine(Engine::Rust, &mut kernel, &mut proxy, &mut tun, &mut vpn)
            .unwrap();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.vpn && connected.connected, "{connected:?}");
        assert_eq!(kernel.fd, Some(9));
        log.lock().unwrap().clear();

        // A real filter change replaces the fd: the child must be stopped after
        // the decision to replace and before the new descriptor is established.
        let saved = book.set_app_rules("include", &["com.a".to_string()], &mut kernel, &mut vpn);
        assert!(saved.vpn && saved.connected, "{saved:?}");
        assert_eq!(saved.included, ["com.a"]);
        assert!(kernel.alive, "the reloaded child is running");
        assert_eq!(kernel.fd, Some(9));
        let events = log.lock().unwrap();
        let position = |name: &str| events.iter().position(|item| *item == name).unwrap_or_else(|| panic!("missing {name} in {events:?}"));
        assert!(position("stop") < position("establish"), "{events:?}");
        assert!(position("establish") < position("start"), "{events:?}");
    }

    #[test]
    fn android_rust_stop_clears_a_stale_fd_even_after_the_child_exited() {
        let dir = temp_dir("android-stale-fd");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Android);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\nrules:\n  - MATCH,DIRECT\n");
        let mut kernel = EngineKernel::new();
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn { grant: true, ..MemoryVpn::default() };
        book.enable("p1", &RejectSource, &mut kernel);
        book.switch_engine(Engine::Rust, &mut kernel, &mut proxy, &mut tun, &mut vpn)
            .unwrap();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.vpn && connected.connected, "{connected:?}");
        assert_eq!(kernel.tun_fd, Some(1));

        // The child exited on its own while the host still tracked the fd. The
        // next launch must not inherit that stale number.
        kernel.alive = false;
        let stops = kernel.stops;
        let off = book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!off.vpn && !off.connected);
        assert_eq!(kernel.tun_fd, None);
        assert_eq!(kernel.stops, stops, "an exited child is not stopped again");
    }

    #[test]
    fn android_rust_denied_reconnect_stops_the_child_before_closing_vpn() {
        let dir = temp_dir("android-denied-reconnect");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Android);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\nrules:\n  - MATCH,DIRECT\n");
        let mut kernel = EngineKernel::new();
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn { grant: true, ..MemoryVpn::default() };
        book.enable("p1", &RejectSource, &mut kernel);
        book.switch_engine(Engine::Rust, &mut kernel, &mut proxy, &mut tun, &mut vpn)
            .unwrap();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.vpn && connected.connected, "{connected:?}");
        assert!(kernel.alive);
        let stops = kernel.stops;

        vpn.grant = false;
        let denied = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert_eq!(denied.failure.as_deref(), Some(takeover::VPN_DENIED));
        assert!(!denied.vpn && !denied.connected);
        assert!(!vpn.open, "the host descriptor is closed after the child");
        assert!(!kernel.alive, "no Rust child outlives the closed descriptor");
        assert_eq!(kernel.tun_fd, None);
        assert_eq!(kernel.stops, stops + 1);
    }

    #[test]
    fn stopping_preserves_the_pending_tun_fd_for_the_next_launch() {
        // `launch` calls `stop()` before spawning; clearing the fd there would
        // drop the `--tun-fd` argument the caller just handed over.
        let dir = temp_dir("pending-tun-fd");
        let mut runtime = ProcessRuntime::new(dir.0.join("runtime"));
        runtime.set_tun_fd(Some(7));
        runtime.stop();
        assert_eq!(runtime.tun_fd, Some(7));
        runtime.set_tun_fd(None);
        assert_eq!(runtime.tun_fd, None);
    }

    #[test]
    fn android_mihomo_connect_keeps_the_vpn_fd_in_yaml() {
        let dir = temp_dir("engine-android-mihomo-fd");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Android);
        book.add_local("direct.yaml", "mixed-port: 7890\nmode: rule\nrules:\n  - MATCH,DIRECT\n");
        let mut kernel = EngineKernel::new();
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn { grant: true, ..MemoryVpn::default() };
        book.enable("p1", &RejectSource, &mut kernel);
        let snapshot = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(snapshot.connected && snapshot.vpn, "{snapshot:?}");
        assert_eq!(kernel.tun_fd, None, "Mihomo takes the fd through the YAML");
        let yaml: Value = serde_yaml::from_str(&kernel.last).unwrap();
        assert_eq!(yaml["tun"]["enable"].as_bool(), Some(true));
        assert_eq!(yaml["tun"]["file-descriptor"].as_i64(), Some(1));
    }

    /// Records the order in which the Android VPN descriptor is released and re-acquired.
    struct OrderVpn {
        open: bool,
        log: Vec<&'static str>,
    }

    impl VpnGrant for OrderVpn {
        fn authorize(&mut self) -> Result<bool, String> {
            self.log.push("authorize");
            Ok(true)
        }

        fn establish(&mut self, _filter: &takeover::AppFilter) -> Result<i32, String> {
            self.log.push("establish");
            self.open = true;
            Ok(7)
        }

        fn close(&mut self) -> Result<(), String> {
            self.log.push("close");
            self.open = false;
            Ok(())
        }
    }

    #[test]
    fn android_engine_switch_releases_the_vpn_descriptor_before_starting_the_target() {
        let dir = temp_dir("engine-android");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Android);
        book.add_local("direct.yaml", "mixed-port: 7890\nmode: rule\nrules:\n  - MATCH,DIRECT\n");
        let mut kernel = EngineKernel::new();
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = OrderVpn { open: false, log: Vec::new() };
        book.enable("p1", &RejectSource, &mut kernel);
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.vpn, "{:?}", connected.failure);
        assert_eq!(vpn.log, ["authorize", "establish"]);

        let switched = book
            .switch_engine(Engine::Rust, &mut kernel, &mut proxy, &mut tun, &mut vpn)
            .unwrap();
        assert_eq!(switched.engine, "rust");
        assert_eq!(switched.running_engine.as_deref(), Some("rust"));
        assert!(switched.vpn);
        // Exactly one descriptor is live, and the old one was closed first.
        assert_eq!(vpn.log, ["authorize", "establish", "close", "authorize", "establish"]);
        assert!(vpn.open);
    }

    /// A KERNEL/VPN pair that proves the child stopped while the fd was still live.
    struct FlagVpn(std::sync::Arc<AtomicBool>);

    impl VpnGrant for FlagVpn {
        fn authorize(&mut self) -> Result<bool, String> {
            Ok(true)
        }

        fn establish(&mut self, _filter: &takeover::AppFilter) -> Result<i32, String> {
            self.0.store(true, Ordering::SeqCst);
            Ok(9)
        }

        fn close(&mut self) -> Result<(), String> {
            self.0.store(false, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Grants one fd, then refuses the replacement a restart asks for.
    struct OnceFlagVpn {
        open: std::sync::Arc<AtomicBool>,
        calls: u32,
    }

    impl VpnGrant for OnceFlagVpn {
        fn authorize(&mut self) -> Result<bool, String> {
            Ok(true)
        }

        fn establish(&mut self, _filter: &takeover::AppFilter) -> Result<i32, String> {
            self.calls += 1;
            if self.calls > 1 {
                return Err("VPN 没有建立".to_string());
            }
            self.open.store(true, Ordering::SeqCst);
            Ok(9)
        }

        fn close(&mut self) -> Result<(), String> {
            self.open.store(false, Ordering::SeqCst);
            Ok(())
        }
    }

    struct StopOrderKernel {
        alive: bool,
        engine: Engine,
        vpn_open: std::sync::Arc<AtomicBool>,
        stopped_while_open: bool,
        tun_fd: Option<i32>,
    }

    impl StopOrderKernel {
        fn new(engine: Engine, vpn_open: std::sync::Arc<AtomicBool>) -> Self {
            Self {
                alive: false,
                engine,
                vpn_open,
                stopped_while_open: false,
                tun_fd: None,
            }
        }
    }

    impl KernelLaunch for StopOrderKernel {
        fn start_or_reload(&mut self, _config_yaml: &str) -> Result<(), String> {
            self.alive = true;
            Ok(())
        }

        fn running(&mut self) -> bool {
            self.alive
        }

        fn engine(&self) -> Engine {
            self.engine
        }

        fn set_engine(&mut self, engine: Engine) {
            self.engine = engine;
        }

        fn set_tun_fd(&mut self, fd: Option<i32>) {
            self.tun_fd = fd;
        }

        fn identity(&self) -> Option<EngineIdentity> {
            self.alive.then(|| EngineIdentity {
                engine: self.engine,
                version: Some("test".to_string()),
                instance: Some("test".to_string()),
            })
        }

        fn stop_kernel(&mut self) {
            self.stopped_while_open = self.vpn_open.load(Ordering::SeqCst);
            self.alive = false;
            self.tun_fd = None;
        }
    }

    #[test]
    fn android_rust_disconnect_stops_the_kernel_before_closing_the_vpn_fd() {
        let dir = temp_dir("engine-android-disconnect");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Android);
        book.add_local(
            "direct.yaml",
            "mixed-port: 7890\nmode: rule\nrules:\n  - MATCH,DIRECT\n",
        );
        let open = std::sync::Arc::new(AtomicBool::new(false));
        let mut kernel = StopOrderKernel::new(Engine::Rust, std::sync::Arc::clone(&open));
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = FlagVpn(std::sync::Arc::clone(&open));
        book.enable("p1", &RejectSource, &mut kernel);
        book.switch_engine(Engine::Rust, &mut kernel, &mut proxy, &mut tun, &mut vpn)
            .unwrap();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.connected && connected.vpn, "{connected:?}");
        assert_eq!(kernel.tun_fd, Some(9), "the fd is a launch argument");

        let disconnected = book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!disconnected.connected && !disconnected.vpn, "{disconnected:?}");
        assert!(
            !kernel.alive,
            "the Android Rust child must exit on disconnect, not survive polling a revoked fd"
        );
        assert_eq!(kernel.tun_fd, None, "the released fd is not reused by a later launch");
        assert!(
            kernel.stopped_while_open && !open.load(Ordering::SeqCst),
            "the child must stop before the host closes its ParcelFileDescriptor"
        );
    }

    #[test]
    fn android_restart_failure_stops_the_rust_child_before_closing_the_vpn_fd() {
        let dir = temp_dir("engine-android-restart-fail");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Android);
        book.add_local(
            "direct.yaml",
            "mixed-port: 7890\nmode: rule\nrules:\n  - MATCH,DIRECT\n",
        );
        let open = std::sync::Arc::new(AtomicBool::new(false));
        let mut kernel = StopOrderKernel::new(Engine::Rust, std::sync::Arc::clone(&open));
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = OnceFlagVpn {
            open: std::sync::Arc::clone(&open),
            calls: 0,
        };
        book.enable("p1", &RejectSource, &mut kernel);
        book.switch_engine(Engine::Rust, &mut kernel, &mut proxy, &mut tun, &mut vpn)
            .unwrap();
        assert!(book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn).vpn);
        assert!(open.load(Ordering::SeqCst));

        let failed = book.restart_kernel(&mut kernel, &mut proxy, &mut tun, &mut vpn).unwrap();
        assert!(!failed.connected && !failed.vpn, "{failed:?}");
        assert_eq!(failed.failure.as_deref(), Some("VPN 没有建立"));
        assert!(
            kernel.stopped_while_open,
            "the restart fallback must stop the child while its old fd is still live"
        );
        assert_eq!(kernel.tun_fd, None, "the failed restart must not reuse the old fd");
        assert!(!open.load(Ordering::SeqCst));
    }

    #[test]
    fn android_switch_away_from_rust_stops_the_child_before_the_vpn_fd_closes() {
        let dir = temp_dir("engine-android-switch-rust");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Android);
        book.add_local(
            "direct.yaml",
            "mixed-port: 7890\nmode: rule\nrules:\n  - MATCH,DIRECT\n",
        );
        let open = std::sync::Arc::new(AtomicBool::new(false));
        let mut kernel = StopOrderKernel::new(Engine::Rust, std::sync::Arc::clone(&open));
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = FlagVpn(std::sync::Arc::clone(&open));
        book.enable("p1", &RejectSource, &mut kernel);
        book.switch_engine(Engine::Rust, &mut kernel, &mut proxy, &mut tun, &mut vpn)
            .unwrap();
        assert!(book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn).vpn);
        assert!(kernel.alive);

        let switched = book
            .switch_engine(Engine::Mihomo, &mut kernel, &mut proxy, &mut tun, &mut vpn)
            .unwrap();
        assert_eq!(switched.engine, "mihomo");
        assert_eq!(switched.running_engine.as_deref(), Some("mihomo"));
        assert!(switched.connected && switched.vpn, "{switched:?}");
        assert!(
            kernel.stopped_while_open,
            "the running Rust child must stop before its inherited fd is replaced"
        );
        assert_eq!(kernel.tun_fd, None, "Mihomo takes the fd through the YAML");
        assert!(
            open.load(Ordering::SeqCst),
            "the switch must leave exactly one live descriptor"
        );
    }

    #[test]
    fn native_kernel_identity_lines_are_parsed_for_readiness() {
        let line = "instance=6f1c pid=42 version=0.1.0 listen=127.0.0.1:7890 overridden_port=- config=sha256:abc rules=3 geosite_dir=- state_dir=-";
        let (instance, version, listen) = parse_kernel_identity(line).unwrap();
        assert_eq!(instance, "6f1c");
        assert_eq!(version.as_deref(), Some("0.1.0"));
        assert_eq!(listen.port(), 7890);
        assert!(parse_kernel_identity("features: mixed").is_none());
        assert!(parse_kernel_identity("instance=- pid=1 listen=127.0.0.1:1").is_none());
    }
}
