use std::collections::BTreeMap;
use std::io::{BufReader, Read};
use std::time::Duration;

/// Machine tag for a `dialer-proxy` hop. The UI translates it; config values stay English-free (T8).
const CHAINED_TAG: &str = "chained";

use serde::{Deserialize, Serialize};
use serde_yaml::Value;

pub const NEED_PROFILE: &str = "需要先添加或更新配置";
pub const NO_NODES: &str = "还没有可显示的节点。";
pub const NO_MATCH: &str = "没有匹配的节点";
pub const NOT_MANUAL: &str = "不能改选";
pub const KERNEL_DOWN: &str = "内核没有运行";
pub const SELECT_FAILED: &str = "节点没有切换";
pub const UNFIX_FAILED: &str = "没有恢复自动选择";

const CONTROLLER_PORT: u16 = 17690;
const CONTROLLER_SECRET: &str = "billow-local";
const DELAY_URL: &str = "http://www.gstatic.com/generate_204";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDelay {
    pub name: String,
    pub delay_ms: Option<u64>,
}

/// Progress payload for the `node-test` event emitted by a full test run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NodeTestEvent {
    pub node: String,
    pub delay: Option<u64>,
    pub failed: bool,
    pub tested: usize,
    pub total: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedGroup {
    pub name: String,
    pub manual: bool,
    pub proxies: Vec<String>,
    pub group_type: String,
    /// Config-declared `icon`, kept only for remote http(s) or inline image data.
    pub icon: Option<String>,
    /// `url-test` / `fallback`: the kernel accepts a fixed node (`SelectAble`).
    pub pinnable: bool,
    /// Config-declared `hidden: true`; list entry points skip it.
    pub hidden: bool,
}

/// The controller has already expanded providers and applied group filters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeCatalog {
    pub members: BTreeMap<String, Vec<String>>,
    pub now: BTreeMap<String, String>,
    pub types: BTreeMap<String, String>,
    pub tags: BTreeMap<String, Vec<String>>,
    pub providers: BTreeMap<String, String>,
    pub dialers: BTreeMap<String, String>,
    /// Node pinned on a `url-test` / `fallback` group; absent or empty means automatic.
    pub fixed: BTreeMap<String, String>,
    /// Controller-reported `hidden` per group.
    pub hidden: BTreeMap<String, bool>,
}

impl RuntimeCatalog {
    pub fn merge_providers(&mut self, other: &Self) {
        for (name, provider) in &other.providers {
            // Inline proxies and groups use /proxies, even if a provider repeats their name.
            if self.types.contains_key(name) { continue; }
            self.providers.insert(name.clone(), provider.clone());
            if let Some(kind) = other.types.get(name) { self.types.insert(name.clone(), kind.clone()); }
            if let Some(tags) = other.tags.get(name) { self.tags.insert(name.clone(), tags.clone()); }
            if let Some(dialer) = other.dialers.get(name) { self.dialers.insert(name.clone(), dialer.clone()); }
        }
    }
}

#[derive(Deserialize)]
struct ControllerCatalog {
    proxies: BTreeMap<String, ControllerProxy>,
}

/// Skip histories, health-check URLs and other fields while decoding: the UI
/// needs only membership, selection and protocol, even for large providers.
#[derive(Deserialize)]
struct ControllerProxy {
    name: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    all: Option<Vec<String>>,
    now: Option<String>,
    udp: Option<bool>,
    xudp: Option<bool>,
    smux: Option<bool>,
    tfo: Option<bool>,
    mptcp: Option<bool>,
    #[serde(rename = "dialer-proxy")]
    dialer_proxy: Option<String>,
    fixed: Option<String>,
    hidden: Option<bool>,
}

#[derive(Deserialize)]
struct ProviderCatalog { providers: BTreeMap<String, ProviderNodes> }

#[derive(Deserialize)]
struct ProviderNodes { proxies: Vec<ControllerProxy> }

fn providers_from_reader(reader: impl Read) -> Result<RuntimeCatalog, String> {
    let response: ProviderCatalog = serde_json::from_reader(reader)
        .map_err(|_| "订阅节点资料没有读取".to_string())?;
    let mut catalog = RuntimeCatalog::default();
    for (provider, nodes) in response.providers {
        for item in nodes.proxies {
            let Some(name) = item.name.clone() else { continue; };
            if catalog.providers.contains_key(&name) { continue; }
            catalog.providers.insert(name.clone(), provider.clone());
            add_proxy_metadata(&mut catalog, &name, &item);
        }
    }
    Ok(catalog)
}

fn add_proxy_metadata(catalog: &mut RuntimeCatalog, name: &str, item: &ControllerProxy) {
    let mut tags: Vec<String> = [(item.udp, "UDP"), (item.xudp, "XUDP"), (item.smux, "Mux"),
        (item.tfo, "TFO"), (item.mptcp, "MPTCP")].into_iter()
        .filter(|(on, _)| *on == Some(true)).map(|(_, tag)| tag.to_string()).collect();
    if let Some(dialer) = item.dialer_proxy.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        tags.push(CHAINED_TAG.to_string());
        catalog.dialers.insert(name.to_string(), dialer.to_string());
    }
    if !tags.is_empty() { catalog.tags.insert(name.to_string(), tags); }
    if let Some(kind) = &item.kind { catalog.types.insert(name.to_string(), kind.clone()); }
}

fn catalog_from_reader(reader: impl Read) -> Result<RuntimeCatalog, String> {
    let response: ControllerCatalog = serde_json::from_reader(reader)
        .map_err(|_| "节点列表没有读取".to_string())?;
    let mut catalog = RuntimeCatalog::default();
    for (name, item) in response.proxies {
        add_proxy_metadata(&mut catalog, &name, &item);
        if let Some(all) = item.all {
            catalog.members.insert(name.clone(), all);
        }
        if let Some(fixed) = item.fixed.filter(|s| !s.is_empty()) {
            catalog.fixed.insert(name.clone(), fixed);
        }
        if let Some(hidden) = item.hidden {
            catalog.hidden.insert(name.clone(), hidden);
        }
        if let Some(now) = item.now.filter(|s| !s.is_empty()) {
            catalog.now.insert(name, now);
        }
    }
    Ok(catalog)
}

#[cfg(test)]
pub fn runtime_catalog(value: &serde_json::Value) -> Result<RuntimeCatalog, String> {
    catalog_from_reader(serde_json::to_vec(value).unwrap().as_slice())
}

pub fn resolved_groups(value: &Value, runtime: &RuntimeCatalog) -> Vec<ParsedGroup> {
    merge_runtime_groups(parse_proxy_groups(value), runtime)
}

pub fn merge_runtime_groups(mut groups: Vec<ParsedGroup>, runtime: &RuntimeCatalog) -> Vec<ParsedGroup> {
    for group in &mut groups {
        if let Some(members) = runtime.members.get(&group.name) {
            group.proxies = members.clone();
        }
    }
    groups
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct NodeItemView {
    pub name: String,
    pub delay_ms: Option<u64>,
    pub failed: bool,
    pub selected: bool,
    pub node_type: String,
    /// Capability tags in display order (UDP, Reality/TLS, transport, …); see `proxy_tags`.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Upstream transit proxy or group when `dialer-proxy` is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dialer_proxy: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct NodeGroupView {
    pub name: String,
    pub kind: String,
    pub now: String,
    pub sort: String,
    pub nodes: Vec<NodeItemView>,
    pub group_type: String,
    pub icon: Option<String>,
    /// `url-test` / `fallback`: a node can be fixed and released again.
    pub pinnable: bool,
    /// Node fixed on a pinnable group. The controller's value wins while it runs.
    pub fixed: Option<String>,
    /// `hidden: true`; list entry points skip it, chains still resolve through it.
    pub hidden: bool,
}

static TEST_URL: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
static TEST_TIMEOUT_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(5000);

/// The delay probe URL and timeout chosen in settings. Empty keeps the default.
pub fn set_probe(url: &str, timeout_ms: u64) {
    let mut guard = TEST_URL.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = url.trim().to_string();
    TEST_TIMEOUT_MS.store(timeout_ms.clamp(1000, 30000), std::sync::atomic::Ordering::Relaxed);
}

fn probe_url() -> String {
    let guard = TEST_URL.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_empty() {
        DELAY_URL.to_string()
    } else {
        guard.clone()
    }
}

fn probe_timeout() -> u64 {
    TEST_TIMEOUT_MS.load(std::sync::atomic::Ordering::Relaxed)
}


/// Proxy name → protocol type (`ss`, `vmess`, …) from the config's `proxies` list, and group types.
pub fn proxy_types(value: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(list) = mapping_get(value, "proxies").and_then(Value::as_sequence) {
        for item in list {
            if let (Some(name), Some(kind)) = (read_string(item, "name"), read_string(item, "type")) {
                out.insert(name, kind);
            }
        }
    }
    if let Some(list) = mapping_get(value, "proxy-groups").and_then(Value::as_sequence) {
        for item in list {
            if let (Some(name), Some(kind)) = (read_string(item, "name"), read_string(item, "type")) {
                out.entry(name).or_insert(kind);
            }
        }
    }
    out.entry("DIRECT".to_string()).or_insert_with(|| "direct".to_string());
    out.entry("REJECT".to_string()).or_insert_with(|| "reject".to_string());
    out
}

/// Protocol and capability tags of one proxy, read from the config.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProxyInfo {
    pub kind: String,
    pub tags: Vec<String>,
    pub dialer_proxy: Option<String>,
}

fn read_bool(value: &Value, key: &str) -> Option<bool> {
    mapping_get(value, key).and_then(|item| match item {
        Value::Bool(flag) => Some(*flag),
        Value::String(text) => match text.to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    })
}

/// Tags users act on, most decisive first: UDP support (games, calls, QUIC),
/// the security layer, the transport, then tuning flags. Protocols that always
/// carry UDP or TLS (hysteria2, tuic, wireguard) do not repeat what the type says.
pub fn proxy_tags(item: &Value) -> Vec<String> {
    let kind = read_string(item, "type").unwrap_or_default().to_ascii_lowercase();
    let mut tags = Vec::new();
    let udp_native = matches!(kind.as_str(), "hysteria" | "hysteria2" | "tuic" | "wireguard");
    if udp_native || read_bool(item, "udp") == Some(true) {
        tags.push("UDP".to_string());
    }
    if read_bool(item, "xudp") == Some(true) || mapping_get(item, "packet-encoding").and_then(Value::as_str) == Some("xudp") {
        tags.push("XUDP".to_string());
    }
    if mapping_get(item, "reality-opts").is_some_and(|value| value.is_mapping()) {
        tags.push("Reality".to_string());
    } else if read_bool(item, "tls") == Some(true) && !matches!(kind.as_str(), "trojan" | "hysteria" | "hysteria2" | "tuic" | "anytls") {
        tags.push("TLS".to_string());
    }
    if let Some(network) = mapping_get(item, "network").and_then(Value::as_str) {
        let label = match network.to_ascii_lowercase().as_str() {
            "ws" => Some("WS"),
            "grpc" => Some("gRPC"),
            "h2" => Some("H2"),
            "http" => Some("HTTP"),
            "xhttp" => Some("XHTTP"),
            _ => None,
        };
        if let Some(label) = label {
            tags.push(label.to_string());
        }
    }
    if mapping_get(item, "flow").and_then(Value::as_str).is_some_and(|flow| flow.contains("vision")) {
        tags.push("Vision".to_string());
    }
    if mapping_get(item, "smux").and_then(|smux| read_bool(smux, "enabled")) == Some(true) {
        tags.push("Mux".to_string());
    }
    if read_bool(item, "tfo") == Some(true) {
        tags.push("TFO".to_string());
    }
    if read_bool(item, "mptcp") == Some(true) {
        tags.push("MPTCP".to_string());
    }
    if mapping_get(item, "dialer-proxy").and_then(Value::as_str).is_some_and(|value| !value.is_empty()) {
        tags.push(CHAINED_TAG.to_string());
    }
    tags
}

/// Proxy name → protocol and tags; groups only carry their type.
pub fn proxy_infos(value: &Value) -> BTreeMap<String, ProxyInfo> {
    let mut out: BTreeMap<String, ProxyInfo> = proxy_types(value)
        .into_iter()
        .map(|(name, kind)| (name, ProxyInfo { kind, tags: Vec::new(), dialer_proxy: None }))
        .collect();
    if let Some(list) = mapping_get(value, "proxies").and_then(Value::as_sequence) {
        for item in list {
            if let Some(name) = read_string(item, "name") {
                if let Some(info) = out.get_mut(&name) {
                    info.tags = proxy_tags(item);
                    info.dialer_proxy = mapping_get(item, "dialer-proxy")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_string);
                }
            }
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerEndpoint {
    pub host: String,
    pub port: u16,
    pub secret: String,
}

pub fn parse_proxy_groups(value: &Value) -> Vec<ParsedGroup> {
    let Some(groups) = mapping_get(value, "proxy-groups").and_then(Value::as_sequence) else {
        return Vec::new();
    };
    let mut parsed = Vec::new();
    for group in groups {
        let Some(name) = read_string(group, "name") else {
            continue;
        };
        if name.is_empty() || parsed.iter().any(|item: &ParsedGroup| item.name == name) {
            continue;
        }
        let mut proxies = read_string_list(group, "proxies");
        if mapping_get(group, "include-all").and_then(Value::as_bool) == Some(true) {
            for proxy in proxy_names(value) {
                if !proxies.iter().any(|item| item == &proxy) {
                    proxies.push(proxy);
                }
            }
        }
        parsed.push(ParsedGroup {
            name,
            manual: is_manual(group),
            proxies,
            group_type: read_string(group, "type")
                .unwrap_or_default()
                .to_ascii_lowercase(),
            icon: read_string(group, "icon").and_then(|icon| usable_icon(&icon)),
            pinnable: is_pinnable(group),
            hidden: mapping_get(group, "hidden").and_then(Value::as_bool) == Some(true),
        });
    }
    parsed
}

/// The group header shows an image only for `http:`, `https:` and `data:image/`.
pub fn usable_icon(raw: &str) -> Option<String> {
    let text = raw.trim();
    if text.is_empty() || text.chars().any(char::is_whitespace) {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    let allowed = lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("data:image/");
    if !allowed {
        return None;
    }
    Some(text.chars().take(2048).collect())
}

pub fn normalize_sort(sort: &str) -> &'static str {
    match sort {
        "delay" => "delay",
        "name" => "name",
        _ => "default",
    }
}

/// Puts an explicitly saved manual choice first so the next launch uses it.
pub fn prioritize_selections(yaml: &str, selected: &BTreeMap<String, String>) -> String {
    let Ok(mut value) = serde_yaml::from_str::<Value>(yaml) else {
        return yaml.to_string();
    };
    let Some(groups) = mapping_get_mut(&mut value, "proxy-groups").and_then(Value::as_sequence_mut)
    else {
        return yaml.to_string();
    };
    for group in groups.iter_mut() {
        if !is_manual(group) {
            continue;
        }
        let Some(name) = read_string(group, "name") else {
            continue;
        };
        let Some(choice) = selected.get(&name) else {
            continue;
        };
        let Some(list) = mapping_get_mut(group, "proxies").and_then(Value::as_sequence_mut) else {
            continue;
        };
        if let Some(index) = list
            .iter()
            .position(|item| item.as_str() == Some(choice.as_str()))
        {
            let node = list.remove(index);
            list.insert(0, node);
        }
    }
    serde_yaml::to_string(&value).unwrap_or_else(|_| yaml.to_string())
}

/// `DELETE /proxies/{group}` clears the fixed node of a `url-test` / `fallback` group.
pub fn delete_selection(endpoint: &ControllerEndpoint, group: &str) -> Result<(), String> {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return Err(KERNEL_DOWN.to_string());
    }
    if group.is_empty() {
        return Err(UNFIX_FAILED.to_string());
    }
    let url = format!(
        "http://{}:{}/proxies/{}",
        endpoint.host,
        endpoint.port,
        encode_segment(group)
    );
    let agent = agent(Duration::from_millis(800));
    let request = agent.delete(&url).set("User-Agent", "Billow");
    let request = if endpoint.secret.is_empty() {
        request
    } else {
        request.set("Authorization", &format!("Bearer {}", endpoint.secret))
    };
    match request.call() {
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(_, response)) => Err(with_reason(UNFIX_FAILED, response)),
        Err(ureq::Error::Transport(_)) => Err(KERNEL_DOWN.to_string()),
    }
}

/// Appends the controller's `message` so a rejected pin explains itself.
fn with_reason(base: &str, response: ureq::Response) -> String {
    let reason = read_body(response).ok()
        .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
        .and_then(|value| value.get("message").and_then(|m| m.as_str()).map(|m| m.trim().to_string()))
        .filter(|message| !message.is_empty());
    match reason {
        Some(reason) => format!("{base}：{}", reason.chars().take(200).collect::<String>()),
        None => base.to_string(),
    }
}

/// Loopback controller so a running kernel can apply a node without touching system proxy.
pub fn ensure_controller(yaml: &str) -> String {
    let Ok(mut value) = serde_yaml::from_str::<Value>(yaml) else {
        return yaml.to_string();
    };
    let Some(map) = value.as_mapping_mut() else {
        return yaml.to_string();
    };
    let has_controller = map
        .keys()
        .any(|key| key.as_str() == Some("external-controller"));
    if !has_controller {
        map.insert(
            Value::String("external-controller".to_string()),
            Value::String(format!("127.0.0.1:{CONTROLLER_PORT}")),
        );
        let has_secret = map.keys().any(|key| key.as_str() == Some("secret"));
        if !has_secret {
            map.insert(
                Value::String("secret".to_string()),
                Value::String(CONTROLLER_SECRET.to_string()),
            );
        }
    }
    serde_yaml::to_string(&value).unwrap_or_else(|_| yaml.to_string())
}

pub fn controller_from_yaml(yaml: &str) -> Option<ControllerEndpoint> {
    let value: Value = serde_yaml::from_str(yaml).ok()?;
    let raw = read_string(&value, "external-controller")?;
    let (host, port) = split_host_port(&raw)?;
    let host = match host.as_str() {
        "0.0.0.0" | "::" | "::0" => "127.0.0.1".to_string(),
        "::1" => "127.0.0.1".to_string(),
        _ => host,
    };
    if !loopback(&host) || port == 0 {
        return None;
    }
    Some(ControllerEndpoint {
        host,
        port,
        secret: read_string(&value, "secret").unwrap_or_default(),
    })
}

const MODE_FAILED: &str = "模式没有切换";
const MODE_READ_TIMEOUT: Duration = Duration::from_millis(5000);

pub fn patch_mode(endpoint: &ControllerEndpoint, mode: &str) -> Result<(), String> {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return Err(MODE_FAILED.to_string());
    }
    let mode = match mode {
        "rule" | "global" | "direct" => mode,
        _ => return Err(MODE_FAILED.to_string()),
    };
    let url = format!("http://{}:{}/configs", endpoint.host, endpoint.port);
    let body = format!("{{\"mode\":\"{mode}\"}}");
    let agent = agent(MODE_READ_TIMEOUT);
    let request = agent
        .patch(&url)
        .set("Content-Type", "application/json")
        .set("User-Agent", "Billow");
    let request = if endpoint.secret.is_empty() {
        request
    } else {
        request.set("Authorization", &format!("Bearer {}", endpoint.secret))
    };
    match request.send_string(&body) {
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(code, response)) => {
            let reason = with_reason(MODE_FAILED, response);
            if reason == MODE_FAILED {
                Err(format!("{MODE_FAILED}（HTTP {code}）"))
            } else {
                Err(reason)
            }
        }
        Err(ureq::Error::Transport(error)) => {
            let detail = error
                .message()
                .map(str::trim)
                .filter(|msg| !msg.is_empty())
                .map(|msg| msg.chars().take(160).collect::<String>());
            match detail {
                Some(detail) => Err(format!("{MODE_FAILED}：{detail}")),
                None => Err(format!("{MODE_FAILED}：{:?}", error.kind())),
            }
        }
    }
}

/// mihomo's `Fallback.Set` records the pin first, then URL-tests a node that is not alive for
/// up to 5 s before answering, so a shorter wait reports a failure for a pin that took effect.
const SELECT_READ_TIMEOUT: Duration = Duration::from_millis(6500);

pub fn put_selection(endpoint: &ControllerEndpoint, group: &str, node: &str) -> Result<(), String> {
    if !loopback(&endpoint.host) || endpoint.port == 0 || group.is_empty() || node.is_empty() {
        return Err(SELECT_FAILED.to_string());
    }
    let url = format!(
        "http://{}:{}/proxies/{}",
        endpoint.host,
        endpoint.port,
        encode_segment(group)
    );
    let body = serde_json::json!({ "name": node }).to_string();
    let agent = agent(SELECT_READ_TIMEOUT);
    let request = agent
        .put(&url)
        .set("Content-Type", "application/json")
        .set("User-Agent", "Billow");
    let request = if endpoint.secret.is_empty() {
        request
    } else {
        request.set("Authorization", &format!("Bearer {}", endpoint.secret))
    };
    match request.send_string(&body) {
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(_, response)) => Err(with_reason(SELECT_FAILED, response)),
        Err(_) => Err(SELECT_FAILED.to_string()),
    }
}

/// Keep the running controller address and secret across hot reloads so the active
/// API listener does not jump ports mid-session.
pub fn rewrite_controller_endpoint(yaml: &str, endpoint: &ControllerEndpoint) -> String {
    let Ok(mut value) = serde_yaml::from_str::<Value>(yaml) else {
        return yaml.to_string();
    };
    let Some(map) = value.as_mapping_mut() else {
        return yaml.to_string();
    };
    map.insert(
        Value::String("external-controller".to_string()),
        Value::String(format!("{}:{}", endpoint.host, endpoint.port)),
    );
    if !endpoint.secret.is_empty() {
        map.insert(
            Value::String("secret".to_string()),
            Value::String(endpoint.secret.clone()),
        );
    }
    serde_yaml::to_string(&value).unwrap_or_else(|_| yaml.to_string())
}

/// Hot-reloads the controller with a full runtime config (`PUT /configs?force=true`).
/// Mihomo expects raw YAML text in `payload` (not base64) and `force=true` so
/// listener, DNS, TUN, and GEO settings take effect without killing the process.
pub fn put_config(endpoint: &ControllerEndpoint, config_yaml: &str) -> Result<(), String> {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return Err(KERNEL_DOWN.to_string());
    }
    let url = format!("http://{}:{}/configs?force=true", endpoint.host, endpoint.port);
    let body = serde_json::json!({ "path": "", "payload": config_yaml }).to_string();
    let agent = agent(Duration::from_secs(12));
    let request = agent
        .put(&url)
        .set("Content-Type", "application/json")
        .set("User-Agent", "Billow");
    let request = if endpoint.secret.is_empty() {
        request
    } else {
        request.set("Authorization", &format!("Bearer {}", endpoint.secret))
    };
    match request.send_string(&body) {
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(_, response)) => {
            let detail = response
                .into_string()
                .ok()
                .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
                .and_then(|json| json.get("message").and_then(serde_json::Value::as_str).map(str::to_string))
                .filter(|msg| !msg.trim().is_empty());
            Err(detail.unwrap_or_else(|| "配置没有热重载".to_string()))
        }
        Err(_) => Err("配置没有热重载".to_string()),
    }
}

/// Best-effort request for the running kernel to close its TUN adapter and routes
/// cleanly before the process is stopped.
pub fn patch_tun_disable(endpoint: &ControllerEndpoint) {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return;
    }
    let url = format!("http://{}:{}/configs", endpoint.host, endpoint.port);
    let body = r#"{"tun":{"enable":false}}"#;
    let agent = agent(Duration::from_millis(500));
    let request = agent
        .patch(&url)
        .set("Content-Type", "application/json")
        .set("User-Agent", "Billow");
    let request = if endpoint.secret.is_empty() {
        request
    } else {
        request.set("Authorization", &format!("Bearer {}", endpoint.secret))
    };
    let _ = request.send_string(body);
}

pub fn fetch_delays(
    endpoint: &ControllerEndpoint,
    nodes: &[String],
) -> Result<Vec<NodeDelay>, String> {
    fetch_delays_with_progress(endpoint, nodes, &mut |_, _, _| {})
}

/// Same probes as [`fetch_delays`], reporting each finished node as soon as its
/// parallel request returns. Used for the per-node `node-test` progress events.
pub fn fetch_delays_with_progress(
    endpoint: &ControllerEndpoint,
    nodes: &[String],
    on_result: &mut dyn FnMut(&str, Option<u64>, bool),
) -> Result<Vec<NodeDelay>, String> {
    fetch_provider_delays(endpoint, nodes, &BTreeMap::new(), on_result)
}

pub fn fetch_provider_delays(
    endpoint: &ControllerEndpoint,
    nodes: &[String],
    providers: &BTreeMap<String, String>,
    on_result: &mut dyn FnMut(&str, Option<u64>, bool),
) -> Result<Vec<NodeDelay>, String> {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return Err(KERNEL_DOWN.to_string());
    }
    if nodes.is_empty() {
        return Ok(Vec::new());
    }
    // A fixed pool starts another probe as soon as one completes. A slow node
    // must not hold up the next batch of otherwise idle workers.
    let mut results: Vec<Option<Result<u64, ProbeFail>>> = (0..nodes.len()).map(|_| None).collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        for _ in 0..nodes.len().min(16) {
            let sender = sender.clone();
            let next = &next;
            scope.spawn(move || loop {
                let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(name) = nodes.get(index) else { break };
                let outcome = delay_one(endpoint, name, providers.get(name).map(String::as_str));
                if sender.send((index, outcome)).is_err() { break; }
            });
        }
        drop(sender);
        for (index, outcome) in receiver {
            let delay = match &outcome { Ok(ms) => Some(*ms), Err(_) => None };
            on_result(&nodes[index], delay, delay.is_none());
            results[index] = Some(outcome);
        }
    });
    let saw_controller = results
        .iter()
        .any(|item| !matches!(item, Some(Err(ProbeFail::Unavailable)) | None));
    if !saw_controller {
        return Err(KERNEL_DOWN.to_string());
    }
    Ok(nodes
        .iter()
        .zip(results)
        .map(|(name, item)| NodeDelay {
            name: name.clone(),
            delay_ms: match item {
                Some(Ok(ms)) => Some(ms),
                _ => None,
            },
        })
        .collect())
}

pub fn fetch_catalog(endpoint: &ControllerEndpoint) -> Result<RuntimeCatalog, String> {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return Err(KERNEL_DOWN.to_string());
    }
    let url = format!("http://{}:{}/proxies", endpoint.host, endpoint.port);
    let agent = agent(Duration::from_millis(800));
    let request = agent.get(&url).set("User-Agent", "Billow");
    let request = if endpoint.secret.is_empty() {
        request
    } else {
        request.set("Authorization", &format!("Bearer {}", endpoint.secret))
    };
    let response = request.call().map_err(|_| KERNEL_DOWN.to_string())?;
    catalog_from_reader(BufReader::new(response.into_reader().take(8_000_000)))
}

pub fn fetch_provider_catalog(endpoint: &ControllerEndpoint) -> Result<RuntimeCatalog, String> {
    if !loopback(&endpoint.host) || endpoint.port == 0 { return Err(KERNEL_DOWN.to_string()); }
    let url = format!("http://{}:{}/providers/proxies", endpoint.host, endpoint.port);
    let response = agent(Duration::from_millis(800)).get(&url)
        .set("Authorization", &format!("Bearer {}", endpoint.secret))
        .call().map_err(|_| "订阅节点资料没有读取".to_string())?;
    providers_from_reader(BufReader::new(response.into_reader().take(8_000_000)))
}

/// Read actual listener state; Mihomo can stay alive after failing to bind a port or TUN.
pub fn listeners_ready(endpoint: &ControllerEndpoint, port: Option<u16>, tun: bool) -> bool {
    if !loopback(&endpoint.host) || endpoint.port == 0 { return false; }
    let url = format!("http://{}:{}/configs", endpoint.host, endpoint.port);
    let client = agent(Duration::from_millis(150));
    let request = client.get(&url).set("Authorization", &format!("Bearer {}", endpoint.secret));
    let Ok(response) = request.call() else { return false; };
    let Ok(body) = read_body(response) else { return false; };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) else { return false; };
    let port_ready = port.is_none_or(|port| {
        value.get("mixed-port").and_then(|p| p.as_u64()) == Some(u64::from(port))
            && std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                Duration::from_millis(150),
            ).is_ok()
    });
    let tun_ready = value.get("tun").and_then(|t| t.get("enable")).and_then(|v| v.as_bool()) == Some(tun);
    port_ready && tun_ready
}

#[cfg(test)]
pub fn fetch_now(endpoint: &ControllerEndpoint) -> Result<BTreeMap<String, String>, String> {
    fetch_catalog(endpoint).map(|catalog| catalog.now)
}

enum ProbeFail {
    Unavailable,
    Node,
}

fn delay_one(endpoint: &ControllerEndpoint, name: &str, provider: Option<&str>) -> Result<u64, ProbeFail> {
    let path = match provider {
        Some(provider) => format!("providers/proxies/{}/{}/healthcheck", encode_segment(provider), encode_segment(name)),
        None => format!("proxies/{}/delay", encode_segment(name)),
    };
    let url = format!(
        "http://{}:{}/{}?timeout={}&url={}",
        endpoint.host,
        endpoint.port,
        path,
        probe_timeout(),
        encode_segment(&probe_url())
    );
    let agent = agent(Duration::from_millis(probe_timeout() + 2000));
    let request = agent.get(&url).set("User-Agent", "Billow");
    let request = if endpoint.secret.is_empty() {
        request
    } else {
        request.set("Authorization", &format!("Bearer {}", endpoint.secret))
    };
    let response = match request.call() {
        Ok(response) => response,
        Err(ureq::Error::Status(_, _)) => return Err(ProbeFail::Node),
        Err(ureq::Error::Transport(_)) => return Err(ProbeFail::Unavailable),
    };
    let text = read_body(response).map_err(|_| ProbeFail::Node)?;
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|_| ProbeFail::Node)?;
    value
        .get("delay")
        .and_then(serde_json::Value::as_u64)
        .ok_or(ProbeFail::Node)
}

fn read_body(response: ureq::Response) -> Result<String, ()> {
    let mut body = String::new();
    response
        .into_reader()
        .take(1_000_000)
        .read_to_string(&mut body)
        .map_err(|_| ())?;
    Ok(body)
}

fn agent(read: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_millis(400))
        .timeout_read(read)
        .timeout_write(Duration::from_millis(400))
        .redirects(0)
        .try_proxy_from_env(false)
        .build()
}

fn loopback(host: &str) -> bool {
    host == "127.0.0.1" || host.eq_ignore_ascii_case("localhost")
}

fn split_host_port(raw: &str) -> Option<(String, u16)> {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        let port = port.parse().ok()?;
        return Some((host.to_string(), port));
    }
    let (host, port) = raw.rsplit_once(':')?;
    let port = port.parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

fn encode_segment(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn is_manual(group: &Value) -> bool {
    match read_string(group, "type") {
        Some(kind) => {
            let kind = kind.trim().to_ascii_lowercase();
            kind == "select" || kind == "selector"
        }
        None => false,
    }
}

/// Mirrors the kernel's `SelectAble` minus `Selector`: load-balance and smart stay automatic.
fn is_pinnable(group: &Value) -> bool {
    read_string(group, "type").is_some_and(|kind| {
        matches!(kind.trim().to_ascii_lowercase().as_str(), "url-test" | "fallback")
    })
}

fn proxy_names(value: &Value) -> Vec<String> {
    let Some(list) = mapping_get(value, "proxies").and_then(Value::as_sequence) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for item in list {
        if let Some(name) = read_string(item, "name") {
            if !name.is_empty() && !names.iter().any(|existing| existing == &name) {
                names.push(name);
            }
        }
    }
    names
}

fn read_string_list(value: &Value, key: &str) -> Vec<String> {
    let Some(list) = mapping_get(value, key).and_then(Value::as_sequence) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in list {
        if let Some(name) = item.as_str() {
            let name = name.trim();
            if !name.is_empty() && !out.iter().any(|existing| existing == name) {
                out.push(name.to_string());
            }
        }
    }
    out
}

fn read_string(value: &Value, key: &str) -> Option<String> {
    mapping_get(value, key)
        .and_then(Value::as_str)
        .map(str::trim)
        .map(ToString::to_string)
        .filter(|text| !text.is_empty())
}

fn mapping_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_mapping()?
        .iter()
        .find(|(candidate, _)| candidate.as_str() == Some(key))
        .map(|(_, item)| item)
}

fn mapping_get_mut<'a>(value: &'a mut Value, key: &str) -> Option<&'a mut Value> {
    value
        .as_mapping_mut()?
        .iter_mut()
        .find(|(candidate, _)| candidate.as_str() == Some(key))
        .map(|(_, item)| item)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_nodes_keep_protocol_and_use_the_provider_healthcheck_endpoint() {
        let providers = providers_from_reader(br#"{"providers":{"local source":{"proxies":[{"name":"HK/1","type":"Shadowsocks","udp":true,"history":[{"delay":999}]}]}}}"#.as_slice()).unwrap();
        let mut catalog = RuntimeCatalog::default();
        catalog.merge_providers(&providers);
        assert_eq!(catalog.types["HK/1"], "Shadowsocks");
        assert_eq!(catalog.tags["HK/1"], ["UDP"]);
        let (port, server) = serve(vec![http_response("200 OK", r#"{"delay":169}"#)]);
        let endpoint = ControllerEndpoint { host: "127.0.0.1".to_string(), port, secret: String::new() };
        let result = fetch_provider_delays(&endpoint, &["HK/1".to_string()], &catalog.providers, &mut |_, _, _| {}).unwrap();
        assert_eq!(result[0].delay_ms, Some(169));
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("GET /providers/proxies/local%20source/HK%2F1/healthcheck?"));
        let mut inline = RuntimeCatalog::default();
        inline.types.insert("HK/1".to_string(), "VLESS".to_string());
        inline.merge_providers(&providers);
        assert!(inline.providers.is_empty());
        assert_eq!(inline.types["HK/1"], "VLESS");
    }

    #[test]
    fn listener_readiness_requires_the_requested_port_and_tun_state() {
        let mixed = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mixed_port = mixed.local_addr().unwrap().port();
        let responses = [
            r#"{"mixed-port":0,"tun":{"enable":false}}"#,
            r#"{"mixed-port":7890,"tun":{"enable":false}}"#,
            r#"{"mixed-port":7890,"tun":{"enable":true}}"#,
            r#"{"mixed-port":7890,"tun":{"enable":true}}"#,
            r#"{"mixed-port":7890,"tun":{"enable":false}}"#,
            r#"{"mixed-port":7890,"tun":{"enable":false}}"#,
        ].into_iter().map(|body| http_response("200 OK", &body.replace("7890", &mixed_port.to_string()))).collect();
        let (port, server) = serve(responses);
        let endpoint = ControllerEndpoint { host: "127.0.0.1".to_string(), port, secret: "test".to_string() };
        assert!(!listeners_ready(&endpoint, Some(mixed_port), false));
        assert!(!listeners_ready(&endpoint, Some(mixed_port), true));
        assert!(listeners_ready(&endpoint, Some(mixed_port), true));
        assert!(!listeners_ready(&endpoint, Some(mixed_port), false), "TUN must actually be disabled");
        assert!(listeners_ready(&endpoint, Some(mixed_port), false));
        drop(mixed);
        assert!(!listeners_ready(&endpoint, Some(mixed_port), false), "reported port without a listener is not ready");
        let requests = server.join().unwrap();
        assert!(requests.iter().all(|request| request.starts_with("GET /configs ")));
    }

    #[test]
    fn catalog_skips_unneeded_history_and_rejects_incomplete_payloads() {
        let history = "{\"time\":\"2026-01-01T00:00:00Z\",\"delay\":42},".repeat(20_000);
        let body = format!(r#"{{"proxies":{{"a":{{"type":"VLESS","history":[{}{{"delay":0}}]}},"group":{{"all":["a"],"now":"a","type":"Selector"}}}}}}"#, history);
        let parsed = catalog_from_reader(body.as_bytes()).unwrap();
        assert_eq!(parsed.members["group"], ["a"]);
        assert_eq!(parsed.types["a"], "VLESS");
        assert_eq!(parsed.now["group"], "a");
        assert!(catalog_from_reader(&body.as_bytes()[..body.len() - 1]).is_err());
        assert!(catalog_from_reader(br#"{"message":"unauthorized"}"#.as_slice()).is_err());
    }

    #[test]
    fn runtime_members_replace_static_lists_and_keep_provider_filters_and_selection() {
        let document: Value = serde_yaml::from_str("proxy-groups:\n  - {name: Available, type: select, use: [remote]}\n  - {name: HK, type: url-test, use: [remote], filter: HK}\n").unwrap();
        let runtime = runtime_catalog(&serde_json::json!({"proxies": {
            "Available": {"type":"Selector", "all":["HK 1", "JP 1"], "now":"JP 1"},
            "HK": {"type":"URLTest", "all":["HK 1"], "now":"HK 1"},
            "HK 1": {"type":"Shadowsocks"}, "JP 1": {"type":"VLESS"}
        }})).unwrap();
        let groups = resolved_groups(&document, &runtime);
        assert_eq!(groups[0].proxies, ["HK 1", "JP 1"]);
        assert_eq!(groups[1].proxies, ["HK 1"]);
        assert_eq!(runtime.now["Available"], "JP 1");
        assert_eq!(runtime.types["JP 1"], "VLESS");
        assert!(runtime_catalog(&serde_json::json!({"message":"unauthorized"})).is_err());
    }
    #[test]
    fn auto_groups_report_pinnable_fixed_and_hidden_from_yaml_and_controller() {
        let document: Value = serde_yaml::from_str("proxy-groups:\n  - {name: Pick, type: select, proxies: [a]}\n  - {name: Fast, type: URL-Test, proxies: [a, b]}\n  - {name: Backup, type: fallback, proxies: [a, b], hidden: true}\n  - {name: Spread, type: load-balance, proxies: [a, b]}\n  - {name: Smart, type: smart, proxies: [a, b]}\n").unwrap();
        let groups = parse_proxy_groups(&document);
        let pinnable: Vec<bool> = groups.iter().map(|group| group.pinnable).collect();
        assert_eq!(pinnable, [false, true, true, false, false]);
        let hidden: Vec<bool> = groups.iter().map(|group| group.hidden).collect();
        assert_eq!(hidden, [false, false, true, false, false]);
        let runtime = runtime_catalog(&serde_json::json!({"proxies": {
            "Fast": {"type":"URLTest", "all":["a", "b"], "now":"b", "fixed":"b", "hidden": true},
            "Backup": {"type":"Fallback", "all":["a", "b"], "now":"a", "fixed":"", "hidden": false},
            "a": {"type":"Shadowsocks"}
        }})).unwrap();
        assert_eq!(runtime.fixed.get("Fast").map(String::as_str), Some("b"));
        assert!(!runtime.fixed.contains_key("Backup"), "an empty fixed means automatic");
        assert_eq!(runtime.hidden.get("Fast"), Some(&true));
        assert_eq!(runtime.hidden.get("Backup"), Some(&false));
        assert!(!runtime.hidden.contains_key("a"));
    }

    #[test]
    fn unfix_sends_delete_to_the_injected_endpoint_and_reports_the_kernel_reason() {
        let (port, handle) = serve(vec![
            http_response("204 No Content", ""),
            http_response("400 Bad Request", "{\"message\":\"Selector update error: not found\"}"),
            http_response("400 Bad Request", "{\"message\":\"proxy not exist\"}"),
        ]);
        let endpoint = ControllerEndpoint { host: "127.0.0.1".to_string(), port, secret: CONTROLLER_SECRET.to_string() };
        delete_selection(&endpoint, "自动").unwrap();
        let rejected = delete_selection(&endpoint, "Fast").unwrap_err();
        assert!(rejected.starts_with(UNFIX_FAILED) && rejected.contains("not found"), "{rejected}");
        let refused = put_selection(&endpoint, "Fast", "gone").unwrap_err();
        assert!(refused.starts_with(SELECT_FAILED) && refused.contains("proxy not exist"), "{refused}");
        let seen = handle.join().unwrap();
        assert!(seen[0].starts_with("DELETE /proxies/%E8%87%AA%E5%8A%A8 "), "{}", seen[0]);
        assert!(seen[0].contains("Bearer billow-local"));
        assert!(seen[1].starts_with("DELETE /proxies/Fast "));
        assert!(seen[2].starts_with("PUT /proxies/Fast "));

        let remote = ControllerEndpoint { host: "198.51.100.1".to_string(), port: 80, secret: String::new() };
        assert_eq!(delete_selection(&remote, "Fast").unwrap_err(), KERNEL_DOWN);
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);
        let down = ControllerEndpoint { host: "127.0.0.1".to_string(), port: closed_port, secret: String::new() };
        assert_eq!(delete_selection(&down, "Fast").unwrap_err(), KERNEL_DOWN);
    }

    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn pinning_waits_for_the_kernel_to_probe_a_dead_fallback_member() {
        // Fallback.Set answers only after URL-testing a dead member (up to 5 s).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 2048];
            while let Ok(n) = stream.read(&mut tmp) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if request_complete(&buf) {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(1500));
            let _ = stream.write_all(http_response("204 No Content", "").as_bytes());
            String::from_utf8_lossy(&buf).into_owned()
        });
        let endpoint = ControllerEndpoint { host: "127.0.0.1".to_string(), port, secret: String::new() };
        put_selection(&endpoint, "故障转移", "dead").unwrap();
        assert!(handle.join().unwrap().starts_with("PUT /proxies/"));
    }
    use std::thread;
    use std::time::Duration;

    fn sample() -> Value {
        serde_yaml::from_str(
            r#"
proxies:
  - name: one
    type: ss
    server: 127.0.0.1
    port: 1
  - name: two
    type: ss
    server: 127.0.0.1
    port: 2
proxy-groups:
  - name: manual
    type: Select
    icon: https://icons.example.com/manual.png
    proxies:
      - one
      - two
      - DIRECT
      - one
  - name: auto
    type: url-test
    icon: file:///tmp/local.png
    proxies:
      - one
      - two
  - name: all
    type: selector
    icon: "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="
    include-all: true
    proxies:
      - DIRECT
"#,
        )
        .unwrap()
    }

    #[test]
    fn parses_manual_and_auto_groups_from_saved_config() {
        let groups = parse_proxy_groups(&sample());
        assert_eq!(groups.len(), 3);
        assert!(groups[0].manual);
        assert_eq!(groups[0].proxies, ["one", "two", "DIRECT"]);
        assert!(!groups[1].manual);
        assert_eq!(groups[1].proxies, ["one", "two"]);
        assert!(groups[2].manual);
        assert_eq!(groups[2].proxies, ["DIRECT", "one", "two"]);
        assert_eq!(
            groups[0].icon.as_deref(),
            Some("https://icons.example.com/manual.png")
        );
        assert!(groups[1].icon.is_none(), "a local file is not a usable icon");
        assert!(groups[2].icon.as_deref().is_some_and(|icon| icon.starts_with("data:image/")));
    }

    #[test]
    fn group_icons_keep_remote_and_inline_images_only() {
        assert_eq!(
            usable_icon(" https://icons.example.com/a.png ").as_deref(),
            Some("https://icons.example.com/a.png")
        );
        assert_eq!(
            usable_icon("HTTP://icons.example.com/a.png").as_deref(),
            Some("HTTP://icons.example.com/a.png")
        );
        assert!(usable_icon("data:image/png;base64,AAAA").is_some());
        for rejected in [
            "",
            "   ",
            "file:///tmp/a.png",
            "javascript:alert(1)",
            "ftp://icons.example.com/a.png",
            "https://icons.example.com/a b.png",
            "data:text/html;base64,AAAA",
        ] {
            assert!(usable_icon(rejected).is_none(), "{rejected}");
        }
        let yaml = r#"
proxy-groups:
  - name: plain
    type: select
    proxies: [DIRECT]
"#;
        let groups = parse_proxy_groups(&serde_yaml::from_str(yaml).unwrap());
        assert!(groups[0].icon.is_none(), "missing icon stays empty");
    }

    #[test]
    fn saved_choice_moves_only_manual_group_to_front() {
        let yaml = serde_yaml::to_string(&sample()).unwrap();
        let mut selected = BTreeMap::new();
        selected.insert("manual".to_string(), "two".to_string());
        selected.insert("auto".to_string(), "two".to_string());
        let updated = prioritize_selections(&yaml, &selected);
        let value: Value = serde_yaml::from_str(&updated).unwrap();
        let groups = parse_proxy_groups(&value);
        assert_eq!(groups[0].proxies[0], "two");
        assert_eq!(groups[1].proxies, ["one", "two"]);
    }

    #[test]
    fn controller_stays_on_loopback_and_keeps_an_existing_one() {
        let yaml = "mixed-port: 7890\nmode: rule\n";
        let ensured = ensure_controller(yaml);
        let endpoint = controller_from_yaml(&ensured).unwrap();
        assert_eq!(endpoint.host, "127.0.0.1");
        assert_eq!(endpoint.port, CONTROLLER_PORT);
        assert_eq!(endpoint.secret, CONTROLLER_SECRET);
        let custom = "external-controller: 127.0.0.1:9090\nsecret: kept\nmixed-port: 1\n";
        let kept = ensure_controller(custom);
        let endpoint = controller_from_yaml(&kept).unwrap();
        assert_eq!(endpoint.port, 9090);
        assert_eq!(endpoint.secret, "kept");
        assert!(controller_from_yaml("external-controller: 203.0.113.10:9090\n").is_none());
    }

    #[test]
    fn selection_and_delay_use_the_injected_endpoint_only() {
        let (port, handle) = serve(vec![
            http_response("204 No Content", ""),
            http_response("200 OK", "{\"delay\":12}"),
            http_response("503 Service Unavailable", ""),
            http_response(
                "200 OK",
                "{\"proxies\":{\"auto\":{\"now\":\"beta\",\"type\":\"URLTest\"}}}",
            ),
        ]);
        let endpoint = ControllerEndpoint {
            host: "127.0.0.1".to_string(),
            port,
            secret: CONTROLLER_SECRET.to_string(),
        };
        put_selection(&endpoint, "手动", "日本").unwrap();
        let delays = fetch_delays(&endpoint, &["甲".to_string(), "乙".to_string()]).unwrap();
        // Probes run in parallel, so which node gets which canned reply is not fixed.
        let mut got: Vec<Option<u64>> = delays.iter().map(|item| item.delay_ms).collect();
        got.sort();
        assert_eq!(got, [None, Some(12)]);
        let now = fetch_now(&endpoint).unwrap();
        assert_eq!(now.get("auto").map(String::as_str), Some("beta"));
        let seen = handle.join().unwrap();
        assert!(seen[0].contains("PUT /proxies/%E6%89%8B"));
        assert!(seen[0].contains("billow-local"));
        assert!(seen[0].contains("日本") || seen[0].contains("\\u65e5\\u672c"));
        assert!(seen[1].contains("/delay?"));
        assert!(!seen.iter().any(|item| item.contains("203.0.113.")));

        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);
        let missing = ControllerEndpoint {
            host: "127.0.0.1".to_string(),
            port: closed_port,
            secret: String::new(),
        };
        assert!(fetch_delays(&missing, &["甲".to_string()]).is_err());
        let remote = ControllerEndpoint {
            host: "198.51.100.1".to_string(),
            port: 80,
            secret: String::new(),
        };
        assert!(put_selection(&remote, "manual", "one").is_err());
        assert!(fetch_delays(&remote, &["one".to_string()]).is_err());
        assert!(fetch_now(&remote).is_err());
    }

    fn http_response(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn serve(responses: Vec<String>) -> (u16, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let mut seen = Vec::new();
            for response in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 2048];
                loop {
                    match stream.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if request_complete(&buf) {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                seen.push(String::from_utf8_lossy(&buf).into_owned());
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
            seen
        });
        (port, handle)
    }

    fn request_complete(buf: &[u8]) -> bool {
        let Some(pos) = buf.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let head = String::from_utf8_lossy(&buf[..pos]);
        let length = head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            if key.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        });
        match length {
            Some(length) => buf.len() >= pos + 4 + length,
            None => true,
        }
    }

    #[test]
    fn probe_pool_starts_the_next_node_while_an_earlier_one_is_slow() {
        use std::io::BufRead;
        use std::sync::{Arc, Condvar, Mutex};
        use std::sync::atomic::{AtomicBool, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let signal = Arc::new((Mutex::new(false), Condvar::new()));
        let pipelined = Arc::new(AtomicBool::new(false));
        let server_signal = Arc::clone(&signal);
        let server_pipelined = Arc::clone(&pipelined);
        let server = thread::spawn(move || {
            thread::scope(|scope| {
                for _ in 0..17 {
                    let (mut stream, _) = listener.accept().unwrap();
                    let signal = Arc::clone(&server_signal);
                    let pipelined = Arc::clone(&server_pipelined);
                    scope.spawn(move || {
                        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let mut first = String::new(); reader.read_line(&mut first).unwrap();
                        loop {
                            let mut line = String::new(); reader.read_line(&mut line).unwrap();
                            if line == "\r\n" || line.is_empty() { break; }
                        }
                        if first.contains("/proxies/n16/") {
                            *signal.0.lock().unwrap() = true;
                            signal.1.notify_all();
                        }
                        if first.contains("/proxies/n0/") {
                            let (seen, _) = signal.1.wait_timeout_while(signal.0.lock().unwrap(), Duration::from_secs(5), |seen| !*seen).unwrap();
                            pipelined.store(*seen, Ordering::Relaxed);
                        }
                        let response = http_response("200 OK", r#"{"delay":5}"#);
                        stream.write_all(response.as_bytes()).unwrap();
                    });
                }
            });
        });
        let endpoint = ControllerEndpoint { host: "127.0.0.1".into(), port, secret: String::new() };
        let names: Vec<String> = (0..17).map(|i| format!("n{i}")).collect();
        let mut progress = Vec::new();
        let results = fetch_delays_with_progress(&endpoint, &names, &mut |name, _, _| progress.push(name.to_string())).unwrap();
        server.join().unwrap();
        assert!(pipelined.load(Ordering::Relaxed), "the 17th probe must start before the first slow batch drains");
        assert_eq!(progress.len(), 17);
        assert_eq!(results.iter().map(|result| result.name.clone()).collect::<Vec<_>>(), names);
    }

    #[test]
    fn node_test_event_payload_carries_progress_and_failure() {
        let event = NodeTestEvent {
            node: "香港 01".to_string(),
            delay: Some(120),
            failed: false,
            tested: 2,
            total: 3,
        };
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            r#"{"node":"香港 01","delay":120,"failed":false,"tested":2,"total":3}"#
        );
        let failed = NodeTestEvent {
            node: "日本 02".to_string(),
            delay: None,
            failed: true,
            tested: 3,
            total: 3,
        };
        let value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&failed).unwrap()).unwrap();
        assert_eq!(value["delay"], serde_json::Value::Null);
        assert_eq!(value["failed"], true);
        assert_eq!(value["tested"], 3);
    }

    #[test]
    fn proxy_tags_follow_config_capabilities_without_repeating_the_protocol() {
        let config: Value = serde_yaml::from_str(
            r#"
proxies:
  - { name: a, type: vless, udp: true, tls: true, network: grpc, flow: xtls-rprx-vision, reality-opts: { public-key: k } }
  - { name: b, type: hysteria2, server: x, port: 1 }
  - { name: c, type: trojan, tls: true, udp: "true", network: ws, smux: { enabled: true }, tfo: true, mptcp: true }
  - { name: d, type: vmess, tls: true, dialer-proxy: a }
  - { name: e, type: ss }
proxy-groups:
  - { name: G, type: select, proxies: [a] }
"#,
        )
        .unwrap();
        let infos = proxy_infos(&config);
        assert_eq!(infos["a"].tags, ["UDP", "Reality", "gRPC", "Vision"]);
        assert_eq!(infos["b"].tags, ["UDP"]);
        assert_eq!(infos["c"].tags, ["UDP", "WS", "Mux", "TFO", "MPTCP"]);
        assert_eq!(infos["d"].tags, ["TLS", CHAINED_TAG]);
        assert_eq!(infos["e"].tags.is_empty(), true);
        assert_eq!(infos["G"].kind, "select");
        assert!(infos["G"].tags.is_empty());
    }

    #[test]
    fn put_config_sends_raw_yaml_with_force_reload_and_preserves_controller() {
        let (port, handle) = serve(vec![http_response("204 No Content", "")]);
        let endpoint = ControllerEndpoint {
            host: "127.0.0.1".to_string(),
            port,
            secret: CONTROLLER_SECRET.to_string(),
        };
        let rewritten = rewrite_controller_endpoint("mixed-port: 7890\nmode: rule\n", &endpoint);
        assert_eq!(controller_from_yaml(&rewritten).as_ref(), Some(&endpoint));
        put_config(&endpoint, &rewritten).unwrap();
        let seen = handle.join().unwrap();
        assert!(seen[0].contains("PUT /configs?force=true HTTP/1.1"));
        assert!(seen[0].contains("mixed-port: 7890"));
    }

    #[test]
    fn patch_mode_sends_json_and_surfaces_controller_error_reason() {
        let (port, handle) = serve(vec![
            http_response("204 No Content", ""),
            http_response("400 Bad Request", r#"{"message":"invalid mode"}"#),
            http_response("500 Internal Server Error", ""),
        ]);
        let endpoint = ControllerEndpoint {
            host: "127.0.0.1".to_string(),
            port,
            secret: CONTROLLER_SECRET.to_string(),
        };
        patch_mode(&endpoint, "global").unwrap();
        let err_json = patch_mode(&endpoint, "direct").unwrap_err();
        assert_eq!(err_json, "模式没有切换：invalid mode");
        let err_status = patch_mode(&endpoint, "rule").unwrap_err();
        assert_eq!(err_status, "模式没有切换（HTTP 500）");
        let seen = handle.join().unwrap();
        assert!(seen[0].starts_with("PATCH /configs HTTP/1.1"));
        assert!(seen[0].contains(r#"{"mode":"global"}"#));
    }
}
