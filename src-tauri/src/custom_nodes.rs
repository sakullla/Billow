#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap, HashSet};

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};

pub const CUSTOM_PROFILE_ID: &str = "__custom__";
pub const CUSTOM_PROFILE_NAME: &str = "纯自建节点";
pub const LANDING_GROUP_NAME: &str = "自建落地";
pub const CHAIN_RELAY_GROUP_NAME: &str = "链式前置";
pub const STANDALONE_SELECT_GROUP: &str = "节点选择";
pub const STANDALONE_AUTO_GROUP: &str = "自动选择";
pub const COLLISION_SUFFIX: &str = " · 自建";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LandingPresetInfo {
    pub id: &'static str,
    pub label: &'static str,
    pub domains: &'static [&'static str],
}

pub const LANDING_PRESETS: &[LandingPresetInfo] = &[
    LandingPresetInfo {
        id: "ai",
        label: "AI 服务（ChatGPT / Claude / Gemini）",
        domains: &[
            "openai.com",
            "chatgpt.com",
            "oaistatic.com",
            "oaiusercontent.com",
            "anthropic.com",
            "claude.ai",
            "claude.com",
            "gemini.google.com",
            "generativelanguage.googleapis.com",
            "aistudio.google.com",
            "deepmind.com",
            "perplexity.ai",
            "x.ai",
            "grok.com",
            "copilot.microsoft.com",
            "githubcopilot.com",
            "poe.com",
            "cursor.sh",
            "cursor.com",
            "mistral.ai",
            "cohere.com",
        ],
    },
    LandingPresetInfo {
        id: "streaming",
        label: "流媒体（Netflix / Disney+ / Spotify）",
        domains: &[
            "netflix.com",
            "nflxvideo.net",
            "nflximg.net",
            "disneyplus.com",
            "disney-plus.net",
            "hulu.com",
            "spotify.com",
            "tiktok.com",
            "tiktokv.com",
        ],
    },
];

pub fn find_preset(id: &str) -> Option<&'static LandingPresetInfo> {
    LANDING_PRESETS.iter().find(|preset| preset.id == id)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DialerTarget {
    #[default]
    Direct,
    ProfileGroup {
        #[serde(default)]
        group: Option<String>,
    },
    FixedProxy {
        name: String,
    },
    CustomNode {
        id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CustomNode {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub note: String,
    pub protocol: String,
    pub raw_yaml: String,
    pub dialer: DialerTarget,
}

impl Default for CustomNode {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            enabled: true,
            note: String::new(),
            protocol: String::new(),
            raw_yaml: String::new(),
            dialer: DialerTarget::Direct,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LandingRuleKind {
    Preset { id: String },
    Domain { pattern: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LandingRuleTarget {
    #[default]
    CustomGroup,
    CustomNode {
        id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct LandingRule {
    pub id: String,
    pub enabled: bool,
    pub rule: LandingRuleKind,
    pub target: LandingRuleTarget,
}

impl Default for LandingRule {
    fn default() -> Self {
        Self {
            id: String::new(),
            enabled: true,
            rule: LandingRuleKind::Preset {
                id: "ai".to_string(),
            },
            target: LandingRuleTarget::CustomGroup,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CustomNodesState {
    pub overlay_enabled: bool,
    pub rules_enabled: bool,
    pub next_node_id: u64,
    pub next_rule_id: u64,
    pub nodes: Vec<CustomNode>,
    pub rules: Vec<LandingRule>,
}

impl Default for CustomNodesState {
    fn default() -> Self {
        Self {
            overlay_enabled: true,
            rules_enabled: true,
            next_node_id: 1,
            next_rule_id: 1,
            nodes: Vec::new(),
            rules: Vec::new(),
        }
    }
}

impl CustomNodesState {
    pub fn alloc_node_id(&mut self) -> String {
        let id = format!("cn{}", self.next_node_id);
        self.next_node_id = self.next_node_id.saturating_add(1);
        id
    }

    pub fn alloc_rule_id(&mut self) -> String {
        let id = format!("lr{}", self.next_rule_id);
        self.next_rule_id = self.next_rule_id.saturating_add(1);
        id
    }

    pub fn has_enabled_nodes(&self) -> bool {
        self.nodes.iter().any(|node| node.enabled)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomNodeWarning {
    pub code: String,
    pub node_id: Option<String>,
    pub rule_id: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedCustomNode {
    pub name: String,
    pub protocol: String,
    pub server: String,
    pub port: u16,
    pub raw_yaml: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParseItemError {
    pub index: usize,
    pub source: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ParseNodesResult {
    pub parsed: Vec<ParsedCustomNode>,
    pub errors: Vec<ParseItemError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SimpleProxyForm {
    pub name: String,
    pub protocol: String,
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub skip_cert_verify: bool,
    #[serde(default)]
    pub udp: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DialerContext {
    pub primary_group: Option<String>,
    pub available_targets: HashSet<String>,
    pub is_standalone: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialerValidationReport {
    pub cycles: Vec<Vec<String>>,
    pub missing_dialers: Vec<CustomNodeWarning>,
    pub valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayResult {
    pub yaml: String,
    pub warnings: Vec<CustomNodeWarning>,
    pub injected_count: usize,
    pub injected_rule_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandaloneResult {
    pub yaml: String,
    pub warnings: Vec<CustomNodeWarning>,
    pub node_count: usize,
    pub rule_count: usize,
}

// ============================================================================
// Simple SOCKS5 / HTTP Form Helpers
// ============================================================================

pub fn build_simple_proxy_yaml(form: &SimpleProxyForm) -> Result<ParsedCustomNode, String> {
    let protocol = match form.protocol.trim().to_ascii_lowercase().as_str() {
        "socks5" | "socks" => "socks5",
        "http" | "https" => "http",
        other => {
            return Err(format!(
                "快捷表单仅支持 SOCKS5 或 HTTP 协议，当前为：{other}"
            ))
        }
    };
    let server = form.server.trim();
    if server.is_empty() {
        return Err("服务器地址不能为空".to_string());
    }
    if form.port == 0 {
        return Err("端口必须在 1 到 65535 之间".to_string());
    }
    let name = if form.name.trim().is_empty() {
        format!("{server}:{}", form.port)
    } else {
        form.name.trim().to_string()
    };

    let mut map = Mapping::new();
    set_str(&mut map, "name", &name);
    set_str(&mut map, "type", protocol);
    set_str(&mut map, "server", server);
    set_u64(&mut map, "port", u64::from(form.port));
    if !form.username.is_empty() {
        set_str(&mut map, "username", &form.username);
    }
    if !form.password.is_empty() {
        set_str(&mut map, "password", &form.password);
    }
    if form.tls {
        set_bool(&mut map, "tls", true);
        if form.skip_cert_verify {
            set_bool(&mut map, "skip-cert-verify", true);
        }
    }
    if protocol == "socks5" {
        set_bool(&mut map, "udp", form.udp);
    }

    finalize_proxy_mapping(map, String::new())
}

pub fn extract_simple_proxy(raw_yaml: &str) -> Option<SimpleProxyForm> {
    let value: Value = serde_yaml::from_str(raw_yaml).ok()?;
    let map = value.as_mapping()?;
    let protocol = map_str(map, "type")?.to_ascii_lowercase();
    if protocol != "socks5" && protocol != "http" {
        return None;
    }
    let server = map_str(map, "server")?.to_string();
    let port = map_u16(map, "port")?;
    let name = map_str(map, "name").unwrap_or("").to_string();
    let username = map_str(map, "username").unwrap_or("").to_string();
    let password = map_str(map, "password").unwrap_or("").to_string();
    let tls = map_bool(map, "tls").unwrap_or(false);
    let skip_cert_verify = map_bool(map, "skip-cert-verify").unwrap_or(false);
    let udp = map_bool(map, "udp").unwrap_or(protocol == "socks5");
    Some(SimpleProxyForm {
        name,
        protocol,
        server,
        port,
        username,
        password,
        tls,
        skip_cert_verify,
        udp,
    })
}

pub fn validate_raw_node_yaml(
    raw_yaml: &str,
    name_override: Option<&str>,
) -> Result<ParsedCustomNode, String> {
    let value: Value = serde_yaml::from_str(raw_yaml)
        .map_err(|err| format!("节点 YAML 语法错误：{err}"))?;
    let mut map = value
        .as_mapping()
        .cloned()
        .ok_or_else(|| "节点 YAML 必须是一个键值映射对象".to_string())?;
    if let Some(name) = name_override.map(str::trim).filter(|s| !s.is_empty()) {
        set_str(&mut map, "name", name);
    }
    finalize_proxy_mapping(map, String::new())
}

// ============================================================================
// Multi-Protocol URI / Base64 / YAML Parser
// ============================================================================

pub fn looks_like_nodes_input(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    for scheme in [
        "vless://",
        "vmess://",
        "trojan://",
        "ss://",
        "hysteria2://",
        "hy2://",
        "tuic://",
        "anytls://",
        "socks5://",
        "socks://",
    ] {
        if lower.contains(scheme) {
            return true;
        }
    }
    if (trimmed.contains("proxies:") || (trimmed.contains("type:") && trimmed.contains("server:")))
        && !lower.starts_with("http://")
        && !lower.starts_with("https://")
    {
        return true;
    }
    if !trimmed.contains("://") {
        if let Some(decoded) = try_decode_base64_text(trimmed) {
            return looks_like_nodes_input(&decoded);
        }
    }
    false
}

pub fn parse_nodes_input(raw: &str, existing_names: &[String]) -> ParseNodesResult {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return ParseNodesResult {
            parsed: Vec::new(),
            errors: vec![ParseItemError {
                index: 1,
                source: String::new(),
                reason: "请输入节点链接、Base64 列表或节点 YAML".to_string(),
            }],
        };
    }

    let mut result = parse_nodes_input_inner(trimmed);
    deduplicate_parsed_names(&mut result.parsed, existing_names);
    result
}

fn parse_nodes_input_inner(trimmed: &str) -> ParseNodesResult {
    // 1. Try YAML mapping / `proxies:` / sequence of mappings.
    if looks_like_yaml_nodes(trimmed) {
        match serde_yaml::from_str::<Value>(trimmed) {
            Ok(value) => {
                if let Some(yaml_result) = parse_yaml_nodes_value(value) {
                    return yaml_result;
                }
            }
            Err(err) => {
                return ParseNodesResult {
                    parsed: Vec::new(),
                    errors: vec![ParseItemError {
                        index: 1,
                        source: truncate_source(trimmed),
                        reason: format!("YAML 语法错误：{err}"),
                    }],
                };
            }
        }
    }

    // 2. Try Base64 subscription/list payload if there is no explicit URI scheme.
    if !trimmed.contains("://") {
        if let Some(decoded) = try_decode_base64_text(trimmed) {
            let decoded_trimmed = decoded.trim();
            if decoded_trimmed.contains("://") || looks_like_yaml_nodes(decoded_trimmed) {
                return parse_nodes_input_inner(decoded_trimmed);
            }
        }
    }

    // 3. Parse line-by-line URIs.
    let mut parsed = Vec::new();
    let mut errors = Vec::new();
    let mut item_index = 0usize;

    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        item_index += 1;
        match parse_single_uri(line) {
            Ok(node) => parsed.push(node),
            Err(reason) => errors.push(ParseItemError {
                index: item_index,
                source: truncate_source(line),
                reason,
            }),
        }
    }

    if parsed.is_empty() && errors.is_empty() {
        errors.push(ParseItemError {
            index: 1,
            source: truncate_source(trimmed),
            reason: "未识别到有效的节点内容".to_string(),
        });
    }

    ParseNodesResult { parsed, errors }
}

fn looks_like_yaml_nodes(trimmed: &str) -> bool {
    if trimmed.starts_with("proxies:")
        || trimmed.contains("\nproxies:")
        || trimmed.starts_with("- name:")
        || trimmed.starts_with("- type:")
        || trimmed.starts_with("- {")
    {
        return true;
    }
    if !trimmed.contains("://") && trimmed.contains("type:") && trimmed.contains("server:") {
        return true;
    }
    false
}

fn parse_yaml_nodes_value(value: Value) -> Option<ParseNodesResult> {
    let items: Vec<Value> = match value {
        Value::Mapping(map) => {
            if let Some(Value::Sequence(seq)) = map.get(Value::String("proxies".to_string())) {
                seq.clone()
            } else if map.contains_key(Value::String("type".to_string()))
                || map.contains_key(Value::String("server".to_string()))
            {
                vec![Value::Mapping(map)]
            } else {
                return None;
            }
        }
        Value::Sequence(seq) => seq,
        _ => return None,
    };

    let mut parsed = Vec::new();
    let mut errors = Vec::new();
    for (idx, item) in items.into_iter().enumerate() {
        let index = idx + 1;
        match item {
            Value::Mapping(map) => {
                let source_label = map_str(&map, "name")
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("YAML 节点 #{index}"));
                match finalize_proxy_mapping(map, String::new()) {
                    Ok(node) => parsed.push(node),
                    Err(reason) => errors.push(ParseItemError {
                        index,
                        source: source_label,
                        reason,
                    }),
                }
            }
            _ => errors.push(ParseItemError {
                index,
                source: format!("YAML 节点 #{index}"),
                reason: "节点项必须是键值映射对象".to_string(),
            }),
        }
    }

    Some(ParseNodesResult { parsed, errors })
}

fn deduplicate_parsed_names(parsed: &mut [ParsedCustomNode], existing_names: &[String]) {
    let mut used: HashSet<String> = existing_names.iter().cloned().collect();
    for node in parsed.iter_mut() {
        let base = node.name.clone();
        let unique = make_unique_name(&base, &used);
        used.insert(unique.clone());
        if unique != node.name {
            node.name = unique.clone();
            if let Ok(Value::Mapping(mut map)) = serde_yaml::from_str::<Value>(&node.raw_yaml) {
                set_str(&mut map, "name", &unique);
                if let Ok(serialized) = serde_yaml::to_string(&Value::Mapping(map)) {
                    node.raw_yaml = serialized.trim().to_string();
                }
            }
        }
    }
}

fn make_unique_name(base: &str, used: &HashSet<String>) -> String {
    if !used.contains(base) {
        return base.to_string();
    }
    let mut counter = 2usize;
    loop {
        let candidate = format!("{base} ({counter})");
        if !used.contains(&candidate) {
            return candidate;
        }
        counter += 1;
    }
}

fn parse_single_uri(uri: &str) -> Result<ParsedCustomNode, String> {
    let (scheme, rest) = uri
        .split_once("://")
        .ok_or_else(|| "缺少协议头（如 vless://、anytls://、socks5://）".to_string())?;
    let scheme = scheme.trim().to_ascii_lowercase();
    match scheme.as_str() {
        "vless" => parse_vless(rest),
        "vmess" => parse_vmess(rest),
        "trojan" => parse_trojan(rest),
        "ss" => parse_ss(rest),
        "hysteria2" | "hy2" => parse_hysteria2(rest),
        "tuic" => parse_tuic(rest),
        "anytls" => parse_anytls(rest),
        "socks5" | "socks" => parse_socks5(rest),
        "http" => parse_http(rest, false),
        "https" => parse_http(rest, true),
        other => Err(format!("暂不支持的节点协议：{other}://")),
    }
}

struct UriParts {
    userinfo: Option<String>,
    host: String,
    port: u16,
    query: BTreeMap<String, String>,
    fragment: Option<String>,
}

fn split_standard_uri(rest: &str, default_port: Option<u16>) -> Result<UriParts, String> {
    let (before_frag, fragment) = match rest.split_once('#') {
        Some((left, frag)) => (left, Some(percent_decode(frag))),
        None => (rest, None),
    };
    let (authority_and_path, query_str) = match before_frag.split_once('?') {
        Some((left, q)) => (left, Some(q)),
        None => (before_frag, None),
    };
    let authority = authority_and_path
        .split_once('/')
        .map(|(auth, _)| auth)
        .unwrap_or(authority_and_path);

    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, hp)) => (Some(u.to_string()), hp),
        None => (None, authority),
    };

    let (host, port) = parse_host_port(hostport, default_port)?;
    let query = query_str.map(parse_query_params).unwrap_or_default();

    Ok(UriParts {
        userinfo,
        host,
        port,
        query,
        fragment,
    })
}

fn parse_host_port(hostport: &str, default_port: Option<u16>) -> Result<(String, u16), String> {
    let hostport = hostport.trim();
    if hostport.is_empty() {
        return Err("缺少服务器地址".to_string());
    }
    if let Some(stripped) = hostport.strip_prefix('[') {
        let (host, after) = stripped
            .split_once(']')
            .ok_or_else(|| "IPv6 地址缺少右括号".to_string())?;
        let port = if let Some(port_str) = after.strip_prefix(':') {
            parse_port(port_str)?
        } else if let Some(dp) = default_port {
            dp
        } else {
            return Err("缺少端口号".to_string());
        };
        if host.trim().is_empty() {
            return Err("服务器地址不能为空".to_string());
        }
        return Ok((host.trim().to_string(), port));
    }

    match hostport.rsplit_once(':') {
        Some((host, port_str)) if !host.contains(':') => {
            let host = host.trim();
            if host.is_empty() {
                return Err("服务器地址不能为空".to_string());
            }
            let port = parse_port(port_str)?;
            Ok((host.to_string(), port))
        }
        _ => {
            if let Some(dp) = default_port {
                Ok((hostport.to_string(), dp))
            } else {
                Err("缺少端口号或格式错误".to_string())
            }
        }
    }
}

fn parse_port(raw: &str) -> Result<u16, String> {
    let port: u16 = raw
        .trim()
        .parse()
        .map_err(|_| format!("端口号无效：{raw}"))?;
    if port == 0 {
        return Err("端口号不能为 0".to_string());
    }
    Ok(port)
}

fn parse_query_params(query: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        };
        if !key.is_empty() {
            map.insert(key, value);
        }
    }
    map
}

fn query_get<'a>(query: &'a BTreeMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    for key in keys {
        if let Some(val) = query.get(*key) {
            if !val.trim().is_empty() {
                return Some(val.trim());
            }
        }
    }
    None
}

fn query_bool(query: &BTreeMap<String, String>, keys: &[&str]) -> Option<bool> {
    query_get(query, keys).and_then(|v| match v.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Some(true),
        "0" | "false" | "no" => Some(false),
        _ => None,
    })
}

fn parse_alpn_list(raw: &str) -> Vec<Value> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| Value::String(s.to_string()))
        .collect()
}

fn default_node_name(fragment: Option<String>, host: &str, port: u16) -> String {
    fragment
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{host}:{port}"))
}

fn parse_vless(rest: &str) -> Result<ParsedCustomNode, String> {
    let parts = split_standard_uri(rest, None)?;
    let uuid = parts
        .userinfo
        .map(|u| percent_decode(&u))
        .filter(|u| !u.is_empty())
        .ok_or_else(|| "VLESS 链接缺少 UUID".to_string())?;
    let name = default_node_name(parts.fragment, &parts.host, parts.port);

    let mut map = Mapping::new();
    set_str(&mut map, "name", &name);
    set_str(&mut map, "type", "vless");
    set_str(&mut map, "server", &parts.host);
    set_u64(&mut map, "port", u64::from(parts.port));
    set_str(&mut map, "uuid", &uuid);
    set_bool(&mut map, "udp", query_bool(&parts.query, &["udp"]).unwrap_or(true));

    if let Some(flow) = query_get(&parts.query, &["flow"]) {
        set_str(&mut map, "flow", flow);
    }

    let security = query_get(&parts.query, &["security"])
        .unwrap_or("")
        .to_ascii_lowercase();
    if security == "tls" || security == "reality" {
        set_bool(&mut map, "tls", true);
    }
    if let Some(sni) = query_get(&parts.query, &["sni", "servername"]) {
        set_str(&mut map, "servername", sni);
    }
    if let Some(fp) = query_get(&parts.query, &["fp", "client-fingerprint"]) {
        set_str(&mut map, "client-fingerprint", fp);
    }
    if query_bool(&parts.query, &["allowInsecure", "insecure", "skip-cert-verify"]) == Some(true) {
        set_bool(&mut map, "skip-cert-verify", true);
    }
    if let Some(alpn) = query_get(&parts.query, &["alpn"]) {
        let list = parse_alpn_list(alpn);
        if !list.is_empty() {
            map.insert(Value::String("alpn".to_string()), Value::Sequence(list));
        }
    }
    if security == "reality" {
        let mut reality = Mapping::new();
        if let Some(pbk) = query_get(&parts.query, &["pbk", "public-key"]) {
            set_str(&mut reality, "public-key", pbk);
        }
        if let Some(sid) = query_get(&parts.query, &["sid", "short-id"]) {
            set_str(&mut reality, "short-id", sid);
        }
        if !reality.is_empty() {
            map.insert(
                Value::String("reality-opts".to_string()),
                Value::Mapping(reality),
            );
        }
    }

    apply_transport_opts(&mut map, &parts.query);
    finalize_proxy_mapping(map, String::new())
}

fn parse_vmess(rest: &str) -> Result<ParsedCustomNode, String> {
    let encoded = rest.trim();
    let decoded = try_decode_base64_text(encoded)
        .ok_or_else(|| "VMess 链接 Base64 解码失败".to_string())?;
    let json: serde_json::Value = serde_json::from_str(decoded.trim())
        .map_err(|_| "VMess 链接 JSON 解析失败".to_string())?;
    let obj = json
        .as_object()
        .ok_or_else(|| "VMess 链接内容必须是 JSON 对象".to_string())?;

    let server = json_str(obj, "add").ok_or_else(|| "VMess 缺少服务器地址 (add)".to_string())?;
    let port = json_u16(obj, "port").ok_or_else(|| "VMess 缺少有效端口 (port)".to_string())?;
    let uuid = json_str(obj, "id").ok_or_else(|| "VMess 缺少 UUID (id)".to_string())?;
    let name = json_str(obj, "ps")
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{server}:{port}"));
    let alter_id = json_u64(obj, "aid").unwrap_or(0);
    let cipher = json_str(obj, "scy")
        .or_else(|| json_str(obj, "cipher"))
        .unwrap_or("auto");

    let mut map = Mapping::new();
    set_str(&mut map, "name", &name);
    set_str(&mut map, "type", "vmess");
    set_str(&mut map, "server", server);
    set_u64(&mut map, "port", u64::from(port));
    set_str(&mut map, "uuid", uuid);
    set_u64(&mut map, "alterId", alter_id);
    set_str(&mut map, "cipher", cipher);
    set_bool(&mut map, "udp", true);

    let tls_enabled = matches!(
        json_str(obj, "tls").map(|s| s.to_ascii_lowercase()).as_deref(),
        Some("tls" | "1" | "true")
    );
    if tls_enabled {
        set_bool(&mut map, "tls", true);
        if let Some(sni) = json_str(obj, "sni").or_else(|| json_str(obj, "host")) {
            set_str(&mut map, "servername", sni);
        }
    }
    if let Some(fp) = json_str(obj, "fp") {
        set_str(&mut map, "client-fingerprint", fp);
    }
    if let Some(alpn) = json_str(obj, "alpn") {
        let list = parse_alpn_list(alpn);
        if !list.is_empty() {
            map.insert(Value::String("alpn".to_string()), Value::Sequence(list));
        }
    }
    if matches!(
        json_str(obj, "allowInsecure")
            .or_else(|| json_str(obj, "skip-cert-verify"))
            .map(|s| s.to_ascii_lowercase())
            .as_deref(),
        Some("1" | "true")
    ) {
        set_bool(&mut map, "skip-cert-verify", true);
    }

    let mut query = BTreeMap::new();
    if let Some(net) = json_str(obj, "net") {
        query.insert("type".to_string(), net.to_string());
    }
    if let Some(host) = json_str(obj, "host") {
        query.insert("host".to_string(), host.to_string());
    }
    if let Some(path) = json_str(obj, "path") {
        query.insert("path".to_string(), path.to_string());
        query.insert("serviceName".to_string(), path.to_string());
    }
    apply_transport_opts(&mut map, &query);

    finalize_proxy_mapping(map, String::new())
}

fn parse_trojan(rest: &str) -> Result<ParsedCustomNode, String> {
    let parts = split_standard_uri(rest, Some(443))?;
    let password = parts
        .userinfo
        .map(|u| percent_decode(&u))
        .filter(|u| !u.is_empty())
        .ok_or_else(|| "Trojan 链接缺少密码".to_string())?;
    let name = default_node_name(parts.fragment, &parts.host, parts.port);

    let mut map = Mapping::new();
    set_str(&mut map, "name", &name);
    set_str(&mut map, "type", "trojan");
    set_str(&mut map, "server", &parts.host);
    set_u64(&mut map, "port", u64::from(parts.port));
    set_str(&mut map, "password", &password);
    set_bool(&mut map, "udp", query_bool(&parts.query, &["udp"]).unwrap_or(true));

    if let Some(sni) = query_get(&parts.query, &["sni", "peer", "servername"]) {
        set_str(&mut map, "sni", sni);
    }
    if let Some(fp) = query_get(&parts.query, &["fp", "client-fingerprint"]) {
        set_str(&mut map, "client-fingerprint", fp);
    }
    if query_bool(&parts.query, &["allowInsecure", "insecure", "skip-cert-verify"]) == Some(true) {
        set_bool(&mut map, "skip-cert-verify", true);
    }
    if let Some(alpn) = query_get(&parts.query, &["alpn"]) {
        let list = parse_alpn_list(alpn);
        if !list.is_empty() {
            map.insert(Value::String("alpn".to_string()), Value::Sequence(list));
        }
    }

    apply_transport_opts(&mut map, &parts.query);
    finalize_proxy_mapping(map, String::new())
}

fn parse_ss(rest: &str) -> Result<ParsedCustomNode, String> {
    let (before_frag, fragment) = match rest.split_once('#') {
        Some((left, frag)) => (left, Some(percent_decode(frag))),
        None => (rest, None),
    };
    let (main_part, query_str) = match before_frag.split_once('?') {
        Some((left, q)) => (left, Some(q)),
        None => (before_frag, None),
    };
    let (method, password, host, port) = if let Some((userinfo, hostport_and_path)) =
        main_part.rsplit_once('@')
    {
        let hostport = hostport_and_path
            .split_once('/')
            .map(|(hp, _)| hp)
            .unwrap_or(hostport_and_path);
        let decoded_userinfo = if userinfo.contains(':') {
            percent_decode(userinfo)
        } else {
            try_decode_base64_text(userinfo)
                .ok_or_else(|| "Shadowsocks 凭据 Base64 解码失败".to_string())?
        };
        let (method, password) = decoded_userinfo
            .split_once(':')
            .ok_or_else(|| "Shadowsocks 缺少加密方式或密码".to_string())?;
        let (host, port) = parse_host_port(hostport, None)?;
        (method.to_string(), password.to_string(), host, port)
    } else {
        let decoded = try_decode_base64_text(main_part)
            .or_else(|| {
                let stripped = main_part.trim_end_matches('/');
                if stripped.len() < main_part.len() {
                    try_decode_base64_text(stripped)
                } else {
                    None
                }
            })
            .ok_or_else(|| "Shadowsocks 链接 Base64 解码失败".to_string())?;
        let (cred, hostport) = decoded
            .rsplit_once('@')
            .ok_or_else(|| "Shadowsocks 链接缺少服务器地址".to_string())?;
        let (method, password) = cred
            .split_once(':')
            .ok_or_else(|| "Shadowsocks 缺少加密方式或密码".to_string())?;
        let (host, port) = parse_host_port(hostport, None)?;
        (method.to_string(), password.to_string(), host, port)
    };

    if method.trim().is_empty() || password.is_empty() {
        return Err("Shadowsocks 加密方式或密码不能为空".to_string());
    }

    let name = default_node_name(fragment, &host, port);
    let mut map = Mapping::new();
    set_str(&mut map, "name", &name);
    set_str(&mut map, "type", "ss");
    set_str(&mut map, "server", &host);
    set_u64(&mut map, "port", u64::from(port));
    set_str(&mut map, "cipher", method.trim());
    set_str(&mut map, "password", &password);
    set_bool(&mut map, "udp", true);

    if let Some(q) = query_str {
        let query = parse_query_params(q);
        if let Some(plugin_raw) = query_get(&query, &["plugin"]) {
            let mut parts = plugin_raw.split(';');
            if let Some(plugin_name) = parts.next().map(str::trim).filter(|s| !s.is_empty()) {
                let normalized = match plugin_name {
                    "obfs-local" | "simple-obfs" => "obfs",
                    other => other,
                };
                set_str(&mut map, "plugin", normalized);
                let mut opts = Mapping::new();
                for kv in parts {
                    if let Some((k, v)) = kv.split_once('=') {
                        let key = match k.trim() {
                            "obfs" => "mode",
                            "obfs-host" => "host",
                            other => other,
                        };
                        set_str(&mut opts, key, v.trim());
                    }
                }
                if !opts.is_empty() {
                    map.insert(
                        Value::String("plugin-opts".to_string()),
                        Value::Mapping(opts),
                    );
                }
            }
        }
    }

    finalize_proxy_mapping(map, String::new())
}

fn parse_hysteria2(rest: &str) -> Result<ParsedCustomNode, String> {
    let parts = split_standard_uri(rest, Some(443))?;
    let password = parts
        .userinfo
        .map(|u| percent_decode(&u))
        .filter(|u| !u.is_empty())
        .ok_or_else(|| "Hysteria2 链接缺少密码".to_string())?;
    let name = default_node_name(parts.fragment, &parts.host, parts.port);

    let mut map = Mapping::new();
    set_str(&mut map, "name", &name);
    set_str(&mut map, "type", "hysteria2");
    set_str(&mut map, "server", &parts.host);
    set_u64(&mut map, "port", u64::from(parts.port));
    set_str(&mut map, "password", &password);

    if let Some(sni) = query_get(&parts.query, &["sni", "servername"]) {
        set_str(&mut map, "sni", sni);
    }
    if query_bool(&parts.query, &["insecure", "allowInsecure", "skip-cert-verify"]) == Some(true) {
        set_bool(&mut map, "skip-cert-verify", true);
    }
    if let Some(obfs) = query_get(&parts.query, &["obfs"]) {
        if obfs != "none" {
            set_str(&mut map, "obfs", obfs);
            if let Some(obfs_pw) = query_get(&parts.query, &["obfs-password"]) {
                set_str(&mut map, "obfs-password", obfs_pw);
            }
        }
    }
    if let Some(alpn) = query_get(&parts.query, &["alpn"]) {
        let list = parse_alpn_list(alpn);
        if !list.is_empty() {
            map.insert(Value::String("alpn".to_string()), Value::Sequence(list));
        }
    }
    if let Some(mport) = query_get(&parts.query, &["mport", "ports"]) {
        set_str(&mut map, "ports", mport);
    }
    if let Some(pin) = query_get(&parts.query, &["pinSHA256", "fingerprint"]) {
        set_str(&mut map, "fingerprint", pin);
    }
    if let Some(up) = query_get(&parts.query, &["up"]) {
        set_str(&mut map, "up", up);
    }
    if let Some(down) = query_get(&parts.query, &["down"]) {
        set_str(&mut map, "down", down);
    }

    finalize_proxy_mapping(map, String::new())
}

fn parse_tuic(rest: &str) -> Result<ParsedCustomNode, String> {
    let parts = split_standard_uri(rest, Some(443))?;
    let userinfo = parts
        .userinfo
        .ok_or_else(|| "TUIC 链接缺少 UUID 和密码".to_string())?;
    let (uuid, password) = userinfo
        .split_once(':')
        .ok_or_else(|| "TUIC 链接需包含 uuid:password".to_string())?;
    let uuid = percent_decode(uuid);
    let password = percent_decode(password);
    if uuid.is_empty() || password.is_empty() {
        return Err("TUIC 链接 UUID 或密码不能为空".to_string());
    }
    let name = default_node_name(parts.fragment, &parts.host, parts.port);

    let mut map = Mapping::new();
    set_str(&mut map, "name", &name);
    set_str(&mut map, "type", "tuic");
    set_str(&mut map, "server", &parts.host);
    set_u64(&mut map, "port", u64::from(parts.port));
    set_str(&mut map, "uuid", &uuid);
    set_str(&mut map, "password", &password);

    if let Some(sni) = query_get(&parts.query, &["sni", "servername"]) {
        set_str(&mut map, "sni", sni);
    }
    if let Some(cc) = query_get(&parts.query, &["congestion_control", "congestion-controller"]) {
        set_str(&mut map, "congestion-controller", cc);
    }
    if let Some(mode) = query_get(&parts.query, &["udp_relay_mode", "udp-relay-mode"]) {
        set_str(&mut map, "udp-relay-mode", mode);
    }
    if let Some(alpn) = query_get(&parts.query, &["alpn"]) {
        let list = parse_alpn_list(alpn);
        if !list.is_empty() {
            map.insert(Value::String("alpn".to_string()), Value::Sequence(list));
        }
    }
    if query_bool(&parts.query, &["disable_sni", "disable-sni"]) == Some(true) {
        set_bool(&mut map, "disable-sni", true);
    }
    if query_bool(&parts.query, &["reduce_rtt", "reduce-rtt"]) == Some(true) {
        set_bool(&mut map, "reduce-rtt", true);
    }
    if query_bool(&parts.query, &["allow_insecure", "allowInsecure", "insecure", "skip-cert-verify"])
        == Some(true)
    {
        set_bool(&mut map, "skip-cert-verify", true);
    }

    finalize_proxy_mapping(map, String::new())
}

fn parse_anytls(rest: &str) -> Result<ParsedCustomNode, String> {
    let parts = split_standard_uri(rest, Some(443))?;
    let password = parts
        .userinfo
        .map(|u| percent_decode(&u))
        .filter(|u| !u.is_empty())
        .ok_or_else(|| "AnyTLS 链接缺少密码".to_string())?;
    let name = default_node_name(parts.fragment, &parts.host, parts.port);

    let mut map = Mapping::new();
    set_str(&mut map, "name", &name);
    set_str(&mut map, "type", "anytls");
    set_str(&mut map, "server", &parts.host);
    set_u64(&mut map, "port", u64::from(parts.port));
    set_str(&mut map, "password", &password);
    set_bool(&mut map, "udp", query_bool(&parts.query, &["udp"]).unwrap_or(true));

    if let Some(sni) = query_get(&parts.query, &["sni", "servername"]) {
        set_str(&mut map, "sni", sni);
    }
    if let Some(fp) = query_get(&parts.query, &["fp", "client-fingerprint"]) {
        set_str(&mut map, "client-fingerprint", fp);
    }
    if query_bool(&parts.query, &["insecure", "allowInsecure", "skip-cert-verify"]) == Some(true) {
        set_bool(&mut map, "skip-cert-verify", true);
    }
    if let Some(alpn) = query_get(&parts.query, &["alpn"]) {
        let list = parse_alpn_list(alpn);
        if !list.is_empty() {
            map.insert(Value::String("alpn".to_string()), Value::Sequence(list));
        }
    }
    for key in [
        "idle-session-check-interval",
        "idle-session-timeout",
        "min-idle-session",
    ] {
        if let Some(raw_num) = query_get(&parts.query, &[key]) {
            if let Ok(num) = raw_num.parse::<u64>() {
                set_u64(&mut map, key, num);
            }
        }
    }

    finalize_proxy_mapping(map, String::new())
}

fn parse_socks5(rest: &str) -> Result<ParsedCustomNode, String> {
    let parts = split_standard_uri(rest, None)?;
    let name = default_node_name(parts.fragment, &parts.host, parts.port);

    let mut map = Mapping::new();
    set_str(&mut map, "name", &name);
    set_str(&mut map, "type", "socks5");
    set_str(&mut map, "server", &parts.host);
    set_u64(&mut map, "port", u64::from(parts.port));
    set_bool(&mut map, "udp", query_bool(&parts.query, &["udp"]).unwrap_or(true));

    if let Some(userinfo) = parts.userinfo {
        let (user, pass) = split_user_pass(&userinfo);
        if !user.is_empty() {
            set_str(&mut map, "username", &user);
        }
        if !pass.is_empty() {
            set_str(&mut map, "password", &pass);
        }
    }
    if query_bool(&parts.query, &["tls"]) == Some(true) {
        set_bool(&mut map, "tls", true);
    }
    if query_bool(&parts.query, &["insecure", "allowInsecure", "skip-cert-verify"]) == Some(true) {
        set_bool(&mut map, "skip-cert-verify", true);
    }

    finalize_proxy_mapping(map, String::new())
}

fn parse_http(rest: &str, is_https: bool) -> Result<ParsedCustomNode, String> {
    let default_port = if is_https { Some(443) } else { Some(80) };
    let parts = split_standard_uri(rest, default_port)?;
    let name = default_node_name(parts.fragment, &parts.host, parts.port);

    let mut map = Mapping::new();
    set_str(&mut map, "name", &name);
    set_str(&mut map, "type", "http");
    set_str(&mut map, "server", &parts.host);
    set_u64(&mut map, "port", u64::from(parts.port));

    if let Some(userinfo) = parts.userinfo {
        let (user, pass) = split_user_pass(&userinfo);
        if !user.is_empty() {
            set_str(&mut map, "username", &user);
        }
        if !pass.is_empty() {
            set_str(&mut map, "password", &pass);
        }
    }
    if is_https || query_bool(&parts.query, &["tls"]) == Some(true) {
        set_bool(&mut map, "tls", true);
    }
    if let Some(sni) = query_get(&parts.query, &["sni", "servername"]) {
        set_str(&mut map, "sni", sni);
    }
    if query_bool(&parts.query, &["insecure", "allowInsecure", "skip-cert-verify"]) == Some(true) {
        set_bool(&mut map, "skip-cert-verify", true);
    }

    finalize_proxy_mapping(map, String::new())
}

fn split_user_pass(userinfo: &str) -> (String, String) {
    if let Some((u, p)) = userinfo.split_once(':') {
        (percent_decode(u), percent_decode(p))
    } else if let Some(decoded) = try_decode_base64_text(userinfo) {
        if let Some((u, p)) = decoded.split_once(':') {
            return (u.to_string(), p.to_string());
        }
        (percent_decode(userinfo), String::new())
    } else {
        (percent_decode(userinfo), String::new())
    }
}

fn apply_transport_opts(map: &mut Mapping, query: &BTreeMap<String, String>) {
    let network = query_get(query, &["type", "net"])
        .unwrap_or("")
        .to_ascii_lowercase();
    match network.as_str() {
        "ws" => {
            set_str(map, "network", "ws");
            let mut ws = Mapping::new();
            if let Some(path) = query_get(query, &["path"]) {
                set_str(&mut ws, "path", path);
            }
            if let Some(host) = query_get(query, &["host"]) {
                let mut headers = Mapping::new();
                set_str(&mut headers, "Host", host);
                ws.insert(
                    Value::String("headers".to_string()),
                    Value::Mapping(headers),
                );
            }
            if !ws.is_empty() {
                map.insert(Value::String("ws-opts".to_string()), Value::Mapping(ws));
            }
        }
        "grpc" => {
            set_str(map, "network", "grpc");
            if let Some(service) = query_get(query, &["serviceName", "path"]) {
                let mut grpc = Mapping::new();
                set_str(&mut grpc, "grpc-service-name", service);
                map.insert(
                    Value::String("grpc-opts".to_string()),
                    Value::Mapping(grpc),
                );
            }
        }
        "h2" | "http" => {
            set_str(map, "network", "h2");
            let mut h2 = Mapping::new();
            if let Some(path) = query_get(query, &["path"]) {
                set_str(&mut h2, "path", path);
            }
            if let Some(host) = query_get(query, &["host"]) {
                h2.insert(
                    Value::String("host".to_string()),
                    Value::Sequence(vec![Value::String(host.to_string())]),
                );
            }
            if !h2.is_empty() {
                map.insert(Value::String("h2-opts".to_string()), Value::Mapping(h2));
            }
        }
        _ => {}
    }
}

fn finalize_proxy_mapping(mut map: Mapping, note: String) -> Result<ParsedCustomNode, String> {
    // Strip dialer-proxy so chaining is always managed cleanly by DialerTarget.
    map.remove(Value::String("dialer-proxy".to_string()));

    let protocol = map_str(&map, "type")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "节点缺少必填字段：type".to_string())?
        .to_string();
    let server = map_str(&map, "server")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "节点缺少必填字段：server".to_string())?
        .to_string();
    let port = map_u16(&map, "port")
        .ok_or_else(|| "节点缺少有效端口字段：port（需为 1~65535）".to_string())?;
    let name = map_str(&map, "name")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{server}:{port}"));

    set_str(&mut map, "name", &name);
    set_str(&mut map, "type", &protocol);
    set_str(&mut map, "server", &server);
    set_u64(&mut map, "port", u64::from(port));

    let raw_yaml = serde_yaml::to_string(&Value::Mapping(map))
        .map_err(|err| format!("节点序列化失败：{err}"))?
        .trim()
        .to_string();

    Ok(ParsedCustomNode {
        name,
        protocol,
        server,
        port,
        raw_yaml,
        note,
    })
}

// ============================================================================
// Dialer Graph Cycle & Reachability Validation
// ============================================================================

pub fn validate_dialer_cycles(nodes: &[CustomNode]) -> Result<(), String> {
    let cycles = detect_dialer_cycles(nodes);
    if let Some(cycle) = cycles.first() {
        return Err(format!("链式代理存在循环引用：{}", cycle.join(" -> ")));
    }
    Ok(())
}

fn detect_dialer_cycles(nodes: &[CustomNode]) -> Vec<Vec<String>> {
    let enabled_by_id: HashMap<&str, &CustomNode> = nodes
        .iter()
        .filter(|n| n.enabled)
        .map(|n| (n.id.as_str(), n))
        .collect();

    let mut state: HashMap<&str, u8> = HashMap::new(); // 0=unvisited, 1=visiting, 2=done
    let mut cycles = Vec::new();

    for node in nodes.iter().filter(|n| n.enabled) {
        let id = node.id.as_str();
        if state.get(id).copied().unwrap_or(0) != 0 {
            continue;
        }
        let mut path_ids: Vec<&str> = Vec::new();
        let mut curr = id;
        loop {
            match state.get(curr).copied().unwrap_or(0) {
                2 => break,
                1 => {
                    if let Some(pos) = path_ids.iter().position(|&p| p == curr) {
                        let mut cycle_names: Vec<String> = path_ids[pos..]
                            .iter()
                            .filter_map(|pid| enabled_by_id.get(pid).map(|n| n.name.clone()))
                            .collect();
                        if let Some(start_node) = enabled_by_id.get(curr) {
                            cycle_names.push(start_node.name.clone());
                        }
                        cycles.push(cycle_names);
                    }
                    break;
                }
                _ => {
                    state.insert(curr, 1);
                    path_ids.push(curr);
                    let next = enabled_by_id.get(curr).and_then(|n| match &n.dialer {
                        DialerTarget::CustomNode { id: target_id } => {
                            if enabled_by_id.contains_key(target_id.as_str()) {
                                Some(target_id.as_str())
                            } else {
                                None
                            }
                        }
                        _ => None,
                    });
                    match next {
                        Some(next_id) => curr = next_id,
                        None => break,
                    }
                }
            }
        }
        for visited in path_ids {
            state.insert(visited, 2);
        }
    }

    cycles
}

pub fn validate_dialer_graph(
    nodes: &[CustomNode],
    context: &DialerContext,
) -> DialerValidationReport {
    let cycles = detect_dialer_cycles(nodes);
    let (_, missing_dialers) = resolve_enabled_nodes_dialers(nodes, context);
    let valid = cycles.is_empty() && missing_dialers.is_empty();
    DialerValidationReport {
        cycles,
        missing_dialers,
        valid,
    }
}

/// Resolves enabled custom nodes against `context`.
/// Returns `(valid_node_ids_in_order, warnings)`.
/// Nodes with missing/unreachable dialers (and nodes transitively depending on them)
/// are excluded rather than silently degraded to direct.
fn resolve_enabled_nodes_dialers(
    nodes: &[CustomNode],
    context: &DialerContext,
) -> (Vec<String>, Vec<CustomNodeWarning>) {
    let enabled_by_id: HashMap<&str, &CustomNode> = nodes
        .iter()
        .filter(|n| n.enabled)
        .map(|n| (n.id.as_str(), n))
        .collect();
    let all_by_id: HashMap<&str, &CustomNode> =
        nodes.iter().map(|n| (n.id.as_str(), n)).collect();

    let mut invalid_reason: HashMap<String, String> = HashMap::new();

    // First pass: direct reachability checks.
    for node in nodes.iter().filter(|n| n.enabled) {
        match &node.dialer {
            DialerTarget::Direct => {}
            DialerTarget::ProfileGroup { group } => {
                if context.is_standalone {
                    invalid_reason.insert(
                        node.id.clone(),
                        format!(
                            "节点「{}」配置了通过订阅策略组中转，但当前为纯自建模式，已跳过（未降级为直连）",
                            node.name
                        ),
                    );
                } else if let Some(group_name) = group.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    if !context.available_targets.contains(group_name) {
                        invalid_reason.insert(
                            node.id.clone(),
                            format!(
                                "节点「{}」指定的订阅策略组「{}」不存在，已跳过（未降级为直连）",
                                node.name, group_name
                            ),
                        );
                    }
                } else if context.primary_group.is_none() {
                    invalid_reason.insert(
                        node.id.clone(),
                        format!(
                            "节点「{}」无法找到当前订阅的默认策略组，已跳过（未降级为直连）",
                            node.name
                        ),
                    );
                }
            }
            DialerTarget::FixedProxy { name } => {
                let target = name.trim();
                if target.is_empty()
                    || context.is_standalone
                    || !context.available_targets.contains(target)
                {
                    invalid_reason.insert(
                        node.id.clone(),
                        format!(
                            "节点「{}」指定的订阅中转节点「{}」不存在，已跳过（未降级为直连）",
                            node.name, target
                        ),
                    );
                }
            }
            DialerTarget::CustomNode { id: target_id } => {
                if target_id == &node.id {
                    invalid_reason.insert(
                        node.id.clone(),
                        format!("节点「{}」不能将自己设为中转节点", node.name),
                    );
                } else if !enabled_by_id.contains_key(target_id.as_str()) {
                    let target_label = all_by_id
                        .get(target_id.as_str())
                        .map(|n| format!("「{}」（已停用）", n.name))
                        .unwrap_or_else(|| format!("「{target_id}」（已删除）"));
                    invalid_reason.insert(
                        node.id.clone(),
                        format!(
                            "节点「{}」依赖的自建中转节点{}不可用，已跳过（未降级为直连）",
                            node.name, target_label
                        ),
                    );
                }
            }
        }
    }

    // Second pass: propagate transitive breakage along CustomNode chains.
    loop {
        let mut changed = false;
        for node in nodes.iter().filter(|n| n.enabled) {
            if invalid_reason.contains_key(&node.id) {
                continue;
            }
            if let DialerTarget::CustomNode { id: target_id } = &node.dialer {
                if invalid_reason.contains_key(target_id) {
                    let target_name = enabled_by_id
                        .get(target_id.as_str())
                        .map(|n| n.name.as_str())
                        .unwrap_or(target_id.as_str());
                    invalid_reason.insert(
                        node.id.clone(),
                        format!(
                            "节点「{}」依赖的上游中转节点「{}」不可用，已跳过（未降级为直连）",
                            node.name, target_name
                        ),
                    );
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }

    let mut valid_ids = Vec::new();
    let mut warnings = Vec::new();
    for node in nodes.iter().filter(|n| n.enabled) {
        if let Some(message) = invalid_reason.get(&node.id) {
            warnings.push(CustomNodeWarning {
                code: "missing_dialer".to_string(),
                node_id: Some(node.id.clone()),
                rule_id: None,
                message: message.clone(),
            });
        } else {
            valid_ids.push(node.id.clone());
        }
    }

    (valid_ids, warnings)
}

// ============================================================================
// Landing Rules Normalization & Compilation
// ============================================================================

pub fn normalize_domain_pattern(raw: &str) -> Result<(bool, String), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("域名不能为空".to_string());
    }
    let (is_exact, rest) = if let Some(stripped) = trimmed.strip_prefix('=') {
        (true, stripped.trim())
    } else {
        (false, trimmed)
    };

    let rest = strip_scheme_prefix(rest);
    let rest = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim();
    let rest = match rest.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => rest,
    };

    let cleaned = if is_exact {
        rest.trim_start_matches('.').to_ascii_lowercase()
    } else {
        rest.trim_start_matches("*.")
            .trim_start_matches('.')
            .to_ascii_lowercase()
    };

    if cleaned.is_empty() || !cleaned.contains('.') || cleaned.len() > 253 {
        return Err(format!("域名格式无效：「{raw}」，请输入如 openai.com 或 .example.com"));
    }

    for label in cleaned.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(format!(
                "域名格式无效：「{raw}」，仅支持字母、数字、连字符和点号"
            ));
        }
    }

    Ok((is_exact, cleaned))
}

fn strip_scheme_prefix(s: &str) -> &str {
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("https://") {
        &s[8..]
    } else if lower.starts_with("http://") {
        &s[7..]
    } else {
        s
    }
}

fn compile_landing_rules(
    rules: &[LandingRule],
    default_group: &str,
    node_name_map: &HashMap<String, String>,
) -> (Vec<String>, Vec<CustomNodeWarning>) {
    let mut compiled = Vec::new();
    let mut seen = HashSet::new();
    let mut warnings = Vec::new();

    for rule in rules.iter().filter(|r| r.enabled) {
        let target = match &rule.target {
            LandingRuleTarget::CustomGroup => default_group.to_string(),
            LandingRuleTarget::CustomNode { id } => match node_name_map.get(id) {
                Some(name) => name.clone(),
                None => {
                    warnings.push(CustomNodeWarning {
                        code: "missing_rule_target".to_string(),
                        node_id: Some(id.clone()),
                        rule_id: Some(rule.id.clone()),
                        message: format!("分流规则目标节点「{id}」已停用、删除或不可用，规则已跳过"),
                    });
                    continue;
                }
            },
        };

        match &rule.rule {
            LandingRuleKind::Preset { id } => match find_preset(id) {
                Some(preset) => {
                    for domain in preset.domains {
                        let line = format!("DOMAIN-SUFFIX,{domain},{target}");
                        if seen.insert(line.clone()) {
                            compiled.push(line);
                        }
                    }
                }
                None => {
                    warnings.push(CustomNodeWarning {
                        code: "unknown_preset".to_string(),
                        node_id: None,
                        rule_id: Some(rule.id.clone()),
                        message: format!("未知的分流预设「{id}」，已跳过"),
                    });
                }
            },
            LandingRuleKind::Domain { pattern } => match normalize_domain_pattern(pattern) {
                Ok((is_exact, domain)) => {
                    let rule_type = if is_exact { "DOMAIN" } else { "DOMAIN-SUFFIX" };
                    let line = format!("{rule_type},{domain},{target}");
                    if seen.insert(line.clone()) {
                        compiled.push(line);
                    }
                }
                Err(reason) => {
                    warnings.push(CustomNodeWarning {
                        code: "invalid_domain".to_string(),
                        node_id: None,
                        rule_id: Some(rule.id.clone()),
                        message: reason,
                    });
                }
            },
        }
    }

    (compiled, warnings)
}

fn is_leading_private_rule(rule: &str) -> bool {
    let upper = rule.trim().to_ascii_uppercase();
    if !upper.contains(",DIRECT") {
        return false;
    }
    upper.starts_with("GEOIP,PRIVATE,")
        || upper.starts_with("GEOSITE,PRIVATE,")
        || upper.starts_with("RULE-SET,PRIVATE,")
        || upper.starts_with("RULE-SET,LAN,")
        || upper.starts_with("DOMAIN-SUFFIX,LOCAL,")
        || upper.starts_with("DOMAIN-SUFFIX,LAN,")
        || upper.starts_with("DOMAIN,LOCALHOST,")
        || upper.starts_with("IP-CIDR,127.0.0.0/")
        || upper.starts_with("IP-CIDR,10.0.0.0/")
        || upper.starts_with("IP-CIDR,172.16.0.0/")
        || upper.starts_with("IP-CIDR,192.168.0.0/")
        || upper.starts_with("IP-CIDR6,FC00::/")
        || upper.starts_with("IP-CIDR6,FE80::/")
}

// ============================================================================
// Subscription Overlay Injection (R4, R3, R6)
// ============================================================================

pub fn inject_overlay(base_yaml: &str, state: &CustomNodesState) -> Result<OverlayResult, String> {
    // Strict no-op when overlay is disabled or no custom nodes are enabled.
    if !state.overlay_enabled || !state.has_enabled_nodes() {
        return Ok(OverlayResult {
            yaml: base_yaml.to_string(),
            warnings: Vec::new(),
            injected_count: 0,
            injected_rule_count: 0,
        });
    }

    validate_dialer_cycles(&state.nodes)?;

    let mut root: Value = serde_yaml::from_str(base_yaml)
        .map_err(|err| format!("订阅配置 YAML 解析失败：{err}"))?;
    let root_map = root
        .as_mapping_mut()
        .ok_or_else(|| "订阅配置根节点必须是 YAML 映射对象".to_string())?;

    let (existing_names, primary_group) = inspect_subscription_targets(root_map);
    let context = DialerContext {
        primary_group: primary_group.clone(),
        available_targets: existing_names.clone(),
        is_standalone: false,
    };

    let (valid_ids, mut warnings) = resolve_enabled_nodes_dialers(&state.nodes, &context);
    if valid_ids.is_empty() {
        return Ok(OverlayResult {
            yaml: base_yaml.to_string(),
            warnings,
            injected_count: 0,
            injected_rule_count: 0,
        });
    }

    let valid_set: HashSet<&str> = valid_ids.iter().map(String::as_str).collect();
    let mut reserved_names = existing_names;
    for builtin in ["DIRECT", "REJECT", "COMPATIBLE", "PASS"] {
        reserved_names.insert(builtin.to_string());
    }

    // Assign collision-free final names for all valid custom nodes.
    let mut node_name_map: HashMap<String, String> = HashMap::new();
    let mut ordered_valid_nodes: Vec<&CustomNode> = Vec::new();
    for node in &state.nodes {
        if !valid_set.contains(node.id.as_str()) {
            continue;
        }
        let final_name = resolve_collision_name(&node.name, &reserved_names);
        reserved_names.insert(final_name.clone());
        node_name_map.insert(node.id.clone(), final_name);
        ordered_valid_nodes.push(node);
    }

    let landing_group_name = resolve_collision_name(LANDING_GROUP_NAME, &reserved_names);
    reserved_names.insert(landing_group_name.clone());

    // If any custom node uses the subscription's primary group as its dialer-proxy,
    // synthesize a dedicated cycle-free `链式前置` select group cloned from the
    // primary group's original members (excluding `自建落地`) so selecting `自建落地`
    // inside the primary group never forms a Mihomo runtime dialer-proxy loop.
    let needs_relay_group = primary_group.as_deref().is_some_and(|primary| {
        ordered_valid_nodes.iter().any(|node| match &node.dialer {
            DialerTarget::ProfileGroup { group: None } => true,
            DialerTarget::ProfileGroup { group: Some(g) } => g.trim() == primary,
            DialerTarget::FixedProxy { name } => name.trim() == primary,
            _ => false,
        })
    });
    let relay_group_name = if needs_relay_group {
        let name = resolve_collision_name(CHAIN_RELAY_GROUP_NAME, &reserved_names);
        reserved_names.insert(name.clone());
        Some(name)
    } else {
        None
    };

    // Compile custom node mappings with resolved dialer-proxy.
    let mut compiled_proxies: Vec<Value> = Vec::new();
    let mut compiled_names: Vec<String> = Vec::new();
    for node in ordered_valid_nodes {
        let final_name = node_name_map[&node.id].clone();
        let proxy_val = compile_custom_node_value(
            node,
            &final_name,
            primary_group.as_deref(),
            relay_group_name.as_deref(),
            &node_name_map,
        )?;
        compiled_proxies.push(proxy_val);
        compiled_names.push(final_name);
    }

    // Inject into `proxies`.
    let proxies_key = Value::String("proxies".to_string());
    let proxies_entry = root_map
        .entry(proxies_key)
        .or_insert_with(|| Value::Sequence(Vec::new()));
    if !proxies_entry.is_sequence() {
        *proxies_entry = Value::Sequence(Vec::new());
    }
    if let Some(seq) = proxies_entry.as_sequence_mut() {
        seq.extend(compiled_proxies);
    }

    // Inject landing `select` group (and optional cycle-free relay group) and expose
    // landing group in the primary select group.
    let mut landing_group = Mapping::new();
    set_str(&mut landing_group, "name", &landing_group_name);
    set_str(&mut landing_group, "type", "select");
    landing_group.insert(
        Value::String("proxies".to_string()),
        Value::Sequence(
            compiled_names
                .iter()
                .map(|n| Value::String(n.clone()))
                .collect(),
        ),
    );

    let groups_key = Value::String("proxy-groups".to_string());
    let groups_entry = root_map
        .entry(groups_key)
        .or_insert_with(|| Value::Sequence(Vec::new()));
    if !groups_entry.is_sequence() {
        *groups_entry = Value::Sequence(Vec::new());
    }
    if let Some(groups_seq) = groups_entry.as_sequence_mut() {
        let mut relay_group: Option<Mapping> = None;
        if let Some(ref primary) = primary_group {
            for group_val in groups_seq.iter_mut() {
                if let Some(gmap) = group_val.as_mapping_mut() {
                    if map_str(gmap, "name") == Some(primary.as_str()) {
                        if let Some(ref relay_name) = relay_group_name {
                            relay_group =
                                Some(build_chain_relay_group(gmap, relay_name, &landing_group_name));
                        }
                        let members_entry = gmap
                            .entry(Value::String("proxies".to_string()))
                            .or_insert_with(|| Value::Sequence(Vec::new()));
                        if let Some(members) = members_entry.as_sequence_mut() {
                            let already = members
                                .iter()
                                .any(|v| v.as_str() == Some(landing_group_name.as_str()));
                            if !already {
                                members.push(Value::String(landing_group_name.clone()));
                            }
                        }
                        break;
                    }
                }
            }
        }
        groups_seq.push(Value::Mapping(landing_group));
        if let Some(relay) = relay_group {
            groups_seq.push(Value::Mapping(relay));
        }
    }

    // Insert lightweight landing rules right after leading private/LAN rules.
    let mut injected_rule_count = 0usize;
    if state.rules_enabled && !state.rules.is_empty() {
        let (compiled_rules, rule_warnings) =
            compile_landing_rules(&state.rules, &landing_group_name, &node_name_map);
        warnings.extend(rule_warnings);
        if !compiled_rules.is_empty() {
            let rules_key = Value::String("rules".to_string());
            let rules_entry = root_map
                .entry(rules_key)
                .or_insert_with(|| Value::Sequence(Vec::new()));
            if !rules_entry.is_sequence() {
                *rules_entry = Value::Sequence(Vec::new());
            }
            if let Some(rules_seq) = rules_entry.as_sequence_mut() {
                let existing_rule_set: HashSet<String> = rules_seq
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect();
                let insert_pos = rules_seq
                    .iter()
                    .take_while(|v| v.as_str().map(is_leading_private_rule).unwrap_or(false))
                    .count();
                let new_rules: Vec<Value> = compiled_rules
                    .into_iter()
                    .filter(|r| !existing_rule_set.contains(r))
                    .map(Value::String)
                    .collect();
                injected_rule_count = new_rules.len();
                rules_seq.splice(insert_pos..insert_pos, new_rules);
            }
        }
    }

    let yaml = serde_yaml::to_string(&root)
        .map_err(|err| format!("叠加自建节点后序列化配置失败：{err}"))?;

    Ok(OverlayResult {
        yaml,
        warnings,
        injected_count: compiled_names.len(),
        injected_rule_count,
    })
}

fn inspect_subscription_targets(root_map: &Mapping) -> (HashSet<String>, Option<String>) {
    let mut names = HashSet::new();
    if let Some(Value::Sequence(proxies)) = root_map.get(Value::String("proxies".to_string())) {
        for item in proxies {
            if let Some(name) = item.as_mapping().and_then(|m| map_str(m, "name")) {
                names.insert(name.to_string());
            }
        }
    }

    let mut first_visible_select: Option<String> = None;
    let mut first_select: Option<String> = None;
    let mut first_any: Option<String> = None;

    if let Some(Value::Sequence(groups)) = root_map.get(Value::String("proxy-groups".to_string())) {
        for item in groups {
            let Some(gmap) = item.as_mapping() else {
                continue;
            };
            let Some(name) = map_str(gmap, "name") else {
                continue;
            };
            names.insert(name.to_string());
            if name.eq_ignore_ascii_case("GLOBAL") {
                continue;
            }
            if first_any.is_none() {
                first_any = Some(name.to_string());
            }
            let gtype = map_str(gmap, "type").unwrap_or("");
            let hidden = map_bool(gmap, "hidden").unwrap_or(false);
            if gtype.eq_ignore_ascii_case("select") {
                if first_select.is_none() {
                    first_select = Some(name.to_string());
                }
                if !hidden && first_visible_select.is_none() {
                    first_visible_select = Some(name.to_string());
                }
            }
        }
    }

    let primary = first_visible_select.or(first_select).or(first_any);
    (names, primary)
}

fn resolve_collision_name(base: &str, reserved: &HashSet<String>) -> String {
    if !reserved.contains(base) {
        return base.to_string();
    }
    let suffixed = format!("{base}{COLLISION_SUFFIX}");
    if !reserved.contains(&suffixed) {
        return suffixed;
    }
    let mut counter = 2usize;
    loop {
        let candidate = format!("{base}{COLLISION_SUFFIX} ({counter})");
        if !reserved.contains(&candidate) {
            return candidate;
        }
        counter += 1;
    }
}

fn build_chain_relay_group(
    primary_map: &Mapping,
    relay_name: &str,
    landing_group_name: &str,
) -> Mapping {
    let mut relay = Mapping::new();
    set_str(&mut relay, "name", relay_name);
    set_str(&mut relay, "type", "select");

    if let Some(Value::Sequence(members)) = primary_map.get(Value::String("proxies".to_string())) {
        let filtered: Vec<Value> = members
            .iter()
            .filter(|v| v.as_str() != Some(landing_group_name))
            .cloned()
            .collect();
        if !filtered.is_empty() {
            relay.insert(
                Value::String("proxies".to_string()),
                Value::Sequence(filtered),
            );
        }
    }

    for key in [
        "use",
        "include-all",
        "include-all-proxies",
        "include-all-providers",
        "filter",
        "exclude-filter",
        "exclude-type",
        "icon",
    ] {
        let k = Value::String(key.to_string());
        if let Some(val) = primary_map.get(&k) {
            relay.insert(k, val.clone());
        }
    }

    relay
}

fn compile_custom_node_value(
    node: &CustomNode,
    final_name: &str,
    primary_group: Option<&str>,
    relay_group: Option<&str>,
    node_name_map: &HashMap<String, String>,
) -> Result<Value, String> {
    let value: Value = serde_yaml::from_str(&node.raw_yaml)
        .map_err(|err| format!("自建节点「{}」配置无效：{err}", node.name))?;
    let mut map = value
        .as_mapping()
        .cloned()
        .ok_or_else(|| format!("自建节点「{}」配置格式错误", node.name))?;
    set_str(&mut map, "name", final_name);
    map.remove(Value::String("dialer-proxy".to_string()));

    match &node.dialer {
        DialerTarget::Direct => {}
        DialerTarget::ProfileGroup { group } => {
            let resolved = group
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .or(primary_group)
                .ok_or_else(|| format!("节点「{}」无法解析订阅策略组", node.name))?;
            let target = if primary_group == Some(resolved) {
                relay_group.unwrap_or(resolved)
            } else {
                resolved
            };
            set_str(&mut map, "dialer-proxy", target);
        }
        DialerTarget::FixedProxy { name } => {
            let resolved = name.trim();
            let target = if primary_group == Some(resolved) {
                relay_group.unwrap_or(resolved)
            } else {
                resolved
            };
            set_str(&mut map, "dialer-proxy", target);
        }
        DialerTarget::CustomNode { id } => {
            let target = node_name_map
                .get(id)
                .ok_or_else(|| format!("节点「{}」的中转节点「{id}」不可用", node.name))?;
            set_str(&mut map, "dialer-proxy", target);
        }
    }

    Ok(Value::Mapping(map))
}

// ============================================================================
// Standalone Zero-YAML Generator (R5)
// ============================================================================

pub fn generate_standalone_yaml(state: &CustomNodesState) -> Result<StandaloneResult, String> {
    if !state.has_enabled_nodes() {
        return Err("还没有启用的自建节点，请先导入或启用至少一个节点".to_string());
    }

    validate_dialer_cycles(&state.nodes)?;

    let context = DialerContext {
        primary_group: None,
        available_targets: HashSet::new(),
        is_standalone: true,
    };

    let (valid_ids, mut warnings) = resolve_enabled_nodes_dialers(&state.nodes, &context);
    if valid_ids.is_empty() {
        let detail = warnings
            .first()
            .map(|w| w.message.clone())
            .unwrap_or_else(|| "所有已启用节点的中转配置均不可用".to_string());
        return Err(format!("无法生成纯自建配置：{detail}"));
    }

    let valid_set: HashSet<&str> = valid_ids.iter().map(String::as_str).collect();
    let mut reserved: HashSet<String> = [
        "DIRECT",
        "REJECT",
        "COMPATIBLE",
        "PASS",
        STANDALONE_SELECT_GROUP,
        STANDALONE_AUTO_GROUP,
    ]
    .into_iter()
    .map(str::to_string)
    .collect();

    let mut node_name_map: HashMap<String, String> = HashMap::new();
    let mut ordered_nodes: Vec<&CustomNode> = Vec::new();
    for node in &state.nodes {
        if !valid_set.contains(node.id.as_str()) {
            continue;
        }
        let final_name = make_unique_name(&node.name, &reserved);
        reserved.insert(final_name.clone());
        node_name_map.insert(node.id.clone(), final_name);
        ordered_nodes.push(node);
    }

    let mut proxies_seq = Vec::new();
    let mut proxy_names = Vec::new();
    for node in ordered_nodes {
        let final_name = node_name_map[&node.id].clone();
        let val = compile_custom_node_value(node, &final_name, None, None, &node_name_map)?;
        proxies_seq.push(val);
        proxy_names.push(final_name);
    }

    let mut select_members = vec![Value::String(STANDALONE_AUTO_GROUP.to_string())];
    select_members.extend(proxy_names.iter().map(|n| Value::String(n.clone())));
    select_members.push(Value::String("DIRECT".to_string()));

    let mut select_group = Mapping::new();
    set_str(&mut select_group, "name", STANDALONE_SELECT_GROUP);
    set_str(&mut select_group, "type", "select");
    select_group.insert(
        Value::String("proxies".to_string()),
        Value::Sequence(select_members),
    );

    let mut auto_group = Mapping::new();
    set_str(&mut auto_group, "name", STANDALONE_AUTO_GROUP);
    set_str(&mut auto_group, "type", "url-test");
    auto_group.insert(
        Value::String("proxies".to_string()),
        Value::Sequence(proxy_names.iter().map(|n| Value::String(n.clone())).collect()),
    );
    set_str(&mut auto_group, "url", "http://www.gstatic.com/generate_204");
    set_u64(&mut auto_group, "interval", 300);
    set_u64(&mut auto_group, "tolerance", 50);

    let mut dns_map = Mapping::new();
    set_bool(&mut dns_map, "enable", true);
    set_bool(&mut dns_map, "ipv6", true);
    set_str(&mut dns_map, "enhanced-mode", "fake-ip");
    set_str(&mut dns_map, "fake-ip-range", "198.18.0.1/16");
    dns_map.insert(
        Value::String("default-nameserver".to_string()),
        str_seq(&["223.5.5.5", "119.29.29.29"]),
    );
    dns_map.insert(
        Value::String("nameserver".to_string()),
        str_seq(&[
            "https://dns.alidns.com/dns-query",
            "https://doh.pub/dns-query",
        ]),
    );
    dns_map.insert(
        Value::String("fallback".to_string()),
        str_seq(&[
            "https://1.1.1.1/dns-query",
            "https://dns.google/dns-query",
        ]),
    );
    let mut fallback_filter = Mapping::new();
    set_bool(&mut fallback_filter, "geoip", true);
    set_str(&mut fallback_filter, "geoip-code", "CN");
    fallback_filter.insert(
        Value::String("ipcidr".to_string()),
        str_seq(&["240.0.0.0/4"]),
    );
    dns_map.insert(
        Value::String("fallback-filter".to_string()),
        Value::Mapping(fallback_filter),
    );

    let mut rules_vec: Vec<String> = vec!["GEOIP,private,DIRECT,no-resolve".to_string()];
    let mut custom_rule_count = 0usize;
    if state.rules_enabled && !state.rules.is_empty() {
        let (compiled_rules, rule_warnings) =
            compile_landing_rules(&state.rules, STANDALONE_SELECT_GROUP, &node_name_map);
        warnings.extend(rule_warnings);
        custom_rule_count = compiled_rules.len();
        rules_vec.extend(compiled_rules);
    }
    rules_vec.push("GEOSITE,cn,DIRECT".to_string());
    rules_vec.push("GEOIP,cn,DIRECT,no-resolve".to_string());
    rules_vec.push(format!("MATCH,{STANDALONE_SELECT_GROUP}"));

    let mut root = Mapping::new();
    set_u64(&mut root, "mixed-port", 7890);
    set_bool(&mut root, "allow-lan", false);
    set_str(&mut root, "mode", "rule");
    set_str(&mut root, "log-level", "info");
    set_bool(&mut root, "ipv6", true);
    set_bool(&mut root, "unified-delay", true);
    set_bool(&mut root, "tcp-concurrent", true);
    root.insert(Value::String("dns".to_string()), Value::Mapping(dns_map));
    root.insert(
        Value::String("proxies".to_string()),
        Value::Sequence(proxies_seq),
    );
    root.insert(
        Value::String("proxy-groups".to_string()),
        Value::Sequence(vec![
            Value::Mapping(select_group),
            Value::Mapping(auto_group),
        ]),
    );
    root.insert(
        Value::String("rules".to_string()),
        Value::Sequence(rules_vec.into_iter().map(Value::String).collect()),
    );

    let yaml = serde_yaml::to_string(&Value::Mapping(root))
        .map_err(|err| format!("生成纯自建配置失败：{err}"))?;

    Ok(StandaloneResult {
        yaml,
        warnings,
        node_count: proxy_names.len(),
        rule_count: custom_rule_count,
    })
}

// ============================================================================
// Low-level Helpers
// ============================================================================

fn set_str(map: &mut Mapping, key: &str, value: &str) {
    map.insert(
        Value::String(key.to_string()),
        Value::String(value.to_string()),
    );
}

fn set_u64(map: &mut Mapping, key: &str, value: u64) {
    map.insert(Value::String(key.to_string()), Value::Number(value.into()));
}

fn set_bool(map: &mut Mapping, key: &str, value: bool) {
    map.insert(Value::String(key.to_string()), Value::Bool(value));
}

fn str_seq(items: &[&str]) -> Value {
    Value::Sequence(items.iter().map(|s| Value::String((*s).to_string())).collect())
}

fn map_str<'a>(map: &'a Mapping, key: &str) -> Option<&'a str> {
    map.get(Value::String(key.to_string()))
        .and_then(Value::as_str)
}

fn map_bool(map: &Mapping, key: &str) -> Option<bool> {
    map.get(Value::String(key.to_string()))
        .and_then(Value::as_bool)
}

fn map_u16(map: &Mapping, key: &str) -> Option<u16> {
    let val = map.get(Value::String(key.to_string()))?;
    if let Some(n) = val.as_u64() {
        return u16::try_from(n).ok().filter(|&p| p > 0);
    }
    if let Some(s) = val.as_str() {
        return s.trim().parse::<u16>().ok().filter(|&p| p > 0);
    }
    None
}

fn json_str<'a>(obj: &'a serde_json::Map<String, serde_json::Value>, key: &str) -> Option<&'a str> {
    obj.get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn json_u64(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<u64> {
    let val = obj.get(key)?;
    if let Some(n) = val.as_u64() {
        return Some(n);
    }
    if let Some(s) = val.as_str() {
        return s.trim().parse::<u64>().ok();
    }
    None
}

fn json_u16(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<u16> {
    json_u64(obj, key)
        .and_then(|n| u16::try_from(n).ok())
        .filter(|&p| p > 0)
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn try_decode_base64_text(input: &str) -> Option<String> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() < 8 {
        return None;
    }
    let engines = [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    for engine in engines {
        if let Ok(bytes) = engine.decode(&compact) {
            if let Ok(text) = String::from_utf8(bytes) {
                return Some(text);
            }
        }
    }
    None
}

fn truncate_source(s: &str) -> String {
    let mut chars = s.chars();
    let prefix: String = chars.by_ref().take(60).collect();
    if chars.next().is_some() {
        format!("{prefix}...")
    } else {
        prefix
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_subscription_yaml() -> &'static str {
        r#"mixed-port: 7890
mode: rule
proxies:
  - name: 香港 01
    type: ss
    server: hk1.example.com
    port: 443
    cipher: aes-128-gcm
    password: secret
  - name: 美国落地
    type: trojan
    server: us-sub.example.com
    port: 443
    password: subpw
proxy-groups:
  - name: 节点选择
    type: select
    proxies:
      - 自动选择
      - 香港 01
      - 美国落地
  - name: 自动选择
    type: url-test
    proxies:
      - 香港 01
rules:
  - GEOIP,private,DIRECT,no-resolve
  - DOMAIN-SUFFIX,local,DIRECT
  - GEOSITE,cn,DIRECT
  - GEOIP,cn,DIRECT,no-resolve
  - MATCH,节点选择
"#
    }

    fn make_node(id: &str, name: &str, server: &str, dialer: DialerTarget) -> CustomNode {
        let form = SimpleProxyForm {
            name: name.to_string(),
            protocol: "socks5".to_string(),
            server: server.to_string(),
            port: 1080,
            username: "u".to_string(),
            password: "p".to_string(),
            tls: false,
            skip_cert_verify: false,
            udp: true,
        };
        let parsed = build_simple_proxy_yaml(&form).unwrap();
        CustomNode {
            id: id.to_string(),
            name: name.to_string(),
            enabled: true,
            note: String::new(),
            protocol: parsed.protocol,
            raw_yaml: parsed.raw_yaml,
            dialer,
        }
    }

    #[test]
    fn parses_all_supported_uri_protocols_including_anytls() {
        let vmess_json = r#"{"v":"2","ps":"VMess JP","add":"vmess.example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","scy":"auto","net":"ws","host":"ws.example.com","path":"/vm","tls":"tls","sni":"ws.example.com"}"#;
        let vmess_b64 = base64::engine::general_purpose::STANDARD.encode(vmess_json);
        let ss_cred = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:sspass");

        let input = format!(
            "\
vless://22222222-2222-2222-2222-222222222222@vless.example.com:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY123&sid=abcd&flow=xtls-rprx-vision#VLESS%20Reality
vmess://{vmess_b64}
trojan://trpass@trojan.example.com:443?sni=trojan.example.com&alpn=h2,http/1.1#Trojan%20SG
ss://{ss_cred}@ss.example.com:8388#SS%20HK
hysteria2://hy2pass@hy2.example.com:8443?sni=hy2.example.com&obfs=salamander&obfs-password=obfspw&insecure=1#Hy2%20US
hy2://hy2short@hy2b.example.com:443#Hy2%20Short
tuic://33333333-3333-3333-3333-333333333333:tuicpw@tuic.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3#TUIC%20UK
anytls://anypass@any.example.com:443?sni=any.example.com&fp=chrome&alpn=h2&insecure=1&idle-session-check-interval=30&idle-session-timeout=60&min-idle-session=2#AnyTLS%20JP
socks5://alice:bob@1.2.3.4:1080#Socks%20Resi
socks://5.6.7.8:1081#Socks%20Plain
http://u1:p1@9.10.11.12:8080#HTTP%20Proxy
https://u2:p2@proxy.example.com:8443?sni=proxy.example.com#HTTPS%20Proxy
"
        );

        let res = parse_nodes_input(&input, &[]);
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(res.parsed.len(), 12);

        let protocols: Vec<&str> = res.parsed.iter().map(|n| n.protocol.as_str()).collect();
        assert_eq!(
            protocols,
            vec![
                "vless",
                "vmess",
                "trojan",
                "ss",
                "hysteria2",
                "hysteria2",
                "tuic",
                "anytls",
                "socks5",
                "socks5",
                "http",
                "http"
            ]
        );

        // Verify AnyTLS fields in compiled YAML.
        let anytls = &res.parsed[7];
        assert_eq!(anytls.name, "AnyTLS JP");
        let any_val: Value = serde_yaml::from_str(&anytls.raw_yaml).unwrap();
        let any_map = any_val.as_mapping().unwrap();
        assert_eq!(map_str(any_map, "type"), Some("anytls"));
        assert_eq!(map_str(any_map, "password"), Some("anypass"));
        assert_eq!(map_str(any_map, "sni"), Some("any.example.com"));
        assert_eq!(map_str(any_map, "client-fingerprint"), Some("chrome"));
        assert_eq!(map_bool(any_map, "skip-cert-verify"), Some(true));
        assert_eq!(
            any_map
                .get(Value::String("min-idle-session".to_string()))
                .and_then(Value::as_u64),
            Some(2)
        );
    }

    #[test]
    fn parses_base64_list_and_isolates_errors_and_deduplicates_names() {
        let raw_list = "\
anytls://pw1@a.example.com:443#DupNode
invalid://broken
socks5://u:p@b.example.com:1080#DupNode
";
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw_list);
        let res = parse_nodes_input(&b64, &["DupNode".to_string()]);
        assert_eq!(res.parsed.len(), 2);
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].index, 2);
        assert_eq!(res.parsed[0].name, "DupNode (2)");
        assert_eq!(res.parsed[1].name, "DupNode (3)");
        assert!(res.parsed[0].raw_yaml.contains("DupNode (2)"));
    }

    #[test]
    fn parses_single_node_yaml_and_strips_dialer_proxy() {
        let snippet = r#"
name: WG Home
type: wireguard
server: wg.example.com
port: 51820
dialer-proxy: 旧中转
private-key: abc
"#;
        let res = parse_nodes_input(snippet, &[]);
        assert!(res.errors.is_empty());
        assert_eq!(res.parsed.len(), 1);
        assert_eq!(res.parsed[0].protocol, "wireguard");
        assert!(!res.parsed[0].raw_yaml.contains("dialer-proxy"));
    }

    #[test]
    fn simple_proxy_form_roundtrips_socks5_and_http() {
        let form = SimpleProxyForm {
            name: "家宽住宅".to_string(),
            protocol: "socks5".to_string(),
            server: "198.51.100.10".to_string(),
            port: 10808,
            username: "resi".to_string(),
            password: "pwd".to_string(),
            tls: false,
            skip_cert_verify: false,
            udp: true,
        };
        let parsed = build_simple_proxy_yaml(&form).unwrap();
        let extracted = extract_simple_proxy(&parsed.raw_yaml).unwrap();
        assert_eq!(extracted, form);
    }

    #[test]
    fn detects_self_and_multihop_cycles_and_missing_dialers() {
        let self_cycle = vec![make_node(
            "cn1",
            "节点A",
            "1.1.1.1",
            DialerTarget::CustomNode {
                id: "cn1".to_string(),
            },
        )];
        let err = validate_dialer_cycles(&self_cycle).unwrap_err();
        assert!(err.contains("节点A"));

        let multi_cycle = vec![
            make_node(
                "cn1",
                "节点A",
                "1.1.1.1",
                DialerTarget::CustomNode {
                    id: "cn2".to_string(),
                },
            ),
            make_node(
                "cn2",
                "节点B",
                "2.2.2.2",
                DialerTarget::CustomNode {
                    id: "cn3".to_string(),
                },
            ),
            make_node(
                "cn3",
                "节点C",
                "3.3.3.3",
                DialerTarget::CustomNode {
                    id: "cn1".to_string(),
                },
            ),
        ];
        let err = validate_dialer_cycles(&multi_cycle).unwrap_err();
        assert!(err.contains("节点A") && err.contains("节点B") && err.contains("节点C"));

        // Missing fixed dialer & disabled custom dialer must be flagged, never degraded to direct.
        let mut disabled_mid = make_node("cn1", "中转1", "1.1.1.1", DialerTarget::Direct);
        disabled_mid.enabled = false;
        let nodes = vec![
            disabled_mid,
            make_node(
                "cn2",
                "落地A",
                "2.2.2.2",
                DialerTarget::CustomNode {
                    id: "cn1".to_string(),
                },
            ),
            make_node(
                "cn3",
                "落地B",
                "3.3.3.3",
                DialerTarget::FixedProxy {
                    name: "不存在的机场节点".to_string(),
                },
            ),
        ];
        let ctx = DialerContext {
            primary_group: Some("节点选择".to_string()),
            available_targets: ["香港 01".to_string(), "节点选择".to_string()]
                .into_iter()
                .collect(),
            is_standalone: false,
        };
        let report = validate_dialer_graph(&nodes, &ctx);
        assert!(!report.valid);
        assert_eq!(report.missing_dialers.len(), 2);
        assert!(report.missing_dialers[0].message.contains("未降级为直连"));
    }

    #[test]
    fn overlay_is_strict_noop_when_disabled_or_no_enabled_nodes() {
        let base = sample_subscription_yaml();
        let mut state = CustomNodesState::default();
        state.overlay_enabled = false;
        state
            .nodes
            .push(make_node("cn1", "美国落地", "8.8.8.8", DialerTarget::Direct));

        let res = inject_overlay(base, &state).unwrap();
        assert_eq!(res.yaml, base);
        assert_eq!(res.injected_count, 0);

        state.overlay_enabled = true;
        state.nodes[0].enabled = false;
        let res2 = inject_overlay(base, &state).unwrap();
        assert_eq!(res2.yaml, base);
        assert_eq!(res2.injected_count, 0);
    }

    #[test]
    fn overlay_injects_collision_safe_nodes_chains_and_priority_landing_rules() {
        let base = sample_subscription_yaml();
        let mut state = CustomNodesState::default();
        // Name "美国落地" collides with subscription proxy "美国落地".
        state.nodes.push(make_node(
            "cn1",
            "美国落地",
            "8.8.4.4",
            DialerTarget::ProfileGroup { group: None },
        ));
        // Second node chains through cn1 (must rewrite dialer-proxy to renamed "美国落地 · 自建").
        state.nodes.push(make_node(
            "cn2",
            "二跳家宽",
            "9.9.9.9",
            DialerTarget::CustomNode {
                id: "cn1".to_string(),
            },
        ));
        state.rules.push(LandingRule {
            id: "lr1".to_string(),
            enabled: true,
            rule: LandingRuleKind::Preset {
                id: "ai".to_string(),
            },
            target: LandingRuleTarget::CustomGroup,
        });
        state.rules.push(LandingRule {
            id: "lr2".to_string(),
            enabled: true,
            rule: LandingRuleKind::Domain {
                pattern: "https://sub.MyCorp.com/login".to_string(),
            },
            target: LandingRuleTarget::CustomNode {
                id: "cn2".to_string(),
            },
        });
        state.rules.push(LandingRule {
            id: "lr3".to_string(),
            enabled: true,
            rule: LandingRuleKind::Domain {
                pattern: "=exact.example.org".to_string(),
            },
            target: LandingRuleTarget::CustomGroup,
        });

        let res = inject_overlay(base, &state).unwrap();
        assert!(res.warnings.is_empty(), "warnings: {:?}", res.warnings);
        assert_eq!(res.injected_count, 2);
        assert!(res.injected_rule_count >= 22);

        let doc: Value = serde_yaml::from_str(&res.yaml).unwrap();
        let root = doc.as_mapping().unwrap();

        // Check proxies & rewritten dialer-proxy.
        let proxies = root
            .get(Value::String("proxies".to_string()))
            .unwrap()
            .as_sequence()
            .unwrap();
        let cn1 = proxies
            .iter()
            .find(|p| p.as_mapping().and_then(|m| map_str(m, "name")) == Some("美国落地 · 自建"))
            .unwrap()
            .as_mapping()
            .unwrap();
        assert_eq!(map_str(cn1, "dialer-proxy"), Some(CHAIN_RELAY_GROUP_NAME));

        let cn2 = proxies
            .iter()
            .find(|p| p.as_mapping().and_then(|m| map_str(m, "name")) == Some("二跳家宽"))
            .unwrap()
            .as_mapping()
            .unwrap();
        assert_eq!(map_str(cn2, "dialer-proxy"), Some("美国落地 · 自建"));

        // Check landing group is created and exposed in primary select group, while
        // dedicated `链式前置` group clones original members WITHOUT `自建落地` (cycle-free).
        let groups = root
            .get(Value::String("proxy-groups".to_string()))
            .unwrap()
            .as_sequence()
            .unwrap();
        let primary = groups
            .iter()
            .find(|g| g.as_mapping().and_then(|m| map_str(m, "name")) == Some("节点选择"))
            .unwrap()
            .as_mapping()
            .unwrap();
        let primary_members: Vec<&str> = primary
            .get(Value::String("proxies".to_string()))
            .unwrap()
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(primary_members.contains(&LANDING_GROUP_NAME));

        let relay = groups
            .iter()
            .find(|g| g.as_mapping().and_then(|m| map_str(m, "name")) == Some(CHAIN_RELAY_GROUP_NAME))
            .unwrap()
            .as_mapping()
            .unwrap();
        let relay_members: Vec<&str> = relay
            .get(Value::String("proxies".to_string()))
            .unwrap()
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(relay_members, vec!["自动选择", "香港 01", "美国落地"]);
        assert!(!relay_members.contains(&LANDING_GROUP_NAME));

        // Check rule priority ordering: private/LAN first -> landing rules -> CN -> MATCH.
        let rules: Vec<&str> = root
            .get(Value::String("rules".to_string()))
            .unwrap()
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(rules[0], "GEOIP,private,DIRECT,no-resolve");
        assert_eq!(rules[1], "DOMAIN-SUFFIX,local,DIRECT");
        assert_eq!(rules[2], "DOMAIN-SUFFIX,openai.com,自建落地");
        let corp_pos = rules
            .iter()
            .position(|r| *r == "DOMAIN-SUFFIX,sub.mycorp.com,二跳家宽")
            .unwrap();
        let exact_pos = rules
            .iter()
            .position(|r| *r == "DOMAIN,exact.example.org,自建落地")
            .unwrap();
        let cn_pos = rules
            .iter()
            .position(|r| *r == "GEOSITE,cn,DIRECT")
            .unwrap();
        assert!(corp_pos > 1 && corp_pos < cn_pos);
        assert!(exact_pos > 1 && exact_pos < cn_pos);
    }

    #[test]
    fn standalone_generator_refuses_empty_and_builds_complete_config() {
        let empty_state = CustomNodesState::default();
        let err = generate_standalone_yaml(&empty_state).unwrap_err();
        assert!(err.contains("还没有启用的自建节点"));

        let mut state = CustomNodesState::default();
        state
            .nodes
            .push(make_node("cn1", "日本直连", "1.1.1.1", DialerTarget::Direct));
        state.nodes.push(make_node(
            "cn2",
            "美国落地",
            "2.2.2.2",
            DialerTarget::CustomNode {
                id: "cn1".to_string(),
            },
        ));
        state.rules.push(LandingRule {
            id: "lr1".to_string(),
            enabled: true,
            rule: LandingRuleKind::Preset {
                id: "ai".to_string(),
            },
            target: LandingRuleTarget::CustomNode {
                id: "cn2".to_string(),
            },
        });

        let res = generate_standalone_yaml(&state).unwrap();
        assert!(res.warnings.is_empty());
        assert_eq!(res.node_count, 2);
        assert!(res.rule_count >= 20);

        let doc: Value = serde_yaml::from_str(&res.yaml).unwrap();
        let root = doc.as_mapping().unwrap();
        assert_eq!(map_u16(root, "mixed-port"), Some(7890));
        assert!(root.contains_key(Value::String("dns".to_string())));

        let rules: Vec<&str> = root
            .get(Value::String("rules".to_string()))
            .unwrap()
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(rules.first().copied(), Some("GEOIP,private,DIRECT,no-resolve"));
        assert!(rules.contains(&"DOMAIN-SUFFIX,openai.com,美国落地"));
        assert!(rules.contains(&"GEOSITE,cn,DIRECT"));
        assert!(rules.contains(&"GEOIP,cn,DIRECT,no-resolve"));
        assert_eq!(rules.last().copied(), Some("MATCH,节点选择"));
    }

    #[test]
    fn domain_normalization_rejects_invalid_tokens() {
        assert_eq!(
            normalize_domain_pattern(" .OpenAI.com ").unwrap(),
            (false, "openai.com".to_string())
        );
        assert_eq!(
            normalize_domain_pattern("=api.openai.com").unwrap(),
            (true, "api.openai.com".to_string())
        );
        assert!(normalize_domain_pattern("not a domain").is_err());
        assert!(normalize_domain_pattern("localhost").is_err());
    }

    #[test]
    fn overlay_and_standalone_never_degrade_missing_dialer_to_direct() {
        let base = sample_subscription_yaml();
        let mut state = CustomNodesState::default();
        state.nodes.push(make_node(
            "cn1",
            "孤立落地",
            "4.4.4.4",
            DialerTarget::FixedProxy {
                name: "不存在的节点".to_string(),
            },
        ));

        let overlay = inject_overlay(base, &state).unwrap();
        assert_eq!(overlay.injected_count, 0);
        assert_eq!(overlay.yaml, base);
        assert_eq!(overlay.warnings.len(), 1);
        assert_eq!(overlay.warnings[0].code, "missing_dialer");

        // Standalone mode rejects ProfileGroup dialer rather than degrading to direct.
        let mut standalone_state = CustomNodesState::default();
        standalone_state.nodes.push(make_node(
            "cn1",
            "仅订阅中转",
            "5.5.5.5",
            DialerTarget::ProfileGroup { group: None },
        ));
        let err = generate_standalone_yaml(&standalone_state).unwrap_err();
        assert!(err.contains("纯自建模式"));
    }

    #[test]
    fn overlay_rejects_cycles_and_warns_on_missing_rule_target() {
        let base = sample_subscription_yaml();
        let mut cycle_state = CustomNodesState::default();
        cycle_state.nodes.push(make_node(
            "cn1",
            "环A",
            "1.1.1.1",
            DialerTarget::CustomNode {
                id: "cn2".to_string(),
            },
        ));
        cycle_state.nodes.push(make_node(
            "cn2",
            "环B",
            "2.2.2.2",
            DialerTarget::CustomNode {
                id: "cn1".to_string(),
            },
        ));
        let err = inject_overlay(base, &cycle_state).unwrap_err();
        assert!(err.contains("循环引用"));

        let mut rule_state = CustomNodesState::default();
        rule_state
            .nodes
            .push(make_node("cn1", "正常落地", "3.3.3.3", DialerTarget::Direct));
        rule_state.rules.push(LandingRule {
            id: "lr1".to_string(),
            enabled: true,
            rule: LandingRuleKind::Domain {
                pattern: "example.com".to_string(),
            },
            target: LandingRuleTarget::CustomNode {
                id: "cn999".to_string(),
            },
        });
        let res = inject_overlay(base, &rule_state).unwrap();
        assert_eq!(res.injected_count, 1);
        assert_eq!(res.injected_rule_count, 0);
        assert_eq!(res.warnings.len(), 1);
        assert_eq!(res.warnings[0].code, "missing_rule_target");
    }

    #[test]
    fn detects_nodes_input_vs_subscription_url_and_validates_raw_yaml() {
        assert!(!looks_like_nodes_input("https://sub.example.com/clash?token=abc"));
        assert!(looks_like_nodes_input("anytls://pw@host.example.com:443#Node"));
        assert!(looks_like_nodes_input("type: wireguard\nserver: 1.2.3.4\nport: 51820"));

        let validated = validate_raw_node_yaml(
            "type: anytls\nserver: a.example.com\nport: 443\npassword: pw\ndialer-proxy: old",
            Some("重命名节点"),
        )
        .unwrap();
        assert_eq!(validated.name, "重命名节点");
        assert!(!validated.raw_yaml.contains("dialer-proxy"));

        let mut st = CustomNodesState::default();
        assert_eq!(st.alloc_node_id(), "cn1");
        assert_eq!(st.alloc_rule_id(), "lr1");
        assert_eq!(CUSTOM_PROFILE_ID, "__custom__");
    }

    #[test]
    fn invalid_yaml_snippet_returns_yaml_syntax_error_instead_of_uri_fallback() {
        let broken_yaml = "name: broken\ntype: anytls\nserver: [unclosed\nport: 443";
        let res = parse_nodes_input(broken_yaml, &[]);
        assert!(res.parsed.is_empty());
        assert_eq!(res.errors.len(), 1);
        assert!(
            res.errors[0].reason.contains("YAML 语法错误"),
            "unexpected reason: {}",
            res.errors[0].reason
        );
    }

    #[test]
    fn ss_parser_preserves_slash_in_standard_base64_credentials() {
        // Choose a password whose standard Base64 encoding contains '/'.
        // "aes-256-gcm:???" -> "YWVzLTI1Ni1nY206Pz8/" (contains '/')
        let sip002_cred = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:???");
        assert!(sip002_cred.contains('/'));
        let sip002_uri = format!("ss://{sip002_cred}@ss-slash.example.com:8388/#Slash%20SIP002");

        let legacy_payload =
            base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:???@ss-legacy.example.com:8389");
        assert!(legacy_payload.contains('/'));
        let legacy_uri = format!("ss://{legacy_payload}#Slash%20Legacy");

        let res = parse_nodes_input(&format!("{sip002_uri}\n{legacy_uri}"), &[]);
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        assert_eq!(res.parsed.len(), 2);
        assert_eq!(res.parsed[0].name, "Slash SIP002");
        assert_eq!(res.parsed[0].server, "ss-slash.example.com");
        assert_eq!(res.parsed[0].port, 8388);
        assert_eq!(res.parsed[1].name, "Slash Legacy");
        assert_eq!(res.parsed[1].server, "ss-legacy.example.com");
        assert_eq!(res.parsed[1].port, 8389);
    }

    #[test]
    fn fixed_proxy_does_not_match_skipped_custom_node_in_standalone() {
        let mut state = CustomNodesState::default();
        // Node A is skipped in standalone mode because it uses ProfileGroup.
        state.nodes.push(make_node(
            "cn1",
            "节点A",
            "1.1.1.1",
            DialerTarget::ProfileGroup { group: None },
        ));
        // Node B tries to reference "节点A" via FixedProxy — must also be flagged, never emitted dangling.
        state.nodes.push(make_node(
            "cn2",
            "节点B",
            "2.2.2.2",
            DialerTarget::FixedProxy {
                name: "节点A".to_string(),
            },
        ));
        let err = generate_standalone_yaml(&state).unwrap_err();
        assert!(err.contains("无法生成纯自建配置"));
    }

    #[test]
    fn socks5_simple_form_preserves_udp_false_on_roundtrip() {
        let form = SimpleProxyForm {
            name: "无UDP住宅".to_string(),
            protocol: "socks5".to_string(),
            server: "198.51.100.20".to_string(),
            port: 1080,
            username: "u".to_string(),
            password: "p".to_string(),
            tls: false,
            skip_cert_verify: false,
            udp: false,
        };
        let parsed = build_simple_proxy_yaml(&form).unwrap();
        let extracted = extract_simple_proxy(&parsed.raw_yaml).unwrap();
        assert_eq!(extracted, form);
        assert!(!extracted.udp);
    }
}
