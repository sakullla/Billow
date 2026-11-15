use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use crate::nodes::ControllerEndpoint;

pub const LOG_LIMIT: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct ConnectionView {
    pub host: String,
    pub outbound: String,
    pub id: String,
    pub network: String,
    pub conn_type: String,
    pub destination: String,
    pub source: String,
    pub process: String,
    pub rule: String,
    pub rule_payload: String,
    pub chains: Vec<String>,
    pub upload: u64,
    pub download: u64,
    pub start: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct LogView {
    pub level: String,
    pub message: String,
    pub time_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct RuleView {
    pub kind: String,
    pub payload: String,
    pub proxy: String,
    /// `/rules` `extra.hitCount`; old kernels omit it.
    pub hit_count: Option<u64>,
    /// `/rules` `extra.lastHit`; old kernels omit it.
    pub last_hit: Option<String>,
}

/// One rule from the profile's full `rules:` list. The key is computed over the
/// full list, so it stays stable while disabled rules are filtered out of the
/// config actually sent to the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigRule {
    pub key: String,
    pub kind: String,
    pub payload: String,
    pub proxy: String,
}

/// A rule row for the UI. Kernel rows keep their hit data; rules the kernel
/// omits because they are disabled are added back with `disabled: true`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct RuleRowView {
    pub kind: String,
    pub payload: String,
    pub proxy: String,
    pub hit_count: Option<u64>,
    pub last_hit: Option<String>,
    /// Toggle key; `None` for kernel-injected rules that are not in the config.
    pub key: Option<String>,
    pub disabled: bool,
}

/// Stable key for a runtime-disabled rule: type, payload, proxy and the occurrence
/// of that triple in the rule list. Kinds are normalized so `/rules` (`DomainSuffix`)
/// and config text (`DOMAIN-SUFFIX`) produce the same key.
pub fn normalize_rule_kind(kind: &str) -> String {
    kind.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

pub fn rule_key(kind: &str, payload: &str, proxy: &str, occurrence: usize) -> String {
    format!(
        "{}|{}|{}|{}",
        normalize_rule_kind(kind),
        payload.trim(),
        proxy.trim(),
        occurrence
    )
}

fn rule_base(kind: &str, payload: &str, proxy: &str) -> String {
    format!(
        "{}|{}|{}",
        normalize_rule_kind(kind),
        payload.trim(),
        proxy.trim()
    )
}

/// Keys for a `/rules` response, in the order the kernel reports them.
#[cfg_attr(not(test), allow(dead_code))]
pub fn rule_keys(rules: &[RuleView]) -> Vec<String> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    rules
        .iter()
        .map(|rule| {
            let base = rule_base(&rule.kind, &rule.payload, &rule.proxy);
            let occurrence = seen.entry(base.clone()).or_insert(0);
            let key = format!("{base}|{occurrence}");
            *occurrence += 1;
            key
        })
        .collect()
}

/// Full config rule list with keys based on the original order, including
/// duplicates as separate occurrences.
pub fn config_rules(value: &serde_yaml::Value) -> Vec<ConfigRule> {
    let Some(sequence) = value
        .as_mapping()
        .and_then(|map| map.get(serde_yaml::Value::String("rules".to_string())))
        .and_then(serde_yaml::Value::as_sequence)
    else {
        return Vec::new();
    };
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut rules = Vec::new();
    for item in sequence {
        let Some(text) = item.as_str() else {
            continue;
        };
        let Some((kind, payload, proxy)) = config_rule_parts(text) else {
            continue;
        };
        let base = rule_base(&kind, &payload, &proxy);
        let occurrence = seen.entry(base.clone()).or_insert(0);
        let key = rule_key(&kind, &payload, &proxy, *occurrence);
        *occurrence += 1;
        rules.push(ConfigRule {
            key,
            kind,
            payload,
            proxy,
        });
    }
    rules
}

/// Builds UI rows from the full config list and the kernel's (possibly filtered)
/// rows. Index each kernel identity once, keeping occurrence order for duplicates.
/// This avoids rescanning and normalizing whole lists for every rule.
pub fn rule_rows(
    config: &[ConfigRule],
    kernel: &[RuleView],
    disabled: &BTreeSet<String>,
) -> Vec<RuleRowView> {
    let mut available: HashMap<String, VecDeque<usize>> = HashMap::new();
    for (kernel_index, row) in kernel.iter().enumerate() {
        available.entry(rule_base(&row.kind, &row.payload, &row.proxy))
            .or_default()
            .push_back(kernel_index);
    }
    let mut matched = vec![false; kernel.len()];
    let mut config_matches = vec![None; config.len()];
    // Prefer enabled duplicates; disabled occurrences only consume leftover rows
    // from a stale, unfiltered kernel response.
    for disabled_pass in [false, true] {
        for (config_index, rule) in config.iter().enumerate() {
            if disabled.contains(&rule.key) != disabled_pass {
                continue;
            }
            let base = rule_base(&rule.kind, &rule.payload, &rule.proxy);
            if let Some(kernel_index) = available.get_mut(&base).and_then(VecDeque::pop_front) {
                config_matches[config_index] = Some(kernel_index);
                matched[kernel_index] = true;
            }
        }
    }
    drop(available);
    let mut rows = Vec::with_capacity(config.len().max(kernel.len()));
    for (config_index, rule) in config.iter().enumerate() {
        let kernel_row = config_matches[config_index].map(|kernel_index| &kernel[kernel_index]);
        let disabled = disabled.contains(&rule.key);
        if kernel_row.is_none() && !disabled {
            // Keep the kernel's real rows; only add back rules it omitted because
            // they are disabled.
            continue;
        }
        let (kind, payload, proxy, hit_count, last_hit) = match kernel_row {
            Some(row) => (
                row.kind.clone(),
                row.payload.clone(),
                row.proxy.clone(),
                row.hit_count,
                row.last_hit.clone(),
            ),
            None => (
                rule.kind.clone(),
                rule.payload.clone(),
                rule.proxy.clone(),
                None,
                None,
            ),
        };
        rows.push(RuleRowView {
            kind,
            payload,
            proxy,
            hit_count,
            last_hit,
            key: Some(rule.key.clone()),
            disabled,
        });
    }
    for (kernel_index, row) in kernel.iter().enumerate() {
        if matched[kernel_index] {
            continue;
        }
        rows.push(RuleRowView {
            kind: row.kind.clone(),
            payload: row.payload.clone(),
            proxy: row.proxy.clone(),
            hit_count: row.hit_count,
            last_hit: row.last_hit.clone(),
            key: None,
            disabled: false,
        });
    }
    rows
}

/// Splits one config rule line into kind, payload and proxy. Trailing modifiers
/// such as `no-resolve` are ignored, and `MATCH`/`FINAL` have no payload.
pub fn config_rule_parts(text: &str) -> Option<(String, String, String)> {
    let segments: Vec<&str> = text.split(',').map(str::trim).collect();
    if segments.len() < 2 {
        return None;
    }
    let kind = segments[0].to_string();
    let mut end = segments.len();
    while end > 1
        && matches!(
            segments[end - 1].to_ascii_lowercase().as_str(),
            "no-resolve" | "src"
        )
    {
        end -= 1;
    }
    if end < 2 {
        return None;
    }
    let proxy = segments[end - 1].to_string();
    let normalized = normalize_rule_kind(&kind);
    let payload = if normalized == "match" || normalized == "final" {
        String::new()
    } else {
        segments[1..end - 1].join(",")
    };
    Some((kind, payload, proxy))
}

/// Drops disabled rules from the `rules:` list while keeping the occurrence
/// counter over the full input, so keys stay stable as rows are toggled.
pub fn filter_disabled_rules(yaml: &str, disabled: &BTreeSet<String>) -> Result<String, String> {
    if disabled.is_empty() {
        return Ok(yaml.to_string());
    }
    let error = || "配置无法应用".to_string();
    let mut value: serde_yaml::Value = serde_yaml::from_str(yaml).map_err(|_| error())?;
    let Some(map) = value.as_mapping_mut() else {
        return Err(error());
    };
    let rules_field = serde_yaml::Value::String("rules".to_string());
    let Some(sequence) = map
        .get_mut(&rules_field)
        .and_then(|item| item.as_sequence_mut())
    else {
        return Ok(yaml.to_string());
    };
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut kept = Vec::with_capacity(sequence.len());
    for item in sequence.iter() {
        let Some(text) = item.as_str() else {
            kept.push(item.clone());
            continue;
        };
        let Some((kind, payload, proxy)) = config_rule_parts(text) else {
            kept.push(item.clone());
            continue;
        };
        let base = format!(
            "{}|{}|{}",
            normalize_rule_kind(&kind),
            payload.trim(),
            proxy.trim()
        );
        let occurrence = seen.entry(base.clone()).or_insert(0);
        let key = rule_key(&kind, &payload, &proxy, *occurrence);
        *occurrence += 1;
        if !disabled.contains(&key) {
            kept.push(item.clone());
        }
    }
    *sequence = kept;
    serde_yaml::to_string(&value).map_err(|_| error())
}

/// Writes exported logs into `directory` and returns the path. The destination
/// directory is created when missing; failures leave the caller's buffer alone.
pub fn export_logs(directory: &Path, content: &str, now_ms: u64) -> Result<PathBuf, String> {
    fs::create_dir_all(directory).map_err(|_| "日志没有导出".to_string())?;
    let path = directory.join(log_file_name(now_ms));
    fs::write(&path, content).map_err(|_| "日志没有导出".to_string())?;
    Ok(path)
}

/// Timestamped export name in UTC, for example `billow-logs-20231114-221320.log`.
pub fn log_file_name(now_ms: u64) -> String {
    let seconds = now_ms / 1000;
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "billow-logs-{year:04}{month:02}{day:02}-{:02}{:02}{:02}.log",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u64, u64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub struct TrafficTotals {
    pub upload: u64,
    pub download: u64,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis() as u64)
        .unwrap_or(0)
}

pub fn failure_log(message: &str) -> LogView {
    LogView {
        level: "error".to_string(),
        message: message.trim().to_string(),
        time_ms: now_ms(),
    }
}

pub fn normalize_log_filter(filter: &str) -> &'static str {
    match filter.trim().to_ascii_lowercase().as_str() {
        "error" | "错误" => "error",
        "warning" | "warn" | "警告" => "warning",
        "info" | "信息" => "info",
        "debug" | "调试" => "debug",
        _ => "all",
    }
}

pub fn filter_connections(rows: &[ConnectionView], query: &str) -> Vec<ConnectionView> {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return rows.to_vec();
    }
    rows.iter()
        .filter(|row| row.host.to_lowercase().contains(&needle))
        .cloned()
        .collect()
}

pub fn filter_logs(rows: &[LogView], filter: &str) -> Vec<LogView> {
    let filter = normalize_log_filter(filter);
    if filter == "all" {
        return rows.to_vec();
    }
    rows.iter()
        .filter(|row| row.level == filter)
        .cloned()
        .collect()
}

pub fn accept_connections(rows: Vec<ConnectionView>) -> Vec<ConnectionView> {
    rows.into_iter()
        .filter_map(|row| {
            let mut clean = sanitize_connection(row.host.clone(), row.outbound.clone())?;
            clean.id = clean_token(&row.id, 80);
            clean.network = clean_token(&row.network, 20);
            clean.conn_type = clean_token(&row.conn_type, 40);
            clean.destination = clean_token(&row.destination, 120);
            clean.source = clean_token(&row.source, 120);
            clean.process = clean_token(&row.process, 200);
            clean.rule = clean_token(&row.rule, 60);
            clean.rule_payload = clean_token(&row.rule_payload, 200);
            clean.chains = row.chains.iter().map(|item| clean_token(item, 200)).collect();
            clean.upload = row.upload;
            clean.download = row.download;
            clean.start = clean_token(&row.start, 60);
            Some(clean)
        })
        .take(500)
        .collect()
}

pub fn push_logs(logs: &mut Vec<LogView>, incoming: impl IntoIterator<Item = LogView>) {
    for line in incoming {
        if !matches!(line.level.as_str(), "error" | "warning" | "info" | "debug") {
            continue;
        }
        let message = line.message.trim();
        if message.is_empty() {
            continue;
        }
        logs.push(LogView {
            level: line.level,
            message: message.to_string(),
            time_ms: if line.time_ms == 0 { now_ms() } else { line.time_ms },
        });
    }
    let overflow = logs.len().saturating_sub(LOG_LIMIT);
    if overflow > 0 {
        logs.drain(0..overflow);
    }
}

/// One `/connections` read: the accepted rows, byte totals, the pre-truncation count and any failure.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConnectionsReading {
    pub rows: Vec<ConnectionView>,
    pub totals: Option<TrafficTotals>,
    /// Open connections the kernel reported before the view keeps at most 500 rows.
    pub total: usize,
    /// Set only when the controller could not be read.
    pub error: Option<String>,
}

/// Reads the controller `/connections` body into rows plus the running byte totals.
#[cfg_attr(not(test), allow(dead_code))]
pub fn connections_from_body(text: &str) -> Vec<ConnectionView> {
    read_connections(text).rows
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn connections_and_totals(text: &str) -> (Vec<ConnectionView>, Option<TrafficTotals>) {
    let reading = read_connections(text);
    (reading.rows, reading.totals)
}

pub fn read_connections(text: &str) -> ConnectionsReading {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return ConnectionsReading::default();
    };
    let totals = match (
        json_u64(value.get("uploadTotal")),
        json_u64(value.get("downloadTotal")),
    ) {
        (Some(upload), Some(download)) => Some(TrafficTotals { upload, download }),
        _ => None,
    };
    let Some(list) = value.get("connections").and_then(serde_json::Value::as_array) else {
        return ConnectionsReading {
            totals,
            ..Default::default()
        };
    };
    let total = list.len();
    let mut rows = Vec::with_capacity(total.min(500));
    for item in list {
        let metadata = item.get("metadata");
        let host = text_field(metadata, "host")
            .filter(|host| !host.is_empty())
            .or_else(|| text_field(metadata, "destinationIP"))
            .unwrap_or("");
        let chains: Vec<String> = item
            .get("chains")
            .and_then(serde_json::Value::as_array)
            .map(|chains| {
                chains
                    .iter()
                    .filter_map(|chain| chain.as_str().filter(|value| !value.is_empty()))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let outbound = chains.first().cloned().unwrap_or_default();
        let Some(mut row) = sanitize_connection(host.to_string(), outbound) else {
            continue;
        };
        let port = text_field(metadata, "destinationPort").unwrap_or("");
        let dest_ip = text_field(metadata, "destinationIP").unwrap_or("");
        let src_ip = text_field(metadata, "sourceIP").unwrap_or("");
        let src_port = text_field(metadata, "sourcePort").unwrap_or("");
        row.id = clean_token(item.get("id").and_then(serde_json::Value::as_str).unwrap_or(""), 80);
        row.network = clean_token(text_field(metadata, "network").unwrap_or(""), 20);
        row.conn_type = clean_token(text_field(metadata, "type").unwrap_or(""), 40);
        row.destination = clean_token(
            &if port.is_empty() { dest_ip.to_string() } else { format!("{dest_ip}:{port}") },
            120,
        );
        row.source = clean_token(
            &if src_port.is_empty() { src_ip.to_string() } else { format!("{src_ip}:{src_port}") },
            120,
        );
        let process = text_field(metadata, "process")
            .or_else(|| {
                text_field(metadata, "processPath")
                    .map(|path| path.rsplit(['/', '\\']).next().unwrap_or(path))
            })
            .unwrap_or("");
        row.process = clean_token(process, 200);
        row.rule = clean_token(item.get("rule").and_then(serde_json::Value::as_str).unwrap_or(""), 60);
        row.rule_payload = clean_token(
            item.get("rulePayload").and_then(serde_json::Value::as_str).unwrap_or(""),
            200,
        );
        row.chains = chains.iter().map(|item| clean_token(item, 200)).collect();
        row.upload = json_u64(item.get("upload")).unwrap_or(0);
        row.download = json_u64(item.get("download")).unwrap_or(0);
        row.start = clean_token(item.get("start").and_then(serde_json::Value::as_str).unwrap_or(""), 60);
        rows.push(row);
        if rows.len() == 500 {
            break;
        }
    }
    ConnectionsReading {
        rows,
        totals,
        total,
        error: None,
    }
}

fn controller_agent(read: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_millis(400))
        .timeout_read(read)
        .timeout_write(Duration::from_millis(400))
        .redirects(0)
        .try_proxy_from_env(false)
        .build()
}

fn authorize(request: ureq::Request, endpoint: &ControllerEndpoint) -> ureq::Request {
    let request = request.set("User-Agent", "Billow");
    if endpoint.secret.is_empty() {
        request
    } else {
        request.set("Authorization", &format!("Bearer {}", endpoint.secret))
    }
}

/// Closes one connection, or all of them when `id` is `None`.
pub fn close_connections(endpoint: &ControllerEndpoint, id: Option<&str>) -> Result<(), String> {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return Err("内核没有运行".to_string());
    }
    let url = match id {
        Some(id) if !id.trim().is_empty() => format!(
            "http://{}:{}/connections/{}",
            endpoint.host,
            endpoint.port,
            id.trim()
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
                .collect::<String>()
        ),
        Some(_) => return Err("没有这条连接".to_string()),
        None => format!("http://{}:{}/connections", endpoint.host, endpoint.port),
    };
    let agent = controller_agent(Duration::from_millis(800));
    authorize(agent.delete(&url), endpoint)
        .call()
        .map(|_| ())
        .map_err(|_| "连接没有关闭".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct ProviderView {
    pub name: String,
    /// `proxy` or `rule`.
    pub kind: String,
    /// HTTP, File or Inline.
    pub vehicle: String,
    /// Rule providers: domain, ipcidr or classical.
    pub behavior: String,
    pub format: String,
    pub count: u64,
    pub updated_at: String,
    pub used: Option<u64>,
    pub total: Option<u64>,
    pub expire: Option<u64>,
}

pub(crate) fn controller_get(endpoint: &ControllerEndpoint, path: &str) -> Result<serde_json::Value, String> {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return Err("内核没有运行".to_string());
    }
    let url = format!("http://{}:{}{path}", endpoint.host, endpoint.port);
    let agent = controller_agent(Duration::from_millis(3000));
    let response = authorize(agent.get(&url), endpoint)
        .call()
        .map_err(|_| "内核没有响应".to_string())?;
    let mut body = String::new();
    response
        .into_reader()
        .take(16_000_000)
        .read_to_string(&mut body)
        .map_err(|_| "内核没有响应".to_string())?;
    serde_json::from_str(&body).map_err(|_| "内核没有响应".to_string())
}

pub fn providers_from_values(proxies: &serde_json::Value, rules: &serde_json::Value) -> Vec<ProviderView> {
    let mut out = Vec::new();
    if let Some(map) = proxies.get("providers").and_then(serde_json::Value::as_object) {
        for (name, item) in map {
            let vehicle = item.get("vehicleType").and_then(serde_json::Value::as_str).unwrap_or("");
            // `default` and group-backed providers are the profile's own inline proxies.
            if vehicle.eq_ignore_ascii_case("compatible") || name == "default" {
                continue;
            }
            let info = item.get("subscriptionInfo");
            let field = |key: &str| info.and_then(|info| json_u64(info.get(key)));
            let used = match (field("Upload"), field("Download")) {
                (Some(up), Some(down)) => Some(up + down),
                _ => None,
            };
            out.push(ProviderView {
                name: clean_token(name, 200),
                kind: "proxy".to_string(),
                vehicle: clean_token(vehicle, 20),
                behavior: String::new(),
                format: String::new(),
                count: item
                    .get("proxies")
                    .and_then(serde_json::Value::as_array)
                    .map(|list| list.len() as u64)
                    .unwrap_or(0),
                updated_at: clean_token(item.get("updatedAt").and_then(serde_json::Value::as_str).unwrap_or(""), 60),
                used,
                total: field("Total").filter(|total| *total > 0),
                expire: field("Expire").filter(|expire| *expire > 0),
            });
        }
    }
    if let Some(map) = rules.get("providers").and_then(serde_json::Value::as_object) {
        for (name, item) in map {
            let text = |key: &str| clean_token(item.get(key).and_then(serde_json::Value::as_str).unwrap_or(""), 60);
            out.push(ProviderView {
                name: clean_token(name, 200),
                kind: "rule".to_string(),
                vehicle: text("vehicleType"),
                behavior: text("behavior"),
                format: text("format"),
                count: json_u64(item.get("ruleCount")).unwrap_or(0),
                updated_at: text("updatedAt"),
                used: None,
                total: None,
                expire: None,
            });
        }
    }
    out.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.name.cmp(&b.name)));
    out
}

pub fn fetch_providers(endpoint: &ControllerEndpoint) -> Result<Vec<ProviderView>, String> {
    let proxies = controller_get(endpoint, "/providers/proxies")?;
    let rules = controller_get(endpoint, "/providers/rules").unwrap_or(serde_json::Value::Null);
    Ok(providers_from_values(&proxies, &rules))
}

/// `action`: `update` re-downloads the provider; `healthcheck` re-tests a proxy provider.
pub fn provider_action(
    endpoint: &ControllerEndpoint,
    kind: &str,
    name: &str,
    action: &str,
) -> Result<(), String> {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return Err("内核没有运行".to_string());
    }
    let segment = encode_path(name);
    let base = if kind == "rule" { "rules" } else { "proxies" };
    let url = format!("http://{}:{}/providers/{base}/{segment}", endpoint.host, endpoint.port);
    let agent = controller_agent(Duration::from_secs(60));
    let result = match action {
        "healthcheck" if kind != "rule" => authorize(agent.get(&format!("{url}/healthcheck")), endpoint).call(),
        _ => authorize(agent.put(&url), endpoint).send_string(""),
    };
    result.map(|_| ()).map_err(|_| {
        if action == "healthcheck" {
            "健康检查失败".to_string()
        } else {
            "资源没有更新".to_string()
        }
    })
}

/// Re-downloads GeoIP / GeoSite / MMDB / ASN databases named in the profile.
pub fn upgrade_geo(endpoint: &ControllerEndpoint) -> Result<(), String> {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return Err("内核没有运行".to_string());
    }
    let agent = controller_agent(Duration::from_secs(120));
    for path in ["/upgrade/geo", "/configs/geo"] {
        let url = format!("http://{}:{}{path}", endpoint.host, endpoint.port);
        if authorize(agent.post(&url), endpoint)
            .set("Content-Type", "application/json")
            .send_string("{}")
            .is_ok()
        {
            return Ok(());
        }
    }
    Err("GEO 数据库没有更新".to_string())
}

pub(crate) fn encode_path(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

pub fn flush_cache(endpoint: &ControllerEndpoint, which: &str) -> Result<(), String> {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return Err("内核没有运行".to_string());
    }
    let which = if which == "fakeip" { "fakeip" } else { "dns" };
    let url = format!("http://{}:{}/cache/{which}/flush", endpoint.host, endpoint.port);
    let agent = controller_agent(Duration::from_millis(1500));
    authorize(agent.post(&url), endpoint)
        .send_string("")
        .map(|_| ())
        .map_err(|_| "缓存没有清除".to_string())
}

pub fn fetch_rules(endpoint: &ControllerEndpoint) -> Result<Vec<RuleView>, String> {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return Err("内核没有运行".to_string());
    }
    let url = format!("http://{}:{}/rules", endpoint.host, endpoint.port);
    let agent = controller_agent(Duration::from_millis(1500));
    let response = authorize(agent.get(&url), endpoint)
        .call()
        .map_err(|_| "规则没有读取".to_string())?;
    let mut body = String::new();
    response
        .into_reader()
        .take(8_000_000)
        .read_to_string(&mut body)
        .map_err(|_| "规则没有读取".to_string())?;
    Ok(rules_from_body(&body))
}

pub fn rules_from_body(text: &str) -> Vec<RuleView> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(list) = value.get("rules").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    list.iter()
        .map(|item| {
            let (hit_count, last_hit) = rule_hits(item);
            RuleView {
                kind: clean_token(item.get("type").and_then(serde_json::Value::as_str).unwrap_or(""), 60),
                payload: clean_token(
                    item.get("payload").and_then(serde_json::Value::as_str).unwrap_or(""),
                    400,
                ),
                proxy: clean_token(item.get("proxy").and_then(serde_json::Value::as_str).unwrap_or(""), 200),
                hit_count,
                last_hit,
            }
        })
        .filter(|rule| !rule.kind.is_empty())
        .collect()
}

/// Hit statistics live under `extra` and are absent on kernels that do not track them.
fn rule_hits(item: &serde_json::Value) -> (Option<u64>, Option<String>) {
    let Some(extra) = item.get("extra") else {
        return (None, None);
    };
    let hit_count = json_u64(extra.get("hitCount"));
    let last_hit = extra
        .get("lastHit")
        .and_then(serde_json::Value::as_str)
        .map(|value| clean_token(value, 60))
        .filter(|value| !value.is_empty());
    (hit_count, last_hit)
}

pub fn parse_log_line(line: &str) -> Option<LogView> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    if line.starts_with('{')
        && let Some(view) = parse_log_json(line)
    {
        return Some(view);
    }
    let level = field_value(line, "level")
        .as_deref()
        .and_then(normalize_level_token)
        .or_else(|| leading_level(line).and_then(normalize_level_token))?;
    let message = field_value(line, "msg").unwrap_or_else(|| line.to_string());
    let message = message.trim();
    if message.is_empty() {
        return None;
    }
    Some(LogView {
        level: level.to_string(),
        message: message.to_string(),
        time_ms: now_ms(),
    })
}

const CONNECTIONS_ERROR: &str = "连接没有读取";

pub fn fetch_connections_with_totals(endpoint: &ControllerEndpoint) -> ConnectionsReading {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return ConnectionsReading {
            error: Some(CONNECTIONS_ERROR.to_string()),
            ..Default::default()
        };
    }
    let url = format!("http://{}:{}/connections", endpoint.host, endpoint.port);
    let agent = controller_agent(Duration::from_millis(800));
    let failure = || ConnectionsReading {
        error: Some(CONNECTIONS_ERROR.to_string()),
        ..Default::default()
    };
    let Ok(response) = authorize(agent.get(&url), endpoint).call() else {
        return failure();
    };
    let mut body = String::new();
    if response
        .into_reader()
        .take(4_000_000)
        .read_to_string(&mut body)
        .is_err()
    {
        return failure();
    }
    read_connections(&body)
}

/// Kernel memory from `/memory`, in bytes. Missing or zero means the kernel did not report it.
pub fn fetch_memory(endpoint: &ControllerEndpoint) -> Option<u64> {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return None;
    }
    let url = format!("http://{}:{}/memory", endpoint.host, endpoint.port);
    // Snapshot polling stays responsive even if the controller stalls.
    let agent = controller_agent(Duration::from_millis(800));
    let response = authorize(agent.get(&url), endpoint).call().ok()?;
    let mut body = String::new();
    response
        .into_reader()
        .take(16_384)
        .read_to_string(&mut body)
        .ok()?;
    let value: serde_json::Value = serde_json::from_str(&body).ok()?;
    memory_inuse(&value)
}

fn memory_inuse(value: &serde_json::Value) -> Option<u64> {
    ["inuse", "heapInuse", "used"]
        .iter()
        .find_map(|key| json_u64(value.get(*key)))
        .filter(|bytes| *bytes > 0)
}

/// One controller sample is `{"up":bytes_per_second,"down":bytes_per_second}`.
pub fn traffic_from_text(text: &str) -> Option<(u64, u64)> {
    let value: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    let up = json_u64(value.get("up"))?;
    let down = json_u64(value.get("down"))?;
    Some((up, down))
}

/// `/traffic` stays open and writes a sample about once a second. The latest pair is kept.
pub fn watch_traffic(
    endpoint: ControllerEndpoint,
    latest: Arc<Mutex<Option<(u64, u64)>>>,
    stop: Arc<AtomicBool>,
) {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return;
    }
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_millis(400))
        .timeout_read(Duration::from_millis(1500))
        .timeout_write(Duration::from_millis(400))
        .redirects(0)
        .try_proxy_from_env(false)
        .build();
    while !stop.load(Ordering::Relaxed) {
        let url = format!("http://{}:{}/traffic", endpoint.host, endpoint.port);
        let request = agent.get(&url).set("User-Agent", "Billow");
        let request = if endpoint.secret.is_empty() {
            request
        } else {
            request.set("Authorization", &format!("Bearer {}", endpoint.secret))
        };
        let Ok(response) = request.call() else {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
            continue;
        };
        let mut reader = response.into_reader().take(1_000_000);
        let mut buf = Vec::new();
        let mut tmp = [0u8; 512];
        loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            match reader.read(&mut tmp) {
                Ok(0) => break,
                Ok(count) => {
                    buf.extend_from_slice(&tmp[..count]);
                    store_traffic_buf(&mut buf, &latest);
                }
                Err(_) => {
                    store_traffic_buf(&mut buf, &latest);
                    break;
                }
            }
        }
    }
}

fn store_traffic_buf(buf: &mut Vec<u8>, latest: &Mutex<Option<(u64, u64)>>) {
    loop {
        let Some(end) = buf.iter().position(|byte| *byte == b'\n') else {
            break;
        };
        let line: Vec<u8> = buf.drain(..=end).collect();
        if let Some(sample) = std::str::from_utf8(&line)
            .ok()
            .and_then(traffic_from_text)
        {
            *latest.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(sample);
        }
    }
    if let Some(sample) = std::str::from_utf8(buf).ok().and_then(traffic_from_text) {
        buf.clear();
        *latest.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(sample);
    }
}

fn json_u64(value: Option<&serde_json::Value>) -> Option<u64> {
    let value = value?;
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|number| u64::try_from(number).ok()))
}

fn sanitize_connection(host: String, outbound: String) -> Option<ConnectionView> {
    let host = clean_token(&host, 200);
    let outbound = clean_token(&outbound, 200);
    if host.is_empty() || outbound.is_empty() {
        return None;
    }
    Some(ConnectionView {
        host,
        outbound,
        ..Default::default()
    })
}

fn clean_token(value: &str, limit: usize) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(limit)
        .collect::<String>()
        .trim()
        .to_string()
}

fn text_field<'a>(value: Option<&'a serde_json::Value>, key: &str) -> Option<&'a str> {
    value
        .and_then(|item| item.get(key))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

fn parse_log_json(line: &str) -> Option<LogView> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let level = value
        .get("level")
        .and_then(serde_json::Value::as_str)
        .or_else(|| value.get("type").and_then(serde_json::Value::as_str))
        .and_then(normalize_level_token)?;
    let message = value
        .get("msg")
        .and_then(serde_json::Value::as_str)
        .or_else(|| value.get("message").and_then(serde_json::Value::as_str))
        .or_else(|| value.get("payload").and_then(serde_json::Value::as_str))?
        .trim();
    if message.is_empty() {
        return None;
    }
    Some(LogView {
        level: level.to_string(),
        message: message.to_string(),
        time_ms: now_ms(),
    })
}

fn normalize_level_token(raw: &str) -> Option<&'static str> {
    match raw.trim().trim_matches('"').to_ascii_lowercase().as_str() {
        "error" | "fatal" | "panic" | "err" => Some("error"),
        "warning" | "warn" => Some("warning"),
        "info" => Some("info"),
        "debug" | "trace" => Some("debug"),
        _ => None,
    }
}

fn field_value(line: &str, key: &str) -> Option<String> {
    let token = format!("{key}=");
    let start = line.find(&token)? + token.len();
    let rest = &line[start..];
    if let Some(quoted) = rest.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = quoted.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
                continue;
            }
            if ch == '"' {
                return Some(out);
            }
            out.push(ch);
        }
        return None;
    }
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

fn leading_level(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        return Some(&rest[..end]);
    }
    let head = trimmed.split(['[', ' ', ':']).next()?;
    if head.len() <= 8 && head.chars().all(|ch| ch.is_ascii_alphabetic()) {
        return Some(head);
    }
    None
}

fn loopback(host: &str) -> bool {
    host == "127.0.0.1" || host.eq_ignore_ascii_case("localhost")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_rows_carry_details_and_filter_on_the_host() {
        let body = r#"{
            "downloadTotal": 9,
            "connections": [
                {
                    "id": "c1",
                    "metadata": {
                        "host": "Example.COM",
                        "dnsMode": "fake-ip",
                        "destinationIP": "1.2.3.4",
                        "sourceIP": "127.0.0.1",
                        "processPath": "/tmp/browser"
                    },
                    "upload": 1,
                    "download": 2,
                    "chains": ["香港节点", "代理"],
                    "rule": "Domain",
                    "rulePayload": "example.com"
                },
                {
                    "metadata": {"host": "", "destinationIP": "9.9.9.9", "dnsMode": "normal"},
                    "chains": ["直连"]
                },
                {
                    "metadata": {"host": "dropped.example", "dnsMode": "redir-host"},
                    "chains": []
                }
            ]
        }"#;
        let rows = connections_from_body(body);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].host, "Example.COM");
        assert_eq!(rows[0].outbound, "香港节点");
        assert_eq!(rows[0].chains, ["香港节点", "代理"]);
        assert_eq!(rows[0].rule, "Domain");
        assert_eq!(rows[0].rule_payload, "example.com");
        assert_eq!(rows[0].process, "browser");
        assert_eq!((rows[0].upload, rows[0].download), (1, 2));
        assert_eq!(rows[1].host, "9.9.9.9");
        assert_eq!(rows[1].outbound, "直连");
        let (_, totals) = connections_and_totals(body);
        assert!(totals.is_none(), "uploadTotal is missing so no totals are reported");

        let filtered = filter_connections(&rows, " example ");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].host, "Example.COM");
        assert_eq!(filtered[0].outbound, "香港节点");
        assert!(filter_connections(&rows, "直连").is_empty());
        assert_eq!(filter_connections(&rows, "  ").len(), 2);
    }

    #[test]
    fn logs_keep_error_warning_and_info_and_a_start_failure_is_an_error() {
        let parsed = [
            parse_log_line(r#"time="t" level=info msg="普通记录""#),
            parse_log_line(r#"time="t" level=warning msg="注意一下""#),
            parse_log_line(r#"time="t" level=error msg="内核没有启动""#),
            parse_log_line(r#"{"type":"debug","payload":"dns lookup example.com"}"#),
            parse_log_line(r#"{"type":"error","payload":"启动失败"}"#),
        ];
        let rows = parsed.into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(rows.len(), 5);
        assert_eq!(rows.iter().filter(|row| row.level == "debug").count(), 1);
        assert!(rows.iter().any(|row| row.message == "启动失败"));
        let mut logs = vec![failure_log("内核没有启动")];
        push_logs(&mut logs, rows);
        assert_eq!(filter_logs(&logs, "错误").len(), filter_logs(&logs, "error").len());
        assert!(filter_logs(&logs, "info").iter().all(|row| row.level == "info"));
        assert!(filter_logs(&logs, "警告").iter().all(|row| row.level == "warning"));
        assert!(filter_logs(&logs, "全部").len() > filter_logs(&logs, "error").len());
        assert_eq!(normalize_log_filter("nope"), "all");
    }

    #[test]
    fn rules_body_is_read_into_type_payload_and_proxy() {
        let rules = rules_from_body(
            r#"{"rules":[{"type":"DomainSuffix","payload":"google.com","proxy":"代理","extra":{"hitCount":7,"lastHit":"2026-11-15T10:00:00Z"}},{"type":"Match","payload":"","proxy":"DIRECT"},{"payload":"x"}]}"#,
        );
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].kind, "DomainSuffix");
        assert_eq!(rules[0].proxy, "代理");
        assert_eq!(rules[0].hit_count, Some(7));
        assert_eq!(rules[0].last_hit.as_deref(), Some("2026-11-15T10:00:00Z"));
        assert_eq!(rules[1].kind, "Match");
        assert_eq!(rules[1].hit_count, None, "a kernel without extra reports no hits");
        assert_eq!(rules[1].last_hit, None);
    }

    #[test]
    fn rule_hits_keep_a_zero_count_and_skip_blank_times() {
        let rules = rules_from_body(
            r#"{"rules":[{"type":"Match","proxy":"DIRECT","extra":{"hitCount":0,"lastHit":""}},{"type":"GeoIP","proxy":"DIRECT","extra":{}},{"type":"Domain","proxy":"DIRECT","extra":{"hitCount":"3","lastHit":7}}]}"#,
        );
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].hit_count, Some(0));
        assert_eq!(rules[0].last_hit, None);
        assert_eq!(rules[1].hit_count, None);
        assert_eq!(rules[2].hit_count, None, "a string count is not a hit number");
        assert_eq!(rules[2].last_hit, None);
    }

    #[test]
    fn connections_keep_the_count_before_the_view_truncates() {
        let body = r#"{"connections":[
            {"metadata":{"host":"a.com","destinationIP":"1.1.1.1"},"chains":["A"]},
            {"metadata":{"host":"b.com","destinationIP":"1.1.1.2"},"chains":["A"]},
            {"metadata":{"host":"c.com","destinationIP":"1.1.1.3"},"chains":["A"]}
        ]}"#;
        let reading = read_connections(body);
        assert_eq!(reading.rows.len(), 3);
        assert_eq!(reading.total, 3);
        assert!(reading.error.is_none());
        let empty = read_connections("{}");
        assert_eq!(empty.total, 0);
        assert!(empty.rows.is_empty() && empty.error.is_none());
        let hostile = read_connections("not-json");
        assert_eq!(hostile, ConnectionsReading::default());
    }

    #[test]
    fn connection_limit_keeps_first_valid_rows_and_full_totals() {
        let mut connections = vec![serde_json::json!({"metadata": {}}); 10];
        connections.extend((0..2000).map(|i| serde_json::json!({
            "id": format!("connection-{i}"),
            "metadata": {"host": format!("{i}.example.com")},
            "chains": ["PROXY"]
        })));
        let body = serde_json::json!({
            "connections": connections,
            "uploadTotal": 1234,
            "downloadTotal": 5678
        }).to_string();
        let reading = read_connections(&body);
        assert_eq!(reading.total, 2010);
        assert_eq!(reading.rows.len(), 500);
        assert_eq!(reading.rows[0].id, "connection-0");
        assert_eq!(reading.rows[499].id, "connection-499");
        assert_eq!(reading.totals, Some(TrafficTotals { upload: 1234, download: 5678 }));
    }

    #[test]
    fn a_missing_controller_is_a_read_error_not_an_empty_list() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let reading = fetch_connections_with_totals(&ControllerEndpoint {
            host: "127.0.0.1".to_string(),
            port,
            secret: String::new(),
        });
        assert!(reading.rows.is_empty());
        assert_eq!(reading.total, 0);
        assert_eq!(reading.error.as_deref(), Some(CONNECTIONS_ERROR));
        let remote = ControllerEndpoint {
            host: "198.51.100.1".to_string(),
            port: 80,
            secret: String::new(),
        };
        assert_eq!(
            fetch_connections_with_totals(&remote).error.as_deref(),
            Some(CONNECTIONS_ERROR)
        );
    }

    #[test]
    fn memory_reads_the_first_reported_byte_count() {
        let value = |text: &str| serde_json::from_str::<serde_json::Value>(text).unwrap();
        assert_eq!(memory_inuse(&value(r#"{"inuse":1024,"oslimit":0}"#)), Some(1024));
        assert_eq!(memory_inuse(&value(r#"{"heapInuse":2048}"#)), Some(2048));
        assert_eq!(memory_inuse(&value(r#"{"used":4096}"#)), Some(4096));
        assert_eq!(memory_inuse(&value(r#"{"inuse":0}"#)), None);
        assert_eq!(memory_inuse(&value("{}")), None);
    }

    #[test]
    fn providers_skip_inline_ones_and_read_counts_and_usage() {
        let proxies: serde_json::Value = serde_json::from_str(
            r#"{"providers":{
                "default":{"vehicleType":"Compatible","proxies":[{}]},
                "机场A":{"vehicleType":"HTTP","proxies":[{},{}],"updatedAt":"2026-11-15T00:00:00Z",
                        "subscriptionInfo":{"Upload":1,"Download":2,"Total":10,"Expire":0}}}}"#,
        )
        .unwrap();
        let rules: serde_json::Value = serde_json::from_str(
            r#"{"providers":{"cn":{"behavior":"Domain","format":"MrsRule","ruleCount":120,"vehicleType":"HTTP"}}}"#,
        )
        .unwrap();
        let list = providers_from_values(&proxies, &rules);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].kind, "proxy");
        assert_eq!(list[0].count, 2);
        assert_eq!((list[0].used, list[0].total, list[0].expire), (Some(3), Some(10), None));
        assert_eq!(list[1].kind, "rule");
        assert_eq!(list[1].count, 120);
        assert_eq!(encode_path("机场 A"), "%E6%9C%BA%E5%9C%BA%20A");
    }

    #[test]
    fn traffic_text_reads_up_and_down_only() {
        assert_eq!(traffic_from_text("{\"up\":4,\"down\":5}\n"), Some((4, 5)));
        assert_eq!(traffic_from_text("  {\"up\":0,\"down\":0}  "), Some((0, 0)));
        assert!(traffic_from_text("{\"upload\":1,\"download\":2}").is_none());
        assert!(traffic_from_text("not-json").is_none());
    }

    #[test]
    fn disabled_rule_keys_normalize_kind_and_keep_duplicate_occurrences() {
        let rules = vec![
            RuleView {
                kind: "DomainSuffix".to_string(),
                payload: "google.com".to_string(),
                proxy: "PROXY".to_string(),
                hit_count: None,
                last_hit: None,
            },
            RuleView {
                kind: "DomainSuffix".to_string(),
                payload: "google.com".to_string(),
                proxy: "PROXY".to_string(),
                hit_count: None,
                last_hit: None,
            },
            RuleView {
                kind: "Match".to_string(),
                payload: String::new(),
                proxy: "DIRECT".to_string(),
                hit_count: None,
                last_hit: None,
            },
        ];
        let keys = rule_keys(&rules);
        assert_eq!(keys[0], "domainsuffix|google.com|PROXY|0");
        assert_eq!(keys[1], "domainsuffix|google.com|PROXY|1");
        assert_eq!(keys[2], "match||DIRECT|0");
    }

    #[test]
    fn runtime_config_drops_only_the_disabled_occurrence_and_keeps_modifiers() {
        let yaml = "\
rules:
  - DOMAIN-SUFFIX,google.com,PROXY
  - DOMAIN-SUFFIX,google.com,PROXY
  - IP-CIDR,1.2.3.0/24,DIRECT,no-resolve
  - MATCH,DIRECT
proxies: []
";
        let mut disabled = BTreeSet::new();
        disabled.insert("domainsuffix|google.com|PROXY|1".to_string());
        let filtered = filter_disabled_rules(yaml, &disabled).unwrap();
        assert!(filtered.contains("google.com,PROXY"), "the first occurrence stays");
        assert_eq!(
            filtered.matches("google.com,PROXY").count(),
            1,
            "only the disabled occurrence is dropped"
        );
        assert!(filtered.contains("1.2.3.0/24,DIRECT,no-resolve"));
        assert!(filtered.contains("MATCH,DIRECT"));

        disabled.insert("match||DIRECT|0".to_string());
        let filtered = filter_disabled_rules(yaml, &disabled).unwrap();
        assert!(!filtered.contains("MATCH,DIRECT"));
        assert!(filtered.contains("1.2.3.0/24,DIRECT,no-resolve"));
    }

    #[test]
    fn rule_parts_ignore_trailing_modifiers_and_match_has_no_payload() {
        assert_eq!(
            config_rule_parts("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve").unwrap(),
            ("IP-CIDR".to_string(), "10.0.0.0/8".to_string(), "DIRECT".to_string())
        );
        assert_eq!(
            config_rule_parts("MATCH,漏网之鱼").unwrap(),
            ("MATCH".to_string(), String::new(), "漏网之鱼".to_string())
        );
        assert!(config_rule_parts("MATCH").is_none());
    }

    #[test]
    fn rule_rows_keep_duplicate_occurrence_and_expose_disabled_rows() {
        let yaml = "\
rules:
  - DOMAIN-SUFFIX,google.com,PROXY
  - DOMAIN-SUFFIX,google.com,PROXY
  - MATCH,DIRECT
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let config = config_rules(&value);
        assert_eq!(config[0].key, "domainsuffix|google.com|PROXY|0");
        assert_eq!(config[1].key, "domainsuffix|google.com|PROXY|1");
        assert_eq!(config[2].key, "match||DIRECT|0");

        // The kernel only returns the kept duplicate after the first one is disabled.
        let kernel = vec![
            RuleView {
                kind: "DomainSuffix".to_string(),
                payload: "google.com".to_string(),
                proxy: "PROXY".to_string(),
                hit_count: Some(4),
                last_hit: Some("2026-11-15T10:00:00Z".to_string()),
            },
            RuleView {
                kind: "Match".to_string(),
                payload: String::new(),
                proxy: "DIRECT".to_string(),
                hit_count: Some(9),
                last_hit: None,
            },
        ];
        let disabled = BTreeSet::from([config[0].key.clone()]);
        let rows = rule_rows(&config, &kernel, &disabled);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].key.as_deref(), Some(config[0].key.as_str()));
        assert!(rows[0].disabled, "the omitted first duplicate stays visible");
        assert_eq!(rows[0].kind, "DOMAIN-SUFFIX");
        assert_eq!(rows[0].hit_count, None);
        assert_eq!(rows[1].key.as_deref(), Some(config[1].key.as_str()));
        assert!(!rows[1].disabled);
        assert_eq!(rows[1].hit_count, Some(4), "hit data follows the kept occurrence");
        assert_eq!(rows[2].key.as_deref(), Some(config[2].key.as_str()));
        assert!(!rows[2].disabled);
        assert_eq!(rows[2].hit_count, Some(9));

        // A non-disabled rule the kernel does not return is not invented.
        let omitted = rule_rows(&config, &kernel[1..], &BTreeSet::new());
        assert_eq!(omitted.len(), 1);
        assert_eq!(omitted[0].kind, "Match");

        // A kernel-only rule has no config key, so the UI cannot toggle it.
        let mut extra = kernel.clone();
        extra.push(RuleView {
            kind: "Process".to_string(),
            payload: "chrome".to_string(),
            proxy: "DIRECT".to_string(),
            hit_count: None,
            last_hit: None,
        });
        let rows = rule_rows(&config, &extra, &BTreeSet::new());
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[2].key, None);
        assert!(!rows[2].disabled);
    }

    #[test]
    fn rule_rows_match_enabled_duplicates_before_stale_disabled_rows() {
        let value = serde_yaml::from_str("rules:\n  - DOMAIN,x.com,A\n  - DOMAIN,x.com,A\n  - DOMAIN,x.com,A\n  - MATCH,DIRECT\n").unwrap();
        let config = config_rules(&value);
        let disabled = BTreeSet::from([config[0].key.clone(), config[2].key.clone()]);
        let mut kernel: Vec<_> = (1..=4).map(|hit| RuleView {
            kind: "Domain".to_string(),
            payload: "x.com".to_string(),
            proxy: "A".to_string(),
            hit_count: Some(hit),
            ..Default::default()
        }).collect();
        kernel.insert(1, RuleView {
            kind: "Match".to_string(),
            proxy: "DIRECT".to_string(),
            hit_count: Some(10),
            ..Default::default()
        });
        let rows = rule_rows(&config, &kernel, &disabled);
        assert_eq!(rows.len(), 5);
        assert_eq!(rows.iter().map(|row| row.hit_count).collect::<Vec<_>>(),
            vec![Some(2), Some(1), Some(3), Some(10), Some(4)]);
        assert!(rows[0].disabled && rows[2].disabled);
        assert!(!rows[1].disabled);
        for (row, rule) in rows.iter().zip(&config) {
            assert_eq!(row.key.as_ref(), Some(&rule.key));
        }
        assert_eq!(rows[4].key, None);
    }

    #[test]
    #[ignore = "manual rule matching benchmark; run with --ignored --nocapture"]
    fn rule_rows_large_catalog_benchmark() {
        let config: Vec<_> = (0..3000)
            .map(|i| ConfigRule {
                key: rule_key("DOMAIN-SUFFIX", &format!("{i}.example.com"), "PROXY", 0),
                kind: "DOMAIN-SUFFIX".to_string(),
                payload: format!("{i}.example.com"),
                proxy: "PROXY".to_string(),
            })
            .collect();
        let kernel: Vec<_> = config.iter().rev().map(|rule| RuleView {
            kind: "DomainSuffix".to_string(),
            payload: rule.payload.clone(),
            proxy: rule.proxy.clone(),
            ..Default::default()
        }).collect();
        let started = std::time::Instant::now();
        let rows = rule_rows(&config, &kernel, &BTreeSet::new());
        eprintln!("rule_rows: 3000 reversed rules in {:?}", started.elapsed());
        assert_eq!(rows.len(), config.len());
        for (row, rule) in rows.iter().zip(&config) {
            assert_eq!(row.key.as_ref(), Some(&rule.key));
            assert_eq!(row.payload, rule.payload);
        }
    }

    #[test]
    fn exported_log_name_is_timestamped_and_writes_the_content() {
        assert_eq!(log_file_name(0), "billow-logs-19700101-000000.log");
        assert_eq!(
            log_file_name(1_700_000_000_000),
            "billow-logs-20231114-221320.log"
        );
        let dir = std::env::temp_dir().join(format!(
            "billow-export-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let path = export_logs(&dir, "line one\nline two\n", 0).unwrap();
        assert_eq!(
            path.file_name().unwrap().to_string_lossy(),
            "billow-logs-19700101-000000.log"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "line one\nline two\n");
        let _ = std::fs::remove_dir_all(&dir);

        let blocker = std::env::temp_dir().join(format!(
            "billow-export-block-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_dir_all(&blocker);
        std::fs::write(&blocker, "file").unwrap();
        assert!(export_logs(&blocker, "x", 0).is_err());
        let _ = std::fs::remove_file(&blocker);
    }
}
