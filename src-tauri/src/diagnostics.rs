use std::io::Read;
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

/// Reads the controller `/connections` body into rows plus the running byte totals.
#[cfg_attr(not(test), allow(dead_code))]
pub fn connections_from_body(text: &str) -> Vec<ConnectionView> {
    connections_and_totals(text).0
}

pub fn connections_and_totals(text: &str) -> (Vec<ConnectionView>, Option<TrafficTotals>) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return (Vec::new(), None);
    };
    let totals = match (
        json_u64(value.get("uploadTotal")),
        json_u64(value.get("downloadTotal")),
    ) {
        (Some(upload), Some(download)) => Some(TrafficTotals { upload, download }),
        _ => None,
    };
    let Some(list) = value.get("connections").and_then(serde_json::Value::as_array) else {
        return (Vec::new(), totals);
    };
    let mut rows = Vec::new();
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
    }
    rows.truncate(500);
    (rows, totals)
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

fn controller_get(endpoint: &ControllerEndpoint, path: &str) -> Result<serde_json::Value, String> {
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

fn encode_path(value: &str) -> String {
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
        .map(|item| RuleView {
            kind: clean_token(item.get("type").and_then(serde_json::Value::as_str).unwrap_or(""), 60),
            payload: clean_token(
                item.get("payload").and_then(serde_json::Value::as_str).unwrap_or(""),
                400,
            ),
            proxy: clean_token(item.get("proxy").and_then(serde_json::Value::as_str).unwrap_or(""), 200),
        })
        .filter(|rule| !rule.kind.is_empty())
        .collect()
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

pub fn fetch_connections_with_totals(
    endpoint: &ControllerEndpoint,
) -> (Vec<ConnectionView>, Option<TrafficTotals>) {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return (Vec::new(), None);
    }
    let url = format!("http://{}:{}/connections", endpoint.host, endpoint.port);
    let agent = controller_agent(Duration::from_millis(800));
    let Ok(response) = authorize(agent.get(&url), endpoint).call() else {
        return (Vec::new(), None);
    };
    let mut body = String::new();
    if response
        .into_reader()
        .take(4_000_000)
        .read_to_string(&mut body)
        .is_err()
    {
        return (Vec::new(), None);
    }
    connections_and_totals(&body)
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
            r#"{"rules":[{"type":"DomainSuffix","payload":"google.com","proxy":"代理"},{"type":"Match","payload":"","proxy":"DIRECT"},{"payload":"x"}]}"#,
        );
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].kind, "DomainSuffix");
        assert_eq!(rules[0].proxy, "代理");
        assert_eq!(rules[1].kind, "Match");
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
}
