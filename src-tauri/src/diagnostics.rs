use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use crate::nodes::ControllerEndpoint;

pub const LOG_LIMIT: usize = 400;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionView {
    pub host: String,
    pub outbound: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogView {
    pub level: String,
    pub message: String,
}

pub fn failure_log(message: &str) -> LogView {
    LogView {
        level: "error".to_string(),
        message: message.trim().to_string(),
    }
}

pub fn normalize_log_filter(filter: &str) -> &'static str {
    match filter.trim().to_ascii_lowercase().as_str() {
        "error" | "错误" => "error",
        "warning" | "warn" | "警告" => "warning",
        "info" | "信息" => "info",
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
        .filter_map(|row| sanitize_connection(row.host, row.outbound))
        .take(300)
        .collect()
}

pub fn push_logs(logs: &mut Vec<LogView>, incoming: impl IntoIterator<Item = LogView>) {
    for line in incoming {
        if !matches!(line.level.as_str(), "error" | "warning" | "info") {
            continue;
        }
        let message = line.message.trim();
        if message.is_empty() {
            continue;
        }
        logs.push(LogView {
            level: line.level,
            message: message.to_string(),
        });
    }
    let overflow = logs.len().saturating_sub(LOG_LIMIT);
    if overflow > 0 {
        logs.drain(0..overflow);
    }
}

/// Controller JSON may include DNS mode, rules, and byte counts. None of those are kept.
pub fn connections_from_body(text: &str) -> Vec<ConnectionView> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(list) = value.get("connections").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    for item in list {
        let metadata = item.get("metadata");
        let host = text_field(metadata, "host")
            .filter(|host| !host.is_empty())
            .or_else(|| text_field(metadata, "destinationIP"))
            .unwrap_or("");
        let outbound = item
            .get("chains")
            .and_then(serde_json::Value::as_array)
            .and_then(|chains| {
                chains
                    .iter()
                    .find_map(|chain| chain.as_str().filter(|value| !value.is_empty()))
            })
            .unwrap_or("");
        if let Some(row) = sanitize_connection(host.to_string(), outbound.to_string()) {
            rows.push(row);
        }
    }
    rows.truncate(300);
    rows
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
    })
}

pub fn fetch_connections(endpoint: &ControllerEndpoint) -> Vec<ConnectionView> {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return Vec::new();
    }
    let url = format!("http://{}:{}/connections", endpoint.host, endpoint.port);
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_millis(400))
        .timeout_read(Duration::from_millis(800))
        .timeout_write(Duration::from_millis(400))
        .redirects(0)
        .try_proxy_from_env(false)
        .build();
    let request = agent.get(&url).set("User-Agent", "Billow");
    let request = if endpoint.secret.is_empty() {
        request
    } else {
        request.set("Authorization", &format!("Bearer {}", endpoint.secret))
    };
    let Ok(response) = request.call() else {
        return Vec::new();
    };
    let mut body = String::new();
    if response
        .into_reader()
        .take(1_000_000)
        .read_to_string(&mut body)
        .is_err()
    {
        return Vec::new();
    }
    connections_from_body(&body)
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
    Some(ConnectionView { host, outbound })
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
    })
}

fn normalize_level_token(raw: &str) -> Option<&'static str> {
    match raw.trim().trim_matches('"').to_ascii_lowercase().as_str() {
        "error" | "fatal" | "panic" | "err" => Some("error"),
        "warning" | "warn" => Some("warning"),
        "info" => Some("info"),
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
    fn connection_rows_keep_only_host_and_outbound_and_filter_on_the_host() {
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
        assert_eq!(
            rows,
            vec![
                ConnectionView {
                    host: "Example.COM".to_string(),
                    outbound: "香港节点".to_string(),
                },
                ConnectionView {
                    host: "9.9.9.9".to_string(),
                    outbound: "直连".to_string(),
                },
            ]
        );
        let encoded = serde_json::to_value(&rows[0]).unwrap();
        let object = encoded.as_object().unwrap();
        assert_eq!(object.len(), 2);
        assert!(object.contains_key("host") && object.contains_key("outbound"));
        let dumped = encoded.to_string();
        assert!(!dumped.contains("dnsMode") && !dumped.contains("rulePayload"));
        assert!(!dumped.contains("fake-ip"));

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
        assert_eq!(rows.len(), 4);
        assert!(rows.iter().all(|row| row.level != "debug"));
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
    fn traffic_text_reads_up_and_down_only() {
        assert_eq!(traffic_from_text("{\"up\":4,\"down\":5}\n"), Some((4, 5)));
        assert_eq!(traffic_from_text("  {\"up\":0,\"down\":0}  "), Some((0, 0)));
        assert!(traffic_from_text("{\"upload\":1,\"download\":2}").is_none());
        assert!(traffic_from_text("not-json").is_none());
    }
}
