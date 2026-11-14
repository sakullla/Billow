use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;

use serde::Serialize;
use serde_yaml::Value;

pub const NEED_PROFILE: &str = "需要先添加或更新配置";
pub const NO_NODES: &str = "还没有可显示的节点。";
pub const NO_MATCH: &str = "没有匹配的节点";
pub const NOT_MANUAL: &str = "不能改选";
pub const KERNEL_DOWN: &str = "内核没有运行";
pub const SELECT_FAILED: &str = "节点没有切换";

const CONTROLLER_PORT: u16 = 17690;
const CONTROLLER_SECRET: &str = "billow-local";
const DELAY_URL: &str = "http://www.gstatic.com/generate_204";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDelay {
    pub name: String,
    pub delay_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedGroup {
    pub name: String,
    pub manual: bool,
    pub proxies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NodeItemView {
    pub name: String,
    pub delay_ms: Option<u64>,
    pub failed: bool,
    pub selected: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NodeGroupView {
    pub name: String,
    pub kind: String,
    pub now: String,
    pub sort: String,
    pub nodes: Vec<NodeItemView>,
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
        });
    }
    parsed
}

pub fn sorted_nodes(nodes: Vec<NodeItemView>, sort: &str) -> Vec<NodeItemView> {
    let mut indexed: Vec<(usize, NodeItemView)> = nodes.into_iter().enumerate().collect();
    match sort {
        "name" => indexed.sort_by(|left, right| {
            left.1
                .name
                .to_lowercase()
                .cmp(&right.1.name.to_lowercase())
                .then(left.0.cmp(&right.0))
        }),
        "delay" => indexed
            .sort_by(|left, right| delay_key(&left.1, left.0).cmp(&delay_key(&right.1, right.0))),
        _ => {}
    }
    indexed.into_iter().map(|(_, node)| node).collect()
}

fn delay_key(node: &NodeItemView, index: usize) -> (u8, u64, usize) {
    if node.delay_ms.is_some() && !node.failed {
        (0, node.delay_ms.unwrap_or(0), index)
    } else if node.failed {
        (2, 0, index)
    } else {
        (1, 0, index)
    }
}

/// Name filtering hides rows only. An empty result means nothing matched.
pub fn filter_visible(mut groups: Vec<NodeGroupView>, query: &str) -> (Vec<NodeGroupView>, bool) {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return (groups, false);
    }
    for group in &mut groups {
        group
            .nodes
            .retain(|node| node.name.to_lowercase().contains(&query));
    }
    groups.retain(|group| !group.nodes.is_empty());
    let none = groups.is_empty();
    (groups, none)
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

pub fn patch_mode(endpoint: &ControllerEndpoint, mode: &str) -> Result<(), String> {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return Err("模式没有切换".to_string());
    }
    let mode = match mode {
        "rule" | "global" | "direct" => mode,
        _ => return Err("模式没有切换".to_string()),
    };
    let url = format!("http://{}:{}/configs", endpoint.host, endpoint.port);
    let body = format!("{{\"mode\":\"{mode}\"}}");
    let agent = agent(Duration::from_millis(800));
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
        Err(_) => Err("模式没有切换".to_string()),
    }
}

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
    let agent = agent(Duration::from_millis(800));
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
        Err(_) => Err(SELECT_FAILED.to_string()),
    }
}

pub fn fetch_delays(
    endpoint: &ControllerEndpoint,
    nodes: &[String],
) -> Result<Vec<NodeDelay>, String> {
    if !loopback(&endpoint.host) || endpoint.port == 0 {
        return Err(KERNEL_DOWN.to_string());
    }
    let mut out = Vec::new();
    let mut saw_controller = false;
    for name in nodes {
        match delay_one(endpoint, name) {
            Ok(ms) => {
                saw_controller = true;
                out.push(NodeDelay {
                    name: name.clone(),
                    delay_ms: Some(ms),
                });
            }
            Err(ProbeFail::Node) => {
                saw_controller = true;
                out.push(NodeDelay {
                    name: name.clone(),
                    delay_ms: None,
                });
            }
            Err(ProbeFail::Unavailable) if !saw_controller => return Err(KERNEL_DOWN.to_string()),
            Err(ProbeFail::Unavailable) => out.push(NodeDelay {
                name: name.clone(),
                delay_ms: None,
            }),
        }
    }
    Ok(out)
}

pub fn fetch_now(endpoint: &ControllerEndpoint) -> Result<BTreeMap<String, String>, String> {
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
    let text = read_body(response).map_err(|_| KERNEL_DOWN.to_string())?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| KERNEL_DOWN.to_string())?;
    let mut out = BTreeMap::new();
    let Some(proxies) = value.get("proxies").and_then(serde_json::Value::as_object) else {
        return Ok(out);
    };
    for (name, item) in proxies {
        if let Some(now) = item.get("now").and_then(serde_json::Value::as_str) {
            if !now.is_empty() {
                out.insert(name.clone(), now.to_string());
            }
        }
    }
    Ok(out)
}

enum ProbeFail {
    Unavailable,
    Node,
}

fn delay_one(endpoint: &ControllerEndpoint, name: &str) -> Result<u64, ProbeFail> {
    let url = format!(
        "http://{}:{}/proxies/{}/delay?timeout=5000&url={}",
        endpoint.host,
        endpoint.port,
        encode_segment(name),
        encode_segment(DELAY_URL)
    );
    let agent = agent(Duration::from_millis(7000));
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
    use std::io::{Read, Write};
    use std::net::TcpListener;
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
    proxies:
      - one
      - two
      - DIRECT
      - one
  - name: auto
    type: url-test
    proxies:
      - one
      - two
  - name: all
    type: selector
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
    }

    #[test]
    fn sort_and_filter_only_change_the_view() {
        let nodes = vec![
            item("z-node", Some(20), false),
            item("m-node", None, true),
            item("a-node", Some(5), false),
        ];
        let by_delay = sorted_nodes(nodes.clone(), "delay");
        assert_eq!(names(&by_delay), ["a-node", "z-node", "m-node"]);
        assert!(by_delay[2].failed);
        let by_name = sorted_nodes(nodes.clone(), "name");
        assert_eq!(names(&by_name), ["a-node", "m-node", "z-node"]);
        let original = sorted_nodes(nodes, "default");
        assert_eq!(names(&original), ["z-node", "m-node", "a-node"]);

        let groups = vec![NodeGroupView {
            name: "manual".to_string(),
            kind: "manual".to_string(),
            now: "z-node".to_string(),
            sort: "default".to_string(),
            nodes: original,
        }];
        let (matched, none) = filter_visible(groups.clone(), "a-n");
        assert!(!none);
        assert_eq!(names(&matched[0].nodes), ["a-node"]);
        let (empty, none) = filter_visible(groups.clone(), "missing");
        assert!(none && empty.is_empty());
        assert_eq!(groups[0].nodes.len(), 3);
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
        assert_eq!(delays[0].delay_ms, Some(12));
        assert_eq!(delays[1].delay_ms, None);
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

    fn item(name: &str, delay_ms: Option<u64>, failed: bool) -> NodeItemView {
        NodeItemView {
            name: name.to_string(),
            delay_ms,
            failed,
            selected: false,
        }
    }

    fn names(nodes: &[NodeItemView]) -> Vec<&str> {
        nodes.iter().map(|node| node.name.as_str()).collect()
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
}
