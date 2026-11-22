//! T25 control API integration tests: auth, route/status shapes, selection,
//! delay, reload, provider update failure, connection close and streams.
//!
//! Everything runs against the real controller listener with a hand-written
//! HTTP/1.1 client so the exact bytes (status, headers, NDJSON/chunked stream)
//! are what the pinned API returns.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use billow_kernel::{Kernel, Limits};

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

struct Harness {
    kernel: Kernel,
    addr: SocketAddr,
    _dir: Option<PathBuf>,
}

impl Harness {
    fn start(yaml: &str) -> Harness {
        let (kernel, warnings) =
            Kernel::start_from_yaml(yaml, None, Limits::default()).expect("kernel starts");
        assert!(warnings.iter().all(|warning| !warning.contains("external-controller")), "{warnings:?}");
        let (tcp, _, _) = kernel.controller_addrs();
        Harness {
            kernel,
            addr: tcp.expect("controller TCP listener"),
            _dir: None,
        }
    }

    fn start_file(path: PathBuf) -> Harness {
        let (kernel, _) = Kernel::start(&path, None, Limits::default()).expect("kernel starts");
        let (tcp, _, _) = kernel.controller_addrs();
        Harness {
            kernel,
            addr: tcp.expect("controller TCP listener"),
            _dir: path.parent().map(|dir| dir.to_path_buf()),
        }
    }

    fn request(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> HttpResponse {
        request(self.addr, method, path, headers, body)
    }

    fn authed(&self, method: &str, path: &str, body: &str, secret: &str) -> HttpResponse {
        let bearer = format!("Bearer {secret}");
        self.request(method, path, &[("Authorization", &bearer)], body)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.kernel.stop();
    }
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_str(self.body.trim()).unwrap_or_else(|error| {
            panic!("body is not JSON ({error}): {:?}", self.body)
        })
    }
}

fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> HttpResponse {
    let mut stream = TcpStream::connect(addr).expect("connect controller");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body.as_bytes()).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> HttpResponse {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response head");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status line");
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    let mut body = raw[split + 4..].to_vec();
    if headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding") && value.to_ascii_lowercase().contains("chunked")
    }) {
        body = decode_chunked(&body);
    }
    HttpResponse {
        status,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    }
}

fn decode_chunked(mut raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = raw.windows(2).position(|window| window == b"\r\n") else {
            break;
        };
        let size_text = String::from_utf8_lossy(&raw[..line_end]).to_string();
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("0").trim(), 16)
            .unwrap_or(0);
        raw = &raw[line_end + 2..];
        if size == 0 {
            break;
        }
        let take = size.min(raw.len());
        out.extend_from_slice(&raw[..take]);
        raw = raw.get(take + 2..).unwrap_or_default();
    }
    out
}

/// Reads the response head and returns the stream positioned at the body
/// (chunked frames included); used for `/traffic` and `/logs`.
fn open_stream(addr: SocketAddr, path: &str, headers: &[(&str, &str)]) -> (TcpStream, HttpResponse) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    let mut head = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0, "stream closed before the head");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = parse_response(&buffer[..position + 4]);
            let rest = buffer[position + 4..].to_vec();
            // Push already-read body bytes back through a cursor is not
            // possible on a socket; instead read the first frame from the
            // caller-visible body when the server sent it with the head.
            return (stream, HttpResponse { body: String::from_utf8_lossy(&rest).to_string(), ..head });
        }
    }
}

fn read_frame(stream: &mut TcpStream) -> String {
    let mut line = Vec::new();
    let mut chunk = [0u8; 1];
    loop {
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0, "stream ended before a frame");
        line.push(chunk[0]);
        if line.ends_with(b"\r\n") {
            break;
        }
    }
    let size_text = String::from_utf8_lossy(&line).trim().to_string();
    let size = usize::from_str_radix(&size_text, 16).unwrap_or(0);
    assert!(size > 0, "empty chunk");
    let mut body = vec![0u8; size];
    stream.read_exact(&mut body).unwrap();
    let mut trailer = [0u8; 2];
    stream.read_exact(&mut trailer).unwrap();
    String::from_utf8_lossy(&body).to_string()
}

const SECRET: &str = "t25-secret";

fn sample_yaml(mixed: u16, controller: u16) -> String {
    format!(
        "mixed-port: {mixed}\nmode: rule\nlog-level: info\nexternal-controller: 127.0.0.1:{controller}\nsecret: {SECRET}\nproxies:\n  - {{name: n1, type: socks5, server: 127.0.0.1, port: 1}}\n  - {{name: n2, type: http, server: 127.0.0.1, port: 2}}\nproxy-groups:\n  - {{name: Sel, type: select, proxies: [n1, n2, DIRECT]}}\n  - {{name: Fast, type: url-test, proxies: [n1, n2], url: \"http://127.0.0.1:9/\", interval: 3600, lazy: true}}\nrule-providers:\n  rp:\n    type: inline\n    behavior: classical\n    payload: [\"DOMAIN,example.com\"]\nproxy-providers:\n  pp:\n    type: inline\n    payload:\n      - {{name: pn1, type: socks5, server: 127.0.0.1, port: 3}}\nrules:\n  - RULE-SET,rp,DIRECT\n  - MATCH,Sel\n"
    )
}

#[test]
fn auth_routes_and_config_shapes_match_the_pinned_api() {
    let harness = Harness::start(&sample_yaml(free_port(), 0));
    let skill = SECRET;

    // No credentials -> 401 with the pinned JSON error.
    let response = harness.request("GET", "/version", &[], "");
    assert_eq!(response.status, 401);
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert_eq!(response.json()["message"], "Unauthorized");

    // Query tokens only authenticate WebSocket upgrades in pinned.
    let response = harness.request("GET", &format!("/version?token={skill}"), &[], "");
    assert_eq!(response.status, 401);

    // Wrong header forms are rejected like the pinned constant-time compare.
    let response = harness.request("GET", "/version", &[("Authorization", "bearer t25-secret")], "");
    assert_eq!(response.status, 401);
    let response = harness.request(
        "GET",
        "/version",
        &[("Authorization", "Bearer  t25-secret")],
        "",
    );
    assert_eq!(response.status, 401);

    // Authorized version: shape only (this kernel reports its own version).
    let response = harness.authed("GET", "/version", "", skill);
    assert_eq!(response.status, 200);
    let version = response.json();
    assert!(version.get("meta").unwrap().is_boolean());
    assert!(version.get("version").unwrap().is_string());

    // Unknown route without credentials is still 404 (pinned routing happens
    // before the auth middleware).
    let response = harness.request("GET", "/nope", &[], "");
    assert_eq!(response.status, 404);
    assert_eq!(response.body, "404 page not found");
    assert_eq!(
        response.header("content-type"),
        Some("text/plain; charset=utf-8")
    );

    // Known route, wrong method: 405 before auth, with Allow.
    let response = harness.request("POST", "/version", &[], "");
    assert_eq!(response.status, 405);
    assert_eq!(response.header("allow"), Some("GET"));

    // CORS preflight is unauthenticated and follows the pinned headers.
    let response = harness.request(
        "OPTIONS",
        "/version",
        &[
            ("Origin", "http://127.0.0.1:1420"),
            ("Access-Control-Request-Method", "GET"),
            ("Access-Control-Request-Headers", "authorization"),
        ],
        "",
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.header("access-control-allow-origin"), Some("*"));
    assert_eq!(response.header("access-control-allow-methods"), Some("GET"));
    assert_eq!(response.header("access-control-allow-headers"), Some("authorization"));
    assert_eq!(response.header("access-control-max-age"), Some("300"));

    // /configs carries the mixed-port and TUN state Billow reads.
    let response = harness.authed("GET", "/configs", "", skill);
    assert_eq!(response.status, 200);
    let configs = response.json();
    assert_eq!(configs["mixed-port"], harness.kernel.listen_addr().port());
    assert_eq!(configs["tun"]["enable"], false);
    assert_eq!(configs["mode"], "rule");
    assert_eq!(configs["ipv6"], true);

    // /rules maps the matcher name and payload like pinned `Rule.RuleType()`.
    let response = harness.authed("GET", "/rules", "", skill);
    let rules = response.json();
    assert_eq!(rules["rules"][0]["type"], "RuleSet");
    assert_eq!(rules["rules"][0]["payload"], "rp");
    assert_eq!(rules["rules"][0]["proxy"], "DIRECT");
    assert_eq!(rules["rules"][1]["type"], "Match");
    assert_eq!(rules["rules"][1]["size"], -1);

    // /proxies: DIRECT/REJECT builtins, groups, inline and provider nodes.
    let response = harness.authed("GET", "/proxies", "", skill);
    let proxies = &response.json()["proxies"];
    assert_eq!(proxies["DIRECT"]["type"], "Direct");
    assert_eq!(proxies["REJECT"]["type"], "Reject");
    assert_eq!(proxies["Sel"]["type"], "Selector");
    assert_eq!(proxies["Sel"]["now"], "n1");
    assert_eq!(proxies["Sel"]["all"][0], "n1");
    assert_eq!(proxies["Fast"]["type"], "URLTest");
    assert_eq!(proxies["Fast"]["expectedStatus"], "*");
    assert_eq!(proxies["n1"]["type"], "Socks5");
    assert_eq!(proxies["n2"]["type"], "Http");
    // Provider nodes stay under /providers/proxies, like pinned `tunnel.Proxies`.
    assert!(proxies.get("pn1").is_none());
    assert!(proxies["Sel"].get("id").is_none());
    assert!(proxies["n1"].get("id").is_some());

    // Provider maps: real providers plus the Compatible group/default entries.
    let response = harness.authed("GET", "/providers/proxies", "", skill);
    let providers = &response.json()["providers"];
    assert_eq!(providers["pp"]["vehicleType"], "Inline");
    assert_eq!(providers["pp"]["type"], "Proxy");
    assert_eq!(providers["pp"]["proxies"][0]["name"], "pn1");
    assert_eq!(providers["Sel"]["vehicleType"], "Compatible");
    assert_eq!(providers["default"]["vehicleType"], "Compatible");
    let response = harness.authed("GET", "/providers/rules", "", skill);
    let rules = &response.json()["providers"];
    assert_eq!(rules["rp"]["behavior"], "Classical");
    assert_eq!(rules["rp"]["format"], "");
    assert_eq!(rules["rp"]["ruleCount"], 1);
    assert_eq!(rules["rp"]["vehicleType"], "Inline");

    // Missing resources are explicit JSON 404s.
    let response = harness.authed("GET", "/proxies/missing", "", skill);
    assert_eq!(response.status, 404);
    assert_eq!(response.json()["message"], "Resource not found");
    let response = harness.authed("GET", "/providers/proxies/missing", "", skill);
    assert_eq!(response.status, 404);
}

#[test]
fn selection_delay_and_patch() {
    let harness = Harness::start(&sample_yaml(free_port(), 0));
    let skill = SECRET;

    let response = harness.authed("PUT", "/proxies/Sel", r#"{"name":"n2"}"#, skill);
    assert_eq!(response.status, 204);
    let response = harness.authed("GET", "/proxies/Sel", "", skill);
    assert_eq!(response.json()["now"], "n2");

    let response = harness.authed("PUT", "/proxies/Sel", r#"{"name":"missing"}"#, skill);
    assert_eq!(response.status, 400);
    assert_eq!(
        response.json()["message"],
        "Selector update error: proxy not exist"
    );

    // A Selector has no `fixed` state; DELETE is the pinned 400.
    let response = harness.authed("DELETE", "/proxies/Sel", "", skill);
    assert_eq!(response.status, 400);
    assert_eq!(response.json()["message"], "Body invalid");

    // PATCH: the TUN-disable request Billow sends before stopping is a no-op.
    let response = harness.authed("PATCH", "/configs", r#"{"tun":{"enable":false}}"#, skill);
    assert_eq!(response.status, 204);
    let response = harness.authed("PATCH", "/configs", r#"{"tun":{"enable":true}}"#, skill);
    assert_eq!(response.status, 400);
    let response = harness.authed("PATCH", "/configs", r#"{"mixed-port":1}"#, skill);
    assert_eq!(response.status, 400);
    let response = harness.authed("PATCH", "/configs", r#"{"unknown":1}"#, skill);
    assert_eq!(response.status, 400);

    // Delay: timeout is mandatory in pinned.
    let response = harness.authed("GET", "/proxies/DIRECT/delay?url=http://127.0.0.1:9/", "", skill);
    assert_eq!(response.status, 400);
    assert_eq!(response.json()["message"], "Body invalid");
    let response = harness.authed("GET", "/proxies/missing/delay?timeout=500&url=http://127.0.0.1:9/", "", skill);
    assert_eq!(response.status, 404);
    let response = harness.authed("GET", "/proxies/DIRECT/delay?timeout=500&expected=bad&url=http://127.0.0.1:9/", "", skill);
    assert_eq!(response.status, 400);

    // A live local target measures a delay; an unreachable one is 503.
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_addr = target.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = target.accept() {
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
        }
    });
    let response = harness.authed(
        "GET",
        &format!("/proxies/DIRECT/delay?timeout=2000&url=http://{target_addr}/"),
        "",
        skill,
    );
    assert_eq!(response.status, 200, "{}", response.body);
    assert!(response.json()["delay"].as_u64().unwrap() >= 1);
    server.join().unwrap();
    // `expected` is parsed but does not turn a successful HEAD into an error.
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_addr = target.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = target.accept() {
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        }
    });
    let response = harness.authed(
        "GET",
        &format!("/proxies/DIRECT/delay?timeout=2000&expected=204&url=http://{target_addr}/"),
        "",
        skill,
    );
    assert_eq!(response.status, 200, "{}", response.body);
    server.join().unwrap();
    let response = harness.authed(
        "GET",
        "/proxies/n1/delay?timeout=300&url=http://127.0.0.1:9/",
        "",
        skill,
    );
    assert_eq!(response.status, 503);
    assert_eq!(
        response.json()["message"],
        "An error occurred in the delay test"
    );
}

#[test]
fn reload_swaps_generation_and_keeps_the_old_one_on_failure() {
    let mixed = free_port();
    let harness = Harness::start(&sample_yaml(mixed, 0));
    let skill = SECRET;
    let configs = harness.authed("GET", "/configs", "", skill).json();
    assert_eq!(configs["mixed-port"], mixed);

    let reload = |harness: &Harness, yaml: &str| {
        let body = serde_json::json!({ "path": "", "payload": yaml }).to_string();
        harness.authed("PUT", "/configs?force=true", &body, skill)
    };

    // Successful reload: the rule list and runtime selection change.
    let mut next = sample_yaml(mixed, 0);
    next = next.replace("  - MATCH,Sel\n", "  - MATCH,DIRECT\n");
    let response = reload(&harness, &next);
    assert_eq!(response.status, 204, "{}", response.body);
    let rules = harness.authed("GET", "/rules", "", skill).json();
    assert_eq!(rules["rules"][1]["proxy"], "DIRECT");
    let (action, _) = harness.kernel.evaluate("anything.example", None);
    assert_eq!(action, billow_kernel::Action::Direct);

    // Invalid YAML is 400 and keeps the previous generation.
    let response = reload(&harness, "mixed-port: 1\nmode: nope\n");
    assert_eq!(response.status, 400);
    assert!(!response.json()["message"].as_str().unwrap().is_empty());
    let rules = harness.authed("GET", "/rules", "", skill).json();
    assert_eq!(rules["rules"][1]["proxy"], "DIRECT");

    // Moving the listener is refused by name instead of silently keeping a
    // stale `mixed-port`.
    let response = reload(&harness, &sample_yaml(mixed + 1, harness.addr.port()));
    assert_eq!(response.status, 400);
    assert!(response.json()["message"]
        .as_str()
        .unwrap()
        .contains("mixed-port"));

    // Changing the controller listener/secret on reload is refused too.
    let mut other = sample_yaml(mixed, 0);
    other = other.replace(&format!("secret: {SECRET}"), "secret: different");
    let response = reload(&harness, &other);
    assert_eq!(response.status, 400);
    assert!(response.json()["message"].as_str().unwrap().contains("secret"));

    // The old controller still accepts the old secret and the old config.
    let response = harness.authed("GET", "/configs", "", skill);
    assert_eq!(response.status, 200);
    assert_eq!(response.json()["mixed-port"], mixed);
}

#[test]
fn provider_update_failure_keeps_the_old_snapshot() {
    let dir = std::env::temp_dir().join(format!(
        "billow-t25-provider-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("rules.yaml"),
        "payload:\n  - DOMAIN,example.com\n",
    )
    .unwrap();
    let yaml = format!(
        "mixed-port: {}\nexternal-controller: 127.0.0.1:0\nsecret: {SECRET}\nrule-providers:\n  rp:\n    type: file\n    behavior: classical\n    path: rules.yaml\nproxy-providers:\n  pp:\n    type: file\n    path: proxies.yaml\nrules:\n  - RULE-SET,rp,DIRECT\n  - MATCH,DIRECT\n",
        free_port()
    );
    std::fs::write(
        dir.join("proxies.yaml"),
        "proxies:\n  - {name: pn1, type: socks5, server: 127.0.0.1, port: 1}\n",
    )
    .unwrap();
    std::fs::write(dir.join("config.yaml"), &yaml).unwrap();
    let harness = Harness::start_file(dir.join("config.yaml"));
    let skill = SECRET;

    let before = harness.authed("GET", "/providers/rules", "", skill).json();
    assert_eq!(before["providers"]["rp"]["ruleCount"], 1);
    assert_eq!(before["providers"]["rp"]["vehicleType"], "File");
    assert_eq!(before["providers"]["rp"]["format"], "YamlRule");

    // Break the payload, then update: 503 and the old entries stay.
    std::fs::write(dir.join("rules.yaml"), "payload: [not-a-rule]\n").unwrap();
    let response = harness.authed("PUT", "/providers/rules/rp", "", skill);
    assert_eq!(response.status, 503);
    assert!(!response.json()["message"].as_str().unwrap().is_empty());
    let after = harness.authed("GET", "/providers/rules", "", skill).json();
    assert_eq!(after["providers"]["rp"]["ruleCount"], 1);

    // A missing proxy-provider file is a 503 too; the snapshot stays.
    let before = harness.authed("GET", "/providers/proxies/pp", "", skill).json();
    std::fs::remove_file(dir.join("proxies.yaml")).unwrap();
    let response = harness.authed("PUT", "/providers/proxies/pp", "", skill);
    assert_eq!(response.status, 503);
    let after = harness.authed("GET", "/providers/proxies/pp", "", skill).json();
    assert_eq!(after["proxies"], before["proxies"]);

    // Restoring the file makes the update succeed (204).
    std::fs::write(
        dir.join("proxies.yaml"),
        "proxies:\n  - {name: pn1, type: socks5, server: 127.0.0.1, port: 1}\n",
    )
    .unwrap();
    let response = harness.authed("PUT", "/providers/proxies/pp", "", skill);
    assert_eq!(response.status, 204);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn connections_are_listed_with_metadata_and_can_be_closed() {
    let harness = Harness::start(&format!(
        "mixed-port: {}\nexternal-controller: 127.0.0.1:0\nsecret: {SECRET}\nrules:\n  - MATCH,DIRECT\n",
        free_port()
    ));
    let skill = SECRET;
    // A target that holds the tunnel open.
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_addr = target.local_addr().unwrap();
    let held = std::thread::spawn(move || {
        let Ok((mut stream, _)) = target.accept() else {
            return;
        };
        let mut buffer = [0u8; 1024];
        let _ = stream.read(&mut buffer);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        std::thread::sleep(Duration::from_secs(3));
    });

    let mut client = TcpStream::connect(harness.kernel.listen_addr()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    client
        .write_all(
            format!("CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n\r\n").as_bytes(),
        )
        .unwrap();
    let mut head = [0u8; 128];
    let read = client.read(&mut head).unwrap();
    assert!(String::from_utf8_lossy(&head[..read]).starts_with("HTTP/1.1 200"));
    client
        .write_all(b"GET /held HTTP/1.1\r\nHost: held\r\n\r\n")
        .unwrap();

    // Wait until the tracker is registered (the reply is written before the
    // relay loop registers it).
    let mut connections = harness.authed("GET", "/connections", "", skill).json();
    let deadline = Instant::now() + Duration::from_secs(2);
    while connections["connections"].is_null() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
        connections = harness.authed("GET", "/connections", "", skill).json();
    }
    let row = &connections["connections"][0];
    assert_eq!(row["metadata"]["network"], "tcp");
    assert_eq!(row["metadata"]["type"], "HTTPS");
    assert_eq!(row["metadata"]["destinationIP"], "127.0.0.1");
    assert_eq!(
        row["metadata"]["destinationPort"],
        target_addr.port().to_string()
    );
    assert_eq!(row["metadata"]["inboundName"], "DEFAULT-MIXED");
    assert_eq!(row["chains"][0], "DIRECT");
    assert_eq!(row["rule"], "Match");
    assert_eq!(row["rulePayload"], "");
    assert!(row["id"].as_str().unwrap().len() >= 32);
    let id = row["id"].as_str().unwrap().to_string();

    let response = harness.authed("DELETE", &format!("/connections/{id}"), "", skill);
    assert_eq!(response.status, 204);
    // The client sees the tunnel close.
    let mut buffer = [0u8; 64];
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let closed = loop {
        match client.read(&mut buffer) {
            Ok(0) | Err(_) => break true,
            Ok(_) => continue,
        }
    };
    assert!(closed);
    std::thread::sleep(Duration::from_millis(100));
    let after = harness.authed("GET", "/connections", "", skill).json();
    assert!(after["connections"].is_null());

    // DELETE of an unknown id is still 204 (pinned ignores it).
    let response = harness.authed("DELETE", "/connections/not-a-real-id", "", skill);
    assert_eq!(response.status, 204);
    let _ = held.join();
}

#[test]
fn traffic_and_logs_stream_frames() {
    let harness = Harness::start(&sample_yaml(free_port(), 0));
    let bearer = format!("Bearer {SECRET}");
    let (mut stream, head) = open_stream(harness.addr, "/traffic", &[("Authorization", &bearer)]);
    assert_eq!(head.status, 200);
    assert_eq!(head.header("content-type"), Some("application/json"));
    // The first chunk may already share the head read; otherwise read it.
    let first = if head.body.is_empty() {
        read_frame(&mut stream)
    } else {
        decode_chunked(head.body.as_bytes())
            .split(|byte| *byte == b'\n')
            .next()
            .map(|line| String::from_utf8_lossy(line).to_string())
            .unwrap_or_default()
    };
    let frame: serde_json::Value = serde_json::from_str(first.trim()).expect("traffic frame JSON");
    assert!(frame.get("up").unwrap().is_u64());
    assert!(frame.get("down").unwrap().is_u64());
    assert!(frame.get("upTotal").unwrap().is_u64());
    assert!(frame.get("downTotal").unwrap().is_u64());
    drop(stream);

    // A log frame arrives after a kernel event. The invalid reload publishes
    // a warning through the same bus.
    let (mut logs, head) = open_stream(harness.addr, "/logs?level=info", &[("Authorization", &bearer)]);
    assert_eq!(head.status, 200);
    let response = harness.authed(
        "PUT",
        "/configs?force=true",
        r#"{"path":"","payload":"mode: nope\n"}"#,
        SECRET,
    );
    assert_eq!(response.status, 400);
    let line = if head.body.is_empty() {
        read_frame(&mut logs)
    } else {
        String::from_utf8_lossy(&decode_chunked(head.body.as_bytes()))
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    };
    let frame: serde_json::Value = serde_json::from_str(line.trim()).expect("log frame JSON");
    assert!(frame.get("type").unwrap().is_string());
    assert!(frame.get("payload").unwrap().is_string());
}

#[cfg(unix)]
#[test]
fn unix_socket_serves_without_bearer() {
    use std::os::unix::net::UnixStream;
    let socket = std::env::temp_dir().join(format!(
        "billow-t25-{}-{}.sock",
        std::process::id(),
        free_port()
    ));
    let yaml = format!(
        "mixed-port: {}\nexternal-controller-unix: {}\nsecret: {SECRET}\nrules:\n  - MATCH,DIRECT\n",
        free_port(),
        socket.display()
    );
    let (kernel, _) = Kernel::start_from_yaml(&yaml, None, Limits::default()).unwrap();
    let (_, _, unix_path) = kernel.controller_addrs();
    assert_eq!(unix_path.as_deref(), Some(socket.as_path()));

    let mut stream = UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(b"GET /version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let response = parse_response(&raw);
    assert_eq!(response.status, 200, "{}", response.body);
    let mut kernel = kernel;
    kernel.stop().unwrap();
    let _ = std::fs::remove_file(&socket);
}

#[test]
fn cors_allow_origins_is_enforced_when_configured() {
    let yaml = format!(
        "mixed-port: {}\nexternal-controller: 127.0.0.1:0\nsecret: {SECRET}\nexternal-controller-cors: {{allow-origins: [http://allowed.example], allow-private-network: true}}\nrules:\n  - MATCH,DIRECT\n",
        free_port()
    );
    let harness = Harness::start(&yaml);
    let response = harness.request(
        "GET",
        "/version",
        &[("Origin", "http://allowed.example"), ("Authorization", &format!("Bearer {SECRET}"))],
        "",
    );
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header("access-control-allow-origin"),
        Some("http://allowed.example")
    );
    let response = harness.request(
        "GET",
        "/version",
        &[("Origin", "http://denied.example"), ("Authorization", &format!("Bearer {SECRET}"))],
        "",
    );
    assert_eq!(response.status, 200);
    assert!(response.header("access-control-allow-origin").is_none());
    let response = harness.request(
        "OPTIONS",
        "/version",
        &[
            ("Origin", "http://allowed.example"),
            ("Access-Control-Request-Method", "GET"),
            ("Access-Control-Request-Private-Network", "true"),
        ],
        "",
    );
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header("access-control-allow-private-network"),
        Some("true")
    );
}
