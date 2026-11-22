//! T23 proxy-group tests: parsing, member expansion, selection, health checks,
//! persistence and rule targets naming a group.
//!
//! Runtime cases use loopback HTTP CONNECT nodes; a health node answers the
//! probe `HEAD` itself with a configured delay/status, a forwarding node
//! tunnels to the echo endpoint.

#[allow(dead_code)]
mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;

use billow_kernel::config::{Action, EmptyFallback, GroupKind, LoadBalanceStrategy};
use billow_kernel::{Kernel, KernelOptions, Limits};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "billow-groups-{name}-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn start(yaml: &str, base: &std::path::Path, cache: Option<PathBuf>) -> (Kernel, Vec<String>) {
    let loaded = billow_kernel::load_config(yaml, "groups.yaml").expect("configuration loads");
    Kernel::start_with_options(
        &loaded,
        None,
        base.to_path_buf(),
        Limits::default(),
        &KernelOptions { cache_dir: cache },
    )
    .expect("kernel starts")
}

fn config_with(port: u16, proxies: &str, groups: &str, rules: &str) -> String {
    format!(
        "mixed-port: {port}\nlog-level: silent\nproxies:\n{proxies}\nproxy-groups:\n{groups}\nrules:\n{rules}\n"
    )
}

fn http_proxy_line(name: &str, port: u16) -> String {
    format!("  - {{name: {name}, type: http, server: 127.0.0.1, port: {port}}}\n")
}

async fn connect_through(kernel: &Kernel, target: SocketAddr) -> String {
    let authority = target.to_string();
    let (mut stream, _status) = http_connect(kernel.listen_addr(), &authority)
        .await
        .expect("CONNECT through the mixed listener");
    stream
        .write_all(b"ping")
        .await
        .expect("write payload through the tunnel");
    let mut reply = vec![0u8; 8];
    let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut reply))
        .await
        .ok()
        .and_then(|result| result.ok())
        .unwrap_or(0);
    let text = String::from_utf8_lossy(&reply[..read]).to_string();
    let _ = stream.shutdown().await;
    text
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

#[test]
fn every_group_type_parses_with_the_pinned_fields() {
    let yaml = r#"mixed-port: 1
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1080}
  - {name: b, type: socks5, server: 127.0.0.1, port: 1081}
proxy-groups:
  - {name: sel, type: select, proxies: [a, b], default-selected: b, url: 'http://127.0.0.1:9/p', interval: 5, timeout: 100, lazy: false, max-failed-times: 3, expected-status: '200-204/301', hidden: true, icon: 'https://x/i.png', disable-udp: true}
  - {name: auto, type: url-test, proxies: [a, b], tolerance: 50}
  - {name: fb, type: fallback, proxies: [a, b], expected-status: 204}
  - {name: lb, type: load-balance, proxies: [a, b], strategy: round-robin}
  - {name: outer, type: select, proxies: [auto]}
rules:
  - MATCH,outer
"#;
    let loaded = billow_kernel::load_config(yaml, "g.yaml").expect("valid groups load");
    let groups = &loaded.config.proxy_groups;
    assert_eq!(groups.len(), 5);
    assert_eq!(groups[0].kind, GroupKind::Select);
    assert_eq!(groups[0].proxies, ["a", "b"]);
    assert_eq!(groups[0].default_selected.as_deref(), Some("b"));
    assert_eq!(groups[0].interval, 5);
    assert_eq!(groups[0].timeout, 100);
    assert!(!groups[0].lazy);
    assert_eq!(groups[0].max_failed_times, 3);
    assert_eq!(groups[0].expected_status.as_spec(), "200-204/301");
    assert!(groups[0].expected_status.check(202));
    assert!(!groups[0].expected_status.check(302));
    assert!(groups[0].hidden);
    assert_eq!(groups[0].icon, "https://x/i.png");
    assert!(groups[0].disable_udp);
    assert_eq!(groups[1].kind, GroupKind::UrlTest);
    assert_eq!(groups[1].tolerance, 50);
    // Pinned default interval for automatic groups with inline members.
    assert_eq!(groups[1].interval, 300);
    assert_eq!(groups[2].kind, GroupKind::Fallback);
    assert_eq!(groups[2].expected_status.as_spec(), "204");
    assert_eq!(groups[3].strategy, LoadBalanceStrategy::RoundRobin);
    // Forward nested reference; the rule target names the outer group.
    assert_eq!(groups[4].proxies, ["auto"]);
    assert_eq!(loaded.config.rules[0].action, Action::Group(4));
    assert_eq!(loaded.config.action_name(Action::Group(4)), "outer");
    // Defaults recorded as zero; the runtime substitutes 5000 ms / 5 tries.
    assert_eq!(groups[1].timeout, 0);
    assert_eq!(groups[1].max_failed_times, 0);
    assert!(groups[1].lazy);
}

#[test]
fn relay_is_rejected_with_the_pinned_removal_message() {
    let yaml = "mixed-port: 1\nproxy-groups:\n  - {name: old, type: relay, proxies: [DIRECT]}\nrules: ['MATCH,DIRECT']\n";
    let error = billow_kernel::load_config(yaml, "g.yaml").expect_err("relay is gone");
    let text = error.to_string();
    assert!(text.contains("relay"), "{text}");
    assert!(text.contains("dialer-proxy"), "{text}");
}

#[test]
fn unknown_types_missing_members_and_duplicates_fail_by_name() {
    for (yaml, needle) in [
        (
            "mixed-port: 1\nproxy-groups:\n  - {name: g, type: smart, proxies: [DIRECT]}\nrules: ['MATCH,DIRECT']\n",
            "unsupported type: smart",
        ),
        (
            "mixed-port: 1\nproxy-groups:\n  - {name: g, type: select}\nrules: ['MATCH,DIRECT']\n",
            "`use` or `proxies` missing",
        ),
        (
            "mixed-port: 1\nproxy-groups:\n  - {name: g, type: select, proxies: [nope]}\nrules: ['MATCH,DIRECT']\n",
            "'nope' not found",
        ),
        (
            "mixed-port: 1\nproxies:\n  - {name: g, type: socks5, server: 127.0.0.1, port: 1}\nproxy-groups:\n  - {name: g, type: select, proxies: [DIRECT]}\nrules: ['MATCH,DIRECT']\n",
            "duplicate name",
        ),
        (
            "mixed-port: 1\nproxy-groups:\n  - {name: g, type: select, proxies: [h]}\n  - {name: h, type: select, proxies: [g]}\nrules: ['MATCH,DIRECT']\n",
            "loop detected",
        ),
        (
            "mixed-port: 1\nproxy-groups:\n  - {name: g, type: select, proxies: [DIRECT], use: [missing]}\nrules: ['MATCH,DIRECT']\n",
            "'missing' not found",
        ),
        (
            "mixed-port: 1\nproxy-groups:\n  - {name: g, type: load-balance, proxies: [DIRECT], strategy: nope}\nrules: ['MATCH,DIRECT']\n",
            "unsupported strategy",
        ),
        (
            "mixed-port: 1\nproxy-groups:\n  - {name: g, type: load-balance, proxies: [DIRECT], hash-key: in-user}\nrules: ['MATCH,DIRECT']\n",
            "hash-key 'in-user'",
        ),
        (
            "mixed-port: 1\nproxy-groups:\n  - {name: g, type: select, proxies: [DIRECT], expected-status: '2xx'}\nrules: ['MATCH,DIRECT']\n",
            "invalid range",
        ),
        (
            "mixed-port: 1\nproxy-groups:\n  - {name: g, type: select, proxies: [DIRECT], empty-fallback: other}\nrules: ['MATCH,DIRECT']\n",
            "empty fallback proxy 'other' not found",
        ),
    ] {
        let error = billow_kernel::load_config(yaml, "g.yaml")
            .map(|_| String::new())
            .unwrap_or_else(|error| error.to_string());
        assert!(error.contains(needle), "expected {needle:?} in {error:?}");
    }
}

#[test]
fn filters_split_on_backticks_and_types_on_pipe() {
    let yaml = r#"mixed-port: 1
proxy-groups:
  - name: g
    type: select
    proxies: [DIRECT]
    filter: '^HK`^JP'
    exclude-filter: 'expired`test'
    exclude-type: 'ss|SSR'
rules: ['MATCH,DIRECT']
"#;
    let loaded = billow_kernel::load_config(yaml, "g.yaml").expect("filters load");
    let group = &loaded.config.proxy_groups[0];
    assert_eq!(group.filter, ["^HK", "^JP"]);
    assert_eq!(group.exclude_filter, ["expired", "test"]);
    assert_eq!(group.exclude_type, ["ss", "ssr"]);
}

#[test]
fn include_all_expands_sorted_proxy_and_provider_names() {
    let yaml = r#"mixed-port: 1
proxies:
  - {name: Zebra, type: socks5, server: 127.0.0.1, port: 1}
  - {name: Alpha, type: socks5, server: 127.0.0.1, port: 2}
proxy-groups:
  - {name: all, type: select, include-all: true, filter: '^A'}
  - {name: all-no-filter, type: select, include-all-proxies: true}
rules: ['MATCH,DIRECT']
"#;
    let loaded = billow_kernel::load_config(yaml, "g.yaml").expect("include-all loads");
    assert_eq!(loaded.config.proxy_groups[0].proxies, ["Alpha"]);
    // Sorted inline names, matching pinned `slices.Sort(AllProxies)`.
    assert_eq!(
        loaded.config.proxy_groups[1].proxies,
        ["Alpha", "Zebra"]
    );
}

#[test]
fn include_all_proxies_empty_expansion_uses_the_configured_fallback() {
    // Pinned `parser.go` appends `groupOption.EmptyFallback`, not a hard-coded
    // COMPATIBLE. With `empty-fallback: REJECT` the group must block instead
    // of falling back to a direct route.
    let yaml = r#"mixed-port: 1
proxy-groups:
  - {name: blocked, type: select, include-all-proxies: true, empty-fallback: REJECT}
  - {name: plain, type: select, include-all-proxies: true}
  - {name: direct, type: select, include-all-proxies: true, empty-fallback: DIRECT}
rules: ['MATCH,DIRECT']
"#;
    let loaded = billow_kernel::load_config(yaml, "g.yaml").expect("empty expansion loads");
    assert_eq!(loaded.config.proxy_groups[0].proxies, ["REJECT"]);
    assert_eq!(loaded.config.proxy_groups[0].empty_fallback, EmptyFallback::Reject);
    assert_eq!(loaded.config.proxy_groups[1].proxies, ["COMPATIBLE"]);
    assert_eq!(loaded.config.proxy_groups[1].empty_fallback, EmptyFallback::Compatible);
    assert_eq!(loaded.config.proxy_groups[2].proxies, ["DIRECT"]);
    assert_eq!(loaded.config.proxy_groups[2].empty_fallback, EmptyFallback::Direct);
}

#[test]
fn empty_fallback_and_profile_are_parsed() {
    let yaml = r#"mixed-port: 1
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1}
profile:
  store-selected: true
  store-fake-ip: true
proxy-groups:
  - {name: g, type: select, proxies: [a]}
  - {name: h, type: select, proxies: [a], empty-fallback: a}
rules: ['MATCH,g']
"#;
    let loaded = billow_kernel::load_config(yaml, "g.yaml").expect("profile loads");
    assert!(loaded.config.profile.store_selected);
    assert!(loaded.config.profile.store_fake_ip);
    assert_eq!(loaded.config.proxy_groups[0].empty_fallback, EmptyFallback::Compatible);
    assert_eq!(loaded.config.proxy_groups[1].empty_fallback, EmptyFallback::Proxy(0));
    assert!(
        loaded
            .warnings
            .iter()
            .any(|warning| warning.contains("store-fake-ip")),
        "{:?}",
        loaded.warnings
    );
    assert_eq!(loaded.config.rules[0].action, Action::Group(0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filtered_empty_members_use_the_configured_fallback_name() {
    // Pinned `GroupBase.GetProxies` returns `gb.EmptyFallback()`, whose name
    // follows the configured builtin: COMPATIBLE by default, DIRECT when the
    // configuration names it.
    let port = free_port();
    let yaml = config_with(
        port,
        &http_proxy_line("a", 9),
        "  - {name: compat, type: select, proxies: [a], exclude-filter: '^a'}\n  - {name: direct, type: select, proxies: [a], exclude-filter: '^a', empty-fallback: DIRECT}\n",
        "  - MATCH,compat\n",
    );
    let dir = temp_dir("empty-fallback-name");
    let (mut kernel, _) = start(&yaml, &dir, None);
    assert_eq!(
        kernel.groups().group_status("compat").expect("compat").all,
        ["COMPATIBLE"]
    );
    assert_eq!(
        kernel.groups().group_status("direct").expect("direct").all,
        ["DIRECT"]
    );
    assert_eq!(
        kernel.groups().group_status("direct").expect("direct").empty_fallback,
        "DIRECT"
    );
    kernel.stop().expect("stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unknown_rule_outbound_mentions_groups() {
    let yaml = "mixed-port: 1\nrules: ['MATCH,NOT-THERE']\n";
    let error = billow_kernel::load_config(yaml, "g.yaml").expect_err("unknown target");
    let text = error.to_string();
    assert!(text.contains("proxy or proxy group"), "{text}");
}

#[test]
fn provider_dialer_proxy_must_name_an_inline_proxy() {
    let dir = temp_dir("provider-dialer");
    let port = free_port();
    let yaml = format!(
        "mixed-port: {port}\nlog-level: silent\nproxy-providers:\n  remote:\n    type: inline\n    payload:\n      - {{name: p1, type: http, server: 127.0.0.1, port: 9, dialer-proxy: p2}}\n      - {{name: p2, type: http, server: 127.0.0.1, port: 9}}\nproxy-groups:\n  - {{name: G, type: select, use: [remote]}}\nrules:\n  - MATCH,G\n"
    );
    let loaded = billow_kernel::load_config(&yaml, "groups.yaml").expect("provider payload loads");
    let error = Kernel::start_with_options(
        &loaded,
        None,
        dir.clone(),
        Limits::default(),
        &KernelOptions::default(),
    )
    .err()
    .expect("a provider-internal dialer target must not silently dial directly");
    let text = error.to_string();
    assert!(text.contains("dialer-proxy 'p2'"), "{text}");
    assert!(text.contains("not an inline proxy"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Runtime: selection, rule targets, persistence
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rule_targeting_a_group_dials_the_selected_member_and_persists() {
    let echo = spawn_endpoint(EchoMode::Echo).await;
    let node_a = spawn_http_proxy_node(ProxyNodeMode::Forward);
    let node_b = spawn_http_proxy_node(ProxyNodeMode::Forward);
    let port = free_port();
    let yaml = config_with(
        port,
        &format!(
            "{}{}",
            http_proxy_line("node-a", node_a.port),
            http_proxy_line("node-b", node_b.port)
        ),
        &format!(
            "  - {{name: PROXY, type: select, proxies: [node-a, node-b], default-selected: node-a}}\n"
        ),
        "  - MATCH,PROXY\n",
    );
    let dir = temp_dir("select");
    let (mut kernel, _) = start(&yaml, &dir, Some(dir.clone()));
    assert_eq!(
        kernel
            .groups()
            .group_status("PROXY")
            .expect("group status")
            .now,
        "node-a"
    );
    assert_eq!(connect_through(&kernel, format!("127.0.0.1:{}", echo.port).parse().unwrap()).await, "ping");
    assert_eq!(node_a.connections.load(Ordering::Relaxed), 1);
    assert_eq!(node_b.connections.load(Ordering::Relaxed), 0);

    assert!(kernel.select_group("PROXY", "node-b").expect("selection"));
    assert_eq!(connect_through(&kernel, format!("127.0.0.1:{}", echo.port).parse().unwrap()).await, "ping");
    assert_eq!(node_b.connections.load(Ordering::Relaxed), 1);
    let cache = dir.join("cache.yaml");
    assert!(cache.exists(), "the selection cache is written");
    kernel.stop().expect("stop");

    // A new kernel with the same cache directory restores the selection
    // before any traffic (pinned `patchSelectGroup`).
    let (mut kernel, _) = start(&yaml, &dir, Some(dir.clone()));
    assert_eq!(
        kernel
            .groups()
            .group_status("PROXY")
            .expect("group status")
            .now,
        "node-b"
    );
    kernel.stop().expect("stop");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = echo;
}

// ---------------------------------------------------------------------------
// Runtime: health checks and failover
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn url_test_picks_the_lowest_delay_and_falls_back() {
    let echo = spawn_endpoint(EchoMode::Echo).await;
    let slow = spawn_http_proxy_node(ProxyNodeMode::Health {
        delay: Duration::from_millis(200),
        status: 204,
    });
    let fast = spawn_http_proxy_node(ProxyNodeMode::Health {
        delay: Duration::from_millis(5),
        status: 204,
    });
    let port = free_port();
    let url = format!("http://127.0.0.1:{}/generate_204", echo.port);
    let yaml = config_with(
        port,
        &format!(
            "{}{}",
            http_proxy_line("slow", slow.port),
            http_proxy_line("fast", fast.port)
        ),
        &format!(
            "  - {{name: AUTO, type: url-test, proxies: [slow, fast], url: '{url}', interval: 1, lazy: false, timeout: 1000}}\n"
        ),
        "  - MATCH,AUTO\n",
    );
    let dir = temp_dir("urltest");
    let (mut kernel, _) = start(&yaml, &dir, None);
    let groups = kernel.groups().clone();
    let picked = wait_until(Duration::from_secs(10), || {
        groups
            .group_status("AUTO")
            .map(|status| {
                status.now == "fast"
                    && status
                        .members
                        .iter()
                        .all(|member| member.delay.is_some())
            })
            .unwrap_or(false)
    })
    .await;
    let status = groups.group_status("AUTO").expect("status");
    assert!(picked, "url-test must pick the fast node, got {status:?}");
    let slow_health = status
        .members
        .iter()
        .find(|member| member.name == "slow")
        .expect("slow member");
    let fast_health = status
        .members
        .iter()
        .find(|member| member.name == "fast")
        .expect("fast member");
    assert!(slow_health.alive && fast_health.alive, "{status:?}");
    assert!(
        slow_health.delay.unwrap_or(0) > fast_health.delay.unwrap_or(0),
        "{status:?}"
    );
    assert_eq!(
        connect_through(&kernel, format!("127.0.0.1:{}", echo.port).parse().unwrap()).await,
        "ping"
    );
    kernel.stop().expect("stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn url_test_probes_at_startup_with_default_lazy() {
    // Pinned `NewHealthCheck`/`HealthCheck.process` runs `go hc.check()`
    // before the first interval tick even when `lazy` defaults to true (the
    // differential's default configuration omits both `lazy` and `interval`).
    let echo = spawn_endpoint(EchoMode::Echo).await;
    let slow = spawn_http_proxy_node(ProxyNodeMode::Health {
        delay: Duration::from_millis(300),
        status: 204,
    });
    let fast = spawn_http_proxy_node(ProxyNodeMode::Health {
        delay: Duration::from_millis(10),
        status: 204,
    });
    let port = free_port();
    let url = format!("http://127.0.0.1:{}/generate_204", echo.port);
    let yaml = config_with(
        port,
        &format!(
            "{}{}",
            http_proxy_line("slow", slow.port),
            http_proxy_line("fast", fast.port)
        ),
        &format!("  - {{name: AUTO, type: url-test, proxies: [slow, fast], url: '{url}'}}\n"),
        "  - MATCH,AUTO\n",
    );
    let dir = temp_dir("urltest-default-lazy");
    let (mut kernel, _) = start(&yaml, &dir, None);
    let groups = kernel.groups().clone();
    let picked = wait_until(Duration::from_secs(5), || {
        groups
            .group_status("AUTO")
            .map(|status| {
                status.now == "fast"
                    && status
                        .members
                        .iter()
                        .any(|member| member.name == "fast" && member.delay.is_some())
            })
            .unwrap_or(false)
    })
    .await;
    let status = groups.group_status("AUTO").expect("status");
    assert!(
        picked,
        "the startup probe must run despite the default lazy flag: {status:?}"
    );
    assert!(
        status
            .members
            .iter()
            .find(|member| member.name == "slow")
            .and_then(|member| member.delay)
            .is_none_or(|delay| delay > 100),
        "the 300 ms member must not win: {status:?}"
    );
    kernel.stop().expect("stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nested_auto_group_probes_at_startup_and_serves_outer_traffic() {
    // A nested url-test group has its own `HealthCheck`; its startup probe
    // runs independently of the outer selector, and outer dials follow the
    // nested selection.
    let echo = spawn_endpoint(EchoMode::Echo).await;
    let slow = spawn_http_proxy_node(ProxyNodeMode::Health {
        delay: Duration::from_millis(250),
        status: 204,
    });
    let fast = spawn_http_proxy_node(ProxyNodeMode::Health {
        delay: Duration::from_millis(10),
        status: 204,
    });
    let port = free_port();
    let url = format!("http://127.0.0.1:{}/generate_204", echo.port);
    let yaml = config_with(
        port,
        &format!(
            "{}{}",
            http_proxy_line("slow", slow.port),
            http_proxy_line("fast", fast.port)
        ),
        &format!(
            "  - {{name: INNER, type: url-test, proxies: [slow, fast], url: '{url}'}}\n  - {{name: OUTER, type: select, proxies: [INNER]}}\n"
        ),
        "  - MATCH,OUTER\n",
    );
    let dir = temp_dir("nested-default-lazy");
    let (mut kernel, _) = start(&yaml, &dir, None);
    let groups = kernel.groups().clone();
    assert!(wait_until(Duration::from_secs(5), || {
        groups
            .group_status("INNER")
            .map(|status| status.now == "fast")
            .unwrap_or(false)
    })
    .await);
    let before_fast = fast.connections.load(Ordering::Relaxed);
    let before_slow = slow.connections.load(Ordering::Relaxed);
    assert_eq!(
        connect_through(&kernel, format!("127.0.0.1:{}", echo.port).parse().unwrap()).await,
        "ping"
    );
    assert_eq!(fast.connections.load(Ordering::Relaxed), before_fast + 1);
    assert_eq!(slow.connections.load(Ordering::Relaxed), before_slow);
    kernel.stop().expect("stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tolerance_keeps_or_switches_the_previous_fast_node() {
    // Pinned `URLTest.fast`: the first computation sets the fastest member;
    // a later computation keeps it while `previous.delay <= fast.delay +
    // tolerance` (and switches to it when it is the first member, which the
    // pinned `fastNotExist` quirk deliberately treats as "not seen").
    async fn observe(tolerance: u16) -> String {
        let echo = spawn_endpoint(EchoMode::Echo).await;
        // First member: slow on its first probe, then within tolerance of the
        // second member. Second member is constant at 100 ms.
        let changing = spawn_http_proxy_node(ProxyNodeMode::HealthSequence {
            delays: vec![Duration::from_millis(200), Duration::from_millis(90)],
            status: 204,
        });
        let steady = spawn_http_proxy_node(ProxyNodeMode::Health {
            delay: Duration::from_millis(100),
            status: 204,
        });
        let port = free_port();
        let url = format!("http://127.0.0.1:{}/generate_204", echo.port);
        let yaml = config_with(
            port,
            &format!(
                "{}{}",
                http_proxy_line("changing", changing.port),
                http_proxy_line("steady", steady.port)
            ),
            &format!(
                "  - {{name: AUTO, type: url-test, proxies: [changing, steady], url: '{url}', interval: 3, lazy: false, timeout: 1000, tolerance: {tolerance}}}\n"
            ),
            "  - MATCH,AUTO\n",
        );
        let dir = temp_dir(&format!("tolerance-{tolerance}"));
        let (mut kernel, _) = start(&yaml, &dir, None);
        let groups = kernel.groups().clone();
        assert!(wait_until(Duration::from_secs(5), || {
            groups
                .group_status("AUTO")
                .map(|status| {
                    status.now == "steady"
                        && status
                            .members
                            .iter()
                            .all(|member| member.delay.is_some())
                })
                .unwrap_or(false)
        })
        .await, "the first resolution must pick the 100 ms member");
        // The second health round changes the first member to 90 ms.
        tokio::time::sleep(Duration::from_millis(3400)).await;
        let now = groups
            .group_status("AUTO")
            .map(|status| status.now)
            .unwrap_or_default();
        kernel.stop().expect("stop");
        let _ = std::fs::remove_dir_all(&dir);
        now
    }
    assert_eq!(observe(50).await, "steady", "tolerance 50 keeps the previous node");
    assert_eq!(observe(0).await, "changing", "tolerance 0 switches to the faster node");
}

// ---------------------------------------------------------------------------
// Runtime: provider health checks and dialer-proxy chains
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_health_check_probes_at_startup_with_default_lazy() {
    let dir = temp_dir("provider-default-lazy");
    let echo = spawn_endpoint(EchoMode::Echo).await;
    let slow = spawn_http_proxy_node(ProxyNodeMode::Health {
        delay: Duration::from_millis(300),
        status: 204,
    });
    let fast = spawn_http_proxy_node(ProxyNodeMode::Health {
        delay: Duration::from_millis(10),
        status: 204,
    });
    // A file provider with an enabled health check: pinned `baseProvider.Initial`
    // starts `process()`, which checks once immediately even with the default
    // `lazy: true`.
    std::fs::write(
        dir.join("nodes.yaml"),
        format!(
            "proxies:\n  - {{name: slow, type: http, server: 127.0.0.1, port: {}}}\n  - {{name: fast, type: http, server: 127.0.0.1, port: {}}}\n",
            slow.port, fast.port
        ),
    )
    .expect("provider file");
    let port = free_port();
    let url = format!("http://127.0.0.1:{}/generate_204", echo.port);
    let yaml = format!(
        "mixed-port: {port}\nlog-level: silent\nproxy-providers:\n  remote:\n    type: file\n    path: nodes.yaml\n    health-check:\n      enable: true\n      url: '{url}'\nproxy-groups:\n  - {{name: AUTO, type: url-test, use: [remote]}}\nrules:\n  - MATCH,AUTO\n"
    );
    let (mut kernel, _) = start(&yaml, &dir, None);
    let groups = kernel.groups().clone();
    let picked = wait_until(Duration::from_secs(5), || {
        groups
            .group_status("AUTO")
            .map(|status| {
                status.now == "fast"
                    && status
                        .members
                        .iter()
                        .any(|member| member.name == "fast" && member.delay.is_some())
            })
            .unwrap_or(false)
    })
    .await;
    assert!(
        picked,
        "the provider startup check must populate the group's health: {:?}",
        groups.group_status("AUTO")
    );
    kernel.stop().expect("stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_snapshot_update_triggers_a_health_check() {
    let dir = temp_dir("provider-update-health");
    let echo = spawn_endpoint(EchoMode::Echo).await;
    let slow = spawn_http_proxy_node(ProxyNodeMode::Health {
        delay: Duration::from_millis(200),
        status: 204,
    });
    let fast = spawn_http_proxy_node(ProxyNodeMode::Health {
        delay: Duration::from_millis(10),
        status: 204,
    });
    std::fs::write(
        dir.join("nodes.yaml"),
        format!(
            "proxies:\n  - {{name: slow, type: http, server: 127.0.0.1, port: {}}}\n",
            slow.port
        ),
    )
    .expect("provider file");
    let port = free_port();
    let url = format!("http://127.0.0.1:{}/generate_204", echo.port);
    let yaml = format!(
        "mixed-port: {port}\nlog-level: silent\nproxy-providers:\n  remote:\n    type: file\n    path: nodes.yaml\n    health-check:\n      enable: true\n      url: '{url}'\nproxy-groups:\n  - {{name: AUTO, type: url-test, use: [remote]}}\nrules:\n  - MATCH,AUTO\n"
    );
    let (mut kernel, _) = start(&yaml, &dir, None);
    let groups = kernel.groups().clone();
    assert!(wait_until(Duration::from_secs(5), || {
        groups
            .group_status("AUTO")
            .map(|status| status.now == "slow")
            .unwrap_or(false)
    })
    .await);
    std::fs::write(
        dir.join("nodes.yaml"),
        format!(
            "proxies:\n  - {{name: slow, type: http, server: 127.0.0.1, port: {}}}\n  - {{name: fast, type: http, server: 127.0.0.1, port: {}}}\n",
            slow.port, fast.port
        ),
    )
    .expect("provider file update");
    kernel
        .update_proxy_provider("remote")
        .expect("provider update");
    let picked = wait_until(Duration::from_secs(5), || {
        groups
            .group_status("AUTO")
            .map(|status| status.now == "fast")
            .unwrap_or(false)
    })
    .await;
    assert!(
        picked,
        "a provider snapshot swap must probe the new member before url-test ranks it: {:?}",
        groups.group_status("AUTO")
    );
    kernel.stop().expect("stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_probe_uses_the_dialer_proxy_chain() {
    // A probe must dial through the member's full chain; a single-hop dial
    // would bypass the SOCKS5 hop and never connect it.
    let health = spawn_endpoint(EchoMode::Health {
        delay: Duration::ZERO,
        status: 204,
    })
    .await;
    let exit = spawn_socks5_node();
    let hop = spawn_socks5_node();
    let port = free_port();
    let url = format!("http://127.0.0.1:{}/generate_204", health.port);
    let yaml = config_with(
        port,
        &format!(
            "  - {{name: exit, type: socks5, server: 127.0.0.1, port: {}, dialer-proxy: hop}}\n  - {{name: hop, type: socks5, server: 127.0.0.1, port: {}}}\n",
            exit.port, hop.port
        ),
        &format!(
            "  - {{name: AUTO, type: url-test, proxies: [exit], url: '{url}', interval: 1, lazy: false, timeout: 1000}}\n"
        ),
        "  - MATCH,AUTO\n",
    );
    let dir = temp_dir("probe-chain");
    let (mut kernel, _) = start(&yaml, &dir, None);
    let groups = kernel.groups().clone();
    let probed = wait_until(Duration::from_secs(5), || {
        groups
            .group_status("AUTO")
            .and_then(|status| {
                status
                    .members
                    .iter()
                    .find(|member| member.name == "exit")
                    .and_then(|member| member.delay)
            })
            .is_some()
    })
    .await;
    assert!(probed, "the chained probe must succeed");
    assert!(
        hop.connections.load(Ordering::Relaxed) > 0,
        "the probe must enter the dialer-proxy hop"
    );
    assert!(
        exit.connections.load(Ordering::Relaxed) > 0,
        "the exit is reached through the hop"
    );
    kernel.stop().expect("stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fallback_moves_off_a_dead_node() {
    let echo = spawn_endpoint(EchoMode::Echo).await;
    let dead_port = free_port();
    let backup = spawn_http_proxy_node(ProxyNodeMode::Health {
        delay: Duration::ZERO,
        status: 204,
    });
    let port = free_port();
    let url = format!("http://127.0.0.1:{}/generate_204", echo.port);
    let yaml = config_with(
        port,
        &format!(
            "{}{}",
            http_proxy_line("dead", dead_port),
            http_proxy_line("backup", backup.port)
        ),
        &format!(
            "  - {{name: FB, type: fallback, proxies: [dead, backup], url: '{url}', interval: 1, lazy: false, timeout: 500}}\n"
        ),
        "  - MATCH,FB\n",
    );
    let dir = temp_dir("fallback");
    let (mut kernel, _) = start(&yaml, &dir, None);
    let groups = kernel.groups().clone();
    let moved = wait_until(Duration::from_secs(10), || {
        groups
            .group_status("FB")
            .map(|status| {
                status.now == "backup"
                    && status
                        .members
                        .iter()
                        .any(|member| member.name == "dead" && !member.alive)
            })
            .unwrap_or(false)
    })
    .await;
    assert!(moved, "fallback must move to the alive member: {:?}", groups.group_status("FB"));
    assert_eq!(
        connect_through(&kernel, format!("127.0.0.1:{}", echo.port).parse().unwrap()).await,
        "ping"
    );
    kernel.stop().expect("stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nested_group_resolves_to_the_inner_selection() {
    let echo = spawn_endpoint(EchoMode::Echo).await;
    let dead_port = free_port();
    let backup = spawn_http_proxy_node(ProxyNodeMode::Health {
        delay: Duration::ZERO,
        status: 204,
    });
    let port = free_port();
    let url = format!("http://127.0.0.1:{}/generate_204", echo.port);
    let yaml = config_with(
        port,
        &format!(
            "{}{}",
            http_proxy_line("dead", dead_port),
            http_proxy_line("backup", backup.port)
        ),
        &format!(
            "  - {{name: INNER, type: fallback, proxies: [dead, backup], url: '{url}', interval: 1, lazy: false, timeout: 500}}\n  - {{name: OUTER, type: select, proxies: [INNER]}}\n"
        ),
        "  - MATCH,OUTER\n",
    );
    let dir = temp_dir("nested");
    let (mut kernel, _) = start(&yaml, &dir, None);
    let groups = kernel.groups().clone();
    assert_eq!(
        groups.group_status("OUTER").expect("outer").now,
        "INNER",
        "a nested group reports the group name as its current member"
    );
    assert!(wait_until(Duration::from_secs(10), || {
        groups
            .group_status("INNER")
            .map(|status| status.now == "backup")
            .unwrap_or(false)
    })
    .await);
    assert_eq!(
        connect_through(&kernel, format!("127.0.0.1:{}", echo.port).parse().unwrap()).await,
        "ping"
    );
    kernel.stop().expect("stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn load_balance_round_robin_cycles_the_alive_members() {
    let echo = spawn_endpoint(EchoMode::Echo).await;
    // Automatic group types get the pinned default 300 s startup probe; the
    // nodes must answer its HEAD (and still forward ordinary tunnels).
    let node_a = spawn_http_proxy_node(ProxyNodeMode::Health {
        delay: Duration::ZERO,
        status: 204,
    });
    let node_b = spawn_http_proxy_node(ProxyNodeMode::Health {
        delay: Duration::ZERO,
        status: 204,
    });
    let port = free_port();
    let url = format!("http://127.0.0.1:{}/generate_204", echo.port);
    let yaml = config_with(
        port,
        &format!(
            "{}{}",
            http_proxy_line("node-a", node_a.port),
            http_proxy_line("node-b", node_b.port)
        ),
        &format!(
            "  - {{name: LB, type: load-balance, proxies: [node-a, node-b], strategy: round-robin, url: '{url}'}}\n"
        ),
        "  - MATCH,LB\n",
    );
    let dir = temp_dir("lb");
    let (mut kernel, _) = start(&yaml, &dir, None);
    let groups = kernel.groups().clone();
    assert!(wait_until(Duration::from_secs(5), || {
        groups
            .group_status("LB")
            .map(|status| status.members.iter().all(|member| member.delay.is_some()))
            .unwrap_or(false)
    })
    .await);
    let target: SocketAddr = format!("127.0.0.1:{}", echo.port).parse().unwrap();
    for expected in ["a", "b", "a", "b"] {
        let before_a = node_a.connections.load(Ordering::Relaxed);
        let before_b = node_b.connections.load(Ordering::Relaxed);
        connect_through(&kernel, target).await;
        let after_a = node_a.connections.load(Ordering::Relaxed);
        let after_b = node_b.connections.load(Ordering::Relaxed);
        let served = if after_a > before_a {
            "a"
        } else if after_b > before_b {
            "b"
        } else {
            "none"
        };
        assert_eq!(served, expected, "round-robin order");
    }
    // Pinned `LoadBalance.Now()` is empty for the strategy groups.
    assert_eq!(kernel.groups().group_status("LB").expect("status").now, "");
    kernel.stop().expect("stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn load_balance_consistent_hashing_pins_one_destination() {
    let echo = spawn_endpoint(EchoMode::Echo).await;
    let node_a = spawn_http_proxy_node(ProxyNodeMode::Health {
        delay: Duration::ZERO,
        status: 204,
    });
    let node_b = spawn_http_proxy_node(ProxyNodeMode::Health {
        delay: Duration::ZERO,
        status: 204,
    });
    let port = free_port();
    let url = format!("http://127.0.0.1:{}/generate_204", echo.port);
    let yaml = config_with(
        port,
        &format!(
            "{}{}",
            http_proxy_line("node-a", node_a.port),
            http_proxy_line("node-b", node_b.port)
        ),
        &format!("  - {{name: LB, type: load-balance, proxies: [node-a, node-b], url: '{url}'}}\n"),
        "  - MATCH,LB\n",
    );
    let dir = temp_dir("lb-hash");
    let (mut kernel, _) = start(&yaml, &dir, None);
    let groups = kernel.groups().clone();
    assert!(wait_until(Duration::from_secs(5), || {
        groups
            .group_status("LB")
            .map(|status| status.members.iter().all(|member| member.delay.is_some()))
            .unwrap_or(false)
    })
    .await);
    let target: SocketAddr = format!("127.0.0.1:{}", echo.port).parse().unwrap();
    let mut served = Vec::new();
    for _ in 0..4 {
        let before_a = node_a.connections.load(Ordering::Relaxed);
        let before_b = node_b.connections.load(Ordering::Relaxed);
        connect_through(&kernel, target).await;
        if node_a.connections.load(Ordering::Relaxed) > before_a {
            served.push('a');
        } else if node_b.connections.load(Ordering::Relaxed) > before_b {
            served.push('b');
        } else {
            served.push('?');
        }
    }
    assert!(
        served.windows(2).all(|pair| pair[0] == pair[1]),
        "consistent hashing must pin one destination to one member: {served:?}"
    );
    kernel.stop().expect("stop");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Runtime: providers and filters
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn use_provider_members_are_filtered_by_the_group() {
    let dir = temp_dir("provider");
    std::fs::write(
        dir.join("nodes.yaml"),
        "proxies:\n  - {name: Node-A, type: http, server: 127.0.0.1, port: 1}\n  - {name: Node-B, type: http, server: 127.0.0.1, port: 2}\n",
    )
    .expect("provider file");
    let port = free_port();
    let yaml = format!(
        "mixed-port: {port}\nlog-level: silent\nproxy-providers:\n  remote:\n    type: file\n    path: nodes.yaml\nproxy-groups:\n  - {{name: USED, type: select, use: [remote], filter: '^Node-B'}}\nrules:\n  - MATCH,USED\n"
    );
    let (mut kernel, _) = start(&yaml, &dir, None);
    let status = kernel.groups().group_status("USED").expect("status");
    assert_eq!(status.all, ["Node-B"]);
    assert_eq!(status.now, "Node-B");
    kernel.stop().expect("stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exclude_type_compares_the_pinned_adapter_name() {
    let echo = spawn_endpoint(EchoMode::Echo).await;
    let node = spawn_http_proxy_node(ProxyNodeMode::Forward);
    let port = free_port();
    let yaml = config_with(
        port,
        &format!(
            "{}{}",
            http_proxy_line("node-a", node.port),
            format!("  - {{name: socks-a, type: socks5, server: 127.0.0.1, port: {}}}\n", free_port())
        ),
        "  - {name: SEL, type: select, proxies: [node-a, socks-a], exclude-type: 'Http'}\n",
        "  - MATCH,SEL\n",
    );
    let dir = temp_dir("exclude-type");
    let (mut kernel, _) = start(&yaml, &dir, None);
    let status = kernel.groups().group_status("SEL").expect("status");
    assert_eq!(status.all, ["socks-a"], "pinned compares 'Socks5'/'Http'");
    // Selection is now the socks member; the rule still resolves.
    let _ = connect_through(&kernel, format!("127.0.0.1:{}", echo.port).parse().unwrap()).await;
    assert_eq!(node.connections.load(Ordering::Relaxed), 0);
    kernel.stop().expect("stop");
    let _ = std::fs::remove_dir_all(&dir);
}
