use std::net::{IpAddr, Ipv4Addr};

use billow_kernel::config::{
    parse_rule, Action, InType, Matcher, NetworkKind, PortKind, ProcessKind, RuleBehavior,
    RuleFormat, RulesSource,
};
use billow_kernel::load_config;

fn err_tag(yaml: &str) -> String {
    match load_config(yaml, "test.yaml") {
        Ok(_) => "ok".to_string(),
        Err(e) => format!("{}: {e}", e.tag()),
    }
}

#[test]
fn accepts_the_implemented_subset() {
    let loaded = load_config(
        "mixed-port: 17890\nallow-lan: false\nbind-address: 127.0.0.1\nmode: rule\nlog-level: info\nrules:\n  - DOMAIN,www.example.com,\"REJECT\"\n  - DOMAIN-SUFFIX,example.org,DIRECT\n  - IP-CIDR,10.0.0.0/8,REJECT,no-resolve\n  - IP-CIDR6,2001:db8::/32,DIRECT\n  - MATCH,DIRECT\n",
        "test.yaml",
    )
    .expect("valid subset accepted");
    assert_eq!(loaded.config.listen, "127.0.0.1:17890".parse().unwrap());
    assert_eq!(loaded.config.rules.len(), 5);
    assert_eq!(
        loaded.config.rules[0].matcher,
        Matcher::Domain("www.example.com".to_string())
    );
    assert_eq!(loaded.config.rules[0].action, Action::Reject);
    assert!(loaded.config.rules[2].no_resolve);
    assert!(loaded.config.digest.starts_with("sha256:"));
}

#[test]
fn defaults_to_mihomo_port_and_loopback() {
    let loaded = load_config("rules: ['MATCH,DIRECT']\n", "t").unwrap();
    assert_eq!(loaded.config.listen.port(), 7890);
    assert!(loaded.config.listen.ip().is_loopback());
}

#[test]
fn rejects_every_unimplemented_top_level_key() {
    for key in [
        "listeners",
        "tunnels",
        "external-controller-pipe",
        "experimental",
        "skip-auth-prefixes",
        "global-client-fingerprint",
    ] {
        let yaml = format!("{key}: {{}}\nmixed-port: 1\n");
        assert!(
            err_tag(&yaml).starts_with("unsupported"),
            "{key} must be rejected, got {}",
            err_tag(&yaml)
        );
    }
}

#[test]
fn billow_launcher_keys_are_inert_or_named() {
    // Billow's `apply_settings` injects these into every Android/desktop
    // artifact. The disabled/neutral forms must keep the file loadable while
    // the tuning they request is named as a gap; a value that would need the
    // missing implementation is still a named rejection.
    let loaded = load_config(
        "mixed-port: 1\nredir-port: 0\ntproxy-port: 0\nunified-delay: true\ntcp-concurrent: true\nfind-process-mode: off\nkeep-alive-interval: 30\ndisable-keep-alive: false\n",
        "test.yaml",
    )
    .expect("Billow launcher keys load");
    let warnings = loaded.warnings.join("\n");
    for needle in [
        "redir-port 0",
        "tproxy-port 0",
        "unified-delay",
        "tcp-concurrent",
        "find-process-mode is off",
        "keep-alive-interval 30s",
        "disable-keep-alive",
    ] {
        assert!(warnings.contains(needle), "missing warning '{needle}': {warnings}");
    }
    for yaml in [
        "mixed-port: 1\nredir-port: 7892\n",
        "mixed-port: 1\ntproxy-port: 7893\n",
        "mixed-port: 1\nfind-process-mode: always\n",
    ] {
        assert!(err_tag(yaml).starts_with("unsupported"), "{yaml}: {}", err_tag(yaml));
    }
}

#[test]
fn controller_listeners_secret_and_cors_are_parsed() {
    let yaml = "mixed-port: 1\nexternal-controller: 127.0.0.1:9090\nexternal-controller-unix: /tmp/billow.sock\nexternal-controller-tls: 127.0.0.1:9443\nsecret: s3cr3t\nexternal-controller-cors: {allow-origins: [http://localhost:1420], allow-private-network: false}\n";
    let loaded = load_config(yaml, "test.yaml").expect("controller shape");
    let controller = &loaded.config.controller;
    assert_eq!(controller.external_controller.as_deref(), Some("127.0.0.1:9090"));
    assert_eq!(
        controller.external_controller_unix.as_deref(),
        Some(std::path::Path::new("/tmp/billow.sock"))
    );
    assert_eq!(controller.external_controller_tls.as_deref(), Some("127.0.0.1:9443"));
    assert_eq!(controller.secret, "s3cr3t");
    assert_eq!(controller.cors.allow_origins, ["http://localhost:1420"]);
    assert!(!controller.cors.allow_private_network);
    // Pinned defaults: any origin, private-network preflights allowed.
    let defaults = load_config("mixed-port: 1\nexternal-controller: 127.0.0.1:0\n", "test.yaml")
        .unwrap()
        .config
        .controller
        .clone();
    assert_eq!(defaults.cors.allow_origins, ["*"]);
    assert!(defaults.cors.allow_private_network);
    // A malformed address names the key and fails at load time.
    assert!(err_tag("mixed-port: 1\nexternal-controller: 9090\n").starts_with("invalid_value"));
}

#[test]
fn rejects_unimplemented_rule_types_and_outbounds() {
    for line in [
        "UID,1000,DIRECT",
        "DSCP,4,DIRECT",
        "IN-USER,alice,DIRECT",
        "IN-NAME,DEFAULT-MIXED,DIRECT",
        "REMATCH-NAME,x,DIRECT",
    ] {
        let yaml = format!("rules: ['{line}']\n");
        assert!(
            err_tag(&yaml).starts_with("unsupported"),
            "{line} must be rejected, got {}",
            err_tag(&yaml)
        );
    }
    // A rule naming a proxy that `proxies` does not define is not a group support claim.
    assert!(err_tag("rules: ['DOMAIN,a.example,Proxy']\n").starts_with("unsupported"));
    // PASS markers are a sub-rule concern this slice does not implement.
    assert!(err_tag("rules: ['MATCH,PASS']\n").starts_with("unsupported"));
    // Unknown parameters are named instead of silently ignored.
    assert!(err_tag("rules: ['DOMAIN,a.example,DIRECT,src']\n").starts_with("unsupported"));
}

#[test]
fn parses_the_pinned_rule_types() {
    let rule = parse_rule("DOMAIN-KEYWORD,EeXample,REJECT").unwrap();
    assert_eq!(rule.matcher, Matcher::DomainKeyword("eexample".into()));
    let rule = parse_rule("DOMAIN-WILDCARD,*.Example.com,DIRECT").unwrap();
    assert_eq!(rule.matcher, Matcher::DomainWildcard("*.example.com".into()));
    assert!(parse_rule("DOMAIN-REGEX,^ads?\\.example$,REJECT").is_ok());
    let rule = parse_rule("DST-PORT,80/443,REJECT").unwrap();
    assert_eq!(
        rule.matcher,
        Matcher::Port {
            kind: PortKind::Dst,
            ranges: vec![(80, 80), (443, 443)]
        }
    );
    let rule = parse_rule("SRC-PORT,1000-2000,DIRECT").unwrap();
    assert_eq!(
        rule.matcher,
        Matcher::Port {
            kind: PortKind::Src,
            ranges: vec![(1000, 2000)]
        }
    );
    let rule = parse_rule("IN-PORT,7890,DIRECT").unwrap();
    assert!(matches!(
        rule.matcher,
        Matcher::Port {
            kind: PortKind::In,
            ..
        }
    ));
    assert_eq!(
        parse_rule("NETWORK,udp,DIRECT").unwrap().matcher,
        Matcher::Network(NetworkKind::Udp)
    );
    assert_eq!(
        parse_rule("IN-TYPE,SOCKS/DIRECT".trim_end_matches("/DIRECT").to_string().as_str())
            .unwrap_err()
            .tag(),
        "invalid_value"
    );
    let rule = parse_rule("IN-TYPE,HTTP/SOCKS,DIRECT").unwrap();
    assert_eq!(
        rule.matcher,
        Matcher::InType(vec![InType::Http, InType::Socks5])
    );
    assert_eq!(
        parse_rule("PROCESS-NAME,curl,DIRECT").unwrap().matcher,
        Matcher::Process {
            kind: ProcessKind::Name,
            pattern: "curl".into(),
            regex: false
        }
    );
    assert!(parse_rule("PROCESS-NAME-REGEX,^cur[lL]$,DIRECT").is_ok());
    assert_eq!(
        parse_rule("PROCESS-NAME-WILDCARD,cu*rl,DIRECT").unwrap().matcher,
        Matcher::ProcessWildcard {
            kind: ProcessKind::Name,
            pattern: "cu*rl".into()
        }
    );
    assert_eq!(
        parse_rule("PROCESS-PATH-WILDCARD,/usr/bin/*,DIRECT").unwrap().matcher,
        Matcher::ProcessWildcard {
            kind: ProcessKind::Path,
            pattern: "/usr/bin/*".into()
        }
    );
    assert_eq!(
        parse_rule("SRC-IP-CIDR,10.0.0.0/8,DIRECT").unwrap().matcher,
        Matcher::IpCidr {
            net: "10.0.0.0/8".parse().unwrap(),
            source: true,
            no_resolve: true
        }
    );
    assert_eq!(
        parse_rule("IP-SUFFIX,0.0.0.1/32,DIRECT").unwrap().matcher,
        Matcher::IpSuffix {
            net: "0.0.0.1/32".parse().unwrap(),
            source: false,
            no_resolve: false
        }
    );
    assert_eq!(
        parse_rule("GEOIP,CN,DIRECT,no-resolve").unwrap().matcher,
        Matcher::GeoIp {
            country: "cn".into(),
            source: false,
            no_resolve: true
        }
    );
    assert_eq!(
        parse_rule("SRC-GEOIP,CN,DIRECT").unwrap().matcher,
        Matcher::GeoIp {
            country: "cn".into(),
            source: true,
            no_resolve: true
        }
    );
    assert_eq!(
        parse_rule("IP-ASN,13335,DIRECT").unwrap().matcher,
        Matcher::IpAsn {
            asn: "13335".into(),
            source: false,
            no_resolve: false
        }
    );
    assert!(parse_rule("IP-ASN,AS13335,DIRECT").is_err());
    assert_eq!(
        parse_rule("GEOSITE,cn,DIRECT").unwrap().matcher,
        Matcher::GeoSite("cn".into())
    );
    assert_eq!(
        parse_rule("MATCH,REJECT-DROP").unwrap().action,
        Action::RejectDrop
    );
}

#[test]
fn logic_and_sub_rule_shapes_are_parsed() {
    let yaml = r#"
mixed-port: 1
sub-rules:
  branch:
    - DOMAIN,inside.example,DIRECT
    - MATCH,REJECT
rules:
  - AND,((DOMAIN,a.example),(NETWORK,TCP)),REJECT
  - OR,((DOMAIN,b.example),(DST-PORT,443)),DIRECT
  - NOT,((DOMAIN-SUFFIX,ok.example)),REJECT
  - SUB-RULE,(NETWORK,TCP),branch
  - MATCH,DIRECT
"#;
    let loaded = load_config(yaml, "test.yaml").unwrap();
    assert!(matches!(loaded.config.rules[0].matcher, Matcher::And(_)));
    assert!(matches!(loaded.config.rules[1].matcher, Matcher::Or(_)));
    assert!(matches!(loaded.config.rules[2].matcher, Matcher::Not(_)));
    assert!(matches!(
        loaded.config.rules[3].matcher,
        Matcher::SubRule { .. }
    ));
    assert_eq!(loaded.config.sub_rules.len(), 1);

    // An unknown sub-rule name fails like Mihomo's parser.
    assert!(err_tag(
        "sub-rules: {b: ['MATCH,DIRECT']}\nrules: ['SUB-RULE,(NETWORK,TCP),missing']\n"
    )
    .starts_with("invalid_value"));
    // A cycle is rejected before the kernel starts.
    assert!(err_tag(
        "sub-rules:\n  a: ['SUB-RULE,(NETWORK,TCP),b']\n  b: ['SUB-RULE,(NETWORK,TCP),a']\n"
    )
    .starts_with("invalid_value"));
    // NOT must contain one rule.
    assert!(err_tag("rules: ['NOT,((DOMAIN,a),(DOMAIN,b)),DIRECT']\n").starts_with("invalid_value"));
}

#[test]
fn rule_providers_are_parsed_with_all_vehicles_and_formats() {
    let yaml = r#"
mixed-port: 1
rule-providers:
  inline-domain:
    type: inline
    behavior: domain
    payload: ['+.example.com', 'plain.example']
  file-ip:
    type: file
    behavior: ipcidr
    format: text
    path: ./providers/ip.txt
    interval: 60
  mrs-rules:
    type: http
    behavior: classical
    format: mrs
    url: https://example.invalid/rules.mrs
    path: ./cache/rules.mrs
    header:
      Authorization: token
    size-limit: 1024
rules:
  - RULE-SET,inline-domain,REJECT
  - RULE-SET,file-ip,DIRECT,no-resolve
  - RULE-SET,mrs-rules,DIRECT
  - MATCH,DIRECT
"#;
    let loaded = load_config(yaml, "test.yaml").unwrap();
    assert_eq!(loaded.config.rule_providers.len(), 3);
    let inline = &loaded.config.rule_providers[0];
    assert_eq!(inline.behavior, RuleBehavior::Domain);
    assert_eq!(inline.format, RuleFormat::Yaml);
    assert_eq!(inline.payload, ["+.example.com", "plain.example"]);
    let file = &loaded.config.rule_providers[1];
    assert_eq!(file.format, RuleFormat::Text);
    assert_eq!(file.interval, Some(std::time::Duration::from_secs(60)));
    let mrs = &loaded.config.rule_providers[2];
    assert_eq!(mrs.format, RuleFormat::Mrs);
    assert_eq!(mrs.header, [("Authorization".to_string(), "token".to_string())]);

    // An undefined RULE-SET target is a configuration failure, not a runtime miss.
    assert!(err_tag("rules: ['RULE-SET,missing,DIRECT']\n").starts_with("invalid_value"));
    assert!(err_tag(
        "rule-providers: {p: {type: inline, behavior: nope, payload: []}}\n"
    )
    .starts_with("unsupported"));
    assert!(err_tag(
        "rule-providers: {p: {type: noop, behavior: domain, payload: []}}\n"
    )
    .starts_with("unsupported"));
}

#[test]
fn proxy_providers_parse_filters_and_health_checks() {
    let yaml = r#"
mixed-port: 1
proxy-providers:
  sub:
    type: http
    url: https://example.invalid/sub.yaml
    path: ./cache/sub.yaml
    filter: '^(HK|JP)'
    exclude-filter: 'expired'
    exclude-type: ssr
    dialer-proxy: hop
    interval: 3600
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 300
      timeout: 5
      lazy: false
      expected-status: 204
proxies:
  - {name: hop, type: socks5, server: 127.0.0.1, port: 1080}
rules: ['MATCH,DIRECT']
"#;
    let loaded = load_config(yaml, "test.yaml").unwrap();
    let provider = &loaded.config.proxy_providers[0];
    assert_eq!(provider.filter.as_deref(), Some("^(HK|JP)"));
    assert_eq!(provider.exclude_type, ["ssr"]);
    assert_eq!(provider.dialer_proxy.as_deref(), Some("hop"));
    assert!(provider.health_check.enable);
    assert_eq!(provider.health_check.expected_status, "204");
    assert!(!provider.health_check.lazy);
}

#[test]
fn proxy_providers_follow_the_pinned_filter_override_and_bundle_schema() {
    // Pinned `NewProxiesParser`: filters split on a backtick, exclude-type on
    // `|`; `override` and `age-secret-key` are declared fields.
    let yaml = r#"
mixed-port: 1
proxy-providers:
  sub:
    type: inline
    payload:
      - {name: HK-1, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-256-gcm, password: p}
    filter: '^HK`^JP'
    exclude-filter: 'expired`test'
    exclude-type: ss|ssr
    override:
      udp: true
      skip-cert-verify: true
      dialer-proxy: hop
      additional-prefix: '[p] '
      additional-suffix: ' +'
      proxy-name:
        - pattern: 'HK'
          target: 'HongKong'
rules: ['MATCH,DIRECT']
"#;
    let loaded = load_config(yaml, "test.yaml").unwrap();
    let provider = &loaded.config.proxy_providers[0];
    assert_eq!(provider.exclude_type, ["ss", "ssr"]);
    assert_eq!(provider.overrides.udp, Some(true));
    assert_eq!(provider.overrides.skip_cert_verify, Some(true));
    assert_eq!(provider.overrides.dialer_proxy.as_deref(), Some("hop"));
    assert_eq!(provider.overrides.additional_prefix.as_deref(), Some("[p] "));
    assert_eq!(provider.overrides.proxy_name.len(), 1);

    // A pinned override field this kernel cannot apply is named, not ignored.
    for field in [
        "override: {tfo: true}",
        "override: {mptcp: true}",
        "override: {udp-over-tcp: true}",
        "override: {up: '1 Mbps'}",
        "override: {name-cert-verify: x}",
        "override: {interface-name: en0}",
        "override: {routing-mark: 1}",
        "override: {ip-version: ipv4}",
        "override: {override-expr: ['x']}",
    ] {
        let yaml = format!("proxy-providers: {{sub: {{type: inline, payload: [], {field}}}}}\n");
        let error = err_tag(&yaml);
        assert!(error.starts_with("unsupported"), "{field}: {error}");
        assert!(error.contains("override."), "{field}: {error}");
    }
    assert!(err_tag(
        "proxy-providers: {sub: {type: inline, payload: [], age-secret-key: AGE-SECRET-KEY-1X}}\n"
    )
    .contains("age-secret-key"));
    assert!(err_tag(
        "rule-providers: {r: {type: file, behavior: domain, path: x, path-in-bundle: rules/x.mrs}}\n"
    )
    .contains("path-in-bundle"));
}

/// Mihomo's decoder tolerates top-level keys it does not declare, so a file
/// carrying one (a fixture block, a newer option) must load; a key the pinned
/// version declares but this kernel does not implement still fails.
#[test]
fn unknown_top_level_keys_are_ignored_like_mihomo() {
    let loaded = load_config(
        "mixed-port: 1\nx-kernel-compat:\n  requests: []\nrulez: [MATCH,DIRECT]\nrules: ['MATCH,DIRECT']\n",
        "t",
    )
    .expect("unknown top-level keys load");
    assert_eq!(loaded.config.rules.len(), 1);
    assert!(
        loaded.warnings.iter().any(|w| w.contains("x-kernel-compat")),
        "{:?}",
        loaded.warnings
    );
    assert!(
        loaded.warnings.iter().any(|w| w.contains("rulez")),
        "{:?}",
        loaded.warnings
    );
    // Known but unimplemented keys still fail with their name.
    for key in ["listeners", "ntp"] {
        let yaml = format!("mixed-port: 1\n{key}: {{}}\n");
        let e = err_tag(&yaml);
        assert!(e.starts_with("unsupported"), "{key}: {e}");
    }
    // DNS and hosts are implemented (T22): an empty block is inert, and an
    // enabled DNS block is validated.
    let loaded = load_config("mixed-port: 1\ndns: {}\nhosts: {}\n", "t").expect("empty blocks load");
    assert!(!loaded.config.dns.enable);
    assert!(loaded.config.hosts.entries.is_empty());
    // The do-nothing forms of TUN/sniffer and inert geox-url are registered
    // with a warning; enabling them still fails by name.
    let loaded = load_config(
        "mixed-port: 1\ntun: {enable: false}\nsniffer: {enable: false}\ngeox-url: {geoip: 'https://example.invalid/GeoIP.dat'}\n",
        "t",
    )
    .expect("disabled tun/sniffer and geox-url load");
    for needle in ["tun", "sniffer", "geox-url"] {
        assert!(
            loaded.warnings.iter().any(|warning| warning.contains(needle)),
            "{needle}: {:?}",
            loaded.warnings
        );
    }
    assert!(err_tag("tun: {enable: true}\n").starts_with("unsupported"));
    assert!(err_tag("sniffer: {enable: true}\n").starts_with("unsupported"));
}

#[test]
fn geodata_options_are_parsed_and_named_gaps_rejected() {
    let loaded = load_config(
        "mixed-port: 1\ngeodata-mode: true\ngeodata-loader: memc\ngeosite-matcher: mph\n",
        "t",
    )
    .unwrap();
    assert!(loaded.config.geodata_mode);
    assert_eq!(loaded.config.geodata_loader, "memconservative");
    assert_eq!(loaded.config.geosite_matcher, "mph");
    assert!(err_tag("geodata-loader: fancy\n").starts_with("unsupported"));
    assert!(err_tag("geo-auto-update: true\n").starts_with("unsupported"));
    let loaded = load_config("geo-auto-update: false\ngeo-update-interval: 24\n", "t").unwrap();
    assert!(!loaded.config.geo_auto_update);
    assert!(loaded
        .warnings
        .iter()
        .any(|warning| warning.contains("geo-update-interval")));
}

#[test]
fn rejects_unimplemented_modes_and_levels() {
    assert!(err_tag("mode: global\n").starts_with("unsupported"));
    assert!(err_tag("log-level: trace\n").starts_with("unsupported"));
    // Port 0 is valid Mihomo syntax (disabled); a configuration with no other
    // listener fails by name rather than binding an ephemeral port.
    assert!(err_tag("mixed-port: 0\n").starts_with("unsupported"));
    assert!(err_tag("mixed-port: 0\n").contains("no listener"));
    assert!(err_tag("mixed-port: 70000\n").starts_with("invalid_value"));
    assert!(err_tag("bind-address: 0.0.0.0\n").starts_with("invalid_value"));
    assert!(err_tag("bind-address: 0.0.0.0\nallow-lan: true\n").starts_with("ok"));
    assert!(
        err_tag("[unclosed").starts_with("invalid_yaml:"),
        "{}",
        err_tag("[unclosed")
    );
}

#[test]
fn absent_rules_means_direct() {
    let loaded = load_config("mixed-port: 1\n", "t").unwrap();
    assert_eq!(loaded.config.rules_source, RulesSource::None);
    assert!(loaded.config.empty_rules);
}

#[test]
fn parses_rules_individually() {
    let rule = parse_rule("DOMAIN-SUFFIX,EeXample.Com,REJECT").unwrap();
    assert_eq!(
        rule.matcher,
        Matcher::DomainSuffix("eexample.com".to_string())
    );
    let net = parse_rule("IP-CIDR, 192.168.1.0/24 , DIRECT ").unwrap();
    match net.matcher {
        Matcher::IpCidr { net, .. } => {
            assert!(net.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99))));
            assert!(!net.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
            assert!(!net.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(parse_rule("IP-CIDR6,2001:db8::/32,DIRECT").is_ok());
    assert!(parse_rule("IP-CIDR6,10.0.0.0/8,DIRECT").is_err());
}

fn proxy_err(yaml: &str) -> String {
    match load_config(yaml, "test.yaml") {
        Ok(_) => "ok".to_string(),
        Err(e) => format!("{}: {e}", e.tag()),
    }
}


#[test]
fn parses_each_implemented_protocol_and_rule_targets_by_name() {
    let yaml = r#"
mixed-port: 1
proxies:
  - {name: s5, type: socks5, server: 127.0.0.1, port: 1080, username: u, password: p}
  - {name: h1, type: http, server: 127.0.0.1, port: 3128, username: u, password: p, headers: {X-Probe: yes}}
  - {name: ss1, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-128-gcm, password: pw, udp: true}
  - {name: tj, type: trojan, server: 127.0.0.1, port: 443, password: pw, sni: tj.example, skip-cert-verify: true}
  - {name: vl, type: vless, server: 127.0.0.1, port: 8443, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true, network: ws, ws-opts: {path: /ws, headers: {Host: vl.example}}}
  - {name: vm, type: vmess, server: 127.0.0.1, port: 443, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, alterId: 0, cipher: auto}
  - {name: sn, type: snell, server: 127.0.0.1, port: 443, psk: p, version: 3}
  - {name: tt, type: trusttunnel, server: 127.0.0.1, port: 443, username: u, password: p}
  - {name: gr, type: gost-relay, server: 127.0.0.1, port: 9000, forward: true, tls: true, sni: gr.example, username: u, password: p}
  - {name: sh, type: ssh, server: 127.0.0.1, port: 22, username: u, password: p}
  - {name: sr, type: ssr, server: 127.0.0.1, port: 8388, cipher: aes-256-cfb, password: p, protocol: origin, obfs: plain}
  - {name: tq, type: tuic, server: 127.0.0.1, port: 8443, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, password: p, alpn: [h3]}
  - {name: hy, type: hysteria, server: 127.0.0.1, port: 8443, up: 50 Mbps, down: 50 Mbps, auth-str: p}
  - {name: hy2, type: hysteria2, server: 127.0.0.1, port: 8443, password: p, alpn: [h3]}
rules:
  - DOMAIN,a.example,ss1
  - MATCH,h1
"#;
    let loaded = load_config(yaml, "test.yaml").expect("accepted");
    let config = loaded.config;
    assert_eq!(config.proxies.len(), 14);
    assert_eq!(config.proxies[0].type_name(), "socks5");
    assert_eq!(config.proxies[2].type_name(), "ss");
    assert!(config.proxies[2].udp_enabled());
    assert_eq!(config.proxies[5].type_name(), "vmess");
    assert_eq!(config.proxies[6].type_name(), "snell");
    assert_eq!(config.proxies[7].type_name(), "trusttunnel");
    assert_eq!(config.proxies[8].type_name(), "gost-relay");
    assert_eq!(config.proxies[9].type_name(), "ssh");
    assert_eq!(config.proxies[10].type_name(), "ssr");
    assert_eq!(config.proxies[11].type_name(), "tuic");
    assert_eq!(config.proxies[12].type_name(), "hysteria");
    assert_eq!(config.proxies[13].type_name(), "hysteria2");
    // Hysteria2 enables UDP unconditionally in the pinned outbound.
    assert!(config.proxies[13].udp_enabled());
    assert!(!config.proxies[5].udp_enabled());
    assert_eq!(config.action_name(billow_kernel::Action::Proxy(2)), "ss1");
    assert_eq!(config.action_name(billow_kernel::Action::Proxy(1)), "h1");
    assert!(config
        .feature_summary()
        .contains("protocols=s5=socks5,h1=http,ss1=ss,tj=trojan,vl=vless,vm=vmess,sn=snell,tt=trusttunnel,gr=gost-relay,sh=ssh,sr=ssr,tq=tuic,hy=hysteria,hy2=hysteria2"));
}

#[test]
fn unimplemented_protocol_and_option_name_the_field() {
    let e = proxy_err("proxies:\n  - {name: s1, type: mesh-unknown, server: x, port: 1}\nrules: ['MATCH,DIRECT']\n");
    assert!(e.starts_with("unsupported"), "{e}");
    assert!(e.contains("proxies[0] (name=s1, type=mesh-unknown)"), "{e}");
    let e = proxy_err("proxies:\n  - {name: v, type: vless, server: x, port: 1, uuid: 9d0cb9d0964f4ef6897d6c6b3ccf9e68, tls: true, reality-opts: {public-key: k}}\nrules: ['MATCH,DIRECT']\n");
    assert!(
        e.contains("option 'reality-opts' is not implemented"),
        "{e}"
    );
    // Keys the pinned type does not know are ignored by Mihomo's decoder, so
    // the same file must load here (R2: do not reject a valid configuration).
    assert_eq!(
        proxy_err("proxies:\n  - {name: t, type: trojan, server: x, port: 1, password: p, smux: {enabled: true}}\nrules: ['MATCH,DIRECT']\n"),
        "ok"
    );
    assert_eq!(
        proxy_err("proxies:\n  - {name: t, type: trojan, server: x, port: 1, password: p, bogus: 1}\nrules: ['MATCH,DIRECT']\n"),
        "ok"
    );
    let e = proxy_err("proxies:\n  - {name: s, type: ss, server: x, port: 1, cipher: rc4-md5, password: p}\nrules: ['MATCH,DIRECT']\n");
    assert!(
        e.contains("option 'cipher' value 'rc4-md5' is not implemented"),
        "{e}"
    );
    let e = proxy_err("proxies:\n  - {name: s, type: ss, server: x, port: 1, cipher: aes-256-gcm, password: p, plugin: obfs, plugin-opts: {mode: tls}}\nrules: ['MATCH,DIRECT']\n");
    assert!(e.contains("option 'plugin' value 'obfs'"), "{e}");
    let e = proxy_err("proxies:\n  - {name: v, type: vless, server: x, port: 1, uuid: 9d0cb9d0964f4ef6897d6c6b3ccf9e68, flow: xtls-rprx-vision}\nrules: ['MATCH,DIRECT']\n");
    assert!(e.contains("option 'flow' value 'xtls-rprx-vision'"), "{e}");
    // `udp-over-tcp` belongs to ss, not socks5: Mihomo ignores it there, so
    // the same file must load (the ss case above still rejects it when set).
    assert_eq!(
        proxy_err("proxies:\n  - {name: s, type: socks5, server: x, port: 1, udp-over-tcp: true}\nrules: ['MATCH,DIRECT']\n"),
        "ok"
    );
    let e = proxy_err("proxies:\n  - {name: s, type: ss, server: x, port: 1, cipher: aes-256-gcm, password: p, udp-over-tcp: true}\nrules: ['MATCH,DIRECT']\n");
    assert_eq!(e, "ok", "ss UoT is implemented and loads");
}


/// The option table must not admit a key the parser does not honour: each of
/// these was silently accepted before the T4 repair. One case per key so a
/// regression names the exact field.
#[test]
fn every_unimplemented_proxy_option_is_rejected_with_its_field() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "trojan",
            "server: 127.0.0.1, port: 1, password: p",
            "ech-opts: {enable: true}",
        ),
        (
            "trojan",
            "server: 127.0.0.1, port: 1, password: p",
            "restls-opts: {password: p}",
        ),
        ("trojan", "server: 127.0.0.1, port: 1, password: p", "jls-opts: {password: p}"),
        (
            "trojan",
            "server: 127.0.0.1, port: 1, password: p",
            "client-fingerprint: chrome",
        ),
        (
            "vless",
            "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true",
            "ech-opts: {enable: true}",
        ),
        (
            "vless",
            "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true",
            "shadow-tls-opts: {password: p}",
        ),
        (
            "vless",
            "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true",
            "restls-opts: {password: p}",
        ),
        (
            "vless",
            "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true",
            "jls-opts: {password: p}",
        ),
        (
            "vless",
            "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true",
            "network: grpc",
        ),
        (
            "anytls",
            "server: 127.0.0.1, port: 1, password: p",
            "ech-opts: {enable: true}",
        ),
        (
            "anytls",
            "server: 127.0.0.1, port: 1, password: p",
            "restls-opts: {password: p}",
        ),
            ];
    for (kind, base, option) in cases {
        let key = option.split(':').next().unwrap_or_default();
        let yaml = format!(
            "proxies:\n  - {{name: p, type: {kind}, {base}, {option}}}\nrules: ['MATCH,p']\n"
        );
        let e = proxy_err(&yaml);
        assert!(e.starts_with("unsupported"), "{kind}/{key}: {e}");
        assert!(e.contains(&format!("option '{key}'")), "{kind}/{key}: {e}");
    }
    // The no-op form of a boolean states what the kernel already does.
    for (kind, base, option) in [
        ("socks5", "server: 127.0.0.1, port: 1", "udp: false"),
        (
            "vless",
            "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68",
            "udp: false",
        ),
        ("anytls", "server: 127.0.0.1, port: 1, password: p", "udp: false"),
    ] {
        let yaml = format!(
            "proxies:\n  - {{name: p, type: {kind}, {base}, {option}}}\nrules: ['MATCH,p']\n"
        );
        assert_eq!(proxy_err(&yaml), "ok", "{kind}/{option} should load");
    }
}


/// `udp: true` with a `dialer-proxy` must be explicit about the hop: a UDP
/// association can only be carried by a SOCKS5 hop, and a longer chain is not
/// implemented. Both cases fail at load time so `--check` shows it, instead of
/// a UDP association silently dialling the server directly.
#[test]
fn udp_with_a_dialer_proxy_requires_one_socks5_hop() {
    let socks_hop = |extra: &str| {
        format!(
            "proxies:\n  - {{name: exit, type: ss, server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p, udp: true, dialer-proxy: hop}}\n  - {{name: hop, type: socks5, server: 127.0.0.1, port: 2{extra}}}\nrules: ['MATCH,exit']\n"
        )
    };
    assert_eq!(proxy_err(&socks_hop("")), "ok", "a single socks5 hop is supported");
    let loaded = load_config(&socks_hop(""), "t").unwrap();
    assert!(loaded.config.proxies[0].udp_enabled());

    // A hop without a UDP association is refused, naming both sides.
    let e = proxy_err(
        "proxies:\n  - {name: exit, type: ss, server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p, udp: true, dialer-proxy: hop}\n  - {name: hop, type: vless, server: 127.0.0.1, port: 2, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true}\nrules: ['MATCH,exit']\n",
    );
    assert!(e.starts_with("unsupported"), "{e}");
    assert!(e.contains("proxies[0] (name=exit, type=ss)"), "{e}");
    assert!(e.contains("dialer-proxy' 'hop' (type=vless)"), "{e}");
    assert!(e.contains("only a socks5 hop can carry a UDP association"), "{e}");

    // A second hop would need nested associations.
    let e = proxy_err(
        "proxies:\n  - {name: exit, type: ss, server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p, udp: true, dialer-proxy: hop}\n  - {name: hop, type: socks5, server: 127.0.0.1, port: 2, dialer-proxy: hop2}\n  - {name: hop2, type: socks5, server: 127.0.0.1, port: 3}\nrules: ['MATCH,exit']\n",
    );
    assert!(e.contains("multi-hop 'dialer-proxy' chain is not implemented"), "{e}");

    // TCP-only proxies keep the old behaviour (the chain is validated at dial
    // time); `udp: false` does not trigger the UDP rule.
    assert_eq!(
        proxy_err(
            "proxies:\n  - {name: exit, type: ss, server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p, dialer-proxy: hop}\n  - {name: hop, type: vless, server: 127.0.0.1, port: 2, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true}\nrules: ['MATCH,exit']\n"
        ),
        "ok"
    );
}

/// Mihomo accepts these forms and does nothing with them (`-t` passes), so the
/// kernel must accept them too: rejecting a valid configuration is a
/// compatibility failure. The behaviour-changing form of each key still fails.
#[test]
fn noop_option_forms_mihomo_accepts_are_loaded() {
    let noops: &[(&str, &str, &str)] = &[
        // TLS-only options with TLS off are ignored by Mihomo.
        ("socks5", "server: 127.0.0.1, port: 1", "skip-cert-verify: true"),
        ("socks5", "server: 127.0.0.1, port: 1", "sni: example.org"),
        ("socks5", "server: 127.0.0.1, port: 1", "alpn: [h2]"),
        ("socks5", "server: 127.0.0.1, port: 1", "fingerprint: chrome"),
        ("socks5", "server: 127.0.0.1, port: 1", "certificate: x.pem"),
        ("http", "server: 127.0.0.1, port: 1", "skip-cert-verify: true"),
        ("vless", "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68", "ech-opts: {enable: true}"),
        // Disabled/empty values.
        ("socks5", "server: 127.0.0.1, port: 1", "smux: {enabled: false}"),
        ("socks5", "server: 127.0.0.1, port: 1", "smux: {enabled: true}"),
        ("socks5", "server: 127.0.0.1, port: 1", "smux: {enabled: false, protocol: h2mux}"),
        ("socks5", "server: 127.0.0.1, port: 1", "ech-opts: {enable: false, config: x}"),
        ("socks5", "server: 127.0.0.1, port: 1, tls: true", "ech-opts: {enable: false, config: x}"),
        ("socks5", "server: 127.0.0.1, port: 1", "bogus: 1"),
        ("trojan", "server: 127.0.0.1, port: 1, password: p", "smux: {enabled: true, protocol: h2mux}"),
        ("ss", "server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p", "plugin-opts: {mode: tls}"),
        ("vless", "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68", "ss-opts: {enabled: true, password: p}"),
        // Keys another proxy type declares are unknown here: Mihomo ignores
        // them, so they must load (a cross-protocol key is not a gap).
        ("socks5", "server: 127.0.0.1, port: 1", "shadow-tls-opts: {password: p}"),
        ("socks5", "server: 127.0.0.1, port: 1", "restls-opts: {password: p}"),
        ("socks5", "server: 127.0.0.1, port: 1, tls: true", "ech-opts: {enable: true}"),
        ("socks5", "server: 127.0.0.1, port: 1", "udp-over-tcp: true"),
        ("socks5", "server: 127.0.0.1, port: 1", "udp-over-tcp-version: 2"),
        ("socks5", "server: 127.0.0.1, port: 1", "ss-opts: {enabled: true, password: p}"),
        ("socks5", "server: 127.0.0.1, port: 1, tls: true", "sni: example.org"),
        ("socks5", "server: 127.0.0.1, port: 1, tls: true", "alpn: [h2]"),
        ("http", "server: 127.0.0.1, port: 1", "jls-opts: {}"),
        ("http", "server: 127.0.0.1, port: 1", "shadow-tls-opts: {password: p}"),
        ("http", "server: 127.0.0.1, port: 1", "udp-over-tcp: true"),
        ("ss", "server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p", "shadow-tls-opts: {password: p}"),
        ("ss", "server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p", "jls-opts: {password: p, username: u}"),
        ("ss", "server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p", "restls-opts: {password: p}"),
        ("ss", "server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p", "ech-opts: {enable: true}"),
        ("trojan", "server: 127.0.0.1, port: 1, password: p", "udp-over-tcp: true"),
        ("vless", "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68", "udp-over-tcp: true"),
        ("anytls", "server: 127.0.0.1, port: 1, password: p", "udp-over-tcp: true"),
        ("socks5", "server: 127.0.0.1, port: 1", "grpc-opts: {}"),
        ("socks5", "server: 127.0.0.1, port: 1", "ech-opts: {enable: false}"),
        ("socks5", "server: 127.0.0.1, port: 1", "fingerprint: ''"),
        ("socks5", "server: 127.0.0.1, port: 1", "tfo: false"),
        ("socks5", "server: 127.0.0.1, port: 1", "mptcp: false"),
        ("socks5", "server: 127.0.0.1, port: 1", "interface-name: ''"),
        ("socks5", "server: 127.0.0.1, port: 1", "routing-mark: 0"),
        ("socks5", "server: 127.0.0.1, port: 1", "udp-over-tcp: false"),
        ("trojan", "server: 127.0.0.1, port: 1, password: p", "grpc-opts: {}"),
        // A transport block for a transport the configuration did not select
        // is ignored by Mihomo even when it has content.
        ("trojan", "server: 127.0.0.1, port: 1, password: p", "grpc-opts: {grpc-service-name: svc}"),
        ("trojan", "server: 127.0.0.1, port: 1, password: p, network: ws, ws-opts: {path: /ws}", "http-opts: {path: [/x]}"),
        ("vless", "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68", "h2-opts: {host: [h.example]}"),
        ("trojan", "server: 127.0.0.1, port: 1, password: p", "ech-opts: {enable: false}"),
        ("trojan", "server: 127.0.0.1, port: 1, password: p", "smux: {enabled: false}"),
        ("trojan", "server: 127.0.0.1, port: 1, password: p", "ss-opts: {}"),
        ("vless", "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68", "grpc-opts: {}"),
        ("anytls", "server: 127.0.0.1, port: 1, password: p", "idle-session-timeout: 0"),
        ("anytls", "server: 127.0.0.1, port: 1, password: p", "client-metadata: ''"),
        ("ss", "server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p", "plugin: ''"),
        ("ss", "server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p", "plugin-opts: {}"),
    ];
    for (kind, base, option) in noops {
        let yaml = format!(
            "proxies:\n  - {{name: p, type: {kind}, {base}, {option}}}\nrules: ['MATCH,p']\n"
        );
        assert_eq!(proxy_err(&yaml), "ok", "{kind}/{option} must load");
    }

    // `reality-opts`/`jls-opts` require fields: Mihomo's own `-t` rejects the
    // empty block, so the kernel rejects it too (even with TLS off).
    for (kind, base, option) in [
        ("vless", "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68", "reality-opts: {}"),
        ("vless", "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true", "reality-opts: {}"),
        ("trojan", "server: 127.0.0.1, port: 1, password: p", "jls-opts: {}"),
        ("anytls", "server: 127.0.0.1, port: 1, password: p", "jls-opts: {}"),
    ] {
        let key = option.split(':').next().unwrap_or_default();
        let yaml = format!(
            "proxies:\n  - {{name: p, type: {kind}, {base}, {option}}}\nrules: ['MATCH,p']\n"
        );
        let e = proxy_err(&yaml);
        assert!(e.starts_with("unsupported"), "{kind}/{key}: {e}");
        assert!(e.contains(&format!("option '{key}'")), "{kind}/{key}: {e}");
    }

    // The same keys with a value that changes behaviour still fail.
    let enabled: &[(&str, &str, &str)] = &[
        // `ech-opts`/`udp-over-tcp` are not socks5 options: Mihomo ignores them
        // there (covered by the no-op list), so they cannot be "enabled".
        ("vless", "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true", "reality-opts: {public-key: k}"),
        // anytls ShadowTLS v3 carries the account in the ClientHello session
        // id, which rustls generates internally: a named rejection.
        ("anytls", "server: 127.0.0.1, port: 1, password: p", "shadow-tls-opts: {password: p, version: 3}"),
        // ShadowTLS and JLS are mutually exclusive in the pinned type.
        ("anytls", "server: 127.0.0.1, port: 1, password: p", "shadow-tls-opts: {password: p}, jls-opts: {username: u, password: p}"),
        ("ss", "server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p", "plugin: obfs"),
    ];
    for (kind, base, option) in enabled {
        let key = option.split(':').next().unwrap_or_default();
        let yaml = format!(
            "proxies:\n  - {{name: p, type: {kind}, {base}, {option}}}\nrules: ['MATCH,p']\n"
        );
        let e = proxy_err(&yaml);
        assert!(e.starts_with("unsupported"), "{kind}/{key}: {e}");
        assert!(e.contains(&format!("option '{key}'")), "{kind}/{key}: {e}");
    }
}

#[test]
fn proxy_list_rejects_bad_shapes_and_names() {
    assert!(proxy_err("proxies: {}\n").starts_with("invalid_value"));
    let e = proxy_err("proxies:\n  - {name: DIRECT, type: ss, server: x, port: 1, cipher: aes-128-gcm, password: p}\n");
    assert!(e.contains("reserved"), "{e}");
    let e = proxy_err("proxies:\n  - {name: a, type: ss, server: x, port: 1, cipher: aes-128-gcm, password: p}\n  - {name: a, type: http, server: x, port: 1}\n");
    assert!(e.contains("duplicate proxy name 'a'"), "{e}");
    let e = proxy_err(
        "proxies:\n  - {name: a, type: ss, server: x, cipher: aes-128-gcm, password: p}\n",
    );
    assert!(e.contains("missing required option 'port'"), "{e}");
    let e =
        proxy_err("proxies:\n  - {name: a, type: ss, server: x, port: 1, cipher: aes-128-gcm}\n");
    assert!(e.contains("missing required option 'password'"), "{e}");
    let e = proxy_err("proxies:\n  - {name: a, type: vless, server: x, port: 1, uuid: nope}\n");
    assert!(e.contains("option 'uuid'"), "{e}");
}

#[test]
fn authentication_is_parsed_for_the_inbound() {
    let loaded = load_config(
        "authentication: ['alice:secret', 'bob:pw']\nmixed-port: 1\n",
        "t",
    )
    .unwrap();
    assert_eq!(loaded.config.inbound_users.len(), 2);
    assert_eq!(
        loaded.config.inbound_users[0],
        ("alice".to_string(), "secret".to_string())
    );
    assert!(err_tag("authentication: ['noseparator']\n").starts_with("invalid_value"));
    assert!(err_tag("authentication: [':x']\n").starts_with("invalid_value"));
}

/// A self-signed CA certificate committed with the test (no private key): the
/// parser only needs a PEM block, so the case does not depend on any file that
/// happens to exist on the machine.
const TEST_ROOT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIC9jCCAd6gAwIBAgIUelKdKzfsjux9SN8/Qn4tL9YDcDIwDQYJKoZIhvcNAQEL\nBQAwGzEZMBcGA1UEAwwQYmlsbG93LXRlc3Qtcm9vdDAeFw0yNjExMjEwNDExMTla\nFw0zNjExMTgwNDExMTlaMBsxGTAXBgNVBAMMEGJpbGxvdy10ZXN0LXJvb3QwggEi\nMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2wRi2FVbHIunj30b3Jn2t5HUT\nqBpmUXc+554NeKtqP9NoCTFmZkhDfTRgakZpzJiT3GwizRASCM2622IqlEcHzINl\nZ+vsWAf9K8gHIgcHlCA8W43VW+eR9WoPAKwyFd9s2XP4ybFz7JuKAIsvCChFE894\nhuCbDsJ1tSzBdMhazwlr1VYHPKyQsXNYHWjRUCizEe+zWDbNbdwMduqL13k0XJ3G\n+9Eq0Y1QASbTUGYcoBUtDTpK5Dw2yKMrfNgRsOY9JpazRUZHPJVoRqQA2ynXdWLa\nrPeDVh7ft4MLELi7XsxnqK6ilWlqGZ1mIlyBA1V7SEKAQvVPuB7q3ZDS6ZmXAgMB\nAAGjMjAwMB0GA1UdDgQWBBT40+3az1yyAvbYOv/DssEWj1kIljAPBgNVHRMBAf8E\nBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAnRn5jByX32e7OOb1Z0GOejmCgDMoC\nME5fQElY4zyrMQ+/Ee6WyHbZMyK3my3JArc/NBIABz69rMXpBCR1K+UEqopjdxhX\niDuRqx3BtMaGRl+/2Zf2yvYdDObWzW1vPWViV+nYy/FQZpvG/Vq3weuC3O8HpCeh\n5xh9V9yh2XUbOsJGWcdwXxVGSgRkReueCN2BZCL1htpOFr2bNYTraeH9z8jmjRIR\nKGPvMu2bOX3cnpyynHKC+ppP1Xh5kH7GP/a39aIUMzxR/pM5TRGFHtoA4QyaZhE7\nds7T4WWGAhf+mImBbogczhBpT0POr/8m+gV8vHwpb/mJrvXK/ELuGWVH\n-----END CERTIFICATE-----\n";

#[test]
fn tls_roots_are_loaded_and_unknown_tls_keys_fail() {
    let dir = std::env::temp_dir().join(format!("billow-tls-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("custom")).unwrap();
    std::fs::write(dir.join("custom/root.pem"), TEST_ROOT_PEM).unwrap();
    let yaml = format!(
        "tls:\n  certificate: {}\nmixed-port: 1\n",
        dir.join("custom").display()
    );
    let loaded = load_config(&yaml, "test.yaml").expect("tls certificate directory");
    assert_eq!(loaded.config.tls_roots.len(), 1);
    let yaml = format!(
        "tls:\n  custom-cert: [{}]\nmixed-port: 1\n",
        dir.join("custom/root.pem").display()
    );
    assert_eq!(
        load_config(&yaml, "test.yaml")
            .unwrap()
            .config
            .tls_roots
            .len(),
        1
    );
    // `tls.private-key` is parsed for the controller TLS listener; a missing
    // file is an invalid value, and an unknown tls key is still named.
    assert!(err_tag("tls:\n  private-key: /nonexistent/billow.key\n").starts_with("invalid_value"));
    let e = err_tag("tls:\n  client-auth-type: require-and-verify\n");
    assert!(e.starts_with("unsupported"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dialer_proxy_references_are_validated() {
    let base = |extra: &str| {
        format!(
            "proxies:\n  - {{name: a, type: socks5, server: 127.0.0.1, port: 1{extra}}}\n  - {{name: b, type: socks5, server: 127.0.0.1, port: 2, dialer-proxy: a}}\nrules: ['MATCH,a']\n"
        )
    };
    let loaded = load_config(&base(""), "t").expect("valid chain");
    assert_eq!(loaded.config.proxies[1].dialer_proxy(), Some("a"));
    assert_eq!(loaded.config.proxies[0].dialer_proxy(), None);
    let e = proxy_err("proxies:\n  - {name: a, type: socks5, server: 127.0.0.1, port: 1, dialer-proxy: missing}\nrules: ['MATCH,a']\n");
    assert!(e.contains("dialer-proxy 'missing' not found"), "{e}");
    let e = proxy_err("proxies:\n  - {name: a, type: socks5, server: 127.0.0.1, port: 1, dialer-proxy: a}\nrules: ['MATCH,a']\n");
    assert!(e.contains("refers to itself"), "{e}");
    let e = proxy_err("proxies:\n  - {name: a, type: socks5, server: x, port: 1, dialer-proxy: b}\n  - {name: b, type: socks5, server: y, port: 2, dialer-proxy: a}\nrules: ['MATCH,a']\n");
    assert!(e.contains("circular dialer-proxy dependency"), "{e}");
    let e = proxy_err("proxies:\n  - {name: a, type: socks5, server: x, port: 1, dialer-proxy: Group}\nrules: ['MATCH,a']\n");
    assert!(e.contains("proxy groups are not implemented"), "{e}");
}

#[test]
fn anytls_options_are_strict() {
    let ok = "proxies:\n  - {name: at, type: anytls, server: 127.0.0.1, port: 443, password: p, sni: at.example, skip-cert-verify: true, alpn: [h2]}\nrules: ['MATCH,at']\n";
    let loaded = load_config(ok, "t").expect("anytls accepted");
    assert_eq!(loaded.config.proxies[0].type_name(), "anytls");
    // Session reuse, UoT and the uTLS name are implemented: their enabled
    // forms load (behaviour is covered by the protocol and peer tests).
    load_config(
        "proxies:\n  - {name: at, type: anytls, server: 127.0.0.1, port: 443, password: p, udp: true, client-metadata: m, idle-session-check-interval: 30, idle-session-timeout: 30, min-idle-session: 1, disable-reuse: true, client-fingerprint: chrome}\nrules: ['MATCH,at']\n",
        "t",
    )
    .expect("anytls session/UoT/fingerprint options load");
    for (field, value) in [
        ("ech-opts", "{enable: true, config: x}"),
        ("restls-opts", "{password: p}"),
        ("shadow-tls-opts", "{password: p, version: 3}"),
        ("shadow-tls-opts", "{password: p, version: 4}"),
        ("jls-opts", "{}"),
    ] {
        let yaml = format!("proxies:\n  - {{name: at, type: anytls, server: x, port: 1, password: p, {field}: {value}}}\nrules: ['MATCH,at']\n");
        let e = proxy_err(&yaml);
        assert!(e.contains(&format!("option '{field}'")), "{field}: {e}");
    }
    // ShadowTLS v1/v2 and JLS are implemented security modes: their enabled
    // forms load with the parsed mode (behaviour is covered by the peer tests).
    use billow_kernel::proxies::{AnytlsSecurity, Protocol};
    for (block, want_version) in [
        ("shadow-tls-opts: {password: p}", 2u8),
        ("shadow-tls-opts: {password: p, version: 1}", 1u8),
        ("shadow-tls-opts: {password: p, version: 2}", 2u8),
    ] {
        let yaml = format!("proxies:\n  - {{name: at, type: anytls, server: 127.0.0.1, port: 1, password: p, {block}}}\nrules: ['MATCH,at']\n");
        let loaded = load_config(&yaml, "t").expect("shadow-tls loads");
        match &loaded.config.proxies[0].protocol {
            Protocol::Anytls(p) => match &p.security {
                AnytlsSecurity::ShadowTls { password, version } => {
                    assert_eq!(password.expose(), "p");
                    assert_eq!(*version, want_version);
                }
                other => panic!("expected shadow-tls, got {other:?}"),
            },
            other => panic!("expected anytls, got {other:?}"),
        }
    }
    let loaded = load_config(
        "proxies:\n  - {name: at, type: anytls, server: 127.0.0.1, port: 1, password: p, jls-opts: {username: u, password: jp}}\nrules: ['MATCH,at']\n",
        "t",
    )
    .expect("jls loads");
    match &loaded.config.proxies[0].protocol {
        Protocol::Anytls(p) => match &p.security {
            AnytlsSecurity::Jls { username, password } => {
                assert_eq!(username.expose(), "u");
                assert_eq!(password.expose(), "jp");
            }
            other => panic!("expected jls, got {other:?}"),
        },
        other => panic!("expected anytls, got {other:?}"),
    }
}

#[test]
fn anytls_session_intervals_match_the_pinned_normalisation() {
    use billow_kernel::proxies::Protocol;

    // Pinned `session.NewClient`: an interval/timeout at or below 5s (including
    // the zero value) becomes 30s; above 5s it is kept.
    for (interval, timeout, want_interval, want_timeout) in [
        (10, 40, 10, 40),
        (5, 3, 30, 30),
        (1, 0, 30, 30),
    ] {
        let yaml = format!(
            "proxies:\n  - {{name: at, type: anytls, server: 127.0.0.1, port: 443, password: p, idle-session-check-interval: {interval}, idle-session-timeout: {timeout}}}\nrules: ['MATCH,at']\n"
        );
        let loaded = load_config(&yaml, "t").expect("anytls intervals load");
        match &loaded.config.proxies[0].protocol {
            Protocol::Anytls(p) => {
                assert_eq!(p.idle_session_check_interval, want_interval);
                assert_eq!(p.idle_session_timeout, want_timeout);
                assert_eq!(p.session_pool.check_interval(), want_interval);
            }
            other => panic!("expected anytls, got {other:?}"),
        }
    }
}

#[test]
fn t30_datagram_and_fingerprint_options_are_accepted() {
    use billow_kernel::proxies::Protocol;

    let loaded = load_config(
        "proxies:\n  - {name: v, type: vless, server: 127.0.0.1, port: 443, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true, udp: true, client-fingerprint: chrome}\nrules: ['MATCH,v']\n",
        "t",
    )
    .expect("vless udp loads");
    match &loaded.config.proxies[0].protocol {
        Protocol::Vless(p) => {
            assert!(p.udp);
            // The pinned default without packet-addr/packet-encoding is XUDP.
            assert!(p.xudp);
            assert!(!p.packet_addr);
            assert_eq!(
                p.tls_settings.client_fingerprint.as_deref(),
                Some("chrome")
            );
        }
        other => panic!("expected vless, got {other:?}"),
    }
    let loaded = load_config(
        "proxies:\n  - {name: v, type: vless, server: 127.0.0.1, port: 443, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true, udp: true, packet-encoding: packetaddr}\nrules: ['MATCH,v']\n",
        "t",
    )
    .expect("vless packet-addr loads");
    match &loaded.config.proxies[0].protocol {
        Protocol::Vless(p) => {
            assert!(p.packet_addr);
            assert!(!p.xudp);
        }
        other => panic!("expected vless, got {other:?}"),
    }

    let loaded = load_config(
        "proxies:\n  - {name: m, type: vmess, server: 127.0.0.1, port: 443, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, alterId: 0, cipher: auto, udp: true, xudp: true}\nrules: ['MATCH,m']\n",
        "t",
    )
    .expect("vmess xudp loads");
    match &loaded.config.proxies[0].protocol {
        Protocol::Vmess(p) => {
            assert!(p.udp);
            assert!(p.xudp);
            assert!(!p.packet_addr);
        }
        other => panic!("expected vmess, got {other:?}"),
    }

    for option in ["udp-over-tcp: true", "udp-over-tcp: true, udp-over-tcp-version: 1"] {
        let yaml = format!(
            "proxies:\n  - {{name: s, type: ss, server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p, {option}}}\nrules: ['MATCH,s']\n"
        );
        let loaded = load_config(&yaml, "t").expect("ss UoT loads");
        match &loaded.config.proxies[0].protocol {
            Protocol::Shadowsocks(p) => {
                assert!(p.udp_over_tcp);
                assert!(p.udp);
            }
            other => panic!("expected ss, got {other:?}"),
        }
    }
    // An unsupported UoT version is a named rejection, not a silent default.
    let e = proxy_err(
        "proxies:\n  - {name: s, type: ss, server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p, udp-over-tcp: true, udp-over-tcp-version: 3}\nrules: ['MATCH,s']\n",
    );
    assert!(e.contains("udp-over-tcp-version"), "{e}");
}

#[test]
fn vmess_options_are_strict() {
    let ok = "proxies:\n  - {name: vm, type: vmess, server: 127.0.0.1, port: 443, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, alterId: 0, cipher: auto, tls: true, sni: vm.example, network: ws, ws-opts: {path: /vm}}\nrules: ['MATCH,vm']\n";
    let loaded = load_config(ok, "t").expect("vmess accepted");
    assert_eq!(loaded.config.proxies[0].type_name(), "vmess");
    for (field, value) in [
        ("alterId", "1"),
        ("cipher", "rc4-md5"),
        ("network", "grpc"),
        ("global-padding", "true"),
        ("authenticated-length", "true"),
        ("reality-opts", "{public-key: key}"),
    ] {
        let base = if field == "alterId" {
            format!("uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, cipher: auto, alterId: {value}")
        } else if field == "cipher" {
            format!("uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, alterId: 0, cipher: {value}")
        } else {
            format!("uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, alterId: 0, cipher: auto, {field}: {value}")
        };
        let yaml = format!("proxies:\n  - {{name: vm, type: vmess, server: x, port: 1, {base}}}\nrules: ['MATCH,vm']\n");
        let e = proxy_err(&yaml);
        assert!(e.contains(&format!("option '{field}'")), "{field}: {e}");
    }
    // A transport block for a network that is not selected is ignored by
    // Mihomo, so it loads here too.
    load_config(
        "proxies:\n  - {name: vm, type: vmess, server: x, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, alterId: 0, cipher: auto, grpc-opts: {grpc-service-name: s}}\nrules: ['MATCH,vm']\n",
        "t",
    )
    .expect("an unselected transport block is ignored");
    // Mihomo's decoder requires both fields; the kernel does too.
    for missing in [
        "proxies:\n  - {name: vm, type: vmess, server: x, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, cipher: auto}\nrules: ['MATCH,vm']\n",
        "proxies:\n  - {name: vm, type: vmess, server: x, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, alterId: 0}\nrules: ['MATCH,vm']\n",
    ] {
        let e = proxy_err(missing);
        assert!(e.contains("missing required option"), "{e}");
    }
}

#[test]
fn vmess_tlsmirror_options_load_and_name_the_unimplemented_extras() {
    use billow_kernel::proxies::Protocol;
    // The pinned decoder ignores unknown keys; `{enabled: true}` selects
    // nothing and is accepted even without TLS.
    load_config(
        "proxies:\n  - {name: vm, type: vmess, server: x, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, alterId: 0, cipher: auto, tlsmirror-opts: {enabled: true}}\nrules: ['MATCH,vm']\n",
        "t",
    )
    .expect("a tlsmirror block with no primary key is a no-op");
    let key = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    let yaml = format!("proxies:\n  - {{name: vm, type: vmess, server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, alterId: 0, cipher: auto, tls: true, tlsmirror-opts: {{primary-key: \"{key}\"}}}}\nrules: ['MATCH,vm']\n");
    let loaded = load_config(&yaml, "t").expect("tlsmirror loads");
    match &loaded.config.proxies[0].protocol {
        Protocol::Vmess(proxy) => {
            assert_eq!(
                proxy.tlsmirror.as_ref().map(|mirror| mirror.primary_key.as_str()),
                Some(key)
            );
        }
        other => panic!("expected vmess, got {other:?}"),
    }
    for (block, field) in [
        (
            format!("tlsmirror-opts: {{primary-key: \"{key}\"}}"),
            "tlsmirror-opts",
        ),
        (
            format!("tls: true, tlsmirror-opts: {{primary-key: \"{key}\", transport-layer-padding: {{enabled: true}}}}"),
            "transport-layer-padding",
        ),
        (
            format!("tls: true, tlsmirror-opts: {{primary-key: \"{key}\", sequence-watermarking-enabled: true}}"),
            "sequence-watermarking-enabled",
        ),
    ] {
        let yaml = format!("proxies:\n  - {{name: vm, type: vmess, server: x, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, alterId: 0, cipher: auto, {block}}}\nrules: ['MATCH,vm']\n");
        let error = proxy_err(&yaml);
        assert!(error.contains(field), "{block}: {error}");
    }
}

#[test]
fn vmess_mkcp_and_mekya_options_load() {
    use billow_kernel::proxies::{Protocol, VmessNetwork};
    let mkcp = "proxies:\n  - {name: vm, type: vmess, server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, alterId: 0, cipher: auto, network: mkcp, mkcp-opts: {mtu: 1350, tti: 40, seed: s, header: srtp, congestion: true}}\nrules: ['MATCH,vm']\n";
    let loaded = load_config(mkcp, "t").expect("vmess mkcp loads");
    match &loaded.config.proxies[0].protocol {
        Protocol::Vmess(proxy) => match &proxy.network {
            VmessNetwork::Mkcp(options) => {
                assert_eq!(options.mtu, 1350);
                assert_eq!(options.tti, 40);
                assert_eq!(options.seed, "s");
                assert_eq!(options.header, "srtp");
                assert!(options.congestion);
            }
            other => panic!("expected mkcp, got {other:?}"),
        },
        other => panic!("expected vmess, got {other:?}"),
    }
    let mekya = "proxies:\n  - {name: vm, type: vmess, server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, alterId: 0, cipher: auto, tls: true, network: mekya, mekya-opts: {url: 'https://127.0.0.1:1/', h2-pool-size: 2, max-write-delay: 20, kcp: {header: none}}}\nrules: ['MATCH,vm']\n";
    let loaded = load_config(mekya, "t").expect("vmess mekya loads");
    match &loaded.config.proxies[0].protocol {
        Protocol::Vmess(proxy) => match &proxy.network {
            VmessNetwork::Mekya(options) => {
                assert_eq!(options.url, "https://127.0.0.1:1/");
                assert_eq!(options.h2_pool_size, 2);
                assert_eq!(options.max_write_delay, 20);
                assert_eq!(options.kcp.header, "none");
            }
            other => panic!("expected mekya, got {other:?}"),
        },
        other => panic!("expected vmess, got {other:?}"),
    }
    // Unknown MKCP knobs and headers are named instead of ignored.
    for (block, field) in [
        ("mkcp-opts: {bogus: 1}", "bogus"),
        ("mkcp-opts: {header: bogus}", "mkcp-opts.header"),
        ("mekya-opts: {bogus: 1}", "bogus"),
    ] {
        let network = if block.starts_with("mekya") {
            "mekya"
        } else {
            "mkcp"
        };
        let yaml = format!(
            "proxies:\n  - {{name: vm, type: vmess, server: x, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, alterId: 0, cipher: auto, network: {network}, {block}}}\nrules: ['MATCH,vm']\n"
        );
        let error = proxy_err(&yaml);
        assert!(error.contains(field), "{block}: {error}");
    }
}

#[test]
fn snell_options_are_strict() {
    for version in [1, 2, 3] {
        let yaml = format!("proxies:\n  - {{name: sn, type: snell, server: 127.0.0.1, port: 443, psk: p, version: {version}}}\nrules: ['MATCH,sn']\n");
        let loaded = load_config(&yaml, "t").expect("snell accepted");
        assert_eq!(loaded.config.proxies[0].type_name(), "snell");
    }
    let obfs = "proxies:\n  - {name: sn, type: snell, server: 127.0.0.1, port: 443, psk: p, version: 3, obfs-opts: {mode: http, host: bing.com}}\nrules: ['MATCH,sn']\n";
    load_config(obfs, "t").expect("snell http obfs accepted");
    for (field, value) in [
        ("version", "4"),
        ("version", "6"),
        ("reuse", "true"),
        ("mode", "unshaped"),
        ("udp", "true"),
        ("obfs-opts", "{mode: tls}"),
    ] {
        let base = if field == "version" {
            format!("psk: p, version: {value}")
        } else {
            format!("psk: p, version: 3, {field}: {value}")
        };
        let yaml = format!("proxies:\n  - {{name: sn, type: snell, server: x, port: 1, {base}}}\nrules: ['MATCH,sn']\n");
        let e = proxy_err(&yaml);
        if field == "obfs-opts" {
            // The sub-option is named: `option 'obfs-opts.mode' value 'tls' ...`.
            assert!(e.contains("option 'obfs-opts"), "{field}: {e}");
        } else {
            assert!(e.contains(&format!("option '{field}'")), "{field}: {e}");
        }
    }
    let e = proxy_err("proxies:\n  - {name: sn, type: snell, server: x, port: 1, version: 2}\nrules: ['MATCH,sn']\n");
    assert!(e.contains("missing required option 'psk'"), "{e}");
}

#[test]
fn trusttunnel_options_are_strict() {
    let ok = "proxies:\n  - {name: tt, type: trusttunnel, server: 127.0.0.1, port: 443, username: u, password: p, sni: tt.example, skip-cert-verify: true, alpn: [h2]}\nrules: ['MATCH,tt']\n";
    let loaded = load_config(ok, "t").expect("trusttunnel accepted");
    assert_eq!(loaded.config.proxies[0].type_name(), "trusttunnel");
    for (field, value) in [
        ("udp", "true"),
        ("quic", "true"),
        ("health-check", "true"),
        ("max-connections", "4"),
        ("min-streams", "1"),
        ("max-streams", "8"),
        ("congestion-controller", "bbr"),
        ("cwnd", "16"),
        ("bbr-profile", "standard"),
        ("client-fingerprint", "chrome"),
        ("ech-opts", "{enable: true, config: x}"),
        ("alpn", "[h3]"),
    ] {
        let yaml = format!("proxies:\n  - {{name: tt, type: trusttunnel, server: x, port: 1, {field}: {value}}}\nrules: ['MATCH,tt']\n");
        let e = proxy_err(&yaml);
        assert!(e.contains(&format!("option '{field}'")), "{field}: {e}");
    }
    // Certificate identities are verified by the shared TLS client.
    load_config(
        "proxies:\n  - {name: tt, type: trusttunnel, server: x, port: 1, sni: tt.example, name-cert-verify: tt.example, fingerprint: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', certificate: cert.pem, private-key: key.pem}\nrules: ['MATCH,tt']\n",
        "t",
    )
    .expect("trusttunnel TLS identities load");
}

#[test]
fn gost_relay_options_are_strict() {
    let ok = "proxies:\n  - {name: gr, type: gost-relay, server: 127.0.0.1, port: 9000, forward: true, tls: true, sni: gr.example, username: u, password: p, skip-cert-verify: true}\nrules: ['MATCH,gr']\n";
    let loaded = load_config(ok, "t").expect("gost-relay accepted");
    assert_eq!(loaded.config.proxies[0].type_name(), "gost-relay");
    // `forward: false`, empty credentials and `udp: false` state the same
    // thing the kernel does, so they load.
    load_config(
        "proxies:\n  - {name: gr, type: gost-relay, server: 127.0.0.1, port: 9000, forward: false, udp: false, username: '', password: ''}\nrules: ['MATCH,gr']\n",
        "t",
    )
    .expect("disabled forms load");
    // The UDP association and the smux session are implemented, so their
    // enabled forms load.
    load_config(
        "proxies:\n  - {name: gr, type: gost-relay, server: 127.0.0.1, port: 9000, udp: true, mux: true}\nrules: ['MATCH,gr']\n",
        "t",
    )
    .expect("udp and mux load");
    for (field, value) in [("client-fingerprint", "chrome")] {
        let yaml = format!("proxies:\n  - {{name: gr, type: gost-relay, server: x, port: 1, tls: true, {field}: {value}}}\nrules: ['MATCH,gr']\n");
        let e = proxy_err(&yaml);
        assert!(e.contains(&format!("option '{field}'")), "{field}: {e}");
    }
    load_config(
        "proxies:\n  - {name: gr, type: gost-relay, server: x, port: 1, tls: true, sni: gr.example, name-cert-verify: gr.example, fingerprint: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}\nrules: ['MATCH,gr']\n",
        "t",
    )
    .expect("gost-relay TLS identities load");
}

#[test]
fn ssh_options_are_strict() {
    let ok = "proxies:\n  - {name: sh, type: ssh, server: 127.0.0.1, port: 22, username: u, password: p}\nrules: ['MATCH,sh']\n";
    let loaded = load_config(ok, "t").expect("ssh accepted");
    assert_eq!(loaded.config.proxies[0].type_name(), "ssh");
    // Inline PEM and pinned host keys are parsed at load time, as Mihomo
    // parses them when it constructs the outbound.
    let key = russh::keys::PrivateKey::random(
        &mut rand::rngs::OsRng,
        russh::keys::Algorithm::Ed25519,
    )
    .expect("key");
    let pem = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .expect("pem");
    let authorized = key.public_key().to_openssh().expect("authorized key");
    let yaml = format!(
        "proxies:\n  - name: sh\n    type: ssh\n    server: 127.0.0.1\n    port: 22\n    username: u\n    private-key: |\n{}    host-key: [\"{authorized}\"]\n    host-key-algorithms: [ssh-ed25519]\nrules: ['MATCH,sh']\n",
        pem.lines().map(|line| format!("      {line}\n")).collect::<String>()
    );
    load_config(&yaml, "t").expect("inline key, host key and algorithm accepted");
    // `BasicOption` socket knobs are part of every outbound; the stream dialer
    // applies them instead of rejecting a valid configuration.
    let with_basic = "proxies:\n  - {name: sh, type: ssh, server: x, port: 22, username: u, tfo: true, mptcp: true, interface-name: en0, routing-mark: 100, ip-version: ipv4}\nrules: ['MATCH,sh']\n";
    let loaded = load_config(with_basic, "t").expect("basic dialer options load");
    let dialer = &loaded.config.proxies[0].dialer;
    assert!(dialer.tfo);
    assert!(dialer.mptcp);
    assert_eq!(dialer.interface_name.as_deref(), Some("en0"));
    assert_eq!(dialer.routing_mark, 100);
    assert_eq!(dialer.ip_version, billow_kernel::proxies::IpVersion::V4Only);
    let e = proxy_err("proxies:\n  - {name: sh, type: ssh, server: x, port: 22, username: u, routing-mark: -1}\nrules: ['MATCH,sh']\n");
    assert!(e.contains("option 'routing-mark'"), "{e}");
    let e = proxy_err("proxies:\n  - {name: sh, type: ssh, server: x, port: 22, password: p}\nrules: ['MATCH,sh']\n");
    assert!(e.contains("missing required option 'username'"), "{e}");
    let e = proxy_err("proxies:\n  - {name: sh, type: ssh, server: x, port: 22, username: u, private-key: /tmp/id_ed25519}\nrules: ['MATCH,sh']\n");
    assert!(e.contains("option 'private-key' file paths are not implemented"), "{e}");
    let e = proxy_err("proxies:\n  - {name: sh, type: ssh, server: x, port: 22, username: u, host-key: [not-a-key]}\nrules: ['MATCH,sh']\n");
    assert!(e.contains("option 'host-key'"), "{e}");
    let e = proxy_err("proxies:\n  - {name: sh, type: ssh, server: x, port: 22, username: u, host-key-algorithms: [nope]}\nrules: ['MATCH,sh']\n");
    assert!(e.contains("option 'host-key-algorithms'"), "{e}");
}

#[test]
fn ssr_options_are_strict() {
    let ok = "proxies:\n  - {name: sr, type: ssr, server: 127.0.0.1, port: 8388, cipher: AES-256-CFB, password: p, protocol: origin, protocol-param: ignored, obfs: plain, obfs-param: ignored}\nrules: ['MATCH,sr']\n";
    let loaded = load_config(ok, "t").expect("ssr accepted");
    assert_eq!(loaded.config.proxies[0].type_name(), "ssr");
    load_config(
        "proxies:\n  - {name: sr, type: ssr, server: x, port: 1, cipher: none, password: '', protocol: origin, obfs: plain, udp: false}\nrules: ['MATCH,sr']\n",
        "t",
    )
    .expect("dummy cipher with an empty password and udp: false loads");
    // Every protocol and obfs the pinned type registers is implemented, and
    // `udp: true` opens the pinned association.
    for (protocol, obfs) in [
        ("auth_sha1_v4", "plain"),
        ("auth_aes128_md5", "http_simple"),
        ("auth_aes128_sha1", "http_post"),
        ("auth_chain_a", "random_head"),
        ("auth_chain_b", "tls1.2_ticket_auth"),
        ("origin", "tls1.2_ticket_fastauth"),
    ] {
        let yaml = format!(
            "proxies:\n  - {{name: sr, type: ssr, server: 127.0.0.1, port: 1, cipher: aes-256-cfb, password: p, protocol: {protocol}, obfs: {obfs}, udp: true}}\nrules: ['MATCH,sr']\n"
        );
        load_config(&yaml, "t").unwrap_or_else(|e| panic!("{protocol}/{obfs}: {e}"));
    }
    for (field, value) in [
        ("protocol", "auth_chain_c"),
        ("obfs", "tls1.3_ticket_auth"),
        ("cipher", "aes-256-gcm"),
    ] {
        // protocol/obfs/cipher are required, so replace the base value
        // instead of adding a duplicate key.
        let base = match field {
            "protocol" => format!("cipher: aes-256-cfb, password: p, protocol: {value}, obfs: plain"),
            "obfs" => format!("cipher: aes-256-cfb, password: p, protocol: origin, obfs: {value}"),
            "cipher" => format!("cipher: {value}, password: p, protocol: origin, obfs: plain"),
            _ => format!("cipher: aes-256-cfb, password: p, protocol: origin, obfs: plain, {field}: {value}"),
        };
        let yaml = format!("proxies:\n  - {{name: sr, type: ssr, server: x, port: 1, {base}}}\nrules: ['MATCH,sr']\n");
        let e = proxy_err(&yaml);
        assert!(e.contains(&format!("option '{field}'")), "{field}: {e}");
    }
    load_config(
        "proxies:\n  - {name: sr, type: ssr, server: x, port: 1, cipher: aes-256-cfb, password: p, protocol: origin, obfs: plain, tfo: true, mptcp: true, ip-version: ipv6}\nrules: ['MATCH,sr']\n",
        "t",
    )
    .expect("basic dialer options load for ssr");
    let e = proxy_err("proxies:\n  - {name: sr, type: ssr, server: x, port: 1, cipher: aes-256-cfb, password: p, obfs: plain}\nrules: ['MATCH,sr']\n");
    assert!(e.contains("missing required option 'protocol'"), "{e}");
}

#[test]
fn shadowquic_transport_options_are_parsed_and_jls_gaps_named() {
    let yaml = "proxies:\n  - {name: sq, type: shadowquic, server: 127.0.0.1, port: 443, username: alice, password: secret, sni: example.org, alpn: [h3], udp-over-stream: true, keep-alive-interval: 1500, recv-window-conn: 65536, recv-window: 131072, disable-mtu-discovery: true, max-datagram-frame-size: 1400, max-open-streams: 8}\nrules: ['MATCH,sq']\n";
    let loaded = load_config(yaml, "test.yaml").expect("shadowquic options load");
    let proxy = &loaded.config.proxies[0];
    assert_eq!(proxy.type_name(), "shadowquic");
    assert!(proxy.udp_enabled());
    match &proxy.protocol {
        billow_kernel::proxies::Protocol::ShadowQuic(option) => {
            assert_eq!(option.server, "127.0.0.1");
            assert_eq!(option.port, 443);
            assert_eq!(option.username, "alice");
            assert_eq!(option.password, "secret");
            assert_eq!(option.sni.as_deref(), Some("example.org"));
            assert_eq!(option.alpn, vec!["h3".to_string()]);
            assert!(option.udp_over_stream);
            assert_eq!(option.keep_alive_interval, 1500);
            assert_eq!(option.recv_window_conn, 65536);
            assert_eq!(option.recv_window, 131072);
            assert!(option.disable_mtu_discovery);
            assert_eq!(option.max_datagram_frame_size, 1400);
            assert_eq!(option.max_open_streams, 8);
        }
        other => panic!("expected shadowquic, got {other:?}"),
    }

    // The pinned type has no `tls`, `skip-cert-verify` or `udp` key; Mihomo
    // ignores them, so the same file must load (R2).
    let ignored = "proxies:\n  - {name: sq, type: shadowquic, server: x, port: 1, tls: false, skip-cert-verify: true, udp: false, name-cert-verify: x}\nrules: ['MATCH,sq']\n";
    assert_eq!(err_tag(ignored), "ok");

    for (extra, field) in [
        ("zero-rtt: true", "zero-rtt"),
        ("congestion-controller: bbr", "congestion-controller"),
        ("bbr-profile: aggressive", "bbr-profile"),
        ("cwnd: 64", "cwnd"),
        ("up: 50 Mbps", "up"),
        ("down: 50 Mbps", "down"),
        ("quic-versions: [v2]", "quic-versions"),
        ("dialer-proxy: p2", "dialer-proxy"),
    ] {
        let yaml = format!(
            "proxies:\n  - {{name: sq, type: shadowquic, server: x, port: 1, {extra}}}\n  - {{name: p2, type: socks5, server: 127.0.0.1, port: 2}}\nrules: ['MATCH,sq']\n"
        );
        let error = proxy_err(&yaml);
        assert!(error.contains(field), "{extra}: {error}");
        assert!(error.contains("not implemented"), "{extra}: {error}");
    }

    // T28: the QUIC endpoint applies the UDP-relevant BasicOption knobs;
    // `tfo`/`mptcp` are accepted no-ops because a QUIC server socket is UDP.
    let applied = "proxies:\n  - {name: sq, type: shadowquic, server: x, port: 1, tfo: true, mptcp: true, interface-name: eth0, routing-mark: 100, ip-version: ipv4}\nrules: ['MATCH,sq']\n";
    assert_eq!(err_tag(applied), "ok");
}

#[test]
fn deferred_families_name_their_decision() {}

#[test]
fn wireguard_accepts_the_pinned_shapes_and_names_its_gaps() {
    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    // `peers:` form with the three reserved bytes and a pre-shared key.
    assert_eq!(
        proxy_err(&format!(
            "proxies:\n  - {{name: wg, type: wireguard, private-key: {KEY}, ip: 10.13.13.2, ipv6: fd00::2, mtu: 1420, udp: true, persistent-keepalive: 25, peers: [{{server: 127.0.0.1, port: 51820, public-key: {KEY}, pre-shared-key: {KEY}, reserved: [1, 2, 3], allowed-ips: [0.0.0.0/0, '::/0']}}]}}\nrules: ['MATCH,wg']\n"
        )),
        "ok"
    );
    // The embedded single-peer form defaults its allowed IPs from ip/ipv6.
    assert_eq!(
        proxy_err(&format!(
            "proxies:\n  - {{name: wg, type: wireguard, server: 127.0.0.1, port: 51820, private-key: {KEY}, ip: 10.13.13.2, public-key: {KEY}}}\nrules: ['MATCH,wg']\n"
        )),
        "ok"
    );
    // A bad key is a load failure that names the option, not a runtime one.
    let e = proxy_err(
        "proxies:\n  - {name: wg, type: wireguard, private-key: nope, peers: [{server: 127.0.0.1, port: 1, public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, allowed-ips: [0.0.0.0/0]}]}\nrules: ['MATCH,wg']\n",
    );
    assert!(e.contains("option 'private-key'"), "{e}");
    // The pinned AmneziaWG extension is a different device implementation.
    let e = proxy_err(&format!(
        "proxies:\n  - {{name: wg, type: wireguard, private-key: {KEY}, peers: [{{server: 127.0.0.1, port: 1, public-key: {KEY}, allowed-ips: [0.0.0.0/0]}}], amnezia-wg-option: {{jc: 4}}}}\nrules: ['MATCH,wg']\n"
    ));
    assert!(e.contains("amnezia-wg-option"), "{e}");
    assert!(e.contains("amneziawg-go"), "{e}");
    // The userspace IP stack belongs to the T6/T7 device layer.
    let e = proxy_err(&format!(
        "proxies:\n  - {{name: wg, type: wireguard, private-key: {KEY}, peers: [{{server: 127.0.0.1, port: 1, public-key: {KEY}, allowed-ips: [0.0.0.0/0]}}], ip-stack: {{mode: gvisor}}}}\nrules: ['MATCH,wg']\n"
    ));
    assert!(e.contains("ip-stack.mode"), "{e}");
    assert!(e.contains("T6/T7"), "{e}");
    // A peer without allowed IPs is rejected by the pinned device too.
    let e = proxy_err(&format!(
        "proxies:\n  - {{name: wg, type: wireguard, private-key: {KEY}, peers: [{{server: 127.0.0.1, port: 1, public-key: {KEY}}}]}}\nrules: ['MATCH,wg']\n"
    ));
    assert!(e.contains("allowed-ips"), "{e}");
    let e = proxy_err(&format!(
        "proxies:\n  - {{name: wg, type: wireguard, private-key: {KEY}, peers: [{{server: 127.0.0.1, port: 1, public-key: {KEY}, reserved: [1, 2], allowed-ips: [0.0.0.0/0]}}]}}\nrules: ['MATCH,wg']\n"
    ));
    assert!(e.contains("reserved"), "{e}");
}

#[test]
fn openvpn_accepts_the_pinned_shapes_and_names_its_gaps() {
    let ca = "-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----";
    let cert = "-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----";
    let key = "-----BEGIN PRIVATE KEY-----\\nMIIB\\n-----END PRIVATE KEY-----";
    assert_eq!(
        proxy_err(&format!(
            "proxies:\n  - {{name: ov, type: openvpn, server: 127.0.0.1, port: 1194, proto: udp, cipher: AES-256-GCM, auth: SHA256, ca: \"{ca}\", cert: \"{cert}\", key: \"{key}\", username: u, password: p, data-ciphers: [AES-256-GCM, CHACHA20-POLY1305], ping: 10}}\nrules: ['MATCH,ov']\n"
        )),
        "ok"
    );
    // The transport accepts TCP framing too; the data channel is unchanged.
    assert_eq!(
        proxy_err(&format!(
            "proxies:\n  - {{name: ov, type: openvpn, server: 127.0.0.1, port: 1194, proto: tcp, ca: \"{ca}\"}}\nrules: ['MATCH,ov']\n"
        )),
        "ok"
    );
    // CBC data channels and the control-channel static keys are explicit gaps.
    let e = proxy_err(&format!(
        "proxies:\n  - {{name: ov, type: openvpn, server: 127.0.0.1, port: 1194, cipher: AES-256-CBC, ca: \"{ca}\"}}\nrules: ['MATCH,ov']\n"
    ));
    assert!(e.contains("AES-256-CBC"), "{e}");
    assert!(e.contains("not implemented"), "{e}");
    let e = proxy_err(&format!(
        "proxies:\n  - {{name: ov, type: openvpn, server: 127.0.0.1, port: 1194, ca: \"{ca}\", tls-crypt: secret}}\nrules: ['MATCH,ov']\n"
    ));
    assert!(e.contains("tls-crypt"), "{e}");
    let e = proxy_err(&format!(
        "proxies:\n  - {{name: ov, type: openvpn, server: 127.0.0.1, port: 1194, ca: \"{ca}\", comp-lzo: yes}}\nrules: ['MATCH,ov']\n"
    ));
    assert!(e.contains("comp-lzo"), "{e}");
    // The userspace IP stack belongs to the T6/T7 device layer.
    let e = proxy_err(&format!(
        "proxies:\n  - {{name: ov, type: openvpn, server: 127.0.0.1, port: 1194, ca: \"{ca}\", ip-stack: {{mode: gvisor}}}}\nrules: ['MATCH,ov']\n"
    ));
    assert!(e.contains("ip-stack.mode"), "{e}");
    // A certificate without its key is not a usable TLS identity.
    let e = proxy_err(&format!(
        "proxies:\n  - {{name: ov, type: openvpn, server: 127.0.0.1, port: 1194, ca: \"{ca}\", cert: \"{cert}\"}}\nrules: ['MATCH,ov']\n"
    ));
    assert!(e.contains("'cert' and 'key'"), "{e}");
}

#[test]
fn mesh_control_planes_load_the_pinned_shapes() {
    // These exact shapes pass `mihomo -t` for v1.19.34 (see
    // tool/kernel-compat/evidence/t16-mesh-parity.log). T19 implements the
    // configuration semantics and protocol layers, so they load here too;
    // every dial still names the T6/T7 device layer.
    let identity = "64bb654c16:0:1621a4a2d540cdf6d3b63947a29b9aaed1c86842b12da93e468fa723944c3c4357e8ac7436ccb931a0c230df4da2a8575237262a9564d543cd725b4f48de76c2:cfedde328eca0973d0ddaf3f47f78fc43f9c332b2019cecbecc7e483652d03eda60ec8322f1589580807a3ca79163bd673892eb433b54945c697dfef79e2adc7".to_string();
    let cases = [
        "proxies:\n  - {name: m, type: tailscale, server: 127.0.0.1, port: 1}\nrules: ['MATCH,m']\n".to_string(),
        "proxies:\n  - {name: m, type: tailscale, control-url: http://127.0.0.1:1}\nrules: ['MATCH,m']\n".to_string(),
        "proxies:\n  - {name: m, type: zerotier, network: 8056c2e21c000001}\nrules: ['MATCH,m']\n".to_string(),
        format!("proxies:\n  - {{name: m, type: zerotier, network: 8056c2e21c000001, identity-secret: {identity}}}\nrules: ['MATCH,m']\n"),
        "proxies:\n  - {name: m, type: easytier, network-name: billow-test, network-secret: billow-secret, peers: ['udp://127.0.0.1:11010']}\nrules: ['MATCH,m']\n".to_string(),
        "proxies:\n  - {name: m, type: easytier, network-name: billow-test, network-secret: billow-secret, peers: ['tcp://127.0.0.1:11010'], encryption-algorithm: chacha20, disable-p2p: true}\nrules: ['MATCH,m']\n".to_string(),
        "proxies:\n  - {name: m, type: easytier, network-name: billow-test, network-secret: billow-secret, peers: ['tcp://127.0.0.1:11010'], secure-mode: true, enable-encryption: true, encryption-algorithm: aes-gcm}\nrules: ['MATCH,m']\n".to_string(),
    ];
    for yaml in cases {
        assert_eq!(proxy_err(&yaml), "ok", "{yaml}");
    }
    // Registration-only Tailscale options, the EasyTier digest gap and
    // device-stack-only options are explicit rejections.
    for (yaml, needle) in [
        (
            "proxies:\n  - {name: m, type: tailscale, auth-key: tskey-1, control-url: http://127.0.0.1:1}\nrules: ['MATCH,m']\n",
            "auth-key",
        ),
        (
            "proxies:\n  - {name: m, type: tailscale, state-dir: tailscale-state, control-url: http://127.0.0.1:1}\nrules: ['MATCH,m']\n",
            "state-dir",
        ),
        (
            "proxies:\n  - {name: m, type: tailscale, accept-routes: true, control-url: http://127.0.0.1:1}\nrules: ['MATCH,m']\n",
            "accept-routes",
        ),
        (
            "proxies:\n  - {name: m, type: tailscale, exit-node: 100.64.0.1, control-url: http://127.0.0.1:1}\nrules: ['MATCH,m']\n",
            "exit-node",
        ),
        (
            "proxies:\n  - {name: m, type: tailscale, hostname: billow, control-url: http://127.0.0.1:1}\nrules: ['MATCH,m']\n",
            "hostname",
        ),
        (
            "proxies:\n  - {name: m, type: tailscale, control-url: http://127.0.0.1:1, ephemeral: true}\nrules: ['MATCH,m']\n",
            "ephemeral",
        ),
        (
            "proxies:\n  - {name: m, type: easytier, network-name: n, network-secret: s, peers: ['udp://127.0.0.1:1'], enable-encryption: true}\nrules: ['MATCH,m']\n",
            "secure-mode",
        ),
        (
            "proxies:\n  - {name: m, type: easytier, network-name: n, network-secret: s, peers: ['udp://127.0.0.1:1'], hostname: h}\nrules: ['MATCH,m']\n",
            "hostname",
        ),
        (
            "proxies:\n  - {name: m, type: easytier, network-name: n, network-secret: s, peers: ['udp://127.0.0.1:1'], ipv4: 10.0.0.1/24}\nrules: ['MATCH,m']\n",
            "ipv4",
        ),
        (
            "proxies:\n  - {name: m, type: zerotier, network: 8056c2e21c000001, ip-stack: {mode: gvisor}}\nrules: ['MATCH,m']\n",
            "ip-stack",
        ),
        (
            "proxies:\n  - {name: m, type: zerotier, network: 8056c2e21c000001, tcp-fallback-mode: force}\nrules: ['MATCH,m']\n",
            "tcp-fallback-mode",
        ),
        (
            "proxies:\n  - {name: m, type: zerotier, network: 8056c2e21c000001, tcp-fallback-relay: relay:443}\nrules: ['MATCH,m']\n",
            "tcp-fallback-relay",
        ),
        (
            "proxies:\n  - {name: m, type: tailscale, control-url: http://127.0.0.1:1, dialer-proxy: p2}\n  - {name: p2, type: direct}\nrules: ['MATCH,m']\n",
            "dialer-proxy",
        ),
    ] {
        let error = proxy_err(yaml);
        assert!(error.starts_with("unsupported:"), "{error}");
        assert!(error.contains(needle), "{error}");
    }
}

#[tokio::test]
async fn implemented_device_families_load_and_dial_names_the_t6_t7_gap() {
    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let ca = "-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----";
    let zt_identity = "64bb654c16:0:1621a4a2d540cdf6d3b63947a29b9aaed1c86842b12da93e468fa723944c3c4357e8ac7436ccb931a0c230df4da2a8575237262a9564d543cd725b4f48de76c2:cfedde328eca0973d0ddaf3f47f78fc43f9c332b2019cecbecc7e483652d03eda60ec8322f1589580807a3ca79163bd673892eb433b54945c697dfef79e2adc7".to_string();
    let configs = [
        format!(
            "mixed-port: 1\nproxies:\n  - {{name: wg, type: wireguard, private-key: {KEY}, peers: [{{server: 127.0.0.1, port: 9, public-key: {KEY}, allowed-ips: [0.0.0.0/0]}}]}}\nrules: ['MATCH,wg']\n"
        ),
        format!(
            "mixed-port: 1\nproxies:\n  - {{name: ov, type: openvpn, server: 127.0.0.1, port: 9, ca: \"{ca}\"}}\nrules: ['MATCH,ov']\n"
        ),
        "mixed-port: 1\nproxies:\n  - {name: ts, type: tailscale, control-url: http://127.0.0.1:1}\nrules: ['MATCH,ts']\n".to_string(),
        format!(
            "mixed-port: 1\nproxies:\n  - {{name: zt, type: zerotier, network: 8056c2e21c000001, identity-secret: {zt_identity}}}\nrules: ['MATCH,zt']\n"
        ),
        "mixed-port: 1\nproxies:\n  - {name: et, type: easytier, network-name: billow, network-secret: s, peers: ['tcp://127.0.0.1:1']}\nrules: ['MATCH,et']\n".to_string(),
    ];
    for yaml in configs {
        let loaded = load_config(&yaml, "dial-gap.yaml").expect("configuration loads");
        let proxy = &loaded.config.proxies[0];
        let target = billow_kernel::outbound::Target {
            host: "127.0.0.1".to_string(),
            port: 80,
        };
        let tls = billow_kernel::outbound::tls::ClientTls::new(&[]);
        let error = match billow_kernel::outbound::dial(
            proxy,
            &target,
            std::time::Duration::from_millis(500),
            &tls,
        )
        .await
        {
            Ok(_) => panic!("{} must not produce a stream without the T6/T7 stack", proxy.name),
            Err(error) => error,
        };
        let text = error.to_string();
        assert!(text.contains("T6/T7"), "{}: {text}", proxy.name);
        assert!(text.contains("IP stack"), "{}: {text}", proxy.name);
    }
}

#[test]
fn masque_accepts_the_connect_udp_subset() {
    // RFC 9298 CONNECT-UDP: the QUIC/HTTP/3 association carries UDP only, so
    // the loadable shape is the server plus TLS and the association switch.
    for body in [
        "server: 127.0.0.1, port: 443, udp: true".to_string(),
        "server: 127.0.0.1, port: 443, udp: true, sni: masque.example, skip-cert-verify: true".to_string(),
        "server: 127.0.0.1, port: 443, udp: true, handshake-timeout: 5".to_string(),
        // The pinned placeholder does nothing (the adapter pins the endpoint
        // key instead of verifying a name), so it loads and is ignored.
        "server: 127.0.0.1, port: 443, udp: true, name-cert-verify: example.org".to_string(),
        // `udp: false` loads as in Mihomo; every dial then refuses by name.
        "server: 127.0.0.1, port: 443".to_string(),
        // Empty values ask for nothing and leave the CONNECT-UDP subset.
        "server: 127.0.0.1, port: 443, udp: true, ip: '', ipv6: '', uri: '', network: '', private-key: '', public-key: '', mtu: 0, ip-stack: {}".to_string(),
    ] {
        let yaml = format!("proxies:\n  - {{name: m, type: masque, {body}}}\nrules: ['MATCH,m']\n");
        load_config(&yaml, "t").unwrap_or_else(|e| panic!("{body}: {e}"));
    }
}

/// Throwaway P-256 key material for the configuration tests: a SEC1
/// `ECPrivateKey` and an endpoint `SubjectPublicKeyInfo`, both base64, as the
/// pinned adapter's `x509.ParseECPrivateKey`/`x509.ParsePKIXPublicKey` read
/// them. They authenticate nothing; they only exercise the WARP shape.
const MASQUE_TEST_KEY: &str = "MHcCAQEEIDKh56LbUI7PTfKO5ojiPkNrK2H8jcLrmfdlhv3TsqRzoAoGCCqGSM49AwEHoUQDQgAEMAUkhPqJXQGTsDj6a3yC7F2zxIWXs6UJCc/Mwr6wL3GWgqbrP6tvB52ZUbnalrJXSxMwUFXDTHNqxPhpzzUawA==";
const MASQUE_TEST_ENDPOINT_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMAUkhPqJXQGTsDj6a3yC7F2zxIWXs6UJCc/Mwr6wL3GWgqbrP6tvB52ZUbnalrJXSxMwUFXDTHNqxPhpzzUawA==";

#[test]
fn masque_accepts_the_pinned_connect_ip_shape() {
    // The pinned `MasqueOption`: keys, local addresses, URI, MTU, ip-stack,
    // remote resolution and the TLS options all load.
    for body in [
        format!(
            "server: 127.0.0.1, port: 443, udp: true, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_ENDPOINT_KEY}', ip: 172.16.0.2, ipv6: fd00::2"
        ),
        format!(
            "server: 127.0.0.1, port: 443, udp: true, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_ENDPOINT_KEY}', ip: 172.16.0.2/32, uri: https://example.org/tunnel, mtu: 1400"
        ),
        format!(
            "server: 127.0.0.1, port: 443, udp: true, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_ENDPOINT_KEY}', ipv6: fd00::2/128, ip-stack: {{mode: mips, congestion-controller: bbr}}"
        ),
        format!(
            "server: 127.0.0.1, port: 443, udp: true, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_ENDPOINT_KEY}', ip: 172.16.0.2, remote-dns-resolve: true, dns: [1.1.1.1, 'udp://1.1.1.1:5353', '[fd00::1]:53']"
        ),
        format!(
            "server: 127.0.0.1, port: 443, udp: true, sni: consumer-masque.cloudflareclient.com, skip-cert-verify: true, handshake-timeout: 5, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_ENDPOINT_KEY}', ip: 172.16.0.2"
        ),
        format!(
            "server: 127.0.0.1, port: 443, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_ENDPOINT_KEY}', ip: 172.16.0.2"
        ),
    ] {
        let yaml = format!("proxies:\n  - {{name: m, type: masque, {body}}}\nrules: ['MATCH,m']\n");
        load_config(&yaml, "t").unwrap_or_else(|e| panic!("{body}: {e}"));
    }
}

#[test]
fn masque_connect_ip_shape_is_strict() {
    for (body, needle) in [
        (
            format!("server: x, port: 1, public-key: '{MASQUE_TEST_ENDPOINT_KEY}', ip: 172.16.0.2"),
            "option 'private-key' is required",
        ),
        (
            format!("server: x, port: 1, private-key: '{MASQUE_TEST_KEY}', ip: 172.16.0.2"),
            "option 'public-key' is required",
        ),
        (
            format!("server: x, port: 1, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_ENDPOINT_KEY}'"),
            "missing local address",
        ),
        (
            "server: x, port: 1, private-key: not-base64!, public-key: x, ip: 172.16.0.2".to_string(),
            "option 'private-key'",
        ),
        (
            format!("server: x, port: 1, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_KEY}', ip: 172.16.0.2"),
            "option 'public-key'",
        ),
        (
            format!("server: x, port: 1, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_ENDPOINT_KEY}', ip: fd00::2"),
            "not an IPv4 address",
        ),
        (
            format!("server: x, port: 1, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_ENDPOINT_KEY}', ip: 172.16.0.2, mtu: 40"),
            "option 'mtu'",
        ),
        (
            format!("server: x, port: 1, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_ENDPOINT_KEY}', ip: 172.16.0.2, mtu: -1"),
            "option 'mtu'",
        ),
        (
            format!("server: x, port: 1, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_ENDPOINT_KEY}', ip: 172.16.0.2, ip-stack: {{mode: gvisor}}"),
            "gvisor",
        ),
        (
            format!("server: x, port: 1, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_ENDPOINT_KEY}', ip: 172.16.0.2, ip-stack: {{mode: auto, tcp: true}}"),
            "ip-stack.tcp",
        ),
        (
            format!("server: x, port: 1, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_ENDPOINT_KEY}', ip: 172.16.0.2, ip-stack: {{congestion-controller: vegas}}"),
            "congestion-controller",
        ),
        (
            format!("server: x, port: 1, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_ENDPOINT_KEY}', ip: 172.16.0.2, dns: ['https://1.1.1.1/dns-query']"),
            "udp://",
        ),
        (
            format!("server: x, port: 1, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_ENDPOINT_KEY}', ip: 172.16.0.2, dns: [dns.example]"),
            "not an IP address",
        ),
        (
            format!("server: x, port: 1, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_ENDPOINT_KEY}', ip: 172.16.0.2, uri: http://example.org"),
            "https",
        ),
        (
            format!("server: x, port: 1, private-key: '{MASQUE_TEST_KEY}', public-key: '{MASQUE_TEST_ENDPOINT_KEY}', ip: 172.16.0.2, uri: 'https://example.org/{{target}}'"),
            "URI template",
        ),
        (
            "server: x, port: 1, udp: true, network: h2".to_string(),
            "option 'network' value 'h2'",
        ),
        (
            "server: x, port: 1, udp: true, network: h3-l4proxy".to_string(),
            "h3-l4proxy",
        ),
        // `congestion-controller: cubic|new_reno|bbr` and a non-negative
        // `cwnd` are implemented (T28); unknown controllers and a negative
        // window stay rejections.
        (
            "server: x, port: 1, udp: true, congestion-controller: vegas".to_string(),
            "congestion-controller",
        ),
        (
            "server: x, port: 1, udp: true, cwnd: -1".to_string(),
            "option 'cwnd' must not be negative",
        ),
        (
            "server: x, port: 1, udp: true, bbr-profile: standard".to_string(),
            "bbr-profile",
        ),
        (
            "server: x, port: 1, udp: true, dialer-proxy: hop".to_string(),
            "option 'dialer-proxy'",
        ),
        (
            "server: x, port: 1, udp: true, mtu: 1280".to_string(),
            "option 'private-key' is required",
        ),
        (
            "server: x, port: 1, udp: true, handshake-timeout: -1".to_string(),
            "handshake-timeout",
        ),
    ] {
        let yaml = format!("proxies:\n  - {{name: m, type: masque, {body}}}\nrules: ['MATCH,m']\n");
        let e = proxy_err(&yaml);
        assert!(e.contains(needle), "{body}: {e}");
    }
}

#[test]
fn mieru_options_are_strict() {
    // The TCP stream is implemented; both port shapes and both handshake
    // modes (the mode only changes when the handshake runs) load.
    for body in [
        "port: 2999, transport: TCP, username: u, password: p".to_string(),
        "port-range: 2090-2099, transport: TCP, username: u, password: p".to_string(),
        "port: 2999, transport: TCP, username: u, password: p, handshake-mode: HANDSHAKE_NO_WAIT".to_string(),
        "port: 2999, transport: TCP, username: u, password: p, multiplexing: MULTIPLEXING_OFF".to_string(),
    ] {
        let yaml = format!("proxies:\n  - {{name: m, type: mieru, server: x, {body}}}\nrules: ['MATCH,m']\n");
        load_config(&yaml, "t").unwrap_or_else(|e| panic!("{body}: {e}"));
    }
    for (body, needle) in [
        (
            "port: 2999, transport: UDP, username: u, password: p",
            "transport' value 'UDP'",
        ),
        (
            "port: 2999, transport: TCP, username: u, password: p, udp: true",
            "option 'udp' is not implemented",
        ),
        (
            "port: 2999, transport: TCP, username: u, password: p, multiplexing: MULTIPLEXING_LOW",
            "multiplexing' value 'MULTIPLEXING_LOW'",
        ),
        (
            "port: 2999, transport: TCP, username: u, password: p, traffic-pattern: AbCd",
            "traffic-pattern' value 'AbCd'",
        ),
        (
            "port: 2999, port-range: 2000-2100, transport: TCP, username: u, password: p",
            "cannot both be set",
        ),
        (
            "transport: TCP, username: u, password: p",
            "either 'port' or 'port-range'",
        ),
    ] {
        let yaml = format!("proxies:\n  - {{name: m, type: mieru, server: x, {body}}}\nrules: ['MATCH,m']\n");
        let e = proxy_err(&yaml);
        assert!(e.contains(needle), "{body}: {e}");
    }
    let e = proxy_err("proxies:\n  - {name: m, type: mieru, server: x, port: 1, transport: TCP}\nrules: ['MATCH,m']\n");
    assert!(e.contains("missing required option 'username'"), "{e}");
}

#[test]
fn sudoku_options_are_strict() {
    for body in [
        "key: k".to_string(),
        "key: k, table-type: prefer_ascii, enable-pure-downlink: false".to_string(),
        "key: k, table-type: up_ascii_down_entropy".to_string(),
        "key: k, custom-table: xpxvvpvv".to_string(),
        "key: k, custom-tables: [\"xpxvvpvv\", \"vxpvxvvp\"]".to_string(),
        "key: k, aead-method: none, padding-min: 0, padding-max: 0".to_string(),
        "key: k, httpmask: {disable: true}, multiplex: off".to_string(),
        "key: k, httpmask: {disable: false, mode: legacy, path-root: aabbcc}".to_string(),
        "key: k, http-mask: false, multiplex: auto".to_string(),
        // `multiplex: on` is the implemented Sudoku session mux, not a gap.
        "key: k, multiplex: on".to_string(),
        // TLS/host only shape the HTTP tunnel modes, which the legacy mask
        // does not use (Mihomo ignores them there as well).
        "key: k, http-mask-tls: true, http-mask-host: example.org".to_string(),
    ] {
        let yaml = format!("proxies:\n  - {{name: s, type: sudoku, server: x, port: 1, {body}}}\nrules: ['MATCH,s']\n");
        load_config(&yaml, "t").unwrap_or_else(|e| panic!("{body}: {e}"));
    }
    for (body, needle) in [
        ("key: k, http-mask-mode: stream", "http-mask-mode' value 'stream'"),
        ("key: k, httpmask: {mode: ws}", "http-mask-mode' value 'ws'"),
        ("key: k, multiplex: always", "multiplex' value 'always'"),
        ("key: k, udp: true", "option 'udp' is not implemented"),
        ("key: k, table-type: prefer_magic", "table-type' value 'prefer_magic'"),
        ("key: k, custom-table: xxxvvvpp", "custom table pattern"),
        ("key: k, aead-method: rc4", "aead-method' value 'rc4'"),
        ("key: k, padding-min: 30, padding-max: 20", "padding-max' must be >="),
        ("key: k, path-root: a/b", "path-root' must be a single path segment"),
    ] {
        let yaml = format!("proxies:\n  - {{name: s, type: sudoku, server: x, port: 1, {body}}}\nrules: ['MATCH,s']\n");
        let e = proxy_err(&yaml);
        assert!(e.contains(needle), "{body}: {e}");
    }
    let e = proxy_err("proxies:\n  - {name: s, type: sudoku, server: x, port: 1}\nrules: ['MATCH,s']\n");
    assert!(e.contains("missing required option 'key'"), "{e}");
}

// ---------------------------------------------------------------------------
// T27: BasicOption dialer knobs, TLS identities and QUIC transport tuning.
// ---------------------------------------------------------------------------

#[test]
fn t27_tls_identity_options_are_parsed() {
    let yaml = "proxies:\n  - {name: s, type: socks5, server: 127.0.0.1, port: 1, tls: true, sni: s.example, skip-cert-verify: false, name-cert-verify: verify.example, fingerprint: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99', certificate: cert.pem, private-key: key.pem}\nrules: ['MATCH,s']\n";
    let loaded = load_config(yaml, "t").expect("TLS identity options load");
    let billow_kernel::proxies::Protocol::Socks5(proxy) = &loaded.config.proxies[0].protocol else {
        panic!("expected socks5");
    };
    let settings = &proxy.tls_settings;
    assert_eq!(settings.name_cert_verify.as_deref(), Some("verify.example"));
    assert_eq!(settings.fingerprint.as_deref().map(|bytes| bytes.len()), Some(32));
    assert_eq!(settings.certificate.as_deref(), Some("cert.pem"));
    assert_eq!(settings.private_key.as_deref(), Some("key.pem"));

    // `fingerprint` is a certificate pin, not a browser fingerprint.
    let error = proxy_err("proxies:\n  - {name: s, type: socks5, server: x, port: 1, tls: true, fingerprint: chrome}\nrules: ['MATCH,s']\n");
    assert!(error.contains("option 'fingerprint'"), "{error}");
    // With TLS off Mihomo ignores the identity options, so they load unread.
    load_config(
        "proxies:\n  - {name: s, type: socks5, server: x, port: 1, fingerprint: chrome, certificate: cert.pem}\nrules: ['MATCH,s']\n",
        "t",
    )
    .expect("TLS identity options are ignored without TLS");
}

#[test]
fn t27_quic_transport_tuning_is_parsed() {
    let tuic = "proxies:\n  - {name: q, type: tuic, server: x, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, password: p, congestion-controller: bbr, cwnd: 32, recv-window-conn: 1024, recv-window: 2048, disable-mtu-discovery: true}\nrules: ['MATCH,q']\n";
    let loaded = load_config(tuic, "t").expect("TUIC tuning loads");
    let billow_kernel::proxies::Protocol::Tuic(proxy) = &loaded.config.proxies[0].protocol else {
        panic!("expected tuic");
    };
    assert_eq!(proxy.congestion_controller.as_deref(), Some("bbr"));
    assert_eq!(proxy.cwnd, 32);
    assert_eq!(proxy.stream_receive_window, Some(1024));
    assert_eq!(proxy.connection_receive_window, Some(2048));
    assert!(proxy.disable_mtu_discovery);
    let error = proxy_err("proxies:\n  - {name: q, type: tuic, server: x, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, password: p, congestion-controller: bbr_meta_v1}\nrules: ['MATCH,q']\n");
    assert!(error.contains("congestion-controller"), "{error}");

    let h2 = "proxies:\n  - {name: q, type: hysteria2, server: x, port: 1, password: p, cwnd: 64, initial-stream-receive-window: 1024, max-stream-receive-window: 4096, initial-connection-receive-window: 2048, max-connection-receive-window: 8192}\nrules: ['MATCH,q']\n";
    let loaded = load_config(h2, "t").expect("hysteria2 tuning loads");
    let billow_kernel::proxies::Protocol::Hysteria2(proxy) = &loaded.config.proxies[0].protocol else {
        panic!("expected hysteria2");
    };
    assert_eq!(proxy.cwnd, 64);
    assert_eq!(proxy.stream_receive_window, Some(4096));
    assert_eq!(proxy.connection_receive_window, Some(8192));

    let h1 = "proxies:\n  - {name: q, type: hysteria, server: x, port: 1, up: 50 Mbps, down: 50 Mbps, recv-window-conn: 1024, recv-window: 2048, disable-mtu-discovery: true}\nrules: ['MATCH,q']\n";
    let loaded = load_config(h1, "t").expect("hysteria tuning loads");
    let billow_kernel::proxies::Protocol::Hysteria(proxy) = &loaded.config.proxies[0].protocol else {
        panic!("expected hysteria");
    };
    assert_eq!(proxy.stream_receive_window, Some(1024));
    assert_eq!(proxy.connection_receive_window, Some(2048));
    assert!(proxy.disable_mtu_discovery);
}

#[test]
fn t27_socks5_udp_is_accepted_and_chain_is_named() {
    let loaded = load_config(
        "proxies:\n  - {name: s, type: socks5, server: 127.0.0.1, port: 1080, udp: true}\nrules: ['MATCH,s']\n",
        "t",
    )
    .expect("socks5 UDP association loads");
    assert!(loaded.config.proxies[0].udp_enabled());
    let error = proxy_err(
        "proxies:\n  - {name: s, type: socks5, server: 127.0.0.1, port: 1080, udp: true, dialer-proxy: hop}\n  - {name: hop, type: socks5, server: 127.0.0.1, port: 1081}\nrules: ['MATCH,s']\n",
    );
    assert!(error.contains("option 'udp' with 'dialer-proxy'"), "{error}");
}

#[test]
fn t31_hysteria2_udp_is_always_enabled_and_a_chain_loads() {
    // The pinned Hysteria2Option has no `udp` field: `udp: true` and
    // `udp: false` are tolerated no-ops and UDP stays enabled (the outbound
    // sets `UDP: true` in its Base). Traffic must never be accepted and then
    // dropped, so both load.
    for flag in ["udp: true", "udp: false"] {
        let loaded = load_config(
            &format!(
                "proxies:\n  - {{name: q, type: hysteria2, server: 127.0.0.1, port: 8443, password: p, {flag}}}\nrules: ['MATCH,q']\n"
            ),
            "t",
        )
        .expect("hysteria2 UDP loads");
        assert!(
            loaded.config.proxies[0].udp_enabled(),
            "hysteria2 UDP is unconditionally enabled ({flag})"
        );
    }
    // A QUIC UDP session cannot be carried through a hop, but the pinned
    // client accepts the configuration and the runtime refuses only the
    // association (a named `DialError::Chain`). The rule is DIRECT, so the
    // chained proxy is unused: rejecting the whole file would take down every
    // unrelated proxy with it.
    let chained = load_config(
        "proxies:\n  - {name: q, type: hysteria2, server: 127.0.0.1, port: 8443, password: p, dialer-proxy: hop}\n  - {name: hop, type: socks5, server: 127.0.0.1, port: 1081}\nrules: ['MATCH,DIRECT']\n",
        "t",
    )
    .expect("a hysteria2 chain loads");
    assert_eq!(chained.config.proxies[0].dialer_proxy(), Some("hop"));
}

#[test]
fn t28_tcp_basic_options_reach_the_shared_dialer_families() {
    // mieru and sudoku dial their server with the shared stream dialer, so
    // tfo/mptcp/interface-name/routing-mark/ip-version are applied to that
    // socket instead of being rejected.
    for (kind, base) in [
        (
            "mieru",
            "server: 127.0.0.1, port: 1, transport: TCP, username: u, password: p",
        ),
        ("sudoku", "server: 127.0.0.1, port: 1, key: k"),
    ] {
        let yaml = format!(
            "proxies:\n  - {{name: p, type: {kind}, {base}, tfo: true, mptcp: true, interface-name: lo0, routing-mark: 100, ip-version: ipv4}}\nrules: ['MATCH,p']\n"
        );
        let loaded = load_config(&yaml, "t").unwrap_or_else(|e| panic!("{kind}: {e}"));
        let proxy = &loaded.config.proxies[0];
        assert!(proxy.dialer.tfo, "{kind}");
        assert!(proxy.dialer.mptcp, "{kind}");
        assert_eq!(proxy.dialer.interface_name.as_deref(), Some("lo0"), "{kind}");
        assert_eq!(proxy.dialer.routing_mark, 100, "{kind}");
        assert_eq!(proxy.dialer.ip_version, billow_kernel::proxies::IpVersion::V4Only);
    }
    // shadowquic is QUIC over UDP: interface-name/routing-mark shape the UDP
    // endpoint and ip-version filters its server address. tfo/mptcp are TCP
    // options the pinned packet dialer never applies, so they are accepted
    // no-ops here too.
    let yaml = "proxies:\n  - {name: p, type: shadowquic, server: 127.0.0.1, port: 1, username: u, password: p, interface-name: lo0, routing-mark: 100, ip-version: ipv4, tfo: true, mptcp: true}\nrules: ['MATCH,p']\n";
    let loaded = load_config(yaml, "t").expect("shadowquic basic options load");
    let proxy = &loaded.config.proxies[0];
    assert_eq!(proxy.dialer.interface_name.as_deref(), Some("lo0"));
    assert_eq!(proxy.dialer.ip_version, billow_kernel::proxies::IpVersion::V4Only);
}

#[test]
fn t28_masque_quic_controller_and_trojan_ss_opts_are_parsed() {
    load_config(
        "proxies:\n  - {name: m, type: masque, server: 127.0.0.1, port: 1, udp: true, congestion-controller: bbr, cwnd: 32}\nrules: ['MATCH,m']\n",
        "t",
    )
    .expect("masque QUIC controller loads");
    let error = proxy_err(
        "proxies:\n  - {name: m, type: masque, server: 127.0.0.1, port: 1, udp: true, bbr-profile: standard}\nrules: ['MATCH,m']\n",
    );
    assert!(error.contains("option 'bbr-profile'"), "{error}");
    // Pinned `SetCongestionController` treats bbr_meta_v2 as an alias of bbr.
    load_config(
        "proxies:\n  - {name: m, type: masque, server: 127.0.0.1, port: 1, udp: true, congestion-controller: bbr_meta_v2}\nrules: ['MATCH,m']\n",
        "t",
    )
    .expect("masque bbr_meta_v2 loads");
    let error = proxy_err(
        "proxies:\n  - {name: m, type: masque, server: 127.0.0.1, port: 1, udp: true, congestion-controller: bbr_meta_v1}\nrules: ['MATCH,m']\n",
    );
    assert!(
        error.contains("bbr_meta_v1") && error.contains("option 'congestion-controller'"),
        "{error}"
    );

    for method in ["AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-IETF-POLY1305", "XCHACHA20-IETF-POLY1305"] {
        load_config(
            &format!(
                "proxies:\n  - {{name: t, type: trojan, server: 127.0.0.1, port: 443, password: p, ss-opts: {{enabled: true, method: {method}, password: sp}}}}\nrules: ['MATCH,t']\n"
            ),
            "t",
        )
        .unwrap_or_else(|e| panic!("trojan ss-opts {method}: {e}"));
    }
    for cipher in ["aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"] {
        load_config(
            &format!(
                "proxies:\n  - {{name: s, type: ss, server: 127.0.0.1, port: 1, cipher: {cipher}, password: p}}\nrules: ['MATCH,s']\n"
            ),
            "t",
        )
        .unwrap_or_else(|e| panic!("ss cipher {cipher}: {e}"));
    }
    // Stream ciphers stay named rejections until their framing is ported.
    let error = proxy_err(
        "proxies:\n  - {name: s, type: ss, server: 127.0.0.1, port: 1, cipher: aes-256-cfb, password: p}\nrules: ['MATCH,s']\n",
    );
    assert!(error.contains("option 'cipher' value 'aes-256-cfb'"), "{error}");

    load_config(
        "proxies:\n  - {name: t, type: trojan, server: 127.0.0.1, port: 443, password: p, ss-opts: {enabled: true, method: AES-256-GCM, password: sp}}\nrules: ['MATCH,t']\n",
        "t",
    )
    .expect("trojan ss-opts loads");
    // A disabled block is a no-op, as in the pinned type.
    load_config(
        "proxies:\n  - {name: t, type: trojan, server: 127.0.0.1, port: 443, password: p, ss-opts: {}}\nrules: ['MATCH,t']\n",
        "t",
    )
    .expect("disabled ss-opts loads");
    let error = proxy_err(
        "proxies:\n  - {name: t, type: trojan, server: 127.0.0.1, port: 443, password: p, ss-opts: {enabled: true, method: rc4-md5, password: sp}}\nrules: ['MATCH,t']\n",
    );
    assert!(error.contains("option 'ss-opts.method'"), "{error}");
    let error = proxy_err(
        "proxies:\n  - {name: t, type: trojan, server: 127.0.0.1, port: 443, password: p, ss-opts: {enabled: true}}\nrules: ['MATCH,t']\n",
    );
    assert!(error.contains("option 'ss-opts.password'"), "{error}");
}
