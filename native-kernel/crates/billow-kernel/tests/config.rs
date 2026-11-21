use std::net::{IpAddr, Ipv4Addr};

use billow_kernel::config::{parse_rule, GeoSiteDatabase, RulesSource};
use billow_kernel::{load_config, Action, ConfigError, Matcher};

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
    assert!(loaded.warnings.is_empty());
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
        "proxy-groups",
        "proxy-providers",
        "rule-providers",
        "dns",
        "hosts",
        "tun",
        "listeners",
        "tunnels",
        "sniffer",
        "external-controller",
        "secret",
        "geodata-mode",
        "profile",
        "experimental",
        "ipv6",
        "unified-delay",
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
fn rejects_unimplemented_rule_types_and_outbounds() {
    assert!(err_tag("rules: ['GEOIP,CN,DIRECT']\n").starts_with("unsupported"));
    assert!(err_tag("rules: ['DOMAIN-KEYWORD,x,DIRECT']\n").starts_with("unsupported"));
    assert!(err_tag("rules: ['PROCESS-NAME,x,DIRECT']\n").starts_with("unsupported"));
    // A rule naming a proxy that `proxies` does not define is not a group support claim.
    assert!(err_tag("rules: ['DOMAIN,a.example,Proxy']\n").starts_with("unsupported"));
    assert!(err_tag("rules: ['DOMAIN,a.example,DIRECT,src']\n").starts_with("invalid_value"));
    assert!(err_tag("rules: ['IP-CIDR,10.0.0.0/8,DIRECT,src']\n").starts_with("unsupported"));
    assert!(
        err_tag("rules: ['MATCH,DIRECT', 'DOMAIN,a.example,REJECT']\n")
            .starts_with("invalid_value")
    );
    assert!(err_tag("rules: MATCH,DIRECT\n").starts_with("invalid_yaml"));
}

#[test]
fn rejects_unimplemented_modes_and_levels() {
    assert!(err_tag("mode: global\n").starts_with("unsupported"));
    assert!(err_tag("log-level: trace\n").starts_with("unsupported"));
    assert!(err_tag("mixed-port: 0\n").starts_with("invalid_value"));
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
        Matcher::IpCidr(n) => {
            assert!(n.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99))));
            assert!(!n.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
            assert!(!n.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(parse_rule("IP-CIDR6,2001:db8::/32,DIRECT").is_ok());
    assert!(parse_rule("IP-CIDR6,10.0.0.0/8,DIRECT").is_err());
}

#[test]
fn geosite_databases_match_domains_and_suffixes() {
    let mut db = GeoSiteDatabase::default();
    db.merge_yaml(
        "key: gfw\ntags:\n  - name: adblock\n    rules:\n      - domain: [ads.example]\n      - sub_domain: [tracker.example, '*.wild.example']\n",
    )
    .unwrap();
    db.merge_yaml("key: cn\ntags:\n  - name: geolocation-cn\n    rules:\n      - domain_keyword: [chinanet]\n").unwrap();
    assert!(db.matches("gfw", "ads.example"));
    assert!(db.matches("gfw/adblock", "x.tracker.example"));
    assert!(db.matches("gfw", "wild.example"));
    // geosite sub_domain semantics: the entry itself and any subdomain match.
    assert!(db.matches("gfw", "tracker.example"));
    assert!(db.matches("gfw", "a.b.tracker.example"));
    assert!(!db.matches("gfw", "nottracker.example"));
    assert!(!db.matches("gfw", "unrelated.example"));
    assert!(!db.matches("unknown", "ads.example"));
    assert!(db.matches("cn", "host.chinanet.example"));

    let mut unsupported = GeoSiteDatabase::default();
    let e = unsupported
        .merge_yaml("key: gfw\ntags:\n  - name: t\n    rules:\n      - domain_regex: ['^.*$']\n")
        .unwrap_err();
    assert!(matches!(e, ConfigError::Unsupported(_)));
    let e = unsupported
        .merge_yaml(
            "key: gfw\ntags:\n  - name: t\n    rules:\n      - sub_domain: ['*.ex*ample']\n",
        )
        .unwrap_err();
    assert!(matches!(e, ConfigError::Unsupported(_)));
}

#[test]
fn geosite_rule_without_database_directory_fails_at_start() {
    let yaml = "mixed-port: 1\nrules: ['GEOSITE,gfw,REJECT']\n";
    let e = billow_kernel::Kernel::start_from_yaml(yaml, None, billow_kernel::Limits::default())
        .err()
        .expect("must fail");
    assert!(
        matches!(
            e,
            billow_kernel::StartError::Config(ConfigError::Unsupported(_))
        ),
        "{e}"
    );
}

#[test]
fn geosite_missing_key_fails_loudly() {
    let dir = std::env::temp_dir().join(format!("billow-geosite-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut keys = std::collections::BTreeSet::new();
    keys.insert("gfw".to_string());
    let e = GeoSiteDatabase::load_from_dir(&dir, &keys).unwrap_err();
    assert!(matches!(e, ConfigError::Unsupported(_)), "{e}");
    std::fs::write(
        dir.join("gfw.yaml"),
        "key: gfw\ntags:\n  - name: ads\n    rules:\n      - domain: [x.example]\n",
    )
    .unwrap();
    let ok = GeoSiteDatabase::load_from_dir(&dir, &keys).unwrap();
    assert!(ok.matches("gfw", "x.example"));
    assert!(!ok.matches("gfw", "other.example"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn geosite_dat_file_fails_explicitly() {
    // A binary `.dat` is accepted only if it happens to be YAML; otherwise it must be reported.
    let dir = std::env::temp_dir().join(format!("billow-geosite-dat-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("gfw.dat"), b"\x00\x01binary").unwrap();
    let mut keys = std::collections::BTreeSet::new();
    keys.insert("gfw".to_string());
    let e = GeoSiteDatabase::load_from_dir(&dir, &keys).unwrap_err();
    assert!(matches!(e, ConfigError::Unsupported(_)), "{e}");
    std::fs::remove_dir_all(&dir).unwrap();
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
rules:
  - DOMAIN,a.example,ss1
  - MATCH,h1
"#;
    let loaded = load_config(yaml, "test.yaml").expect("accepted");
    let config = loaded.config;
    assert_eq!(config.proxies.len(), 5);
    assert_eq!(config.proxies[0].type_name(), "socks5");
    assert_eq!(config.proxies[2].type_name(), "ss");
    assert!(config.proxies[2].udp_enabled());
    assert_eq!(config.action_name(billow_kernel::Action::Proxy(2)), "ss1");
    assert_eq!(config.action_name(billow_kernel::Action::Proxy(1)), "h1");
    assert!(config
        .feature_summary()
        .contains("protocols=s5=socks5,h1=http,ss1=ss,tj=trojan,vl=vless"));
}

#[test]
fn unimplemented_protocol_and_option_name_the_field() {
    let e = proxy_err("proxies:\n  - {name: s1, type: hysteria2, server: x, port: 1, up: 100}\nrules: ['MATCH,DIRECT']\n");
    assert!(e.starts_with("unsupported"), "{e}");
    assert!(e.contains("proxies[0] (name=s1, type=hysteria2)"), "{e}");
    let e = proxy_err("proxies:\n  - {name: v, type: vless, server: x, port: 1, uuid: 9d0cb9d0964f4ef6897d6c6b3ccf9e68, reality-opts: {public-key: k}}\nrules: ['MATCH,DIRECT']\n");
    assert!(
        e.contains("option 'reality-opts' is not implemented"),
        "{e}"
    );
    let e = proxy_err("proxies:\n  - {name: t, type: trojan, server: x, port: 1, password: p, smux: {enabled: true}}\nrules: ['MATCH,DIRECT']\n");
    assert!(e.contains("option 'smux' is not implemented"), "{e}");
    let e = proxy_err("proxies:\n  - {name: t, type: trojan, server: x, port: 1, password: p, bogus: 1}\nrules: ['MATCH,DIRECT']\n");
    assert!(e.contains("option 'bogus' is not implemented"), "{e}");
    let e = proxy_err("proxies:\n  - {name: s, type: ss, server: x, port: 1, cipher: rc4-md5, password: p}\nrules: ['MATCH,DIRECT']\n");
    assert!(
        e.contains("option 'cipher' value 'rc4-md5' is not implemented"),
        "{e}"
    );
    let e = proxy_err("proxies:\n  - {name: s, type: ss, server: x, port: 1, cipher: aes-256-gcm, password: p, plugin: obfs, plugin-opts: {mode: tls}}\nrules: ['MATCH,DIRECT']\n");
    assert!(e.contains("option 'plugin' value 'obfs'"), "{e}");
    let e = proxy_err("proxies:\n  - {name: v, type: vless, server: x, port: 1, uuid: 9d0cb9d0964f4ef6897d6c6b3ccf9e68, flow: xtls-rprx-vision}\nrules: ['MATCH,DIRECT']\n");
    assert!(e.contains("option 'flow' value 'xtls-rprx-vision'"), "{e}");
    let e = proxy_err("proxies:\n  - {name: s, type: socks5, server: x, port: 1, udp-over-tcp: true}\nrules: ['MATCH,DIRECT']\n");
    assert!(
        e.contains("option 'udp-over-tcp' is not implemented"),
        "{e}"
    );
}


/// The option table must not admit a key the parser does not honour: each of
/// these was silently accepted before the T4 repair. One case per key so a
/// regression names the exact field.
#[test]
fn every_unimplemented_proxy_option_is_rejected_with_its_field() {
    let cases: &[(&str, &str, &str)] = &[
        ("socks5", "server: 127.0.0.1, port: 1", "udp: true"),
        ("socks5", "server: 127.0.0.1, port: 1", "fingerprint: chrome"),
        ("socks5", "server: 127.0.0.1, port: 1", "certificate: x.pem"),
        ("socks5", "server: 127.0.0.1, port: 1", "private-key: k.pem"),
        ("socks5", "server: 127.0.0.1, port: 1", "name-cert-verify: x"),
        ("socks5", "server: 127.0.0.1, port: 1", "ip-version: ipv4"),
        ("http", "server: 127.0.0.1, port: 1", "fingerprint: chrome"),
        ("http", "server: 127.0.0.1, port: 1", "certificate: x.pem"),
        ("http", "server: 127.0.0.1, port: 1", "private-key: k.pem"),
        ("http", "server: 127.0.0.1, port: 1", "name-cert-verify: x"),
        ("http", "server: 127.0.0.1, port: 1", "ip-version: ipv4"),
        ("http", "server: 127.0.0.1, port: 1", "udp: true"),
        (
            "ss",
            "server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p",
            "udp-over-tcp: true",
        ),
        (
            "ss",
            "server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p",
            "udp-over-tcp-version: 2",
        ),
        (
            "ss",
            "server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p",
            "client-fingerprint: chrome",
        ),
        (
            "ss",
            "server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p",
            "ip-version: ipv4",
        ),
        ("trojan", "server: 127.0.0.1, port: 1, password: p", "ss-opts: {enabled: true}"),
        ("trojan", "server: 127.0.0.1, port: 1, password: p", "ech-opts: {enable: true}"),
        (
            "trojan",
            "server: 127.0.0.1, port: 1, password: p",
            "shadow-tls-opts: {password: p}",
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
        ("trojan", "server: 127.0.0.1, port: 1, password: p", "ip-version: ipv4"),
        (
            "vless",
            "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68",
            "ech-opts: {enable: true}",
        ),
        (
            "vless",
            "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68",
            "shadow-tls-opts: {password: p}",
        ),
        (
            "vless",
            "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68",
            "restls-opts: {password: p}",
        ),
        (
            "vless",
            "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68",
            "jls-opts: {password: p}",
        ),
        (
            "vless",
            "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68",
            "client-fingerprint: chrome",
        ),
        (
            "vless",
            "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68",
            "ip-version: ipv4",
        ),
        (
            "vless",
            "server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68",
            "udp: true",
        ),
        (
            "anytls",
            "server: 127.0.0.1, port: 1, password: p",
            "ech-opts: {enable: true}",
        ),
        (
            "anytls",
            "server: 127.0.0.1, port: 1, password: p",
            "shadow-tls-opts: {password: p}",
        ),
        (
            "anytls",
            "server: 127.0.0.1, port: 1, password: p",
            "restls-opts: {password: p}",
        ),
        (
            "anytls",
            "server: 127.0.0.1, port: 1, password: p",
            "jls-opts: {password: p}",
        ),
        (
            "anytls",
            "server: 127.0.0.1, port: 1, password: p",
            "client-fingerprint: chrome",
        ),
        (
            "anytls",
            "server: 127.0.0.1, port: 1, password: p",
            "ip-version: ipv4",
        ),
        (
            "anytls",
            "server: 127.0.0.1, port: 1, password: p",
            "fingerprint: chrome",
        ),
        (
            "anytls",
            "server: 127.0.0.1, port: 1, password: p",
            "certificate: x.pem",
        ),
        (
            "anytls",
            "server: 127.0.0.1, port: 1, password: p",
            "private-key: k.pem",
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
    let e = err_tag("tls:\n  private-key: x\n");
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
    for (field, value) in [
        ("client-metadata", "m"),
        ("idle-session-timeout", "30"),
        ("min-idle-session", "1"),
        ("disable-reuse", "true"),
        ("udp", "true"),
    ] {
        let yaml = format!("proxies:\n  - {{name: at, type: anytls, server: x, port: 1, password: p, {field}: {value}}}\nrules: ['MATCH,at']\n");
        let e = proxy_err(&yaml);
        assert!(e.contains(&format!("option '{field}'")), "{field}: {e}");
    }
}
