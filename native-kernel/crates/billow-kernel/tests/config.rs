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
        "proxies",
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
