//! T24 resource coverage: every implemented rule type, the three rule-provider
//! vehicles and formats, proxy-provider filters, GEO/MRS reads, atomic updates
//! and the shape of Billow's effective (override-merged) configuration.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use billow_kernel::{Action, InType, Kernel, Limits, NetworkKind, Target};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "billow-t24-{}-{label}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("addr").port()
}

fn start(yaml: &str, geodata: Option<PathBuf>) -> Kernel {
    let (kernel, warnings) =
        Kernel::start_from_yaml(yaml, geodata, Limits::default()).expect("kernel starts");
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
    kernel
}

fn start_with_base(yaml: &str, geodata: Option<PathBuf>, base: PathBuf) -> Kernel {
    let loaded = billow_kernel::load_config(yaml, "test.yaml").expect("config parses");
    let (kernel, warnings) =
        Kernel::start_with_dir(&loaded, geodata, base, Limits::default()).expect("kernel starts");
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
    kernel
}

fn start_error(yaml: &str, base: PathBuf) -> String {
    let loaded = billow_kernel::load_config(yaml, "test.yaml").expect("config parses");
    Kernel::start_with_dir(&loaded, None, base, Limits::default())
        .err()
        .expect("start must fail")
        .to_string()
}

fn eval(kernel: &Kernel, target: &Target) -> Action {
    kernel.evaluate_target(target).0
}

fn domain_eval(kernel: &Kernel, host: &str) -> Action {
    eval(kernel, &Target::new(host, None))
}

fn ip_eval(kernel: &Kernel, ip: &str) -> Action {
    eval(kernel, &Target::new(ip, Some(ip.parse().unwrap())))
}

fn one_rule(rule: &str) -> String {
    format!("mixed-port: {}\nrules:\n  - {rule}\n  - MATCH,DIRECT\n", free_port())
}

#[test]
fn every_rule_type_matches_with_the_pinned_metadata() {
    // Domain family.
    assert_eq!(domain_eval(&start(&one_rule("DOMAIN,a.example,REJECT"), None), "a.example"), Action::Reject);
    assert_eq!(domain_eval(&start(&one_rule("DOMAIN-SUFFIX,example.com,REJECT"), None), "x.example.com"), Action::Reject);
    assert_eq!(domain_eval(&start(&one_rule("DOMAIN-KEYWORD,adserver,REJECT"), None), "cdn.adserver.example"), Action::Reject);
    assert_eq!(domain_eval(&start(&one_rule("DOMAIN-WILDCARD,*.wild.example,REJECT"), None), "a.wild.example"), Action::Reject);
    assert_eq!(domain_eval(&start(&one_rule("DOMAIN-WILDCARD,*.wild.example,REJECT"), None), "a.b.wild.example"), Action::Reject);
    assert_eq!(domain_eval(&start(&one_rule("DOMAIN-REGEX,^ads?[0-9]+\\.example$,REJECT"), None), "ads12.example"), Action::Reject);

    // Destination/source ports, networks and inbound metadata.
    let kernel = start(&one_rule("DST-PORT,443-444,REJECT"), None);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_port(443)), Action::Reject);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_port(445)), Action::Direct);
    let kernel = start(&one_rule("SRC-PORT,5000-6000,REJECT"), None);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_source("127.0.0.2".parse().unwrap(), 5500)), Action::Reject);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_source("127.0.0.2".parse().unwrap(), 6001)), Action::Direct);
    let kernel = start(&one_rule("NETWORK,UDP,REJECT"), None);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_network(NetworkKind::Udp)), Action::Reject);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_network(NetworkKind::Tcp)), Action::Direct);
    let kernel = start(&one_rule("IN-TYPE,SOCKS,REJECT"), None);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_inbound(7890, InType::Socks5)), Action::Reject);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_inbound(7890, InType::Https)), Action::Direct);
    let kernel = start(&one_rule("IN-TYPE,HTTPS,REJECT"), None);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_inbound(7890, InType::Https)), Action::Reject);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_inbound(7890, InType::Http)), Action::Direct);
    let kernel = start(&one_rule("IN-PORT,7890,REJECT"), None);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_inbound(7890, InType::Http)), Action::Reject);

    // Source address and process metadata.
    assert_eq!(ip_eval(&start(&one_rule("SRC-IP-CIDR,10.0.0.0/8,REJECT"), None), "10.1.2.3"), Action::Direct);
    let kernel = start(&one_rule("SRC-IP-CIDR,10.0.0.0/8,REJECT"), None);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_source("10.1.2.3".parse().unwrap(), 1234)), Action::Reject);
    let kernel = start(&one_rule("PROCESS-NAME,curl,REJECT"), None);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_process(Some("CURL"), None)), Action::Reject);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_process(Some("wget"), None)), Action::Direct);
    let kernel = start(&one_rule("PROCESS-PATH-REGEX,/usr/bin/curl$,REJECT"), None);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_process(None, Some("/usr/bin/curl"))), Action::Reject);
    let kernel = start(&one_rule("PROCESS-NAME-WILDCARD,cu*?l,REJECT"), None);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_process(Some("CURL"), None)), Action::Reject);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_process(Some("wget"), None)), Action::Direct);
    let kernel = start(&one_rule("PROCESS-PATH-WILDCARD,/usr/*/curl,REJECT"), None);
    assert_eq!(eval(&kernel, &Target::new("a.example", None).with_process(None, Some("/usr/bin/curl"))), Action::Reject);
    let kernel = start(&one_rule("IP-SUFFIX,0.0.0.7/8,REJECT"), None);
    assert_eq!(ip_eval(&kernel, "10.0.0.7"), Action::Reject);
    assert_eq!(ip_eval(&kernel, "10.0.0.8"), Action::Direct);
}

#[test]
fn sub_rule_lists_choose_the_outbound() {
    let yaml = format!(
        r#"
mixed-port: {}
sub-rules:
  branch:
    - DOMAIN,inside.example,DIRECT
    - MATCH,REJECT
rules:
  - SUB-RULE,(NETWORK,TCP),branch
  - MATCH,DIRECT
"#,
        free_port()
    );
    let kernel = start(&yaml, None);
    assert_eq!(eval(&kernel, &Target::new("inside.example", None).with_network(NetworkKind::Tcp)), Action::Direct);
    assert_eq!(eval(&kernel, &Target::new("other.example", None).with_network(NetworkKind::Tcp)), Action::Reject);
    assert_eq!(eval(&kernel, &Target::new("inside.example", None).with_network(NetworkKind::Udp)), Action::Direct);
}

#[test]
fn rule_providers_cover_every_vehicle_and_format() {
    let dir = temp_dir("providers");
    let providers = dir.join("providers");
    std::fs::create_dir_all(&providers).unwrap();
    std::fs::write(providers.join("domain.txt"), "+.blocked.example\n*.wild.example\nplain.example\nsub.*.middle.example\n").unwrap();
    std::fs::write(providers.join("ip.txt"), "10.0.0.0/8\n2001:db8::/32\n").unwrap();
    std::fs::write(
        providers.join("classical.yaml"),
        "payload:\n  - DOMAIN-SUFFIX,classical.example\n  - DST-PORT,8080\n  - PROCESS-NAME-WILDCARD,cur*\n",
    )
    .unwrap();
    std::fs::write(providers.join("domain.mrs"), include_bytes!("../../../../src-tauri/testdata/domain.mrs")).unwrap();
    let yaml = format!(
        r#"
mixed-port: {}
rule-providers:
  inline-domain:
    type: inline
    behavior: domain
    payload: ['+.inline.example']
  file-domain:
    type: file
    behavior: domain
    format: text
    path: providers/domain.txt
  file-ip:
    type: file
    behavior: ipcidr
    format: text
    path: providers/ip.txt
  classical:
    type: file
    behavior: classical
    format: yaml
    path: providers/classical.yaml
  mrs:
    type: file
    behavior: domain
    format: mrs
    path: providers/domain.mrs
rules:
  - RULE-SET,inline-domain,REJECT
  - RULE-SET,file-domain,REJECT
  - RULE-SET,file-ip,REJECT
  - RULE-SET,classical,REJECT
  - RULE-SET,mrs,REJECT
  - MATCH,DIRECT
"#,
        free_port(),
    );
    let kernel = start_with_base(&yaml, None, dir.clone());
    assert_eq!(domain_eval(&kernel, "a.inline.example"), Action::Reject);
    assert_eq!(domain_eval(&kernel, "plain.example"), Action::Reject);
    assert_eq!(domain_eval(&kernel, "x.wild.example"), Action::Reject);
    assert_eq!(ip_eval(&kernel, "10.1.2.3"), Action::Reject);
    assert_eq!(ip_eval(&kernel, "2001:db8::1"), Action::Reject);
    assert_eq!(domain_eval(&kernel, "sub.a.middle.example"), Action::Reject);
    assert_eq!(domain_eval(&kernel, "sub.a.b.middle.example"), Action::Direct);
    assert_eq!(domain_eval(&kernel, "a.classical.example"), Action::Reject);
    assert_eq!(eval(&kernel, &Target::new("unmatched.example", None).with_port(8080)), Action::Reject);
    assert_eq!(
        eval(&kernel, &Target::new("unmatched.example", None).with_process(Some("CURL"), None)),
        Action::Reject
    );
    // The MRS fixture contains +.google.com and example.org.
    assert_eq!(domain_eval(&kernel, "www.google.com"), Action::Reject);
    assert_eq!(domain_eval(&kernel, "example.org"), Action::Reject);
    assert_eq!(domain_eval(&kernel, "unmatched.example"), Action::Direct);
    let info = kernel.providers().rule_provider("mrs").unwrap().snapshot();
    assert_eq!(info.compiled.count, 5);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn provider_paths_are_confined_to_the_configuration_root() {
    let dir = temp_dir("provider-paths");
    let outside = temp_dir("provider-paths-outside");
    std::fs::create_dir_all(dir.join("providers")).unwrap();
    std::fs::write(dir.join("providers/domain.txt"), "+.inside.example\n").unwrap();
    std::fs::write(outside.join("outside.txt"), "+.outside.example\n").unwrap();

    let legal = format!(
        "mixed-port: {}\nrule-providers:\n  r:\n    type: file\n    behavior: domain\n    format: text\n    path: providers/domain.txt\nrules: ['RULE-SET,r,REJECT', 'MATCH,DIRECT']\n",
        free_port()
    );
    let kernel = start_with_base(&legal, None, dir.clone());
    assert_eq!(domain_eval(&kernel, "a.inside.example"), Action::Reject);

    // An absolute path inside the root is allowed, as `IsSafePath` allows it.
    let absolute_inside = format!(
        "mixed-port: {}\nrule-providers:\n  r:\n    type: file\n    behavior: domain\n    format: text\n    path: {}\nrules: ['RULE-SET,r,REJECT', 'MATCH,DIRECT']\n",
        free_port(),
        dir.join("providers/domain.txt").display()
    );
    let kernel = start_with_base(&absolute_inside, None, dir.clone());
    assert_eq!(domain_eval(&kernel, "a.inside.example"), Action::Reject);

    // Both `..` and an absolute path outside the root are named rejections.
    for path in [
        "../outside.txt".to_string(),
        outside.join("outside.txt").display().to_string(),
    ] {
        let yaml = format!(
            "mixed-port: {}\nrule-providers:\n  r:\n    type: file\n    behavior: domain\n    format: text\n    path: {path}\nrules: ['RULE-SET,r,REJECT']\n",
            free_port()
        );
        let error = start_error(&yaml, dir.clone());
        assert!(error.contains("not a subpath"), "{path}: {error}");
    }

    // The HTTP cache `path` is validated before the fetch/write.
    let server = TestServer::start("payload:\n  - +.remote.example\n");
    let yaml = format!(
        "mixed-port: {}\nrule-providers:\n  r:\n    type: http\n    behavior: domain\n    format: yaml\n    url: http://127.0.0.1:{}/rules.yaml\n    path: ../escape.yaml\nrules: ['RULE-SET,r,REJECT']\n",
        free_port(),
        server.port
    );
    let error = start_error(&yaml, dir.clone());
    assert!(error.contains("not a subpath"), "{error}");
    assert!(!dir.parent().unwrap().join("escape.yaml").exists());

    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&outside).unwrap();
}

#[test]
fn classical_provider_names_unsupported_rule_types_instead_of_dropping_them() {
    let dir = temp_dir("classical-reject");
    std::fs::create_dir_all(dir.join("providers")).unwrap();
    // `DSCP` is a pinned rule type but this kernel has no DSCP metadata, so
    // the provider must fail by name rather than load an incomplete set.
    std::fs::write(
        dir.join("providers/classical.yaml"),
        "payload:\n  - DOMAIN-SUFFIX,dropped.example\n  - DSCP,10\n",
    )
    .unwrap();
    let yaml = format!(
        "mixed-port: {}\nrule-providers:\n  classical:\n    type: file\n    behavior: classical\n    format: yaml\n    path: providers/classical.yaml\nrules: ['RULE-SET,classical,REJECT', 'MATCH,DIRECT']\n",
        free_port()
    );
    let error = start_error(&yaml, dir.clone());
    assert!(error.contains("classical") && error.contains("DSCP"), "{error}");
    std::fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// Local HTTP provider server
// ---------------------------------------------------------------------------

struct ServerState {
    status: u16,
    body: Vec<u8>,
}

struct TestServer {
    port: u16,
    state: Arc<Mutex<ServerState>>,
}

impl TestServer {
    fn start(body: &str) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("server bind");
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(ServerState {
            status: 200,
            body: body.as_bytes().to_vec(),
        }));
        let shared = state.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let state = shared.clone();
                std::thread::spawn(move || {
                    let mut buffer = [0u8; 8192];
                    let _ = stream.read(&mut buffer);
                    let (status, body) = {
                        let state = state.lock().unwrap();
                        (state.status, state.body.clone())
                    };
                    let reason = if status == 200 { "OK" } else { "FAIL" };
                    let head = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(&body);
                });
            }
        });
        TestServer { port, state }
    }

    fn set(&self, status: u16, body: &str) {
        let mut state = self.state.lock().unwrap();
        state.status = status;
        state.body = body.as_bytes().to_vec();
    }
}

#[test]
fn http_provider_update_replaces_and_failure_keeps_the_old_generation() {
    let server = TestServer::start("payload:\n  - +.first.example\n");
    let yaml = format!(
        r#"
mixed-port: {}
rule-providers:
  remote:
    type: http
    behavior: domain
    format: yaml
    url: http://127.0.0.1:{}/rules.yaml
    interval: 60
rules:
  - RULE-SET,remote,REJECT
  - MATCH,DIRECT
"#,
        free_port(),
        server.port
    );
    let kernel = start(&yaml, None);
    assert_eq!(domain_eval(&kernel, "a.first.example"), Action::Reject);
    assert_eq!(domain_eval(&kernel, "a.second.example"), Action::Direct);
    let first = kernel.providers().rule_provider("remote").unwrap().snapshot().generation;
    assert_eq!(first, 1);

    server.set(200, "payload:\n  - +.second.example\n");
    let update = kernel.update_rule_provider("remote").expect("update succeeds");
    assert_eq!(update.generation, 2);
    assert_eq!(update.entries, 1);
    assert_eq!(domain_eval(&kernel, "a.second.example"), Action::Reject);
    assert_eq!(domain_eval(&kernel, "a.first.example"), Action::Direct);

    // A failing update returns the reason and leaves generation 2 in place.
    server.set(500, "payload:\n  - +.third.example\n");
    let error = kernel.update_rule_provider("remote").expect_err("update must fail");
    assert!(error.to_string().contains("HTTP 500"), "{error}");
    assert_eq!(kernel.providers().rule_provider("remote").unwrap().snapshot().generation, 2);
    assert_eq!(domain_eval(&kernel, "a.second.example"), Action::Reject);
    assert_eq!(domain_eval(&kernel, "a.third.example"), Action::Direct);
}

#[test]
fn inline_provider_update_is_a_noop_like_mihomo() {
    let yaml = format!(
        r#"
mixed-port: {}
rule-providers:
  inline:
    type: inline
    behavior: domain
    payload: ['+.inline.example']
rules:
  - RULE-SET,inline,REJECT
  - MATCH,DIRECT
"#,
        free_port()
    );
    let kernel = start(&yaml, None);
    let update = kernel.update_rule_provider("inline").unwrap();
    assert_eq!(update.generation, 1);
    assert!(kernel.update_rule_provider("missing").is_err());
}

#[test]
fn proxy_provider_file_applies_filter_exclude_and_dialer() {
    let dir = temp_dir("proxy-provider");
    std::fs::write(
        dir.join("proxies.yaml"),
        "proxies:\n  - {name: HK-1, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-256-gcm, password: p}\n  - {name: JP-1, type: ss, server: 127.0.0.1, port: 8389, cipher: aes-256-gcm, password: p}\n  - {name: HK-2, type: ssr, server: 127.0.0.1, port: 8390, cipher: aes-256-cfb, password: p, protocol: origin, obfs: plain}\n",
    )
    .unwrap();
    let yaml = format!(
        r#"
mixed-port: {}
proxy-providers:
  sub:
    type: file
    path: proxies.yaml
    filter: '^HK'
    exclude-type: ssr
    dialer-proxy: hop
proxies:
  - {{name: hop, type: socks5, server: 127.0.0.1, port: 1080}}
rules: ['MATCH,DIRECT']
"#,
        free_port(),
    );
    let kernel = start_with_base(&yaml, None, dir.clone());
    let snapshot = kernel.providers().proxy_provider("sub").unwrap().snapshot();
    assert_eq!(snapshot.proxies.len(), 1);
    assert_eq!(snapshot.proxies[0].name, "HK-1");
    assert_eq!(snapshot.proxies[0].dialer_proxy(), Some("hop"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn proxy_provider_override_and_filter_lists_follow_pinned_semantics() {
    let dir = temp_dir("proxy-provider-override");
    std::fs::write(
        dir.join("proxies.yaml"),
        "proxies:\n  - {name: HK-1, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-256-gcm, password: p}\n  - {name: JP-1, type: ss, server: 127.0.0.1, port: 8389, cipher: aes-256-gcm, password: p}\n  - {name: HK-2, type: ssr, server: 127.0.0.1, port: 8390, cipher: aes-256-cfb, password: p, protocol: origin, obfs: plain}\n  - {name: HK-3, type: trojan, server: 127.0.0.1, port: 8391, password: p}\n",
    )
    .unwrap();
    let yaml = format!(
        r#"
mixed-port: {}
proxy-providers:
  sub:
    type: file
    path: proxies.yaml
    filter: '^HK`^JP'
    exclude-filter: 'JP'
    exclude-type: ss|ssr
    dialer-proxy: hop
    override:
      udp: true
      skip-cert-verify: true
      dialer-proxy: hop
      additional-prefix: '[p] '
      additional-suffix: ' +'
      proxy-name:
        - pattern: '^HK'
          target: 'HongKong'
  ss-only:
    type: file
    path: proxies.yaml
    filter: '^HK-1$'
    override:
      udp: true
proxies:
  - {{name: hop, type: socks5, server: 127.0.0.1, port: 1080}}
rules: ['MATCH,DIRECT']
"#,
        free_port()
    );
    let kernel = start_with_base(&yaml, None, dir.clone());
    // `exclude-type: ss|ssr` drops both ss entries; the trojan remains and
    // receives the name/udp/TLS/dialer overrides.
    let snapshot = kernel.providers().proxy_provider("sub").unwrap().snapshot();
    assert_eq!(snapshot.proxies.len(), 1);
    let trojan = &snapshot.proxies[0];
    assert_eq!(trojan.name, "[p] HongKong-3 +");
    assert_eq!(trojan.dialer_proxy(), Some("hop"));
    let billow_kernel::proxies::Protocol::Trojan(trojan_out) = &trojan.protocol else {
        panic!("expected trojan");
    };
    assert!(trojan_out.udp);
    assert!(trojan_out.tls_settings.skip_cert_verify);

    let ss = kernel.providers().proxy_provider("ss-only").unwrap().snapshot();
    assert_eq!(ss.proxies.len(), 1);
    let billow_kernel::proxies::Protocol::Shadowsocks(ss_out) = &ss.proxies[0].protocol else {
        panic!("expected ss");
    };
    assert!(ss_out.udp);

    // An unsupported pinned override field is named at load, never ignored.
    let yaml = format!(
        "mixed-port: {}\nproxy-providers:\n  sub:\n    type: file\n    path: proxies.yaml\n    override:\n      tfo: true\nrules: ['MATCH,DIRECT']\n",
        free_port()
    );
    let error = billow_kernel::load_config(&yaml, "test.yaml")
        .err()
        .expect("override.tfo must fail");
    assert!(error.to_string().contains("override.tfo"), "{error}");

    std::fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// GEO data fixtures (protobuf .dat)
// ---------------------------------------------------------------------------

fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn field_bytes(field: u64, bytes: &[u8]) -> Vec<u8> {
    let mut out = varint((field << 3) | 2);
    out.extend(varint(bytes.len() as u64));
    out.extend(bytes);
    out
}

fn field_varint(field: u64, value: u64) -> Vec<u8> {
    let mut out = varint(field << 3);
    out.extend(varint(value));
    out
}

fn geosite_dat() -> Vec<u8> {
    // GeoSiteList { entry: GeoSite { country_code: "test", domain: [
    //   {type: Domain(2), value: "example.test"},
    //   {type: Full(3), value: "only.test"},
    //   {type: Plain(0), value: "keyword"},
    //   {type: Full(3), value: "attr.test", attribute: [{key: "ads"}]},
    // ] } }
    let mut attr = Vec::new();
    attr.extend(field_bytes(1, b"ads"));
    let mut domains = Vec::new();
    let mut domain = field_varint(1, 2);
    domain.extend(field_bytes(2, b"example.test"));
    domains.extend(field_bytes(2, &domain));
    let mut domain = field_varint(1, 3);
    domain.extend(field_bytes(2, b"only.test"));
    domains.extend(field_bytes(2, &domain));
    let mut domain = field_varint(1, 0);
    domain.extend(field_bytes(2, b"keyword"));
    domains.extend(field_bytes(2, &domain));
    let mut domain = field_varint(1, 3);
    domain.extend(field_bytes(2, b"attr.test"));
    domain.extend(field_bytes(3, &attr));
    domains.extend(field_bytes(2, &domain));
    let mut site = field_bytes(1, b"test");
    site.extend(domains);
    let mut list = field_bytes(1, &site);
    list.shrink_to_fit();
    list
}

fn geoip_dat() -> Vec<u8> {
    // GeoIPList { entry: GeoIP { country_code: "zz", cidr: [
    //   {ip: 10.0.0.0, prefix: 8}, {ip: 2001:db8::, prefix: 32} ] } }
    let mut cidrs = Vec::new();
    let mut cidr = field_bytes(1, &[10, 0, 0, 0]);
    cidr.extend(field_varint(2, 8));
    cidrs.extend(field_bytes(2, &cidr));
    let mut cidr = field_bytes(1, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    cidr.extend(field_varint(2, 32));
    cidrs.extend(field_bytes(2, &cidr));
    let mut cidr = field_bytes(1, &[127, 0, 0, 1]);
    cidr.extend(field_varint(2, 32));
    cidrs.extend(field_bytes(2, &cidr));
    let mut entry = field_bytes(1, b"zz");
    entry.extend(cidrs);
    field_bytes(1, &entry)
}

#[test]
fn geosite_and_geoip_dat_rules_match_the_pinned_forms() {
    let dir = temp_dir("geodata");
    std::fs::write(dir.join("GeoSite.dat"), geosite_dat()).unwrap();
    std::fs::write(dir.join("GeoIP.dat"), geoip_dat()).unwrap();
    let yaml = format!(
        r#"
mixed-port: {}
geodata-mode: true
rules:
  - GEOSITE,test,REJECT
  - GEOSITE,test@ads,REJECT
  - GEOIP,zz,REJECT
  - GEOIP,lan,DIRECT
  - MATCH,DIRECT
"#,
        free_port()
    );
    let kernel = start(&yaml, Some(dir.clone()));
    assert_eq!(domain_eval(&kernel, "a.example.test"), Action::Reject);
    assert_eq!(domain_eval(&kernel, "only.test"), Action::Reject);
    assert_eq!(domain_eval(&kernel, "notexample.test"), Action::Direct);
    assert_eq!(domain_eval(&kernel, "keyword.example"), Action::Reject);
    assert_eq!(ip_eval(&kernel, "10.9.8.7"), Action::Reject);
    assert_eq!(ip_eval(&kernel, "2001:db8::1"), Action::Reject);
    assert_eq!(ip_eval(&kernel, "192.168.1.1"), Action::Direct);

    // Source variants inspect the client address, not the destination.
    let source_yaml = format!(
        r#"
mixed-port: {}
geodata-mode: true
rule-providers:
  loopback:
    type: inline
    behavior: ipcidr
    payload: ['127.0.0.1/32']
rules:
  - SRC-GEOIP,zz,REJECT
  - RULE-SET,loopback,REJECT,src
  - MATCH,DIRECT
"#,
        free_port()
    );
    let source_kernel = start(&source_yaml, Some(dir.clone()));
    let from_loopback = Target::new("a.example", None).with_source("127.0.0.1".parse().unwrap(), 1000);
    let from_private = Target::new("a.example", None).with_source("172.16.0.1".parse().unwrap(), 1000);
    assert_eq!(eval(&source_kernel, &from_loopback), Action::Reject);
    assert_eq!(eval(&source_kernel, &from_private), Action::Direct);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn geosite_requires_a_database_directory_and_missing_keys_fail() {
    let error = Kernel::start_from_yaml(&one_rule("GEOSITE,test,REJECT"), None, Limits::default())
        .err()
        .expect("must fail");
    assert!(error.to_string().contains("geosite-dir"), "{error}");

    let dir = temp_dir("geodata-missing");
    std::fs::write(dir.join("GeoSite.dat"), geosite_dat()).unwrap();
    let error = Kernel::start_from_yaml(&one_rule("GEOSITE,absent,REJECT"), Some(dir.clone()), Limits::default())
        .err()
        .expect("must fail");
    assert!(error.to_string().contains("absent"), "{error}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
#[ignore = "needs decompressed Country.mmdb and ASN.mmdb; run with BILLOW_MMDB_DIR"]
fn real_mmdb_reads_the_bundled_geodata() {
    let dir = std::env::var("BILLOW_MMDB_DIR").expect("BILLOW_MMDB_DIR");
    let country = billow_kernel::geodata::Mmdb::open(&PathBuf::from(&dir).join("Country.mmdb"))
        .expect("Country.mmdb");
    let codes = country.country_codes("1.1.1.1".parse().unwrap());
    assert!(codes.iter().any(|code| code == "au"), "{codes:?}");
    assert!(country.country_codes("223.5.5.5".parse().unwrap()).iter().any(|code| code == "cn"));
    let asn = billow_kernel::geodata::Mmdb::open(&PathBuf::from(&dir).join("ASN.mmdb"))
        .expect("ASN.mmdb");
    assert_eq!(asn.asn("1.1.1.1".parse().unwrap()).0, "13335");
}

#[test]
fn provider_reference_cycles_are_rejected_before_listening() {
    let yaml = format!(
        r#"
mixed-port: {}
rule-providers:
  a:
    type: inline
    behavior: classical
    payload: ['RULE-SET,b']
  b:
    type: inline
    behavior: classical
    payload: ['RULE-SET,a']
rules:
  - RULE-SET,a,REJECT
  - MATCH,DIRECT
"#,
        free_port()
    );
    let error = Kernel::start_from_yaml(&yaml, None, Limits::default())
        .err()
        .expect("cycle must fail");
    assert!(error.to_string().contains("circular"), "{error}");
}

/// The shape Billow's `profile.rs` produces for the Rust engine: override-merged
/// rules/providers plus the launcher keys `prepare`/`apply_settings`/
/// `finish_yaml_for` insert (Android adds `port: 0`, `socks-port: 0`,
/// `external-controller` and a disabled `tun`; settings may add `dns`,
/// `sniffer` and `geox-url`; the profile itself carries `proxy-groups`).
/// This is a replica of that output, not a hand-written "Mihomo config".
fn billow_effective_yaml(port: u16) -> String {
    format!(
        r#"mixed-port: {port}
port: 0
socks-port: 0
allow-lan: false
mode: rule
log-level: info
external-controller: 127.0.0.1:49152
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: ['223.5.5.5']
tun:
  enable: false
  auto-route: false
  auto-detect-interface: false
  dns-hijack: ['any:53']
sniffer:
  enable: true
  sniff:
    TLS:
      ports: [443]
geox-url:
  geoip: 'https://example.invalid/GeoIP.dat'
  geosite: 'https://example.invalid/GeoSite.dat'
proxies:
  - {{name: node-a, type: socks5, server: 127.0.0.1, port: 1080}}
proxy-groups:
  - {{name: PROXY, type: select, proxies: [node-a]}}
rule-providers:
  override-extra:
    type: inline
    behavior: domain
    payload: ['+.override.example', 'corp.example']
rules:
  - RULE-SET,override-extra,REJECT
  - DOMAIN-SUFFIX,corp.com,DIRECT
  - DOMAIN-SUFFIX,profile.example,node-a
  - MATCH,DIRECT
"#
    )
}

#[test]
fn billow_effective_configuration_registers_cross_task_keys_explicitly() {
    let yaml = billow_effective_yaml(free_port());

    // The full artifact is not claimed to load directly: the behavior-changing
    // cross-task blocks are named rejections.
    let error = billow_kernel::load_config(&yaml, "effective.yaml")
        .err()
        .expect("cross-task blocks must be rejected");
    let text = error.to_string();
    assert!(
        ["external-controller", "dns", "proxy-groups", "sniffer", "tun"]
            .iter()
            .any(|key| text.contains(key)),
        "{text}"
    );

    // Each boundary is individually named.
    for (key, value) in [
        ("external-controller", "127.0.0.1:49152"),
        ("dns", "{enable: true}"),
        ("proxy-groups", "[]"),
    ] {
        let yaml = format!("mixed-port: {}\n{key}: {value}\n", free_port());
        let error = billow_kernel::load_config(&yaml, "effective.yaml")
            .err()
            .expect("must be rejected");
        assert!(error.to_string().contains(key), "{key}: {error}");
    }
    for key in ["sniffer", "tun"] {
        let yaml = format!("mixed-port: {}\n{key}: {{enable: true}}\n", free_port());
        let error = billow_kernel::load_config(&yaml, "effective.yaml")
            .err()
            .expect("enabled block must be rejected");
        assert!(error.to_string().contains(key), "{key}: {error}");
    }

    // `port: 0`/`socks-port: 0` are disabled listener aliases, not ephemeral
    // binds; `mixed-port` still selects the listener. A file whose only ports
    // are 0 has no listener and is named instead of binding an unseen port.
    let loaded = billow_kernel::load_config(
        &format!("mixed-port: {}\nport: 0\nsocks-port: 0\n", free_port()),
        "effective.yaml",
    )
    .expect("zero aliases are inert");
    assert_ne!(loaded.config.listen.port(), 0);
    assert!(billow_kernel::load_config("mixed-port: 0\n", "effective.yaml").is_err());
}

#[test]
fn billow_effective_configuration_rule_subset_keeps_override_order() {
    // Take the real launcher artifact, remove only the keys registered as
    // cross-task rejections above, and verify the override engine's rule order
    // (prepended provider rule, profile rules, MATCH) survives.
    let mixed_port = free_port();
    let yaml = billow_effective_yaml(mixed_port);
    let mut value: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    let mapping = value.as_mapping_mut().unwrap();
    for key in [
        "external-controller",
        "dns",
        "tun",
        "sniffer",
        "geox-url",
        "proxy-groups",
    ] {
        mapping.remove(serde_yaml::Value::String(key.to_string()));
    }
    let subset = serde_yaml::to_string(&value).unwrap();
    let loaded = billow_kernel::load_config(&subset, "effective-rust.yaml")
        .expect("rule/provider/proxy subset loads");
    assert_eq!(loaded.config.rules.len(), 4);
    assert_eq!(loaded.config.rule_providers.len(), 1);
    assert_eq!(loaded.config.proxies.len(), 1);
    assert_eq!(loaded.config.listen.port(), mixed_port);
    let kernel = start(&subset, None);
    assert_eq!(domain_eval(&kernel, "x.override.example"), Action::Reject);
    assert_eq!(domain_eval(&kernel, "corp.com"), Action::Direct);
    assert!(matches!(domain_eval(&kernel, "profile.example"), Action::Proxy(_)));
}
