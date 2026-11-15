//! Read-only details behind the Resources page: what a proxy provider holds,
//! what a rule provider matches, and the state of the GEO databases.
//!
//! The kernel runs without `-d`, so Mihomo keeps provider caches and GEO files
//! in its default home (`$CLASH_HOME_DIR` or `~/.config/mihomo`). Rule provider
//! content is not exposed by the controller API, so it is read from the same
//! file the kernel loads: inline payloads from the config, `path` when set, and
//! `rules/<md5(url)>` for HTTP providers without one.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use md5::{Digest, Md5};
use serde::Serialize;
use serde_yaml::Value;

use crate::diagnostics;
use crate::nodes::ControllerEndpoint;

/// Rows sent to the page; the total still reports the full count.
pub const MAX_RULE_ROWS: usize = 5000;

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct ProviderProxy {
    pub name: String,
    pub node_type: String,
    pub tags: Vec<String>,
    pub delay_ms: Option<u64>,
    pub alive: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct ProviderDetail {
    pub kind: String,
    pub name: String,
    pub proxies: Vec<ProviderProxy>,
    pub rules: Vec<String>,
    pub total: usize,
    /// Why rows are missing or partial (binary format, file not downloaded yet, …).
    pub notice: Option<String>,
    /// Where the rules came from: `inline`, a file path, or the URL.
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GeoFile {
    pub key: String,
    pub label: String,
    pub file: String,
    pub exists: bool,
    pub size: Option<u64>,
    pub modified_ms: Option<u64>,
}

/// Desktop kernels run without `-d`, so their home is mihomo's default.
#[cfg(not(target_os = "android"))]
pub fn kernel_home() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("CLASH_HOME_DIR").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".config").join("mihomo"))
}

fn md5_hex(text: &str) -> String {
    Md5::digest(text.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.as_mapping()?.get(Value::String(key.to_string()))
}

fn get_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    get(value, key).and_then(Value::as_str)
}

/// Capability tags from the controller's proxy JSON (same words as config-derived tags).
fn api_tags(item: &serde_json::Value) -> Vec<String> {
    let flag = |key: &str| item.get(key).and_then(serde_json::Value::as_bool) == Some(true);
    let mut tags = Vec::new();
    if flag("udp") {
        tags.push("UDP".to_string());
    }
    if flag("xudp") {
        tags.push("XUDP".to_string());
    }
    if flag("smux") {
        tags.push("Mux".to_string());
    }
    if flag("tfo") {
        tags.push("TFO".to_string());
    }
    if flag("mptcp") {
        tags.push("MPTCP".to_string());
    }
    if item.get("dialer-proxy").and_then(serde_json::Value::as_str).is_some_and(|value| !value.is_empty()) {
        tags.push("链式".to_string());
    }
    tags
}

pub fn proxies_from_value(value: &serde_json::Value) -> Vec<ProviderProxy> {
    let Some(list) = value.get("proxies").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|item| {
            let name = item.get("name")?.as_str()?.to_string();
            let history = item.get("history").and_then(serde_json::Value::as_array);
            let delay_ms = history
                .and_then(|entries| entries.last())
                .and_then(|entry| entry.get("delay"))
                .and_then(serde_json::Value::as_u64)
                .filter(|delay| *delay > 0);
            Some(ProviderProxy {
                name,
                node_type: item.get("type").and_then(serde_json::Value::as_str).unwrap_or("").to_ascii_lowercase(),
                tags: api_tags(item),
                delay_ms,
                alive: item.get("alive").and_then(serde_json::Value::as_bool),
            })
        })
        .collect()
}

pub fn proxy_detail(endpoint: &ControllerEndpoint, name: &str) -> Result<ProviderDetail, String> {
    let path = format!("/providers/proxies/{}", diagnostics::encode_path(name));
    let value = diagnostics::controller_get(endpoint, &path)?;
    let proxies = proxies_from_value(&value);
    Ok(ProviderDetail {
        kind: "proxy".to_string(),
        name: name.to_string(),
        total: proxies.len(),
        proxies,
        ..ProviderDetail::default()
    })
}

/// Keep only a preview while counting all entries, without a second full YAML tree.
#[derive(Default)]
struct RulePreview {
    rows: Vec<String>,
    total: usize,
}

impl RulePreview {
    fn push(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() { return; }
        self.total += 1;
        if self.rows.len() < MAX_RULE_ROWS { self.rows.push(line.to_string()); }
    }
}

impl<'de> serde::Deserialize<'de> for RulePreview {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PreviewVisitor;
        impl<'de> serde::de::Visitor<'de> for PreviewVisitor {
            type Value = RulePreview;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a rule payload sequence")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut preview = RulePreview::default();
                while let Some(value) = seq.next_element::<Value>()? {
                    if let Some(line) = value.as_str() { preview.push(line); }
                }
                Ok(preview)
            }
        }
        deserializer.deserialize_seq(PreviewVisitor)
    }
}

fn parse_rules(body: &str, format: &str) -> RulePreview {
    if format.eq_ignore_ascii_case("yaml") || body.trim_start().starts_with("payload:") {
        #[derive(serde::Deserialize)]
        struct Payload { payload: RulePreview }
        if let Ok(value) = serde_yaml::from_str::<Payload>(body) { return value.payload; }
    }
    let mut preview = RulePreview::default();
    for line in body.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") || line == "payload:" { continue; }
        preview.push(line.trim_start_matches("- ").trim_matches(|c| c == '\'' || c == '"'));
    }
    preview
}

/// Locate a rule provider's content from the effective config (`config_yaml`).
pub fn rule_detail(config_yaml: &str, name: &str, home: Option<&Path>) -> ProviderDetail {
    let mut detail = ProviderDetail { kind: "rule".to_string(), name: name.to_string(), ..ProviderDetail::default() };
    let mut config: Value = serde_yaml::from_str(config_yaml).unwrap_or(Value::Null);
    // Providers commonly share `<<: *anchor` defaults; `type` and `format` live there.
    let _ = config.apply_merge();
    let Some(entry) = get(&config, "rule-providers").and_then(|providers| get(providers, name)) else {
        detail.notice = Some("当前配置里没有这个规则集".to_string());
        return detail;
    };
    let kind = get_str(entry, "type").unwrap_or("").to_ascii_lowercase();
    let format = get_str(entry, "format").unwrap_or("yaml").to_ascii_lowercase();
    let rules = if kind == "inline" {
        detail.source = Some("inline".to_string());
        let mut preview = RulePreview::default();
        if let Some(list) = get(entry, "payload").and_then(Value::as_sequence) {
            for line in list.iter().filter_map(Value::as_str) { preview.push(line); }
        }
        preview
    } else {
        let path = match (get_str(entry, "path"), get_str(entry, "url")) {
            (Some(path), _) if !path.is_empty() => {
                let path = PathBuf::from(path);
                if path.is_absolute() { Some(path) } else { home.map(|home| home.join(path)) }
            }
            (_, Some(url)) if kind == "http" => home.map(|home| home.join("rules").join(md5_hex(url))),
            _ => None,
        };
        detail.source = get_str(entry, "url").map(str::to_string).or_else(|| path.as_ref().map(|path| path.display().to_string()));
        if format == "mrs" || path.as_ref().is_some_and(|path| path.extension().is_some_and(|ext| ext == "mrs")) {
            detail.notice = Some("MRS 是二进制格式，无法逐条预览".to_string());
            return detail;
        }
        // A preview must never allocate an unbounded provider file in the app process.
        const MAX_PREVIEW_BYTES: u64 = 8 * 1024 * 1024;
        let body = path.as_ref().and_then(|path| {
            let file = fs::File::open(path).ok()?;
            let mut body = String::new();
            file.take(MAX_PREVIEW_BYTES + 1).read_to_string(&mut body).ok()?;
            Some(body)
        });
        let Some(body) = body else {
            // Name the path that was tried so a mismatch can be read off the sheet.
            detail.notice = Some(match path.as_ref() {
                Some(path) => format!("还没有找到可读取的规则文件（{}）；连接并更新这个规则集后再查看", path.display()),
                None => "还没有找到可读取的规则文件；连接并更新这个规则集后再查看".to_string(),
            });
            return detail;
        };
        if body.len() as u64 > MAX_PREVIEW_BYTES {
            detail.notice = Some("规则文件超过 8 MiB，已跳过预览；不影响内核加载完整规则".to_string());
            return detail;
        }
        parse_rules(&body, &format)
    };
    detail.total = rules.total;
    if rules.total > MAX_RULE_ROWS {
        detail.notice = Some(format!("只显示前 {MAX_RULE_ROWS} 条"));
    }
    detail.rules = rules.rows;
    detail
}

/// GEO databases Mihomo may load, in the order users recognise them.
/// Checks both lowercase (`geoip.dat`) and Android/Linux PascalCase (`GeoIP.dat`,
/// `Country.mmdb`, `ASN.mmdb`) filenames so case-sensitive filesystems report
/// bundled or downloaded databases accurately.
pub fn geo_files(home: Option<&Path>) -> Vec<GeoFile> {
    let specs: [(&str, &str, &[&str]); 4] = [
        ("geoip", "GeoIP", &["geoip.dat", "GeoIP.dat"]),
        ("geosite", "GeoSite", &["geosite.dat", "GeoSite.dat"]),
        ("mmdb", "MMDB", &["geoip.metadb", "GeoIP.metadb", "Country.mmdb", "country.mmdb"]),
        ("asn", "ASN", &["GeoLite2-ASN.mmdb", "ASN.mmdb", "asn.mmdb"]),
    ];
    specs
        .into_iter()
        .map(|(key, label, candidates)| {
            let matched = home.and_then(|dir| {
                candidates
                    .iter()
                    .filter_map(|&name| {
                        let meta = fs::metadata(dir.join(name)).ok().filter(|meta| meta.is_file())?;
                        let modified_ms = meta
                            .modified()
                            .ok()
                            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                            .map(|age| age.as_millis() as u64);
                        Some((name, meta.len(), modified_ms))
                    })
                    .max_by_key(|&(_, size, modified_ms)| (size > 0, modified_ms.unwrap_or(0)))
            });
            GeoFile {
                key: key.to_string(),
                label: label.to_string(),
                file: matched.map(|(name, _, _)| name).unwrap_or(candidates[0]).to_string(),
                exists: matched.is_some(),
                size: matched.map(|(_, size, _)| size),
                modified_ms: matched.and_then(|(_, _, modified_ms)| modified_ms),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_home(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("billow-res-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("rules")).unwrap();
        dir
    }

    #[test]
    fn rule_providers_resolve_inline_path_and_url_cache() {
        let home = temp_home("rules");
        fs::write(home.join("rules").join(md5_hex("https://x/ads.yaml")), "payload:\n  - DOMAIN-SUFFIX,ads.com\n  - '+.track.io'\n").unwrap();
        fs::write(home.join("cn.txt"), "# comment\nIP-CIDR,1.0.0.0/8\n\n").unwrap();
        let config = r#"
rule-providers:
  ads: { type: http, url: "https://x/ads.yaml", behavior: domain }
  cn: { type: file, path: ./cn.txt, format: text }
  mine: { type: inline, behavior: classical, payload: [ "DOMAIN,a.com", "DOMAIN,b.com" ] }
  bin: { type: http, url: "https://x/a.mrs", format: mrs }
  missing: { type: http, url: "https://x/none.yaml" }
"#;
        let ads = rule_detail(config, "ads", Some(&home));
        assert_eq!(ads.rules, ["DOMAIN-SUFFIX,ads.com", "+.track.io"]);
        assert_eq!(ads.source.as_deref(), Some("https://x/ads.yaml"));
        assert_eq!(rule_detail(config, "cn", Some(&home)).rules, ["IP-CIDR,1.0.0.0/8"]);
        let inline = rule_detail(config, "mine", Some(&home));
        assert_eq!((inline.total, inline.source.as_deref()), (2, Some("inline")));
        assert!(rule_detail(config, "bin", Some(&home)).notice.unwrap().contains("MRS"));
        assert!(rule_detail(config, "missing", Some(&home)).notice.unwrap().contains("还没有找到"));
        assert!(rule_detail(config, "nope", Some(&home)).notice.is_some());
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn rule_providers_read_type_and_format_through_merge_keys() {
        let home = temp_home("merge");
        let url = "https://x/disney.yaml";
        fs::write(home.join("rules").join(md5_hex(url)), "payload:
  - 'DOMAIN,disney.com'
").unwrap();
        // Anchored defaults, and the literal `<<:` mapping a re-serialized config carries.
        let anchored = format!("c: &c {{ type: http, behavior: classical, format: yaml }}
rule-providers:
  disney: {{ <<: *c, url: \"{url}\" }}
");
        let literal = format!("rule-providers:
  disney:
    <<:
      type: http
      format: yaml
    url: {url}
");
        for config in [anchored, literal] {
            let detail = rule_detail(&config, "disney", Some(&home));
            assert_eq!(detail.rules, ["DOMAIN,disney.com"], "{config}");
            assert!(detail.notice.is_none());
        }
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn provider_proxies_keep_type_flags_and_last_delay() {
        let value = serde_json::json!({ "proxies": [
            { "name": "a", "type": "Vless", "udp": true, "xudp": true, "tfo": false, "alive": true,
              "history": [{ "delay": 120 }, { "delay": 88 }] },
            { "name": "b", "type": "Shadowsocks", "udp": false, "alive": false, "history": [{ "delay": 0 }] },
        ]});
        let rows = proxies_from_value(&value);
        assert_eq!(rows[0].node_type, "vless");
        assert_eq!(rows[0].tags, ["UDP", "XUDP"]);
        assert_eq!(rows[0].delay_ms, Some(88));
        assert_eq!(rows[1].delay_ms, None);
        assert_eq!(rows[1].alive, Some(false));
    }

    #[test]
    fn large_rule_previews_count_all_but_retain_only_the_limit() {
        let lines = (0..6000).map(|i| format!("DOMAIN,d{i}.example\n")).collect::<String>();
        let text = parse_rules(&lines, "text");
        assert_eq!(text.total, 6000);
        assert_eq!(text.rows.len(), MAX_RULE_ROWS);
        let yaml = format!("payload:\n{}", lines.lines().map(|line| format!("  - {line}\n")).collect::<String>());
        let preview = parse_rules(&yaml, "yaml");
        assert_eq!(preview.total, 6000);
        assert_eq!(preview.rows, text.rows);
    }

    #[test]
    fn geo_files_report_presence_and_size() {
        let home = temp_home("geo");
        fs::write(home.join("geosite.dat"), [0u8; 10]).unwrap();
        let files = geo_files(Some(&home));
        assert_eq!(files.iter().map(|file| file.key.as_str()).collect::<Vec<_>>(), ["geoip", "geosite", "mmdb", "asn"]);
        assert!(!files[0].exists);
        assert_eq!((files[1].exists, files[1].size), (true, Some(10)));
        assert!(files[1].modified_ms.is_some());
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn geo_files_recognises_android_seeded_and_lowercase_filenames() {
        let home = temp_home("geo-android");
        fs::write(home.join("GeoIP.dat"), [1u8; 24]).unwrap();
        fs::write(home.join("GeoSite.dat"), [2u8; 32]).unwrap();
        fs::write(home.join("Country.mmdb"), [3u8; 16]).unwrap();
        fs::write(home.join("ASN.mmdb"), [4u8; 12]).unwrap();
        let files = geo_files(Some(&home));
        assert!(files.iter().all(|file| file.exists));
        assert_eq!(
            files.iter().map(|file| (file.key.as_str(), file.file.as_str(), file.size)).collect::<Vec<_>>(),
            [
                ("geoip", "GeoIP.dat", Some(24)),
                ("geosite", "GeoSite.dat", Some(32)),
                ("mmdb", "Country.mmdb", Some(16)),
                ("asn", "ASN.mmdb", Some(12)),
            ]
        );
        let _ = fs::remove_dir_all(home);
    }
}
