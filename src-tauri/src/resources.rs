//! Read-only details behind the Resources page: what a proxy provider holds,
//! what a rule provider matches, and the state of the GEO databases.
//!
//! The kernel runs without `-d`, so Mihomo keeps provider caches and GEO files
//! in its default home (`$CLASH_HOME_DIR` or `~/.config/mihomo`). Rule provider
//! content is not exposed by the controller API, so it is read from the same
//! file the kernel loads: inline payloads from the config, `path` when set, and
//! `rules/<md5(url)>` for HTTP providers without one.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

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

/// Desktop data home, passed explicitly to Mihomo and shared by resource readers.
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
/// With a needle, only matching rules are counted and kept, so a search covers
/// the whole set rather than the first rows that fit in a preview.
#[derive(Default)]
struct RulePreview {
    rows: Vec<String>,
    total: usize,
    /// Lowercased search text; empty keeps every rule.
    needle: String,
}

impl RulePreview {
    fn new(query: &str) -> Self {
        RulePreview { needle: query.trim().to_lowercase(), ..RulePreview::default() }
    }

    fn push(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() { return; }
        if !self.needle.is_empty() && !contains_rule(line, &self.needle) { return; }
        self.total += 1;
        if self.rows.len() < MAX_RULE_ROWS { self.rows.push(line.to_string()); }
    }
}

fn contains_rule(line: &str, needle: &str) -> bool {
    if line.is_ascii() && needle.is_ascii() {
        line.as_bytes().windows(needle.len()).any(|part| part.eq_ignore_ascii_case(needle.as_bytes()))
    } else {
        line.to_lowercase().contains(needle)
    }
}

#[derive(Clone, PartialEq, Eq)]
struct RuleFileStamp {
    path: PathBuf,
    size: u64,
    modified: SystemTime,
}

impl RuleFileStamp {
    fn new(path: &Path, metadata: &fs::Metadata) -> Option<Self> {
        Some(Self { path: path.to_path_buf(), size: metadata.len(), modified: metadata.modified().ok()? })
    }
}

/// Maximum rule-provider file size read into the app process for preview or static matching.
pub const MAX_PREVIEW_BYTES: u64 = 8 * 1024 * 1024;

/// Retain at most one compact decoded set, not millions of allocated Strings.
/// Serializing cache misses also prevents overlapping searches from multiplying
/// the decompressor/decoder's peak memory. Query results are never cached.
#[derive(Default)]
struct MrsCache {
    entry: Option<(RuleFileStamp, &'static str, Arc<str>)>,
}

impl MrsCache {
    fn decode_with_behavior(
        &mut self,
        body: &[u8],
        stamp: Option<RuleFileStamp>,
    ) -> Result<(&'static str, Arc<str>), String> {
        if let Some((previous, behavior, text)) = &self.entry {
            if stamp.as_ref() == Some(previous) {
                return Ok((*behavior, Arc::clone(text)));
            }
        }
        self.entry = None;
        let decoded = crate::mrs::decode(body)?;
        let behavior = decoded.behavior;
        let rules = decoded.rules;
        let mut text = String::with_capacity(rules.iter().map(|line| line.len() + 1).sum());
        for rule in rules {
            text.push_str(&rule);
            text.push('\n');
        }
        let text: Arc<str> = Arc::from(text);
        if text.len() <= MAX_PREVIEW_BYTES as usize {
            if let Some(stamp) = stamp {
                self.entry = Some((stamp, behavior, Arc::clone(&text)));
            }
        }
        Ok((behavior, text))
    }

    fn decode(&mut self, body: &[u8], stamp: Option<RuleFileStamp>) -> Result<Arc<str>, String> {
        self.decode_with_behavior(body, stamp).map(|(_, text)| text)
    }
}

fn mrs_cache() -> &'static Mutex<MrsCache> {
    static CACHE: OnceLock<Mutex<MrsCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(MrsCache::default()))
}

trait RuleSink {
    fn push(&mut self, line: &str);
    fn done(&self) -> bool {
        false
    }
}

impl RuleSink for RulePreview {
    fn push(&mut self, line: &str) {
        RulePreview::push(self, line);
    }
}

/// Streams `payload:` into a sink, so a large YAML set never becomes a full tree.
struct PayloadSeed<S>(S);

impl<'de, S: RuleSink> serde::de::DeserializeSeed<'de> for PayloadSeed<S> {
    type Value = S;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        struct MapVisitor<S>(S);
        impl<'de, S: RuleSink> serde::de::Visitor<'de> for MapVisitor<S> {
            type Value = S;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a rule provider document with a payload")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut sink = Some(self.0);
                let mut found = None;
                while let Some(key) = map.next_key::<String>()? {
                    match (key.as_str(), sink.take()) {
                        ("payload", Some(current)) => found = Some(map.next_value_seed(SeqSeed(current))?),
                        (_, current) => {
                            sink = current;
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                found.ok_or_else(|| serde::de::Error::missing_field("payload"))
            }
        }
        deserializer.deserialize_map(MapVisitor(self.0))
    }
}

struct SeqSeed<S>(S);

impl<'de, S: RuleSink> serde::de::DeserializeSeed<'de> for SeqSeed<S> {
    type Value = S;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        struct SeqVisitor<S>(S);
        impl<'de, S: RuleSink> serde::de::Visitor<'de> for SeqVisitor<S> {
            type Value = S;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a rule payload sequence")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut sink = self.0;
                while !sink.done() {
                    let Some(value) = seq.next_element::<Value>()? else {
                        break;
                    };
                    if let Some(line) = value.as_str() {
                        sink.push(line);
                    }
                }
                while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(sink)
            }
        }
        deserializer.deserialize_seq(SeqVisitor(self.0))
    }
}

fn scan_rules_into<S: RuleSink>(body: &str, format: &str, mut sink: S, fallback: impl FnOnce() -> S) -> S {
    use serde::de::DeserializeSeed;
    if format.eq_ignore_ascii_case("yaml") || body.trim_start().starts_with("payload:") {
        if let Ok(done) = PayloadSeed(sink).deserialize(serde_yaml::Deserializer::from_str(body)) {
            return done;
        }
        sink = fallback();
    }
    for line in body.lines().map(str::trim) {
        if sink.done() {
            break;
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") || line == "payload:" {
            continue;
        }
        sink.push(line.trim_start_matches("- ").trim_matches(|c| c == '\'' || c == '"'));
    }
    sink
}

fn parse_rules(body: &str, format: &str, query: &str) -> RulePreview {
    scan_rules_into(body, format, RulePreview::new(query), || RulePreview::new(query))
}

fn resolve_provider_path(entry: &Value, kind: &str, home: Option<&Path>) -> Option<PathBuf> {
    match (get_str(entry, "path"), get_str(entry, "url")) {
        (Some(path), _) if !path.is_empty() => {
            let path = PathBuf::from(path);
            if path.is_absolute() {
                Some(path)
            } else {
                home.map(|home| home.join(path))
            }
        }
        (_, Some(url)) if kind == "http" => home.map(|home| home.join("rules").join(md5_hex(url))),
        _ => None,
    }
}

/// Locate a rule provider's content from the effective config (`config_yaml`).
/// A non-empty `query` filters the whole set; the result then lists matches only.
pub fn rule_detail(config_yaml: &str, name: &str, home: Option<&Path>, query: &str) -> ProviderDetail {
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
        let mut preview = RulePreview::new(query);
        if let Some(list) = get(entry, "payload").and_then(Value::as_sequence) {
            for line in list.iter().filter_map(Value::as_str) { preview.push(line); }
        }
        preview
    } else {
        let path = resolve_provider_path(entry, &kind, home);
        detail.source = get_str(entry, "url").map(str::to_string).or_else(|| path.as_ref().map(|path| path.display().to_string()));
        // A preview must never allocate an unbounded provider file in the app process.
        let body = path.as_ref().and_then(|path| {
            let file = fs::File::open(path).ok()?;
            let stamp = file.metadata().ok().and_then(|metadata| RuleFileStamp::new(path, &metadata));
            let mut body = Vec::new();
            file.take(MAX_PREVIEW_BYTES + 1).read_to_end(&mut body).ok()?;
            Some((body, stamp))
        });
        let Some((body, stamp)) = body else {
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
        let binary = format == "mrs"
            || path.as_ref().is_some_and(|path| path.extension().is_some_and(|ext| ext == "mrs"))
            || body.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]);
        if binary {
            // MRS is zstd-compressed; decode it the way `mihomo convert-ruleset` dumps it.
            let decoded = mrs_cache().lock().unwrap_or_else(|poisoned| poisoned.into_inner()).decode(&body, stamp);
            match decoded {
                Ok(text) => parse_rules(&text, "text", query),
                Err(reason) => {
                    detail.notice = Some(format!("{reason}；不影响内核加载这个规则集"));
                    return detail;
                }
            }
        } else {
            parse_rules(&String::from_utf8_lossy(&body), &format, query)
        }
    };
    detail.total = rules.total;
    if rules.total > MAX_RULE_ROWS {
        detail.notice = Some(if rules.needle.is_empty() {
            format!("共 {} 条，只列出前 {MAX_RULE_ROWS} 条；搜索会查找全部规则", rules.total)
        } else {
            format!("匹配 {} 条，只列出前 {MAX_RULE_ROWS} 条", rules.total)
        });
    }
    detail.rules = rules.rows;
    detail
}

/// Outcome of statically scanning one `RULE-SET` provider against a parsed target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleProviderMatch {
    /// Confirmed match against a specific sub-rule inside the provider.
    Matched(String),
    /// Scanned the whole provider and confirmed no rule matches.
    NotMatched,
    /// Cannot statically rule out a match in this provider.
    Uncertain {
        reason: String,
        needs_dns: bool,
    },
}

struct RuleProviderMatcher<'a> {
    behavior: &'a str,
    target: &'a diagnostics::ParsedRuleTarget,
    modifiers: diagnostics::RuleModifiers,
    matched: Option<String>,
    uncertain: Option<(String, bool)>,
}

impl<'a> RuleProviderMatcher<'a> {
    fn new(
        behavior: &'a str,
        target: &'a diagnostics::ParsedRuleTarget,
        modifiers: diagnostics::RuleModifiers,
    ) -> Self {
        Self {
            behavior,
            target,
            modifiers,
            matched: None,
            uncertain: None,
        }
    }

    fn finish(self) -> RuleProviderMatch {
        if let Some(sub_rule) = self.matched {
            RuleProviderMatch::Matched(sub_rule)
        } else if let Some((reason, needs_dns)) = self.uncertain {
            RuleProviderMatch::Uncertain { reason, needs_dns }
        } else {
            RuleProviderMatch::NotMatched
        }
    }
}

impl RuleSink for RuleProviderMatcher<'_> {
    fn done(&self) -> bool {
        self.matched.is_some()
    }

    fn push(&mut self, line: &str) {
        if self.matched.is_some() {
            return;
        }
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        match self.behavior {
            "domain" => {
                if line.contains(',') {
                    if let Some((kind, payload, sub_mods)) =
                        diagnostics::parse_classical_sub_rule(line, self.modifiers)
                    {
                        match diagnostics::evaluate_explicit_rule(&kind, &payload, sub_mods, self.target) {
                            diagnostics::RuleEval::Matched(_) => self.matched = Some(line.to_string()),
                            diagnostics::RuleEval::Uncertain { reason, needs_dns, .. } => {
                                if self.uncertain.is_none() {
                                    self.uncertain = Some((reason, needs_dns));
                                }
                            }
                            diagnostics::RuleEval::NotMatched => {}
                        }
                    }
                } else if let Some(host) = self.target.host.as_deref() {
                    if diagnostics::match_domain_pattern(host, line) {
                        self.matched = Some(line.to_string());
                    }
                }
            }
            "ipcidr" => {
                if let Some(ip) = self.target.ip {
                    if diagnostics::ip_in_cidr(ip, line) {
                        self.matched = Some(line.to_string());
                    }
                }
            }
            _ => {
                if let Some((kind, payload, sub_mods)) =
                    diagnostics::parse_classical_sub_rule(line, self.modifiers)
                {
                    match diagnostics::evaluate_explicit_rule(&kind, &payload, sub_mods, self.target) {
                        diagnostics::RuleEval::Matched(_) => self.matched = Some(line.to_string()),
                        diagnostics::RuleEval::Uncertain { reason, needs_dns, .. } => {
                            if self.uncertain.is_none() {
                                self.uncertain = Some((reason, needs_dns));
                            }
                        }
                        diagnostics::RuleEval::NotMatched => {}
                    }
                }
            }
        }
    }
}

/// Evaluates a single `RULE-SET` provider from `config_yaml` against `input`.
#[cfg_attr(not(test), allow(dead_code))]
pub fn match_rule_provider(
    config_yaml: &str,
    name: &str,
    home: Option<&Path>,
    input: &diagnostics::RuleMatchInput,
    modifiers: diagnostics::RuleModifiers,
) -> Result<RuleProviderMatch, String> {
    let target = diagnostics::parse_rule_target(input)?;
    let mut config: Value = serde_yaml::from_str(config_yaml).unwrap_or(Value::Null);
    let _ = config.apply_merge();
    Ok(match_rule_provider_in_config(&config, name, home, &target, modifiers))
}

pub(crate) fn match_rule_provider_in_config(
    config: &Value,
    name: &str,
    home: Option<&Path>,
    target: &diagnostics::ParsedRuleTarget,
    modifiers: diagnostics::RuleModifiers,
) -> RuleProviderMatch {
    let Some(entry) = get(config, "rule-providers").and_then(|providers| get(providers, name)) else {
        return RuleProviderMatch::Uncertain {
            reason: format!("当前配置里没有找到规则集 {name} 的定义"),
            needs_dns: false,
        };
    };
    let kind = get_str(entry, "type").unwrap_or("").to_ascii_lowercase();
    let format = get_str(entry, "format").unwrap_or("yaml").to_ascii_lowercase();
    let explicit_behavior = get_str(entry, "behavior").map(|b| b.to_ascii_lowercase());
    let initial_behavior = explicit_behavior.as_deref().unwrap_or("classical");

    // Fast paths before touching disk.
    if initial_behavior == "domain" && target.host.is_none() {
        return RuleProviderMatch::NotMatched;
    }
    if initial_behavior == "ipcidr" {
        if modifiers.src {
            return RuleProviderMatch::Uncertain {
                reason: format!("规则集 {name} 带 src 修饰符，需结合实际来源 IP 判断"),
                needs_dns: false,
            };
        }
        if target.ip.is_none() {
            if modifiers.no_resolve {
                return RuleProviderMatch::NotMatched;
            }
            return RuleProviderMatch::Uncertain {
                reason: format!("规则集 {name} 为 IP 规则集且未设置 no-resolve，域名需先解析 DNS 才能判定"),
                needs_dns: true,
            };
        }
    }

    if kind == "inline" {
        let mut matcher = RuleProviderMatcher::new(initial_behavior, target, modifiers);
        if let Some(list) = get(entry, "payload").and_then(Value::as_sequence) {
            for line in list.iter().filter_map(Value::as_str) {
                if matcher.done() {
                    break;
                }
                matcher.push(line);
            }
        }
        return matcher.finish();
    }

    let path = resolve_provider_path(entry, &kind, home);
    let body = path.as_ref().and_then(|path| {
        let file = fs::File::open(path).ok()?;
        let stamp = file.metadata().ok().and_then(|metadata| RuleFileStamp::new(path, &metadata));
        let mut body = Vec::new();
        file.take(MAX_PREVIEW_BYTES + 1).read_to_end(&mut body).ok()?;
        Some((body, stamp))
    });
    let Some((body, stamp)) = body else {
        return RuleProviderMatch::Uncertain {
            reason: format!("规则集 {name} 尚未下载或无法读取本地缓存，请先在外部资源页更新"),
            needs_dns: false,
        };
    };
    if body.len() as u64 > MAX_PREVIEW_BYTES {
        return RuleProviderMatch::Uncertain {
            reason: format!("规则集 {name} 体积超过 8 MiB，已跳过静态穿透"),
            needs_dns: false,
        };
    }

    let binary = format == "mrs"
        || path.as_ref().is_some_and(|path| path.extension().is_some_and(|ext| ext == "mrs"))
        || body.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]);

    if binary {
        let decoded = mrs_cache()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .decode_with_behavior(&body, stamp);
        match decoded {
            Ok((mrs_behavior, text)) => {
                let effective_behavior = explicit_behavior.as_deref().unwrap_or(mrs_behavior);
                if effective_behavior == "domain" && target.host.is_none() {
                    return RuleProviderMatch::NotMatched;
                }
                if effective_behavior == "ipcidr" && target.ip.is_none() {
                    if modifiers.no_resolve {
                        return RuleProviderMatch::NotMatched;
                    }
                    return RuleProviderMatch::Uncertain {
                        reason: format!("规则集 {name} 为 IP 规则集且未设置 no-resolve，域名需先解析 DNS 才能判定"),
                        needs_dns: true,
                    };
                }
                let mut matcher = RuleProviderMatcher::new(effective_behavior, target, modifiers);
                for line in text.lines() {
                    if matcher.done() {
                        break;
                    }
                    matcher.push(line);
                }
                matcher.finish()
            }
            Err(reason) => RuleProviderMatch::Uncertain {
                reason: format!("规则集 {name} 解码失败：{reason}"),
                needs_dns: false,
            },
        }
    } else {
        let text = String::from_utf8_lossy(&body);
        let matcher = scan_rules_into(
            &text,
            &format,
            RuleProviderMatcher::new(initial_behavior, target, modifiers),
            || RuleProviderMatcher::new(initial_behavior, target, modifiers),
        );
        matcher.finish()
    }
}

/// GEO databases Mihomo may load, in the order users recognise them.
/// Checks both lowercase (`geoip.dat`) and Android/Linux PascalCase (`GeoIP.dat`,
/// `Country.mmdb`, `ASN.mmdb`) filenames so case-sensitive filesystems report
/// bundled or downloaded databases accurately.
pub const GEO_SPECS: [(&str, &str, &str, &[&str]); 4] = [
    ("geoip", "GeoIP", "GeoIP.dat", &["geoip.dat", "GeoIP.dat"]),
    ("geosite", "GeoSite", "GeoSite.dat", &["geosite.dat", "GeoSite.dat"]),
    (
        "mmdb",
        "MMDB",
        "Country.mmdb",
        &["geoip.metadb", "GeoIP.metadb", "Country.mmdb", "country.mmdb"],
    ),
    (
        "asn",
        "ASN",
        "ASN.mmdb",
        &["GeoLite2-ASN.mmdb", "ASN.mmdb", "asn.mmdb"],
    ),
];

fn list_dir_files(dir: &Path) -> Vec<(String, u64, Option<u64>)> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let meta = entry.metadata().ok().filter(|meta| meta.is_file())?;
            let name = entry.file_name().into_string().ok()?;
            let modified_ms = meta
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|age| age.as_millis() as u64);
            Some((name, meta.len(), modified_ms))
        })
        .collect()
}

pub fn geo_files(home: Option<&Path>) -> Vec<GeoFile> {
    let entries = home.map(list_dir_files).unwrap_or_default();
    GEO_SPECS
        .into_iter()
        .map(|(key, label, canonical, candidates)| {
            let matched = candidates
                .iter()
                .filter_map(|&candidate| {
                    entries
                        .iter()
                        .find(|(actual, _, _)| actual == candidate)
                        .map(|(actual, size, modified_ms)| (actual.as_str(), *size, *modified_ms))
                })
                .max_by_key(|&(_, size, modified_ms)| (size > 0, modified_ms.unwrap_or(0)));
            GeoFile {
                key: key.to_string(),
                label: label.to_string(),
                file: matched.map(|(name, _, _)| name).unwrap_or(canonical).to_string(),
                exists: matched.is_some(),
                size: matched.map(|(_, size, _)| size),
                modified_ms: matched.and_then(|(_, _, modified_ms)| modified_ms),
            }
        })
        .collect()
}

fn target_geo_path(home: &Path, canonical: &str, candidates: &[&str]) -> PathBuf {
    let entries = list_dir_files(home);
    for &candidate in candidates {
        if let Some((actual, _, _)) = entries.iter().find(|(actual, _, _)| actual == candidate) {
            return home.join(actual);
        }
    }
    home.join(canonical)
}

fn fetch_geo_file(url: &str, local_proxy: Option<&str>, temp: &Path) -> Result<(), String> {
    const MAX_GEO_BYTES: u64 = 128 * 1024 * 1024;
    let try_with = |proxy_url: Option<&str>| -> Result<(), String> {
        let mut builder = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(10))
            .timeout_read(std::time::Duration::from_secs(45));
        if let Some(raw_proxy) = proxy_url {
            if let Ok(proxy) = ureq::Proxy::new(raw_proxy) {
                builder = builder.proxy(proxy);
            }
        }
        let response = builder.build().get(url).set("User-Agent", "Billow").call()
            .map_err(|error| format!("请求失败：{error}"))?;
        let mut reader = response.into_reader();
        let mut head = Vec::with_capacity(64);
        reader.by_ref().take(64).read_to_end(&mut head)
            .map_err(|error| format!("读取失败：{error}"))?;
        if head.len() < 16 {
            return Err("下载到的文件为空或已损坏".to_string());
        }
        let prefix = String::from_utf8_lossy(&head).to_ascii_lowercase();
        if prefix.trim_start().starts_with("<!doctype") || prefix.trim_start().starts_with("<html") {
            return Err("下载源返回了网页而非数据库文件".to_string());
        }
        let file = fs::File::create(temp).map_err(|error| format!("写入临时文件失败：{error}"))?;
        let mut writer = std::io::BufWriter::with_capacity(64 * 1024, file);
        writer.write_all(&head).map_err(|error| format!("写入失败：{error}"))?;
        let copied = std::io::copy(&mut reader.take(MAX_GEO_BYTES - head.len() as u64 + 1), &mut writer)
            .map_err(|error| format!("下载写入失败：{error}"))?;
        if copied + head.len() as u64 > MAX_GEO_BYTES {
            return Err("GEO 数据库体积超过 128 MiB 上限".to_string());
        }
        writer.flush().map_err(|error| format!("写入失败：{error}"))?;
        Ok(())
    };
    if let Some(proxy) = local_proxy {
        if try_with(Some(proxy)).is_ok() { return Ok(()); }
        let _ = fs::remove_file(temp);
    }
    let result = try_with(None);
    if result.is_err() { let _ = fs::remove_file(temp); }
    result
}

/// Downloads one (`target = Some("geoip")`) or all (`target = None`) GEO databases
/// into `home` atomically. Uses `urls` (`key -> Vec<candidate_url>`) and tries the
/// active local proxy first when provided.
pub fn download_geo_files(
    home: &Path,
    urls: &[(String, Vec<String>)],
    target: Option<&str>,
    local_proxy: Option<&str>,
) -> Result<Vec<GeoFile>, String> {
    fs::create_dir_all(home).map_err(|error| format!("无法创建 GEO 目录：{error}"))?;
    let selected: Vec<(&str, &str, &str, &[&str], &[String])> = GEO_SPECS
        .into_iter()
        .filter(|(key, _, _, _)| target.is_none_or(|wanted| wanted == *key))
        .filter_map(|(key, label, canonical, candidates)| {
            let candidates_urls = urls
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, list)| list.as_slice())?;
            Some((key, label, canonical, candidates, candidates_urls))
        })
        .collect();
    if selected.is_empty() {
        return Err("未知的 GEO 数据库类型".to_string());
    }

    let results: Vec<Result<(), String>> = std::thread::scope(|scope| {
        let handles: Vec<_> = selected
            .into_iter()
            .map(|(key, label, canonical, candidates, candidate_urls)| {
                scope.spawn(move || {
                    let mut last_err = String::from("没有可用的下载地址");
                    let dest = target_geo_path(home, canonical, candidates);
                    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
                    let temp = home.join(format!(".{key}.{}.{nanos}.part", std::process::id()));
                    let mut downloaded = false;
                    for url in candidate_urls {
                        let url = url.trim();
                        if url.is_empty() {
                            continue;
                        }
                        match fetch_geo_file(url, local_proxy, &temp) {
                            Ok(()) => {
                                downloaded = true;
                                break;
                            }
                            Err(err) => {
                                last_err = format!("{label} ({url})：{err}");
                            }
                        }
                    }
                    if !downloaded {
                        return Err(last_err);
                    }
                    if let Err(err) = fs::rename(&temp, &dest) {
                        let _ = fs::remove_file(&temp);
                        return Err(format!("替换 {label} 数据库失败：{err}"));
                    }
                    Ok(())
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap_or_else(|_| Err("GEO 下载线程异常终止".to_string())))
            .collect()
    });

    let failures: Vec<String> = results.into_iter().filter_map(Result::err).collect();
    if !failures.is_empty() {
        return Err(failures.join("；"));
    }
    Ok(geo_files(Some(home)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mrs_cache_reuses_decoding_and_invalidates_replaced_files() {
        let home = temp_home("mrs-cache");
        let path = home.join("rules.mrs");
        let domain = include_bytes!("../testdata/domain.mrs");
        let ip = include_bytes!("../testdata/ipcidr.mrs");
        let mut cache = MrsCache::default();
        fs::write(&path, domain).unwrap();
        let stamp = || RuleFileStamp::new(&path, &fs::metadata(&path).unwrap());
        let first = cache.decode(domain, stamp()).unwrap();
        let again = cache.decode(domain, stamp()).unwrap();
        assert!(Arc::ptr_eq(&first, &again));
        assert_eq!(parse_rules(&again, "text", "GOOGLE").rows, ["+.google.com"]);
        fs::write(&path, ip).unwrap();
        let replaced = cache.decode(ip, stamp()).unwrap();
        assert!(!Arc::ptr_eq(&first, &replaced));
        assert_eq!(parse_rules(&replaced, "text", "2001:").rows, ["2001:db8::/32"]);
        assert!(cache.decode(b"broken", None).is_err());
        assert!(cache.entry.is_none(), "a failed replacement must not return old rules");
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn rule_search_preserves_ascii_and_unicode_case_matching() {
        assert!(contains_rule("DOMAIN,Example.COM", "example.com"));
        assert!(contains_rule("BÜCHER.example", "bücher"));
        assert!(!contains_rule("different.example", "example.com"));
    }

    #[test]
    fn interrupted_geo_download_keeps_the_previous_file_and_removes_partial_data() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request);
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2048\r\nConnection: close\r\n\r\n").unwrap();
            stream.write_all(&[0x33; 128]).unwrap();
        });
        let home = temp_home("geo-interrupted");
        let path = home.join("GeoIP.dat");
        fs::write(&path, b"previous database").unwrap();
        let urls = vec![("geoip".to_string(), vec![format!("http://127.0.0.1:{port}/geoip")])];
        assert!(download_geo_files(&home, &urls, Some("geoip"), None).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"previous database");
        assert!(fs::read_dir(&home).unwrap().all(|entry| entry.unwrap().path().extension().is_none_or(|ext| ext != "part")));
        server.join().unwrap();
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    #[ignore = "requires BILLOW_TEST_MRS; benchmarks a local rule set without touching the live kernel"]
    fn benchmark_large_mrs_preview_and_search() {
        let path = PathBuf::from(std::env::var_os("BILLOW_TEST_MRS").expect("MRS fixture"));
        let config = format!("rule-providers:\n  benchmark:\n    type: file\n    format: mrs\n    path: {}\n", serde_json::to_string(&path).unwrap());
        for query in ["", "d199999", "missing-rule"] {
            let start = std::time::Instant::now();
            let result = rule_detail(&config, "benchmark", None, query);
            assert!(result.notice.as_deref().is_none_or(|notice| notice.starts_with("共 ") || notice.starts_with("匹配 ")));
            if query.is_empty() { assert!(result.total > 0); }
            println!("query={query:?} total={} retained={} elapsed_ms={:.2}", result.total, result.rules.len(), start.elapsed().as_secs_f64() * 1000.0);
        }
    }

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
        fs::write(home.join("rules").join(md5_hex("https://x/a.mrs")), include_bytes!("../testdata/domain.mrs")).unwrap();
        fs::write(home.join("cn.mrs"), include_bytes!("../testdata/ipcidr.mrs")).unwrap();
        let config = r#"
rule-providers:
  ads: { type: http, url: "https://x/ads.yaml", behavior: domain }
  cn: { type: file, path: ./cn.txt, format: text }
  mine: { type: inline, behavior: classical, payload: [ "DOMAIN,a.com", "DOMAIN,b.com" ] }
  bin: { type: http, url: "https://x/a.mrs", format: mrs, behavior: domain }
  ip: { type: file, path: ./cn.mrs, behavior: ipcidr }
  missing: { type: http, url: "https://x/none.yaml" }
"#;
        let ads = rule_detail(config, "ads", Some(&home), "");
        assert_eq!(ads.rules, ["DOMAIN-SUFFIX,ads.com", "+.track.io"]);
        assert_eq!(ads.source.as_deref(), Some("https://x/ads.yaml"));
        assert_eq!(rule_detail(config, "cn", Some(&home), "").rules, ["IP-CIDR,1.0.0.0/8"]);
        let inline = rule_detail(config, "mine", Some(&home), "");
        assert_eq!((inline.total, inline.source.as_deref()), (2, Some("inline")));
        // Binary MRS sets decode like `mihomo convert-ruleset`, by format or file extension.
        let bin = rule_detail(config, "bin", Some(&home), "");
        assert_eq!(bin.rules, ["*.wild.io", "+.google.com", ".only-sub.net", "a.b.c.d.e", "example.org"]);
        assert!(bin.notice.is_none());
        assert_eq!(rule_detail(config, "ip", Some(&home), "").rules, ["1.0.0.0/23", "10.0.0.0/8", "192.168.1.0/30", "2001:db8::/32"]);
        assert_eq!(rule_detail(config, "bin", Some(&home), "GOOGLE").rules, ["+.google.com"]);
        fs::write(home.join("rules").join(md5_hex("https://x/a.mrs")), b"MRS but damaged").unwrap();
        assert!(rule_detail(config, "bin", Some(&home), "").notice.unwrap().contains("不影响内核"));
        assert!(rule_detail(config, "missing", Some(&home), "").notice.unwrap().contains("还没有找到"));
        assert!(rule_detail(config, "nope", Some(&home), "").notice.is_some());
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
            let detail = rule_detail(&config, "disney", Some(&home), "");
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
        let text = parse_rules(&lines, "text", "");
        assert_eq!(text.total, 6000);
        assert_eq!(text.rows.len(), MAX_RULE_ROWS);
        let yaml = format!("payload:\n{}", lines.lines().map(|line| format!("  - {line}\n")).collect::<String>());
        let preview = parse_rules(&yaml, "yaml", "");
        assert_eq!(preview.total, 6000);
        assert_eq!(preview.rows, text.rows);
        // A search reaches rules past the preview limit, in both formats.
        for (body, format) in [(&lines, "text"), (&yaml, "yaml")] {
            let found = parse_rules(body, format, " D5999.Example ");
            assert_eq!((found.total, found.rows.as_slice()), (1, ["DOMAIN,d5999.example".to_string()].as_slice()));
        }
        // Keys around the payload are skipped, wherever it sits.
        let wrapped = parse_rules("name: x\npayload:\n  - DOMAIN,a.com\nextra: { k: [1, 2] }\n", "yaml", "");
        assert_eq!(wrapped.rows, ["DOMAIN,a.com"]);
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

    #[test]
    fn download_geo_files_updates_all_or_single_database_and_rejects_html() {
        use std::io::Write;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            for _ in 0..5 {
                let Ok((mut stream, _)) = listener.accept() else { break };
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                while let Ok(n) = stream.read(&mut tmp) {
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let req = String::from_utf8_lossy(&buf);
                let body: Vec<u8> = if req.contains("GET /html") {
                    b"<!DOCTYPE html><html><body>404</body></html>".to_vec()
                } else if req.contains("GET /geoip") {
                    vec![0x11; 64]
                } else if req.contains("GET /geosite") {
                    vec![0x22; 80]
                } else if req.contains("GET /mmdb") {
                    vec![0x33; 96]
                } else {
                    vec![0x44; 48]
                };
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
                let _ = stream.shutdown(std::net::Shutdown::Write);
            }
        });

        let home = temp_home("geo-dl");
        // Existing lowercase filename is preserved when updated.
        fs::write(home.join("country.mmdb"), [0u8; 20]).unwrap();
        let urls = vec![
            ("geoip".to_string(), vec![format!("http://127.0.0.1:{port}/html"), format!("http://127.0.0.1:{port}/geoip")]),
            ("geosite".to_string(), vec![format!("http://127.0.0.1:{port}/geosite")]),
            ("mmdb".to_string(), vec![format!("http://127.0.0.1:{port}/mmdb")]),
            ("asn".to_string(), vec![format!("http://127.0.0.1:{port}/asn")]),
        ];
        let files = download_geo_files(&home, &urls, None, None).unwrap();
        assert!(files.iter().all(|f| f.exists));
        assert_eq!(files[0].file, "GeoIP.dat");
        assert_eq!(files[0].size, Some(64));
        assert_eq!(files[1].file, "GeoSite.dat");
        assert_eq!(files[1].size, Some(80));
        assert_eq!(files[2].file, "country.mmdb");
        assert_eq!(files[2].size, Some(96));
        assert_eq!(files[3].file, "ASN.mmdb");
        assert_eq!(files[3].size, Some(48));

        let _ = server.join();
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn match_rule_provider_handles_mrs_domain_wildcards_ipcidr_no_resolve_and_merge_keys() {
        let home = temp_home("match-provider");
        fs::write(home.join("domain.mrs"), include_bytes!("../testdata/domain.mrs")).unwrap();
        fs::write(home.join("ipcidr.mrs"), include_bytes!("../testdata/ipcidr.mrs")).unwrap();
        let config = r#"
base_mrs: &base_mrs
  type: file
  format: mrs
rule-providers:
  dom:
    <<: *base_mrs
    path: ./domain.mrs
    behavior: domain
  ip:
    <<: *base_mrs
    path: ./ipcidr.mrs
    behavior: ipcidr
"#;
        let mods = diagnostics::RuleModifiers::default();
        let no_resolve = diagnostics::RuleModifiers { no_resolve: true, src: false };

        // `*.wild.io` matches single subdomain, not multi-level or apex.
        assert_eq!(
            match_rule_provider(config, "dom", Some(&home), &diagnostics::RuleMatchInput { target: "a.wild.io".into(), ..Default::default() }, mods).unwrap(),
            RuleProviderMatch::Matched("*.wild.io".to_string())
        );
        assert_eq!(
            match_rule_provider(config, "dom", Some(&home), &diagnostics::RuleMatchInput { target: "a.b.wild.io".into(), ..Default::default() }, mods).unwrap(),
            RuleProviderMatch::NotMatched
        );
        // `.only-sub.net` matches subdomain only, not apex.
        assert_eq!(
            match_rule_provider(config, "dom", Some(&home), &diagnostics::RuleMatchInput { target: "only-sub.net".into(), ..Default::default() }, mods).unwrap(),
            RuleProviderMatch::NotMatched
        );
        assert_eq!(
            match_rule_provider(config, "dom", Some(&home), &diagnostics::RuleMatchInput { target: "x.y.only-sub.net".into(), ..Default::default() }, mods).unwrap(),
            RuleProviderMatch::Matched(".only-sub.net".to_string())
        );
        // `ip` provider with pure domain: no-resolve => NotMatched; without no-resolve => Uncertain(needs_dns: true).
        assert_eq!(
            match_rule_provider(config, "ip", Some(&home), &diagnostics::RuleMatchInput { target: "example.com".into(), ..Default::default() }, no_resolve).unwrap(),
            RuleProviderMatch::NotMatched
        );
        match match_rule_provider(config, "ip", Some(&home), &diagnostics::RuleMatchInput { target: "example.com".into(), ..Default::default() }, mods).unwrap() {
            RuleProviderMatch::Uncertain { needs_dns, .. } => assert!(needs_dns),
            other => panic!("expected Uncertain with needs_dns, got {other:?}"),
        }

        let _ = fs::remove_dir_all(home);
    }
}
