//! Geodata readers for the rule engine: Mihomo's MRS rule-set format, the
//! protobuf `GeoSite.dat`/`GeoIP.dat` bundles and MaxMind DB (`.mmdb`) files.
//!
//! Everything here is read-only and independent of Tauri. The MRS decoder is
//! the same algorithm as `src-tauri/src/mrs.rs` (kept in sync by hand so the
//! Tauri resource preview can keep its own public API and tests); the `.dat`
//! reader implements the protobuf messages the pinned Mihomo v1.19.34 declares
//! (`component/geodata/router/config.pb.go`); the `.mmdb` reader follows the
//! MaxMind DB v2 file format used by `Country.mmdb`/`ASN.mmdb`.
//!
//! Matching rules mirror the pinned engine:
//! * geosite `plain` is a case-sensitive substring, `domain` covers the name
//!   and subdomains, `full` is exact and `regex` uses the configured pattern;
//! * geosite `@attr` filters on attribute keys and `!list` negates;
//! * GEOIP reads `GeoIP.dat` in geodata mode and `Country.mmdb` otherwise;
//! * IP-ASN reads `ASN.mmdb` (`GeoLite2-ASN` and the `ipinfo` shape).

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::Deserialize;

use crate::config::ipnet_like::IpNet;
use crate::config::ConfigError;

// ---------------------------------------------------------------------------
// MRS (Mihomo rule set, MRSv1)
// ---------------------------------------------------------------------------

const MRS_MAGIC: [u8; 4] = *b"MRS\x01";
/// Hard cap on decompressed bytes so a crafted file cannot exhaust memory.
const MAX_DECODED: u64 = 128 * 1024 * 1024;
/// Upper bound on emitted entries; real sets stay far below this.
const MAX_ENTRIES: usize = 4_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MrsRules {
    /// `domain` or `ipcidr`.
    pub behavior: &'static str,
    pub rules: Vec<String>,
}

/// Decode an MRS file into `convert-ruleset` style rule lines.
pub fn decode_mrs(compressed: &[u8]) -> Result<MrsRules, String> {
    let body = decompress(compressed)?;
    let mut input = Cursor {
        data: &body,
        at: 0,
    };
    if input.take(4)? != MRS_MAGIC {
        return Err("not an MRS file".to_string());
    }
    let behavior = input.u8()?;
    let _count = input.i64()?;
    let extra = input.i64()?;
    if extra < 0 {
        return Err("MRS header is corrupt".to_string());
    }
    input.take(extra as usize)?;
    match behavior {
        0 => Ok(MrsRules {
            behavior: "domain",
            rules: domain_rules(&mut input)?,
        }),
        1 => Ok(MrsRules {
            behavior: "ipcidr",
            rules: ipcidr_rules(&mut input)?,
        }),
        other => Err(format!("unsupported MRS behavior byte {other}")),
    }
}

fn decompress(compressed: &[u8]) -> Result<Vec<u8>, String> {
    use ruzstd::decoding::StreamingDecoder;
    let mut input = compressed;
    let mut out = Vec::new();
    // A zstd stream may consist of several frames; decode them back to back.
    while !input.is_empty() {
        let decoder = match StreamingDecoder::new(&mut input) {
            Ok(decoder) => decoder,
            Err(_) if !out.is_empty() => break,
            Err(err) => return Err(format!("MRS decompression failed: {err}")),
        };
        let budget = MAX_DECODED.saturating_sub(out.len() as u64);
        decoder
            .take(budget + 1)
            .read_to_end(&mut out)
            .map_err(|err| format!("MRS decompression failed: {err}"))?;
        if out.len() as u64 > MAX_DECODED {
            return Err("MRS rule set is too large after decompression".to_string());
        }
    }
    Ok(out)
}

struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .at
            .checked_add(len)
            .filter(|&end| end <= self.data.len());
        let Some(end) = end else {
            return Err("MRS file is truncated".to_string());
        };
        let slice = &self.data[self.at..end];
        self.at = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn i64(&mut self) -> Result<i64, String> {
        Ok(i64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
    fn len(&mut self, unit: usize) -> Result<usize, String> {
        let len = self.i64()?;
        let rest = self.data.len() - self.at;
        if len < 1 || (len as u128) * (unit as u128) > rest as u128 {
            return Err("MRS data length is invalid".to_string());
        }
        Ok(len as usize)
    }
    fn words(&mut self) -> Result<Words<'a>, String> {
        let len = self.len(8)?;
        Ok(Words(self.take(len * 8)?))
    }
}

struct Words<'a>(&'a [u8]);

impl Words<'_> {
    fn len(&self) -> usize {
        self.0.len() / 8
    }
    fn get(&self, index: usize) -> Option<u64> {
        self.0
            .chunks_exact(8)
            .nth(index)
            .map(|bytes| u64::from_be_bytes(bytes.try_into().expect("8 bytes")))
    }
}

fn bit(words: &Words, index: usize) -> Result<bool, String> {
    words
        .get(index >> 6)
        .map(|word| word & (1 << (index & 63)) != 0)
        .ok_or_else(|| "MRS domain trie is corrupt".to_string())
}

fn domain_rules(input: &mut Cursor) -> Result<Vec<String>, String> {
    if input.u8()? != 1 {
        return Err("unsupported MRS domain set version".to_string());
    }
    let leaves = input.words()?;
    let bitmap = input.words()?;
    let labels_len = input.len(1)?;
    let labels = input.take(labels_len)?;
    let corrupt = || "MRS domain trie is corrupt".to_string();

    let mut ones: Vec<u32> = Vec::new();
    for (word_index, bytes) in bitmap.0.chunks_exact(8).enumerate() {
        let mut word = u64::from_be_bytes(bytes.try_into().expect("8 bytes"));
        while word != 0 {
            ones.push((word_index * 64 + word.trailing_zeros() as usize) as u32);
            word &= word - 1;
        }
    }

    let child_of = |node: usize, wanted: u8| -> Result<Option<usize>, String> {
        let mut index = if node == 0 {
            0
        } else {
            *ones.get(node - 1).ok_or_else(corrupt)? as usize + 1
        };
        while !bit(&bitmap, index)? {
            let offset = index.checked_sub(node).ok_or_else(corrupt)?;
            let label = *labels.get(offset).ok_or_else(corrupt)?;
            if label == wanted {
                return Ok(Some(offset + 1));
            }
            index += 1;
        }
        Ok(None)
    };
    let mut keys: Vec<String> = Vec::new();
    let mut terminals = 0;
    let mut emit = |key: &[u8], node: usize, ancestors: &[(usize, usize)]| -> Result<(), String> {
        terminals += 1;
        if terminals > MAX_ENTRIES {
            return Err("MRS rule set has too many entries".to_string());
        }
        if key.is_empty() {
            return Ok(());
        }
        // The suffix-only path for x is reverse(x) + ".+"; its exact-domain
        // terminal is two ancestors up, so merge the pair directly in the trie.
        if key.ends_with(b".+")
            && ancestors.len() >= 3
            && bit(&leaves, ancestors[ancestors.len() - 3].0)?
        {
            return Ok(());
        }
        let mut paired = false;
        if let Some(dot) = child_of(node, b'.')? {
            if let Some(suffix) = child_of(dot, b'+')? {
                paired = bit(&leaves, suffix)?;
            }
        }
        let key = String::from_utf8_lossy(key);
        let key = key.strip_suffix('+').unwrap_or(&key);
        let mut rule = String::with_capacity(key.len() + if paired { 2 } else { 0 });
        if paired {
            rule.push_str("+.");
        }
        rule.extend(key.chars().rev());
        keys.push(rule);
        Ok(())
    };

    let mut key: Vec<u8> = Vec::new();
    let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
    if bit(&leaves, 0)? {
        emit(&key, 0, &stack)?;
    }
    let step_limit = bitmap.len() * 64 + labels.len() + 1;
    let mut steps = 0usize;
    while let Some(&(node, index)) = stack.last() {
        steps += 1;
        if steps > step_limit || stack.len() > 4096 {
            return Err(corrupt());
        }
        if bit(&bitmap, index)? {
            stack.pop();
            key.pop();
            continue;
        }
        if let Some(top) = stack.last_mut() {
            top.1 += 1;
        }
        let label = *index
            .checked_sub(node)
            .and_then(|offset| labels.get(offset))
            .ok_or_else(corrupt)?;
        let child = index - node + 1;
        let child_at = *ones.get(child - 1).ok_or_else(corrupt)? as usize + 1;
        key.push(label);
        stack.push((child, child_at));
        if bit(&leaves, child)? {
            emit(&key, child, &stack)?;
        }
    }

    keys.sort_unstable();
    Ok(keys)
}

fn ipcidr_rules(input: &mut Cursor) -> Result<Vec<String>, String> {
    if input.u8()? != 1 {
        return Err("unsupported MRS IP set version".to_string());
    }
    let count = input.len(32)?;
    let mut rules = Vec::new();
    for _ in 0..count {
        let from: [u8; 16] = input.take(16)?.try_into().expect("16 bytes");
        let to: [u8; 16] = input.take(16)?.try_into().expect("16 bytes");
        let (from, to) = (Ipv6Addr::from(from), Ipv6Addr::from(to));
        match (from.to_ipv4_mapped(), to.to_ipv4_mapped()) {
            (Some(from), Some(to)) => {
                let (from, to) = (u32::from(from) as u128, u32::from(to) as u128);
                push_prefixes(&mut rules, from, to, 32, |value| {
                    Ipv4Addr::from(value as u32).to_string()
                })?;
            }
            _ => {
                let (from, to) = (u128::from(from), u128::from(to));
                push_prefixes(&mut rules, from, to, 128, |value| {
                    Ipv6Addr::from(value).to_string()
                })?;
            }
        }
    }
    Ok(rules)
}

fn push_prefixes(
    out: &mut Vec<String>,
    mut from: u128,
    to: u128,
    bits: u32,
    show: impl Fn(u128) -> String,
) -> Result<(), String> {
    if from > to {
        return Err("MRS IP range is corrupt".to_string());
    }
    loop {
        let mut size = if from == 0 {
            bits
        } else {
            from.trailing_zeros().min(bits)
        };
        while size > 0 && block_end(from, size).is_none_or(|end| end > to) {
            size -= 1;
        }
        if out.len() >= MAX_ENTRIES {
            return Err("MRS rule set has too many entries".to_string());
        }
        out.push(format!("{}/{}", show(from), bits - size));
        match block_end(from, size).and_then(|end| end.checked_add(1)) {
            Some(next) if next <= to => from = next,
            _ => return Ok(()),
        }
    }
}

fn block_end(from: u128, size: u32) -> Option<u128> {
    if size >= 128 {
        return if from == 0 { Some(u128::MAX) } else { None };
    }
    from.checked_add((1u128 << size) - 1)
}

// ---------------------------------------------------------------------------
// Domain patterns
// ---------------------------------------------------------------------------

/// One domain pattern in the syntax used by rule providers, geosite `domain`
/// entries and MRS output: `x`, `+.x`, `.x`, `*.x` and a bare substring.
#[derive(Debug, Clone)]
pub enum DomainPattern {
    /// Exact name.
    Exact(String),
    /// Name and all subdomains (`+.x`, geosite `domain`).
    SuffixAndExact(String),
    /// Subdomains only (`.x`).
    Suffix(String),
    /// One leading label (`*.x`).
    Wildcard(String),
    /// A dot-separated pattern with `*` labels anywhere, matching the pinned
    /// `component/trie/domain.go` semantics: each `*` covers exactly one
    /// label. `suffix` follows the leading `.`/`+.` forms (`host` ends with
    /// the pattern), and `include_exact` follows `+.` (the pattern itself is
    /// also a match).
    WildcardSegments {
        segments: Vec<String>,
        suffix: bool,
        include_exact: bool,
    },
    /// Case-sensitive substring (geosite `plain`).
    Substring(String),
    /// Case-sensitive compiled regular expression (geosite `regex`).
    Regex(regex::Regex),
}

impl DomainPattern {
    pub fn parse(pattern: &str) -> DomainPattern {
        let lower = pattern.trim().to_ascii_lowercase();
        let segments = || lower.split('.').map(str::to_string).collect::<Vec<_>>();
        let has_wildcard = |parts: &[String]| parts.iter().any(|part| part == "*");
        if let Some(rest) = lower.strip_prefix("+.") {
            let parts: Vec<String> = rest.split('.').map(str::to_string).collect();
            if has_wildcard(&parts) {
                DomainPattern::WildcardSegments {
                    segments: parts,
                    suffix: true,
                    include_exact: true,
                }
            } else {
                DomainPattern::SuffixAndExact(rest.to_string())
            }
        } else if let Some(rest) = lower.strip_prefix('.') {
            let parts: Vec<String> = rest.split('.').map(str::to_string).collect();
            if has_wildcard(&parts) {
                DomainPattern::WildcardSegments {
                    segments: parts,
                    suffix: true,
                    include_exact: false,
                }
            } else {
                DomainPattern::Suffix(rest.to_string())
            }
        } else {
            let parts = segments();
            if has_wildcard(&parts) {
                DomainPattern::WildcardSegments {
                    segments: parts,
                    suffix: false,
                    include_exact: true,
                }
            } else {
                DomainPattern::Exact(lower)
            }
        }
    }

    pub fn matches(&self, host: &str) -> bool {
        match self {
            DomainPattern::Exact(value) => host == value,
            DomainPattern::SuffixAndExact(value) => {
                host == value || host.ends_with(&format!(".{value}"))
            }
            DomainPattern::Suffix(value) => host.ends_with(&format!(".{value}")),
            DomainPattern::Wildcard(value) => {
                let Some(prefix) = host.strip_suffix(&format!(".{value}")) else {
                    return false;
                };
                !prefix.is_empty() && !prefix.contains('.')
            }
            DomainPattern::WildcardSegments {
                segments,
                suffix,
                include_exact,
            } => {
                let labels = host.split('.').collect::<Vec<_>>();
                let window = if *suffix {
                    // `+.` also covers the pattern itself; a leading `.` is
                    // subdomains only and needs at least one extra label.
                    if *include_exact {
                        if labels.len() < segments.len() {
                            return false;
                        }
                    } else if labels.len() <= segments.len() {
                        return false;
                    }
                    &labels[labels.len() - segments.len()..]
                } else {
                    if labels.len() != segments.len() {
                        return false;
                    }
                    &labels[..]
                };
                window
                    .iter()
                    .zip(segments.iter())
                    .all(|(label, pattern)| pattern == "*" || label == pattern)
            }
            DomainPattern::Substring(value) => host.contains(value),
            DomainPattern::Regex(regex) => regex.is_match(host),
        }
    }
}

/// A compiled set of domain patterns (rule-provider `behavior: domain`).
#[derive(Debug, Clone, Default)]
pub struct DomainSet {
    patterns: Vec<DomainPattern>,
}

impl DomainSet {
    pub fn new(patterns: impl IntoIterator<Item = DomainPattern>) -> DomainSet {
        DomainSet {
            patterns: patterns.into_iter().collect(),
        }
    }

    pub fn insert(&mut self, pattern: DomainPattern) {
        self.patterns.push(pattern);
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    pub fn matches(&self, host: &str) -> bool {
        !host.is_empty() && self.patterns.iter().any(|pattern| pattern.matches(host))
    }
}

// ---------------------------------------------------------------------------
// GeoIP matching
// ---------------------------------------------------------------------------

/// A compiled GEOIP target: a list of networks, an `mmdb` country code,
/// optionally negated (`!cn`).
#[derive(Debug, Clone)]
pub enum GeoIpMatcher {
    Lan,
    NotLan,
    Nets { nets: Vec<IpNet>, negate: bool },
    Mmdb {
        code: String,
        negate: bool,
        db: std::sync::Arc<Mmdb>,
    },
}

impl GeoIpMatcher {
    pub fn matches(&self, ip: IpAddr) -> bool {
        match self {
            GeoIpMatcher::Lan => is_lan(ip),
            GeoIpMatcher::NotLan => !is_lan(ip),
            GeoIpMatcher::Nets { nets, negate } => {
                let hit = nets.iter().any(|net| net.contains(ip));
                hit != *negate
            }
            GeoIpMatcher::Mmdb { code, negate, db } => {
                let hit = db.country_codes(ip).iter().any(|found| found == code);
                hit != *negate
            }
        }
    }
}

pub fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
        }
    }
}

// ---------------------------------------------------------------------------
// GeoSite database (text YAML and protobuf `.dat`)
// ---------------------------------------------------------------------------

/// A geosite entry: domain patterns plus the attribute keys used by
/// `GEOSITE,list@attr`.
#[derive(Debug, Clone, Default)]
pub struct GeoSiteEntry {
    pub patterns: Vec<(DomainPattern, Vec<String>)>,
}

/// `GeoSite.dat` entries keyed by `(list, tag)`; text databases keep their tag
/// names, protobuf entries use the empty tag (the pinned file has no tags).
#[derive(Debug, Clone, Default)]
pub struct GeoSiteDatabase {
    entries: BTreeMap<(String, String), GeoSiteEntry>,
}

impl GeoSiteDatabase {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn merge_dat(&mut self, bytes: &[u8]) -> Result<(), ConfigError> {
        let list = ProtoReader::new(bytes)
            .message_fields(|field, wire, value, _at| {
                if field == 1 && wire == 2 {
                    Ok(Some(value))
                } else {
                    Ok(None)
                }
            })
            .map_err(|e| ConfigError::Unsupported(format!("GeoSite.dat is not readable: {e}")))?;
        let mut found = 0usize;
        for site in list {
            let site = ProtoReader::new(site);
            let mut code = String::new();
            let mut domains = Vec::new();
            site.message_fields(|field, wire, value, _at| {
                match (field, wire) {
                    (1, 2) => code = String::from_utf8_lossy(value).to_string(),
                    (2, 2) => domains.push(value.to_vec()),
                    _ => {}
                }
                Ok(None)
            })
            .map_err(|e| ConfigError::Unsupported(format!("GeoSite.dat is not readable: {e}")))?;
            if code.is_empty() {
                continue;
            }
            found += 1;
            for domain in domains {
                let reader = ProtoReader::new(&domain);
                let mut kind = 0u64;
                let mut text = String::new();
                let mut attrs = Vec::new();
                reader
                    .message_fields(|field, wire, value, _at| {
                        match (field, wire) {
                            (1, 0) => kind = read_varint(value).unwrap_or(0),
                            (2, 2) => text = String::from_utf8_lossy(value).to_string(),
                            (3, 2) => {
                                let attr = ProtoReader::new(value);
                                let mut key = String::new();
                                attr.message_fields(|field, wire, value, _at| {
                                    if field == 1 && wire == 2 {
                                        key = String::from_utf8_lossy(value).to_string();
                                    }
                                    Ok(None)
                                })
                                .map_err(|e| {
                                    ConfigError::Unsupported(format!(
                                        "GeoSite.dat attribute is not readable: {e}"
                                    ))
                                })?;
                                if !key.is_empty() {
                                    attrs.push(key);
                                }
                            }
                            _ => {}
                        }
                        Ok(None)
                    })
                    .map_err(|e| {
                        ConfigError::Unsupported(format!("GeoSite.dat is not readable: {e}"))
                    })?;
                if text.is_empty() {
                    continue;
                }
                let pattern = match kind {
                    0 => DomainPattern::Substring(text),
                    1 => {
                        // Mihomo compiles geosite regex entries with Go's
                        // regexp; the Rust engine rejects look-around and
                        // backreferences at load instead of never matching.
                        let regex = strict_regex(&text).map_err(|e| {
                            ConfigError::Unsupported(format!(
                                "GeoSite.dat {code} regex {text:?}: {e}"
                            ))
                        })?;
                        DomainPattern::Regex(regex)
                    }
                    2 => DomainPattern::SuffixAndExact(text.to_ascii_lowercase()),
                    3 => DomainPattern::Exact(text.to_ascii_lowercase()),
                    other => {
                        return Err(ConfigError::Unsupported(format!(
                            "GeoSite.dat {code} domain type {other}"
                        )))
                    }
                };
                self.entries
                    .entry((code.to_ascii_lowercase(), String::new()))
                    .or_default()
                    .patterns
                    .push((pattern, attrs));
            }
        }
        if found == 0 {
            return Err(ConfigError::Unsupported(
                "GeoSite.dat contains no lists".to_string(),
            ));
        }
        Ok(())
    }

    /// Resolve `list`, `list/tag`, `!list` and `list@attr` into one matcher.
    pub fn matcher(&self, value: &str) -> Result<(DomainSet, bool), ConfigError> {
        let mut text = value.trim();
        let negate = text.starts_with('!');
        if negate {
            text = &text[1..];
        }
        let (list, attrs) = match text.split_once('@') {
            Some((list, attrs)) => (
                list,
                attrs
                    .split(',')
                    .map(|a| a.trim().to_ascii_lowercase())
                    .filter(|a| !a.is_empty())
                    .collect::<Vec<_>>(),
            ),
            None => (text, Vec::new()),
        };
        let list = list.to_ascii_lowercase();
        let mut set = DomainSet::default();
        if let Some((key, tag)) = list.split_once('/') {
            if let Some(entry) = self.entries.get(&(key.to_string(), tag.to_string())) {
                for (pattern, keys) in &entry.patterns {
                    if attrs.is_empty()
                        || attrs
                            .iter()
                            .all(|wanted| keys.iter().any(|key| key.eq_ignore_ascii_case(wanted)))
                    {
                        set.insert(pattern.clone());
                    }
                }
            }
        } else {
            for ((key, _), entry) in &self.entries {
                if key != &list {
                    continue;
                }
                for (pattern, keys) in &entry.patterns {
                    if attrs.is_empty()
                        || attrs
                            .iter()
                            .all(|wanted| keys.iter().any(|key| key.eq_ignore_ascii_case(wanted)))
                    {
                        set.insert(pattern.clone());
                    }
                }
            }
        }
        if set.is_empty() {
            return Err(ConfigError::Unsupported(format!(
                "GEOSITE list '{value}' has no matching entry in the loaded database"
            )));
        }
        Ok((set, negate))
    }

    // -- the text database kept for tests and small offline fixtures --------

    pub fn merge_yaml(&mut self, yaml: &str) -> Result<(), ConfigError> {
        let documents = serde_yaml::Deserializer::from_str(yaml)
            .map(serde_yaml::Value::deserialize)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                ConfigError::Unsupported(format!("geosite database not readable by this kernel: {e}"))
            })?;
        let mut raw = Vec::new();
        for document in documents {
            match document {
                serde_yaml::Value::Sequence(items) => {
                    for item in items {
                        raw.push(serde_yaml::from_value::<RawGeoSite>(item).map_err(|e| {
                            ConfigError::Unsupported(format!(
                                "geosite database not readable by this kernel: {e}"
                            ))
                        })?);
                    }
                }
                serde_yaml::Value::Null => {}
                other => {
                    let site: RawGeoSite = serde_yaml::from_value(other).map_err(|e| {
                        ConfigError::Unsupported(format!(
                            "geosite database not readable by this kernel: {e}"
                        ))
                    })?;
                    if site.key.is_empty()
                        || site
                            .key
                            .chars()
                            .any(|c| c.is_whitespace() || c == '/' || c == '.' || c == ',')
                    {
                        return Err(ConfigError::Unsupported(format!(
                            "geosite key '{}' (only plain names selectable by GEOSITE,<key> are implemented)",
                            site.key
                        )));
                    }
                    raw.push(site)
                }
            }
        }
        for site in raw {
            for tag in site.tags {
                let entry = self
                    .entries
                    .entry((site.key.to_ascii_lowercase(), tag.name.to_ascii_lowercase()))
                    .or_default();
                for rule in tag.rules {
                    if !rule.unknown.is_empty() {
                        return Err(ConfigError::Unsupported(format!(
                            "geosite {}/{} rule fields {:?} (only domain, sub_domain and domain_keyword are implemented)",
                            site.key, tag.name, rule.unknown
                        )));
                    }
                    if rule.domain.is_empty()
                        && rule.sub_domain.is_empty()
                        && rule.domain_keyword.is_empty()
                    {
                        return Err(ConfigError::Unsupported(format!(
                            "geosite {}/{} uses a regex/other rule type",
                            site.key, tag.name
                        )));
                    }
                    for domain in rule.domain {
                        entry
                            .patterns
                            .push((DomainPattern::Exact(domain.to_ascii_lowercase()), Vec::new()));
                    }
                    for suffix in rule.sub_domain {
                        let suffix = suffix.trim_start_matches("*.");
                        if suffix.contains('*') {
                            return Err(ConfigError::Unsupported(format!(
                                "geosite {}/{} sub_domain pattern '{suffix}' (only literal and a single leading '*.' wildcard are implemented)",
                                site.key, tag.name
                            )));
                        }
                        entry.patterns.push((
                            DomainPattern::SuffixAndExact(suffix.to_ascii_lowercase()),
                            Vec::new(),
                        ));
                    }
                    for keyword in rule.domain_keyword {
                        entry.patterns.push((
                            DomainPattern::Substring(keyword.to_ascii_lowercase()),
                            Vec::new(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Load `GeoSite.dat`, or `<key>.yaml` files, for the requested keys.
    pub fn load_from_dir(
        dir: &Path,
        keys: &std::collections::BTreeSet<String>,
    ) -> Result<Self, ConfigError> {
        let dat = find_case_insensitive(dir, &["GeoSite.dat", "geosite.dat"]);
        if let Some(path) = dat {
            let bytes = std::fs::read(&path).map_err(|e| {
                ConfigError::Unsupported(format!("cannot read {}: {e}", path.display()))
            })?;
            let mut db = GeoSiteDatabase::default();
            db.merge_dat(&bytes)?;
            // A requested key that the dat does not contain is a load error,
            // exactly as Mihomo's `LoadGeoSiteMatcher` reports it.
            for key in keys {
                let list = key.trim_start_matches('!');
                let list = list.split_once('/').map(|(list, _)| list).unwrap_or(list);
                let list = list.split_once('@').map(|(list, _)| list).unwrap_or(list);
                if !db.entries.keys().any(|(candidate, _)| candidate == list) {
                    return Err(ConfigError::Unsupported(format!(
                        "geosite database {} does not contain key '{key}'",
                        path.display()
                    )));
                }
            }
            return Ok(db);
        }
        let mut db = GeoSiteDatabase::default();
        for key in keys {
            let name = key.trim_start_matches('!');
            let name = name.split_once('/').map(|(list, _)| list).unwrap_or(name);
            let name = name.split_once('@').map(|(list, _)| list).unwrap_or(name);
            let candidates = [
                dir.join(name),
                dir.join(format!("{name}.yaml")),
                dir.join(format!("{name}.json")),
            ];
            let path = candidates.iter().find(|p| p.is_file()).ok_or_else(|| {
                ConfigError::Unsupported(format!(
                    "GEOSITE database '{key}' not found in {} (looked for GeoSite.dat, {key}, {key}.yaml)",
                    dir.display()
                ))
            })?;
            let text = std::fs::read_to_string(path).map_err(|e| {
                ConfigError::Unsupported(format!("cannot read {}: {e}", path.display()))
            })?;
            db.merge_yaml(&text)?;
        }
        Ok(db)
    }
}

#[derive(serde::Deserialize)]
struct RawGeoSite {
    key: String,
    tags: Vec<RawGeoSiteTag>,
}

#[derive(serde::Deserialize)]
struct RawGeoSiteTag {
    name: String,
    #[serde(default)]
    rules: Vec<RawGeoSiteRule>,
}

#[derive(serde::Deserialize)]
struct RawGeoSiteRule {
    #[serde(default)]
    domain: Vec<String>,
    #[serde(default)]
    sub_domain: Vec<String>,
    #[serde(default)]
    domain_keyword: Vec<String>,
    #[serde(flatten)]
    unknown: BTreeMap<String, serde_yaml::Value>,
}

// ---------------------------------------------------------------------------
// GeoIP `.dat`
// ---------------------------------------------------------------------------

/// `GeoIP.dat` entries keyed by lowercase country code.
#[derive(Debug, Clone, Default)]
pub struct GeoIpDatabase {
    entries: BTreeMap<String, Vec<IpNet>>,
}

impl GeoIpDatabase {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn merge_dat(&mut self, bytes: &[u8]) -> Result<(), ConfigError> {
        let list = ProtoReader::new(bytes)
            .message_fields(|field, wire, value, _at| {
                if field == 1 && wire == 2 {
                    Ok(Some(value))
                } else {
                    Ok(None)
                }
            })
            .map_err(|e| ConfigError::Unsupported(format!("GeoIP.dat is not readable: {e}")))?;
        let mut found = 0usize;
        for entry in list {
            let mut code = String::new();
            let mut nets = Vec::new();
            ProtoReader::new(entry)
                .message_fields(|field, wire, value, _at| {
                    match (field, wire) {
                        (1, 2) => code = String::from_utf8_lossy(value).to_string(),
                        (2, 2) => nets.push(value.to_vec()),
                        _ => {}
                    }
                    Ok(None)
                })
                .map_err(|e| {
                    ConfigError::Unsupported(format!("GeoIP.dat is not readable: {e}"))
                })?;
            if code.is_empty() {
                continue;
            }
            found += 1;
            let mut parsed = Vec::new();
            for cidr in nets {
                let mut ip = Vec::new();
                let mut prefix = 0u64;
                ProtoReader::new(&cidr)
                    .message_fields(|field, wire, value, _at| {
                        match (field, wire) {
                            (1, 2) => ip = value.to_vec(),
                            (2, 0) => prefix = read_varint(value).unwrap_or(0),
                            _ => {}
                        }
                        Ok(None)
                    })
                    .map_err(|e| {
                        ConfigError::Unsupported(format!("GeoIP.dat CIDR is not readable: {e}"))
                    })?;
                let addr: IpAddr = match ip.len() {
                    4 => IpAddr::from(<[u8; 4]>::try_from(ip.as_slice()).expect("4 bytes")),
                    16 => IpAddr::from(<[u8; 16]>::try_from(ip.as_slice()).expect("16 bytes")),
                    other => {
                        return Err(ConfigError::Unsupported(format!(
                            "GeoIP.dat {code} CIDR has {other}-byte address"
                        )))
                    }
                };
                let net = IpNet::new(addr, prefix as u8).map_err(|e| {
                    ConfigError::Unsupported(format!("GeoIP.dat {code} CIDR: {e}"))
                })?;
                parsed.push(net);
            }
            self.entries
                .entry(code.to_ascii_lowercase())
                .or_default()
                .extend(parsed);
        }
        if found == 0 {
            return Err(ConfigError::Unsupported(
                "GeoIP.dat contains no countries".to_string(),
            ));
        }
        Ok(())
    }

    pub fn matcher(&self, country: &str) -> Result<GeoIpMatcher, ConfigError> {
        let mut name = country.trim().to_ascii_lowercase();
        let negate = name.starts_with('!');
        if negate {
            name = name[1..].to_string();
        }
        if name == "lan" {
            return Ok(if negate {
                GeoIpMatcher::NotLan
            } else {
                GeoIpMatcher::Lan
            });
        }
        let nets = self.entries.get(&name).ok_or_else(|| {
            ConfigError::Unsupported(format!(
                "GEOIP country '{country}' is not present in GeoIP.dat"
            ))
        })?;
        Ok(GeoIpMatcher::Nets {
            nets: nets.clone(),
            negate,
        })
    }
}

// ---------------------------------------------------------------------------
// A tiny protobuf reader for the geodata messages above
// ---------------------------------------------------------------------------

struct ProtoReader<'a> {
    data: &'a [u8],
}

impl<'a> ProtoReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        ProtoReader { data }
    }

    /// Walk length-delimited message fields, calling `visit(field, wire, value, at)`.
    /// `value` is the raw field bytes for wire type 2 and the raw varint bytes
    /// for wire type 0; only fields the caller needs are returned.
    fn message_fields<F>(self, mut visit: F) -> Result<Vec<&'a [u8]>, String>
    where
        F: FnMut(u64, u8, &'a [u8], usize) -> Result<Option<&'a [u8]>, ConfigError>,
    {
        let mut out = Vec::new();
        let mut at = 0usize;
        while at < self.data.len() {
            let (key, used) = read_varint_at(self.data, at)?;
            at += used;
            let field = key >> 3;
            let wire = (key & 7) as u8;
            match wire {
                0 => {
                    let (_, used) = read_varint_at(self.data, at)?;
                    if let Some(value) = visit(field, wire, &self.data[at..at + used], at)
                        .map_err(|e| e.to_string())?
                    {
                        out.push(value);
                    }
                    at += used;
                }
                1 => {
                    if at + 8 > self.data.len() {
                        return Err("truncated fixed64 field".to_string());
                    }
                    visit(field, wire, &self.data[at..at + 8], at)
                        .map_err(|e| e.to_string())?;
                    at += 8;
                }
                2 => {
                    let (len, used) = read_varint_at(self.data, at)?;
                    at += used;
                    let end = at
                        .checked_add(len as usize)
                        .filter(|end| *end <= self.data.len())
                        .ok_or_else(|| "truncated length-delimited field".to_string())?;
                    if let Some(value) = visit(field, wire, &self.data[at..end], at)
                        .map_err(|e| e.to_string())?
                    {
                        out.push(value);
                    }
                    at = end;
                }
                5 => {
                    if at + 4 > self.data.len() {
                        return Err("truncated fixed32 field".to_string());
                    }
                    visit(field, wire, &self.data[at..at + 4], at)
                        .map_err(|e| e.to_string())?;
                    at += 4;
                }
                other => return Err(format!("unsupported protobuf wire type {other}")),
            }
        }
        Ok(out)
    }
}

fn read_varint(bytes: &[u8]) -> Result<u64, String> {
    read_varint_at(bytes, 0).map(|(value, _)| value)
}

fn read_varint_at(bytes: &[u8], at: usize) -> Result<(u64, usize), String> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (index, byte) in bytes[at..].iter().enumerate() {
        if index >= 10 {
            return Err("varint is too long".to_string());
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
        shift += 7;
    }
    Err("truncated varint".to_string())
}

/// Compile a geosite regex with Rust's `regex` (case-sensitive, like the
/// pinned engine's `regexp.Compile`). Rust-only syntax gaps are errors.
fn strict_regex(pattern: &str) -> Result<regex::Regex, String> {
    regex::Regex::new(pattern).map_err(|e| format!("{e}"))
}

// ---------------------------------------------------------------------------
// MaxMind DB reader
// ---------------------------------------------------------------------------

const MMDB_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
const MMDB_MAX_DEPTH: usize = 64;

#[derive(Debug, Clone)]
pub enum MmdbValue {
    String(String),
    Bytes(Vec<u8>),
    UInt(u64),
    Int(i64),
    Double(f64),
    Bool(bool),
    Map(BTreeMap<String, MmdbValue>),
    Array(Vec<MmdbValue>),
}

impl MmdbValue {
    fn as_str(&self) -> Option<&str> {
        match self {
            MmdbValue::String(value) => Some(value),
            _ => None,
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            MmdbValue::UInt(value) => Some(*value),
            MmdbValue::Int(value) => u64::try_from(*value).ok(),
            _ => None,
        }
    }

    fn get(&self, key: &str) -> Option<&MmdbValue> {
        match self {
            MmdbValue::Map(map) => map.get(key),
            _ => None,
        }
    }
}

impl fmt::Display for MmdbValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MmdbValue::String(value) => write!(f, "{value}"),
            MmdbValue::UInt(value) => write!(f, "{value}"),
            MmdbValue::Int(value) => write!(f, "{value}"),
            MmdbValue::Double(value) => write!(f, "{value}"),
            MmdbValue::Bool(value) => write!(f, "{value}"),
            other => write!(f, "{other:?}"),
        }
    }
}

/// A parsed MaxMind DB file (format version 2).
#[derive(Debug, Clone)]
pub struct Mmdb {
    bytes: Vec<u8>,
    database_type: String,
    ip_version: u8,
    node_count: u64,
    record_size: u8,
    tree_size: usize,
    data_start: usize,
    ipv4_start: u64,
}

impl Mmdb {
    pub fn open(path: &Path) -> Result<Mmdb, ConfigError> {
        let bytes = std::fs::read(path).map_err(|e| {
            ConfigError::Unsupported(format!("cannot read {}: {e}", path.display()))
        })?;
        Mmdb::parse(bytes)
            .map_err(|e| ConfigError::Unsupported(format!("{}: {e}", path.display())))
    }

    pub fn parse(bytes: Vec<u8>) -> Result<Mmdb, String> {
        let marker = find_last(&bytes, MMDB_MARKER)
            .ok_or_else(|| "missing MaxMind DB metadata marker".to_string())?;
        let at = marker + MMDB_MARKER.len();
        // First pass: no data-section base is known yet. This is enough to
        // read `node_count`/`record_size`; real files keep metadata pointers
        // (when any) inside the data section, so decode again below.
        let (metadata, end) = decode_value(&bytes, at, 0, 0, 0)?;
        if end != bytes.len() {
            return Err(format!(
                "{} trailing bytes after MMDB metadata",
                bytes.len().saturating_sub(end)
            ));
        }
        let node_count = metadata
            .get("node_count")
            .and_then(MmdbValue::as_u64)
            .ok_or_else(|| "MMDB metadata has no node_count".to_string())?;
        let record_size = metadata
            .get("record_size")
            .and_then(MmdbValue::as_u64)
            .ok_or_else(|| "MMDB metadata has no record_size".to_string())?;
        let record_size = match record_size {
            16 | 24 | 28 | 32 => record_size as u8,
            other => return Err(format!("MMDB record_size {other} is not supported")),
        };
        let ip_version = metadata
            .get("ip_version")
            .and_then(MmdbValue::as_u64)
            .unwrap_or(4) as u8;
        let database_type = metadata
            .get("database_type")
            .and_then(MmdbValue::as_str)
            .unwrap_or("")
            .to_string();
        let tree_size = node_count
            .checked_mul(u64::from(record_size) / 4)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or_else(|| "MMDB tree size overflows".to_string())?;
        let data_start = tree_size
            .checked_add(16)
            .filter(|start| *start <= bytes.len())
            .ok_or_else(|| "MMDB tree does not fit in the file".to_string())?;
        if marker < data_start {
            return Err("MMDB metadata marker is inside the search tree".to_string());
        }
        // Second pass resolves metadata pointers against the data section.
        let (metadata, _) = decode_value(&bytes, at, data_start, data_start, 0)?;
        if metadata.get("node_count").and_then(MmdbValue::as_u64) != Some(node_count) {
            return Err("MMDB metadata is inconsistent between passes".to_string());
        }
        let mut db = Mmdb {
            bytes,
            database_type,
            ip_version,
            node_count,
            record_size,
            tree_size,
            data_start,
            ipv4_start: 0,
        };
        db.ipv4_start = db.find_ipv4_start()?;
        Ok(db)
    }

    pub fn database_type(&self) -> &str {
        &self.database_type
    }

    /// Country shapes the reader can decode. An unknown type is rejected at
    /// rule load instead of silently never matching.
    pub fn supports_country(&self) -> bool {
        matches!(
            self.database_type.as_str(),
            "" | "Meta-geoip0"
                | "sing-geoip"
                | "GeoLite2-Country"
                | "GeoIP2-Country"
                | "DBIP-Country"
                | "DBIP-Country-Lite"
        )
    }

    pub fn supports_asn(&self) -> bool {
        matches!(
            self.database_type.as_str(),
            "" | "GeoLite2-ASN"
                | "DBIP-ASN-Lite (compat=GeoLite2-ASN)"
                | "ipinfo generic_asn_free.mmdb"
        )
    }

    pub fn lookup(&self, ip: IpAddr) -> Result<Option<MmdbValue>, String> {
        // In a v6 database, IPv4 addresses live below 96 zero bits.
        let mapped_v4 = matches!((self.ip_version, ip), (6, IpAddr::V4(_)));
        let raw = match ip {
            IpAddr::V4(ip) => u32::from(ip) as u128,
            IpAddr::V6(ip) => u128::from(ip),
        };
        let (total, mut node) = if mapped_v4 {
            (32u32, self.ipv4_start)
        } else if ip.is_ipv4() {
            (32, 0)
        } else {
            (128, 0)
        };
        for bit in (0..total).rev() {
            let record = self.read_record(node, (raw >> bit) & 1 == 1)?;
            if record == self.node_count {
                return Ok(None);
            }
            if record > self.node_count {
                let offset = record
                    .checked_sub(self.node_count)
                    .and_then(|delta| usize::try_from(delta).ok())
                    .and_then(|delta| delta.checked_add(self.tree_size))
                    .ok_or_else(|| "MMDB data pointer is invalid".to_string())?;
                if offset >= self.bytes.len() {
                    return Err("MMDB data pointer is outside the file".to_string());
                }
                let (value, _) =
                    decode_value(&self.bytes, offset, self.data_start, self.data_start, 0)?;
                return Ok(Some(value));
            }
            node = record;
        }
        Ok(None)
    }

    fn read_record(&self, node: u64, right: bool) -> Result<u64, String> {
        if node >= self.node_count {
            return Err("MMDB node index is outside the tree".to_string());
        }
        let record_bytes = usize::from(self.record_size) / 4;
        let base = usize::try_from(node)
            .ok()
            .and_then(|node| node.checked_mul(record_bytes))
            .ok_or_else(|| "MMDB node offset overflows".to_string())?;
        let half = record_bytes / 2;
        let offset = base + if right { half } else { 0 };
        let end = offset
            .checked_add(half)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| "MMDB record is outside the file".to_string())?;
        let bytes = &self.bytes[offset..end];
        let value = match self.record_size {
            16 => u64::from(u16::from_be_bytes([bytes[0], bytes[1]])),
            24 => u64::from(bytes[0]) << 16 | u64::from(bytes[1]) << 8 | u64::from(bytes[2]),
            28 => {
                let end = base
                    .checked_add(7)
                    .filter(|end| *end <= self.bytes.len())
                    .ok_or_else(|| "MMDB 28-bit record is outside the file".to_string())?;
                let all: [u8; 7] = self.bytes[base..end].try_into().expect("7 bytes");
                if right {
                    (u64::from(all[3] & 0x0f) << 24)
                        | (u64::from(all[4]) << 16)
                        | (u64::from(all[5]) << 8)
                        | u64::from(all[6])
                } else {
                    (u64::from(all[3] & 0xf0) << 20)
                        | (u64::from(all[0]) << 16)
                        | (u64::from(all[1]) << 8)
                        | u64::from(all[2])
                }
            }
            32 => u64::from(u32::from_be_bytes(
                bytes.try_into().expect("4 bytes"),
            )),
            other => return Err(format!("MMDB record_size {other} is not supported")),
        };
        Ok(value)
    }

    /// Metadata may carry `ipv4_start_node`; older files require walking 96
    /// zero bits from the root. Both shapes are accepted.
    fn find_ipv4_start(&self) -> Result<u64, String> {
        if self.ip_version != 6 {
            return Ok(0);
        }
        let mut node = 0u64;
        for _ in 0..96 {
            let record = self.read_record(node, false)?;
            if record >= self.node_count {
                return Ok(0);
            }
            node = record;
        }
        Ok(node)
    }

    pub fn country_codes(&self, ip: IpAddr) -> Vec<String> {
        let Ok(Some(value)) = self.lookup(ip) else {
            return Vec::new();
        };
        match self.database_type.as_str() {
            "Meta-geoip0" => match value {
                MmdbValue::String(value) => vec![value.to_ascii_lowercase()],
                MmdbValue::Array(items) => items
                    .iter()
                    .filter_map(MmdbValue::as_str)
                    .map(|item| item.to_ascii_lowercase())
                    .collect(),
                _ => Vec::new(),
            },
            "sing-geoip" => value
                .as_str()
                .map(|value| vec![value.to_ascii_lowercase()])
                .unwrap_or_default(),
            _ => value
                .get("country")
                .and_then(|country| country.get("iso_code"))
                .and_then(MmdbValue::as_str)
                .map(|code| vec![code.to_ascii_lowercase()])
                .unwrap_or_default(),
        }
    }

    pub fn asn(&self, ip: IpAddr) -> (String, String) {
        let Ok(Some(value)) = self.lookup(ip) else {
            return (String::new(), String::new());
        };
        match self.database_type.as_str() {
            "GeoLite2-ASN" | "DBIP-ASN-Lite (compat=GeoLite2-ASN)" => (
                value
                    .get("autonomous_system_number")
                    .and_then(MmdbValue::as_u64)
                    .map(|number| number.to_string())
                    .unwrap_or_default(),
                value
                    .get("autonomous_system_organization")
                    .and_then(MmdbValue::as_str)
                    .unwrap_or("")
                    .to_string(),
            ),
            "ipinfo generic_asn_free.mmdb" => {
                let asn = value
                    .get("asn")
                    .and_then(MmdbValue::as_str)
                    .unwrap_or("")
                    .trim_start_matches("AS")
                    .to_string();
                let name = value
                    .get("name")
                    .and_then(MmdbValue::as_str)
                    .unwrap_or("")
                    .to_string();
                (asn, name)
            }
            _ => (String::new(), String::new()),
        }
    }
}

fn find_last(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

/// Decode one MaxMind DB data value at `at`. Pointers are resolved against the
/// data section (`data_start`); metadata pointers are relative to `base`.
fn decode_value(
    bytes: &[u8],
    at: usize,
    data_start: usize,
    pointer_base: usize,
    depth: usize,
) -> Result<(MmdbValue, usize), String> {
    if depth > MMDB_MAX_DEPTH {
        return Err("MMDB value nesting is too deep".to_string());
    }
    let control = *bytes
        .get(at)
        .ok_or_else(|| format!("MMDB value is truncated at {at} (len {})", bytes.len()))?;
    let mut position = at + 1;
    let mut kind = control >> 5;
    if kind == 0 {
        kind = *bytes
            .get(position)
            .ok_or_else(|| "MMDB extended type is truncated".to_string())?
            + 7;
        position += 1;
    }
    let mut size = u64::from(control & 0x1f);
    match size {
        29 => {
            size = 29
                + u64::from(
                    *bytes
                        .get(position)
                        .ok_or_else(|| "MMDB size is truncated".to_string())?,
                );
            position += 1;
        }
        30 => {
            let raw = bytes
                .get(position..position + 2)
                .ok_or_else(|| "MMDB size is truncated".to_string())?;
            size = 285 + u64::from(u16::from_be_bytes([raw[0], raw[1]]));
            position += 2;
        }
        31 => {
            let raw = bytes
                .get(position..position + 3)
                .ok_or_else(|| "MMDB size is truncated".to_string())?;
            size = 65_821
                + u64::from(raw[0]) * 65_536
                + u64::from(raw[1]) * 256
                + u64::from(raw[2]);
            position += 3;
        }
        _ => {}
    }

    match kind {
        1 => {
            // Pointers are relative to the data section, not the file start.
            let pointer_size = (control >> 3) & 0x3;
            let value = u64::from(control & 0x7);
            let pointed = match pointer_size {
                0 => {
                    let next = *bytes
                        .get(position)
                        .ok_or_else(|| "MMDB pointer is truncated".to_string())?;
                    position += 1;
                    (value << 8) | u64::from(next)
                }
                1 => {
                    let raw = bytes
                        .get(position..position + 2)
                        .ok_or_else(|| "MMDB pointer is truncated".to_string())?;
                    position += 2;
                    ((value << 16) | u64::from(u16::from_be_bytes([raw[0], raw[1]]))) + 2048
                }
                2 => {
                    let raw = bytes
                        .get(position..position + 3)
                        .ok_or_else(|| "MMDB pointer is truncated".to_string())?;
                    position += 3;
                    ((value << 24)
                        | (u64::from(raw[0]) << 16)
                        | (u64::from(raw[1]) << 8)
                        | u64::from(raw[2]))
                        + 526_336
                }
                _ => {
                    let raw = bytes
                        .get(position..position + 4)
                        .ok_or_else(|| "MMDB pointer is truncated".to_string())?;
                    position += 4;
                    u64::from(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
                }
            };
            let target = usize::try_from(pointed)
                .ok()
                .and_then(|pointed| pointed.checked_add(pointer_base))
                .ok_or_else(|| "MMDB pointer overflows".to_string())?;
            if target >= bytes.len() {
                return Err("MMDB pointer is outside the data section".to_string());
            }
            let (value, _) = decode_value(bytes, target, data_start, pointer_base, depth + 1)?;
            Ok((value, position))
        }
        2 => {
            let raw = bytes
                .get(position..position + size as usize)
                .ok_or_else(|| "MMDB string is truncated".to_string())?;
            let value = String::from_utf8_lossy(raw).to_string();
            Ok((MmdbValue::String(value), position + size as usize))
        }
        3 => {
            let raw = bytes
                .get(position..position + 8)
                .ok_or_else(|| "MMDB double is truncated".to_string())?;
            let value = f64::from_be_bytes(raw.try_into().expect("8 bytes"));
            Ok((MmdbValue::Double(value), position + 8))
        }
        4 => {
            let raw = bytes
                .get(position..position + size as usize)
                .ok_or_else(|| "MMDB bytes are truncated".to_string())?;
            Ok((MmdbValue::Bytes(raw.to_vec()), position + size as usize))
        }
        5 | 6 | 9 | 10 => {
            let raw = bytes
                .get(position..position + size as usize)
                .ok_or_else(|| "MMDB unsigned integer is truncated".to_string())?;
            let value = read_uint(raw);
            Ok((MmdbValue::UInt(value), position + size as usize))
        }
        7 => {
            let mut map = BTreeMap::new();
            let mut position = position;
            for _ in 0..size {
                let (key, next) =
                    decode_value(bytes, position, data_start, pointer_base, depth + 1)?;
                position = next;
                let (value, next) =
                    decode_value(bytes, position, data_start, pointer_base, depth + 1)?;
                position = next;
                let MmdbValue::String(key) = key else {
                    return Err("MMDB map key is not a string".to_string());
                };
                map.insert(key, value);
            }
            Ok((MmdbValue::Map(map), position))
        }
        8 => {
            let raw = bytes
                .get(position..position + size as usize)
                .ok_or_else(|| "MMDB signed integer is truncated".to_string())?;
            let value = if raw.is_empty() {
                0
            } else {
                let mut value = i64::from(raw[0] as i8);
                for byte in &raw[1..] {
                    value = value
                        .checked_shl(8)
                        .ok_or_else(|| "MMDB signed integer overflows".to_string())?
                        | i64::from(*byte);
                }
                value
            };
            Ok((MmdbValue::Int(value), position + size as usize))
        }
        11 => {
            let mut array = Vec::new();
            let mut position = position;
            for _ in 0..size {
                let (value, next) =
                    decode_value(bytes, position, data_start, pointer_base, depth + 1)?;
                position = next;
                array.push(value);
            }
            Ok((MmdbValue::Array(array), position))
        }
        14 => Ok((MmdbValue::Bool(size != 0), position)),
        15 => {
            let raw = bytes
                .get(position..position + 4)
                .ok_or_else(|| "MMDB float is truncated".to_string())?;
            let value = f32::from_be_bytes(raw.try_into().expect("4 bytes")) as f64;
            Ok((MmdbValue::Double(value), position + 4))
        }
        other => Err(format!("MMDB data type {other} is not supported")),
    }
}

fn read_uint(raw: &[u8]) -> u64 {
    let mut value = 0u64;
    for byte in raw {
        value = (value << 8) | u64::from(*byte);
    }
    value
}

// ---------------------------------------------------------------------------
// Loading a geodata directory
// ---------------------------------------------------------------------------

/// Which files back GEOIP: `GeoIP.dat` (geodata mode) or `Country.mmdb`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoIpSource {
    Dat,
    Mmdb,
}

/// Everything found under the configured geodata directory.
#[derive(Debug, Default, Clone)]
pub struct Geodata {
    pub geosite: GeoSiteDatabase,
    pub geoip_dat: GeoIpDatabase,
    pub mmdb: Option<std::sync::Arc<Mmdb>>,
    pub asn: Option<std::sync::Arc<Mmdb>>,
    pub mode: Option<GeoIpSource>,
}

impl Geodata {
    pub fn load(
        dir: &Path,
        mode: GeoIpSource,
        need_geosite: bool,
        need_geoip: bool,
        need_asn: bool,
        geosite_keys: &std::collections::BTreeSet<String>,
    ) -> Result<Geodata, ConfigError> {
        let mut data = Geodata {
            mode: Some(mode),
            ..Geodata::default()
        };
        if need_geosite {
            data.geosite = GeoSiteDatabase::load_from_dir(dir, geosite_keys)?;
        }
        if need_geoip {
            match mode {
                GeoIpSource::Dat => {
                    let path = find_case_insensitive(dir, &["GeoIP.dat", "geoip.dat"]).ok_or_else(
                        || {
                            ConfigError::Unsupported(format!(
                                "geodata-mode: true needs GeoIP.dat in {} (GEOIP rules are configured)",
                                dir.display()
                            ))
                        },
                    )?;
                    let bytes = std::fs::read(&path).map_err(|e| {
                        ConfigError::Unsupported(format!("cannot read {}: {e}", path.display()))
                    })?;
                    data.geoip_dat.merge_dat(&bytes)?;
                }
                GeoIpSource::Mmdb => {
                    let path = find_case_insensitive(dir, &["Country.mmdb", "country.mmdb"])
                        .ok_or_else(|| {
                            ConfigError::Unsupported(format!(
                                "geodata-mode: false needs Country.mmdb in {} (GEOIP rules are configured); set geodata-mode: true to use GeoIP.dat",
                                dir.display()
                            ))
                        })?;
                    data.mmdb = Some(std::sync::Arc::new(Mmdb::open(&path)?));
                }
            }
        }
        if need_asn {
            let path = find_case_insensitive(dir, &["ASN.mmdb", "asn.mmdb"]).ok_or_else(|| {
                ConfigError::Unsupported(format!(
                    "IP-ASN rules need ASN.mmdb in {}",
                    dir.display()
                ))
            })?;
            data.asn = Some(std::sync::Arc::new(Mmdb::open(&path)?));
        }
        Ok(data)
    }

    pub fn geosite_matcher(&self, value: &str) -> Result<(DomainSet, bool), ConfigError> {
        self.geosite.matcher(value)
    }

    pub fn geoip_matcher(&self, country: &str) -> Result<GeoIpMatcher, ConfigError> {
        match self.mode {
            Some(GeoIpSource::Dat) => self.geoip_dat.matcher(country),
            _ => {
                let name = country.trim().to_ascii_lowercase();
                let negate = name.starts_with('!');
                let code = name.trim_start_matches('!').to_string();
                if code == "lan" {
                    return Ok(if negate {
                        GeoIpMatcher::NotLan
                    } else {
                        GeoIpMatcher::Lan
                    });
                }
                let db = self.mmdb.clone().ok_or_else(|| {
                    ConfigError::Unsupported(format!(
                        "GEOIP,{country} needs a loaded Country.mmdb"
                    ))
                })?;
                if !db.supports_country() {
                    return Err(ConfigError::Unsupported(format!(
                        "GEOIP,{country}: Country.mmdb database type '{}' is not a country database",
                        db.database_type()
                    )));
                }
                Ok(GeoIpMatcher::Mmdb { code, negate, db })
            }
        }
    }

    pub fn country_codes(&self, ip: IpAddr) -> Vec<String> {
        self.mmdb
            .as_ref()
            .map(|mmdb| mmdb.country_codes(ip))
            .unwrap_or_default()
    }

    pub fn asn(&self, ip: IpAddr) -> (String, String) {
        self.asn
            .as_ref()
            .map(|mmdb| mmdb.asn(ip))
            .unwrap_or_default()
    }

    /// `ASN.mmdb` for IP-ASN matchers (compiled once, shared through `Arc`).
    pub fn asn_db(&self) -> Option<std::sync::Arc<Mmdb>> {
        self.asn.clone()
    }
}

fn find_case_insensitive(dir: &Path, names: &[&str]) -> Option<std::path::PathBuf> {
    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut files: Vec<_> = entries.flatten().map(|entry| entry.path()).collect();
        files.sort();
        for name in names {
            if let Some(found) = files.iter().find(|path| {
                path.file_name()
                    .is_some_and(|file| file.to_string_lossy().eq_ignore_ascii_case(name))
            }) {
                return Some(found.clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN_MRS: &[u8] = include_bytes!("../../../../src-tauri/testdata/domain.mrs");
    const DOMAIN_COMPLEX_MRS: &[u8] = include_bytes!("../../../../src-tauri/testdata/domain-complex.mrs");
    const IP_MRS: &[u8] = include_bytes!("../../../../src-tauri/testdata/ipcidr.mrs");

    #[test]
    fn mrs_domain_sets_dump_like_mihomo() {
        let decoded = decode_mrs(DOMAIN_MRS).unwrap();
        assert_eq!(decoded.behavior, "domain");
        assert_eq!(
            decoded.rules,
            ["*.wild.io", "+.google.com", ".only-sub.net", "a.b.c.d.e", "example.org"]
        );
    }

    #[test]
    fn mrs_trie_pairing_preserves_wildcards_and_unicode() {
        let decoded = decode_mrs(DOMAIN_COMPLEX_MRS).unwrap();
        assert_eq!(
            decoded.rules,
            [
                "*.nested.wild.example",
                "*.wild.example",
                "+.bücher.example",
                "+.exact.example",
                "+.paired.example",
                "+.parent.example",
                ".deep.example",
                ".only.example",
                "child.parent.example",
                "leaf.deep.example",
                "plain.example",
                "中文.example",
            ]
        );
    }

    #[test]
    fn mrs_ip_sets_emit_aligned_prefixes() {
        let decoded = decode_mrs(IP_MRS).unwrap();
        assert_eq!(
            decoded.rules,
            ["1.0.0.0/23", "10.0.0.0/8", "192.168.1.0/30", "2001:db8::/32"]
        );
    }

    #[test]
    fn mrs_rejects_damaged_files_without_panicking() {
        assert!(decode_mrs(b"not zstd").is_err());
        for cut in 0..DOMAIN_MRS.len() {
            let _ = decode_mrs(&DOMAIN_MRS[..cut]);
        }
        for cut in 0..IP_MRS.len() {
            let _ = decode_mrs(&IP_MRS[..cut]);
        }
    }

    #[test]
    fn domain_patterns_follow_mihomo_syntax() {
        assert!(DomainPattern::parse("example.com").matches("example.com"));
        assert!(!DomainPattern::parse("example.com").matches("a.example.com"));
        assert!(DomainPattern::parse("+.example.com").matches("example.com"));
        assert!(DomainPattern::parse("+.example.com").matches("a.example.com"));
        assert!(!DomainPattern::parse(".example.com").matches("example.com"));
        assert!(DomainPattern::parse(".example.com").matches("a.example.com"));
        assert!(DomainPattern::parse("*.example.com").matches("a.example.com"));
        assert!(!DomainPattern::parse("*.example.com").matches("b.a.example.com"));
        assert!(DomainPattern::parse("*.example.com").matches("a.example.com"));

        // A `*` label in the middle is a one-label wildcard, not an exact name
        // with a literal asterisk (pinned `component/trie/domain.go`).
        let middle = DomainPattern::parse("sub.*.example.com");
        assert!(middle.matches("sub.a.example.com"));
        assert!(!middle.matches("sub.a.b.example.com"));
        assert!(!middle.matches("sub.example.com"));
        // A `*` label also matches a literal `*` host label, as the trie's
        // wildcard child does.
        assert!(middle.matches("sub.*.example.com"));
        let plus = DomainPattern::parse("+.sub.*.example.com");
        assert!(plus.matches("sub.a.example.com"));
        assert!(plus.matches("x.sub.a.example.com"));
        assert!(!plus.matches("x.sub.a.b.example.com"));
        let dot = DomainPattern::parse(".sub.*.example.com");
        assert!(!dot.matches("sub.a.example.com"));
        assert!(dot.matches("x.sub.a.example.com"));
    }

    #[test]
    fn geoip_lan_and_country_matchers() {
        assert!(GeoIpMatcher::Lan.matches("192.168.1.1".parse().unwrap()));
        assert!(GeoIpMatcher::Lan.matches("127.0.0.1".parse().unwrap()));
        assert!(!GeoIpMatcher::Lan.matches("1.1.1.1".parse().unwrap()));
        let mut db = GeoIpDatabase::default();
        let ip = IpAddr::from([10, 0, 0, 0]);
        let cidr = IpNet::new(ip, 8).unwrap();
        db.entries.insert("cn".to_string(), vec![cidr]);
        assert!(db.matcher("CN").unwrap().matches(ip));
        assert!(db.matcher("!cn").unwrap().matches("1.1.1.1".parse().unwrap()));
        assert!(db.matcher("lan").unwrap().matches(ip));
        assert!(db.matcher("!lan").unwrap().matches("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn mmdb_parses_a_minimal_country_database() {
        // Build a one-node database holding {"country":{"iso_code":"ZZ"}}.
        // node 0: left -> data, right -> no data.
        let country = map_value(1, &[str_value("iso_code"), str_value("ZZ")]);
        let data = map_value(1, &[str_value("country"), country]);
        let tree_size = 6u64; // record_size 24
        let mut bytes = vec![0u8; tree_size as usize];
        let data_offset = tree_size + 16;
        let node_count = 1u64;
        let record = node_count + data_offset - tree_size; // pointer - node_count + tree_size
        let record = record as u32;
        bytes[0..3].copy_from_slice(&record.to_be_bytes()[1..4]);
        bytes[3..6].copy_from_slice(&(node_count as u32).to_be_bytes()[1..4]);
        let mut body = bytes;
        body.extend(std::iter::repeat_n(0u8, 16));
        body.extend(data);
        // Metadata: node_count, record_size, ip_version, database_type.
        let meta = [
            str_value("node_count"),
            uint_value(1),
            str_value("record_size"),
            uint_value(24),
            str_value("ip_version"),
            uint_value(4),
            str_value("database_type"),
            str_value("GeoLite2-Country"),
        ];
        body.push(0xab);
        body.push(0xcd);
        body.push(0xef);
        body.extend(b"MaxMind.com");
        let meta_bytes = map_value(4, &meta);
        body.extend(meta_bytes);
        let db = match Mmdb::parse(body.clone()) {
            Ok(db) => db,
            Err(error) => panic!("minimal mmdb: {error}"),
        };
        assert_eq!(db.database_type(), "GeoLite2-Country");
        assert_eq!(db.country_codes("1.2.3.4".parse().unwrap()), ["zz"]);
        assert!(db.country_codes("200.1.2.3".parse().unwrap()).is_empty());
    }

    fn str_value(value: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.push((2 << 5) | value.len() as u8);
        out.extend(value.as_bytes());
        out
    }

    fn uint_value(value: u64) -> Vec<u8> {
        let size = if value <= 0xff {
            1
        } else if value <= 0xffff {
            2
        } else if value <= 0xff_ffff {
            3
        } else {
            4
        };
        let mut out = vec![(5 << 5) | size as u8];
        out.extend(&value.to_be_bytes()[8 - size..]);
        out
    }

    fn map_value(size: u8, body: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![(7 << 5) | size];
        for part in body {
            out.extend(part);
        }
        out
    }
}
