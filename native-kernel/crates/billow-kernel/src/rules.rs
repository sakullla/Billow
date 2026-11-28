//! Immutable rule set shared through `Arc` and released when the last session drops it.
//!
//! The declarative [`crate::config::Rule`] list is compiled into matchers that
//! own their regular expressions, loaded geosite/geoip data and rule-provider
//! snapshots. Evaluation keeps Mihomo's first-match order: a matching rule's
//! target is the outbound, `SUB-RULE` lets the named list choose it, and a
//! configuration without `MATCH` falls through to DIRECT.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use crate::config::{
    Action, Config, ConfigError, InType, Matcher, NetworkKind, PortKind, PortRange, ProcessKind,
    Rule,
};
use crate::geodata::{DomainPattern, DomainSet, GeoIpMatcher, Geodata};
use crate::provider::{IndexedProvider, ProviderPayload, RuleProviders};

/// Destination and connection metadata available before dialling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Lowercased rule host; empty when the destination was a literal IP
    /// (Mihomo's `Metadata.Host` is empty in that case).
    pub host: String,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub network: Option<NetworkKind>,
    pub source_ip: Option<IpAddr>,
    pub source_port: u16,
    pub in_port: u16,
    pub in_type: Option<InType>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
}

impl Target {
    pub fn new(host: &str, ip: Option<IpAddr>) -> Self {
        let parsed = host.parse::<IpAddr>().ok();
        Target {
            host: if parsed.is_some() {
                String::new()
            } else {
                host.to_ascii_lowercase()
            },
            ip: ip.or(parsed),
            port: 0,
            network: None,
            source_ip: None,
            source_port: 0,
            in_port: 0,
            in_type: None,
            process_name: None,
            process_path: None,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn with_network(mut self, network: NetworkKind) -> Self {
        self.network = Some(network);
        self
    }

    pub fn with_source(mut self, ip: IpAddr, port: u16) -> Self {
        self.source_ip = Some(ip);
        self.source_port = port;
        self
    }

    pub fn with_inbound(mut self, port: u16, in_type: InType) -> Self {
        self.in_port = port;
        self.in_type = Some(in_type);
        self
    }

    pub fn with_process(mut self, name: Option<&str>, path: Option<&str>) -> Self {
        self.process_name = name.map(str::to_string);
        self.process_path = path.map(str::to_string);
        self
    }
}

/// Why a rule fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    pub rule: Rule,
    pub index: usize,
    /// The outbound that won; `SUB-RULE` may differ from `rule.action`.
    pub action: Action,
}

impl RuleMatch {
    /// `DOMAIN-SUFFIX,x -> s1`; proxy names are resolved through the config.
    pub fn label(&self, config: &Config) -> String {
        format!(
            "{} -> {}",
            self.rule.matcher,
            config.action_name(self.action)
        )
    }
}

impl std::fmt::Display for RuleMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.rule.matcher, self.action.as_str())
    }
}

/// State carried between rule evaluations when an IP-based rule needs the
/// destination resolved. The engine first evaluates with
/// [`MatchInput::default`], resolves the host when [`MatchStep::NeedResolve`]
/// comes back, and then re-evaluates with `resolved: true` and the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MatchInput {
    /// Address learned by a previous resolution pass.
    pub ip: Option<IpAddr>,
    /// `true` after a resolution attempt (a `None` IP then means "resolution
    /// failed", and no rule asks again).
    pub resolved: bool,
}

/// One step of the lazy IP resolution used by the pinned `RuleMatchHelper`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchStep {
    /// The first matching rule (and the outbound it selects).
    Matched(RuleMatch),
    /// An IP-based rule with `no-resolve` unset needs the host resolved; the
    /// engine resolves it, then calls [`RuleSet::evaluate_step`] again with the
    /// same start index.
    NeedResolve,
    /// No rule matched; the built-in DIRECT fallthrough applies.
    Fallthrough,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Yes,
    No,
    /// An IP-based rule needs the destination resolved first.
    Resolve,
}

/// Per-pass resolution state: the address learned earlier (or supplied by the
/// caller) and whether a resolution attempt already failed.
struct ResolveState {
    ip: Option<IpAddr>,
    resolved: bool,
    /// `SUB-RULE`'s selected action from the rule that just matched.
    selected: Option<Action>,
}

/// One compiled rule and the declarative source used for labels.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub source: Rule,
    pub matcher: CompiledMatcher,
}

/// Matchers that own compiled regexes and geodata references.
#[derive(Debug, Clone)]
pub enum CompiledMatcher {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(regex::Regex),
    DomainWildcard(String),
    GeoSite { set: DomainSet, negate: bool },
    GeoIp { matcher: GeoIpMatcher, source: bool },
    IpAsn {
        asn: String,
        source: bool,
        db: Arc<crate::geodata::Mmdb>,
    },
    IpCidr { net: crate::config::ipnet_like::IpNet, source: bool },
    IpSuffix { net: crate::config::ipnet_like::IpNet, source: bool },
    Port { kind: PortKind, ranges: Vec<PortRange> },
    Network(NetworkKind),
    InType(Vec<InType>),
    Process { kind: ProcessKind, pattern: String, regex: Option<regex::Regex> },
    ProcessWildcard { kind: ProcessKind, pattern: String },
    RuleSet { name: String, source: bool },
    SubRule { gate: Box<CompiledRule>, name: String },
    And(Vec<CompiledRule>),
    Or(Vec<CompiledRule>),
    Not(Box<CompiledRule>),
    Match,
}

/// A provider snapshot compiled into a matcher, replaced atomically on update.
#[derive(Debug)]
pub struct CompiledRuleSet {
    pub behavior: crate::config::RuleBehavior,
    pub domain: DomainSet,
    pub cidr: Vec<crate::config::ipnet_like::IpNet>,
    pub classical: Vec<CompiledRule>,
    pub(crate) indexed: Option<IndexedProvider>,
    /// Number of entries as reported by the provider payload.
    pub count: usize,
}

impl CompiledRuleSet {
    fn matches_state(
        &self,
        target: &Target,
        state: &mut ResolveState,
        set: &RuleSet,
        allow_resolve: bool,
        source: bool,
    ) -> Outcome {
        match self.behavior {
            crate::config::RuleBehavior::Domain => flag(self.domain.matches(&target.host)),
            crate::config::RuleBehavior::IpCidr => {
                let ip = match resolve_ip(target, state, source, allow_resolve) {
                    Ok(ip) => ip,
                    Err(()) => return Outcome::Resolve,
                };
                flag(ip.is_some_and(|ip| self.cidr.iter().any(|net| net.contains(ip))))
            }
            crate::config::RuleBehavior::Classical => {
                let first_domain = self.indexed.as_ref().and_then(|index| {
                    index.domains.first_match(&target.host).unwrap_or_else(|error| {
                        tracing::error!(%error, "cannot read the rule-provider domain index");
                        None
                    })
                });
                for (position, rule) in self.classical.iter().enumerate() {
                    if let (Some(domain), Some(index)) = (first_domain, &self.indexed) {
                        if domain < index.other_positions[position] {
                            return Outcome::Yes;
                        }
                    }
                    match rule.matches_state(target, state, set, allow_resolve) {
                        Outcome::Yes => return Outcome::Yes,
                        Outcome::Resolve => return Outcome::Resolve,
                        Outcome::No => {}
                    }
                }
                flag(first_domain.is_some())
            }
        }
    }
}

/// Compiled top-level rules plus the provider registry and sub-rule lists.
#[derive(Debug)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
    sub_rules: BTreeMap<String, Vec<CompiledRule>>,
    pub providers: Arc<RuleProviders>,
}

impl RuleSet {
    /// Compile `config` against already-prepared providers.
    pub fn compile(config: &Config, providers: Arc<RuleProviders>) -> Result<Arc<Self>, ConfigError> {
        Self::compile_rules(&config.rules, &config.sub_rules, providers)
    }

    pub(crate) fn compile_rules(
        source: &[Rule],
        sub: &BTreeMap<String, Vec<Rule>>,
        providers: Arc<RuleProviders>,
    ) -> Result<Arc<Self>, ConfigError> {
        let geodata = providers.geodata();
        let slots = providers.slots();
        let mut sub_rules = BTreeMap::new();
        for (name, rules) in sub {
            let mut compiled = Vec::with_capacity(rules.len());
            for rule in rules {
                compiled.push(compile_rule(rule, &geodata, &slots)?);
            }
            sub_rules.insert(name.clone(), compiled);
        }
        let mut rules = Vec::with_capacity(source.len());
        for rule in source {
            rules.push(compile_rule(rule, &geodata, &slots)?);
        }
        Ok(Arc::new(RuleSet {
            rules,
            sub_rules,
            providers,
        }))
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn provider_count(&self) -> usize {
        self.providers.rule_provider_count()
    }

    /// The built-in fallthrough used when no rule matches: DIRECT.
    pub fn fallthrough_match() -> RuleMatch {
        RuleMatch {
            rule: Rule {
                matcher: Matcher::Match,
                action: Action::Direct,
                no_resolve: false,
            },
            index: usize::MAX,
            action: Action::Direct,
        }
    }

    /// First matching rule wins; without `MATCH`, built-in DIRECT. This entry
    /// never resolves a name (the caller provides `target.ip` when known), so
    /// diagnostics and tests keep the pre-DNS behaviour.
    pub fn evaluate(&self, target: &Target) -> RuleMatch {
        match self.evaluate_step(
            target,
            MatchInput {
                ip: target.ip,
                resolved: true,
            },
            0,
        ) {
            MatchStep::Matched(found) => found,
            MatchStep::NeedResolve | MatchStep::Fallthrough => RuleMatch {
                rule: Rule {
                    matcher: Matcher::Match,
                    action: Action::Direct,
                    no_resolve: false,
                },
                index: usize::MAX,
                action: Action::Direct,
            },
        }
    }

    /// Evaluate from `start`. An IP-based rule whose `no-resolve` flag is unset
    /// stops the pass with [`MatchStep::NeedResolve`] when the destination is a
    /// name and no address is known yet; the caller resolves and calls again
    /// with the same `start` and `resolved: true`.
    pub fn evaluate_step(&self, target: &Target, input: MatchInput, start: usize) -> MatchStep {
        let mut state = ResolveState {
            ip: input.ip,
            resolved: input.resolved,
            selected: None,
        };
        for (index, rule) in self.rules.iter().enumerate().skip(start) {
            match rule.matches_state(target, &mut state, self, true) {
                Outcome::Resolve => return MatchStep::NeedResolve,
                Outcome::Yes => {
                    // `SUB-RULE` may choose a different outbound than its own
                    // action; the matching pass records it in the state.
                    let action = state.selected.take().unwrap_or(rule.source.action);
                    let mut source = rule.source.clone();
                    source.action = action;
                    return MatchStep::Matched(RuleMatch {
                        rule: source,
                        index,
                        action,
                    });
                }
                Outcome::No => {}
            }
        }
        MatchStep::Fallthrough
    }

    fn match_sub_rules(
        &self,
        name: &str,
        target: &Target,
        state: &mut ResolveState,
        depth: usize,
    ) -> Result<Option<Action>, ()> {
        if depth > 32 {
            // The loader rejects cycles; the bound only protects a bug.
            return Ok(None);
        }
        let Some(rules) = self.sub_rules.get(name) else {
            return Ok(None);
        };
        for rule in rules {
            match rule.matches_state(target, state, self, true) {
                Outcome::Resolve => return Err(()),
                Outcome::Yes => {
                    return Ok(Some(state.selected.take().unwrap_or(rule.source.action)))
                }
                Outcome::No => {}
            }
        }
        Ok(None)
    }
}

impl CompiledRule {
    fn matches_state(
        &self,
        target: &Target,
        state: &mut ResolveState,
        set: &RuleSet,
        outer_allow: bool,
    ) -> Outcome {
        let allow = outer_allow && !self.source.no_resolve;
        match &self.matcher {
            CompiledMatcher::SubRule { gate, name } => {
                match gate.matches_state(target, state, set, allow) {
                    Outcome::No => Outcome::No,
                    Outcome::Resolve => Outcome::Resolve,
                    Outcome::Yes => match set.match_sub_rules(name, target, state, 0) {
                        Ok(Some(action)) => {
                            state.selected = Some(action);
                            Outcome::Yes
                        }
                        Ok(None) => Outcome::No,
                        Err(()) => Outcome::Resolve,
                    },
                }
            }
            matcher => matcher.matches_state(target, state, set, allow),
        }
    }
}

/// `true`/`false` as an [`Outcome`] without a resolution request.
fn flag(value: bool) -> Outcome {
    if value {
        Outcome::Yes
    } else {
        Outcome::No
    }
}

fn resolve_ip(
    target: &Target,
    state: &mut ResolveState,
    source: bool,
    allow: bool,
) -> Result<Option<IpAddr>, ()> {
    if source {
        return Ok(target.source_ip);
    }
    if let Some(ip) = target.ip {
        return Ok(Some(ip));
    }
    if let Some(ip) = state.ip {
        return Ok(Some(ip));
    }
    if state.resolved {
        return Ok(None);
    }
    if !allow || target.host.is_empty() {
        return Ok(None);
    }
    // The engine resolves and re-evaluates; `state` is rebuilt from the
    // returned `MatchInput`, so a failed resolution is remembered there.
    Err(())
}

impl CompiledMatcher {
    fn matches_state(
        &self,
        target: &Target,
        state: &mut ResolveState,
        set: &RuleSet,
        allow_resolve: bool,
    ) -> Outcome {
        let hit = match self {
            CompiledMatcher::Domain(value) => target.host == *value,
            CompiledMatcher::DomainSuffix(value) => {
                target.host == *value
                    || target.host.strip_suffix(value).is_some_and(|prefix| prefix.ends_with('.'))
            }
            CompiledMatcher::DomainKeyword(value) => target.host.contains(value),
            CompiledMatcher::DomainRegex(regex) => regex.is_match(&target.host),
            CompiledMatcher::DomainWildcard(pattern) => wildcard_match(pattern, &target.host),
            CompiledMatcher::GeoSite { set: domains, negate } => {
                domains.matches(&target.host) != *negate
            }
            CompiledMatcher::GeoIp { matcher, source } => {
                let ip = match resolve_ip(target, state, *source, allow_resolve) {
                    Ok(ip) => ip,
                    Err(()) => return Outcome::Resolve,
                };
                ip.is_some_and(|ip| matcher.matches(ip))
            }
            CompiledMatcher::IpAsn {
                asn,
                source,
                db,
            } => {
                let ip = match resolve_ip(target, state, *source, allow_resolve) {
                    Ok(ip) => ip,
                    Err(()) => return Outcome::Resolve,
                };
                let Some(ip) = ip else {
                    return Outcome::No;
                };
                let (found, _) = db.asn(ip);
                found == *asn
            }
            CompiledMatcher::IpCidr { net, source } => {
                let ip = match resolve_ip(target, state, *source, allow_resolve) {
                    Ok(ip) => ip,
                    Err(()) => return Outcome::Resolve,
                };
                ip.is_some_and(|ip| net.contains(ip))
            }
            CompiledMatcher::IpSuffix { net, source } => {
                let ip = match resolve_ip(target, state, *source, allow_resolve) {
                    Ok(ip) => ip,
                    Err(()) => return Outcome::Resolve,
                };
                ip.is_some_and(|ip| ip_suffix_matches(net, ip))
            }
            CompiledMatcher::Port { kind, ranges } => {
                let port = match kind {
                    PortKind::Dst => target.port,
                    PortKind::Src => target.source_port,
                    PortKind::In => target.in_port,
                };
                ranges.is_empty()
                    || ranges
                        .iter()
                        .any(|(start, end)| (*start..=*end).contains(&port))
            }
            CompiledMatcher::Network(network) => target.network == Some(*network),
            CompiledMatcher::InType(types) => target
                .in_type
                .is_some_and(|in_type| types.iter().any(|candidate| *candidate == in_type)),
            CompiledMatcher::Process {
                kind,
                pattern,
                regex,
            } => {
                let value = match kind {
                    ProcessKind::Name => target.process_name.as_deref(),
                    ProcessKind::Path => target.process_path.as_deref(),
                };
                let Some(value) = value else {
                    return Outcome::No;
                };
                match regex {
                    Some(regex) => regex.is_match(value),
                    None => value.eq_ignore_ascii_case(pattern),
                }
            }
            CompiledMatcher::ProcessWildcard { kind, pattern } => {
                let value = match kind {
                    ProcessKind::Name => target.process_name.as_deref(),
                    ProcessKind::Path => target.process_path.as_deref(),
                };
                let Some(value) = value else {
                    return Outcome::No;
                };
                // Pinned `rules/common/process.go` lowercases both sides and
                // uses `component/wildcard`.
                wildcard_match(
                    &pattern.to_ascii_lowercase(),
                    &value.to_ascii_lowercase(),
                )
            }
            CompiledMatcher::RuleSet { name, source } => {
                let Some(slot) = set.providers.rule_provider(name) else {
                    return Outcome::No;
                };
                let snapshot = slot.snapshot();
                if *source {
                    // Mihomo swaps source and destination for `src` rule sets
                    // and disables resolution (helper.ResolveIP = nil); the
                    // rule host is unchanged.
                    let swapped = Target {
                        ip: target.source_ip,
                        port: target.source_port,
                        source_ip: target.ip,
                        source_port: target.port,
                        ..target.clone()
                    };
                    return snapshot.compiled.matches_state(
                        &swapped,
                        state,
                        set,
                        false,
                        false,
                    );
                }
                return snapshot.compiled.matches_state(
                    target,
                    state,
                    set,
                    allow_resolve,
                    false,
                );
            }
            CompiledMatcher::And(rules) => {
                for rule in rules {
                    match rule.matches_state(target, state, set, allow_resolve) {
                        Outcome::Yes => {}
                        Outcome::No => return Outcome::No,
                        Outcome::Resolve => return Outcome::Resolve,
                    }
                }
                return Outcome::Yes;
            }
            CompiledMatcher::Or(rules) => {
                for rule in rules {
                    match rule.matches_state(target, state, set, allow_resolve) {
                        Outcome::Yes => return Outcome::Yes,
                        Outcome::No => {}
                        Outcome::Resolve => return Outcome::Resolve,
                    }
                }
                return Outcome::No;
            }
            CompiledMatcher::Not(rule) => {
                return match rule.matches_state(target, state, set, allow_resolve) {
                    Outcome::Yes => Outcome::No,
                    Outcome::No => Outcome::Yes,
                    Outcome::Resolve => Outcome::Resolve,
                };
            }
            CompiledMatcher::Match => true,
            // SUB-RULE is resolved by `CompiledRule::matches_state`.
            CompiledMatcher::SubRule { .. } => false,
        };
        flag(hit)
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    // Same semantics as the pinned `component/wildcard`: `*` is any run
    // (including empty), `?` exactly one byte, everything else literal.
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut p, mut v) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            mark = v;
            p += 1;
        } else if let Some(star) = star {
            p = star + 1;
            mark += 1;
            v = mark;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// IP-SUFFIX compares the trailing bits of the pattern with the address.
fn ip_suffix_matches(net: &crate::config::ipnet_like::IpNet, ip: IpAddr) -> bool {
    let (pattern, value, width) = match (net.network(), ip) {
        (IpAddr::V4(pattern), IpAddr::V4(value)) => (
            u128::from(u32::from(pattern)),
            u128::from(u32::from(value)),
            32u32,
        ),
        (IpAddr::V6(pattern), IpAddr::V6(value)) => (u128::from(pattern), u128::from(value), 128u32),
        _ => return false,
    };
    let bits = u32::from(net.prefix());
    if bits == 0 {
        return true;
    }
    let mask = if bits >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    };
    (pattern & mask) == (value & mask) && width >= bits
}

fn compile_rule(
    rule: &Rule,
    geodata: &Geodata,
    slots: &BTreeMap<String, Arc<RuleProviderSlot>>,
) -> Result<CompiledRule, ConfigError> {
    Ok(CompiledRule {
        source: rule.clone(),
        matcher: compile_matcher(&rule.matcher, geodata, slots)?,
    })
}

pub(crate) fn compile_matcher(
    matcher: &Matcher,
    geodata: &Geodata,
    slots: &BTreeMap<String, Arc<RuleProviderSlot>>,
) -> Result<CompiledMatcher, ConfigError> {
    Ok(match matcher {
        Matcher::Domain(value) => CompiledMatcher::Domain(value.clone()),
        Matcher::DomainSuffix(value) => CompiledMatcher::DomainSuffix(value.clone()),
        Matcher::DomainKeyword(value) => CompiledMatcher::DomainKeyword(value.clone()),
        Matcher::DomainRegex(pattern) => CompiledMatcher::DomainRegex(
            regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .map_err(|e| {
                    ConfigError::Unsupported(format!("DOMAIN-REGEX {pattern:?}: {e}"))
                })?,
        ),
        Matcher::DomainWildcard(pattern) => CompiledMatcher::DomainWildcard(pattern.clone()),
        Matcher::GeoSite(value) => {
            let (set, negate) = geodata.geosite_matcher(value)?;
            CompiledMatcher::GeoSite { set, negate }
        }
        Matcher::GeoIp { country, source, .. } => CompiledMatcher::GeoIp {
            matcher: geodata.geoip_matcher(country)?,
            source: *source,
        },
        Matcher::IpAsn { asn, source, .. } => {
            let db = geodata.asn_db().ok_or_else(|| {
                ConfigError::Unsupported(format!(
                    "IP-ASN,{asn} needs ASN.mmdb in the geodata directory"
                ))
            })?;
            if !db.supports_asn() {
                return Err(ConfigError::Unsupported(format!(
                    "IP-ASN,{asn}: ASN.mmdb database type '{}' is not an ASN database",
                    db.database_type()
                )));
            }
            CompiledMatcher::IpAsn {
                asn: asn.clone(),
                source: *source,
                db,
            }
        }
        Matcher::IpCidr { net, source, .. } => CompiledMatcher::IpCidr {
            net: *net,
            source: *source,
        },
        Matcher::IpSuffix { net, source, .. } => CompiledMatcher::IpSuffix {
            net: *net,
            source: *source,
        },
        Matcher::Port { kind, ranges } => CompiledMatcher::Port {
            kind: *kind,
            ranges: ranges.clone(),
        },
        Matcher::Network(network) => CompiledMatcher::Network(*network),
        Matcher::InType(types) => CompiledMatcher::InType(types.clone()),
        Matcher::Process {
            kind,
            pattern,
            regex,
        } => CompiledMatcher::Process {
            kind: *kind,
            pattern: pattern.clone(),
            regex: if *regex {
                Some(
                    regex::RegexBuilder::new(pattern)
                        .case_insensitive(true)
                        .build()
                        .map_err(|e| {
                            ConfigError::Unsupported(format!("process regex {pattern:?}: {e}"))
                        })?,
                )
            } else {
                None
            },
        },
        Matcher::ProcessWildcard { kind, pattern } => CompiledMatcher::ProcessWildcard {
            kind: *kind,
            pattern: pattern.clone(),
        },
        Matcher::RuleSet { name, source, .. } => {
            if !slots.contains_key(name) {
                return Err(ConfigError::ConfigFailed(format!(
                    "RULE-SET references undefined rule-provider '{name}'"
                )));
            }
            CompiledMatcher::RuleSet {
                name: name.clone(),
                source: *source,
            }
        }
        Matcher::SubRule { gate, name } => CompiledMatcher::SubRule {
            gate: Box::new(compile_rule(gate, geodata, slots)?),
            name: name.clone(),
        },
        Matcher::And(rules) => CompiledMatcher::And(
            rules
                .iter()
                .map(|rule| compile_rule(rule, geodata, slots))
                .collect::<Result<_, _>>()?,
        ),
        Matcher::Or(rules) => CompiledMatcher::Or(
            rules
                .iter()
                .map(|rule| compile_rule(rule, geodata, slots))
                .collect::<Result<_, _>>()?,
        ),
        Matcher::Not(rule) => {
            CompiledMatcher::Not(Box::new(compile_rule(rule, geodata, slots)?))
        }
        Matcher::Match => CompiledMatcher::Match,
    })
}

/// Compile a rule-provider payload into its matcher. Domain/IP payloads are
/// inserted directly; classical payloads are parsed as target-less rules.
pub(crate) fn compile_provider_payload(
    name: &str,
    behavior: crate::config::RuleBehavior,
    payload: &ProviderPayload,
    geodata: &Geodata,
    slots: &BTreeMap<String, Arc<RuleProviderSlot>>,
) -> Result<CompiledRuleSet, ConfigError> {
    let mut domain = DomainSet::default();
    let mut cidr = Vec::new();
    let mut classical = Vec::new();
    match behavior {
        crate::config::RuleBehavior::Domain => {
            for entry in &payload.entries {
                if entry.contains('/') {
                    // Mihomo skips an invalid domain in a domain provider with
                    // a warning; a slash is never a valid domain label.
                    continue;
                }
                domain.insert(DomainPattern::parse(entry));
            }
            // MRS output uses `+.x`/`.x`/`*.x`; the text form uses plain names.
            // `DomainPattern::parse` handles both.
        }
        crate::config::RuleBehavior::IpCidr => {
            for entry in &payload.entries {
                if let Ok(net) = entry.parse::<crate::config::ipnet_like::IpNet>() {
                    cidr.push(net);
                }
            }
        }
        crate::config::RuleBehavior::Classical => {
            classical.reserve_exact(payload.entries.len());
            let names = slots.keys().cloned().collect::<std::collections::BTreeSet<_>>();
            for entry in &payload.entries {
                let rule = crate::config::parse_rule_without_target_in(entry, &names)
                    .map_err(|error| {
                        // Never drop a pinned rule type silently: name the
                        // provider, the entry and the reason so `--check`
                        // fails instead of the rule becoming a permanent miss.
                        ConfigError::Unsupported(format!(
                            "rule-provider '{name}' entry {entry:?}: {error}"
                        ))
                    })?;
                if matches!(rule.matcher, crate::config::Matcher::Match) {
                    return Err(ConfigError::Unsupported(format!(
                        "rule-provider '{name}' entry {entry:?}: MATCH is not allowed in a classical rule-provider"
                    )));
                }
                classical.push(compile_rule(&rule, geodata, slots)?);
            }
        }
    }
    let count = match behavior {
        crate::config::RuleBehavior::Domain => domain.len(),
        crate::config::RuleBehavior::IpCidr => cidr.len(),
        crate::config::RuleBehavior::Classical => {
            payload.indexed.as_ref().map_or(classical.len(), |index| index.count)
        }
    };
    Ok(CompiledRuleSet {
        behavior,
        domain,
        count,
        cidr,
        classical,
        indexed: payload.indexed.clone(),
    })
}

/// Provider state held behind an `RwLock`; an update swaps the `Arc` and the
/// previous snapshot stays alive until every session holding it drops.
#[derive(Debug)]
pub struct RuleProviderSnapshot {
    pub generation: u64,
    pub payload: ProviderPayload,
    pub compiled: Arc<CompiledRuleSet>,
    /// When this generation was read (pinned `Provider.UpdatedAt`).
    pub updated_at: std::time::SystemTime,
}

/// One rule provider slot addressed by `RULE-SET`.
#[derive(Debug)]
pub struct RuleProviderSlot {
    pub name: String,
    pub config: crate::config::RuleProviderConfig,
    state: RwLock<Arc<RuleProviderSnapshot>>,
}

impl RuleProviderSlot {
    pub(crate) fn new(
        name: String,
        config: crate::config::RuleProviderConfig,
        snapshot: RuleProviderSnapshot,
    ) -> Arc<Self> {
        Arc::new(RuleProviderSlot {
            name,
            config,
            state: RwLock::new(Arc::new(snapshot)),
        })
    }

    pub fn snapshot(&self) -> Arc<RuleProviderSnapshot> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn replace(&self, snapshot: RuleProviderSnapshot) -> Arc<RuleProviderSnapshot> {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let old = std::mem::replace(&mut *state, Arc::new(snapshot));
        old
    }

    /// Swaps in a new snapshot and returns the generation it was stamped with.
    /// The `+1` happens under the write lock so two concurrent updates of the
    /// same provider cannot both derive the same generation.
    pub(crate) fn replace_next(&self, mut snapshot: RuleProviderSnapshot) -> u64 {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let generation = state.generation + 1;
        snapshot.generation = generation;
        *state = Arc::new(snapshot);
        generation
    }
}
