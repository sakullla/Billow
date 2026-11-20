//! Immutable rule set shared through `Arc` and released when the last session drops it.

use std::net::IpAddr;
use std::sync::Arc;

use crate::config::{Action, Config, GeoSiteDatabase, Matcher, Rule};

/// Compiled, immutable list of rules plus the geosite databases they reference.
#[derive(Debug, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
    geosite: GeoSiteDatabase,
}

/// Destination information available before dialling (the slice never resolves names).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Lowercased host name or textual IP.
    pub host: String,
    pub ip: Option<IpAddr>,
}

impl Target {
    pub fn new(host: &str, ip: Option<IpAddr>) -> Self {
        Target {
            host: host.to_ascii_lowercase(),
            ip,
        }
    }
}

/// Why a rule fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    pub rule: Rule,
    pub index: usize,
}

impl std::fmt::Display for RuleMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.rule.matcher, self.rule.action.as_str())
    }
}

impl RuleSet {
    pub fn from_config(config: &Config, geosite: GeoSiteDatabase) -> Arc<Self> {
        // No `rules` key in the YAML yields an empty list here, which evaluates to built-in DIRECT.
        Arc::new(RuleSet {
            rules: config.rules.clone(),
            geosite,
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// First matching rule wins; without `MATCH`, built-in DIRECT (and, later, RESOLVE).
    pub fn evaluate(&self, target: &Target) -> RuleMatch {
        for (index, rule) in self.rules.iter().enumerate() {
            let hit = match &rule.matcher {
                Matcher::Domain(v) => &target.host == v,
                Matcher::DomainSuffix(v) => {
                    target.host == *v || target.host.ends_with(&format!(".{v}"))
                }
                Matcher::Geosite(v) => self.geosite.matches(v, &target.host),
                Matcher::IpCidr(net) => target.ip.is_some_and(|ip| net.contains(ip)),
                Matcher::Match => true,
            };
            if hit {
                return RuleMatch {
                    rule: rule.clone(),
                    index,
                };
            }
        }
        RuleMatch {
            rule: Rule {
                matcher: Matcher::Match,
                action: Action::Direct,
                no_resolve: false,
            },
            index: usize::MAX,
        }
    }
}
