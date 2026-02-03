use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::dns::DnsMode;

/// Action to take when a rule matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Connect directly without proxy.
    #[default]
    Direct,
    /// Route through the named proxy or proxy chain.
    Proxy(String),
    /// Block the connection entirely.
    Block,
}

/// A single condition that can match against a connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    /// Match against the process name (supports glob patterns).
    /// Multiple names can be separated by `;` (e.g. "chrome.exe;firefox.exe").
    ProcessName(String),
    /// Match against the full process path (supports glob patterns).
    ProcessPath(String),
    /// Match against the destination domain (supports wildcard like *.example.com).
    /// Multiple domains can be separated by `;`.
    Domain(String),
    /// Match against the destination IP/CIDR range.
    Cidr(String),
    /// Match against the destination port.
    Port(u16),
    /// Match against a port range (inclusive).
    PortRange(u16, u16),
    /// Match against the process owner user/group.
    User(String),
    /// Match loopback addresses (127.0.0.0/8, ::1).
    Loopback,
}

/// A routing rule: if all conditions match, apply the action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub conditions: Vec<Condition>,
    pub action: Action,
    #[serde(default = "default_priority")]
    pub priority: i32,
    /// Whether this rule is currently enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional per-rule DNS resolution mode override.
    #[serde(default)]
    pub dns_mode: Option<DnsMode>,
}

fn default_priority() -> i32 {
    0
}

fn default_true() -> bool {
    true
}

/// Context for matching rules against a connection.
#[derive(Debug, Clone)]
pub struct MatchContext {
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub process_user: Option<String>,
    pub dest_domain: Option<String>,
    pub dest_ip: Option<IpAddr>,
    pub dest_port: u16,
}

/// The rule matching engine.
pub struct RuleEngine {
    rules: Vec<Rule>,
    default_action: Action,
}

impl RuleEngine {
    pub fn new(mut rules: Vec<Rule>) -> Self {
        // Sort by priority (higher first).
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        Self {
            rules,
            default_action: Action::Direct,
        }
    }

    /// Create a rule engine with a custom default action (Proxifier-style "default rule").
    pub fn with_default_action(mut rules: Vec<Rule>, default_action: Action) -> Self {
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        Self {
            rules,
            default_action,
        }
    }

    /// Evaluate the rules against the given context.
    /// Returns the action and optional DNS mode override of the first matching rule,
    /// or the default action if none match.
    pub fn evaluate(&self, ctx: &MatchContext) -> Action {
        self.evaluate_with_dns(ctx).0
    }

    /// Evaluate and also return the per-rule DNS mode override if any.
    pub fn evaluate_with_dns(&self, ctx: &MatchContext) -> (Action, Option<DnsMode>) {
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if self.matches_rule(rule, ctx) {
                tracing::debug!(rule = %rule.name, "rule matched");
                return (rule.action.clone(), rule.dns_mode.clone());
            }
        }
        (self.default_action.clone(), None)
    }

    /// Get a reference to the rule list for UI display.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    fn matches_rule(&self, rule: &Rule, ctx: &MatchContext) -> bool {
        rule.conditions
            .iter()
            .all(|cond| self.matches_condition(cond, ctx))
    }

    fn matches_condition(&self, cond: &Condition, ctx: &MatchContext) -> bool {
        match cond {
            Condition::ProcessName(pattern) => {
                if let Some(name) = &ctx.process_name {
                    multi_glob_match(pattern, name)
                } else {
                    false
                }
            }
            Condition::ProcessPath(pattern) => {
                if let Some(path) = &ctx.process_path {
                    multi_glob_match(pattern, path)
                } else {
                    false
                }
            }
            Condition::Domain(pattern) => {
                if let Some(domain) = &ctx.dest_domain {
                    multi_domain_match(pattern, domain)
                } else {
                    false
                }
            }
            Condition::Cidr(cidr_str) => {
                if let Some(ip) = &ctx.dest_ip {
                    if let Ok(net) = cidr_str.parse::<IpNet>() {
                        net.contains(ip)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            Condition::Port(port) => ctx.dest_port == *port,
            Condition::PortRange(start, end) => {
                ctx.dest_port >= *start && ctx.dest_port <= *end
            }
            Condition::User(user_pattern) => {
                if let Some(user) = &ctx.process_user {
                    glob_match(user_pattern, user)
                } else {
                    false
                }
            }
            Condition::Loopback => {
                if let Some(ip) = &ctx.dest_ip {
                    ip.is_loopback()
                } else if let Some(domain) = &ctx.dest_domain {
                    domain == "localhost"
                } else {
                    false
                }
            }
        }
    }
}

/// Match against semicolon-separated glob patterns (e.g. "chrome.exe;firefox.exe").
fn multi_glob_match(pattern: &str, text: &str) -> bool {
    pattern
        .split(';')
        .map(|p| p.trim())
        .any(|p| glob_match(p, text))
}

/// Match against semicolon-separated domain patterns.
fn multi_domain_match(pattern: &str, domain: &str) -> bool {
    pattern
        .split(';')
        .map(|p| p.trim())
        .any(|p| domain_match(p, domain))
}

/// Simple glob matching supporting `*` and `?`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let text = text.to_lowercase();
    glob_match_impl(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_impl(pattern: &[u8], text: &[u8]) -> bool {
    let mut px = 0;
    let mut tx = 0;
    let mut star_px = usize::MAX;
    let mut star_tx = 0;

    while tx < text.len() {
        if px < pattern.len() && (pattern[px] == b'?' || pattern[px] == text[tx]) {
            px += 1;
            tx += 1;
        } else if px < pattern.len() && pattern[px] == b'*' {
            star_px = px;
            star_tx = tx;
            px += 1;
        } else if star_px != usize::MAX {
            px = star_px + 1;
            star_tx += 1;
            tx = star_tx;
        } else {
            return false;
        }
    }

    while px < pattern.len() && pattern[px] == b'*' {
        px += 1;
    }

    px == pattern.len()
}

/// Domain wildcard matching: `*.example.com` matches `foo.example.com`.
fn domain_match(pattern: &str, domain: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let domain = domain.to_lowercase();

    if pattern.starts_with("*.") {
        let suffix = &pattern[1..]; // ".example.com"
        domain.ends_with(suffix) || domain == pattern[2..]
    } else {
        pattern == domain
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_domain_match() {
        assert!(domain_match("*.example.com", "foo.example.com"));
        assert!(domain_match("*.example.com", "example.com"));
        assert!(domain_match("*.example.com", "bar.baz.example.com"));
        assert!(!domain_match("*.example.com", "notexample.com"));
        assert!(domain_match("example.com", "example.com"));
    }

    #[test]
    fn test_glob_match() {
        assert!(glob_match("chrome*", "chrome.exe"));
        assert!(glob_match("*firefox*", "org.mozilla.firefox"));
        assert!(!glob_match("chrome*", "firefox.exe"));
    }

    #[test]
    fn test_multi_glob_match() {
        assert!(multi_glob_match("chrome.exe;firefox.exe", "chrome.exe"));
        assert!(multi_glob_match("chrome.exe;firefox.exe", "firefox.exe"));
        assert!(!multi_glob_match("chrome.exe;firefox.exe", "curl"));
        assert!(multi_glob_match("chrome.exe; firefox*", "firefox.app"));
    }

    #[test]
    fn test_multi_domain_match() {
        assert!(multi_domain_match(
            "*.google.com;*.github.com",
            "api.github.com"
        ));
        assert!(!multi_domain_match(
            "*.google.com;*.github.com",
            "example.com"
        ));
    }

    #[test]
    fn test_disabled_rule() {
        let rules = vec![
            Rule {
                name: "disabled-block".to_string(),
                conditions: vec![Condition::Domain("*.example.com".to_string())],
                action: Action::Block,
                priority: 10,
                enabled: false,
                dns_mode: None,
            },
            Rule {
                name: "proxy-all".to_string(),
                conditions: vec![Condition::Cidr("0.0.0.0/0".to_string())],
                action: Action::Proxy("default".to_string()),
                priority: 0,
                enabled: true,
                dns_mode: None,
            },
        ];

        let engine = RuleEngine::new(rules);
        let ctx = MatchContext {
            process_name: None,
            process_path: None,
            process_user: None,
            dest_domain: Some("foo.example.com".to_string()),
            dest_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            dest_port: 443,
        };
        // Disabled rule is skipped, so it should match proxy-all
        assert_eq!(engine.evaluate(&ctx), Action::Proxy("default".to_string()));
    }

    #[test]
    fn test_loopback_condition() {
        let rules = vec![Rule {
            name: "skip-loopback".to_string(),
            conditions: vec![Condition::Loopback],
            action: Action::Direct,
            priority: 100,
            enabled: true,
            dns_mode: None,
        }];

        let engine = RuleEngine::with_default_action(rules, Action::Proxy("socks".to_string()));

        let ctx_loopback = MatchContext {
            process_name: None,
            process_path: None,
            process_user: None,
            dest_domain: None,
            dest_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            dest_port: 8080,
        };
        assert_eq!(engine.evaluate(&ctx_loopback), Action::Direct);

        let ctx_remote = MatchContext {
            process_name: None,
            process_path: None,
            process_user: None,
            dest_domain: None,
            dest_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            dest_port: 443,
        };
        assert_eq!(
            engine.evaluate(&ctx_remote),
            Action::Proxy("socks".to_string())
        );
    }

    #[test]
    fn test_rule_engine() {
        let rules = vec![
            Rule {
                name: "block-ads".to_string(),
                conditions: vec![Condition::Domain("*.ads.example.com".to_string())],
                action: Action::Block,
                priority: 10,
                enabled: true,
                dns_mode: None,
            },
            Rule {
                name: "proxy-all".to_string(),
                conditions: vec![Condition::Cidr("0.0.0.0/0".to_string())],
                action: Action::Proxy("default".to_string()),
                priority: 0,
                enabled: true,
                dns_mode: None,
            },
        ];

        let engine = RuleEngine::new(rules);

        let ctx = MatchContext {
            process_name: None,
            process_path: None,
            process_user: None,
            dest_domain: Some("tracker.ads.example.com".to_string()),
            dest_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            dest_port: 443,
        };
        assert_eq!(engine.evaluate(&ctx), Action::Block);

        let ctx2 = MatchContext {
            process_name: None,
            process_path: None,
            process_user: None,
            dest_domain: Some("google.com".to_string()),
            dest_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            dest_port: 80,
        };
        assert_eq!(engine.evaluate(&ctx2), Action::Proxy("default".to_string()));
    }

    #[test]
    fn test_per_rule_dns_mode() {
        let rules = vec![Rule {
            name: "remote-dns-for-proxy".to_string(),
            conditions: vec![Condition::Domain("*.sensitive.com".to_string())],
            action: Action::Proxy("socks".to_string()),
            priority: 10,
            enabled: true,
            dns_mode: Some(DnsMode::RemoteResolution),
        }];

        let engine = RuleEngine::new(rules);
        let ctx = MatchContext {
            process_name: None,
            process_path: None,
            process_user: None,
            dest_domain: Some("api.sensitive.com".to_string()),
            dest_ip: None,
            dest_port: 443,
        };
        let (action, dns) = engine.evaluate_with_dns(&ctx);
        assert_eq!(action, Action::Proxy("socks".to_string()));
        assert!(matches!(dns, Some(DnsMode::RemoteResolution)));
    }
}
