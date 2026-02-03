use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Action to take when a rule matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Connect directly without proxy.
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
    ProcessName(String),
    /// Match against the destination domain (supports wildcard like *.example.com).
    Domain(String),
    /// Match against the destination IP/CIDR range.
    Cidr(String),
    /// Match against the destination port.
    Port(u16),
    /// Match against a port range (inclusive).
    PortRange(u16, u16),
}

/// A routing rule: if all conditions match, apply the action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub conditions: Vec<Condition>,
    pub action: Action,
    #[serde(default = "default_priority")]
    pub priority: i32,
}

fn default_priority() -> i32 {
    0
}

/// Context for matching rules against a connection.
#[derive(Debug, Clone)]
pub struct MatchContext {
    pub process_name: Option<String>,
    pub dest_domain: Option<String>,
    pub dest_ip: Option<IpAddr>,
    pub dest_port: u16,
}

/// The rule matching engine.
pub struct RuleEngine {
    rules: Vec<Rule>,
}

impl RuleEngine {
    pub fn new(mut rules: Vec<Rule>) -> Self {
        // Sort by priority (higher first).
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        Self { rules }
    }

    /// Evaluate the rules against the given context.
    /// Returns the action of the first matching rule, or `Action::Direct` if none match.
    pub fn evaluate(&self, ctx: &MatchContext) -> Action {
        for rule in &self.rules {
            if self.matches_rule(rule, ctx) {
                tracing::debug!(rule = %rule.name, "rule matched");
                return rule.action.clone();
            }
        }
        Action::Direct
    }

    fn matches_rule(&self, rule: &Rule, ctx: &MatchContext) -> bool {
        rule.conditions.iter().all(|cond| self.matches_condition(cond, ctx))
    }

    fn matches_condition(&self, cond: &Condition, ctx: &MatchContext) -> bool {
        match cond {
            Condition::ProcessName(pattern) => {
                if let Some(name) = &ctx.process_name {
                    glob_match(pattern, name)
                } else {
                    false
                }
            }
            Condition::Domain(pattern) => {
                if let Some(domain) = &ctx.dest_domain {
                    domain_match(pattern, domain)
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
        }
    }
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
    fn test_rule_engine() {
        let rules = vec![
            Rule {
                name: "block-ads".to_string(),
                conditions: vec![Condition::Domain("*.ads.example.com".to_string())],
                action: Action::Block,
                priority: 10,
            },
            Rule {
                name: "proxy-all".to_string(),
                conditions: vec![Condition::Cidr("0.0.0.0/0".to_string())],
                action: Action::Proxy("default".to_string()),
                priority: 0,
            },
        ];

        let engine = RuleEngine::new(rules);

        let ctx = MatchContext {
            process_name: None,
            dest_domain: Some("tracker.ads.example.com".to_string()),
            dest_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            dest_port: 443,
        };
        assert_eq!(engine.evaluate(&ctx), Action::Block);

        let ctx2 = MatchContext {
            process_name: None,
            dest_domain: Some("google.com".to_string()),
            dest_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            dest_port: 80,
        };
        assert_eq!(engine.evaluate(&ctx2), Action::Proxy("default".to_string()));
    }
}
