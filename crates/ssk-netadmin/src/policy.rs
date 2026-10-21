#![forbid(unsafe_code)]

//! Policy Engine — rule-based allow/deny/redirect/split-route/fail-closed decisions.

use serde::{Deserialize, Serialize};

use crate::error::NetAdminError;
use crate::flow::{FlowRecord, ProtocolKind, RiskLevel};

/// Identifier for a data-plane adapter (matches `AdapterDescriptor::adapter_id`).
pub type AdapterId = String;

/// The action the policy engine selects for a flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    /// Allow the flow to proceed directly (no proxy/relay).
    Allow,
    /// Deny the flow unconditionally.
    Deny,
    /// Redirect through the specified adapter.
    Redirect { adapter_id: AdapterId },
    /// Split-route: use multiple adapters (e.g. first hop + exit node).
    SplitRoute { adapter_ids: Vec<AdapterId> },
    /// Require a signed capability attestation; on success apply the inner action.
    RequireAttestation { then: Box<PolicyAction> },
    /// Fail-closed: deny and emit a forensic record.
    FailClosed,
}

/// Match criteria for a policy rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchCriteria {
    /// Exact destination hostname or literal IP, without resolving DNS.
    #[serde(default)]
    pub dest_host: Option<String>,
    /// Destination port. None matches any port.
    #[serde(default)]
    pub dest_port: Option<u16>,
    /// Glob-style app identifier prefix.  `None` matches any app.
    pub app_prefix: Option<String>,
    /// Destination hostname suffix (e.g. `".example.com"`).  `None` = any.
    /// Applies to DNS names only: an IP literal or numeric IPv4 alias (see
    /// `is_address_form`) is never matched by a suffix, use `dest_host` for
    /// those.
    pub dest_suffix: Option<String>,
    /// Specific protocol.  `None` = any.
    pub protocol: Option<ProtocolKind>,
    /// Minimum risk level to trigger this rule.  `None` = any.
    pub min_risk: Option<RiskLevel>,
    /// Maximum risk level to trigger this rule.  `None` = any.
    pub max_risk: Option<RiskLevel>,
}

/// `true` when `host` spells an address (IP literal or numeric IPv4 alias)
/// rather than a DNS name. `host` is already lowercased and trailing-dot free.
///
/// A suffix compares text, so on a literal it would let the rule `0.1` capture
/// `10.0.0.1`. Neither `:` nor brackets can occur in a DNS name, so a host that
/// carries one is a literal form `IpAddr` may not parse (`fe80::1%eth0`) and no
/// domain rule may claim it. The OS resolver also dials spellings `IpAddr`
/// rejects (`127.1`, `0x7f.0.0.1`, `010.0.0.1`, `2130706433`) as IPv4
/// addresses; every such form ends in a label that starts with a digit, while a
/// real TLD starts with a letter (punycode `xn--` included).
fn is_address_form(host: &str) -> bool {
    let last_label_is_name_like = host
        .rsplit('.')
        .next()
        .is_some_and(|label| label.starts_with(|c: char| c.is_ascii_alphabetic()));
    host.parse::<std::net::IpAddr>().is_ok()
        || host.contains([':', '[', ']'])
        || !last_label_is_name_like
}

impl MatchCriteria {
    /// Returns `true` when this criterion matches the given flow.
    #[must_use]
    pub fn matches(&self, flow: &FlowRecord) -> bool {
        let d = &flow.descriptor;

        if let Some(prefix) = &self.app_prefix {
            if !d.app_id.starts_with(prefix.as_str()) {
                return false;
            }
        }
        if self
            .dest_port
            .is_some_and(|port| port != d.destination_port)
        {
            return false;
        }
        if let Some(host) = &self.dest_host {
            let equal = match (
                host.parse::<std::net::IpAddr>(),
                d.destination_host.parse::<std::net::IpAddr>(),
            ) {
                (Ok(left), Ok(right)) => left == right,
                _ => host
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(d.destination_host.trim_end_matches('.')),
            };
            if !equal {
                return false;
            }
        }
        if let Some(suffix) = &self.dest_suffix {
            let host = d
                .destination_host
                .trim_end_matches('.')
                .to_ascii_lowercase();
            let suffix = suffix.trim_matches('.').to_ascii_lowercase();
            if is_address_form(&host)
                || suffix.is_empty()
                || !(host == suffix || host.ends_with(&format!(".{suffix}")))
            {
                return false;
            }
        }
        if let Some(proto) = self.protocol {
            if d.protocol != proto {
                return false;
            }
        }
        if let Some(min) = self.min_risk {
            if d.risk_level < min {
                return false;
            }
        }
        if let Some(max) = self.max_risk {
            if d.risk_level > max {
                return false;
            }
        }
        true
    }
}

/// A single ordered policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique rule identifier (for audit/explain output).
    pub rule_id: String,
    /// Human-readable description of the rule's intent.
    pub description: String,
    /// Evaluation priority: lower numbers are evaluated first.
    pub priority: u32,
    /// Criteria that must be satisfied to trigger this rule.
    pub criteria: MatchCriteria,
    /// Action to apply when the rule matches.
    pub action: PolicyAction,
}

/// Result of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// The flow for which this decision was made.
    pub flow_id: String,
    /// The matched rule id, or `None` when the implicit fail-closed rule fires.
    pub matched_rule: Option<String>,
    /// The selected action.
    pub action: PolicyAction,
    /// Human-readable rationale.
    pub rationale: String,
}

/// Ordered policy rule set with fail-closed default.
#[derive(Debug, Clone, Default)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    /// Create an engine from an ordered list of rules.
    ///
    /// Rules are sorted by ascending priority before evaluation.
    #[must_use]
    pub fn new(mut rules: Vec<PolicyRule>) -> Self {
        rules.sort_by_key(|r| r.priority);
        Self { rules }
    }

    /// Add a rule to the engine (re-sorts by priority).
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.priority);
    }

    /// Evaluate the rule set for `flow`.
    ///
    /// Returns `Ok(PolicyDecision)` even when the flow is denied; the
    /// `action` field conveys the outcome.  Returns `Err` only on an
    /// internal error.
    ///
    /// Semantics: the first matching rule wins.  When no rule matches, the
    /// implicit **fail-closed** rule fires.
    pub fn evaluate(&self, flow: &FlowRecord) -> Result<PolicyDecision, NetAdminError> {
        for rule in &self.rules {
            if rule.criteria.matches(flow) {
                return Ok(PolicyDecision {
                    flow_id: flow.flow_id.clone(),
                    matched_rule: Some(rule.rule_id.clone()),
                    action: rule.action.clone(),
                    rationale: rule.description.clone(),
                });
            }
        }

        // Implicit fail-closed: no rule matched.
        Ok(PolicyDecision {
            flow_id: flow.flow_id.clone(),
            matched_rule: None,
            action: PolicyAction::FailClosed,
            rationale: "no policy rule matched; fail-closed default applied".into(),
        })
    }

    /// Returns the number of rules in the engine.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{FlowDescriptor, FlowRecord};

    #[test]
    fn configured_destinations_match_domain_boundaries_ports_and_ip_values() {
        let mut criteria = MatchCriteria {
            dest_suffix: Some("corp.example".into()),
            dest_port: Some(443),
            ..MatchCriteria::default()
        };
        for host in ["corp.example", "API.CORP.EXAMPLE."] {
            assert!(criteria.matches(&make_flow("app", host, RiskLevel::Low)));
        }
        for host in ["evilcorp.example", "corp.example.attacker.test"] {
            assert!(!criteria.matches(&make_flow("app", host, RiskLevel::Low)));
        }
        let mut wrong_port = make_flow("app", "corp.example", RiskLevel::Low);
        wrong_port.descriptor.destination_port = 80;
        assert!(!criteria.matches(&wrong_port));
        criteria.dest_suffix = None;
        criteria.dest_host = Some("::1".into());
        assert!(criteria.matches(&make_flow("app", "0:0:0:0:0:0:0:1", RiskLevel::Low)));
        assert!(!criteria.matches(&make_flow("app", "::2", RiskLevel::Low)));
    }

    fn make_flow(app: &str, host: &str, risk: RiskLevel) -> FlowRecord {
        FlowRecord::new(
            format!("flow-{app}"),
            0,
            FlowDescriptor::new(app, host, 443, ProtocolKind::Https, risk),
        )
    }

    fn suffix_criteria(suffix: &str) -> MatchCriteria {
        MatchCriteria {
            dest_suffix: Some(suffix.into()),
            ..MatchCriteria::default()
        }
    }

    #[test]
    fn suffix_rule_never_matches_ip_literal() {
        // (suffix, host): every pair matched before the fix, either because the
        // suffix is a string tail of the literal or because the two are equal.
        let literals = [
            // The reported case: "10.0.0.1".ends_with(".0.1").
            ("0.1", "10.0.0.1"),
            ("0.0.1", "10.0.0.1"),
            ("1", "10.0.0.1"),
            ("0.1", "10.0.0.1."),
            ("0.1", "::ffff:10.0.0.1"),
            ("0.1]", "[::ffff:10.0.0.1]"),
            // A "suffix" that is the whole literal is still not a domain.
            ("10.0.0.1", "10.0.0.1"),
            ("::1", "::1"),
            ("[::1]", "[::1]"),
            ("fe80::1%eth0", "fe80::1%eth0"),
        ];
        let captured: Vec<_> = literals
            .into_iter()
            .filter(|(suffix, host)| {
                suffix_criteria(suffix).matches(&make_flow("app", host, RiskLevel::Low))
            })
            .collect();
        assert!(
            captured.is_empty(),
            "suffix rules must not match IP literals, but matched: {captured:?}"
        );

        // The same literal is still reachable through `dest_host`, which is the
        // field that is defined for literals.
        let exact = MatchCriteria {
            dest_host: Some("10.0.0.1".into()),
            ..MatchCriteria::default()
        };
        assert!(exact.matches(&make_flow("app", "10.0.0.1", RiskLevel::Low)));
    }

    #[test]
    fn suffix_rule_never_matches_numeric_ipv4_alias() {
        // (suffix, host): spellings Rust's IpAddr parser rejects but getaddrinfo
        // dials as IPv4 addresses (inet_aton forms: short, hex, octal, single
        // integer). The OS would connect to the address while a text suffix
        // saw a name.
        let aliases = [
            ("0.1", "127.0.1"),
            ("0.1", "0x7f.0.0.1"),
            ("0.1", "0X7F.0.0.1"),
            ("0.1", "010.0.0.1"),
            ("0.1", "0177.0.0.1"),
            ("0.1", "127.0.1."),
            ("1", "127.1"),
            ("1", "0x7f.1"),
            ("2130706433", "2130706433"),
            ("0x7f000001", "0x7f000001"),
        ];
        let captured: Vec<_> = aliases
            .into_iter()
            .filter(|(suffix, host)| {
                suffix_criteria(suffix).matches(&make_flow("app", host, RiskLevel::Low))
            })
            .collect();
        assert!(
            captured.is_empty(),
            "suffix rules must not match numeric IPv4 aliases, but matched: {captured:?}"
        );
    }

    #[test]
    fn suffix_rule_still_matches_dns_names_on_label_boundaries() {
        // (suffix, host): real names, including ones that embed digits or look
        // like a dotted quad without being one.
        let matching = [
            ("corp.example", "corp.example"),
            ("corp.example", "api.corp.example"),
            ("corp.example", "a.b.corp.example"),
            ("corp.example", "API.CORP.EXAMPLE."),
            (".corp.example", "api.corp.example"),
            (".corp.example", "corp.example"),
            ("corp.example.", "api.corp.example"),
            ("CORP.Example", "api.corp.example"),
            ("corp.example", "10.corp.example"),
            ("0.1.example", "10.0.1.example"),
            ("nip.io", "10.0.0.1.nip.io"),
            ("example", "xn--bcher-kva.example"),
            ("internal", "api.internal"),
            // Numeric leading labels and a punycode TLD are still names: only
            // the final label decides, and it starts with a letter.
            ("example", "127.0.1.example"),
            ("1password.com", "my.1password.com"),
            ("xn--p1ai", "xn--80ak6aa92e.xn--p1ai"),
        ];
        for (suffix, host) in matching {
            assert!(
                suffix_criteria(suffix).matches(&make_flow("app", host, RiskLevel::Low)),
                "suffix {suffix:?} must still match name {host:?}"
            );
        }

        // Label-boundary behaviour is unchanged.
        let not_matching = [
            ("corp.example", "evilcorp.example"),
            ("corp.example", "corp.example.attacker.test"),
            ("corp.example", "xcorp.example"),
            ("corp.example", "example"),
            ("0.1.example", "20.0.1.example.test"),
            ("", "corp.example"),
            (".", "corp.example"),
        ];
        for (suffix, host) in not_matching {
            assert!(
                !suffix_criteria(suffix).matches(&make_flow("app", host, RiskLevel::Low)),
                "suffix {suffix:?} must not match name {host:?}"
            );
        }
    }

    #[test]
    fn allow_low_risk_flow() {
        let engine = PolicyEngine::new(vec![PolicyRule {
            rule_id: "allow-internal".into(),
            description: "allow internal low-risk traffic".into(),
            priority: 10,
            criteria: MatchCriteria {
                dest_host: None,
                dest_port: None,
                app_prefix: None,
                dest_suffix: Some(".internal".into()),
                protocol: None,
                min_risk: None,
                max_risk: Some(RiskLevel::Low),
            },
            action: PolicyAction::Allow,
        }]);

        let flow = make_flow("app-a", "api.internal", RiskLevel::Low);
        let decision = engine.evaluate(&flow).expect("eval must succeed");
        assert_eq!(decision.action, PolicyAction::Allow);
    }

    #[test]
    fn fail_closed_when_no_rule_matches() {
        let engine = PolicyEngine::new(vec![]);
        let flow = make_flow("unknown-app", "external.example.com", RiskLevel::High);
        let decision = engine.evaluate(&flow).expect("eval must succeed");
        assert_eq!(decision.action, PolicyAction::FailClosed);
        assert!(decision.matched_rule.is_none());
    }

    #[test]
    fn redirect_through_adapter() {
        let engine = PolicyEngine::new(vec![PolicyRule {
            rule_id: "redirect-high".into(),
            description: "route high-risk flows through proxy".into(),
            priority: 5,
            criteria: MatchCriteria {
                dest_host: None,
                dest_port: None,
                app_prefix: None,
                dest_suffix: None,
                protocol: None,
                min_risk: Some(RiskLevel::High),
                max_risk: None,
            },
            action: PolicyAction::Redirect {
                adapter_id: "socks5-exit".into(),
            },
        }]);

        let flow = make_flow("app-b", "risky.example.com", RiskLevel::Critical);
        let decision = engine.evaluate(&flow).expect("eval must succeed");
        assert_eq!(
            decision.action,
            PolicyAction::Redirect {
                adapter_id: "socks5-exit".into()
            }
        );
    }

    #[test]
    fn deny_rule_wins_over_lower_priority_allow() {
        let engine = PolicyEngine::new(vec![
            PolicyRule {
                rule_id: "deny-blocked".into(),
                description: "deny blocked destinations".into(),
                priority: 1,
                criteria: MatchCriteria {
                    dest_host: None,
                    dest_port: None,
                    app_prefix: None,
                    dest_suffix: Some(".blocked".into()),
                    protocol: None,
                    min_risk: None,
                    max_risk: None,
                },
                action: PolicyAction::Deny,
            },
            PolicyRule {
                rule_id: "allow-all".into(),
                description: "allow everything else".into(),
                priority: 100,
                criteria: MatchCriteria {
                    dest_host: None,
                    dest_port: None,
                    app_prefix: None,
                    dest_suffix: None,
                    protocol: None,
                    min_risk: None,
                    max_risk: None,
                },
                action: PolicyAction::Allow,
            },
        ]);

        let flow = make_flow("app-c", "bad.blocked", RiskLevel::Medium);
        let decision = engine.evaluate(&flow).expect("eval must succeed");
        assert_eq!(decision.action, PolicyAction::Deny);
    }
}
