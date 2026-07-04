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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchCriteria {
    /// Glob-style app identifier prefix.  `None` matches any app.
    pub app_prefix: Option<String>,
    /// Destination hostname suffix (e.g. `".example.com"`).  `None` = any.
    pub dest_suffix: Option<String>,
    /// Specific protocol.  `None` = any.
    pub protocol: Option<ProtocolKind>,
    /// Minimum risk level to trigger this rule.  `None` = any.
    pub min_risk: Option<RiskLevel>,
    /// Maximum risk level to trigger this rule.  `None` = any.
    pub max_risk: Option<RiskLevel>,
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
        if let Some(suffix) = &self.dest_suffix {
            if !d.destination_host.ends_with(suffix.as_str()) {
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

    fn make_flow(app: &str, host: &str, risk: RiskLevel) -> FlowRecord {
        FlowRecord::new(
            format!("flow-{app}"),
            0,
            FlowDescriptor::new(app, host, 443, ProtocolKind::Https, risk),
        )
    }

    #[test]
    fn allow_low_risk_flow() {
        let engine = PolicyEngine::new(vec![PolicyRule {
            rule_id: "allow-internal".into(),
            description: "allow internal low-risk traffic".into(),
            priority: 10,
            criteria: MatchCriteria {
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
