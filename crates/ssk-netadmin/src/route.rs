#![forbid(unsafe_code)]

//! Route Orchestrator — computes multi-hop, proxy, direct, fallback, and
//! recovery paths for a flow given a policy decision.

use serde::{Deserialize, Serialize};

use crate::error::NetAdminError;
use crate::flow::FlowRecord;
use crate::policy::{PolicyAction, PolicyDecision};

/// Specification of a single hop in a route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopSpec {
    /// Adapter identifier used for this hop.
    pub adapter_id: String,
    /// Relay/proxy address (hostname or IP).
    pub address: String,
    /// Relay/proxy port.
    pub port: u16,
    /// Optional opaque authentication credential for this hop.
    pub auth: Option<String>,
}

impl HopSpec {
    pub fn new(adapter_id: impl Into<String>, address: impl Into<String>, port: u16) -> Self {
        Self {
            adapter_id: adapter_id.into(),
            address: address.into(),
            port,
            auth: None,
        }
    }

    #[must_use]
    pub fn with_auth(mut self, auth: impl Into<String>) -> Self {
        self.auth = Some(auth.into());
        self
    }
}

/// The computed routing plan for a flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteKind {
    /// Connect directly to the destination without any proxy or relay.
    Direct,
    /// Route through a single proxy/relay hop.
    SingleHop(HopSpec),
    /// Route through an ordered chain of hops (multi-hop).
    MultiHop(Vec<HopSpec>),
    /// Try `primary`; on failure automatically fall back to `fallback`.
    Fallback {
        primary: Box<RouteKind>,
        fallback: Box<RouteKind>,
    },
    /// The flow is denied — no route is available.
    Denied { reason: String },
}

/// A fully-resolved routing candidate ready for dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteCandidate {
    /// Flow the candidate was computed for.
    pub flow_id: String,
    /// The computed route.
    pub route: RouteKind,
    /// Whether this route requires attestation before dispatch.
    pub requires_attestation: bool,
}

impl RouteCandidate {
    /// Returns `true` when the flow is denied.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self.route, RouteKind::Denied { .. })
    }
}

/// Adapter registry entry used by the orchestrator to resolve adapter ids to
/// their hop specifications.
#[derive(Debug, Clone)]
pub struct AdapterRegistryEntry {
    pub adapter_id: String,
    pub default_hop: HopSpec,
}

/// Plans routes for flows based on policy decisions.
///
/// The orchestrator resolves adapter identifiers from the policy action against
/// its internal registry.  Unknown adapters cause fail-closed (Denied) routes.
#[derive(Debug, Default)]
pub struct RouteOrchestrator {
    registry: Vec<AdapterRegistryEntry>,
}

impl RouteOrchestrator {
    #[must_use]
    pub fn new(registry: Vec<AdapterRegistryEntry>) -> Self {
        Self { registry }
    }

    /// Register an adapter with its default hop specification.
    pub fn register(&mut self, entry: AdapterRegistryEntry) {
        self.registry.push(entry);
    }

    fn resolve_adapter(&self, adapter_id: &str) -> Option<&AdapterRegistryEntry> {
        self.registry.iter().find(|e| e.adapter_id == adapter_id)
    }

    /// Compute the `RouteCandidate` for `flow` given the `decision` from the
    /// policy engine.
    pub fn plan(
        &self,
        flow: &FlowRecord,
        decision: &PolicyDecision,
    ) -> Result<RouteCandidate, NetAdminError> {
        let (route, requires_attestation) = self.resolve_action(&flow.flow_id, &decision.action)?;
        Ok(RouteCandidate {
            flow_id: flow.flow_id.clone(),
            route,
            requires_attestation,
        })
    }

    #[allow(clippy::only_used_in_recursion)]
    fn resolve_action(
        &self,
        flow_id: &str,
        action: &PolicyAction,
    ) -> Result<(RouteKind, bool), NetAdminError> {
        match action {
            PolicyAction::Allow => Ok((RouteKind::Direct, false)),
            PolicyAction::Deny => Ok((
                RouteKind::Denied {
                    reason: "policy: deny".into(),
                },
                false,
            )),
            PolicyAction::FailClosed => Ok((
                RouteKind::Denied {
                    reason: "policy: fail-closed".into(),
                },
                false,
            )),
            PolicyAction::Redirect { adapter_id } => {
                let entry = self
                    .resolve_adapter(adapter_id)
                    .ok_or_else(|| NetAdminError::UnknownAdapter(adapter_id.clone()))?;
                Ok((RouteKind::SingleHop(entry.default_hop.clone()), false))
            }
            PolicyAction::SplitRoute { adapter_ids } => {
                let mut hops = Vec::with_capacity(adapter_ids.len());
                for aid in adapter_ids {
                    let entry = self
                        .resolve_adapter(aid)
                        .ok_or_else(|| NetAdminError::UnknownAdapter(aid.clone()))?;
                    hops.push(entry.default_hop.clone());
                }
                if hops.is_empty() {
                    return Ok((
                        RouteKind::Denied {
                            reason: "split-route: no adapters".into(),
                        },
                        false,
                    ));
                }
                let route = if hops.len() == 1 {
                    RouteKind::SingleHop(hops.remove(0))
                } else {
                    RouteKind::MultiHop(hops)
                };
                Ok((route, false))
            }
            PolicyAction::RequireAttestation { then } => {
                let (inner_route, _) = self.resolve_action(flow_id, then)?;
                Ok((inner_route, true))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{FlowDescriptor, FlowRecord, ProtocolKind, RiskLevel};
    use crate::policy::{MatchCriteria, PolicyAction, PolicyDecision, PolicyEngine, PolicyRule};

    fn make_flow(id: &str) -> FlowRecord {
        FlowRecord::new(
            id,
            0,
            FlowDescriptor::new(
                "app",
                "example.com",
                443,
                ProtocolKind::Https,
                RiskLevel::Low,
            ),
        )
    }

    fn orchestrator_with_socks() -> RouteOrchestrator {
        RouteOrchestrator::new(vec![AdapterRegistryEntry {
            adapter_id: "socks5-exit".into(),
            default_hop: HopSpec::new("socks5-exit", "proxy.example.com", 1080),
        }])
    }

    #[test]
    fn allow_produces_direct_route() {
        let orc = RouteOrchestrator::default();
        let flow = make_flow("f1");
        let decision = PolicyDecision {
            flow_id: "f1".into(),
            matched_rule: Some("r1".into()),
            action: PolicyAction::Allow,
            rationale: "allow".into(),
        };
        let candidate = orc.plan(&flow, &decision).expect("plan must succeed");
        assert_eq!(candidate.route, RouteKind::Direct);
        assert!(!candidate.requires_attestation);
    }

    #[test]
    fn redirect_resolves_to_single_hop() {
        let orc = orchestrator_with_socks();
        let flow = make_flow("f2");
        let decision = PolicyDecision {
            flow_id: "f2".into(),
            matched_rule: Some("r2".into()),
            action: PolicyAction::Redirect {
                adapter_id: "socks5-exit".into(),
            },
            rationale: "proxy high-risk".into(),
        };
        let candidate = orc.plan(&flow, &decision).expect("plan must succeed");
        assert!(matches!(candidate.route, RouteKind::SingleHop(_)));
    }

    #[test]
    fn unknown_adapter_yields_error() {
        let orc = RouteOrchestrator::default();
        let flow = make_flow("f3");
        let decision = PolicyDecision {
            flow_id: "f3".into(),
            matched_rule: None,
            action: PolicyAction::Redirect {
                adapter_id: "ghost-adapter".into(),
            },
            rationale: "test".into(),
        };
        assert!(orc.plan(&flow, &decision).is_err());
    }

    #[test]
    fn require_attestation_sets_flag() {
        let orc = RouteOrchestrator::default();
        let flow = make_flow("f4");
        let decision = PolicyDecision {
            flow_id: "f4".into(),
            matched_rule: Some("r4".into()),
            action: PolicyAction::RequireAttestation {
                then: Box::new(PolicyAction::Allow),
            },
            rationale: "attested allow".into(),
        };
        let candidate = orc.plan(&flow, &decision).expect("plan must succeed");
        assert!(candidate.requires_attestation);
        assert_eq!(candidate.route, RouteKind::Direct);
    }

    #[test]
    fn fail_closed_denied() {
        let orc = RouteOrchestrator::default();
        let flow = make_flow("f5");
        let decision = PolicyDecision {
            flow_id: "f5".into(),
            matched_rule: None,
            action: PolicyAction::FailClosed,
            rationale: "no match".into(),
        };
        let candidate = orc.plan(&flow, &decision).expect("plan must succeed");
        assert!(candidate.is_denied());
    }

    #[test]
    fn policy_and_route_end_to_end() {
        let engine = PolicyEngine::new(vec![PolicyRule {
            rule_id: "proxy-critical".into(),
            description: "proxy critical risk via socks5".into(),
            priority: 1,
            criteria: MatchCriteria {
                app_prefix: None,
                dest_suffix: None,
                protocol: None,
                min_risk: Some(RiskLevel::Critical),
                max_risk: None,
            },
            action: PolicyAction::Redirect {
                adapter_id: "socks5-exit".into(),
            },
        }]);
        let orc = orchestrator_with_socks();
        let flow = FlowRecord::new(
            "f-e2e",
            1,
            FlowDescriptor::new(
                "app-critical",
                "risky.host",
                443,
                ProtocolKind::Https,
                RiskLevel::Critical,
            ),
        );
        let decision = engine.evaluate(&flow).expect("policy eval");
        let candidate = orc.plan(&flow, &decision).expect("route plan");
        assert!(matches!(candidate.route, RouteKind::SingleHop(_)));
    }
}
