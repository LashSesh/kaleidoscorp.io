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
    /// Broker-managed OpenVPN profile, unavailable until service integration.
    OpenVpn {
        adapter_id: String,
        profile_id: String,
    },
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
    vpn_profiles: std::collections::BTreeMap<String, String>,
}

impl RouteOrchestrator {
    #[must_use]
    pub fn new(registry: Vec<AdapterRegistryEntry>) -> Self {
        Self {
            registry,
            vpn_profiles: Default::default(),
        }
    }

    /// Register an adapter with its default hop specification.
    pub fn register(&mut self, entry: AdapterRegistryEntry) {
        self.registry.push(entry);
    }

    pub fn register_openvpn(&mut self, adapter_id: String, profile_id: String) {
        self.vpn_profiles.insert(adapter_id, profile_id);
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
                if let Some(profile_id) = self.vpn_profiles.get(adapter_id) {
                    return Ok((
                        RouteKind::OpenVpn {
                            adapter_id: adapter_id.clone(),
                            profile_id: profile_id.clone(),
                        },
                        false,
                    ));
                }
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
    use crate::adapter::{
        AdapterKind, DataPlaneAdapter, DirectAdapter, DnsOverrideAdapter, HttpConnectAdapter,
        Socks5Adapter, TlsTunnelAdapter,
    };
    use crate::flow::{FlowDescriptor, FlowRecord, ProtocolKind, RiskLevel};
    use crate::policy::{MatchCriteria, PolicyAction, PolicyDecision, PolicyEngine, PolicyRule};
    use std::collections::BTreeSet;

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
                dest_host: None,
                dest_port: None,
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

    const ALL_ADAPTER_KINDS: [AdapterKind; 6] = [
        AdapterKind::Direct,
        AdapterKind::Socks5,
        AdapterKind::HttpConnect,
        AdapterKind::TlsTunnel,
        AdapterKind::DnsOverride,
        AdapterKind::OpenVpn,
    ];

    /// The registry entry a deployment would derive from each adapter kind. The
    /// match is exhaustive so a new `AdapterKind` cannot go unswept.
    fn registry_entry_for(kind: AdapterKind) -> Option<AdapterRegistryEntry> {
        let id = format!("{kind:?}").to_ascii_lowercase();
        let descriptor = match kind {
            AdapterKind::Direct => DirectAdapter::new(id).describe(),
            AdapterKind::Socks5 => Socks5Adapter::new(id, "socks.example.com", 1080).describe(),
            AdapterKind::HttpConnect => {
                HttpConnectAdapter::new(id, "http.example.com", 3128).describe()
            }
            AdapterKind::TlsTunnel => {
                TlsTunnelAdapter::new(id, "tls.example.com", 8443, "tls.example.com").describe()
            }
            AdapterKind::DnsOverride => DnsOverrideAdapter::new(id, "1.1.1.1", 853).describe(),
            // Has no hop: it is reachable only through `register_openvpn`.
            AdapterKind::OpenVpn => return None,
        };
        let default_hop = HopSpec::new(
            descriptor.adapter_id.clone(),
            descriptor.address,
            descriptor.port,
        );
        Some(AdapterRegistryEntry {
            adapter_id: descriptor.adapter_id,
            default_hop,
        })
    }

    fn action_variant(action: &PolicyAction) -> &'static str {
        match action {
            PolicyAction::Allow => "Allow",
            PolicyAction::Deny => "Deny",
            PolicyAction::Redirect { .. } => "Redirect",
            PolicyAction::SplitRoute { .. } => "SplitRoute",
            PolicyAction::RequireAttestation { .. } => "RequireAttestation",
            PolicyAction::FailClosed => "FailClosed",
        }
    }

    fn route_variant(route: &RouteKind) -> &'static str {
        match route {
            RouteKind::Direct => "Direct",
            RouteKind::OpenVpn { .. } => "OpenVpn",
            RouteKind::SingleHop(_) => "SingleHop",
            RouteKind::MultiHop(_) => "MultiHop",
            RouteKind::Fallback { .. } => "Fallback",
            RouteKind::Denied { .. } => "Denied",
        }
    }

    #[test]
    fn planner_never_emits_fallback() {
        let entries: Vec<_> = ALL_ADAPTER_KINDS
            .into_iter()
            .filter_map(registry_entry_for)
            .collect();
        let mut adapter_ids: Vec<String> = entries.iter().map(|e| e.adapter_id.clone()).collect();
        let hop_ids = adapter_ids.clone();
        adapter_ids.extend(["vpn".to_string(), "ghost".to_string()]);

        // Every way a caller can populate the registry.
        let mut incremental = RouteOrchestrator::default();
        for entry in entries.iter().cloned() {
            incremental.register(entry);
        }
        // The same id registered twice, with a different hop.
        incremental.register(AdapterRegistryEntry {
            adapter_id: hop_ids[0].clone(),
            default_hop: HopSpec::new(hop_ids[0].clone(), "other.example.com", 1),
        });
        let mut with_openvpn = RouteOrchestrator::new(entries.clone());
        with_openvpn.register_openvpn("vpn".into(), "profile-1".into());
        // A profile bound to an id that also has a hop entry.
        with_openvpn.register_openvpn(hop_ids[1].clone(), "profile-2".into());
        let orchestrators = [
            ("empty", RouteOrchestrator::default()),
            ("registry", RouteOrchestrator::new(entries)),
            ("incremental", incremental),
            ("openvpn", with_openvpn),
        ];

        // Every rule outcome: known, unknown, repeated and OpenVPN ids, bare and
        // wrapped in one and two attestation layers.
        let mut base = vec![
            PolicyAction::Allow,
            PolicyAction::Deny,
            PolicyAction::FailClosed,
            PolicyAction::SplitRoute {
                adapter_ids: vec![],
            },
            PolicyAction::SplitRoute {
                adapter_ids: hop_ids.clone(),
            },
            PolicyAction::SplitRoute {
                adapter_ids: adapter_ids.clone(),
            },
        ];
        for id in &adapter_ids {
            base.push(PolicyAction::Redirect {
                adapter_id: id.clone(),
            });
            base.push(PolicyAction::SplitRoute {
                adapter_ids: vec![id.clone()],
            });
            base.push(PolicyAction::SplitRoute {
                adapter_ids: vec![id.clone(), id.clone()],
            });
        }
        let mut actions = base.clone();
        for action in base {
            let once = PolicyAction::RequireAttestation {
                then: Box::new(action),
            };
            actions.push(PolicyAction::RequireAttestation {
                then: Box::new(once.clone()),
            });
            actions.push(once);
        }

        let flow = make_flow("f-sweep");
        let mut action_variants = BTreeSet::new();
        let mut route_variants = BTreeSet::new();
        let mut errors = 0_usize;
        let mut check = |label: &str, decision: &PolicyDecision, orc: &RouteOrchestrator| {
            match orc.plan(&flow, decision) {
                Ok(candidate) => {
                    assert!(
                        !matches!(candidate.route, RouteKind::Fallback { .. }),
                        "{label}: {:?} planned a Fallback route",
                        decision.action
                    );
                    route_variants.insert(route_variant(&candidate.route));
                }
                Err(_) => errors += 1,
            }
            if let Ok(token) = orc.admit(&flow, decision) {
                assert!(
                    !matches!(token.route(), RouteKind::Fallback { .. }),
                    "{label}: {:?} admitted a Fallback route",
                    decision.action
                );
            }
        };
        for (label, orc) in &orchestrators {
            // No rule matches: the engine's own fail-closed decision.
            let implicit = PolicyEngine::default()
                .evaluate(&flow)
                .expect("policy eval");
            assert_eq!(implicit.matched_rule, None);
            check(label, &implicit, orc);

            for action in &actions {
                action_variants.insert(action_variant(action));
                let engine = PolicyEngine::new(vec![PolicyRule {
                    rule_id: "sweep".into(),
                    description: "sweep".into(),
                    priority: 1,
                    criteria: MatchCriteria::default(),
                    action: action.clone(),
                }]);
                let decision = engine.evaluate(&flow).expect("policy eval");
                assert_eq!(&decision.action, action);
                check(label, &decision, orc);
            }
        }

        // The sweep must have exercised every outcome, or "no Fallback" is vacuous.
        assert_eq!(
            action_variants,
            BTreeSet::from([
                "Allow",
                "Deny",
                "FailClosed",
                "Redirect",
                "RequireAttestation",
                "SplitRoute"
            ])
        );
        assert_eq!(
            route_variants,
            BTreeSet::from(["Denied", "Direct", "MultiHop", "OpenVpn", "SingleHop"])
        );
        assert!(errors > 0, "unknown adapters must be planning errors");
    }
}
