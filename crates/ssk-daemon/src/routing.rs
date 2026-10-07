//! Compile the same validated startup routing configuration for planning and
//! execution. This does not create interfaces, install routes or start VPNs.
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use ssk_config::routing::{AdapterTransport, RoutingAction, RoutingConfig, RoutingRule};
use ssk_ipc::{IpcError, ProfileSummaryDto};
use ssk_netadmin::adapter::{AdapterDescriptor, AdapterKind};
use ssk_netadmin::policy::MatchCriteria;
use ssk_netadmin::route::AdapterRegistryEntry;
use ssk_netadmin::{
    FlowRecord, HopSpec, NetAdminError, PolicyAction, PolicyDecision, PolicyEngine, PolicyRule,
    RouteCandidate, RouteOrchestrator,
};
use ssk_netcore::AdapterRegistry;

/// The daemon's startup configuration as the supervisor holds it: the validated
/// file, or the `CONFIG_INVALID` answer that keeps diagnosis reachable. Written
/// once at construction and never again.
pub type ConfigState = Result<ssk_config::LoadedConfig, IpcError>;

/// What `decide` found: the policy's answer and the route planned for it. A
/// denial is an answer too (the decision is a deny or the fail-closed default
/// and the candidate's route is `RouteKind::Denied`); only a failure of the
/// engine or of the planner is an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decided {
    pub decision: PolicyDecision,
    pub candidate: RouteCandidate,
}

/// Which step of `decide` could not produce an answer.
#[derive(Debug, thiserror::Error)]
pub enum DecideError {
    #[error("no routing profile with that id is configured")]
    UnknownProfile,
    // Transparent, so a caller that formats the error (the activation's
    // transition reason) prints exactly what the underlying error prints.
    #[error(transparent)]
    Evaluate(NetAdminError),
    #[error(transparent)]
    Plan(NetAdminError),
}

impl From<DecideError> for IpcError {
    fn from(error: DecideError) -> Self {
        let message = error.to_string();
        match error {
            DecideError::UnknownProfile => IpcError::new("Usage", "UNKNOWN_PROFILE", message),
            DecideError::Evaluate(error) | DecideError::Plan(error) => error.into(),
        }
    }
}

/// What a rule says about the one destination it names, for the guard that
/// decides whether a rule may open a special-use address. Only an exact address
/// AND an exact port on a rule that is not a deny opens anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleBinding {
    NoExactDestination,
    ExactWithoutPort,
    Exact { ip: IpAddr, port: u16 },
}

/// A deny rule that names an address. `port` is the rule's own criterion:
/// `None` denies every port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyIp {
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub rule_id: String,
}

pub struct ConfiguredRouting {
    pub default_profile: String,
    profiles: Vec<CompiledProfile>,
    pub orchestrator: RouteOrchestrator,
    pub adapters: AdapterRegistry,
}

/// One profile, compiled once. The engine keeps its rules private, so what the
/// guards need to know about them is read from the configuration here and is
/// read-only afterwards.
struct CompiledProfile {
    summary: ProfileSummaryDto,
    engine: PolicyEngine,
    /// Only the rules whose binding is not `NoExactDestination`: a rule that is
    /// absent has none.
    bindings: BTreeMap<String, RuleBinding>,
    /// In evaluation order (ascending priority), like the engine's own rules.
    denials: Vec<DenyIp>,
}

/// What `rule_binding` and `exact_ip_denials` answer from, for one profile's
/// rules. Only a destination that parses as an `IpAddr` counts: a name is
/// resolved later and its address is not known here.
fn exact_destinations(rules: &[RoutingRule]) -> (BTreeMap<String, RuleBinding>, Vec<DenyIp>) {
    let mut bindings = BTreeMap::new();
    let mut denials = Vec::new();
    for rule in rules {
        let Some(ip) = rule
            .destination
            .as_deref()
            .and_then(|destination| destination.parse::<IpAddr>().ok())
        else {
            continue;
        };
        let is_deny = matches!(rule.action, RoutingAction::Deny);
        let binding = match rule.port {
            // A deny is never an exemption, whatever it names.
            Some(_) if is_deny => None,
            Some(port) => Some(RuleBinding::Exact { ip, port }),
            None => Some(RuleBinding::ExactWithoutPort),
        };
        if let Some(binding) = binding {
            bindings.insert(rule.id.clone(), binding);
        }
        if is_deny {
            denials.push((
                rule.priority,
                DenyIp {
                    ip,
                    port: rule.port,
                    rule_id: rule.id.clone(),
                },
            ));
        }
    }
    denials.sort_by_key(|(priority, _)| *priority);
    (
        bindings,
        denials.into_iter().map(|(_, denial)| denial).collect(),
    )
}

impl ConfiguredRouting {
    /// Call only after AppConfig validation. No transport is opened here.
    #[must_use]
    pub fn new(config: &RoutingConfig) -> Self {
        let mut orchestrator = RouteOrchestrator::default();
        let mut adapters = AdapterRegistry::new();
        for adapter in &config.adapters {
            let (kind, host, port) = match &adapter.transport {
                AdapterTransport::Socks5 { host, port } => (AdapterKind::Socks5, host, *port),
                AdapterTransport::HttpConnect { host, port } => {
                    (AdapterKind::HttpConnect, host, *port)
                }
                AdapterTransport::TlsTunnel { host, port } => (AdapterKind::TlsTunnel, host, *port),
                AdapterTransport::OpenVpn { profile_id } => {
                    orchestrator.register_openvpn(adapter.id.clone(), profile_id.clone());
                    continue;
                }
            };
            orchestrator.register(AdapterRegistryEntry {
                adapter_id: adapter.id.clone(),
                default_hop: HopSpec::new(&adapter.id, host, port),
            });
            adapters.register(AdapterDescriptor {
                adapter_id: adapter.id.clone(),
                kind,
                address: host.clone(),
                port,
                metadata: vec![],
            });
        }
        let profiles = config
            .profiles
            .iter()
            .map(|profile| {
                let rules = profile
                    .rules
                    .iter()
                    .map(|rule| {
                        let mut action = match &rule.action {
                            RoutingAction::Direct => PolicyAction::Allow,
                            RoutingAction::Deny => PolicyAction::Deny,
                            RoutingAction::Adapter { adapter_id } => PolicyAction::Redirect {
                                adapter_id: adapter_id.clone(),
                            },
                        };
                        if rule.require_attestation {
                            action = PolicyAction::RequireAttestation {
                                then: Box::new(action),
                            };
                        }
                        PolicyRule {
                            rule_id: rule.id.clone(),
                            description: format!(
                                "configured rule {} in profile {}",
                                rule.id, profile.id
                            ),
                            priority: rule.priority,
                            criteria: MatchCriteria {
                                dest_host: rule.destination.clone(),
                                dest_port: rule.port,
                                dest_suffix: rule.domain_suffix.clone(),
                                ..MatchCriteria::default()
                            },
                            action,
                        }
                    })
                    .collect();
                let (bindings, denials) = exact_destinations(&profile.rules);
                CompiledProfile {
                    summary: ProfileSummaryDto {
                        id: profile.id.clone(),
                        name: profile.name.clone(),
                    },
                    engine: PolicyEngine::new(rules),
                    bindings,
                    denials,
                }
            })
            .collect();
        Self {
            default_profile: config.default_profile.clone(),
            profiles,
            orchestrator,
            adapters,
        }
    }

    #[must_use]
    pub fn profiles(&self) -> Vec<ProfileSummaryDto> {
        self.profiles
            .iter()
            .map(|profile| profile.summary.clone())
            .collect()
    }

    fn profile(&self, id: &str) -> Option<&CompiledProfile> {
        self.profiles
            .iter()
            .find(|profile| profile.summary.id == id)
    }

    #[must_use]
    pub fn engine(&self, id: &str) -> Option<&PolicyEngine> {
        self.profile(id).map(|profile| &profile.engine)
    }

    /// The policy-and-plan core of an activation and of `TraceRoute`: evaluate
    /// `flow` under `profile`, then plan a route for the decision. Pure: no
    /// admission, no audit, no socket.
    ///
    /// Both callers use this one function, which is all they share. They pick
    /// their profile differently (an activation takes the one it was asked for,
    /// `TraceRoute` the held session's or the default), they describe the flow
    /// differently (app, protocol and risk), and an activation goes on to admit
    /// the decision and dial where a trace only reports it. That the two agree
    /// on a destination is true only for equal inputs, never by construction.
    ///
    /// # Errors
    /// `UnknownProfile` for an id the configuration does not hold; otherwise
    /// the step that failed, which the profile's rules cannot cause when the
    /// configuration was validated.
    pub fn decide(&self, profile: &str, flow: &FlowRecord) -> Result<Decided, DecideError> {
        let engine = self.engine(profile).ok_or(DecideError::UnknownProfile)?;
        let decision = engine.evaluate(flow).map_err(DecideError::Evaluate)?;
        let candidate = self
            .orchestrator
            .plan(flow, &decision)
            .map_err(DecideError::Plan)?;
        Ok(Decided {
            decision,
            candidate,
        })
    }

    /// What the rule `rule_id` of `profile` says about its destination: `Exact`
    /// only for an address and a port on a rule that is not a deny,
    /// `ExactWithoutPort` for an address without a port, and `NoExactDestination`
    /// for everything else, an unknown profile or rule included.
    #[must_use]
    pub fn rule_binding(&self, profile: &str, rule_id: &str) -> RuleBinding {
        self.profile(profile)
            .and_then(|profile| profile.bindings.get(rule_id))
            .copied()
            .unwrap_or(RuleBinding::NoExactDestination)
    }

    /// Every deny rule of `profile` that names an address, in evaluation order.
    /// An unknown profile has none.
    #[must_use]
    pub fn exact_ip_denials(&self, profile: &str) -> Vec<DenyIp> {
        self.profile(profile)
            .map(|profile| profile.denials.clone())
            .unwrap_or_default()
    }
}

/// Slack above the engine's own bounds before the ingress executor cuts a dial.
const INGRESS_DIAL_MARGIN: Duration = Duration::from_secs(5);

/// The whole-dial deadline for the ingress's own `RouteExecutor` (design 12.9):
/// the executor's resolve timeout `r`, plus its per-TCP connect timeout `c`,
/// plus 5 s.
///
/// The ingress engine bounds an upstream dial itself, by the configured
/// `connect_timeout` (resolution and proxy handshakes included), so the executor
/// must not cut a dial before that bound or before its own steps have had their
/// turns: `r + c` is every step it can be in the middle of, and the margin keeps
/// the executor's deadline strictly behind both. The deadline stays as the safety
/// net for a caller that brings no bound of its own, `probe` for one. Pure, so
/// that its table can be tested without an executor, and saturating, so that no
/// configured value can make it panic.
///
/// The activation executor does not use this: it keeps its 10 s and 30 s, above
/// the supervisor's own 20 s activation deadline.
#[must_use]
pub fn ingress_executor_dial_deadline(
    resolve_timeout: Duration,
    connect_timeout: Duration,
) -> Duration {
    resolve_timeout
        .saturating_add(connect_timeout)
        .saturating_add(INGRESS_DIAL_MARGIN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_config::routing::{RoutingProfile, RoutingRule};
    use ssk_netadmin::{FlowDescriptor, FlowRecord, NetAdminError, ProtocolKind, RiskLevel};

    fn rule(
        id: &str,
        priority: u32,
        destination: Option<&str>,
        port: Option<u16>,
        action: RoutingAction,
    ) -> RoutingRule {
        RoutingRule {
            id: id.into(),
            priority,
            destination: destination.map(str::to_string),
            domain_suffix: None,
            port,
            action,
            require_attestation: false,
        }
    }

    fn exit() -> RoutingAction {
        RoutingAction::Adapter {
            adapter_id: "exit".into(),
        }
    }

    fn profile(id: &str, rules: Vec<RoutingRule>) -> RoutingProfile {
        RoutingProfile {
            id: id.into(),
            name: id.into(),
            rules,
        }
    }

    fn routing_of(profiles: Vec<RoutingProfile>) -> ConfiguredRouting {
        ConfiguredRouting::new(&RoutingConfig {
            default_profile: profiles[0].id.clone(),
            profiles,
            adapters: vec![ssk_config::routing::RoutingAdapter {
                id: "exit".into(),
                transport: AdapterTransport::Socks5 {
                    host: "proxy.example".into(),
                    port: 1080,
                },
            }],
        })
    }

    fn flow(host: &str, port: u16) -> FlowRecord {
        FlowRecord::new(
            "flow-1",
            0,
            FlowDescriptor::new("app", host, port, ProtocolKind::Tcp, RiskLevel::Low),
        )
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address")
    }

    /// Written in a scrambled order on purpose: the list must come back in
    /// evaluation order (ascending priority), not in the order of the file.
    #[test]
    fn exact_ip_denials_lists_only_deny_rules_with_an_ip_destination() {
        let mut attested = rule(
            "deny-attested",
            70,
            Some("203.0.113.50"),
            None,
            RoutingAction::Deny,
        );
        attested.require_attestation = true;
        let mut suffix = rule("deny-suffix", 50, None, None, RoutingAction::Deny);
        suffix.domain_suffix = Some("ads.example".into());
        let routing = routing_of(vec![
            profile(
                "main",
                vec![
                    rule(
                        "deny-v4-port",
                        30,
                        Some("203.0.113.9"),
                        Some(443),
                        RoutingAction::Deny,
                    ),
                    attested,
                    rule(
                        "allow-ip",
                        5,
                        Some("192.0.2.1"),
                        Some(80),
                        RoutingAction::Direct,
                    ),
                    rule(
                        "deny-name",
                        40,
                        Some("blocked.example"),
                        None,
                        RoutingAction::Deny,
                    ),
                    rule(
                        "deny-v4-any",
                        10,
                        Some("198.51.100.7"),
                        None,
                        RoutingAction::Deny,
                    ),
                    suffix,
                    rule("route-ip", 6, Some("192.0.2.2"), None, exit()),
                    rule("deny-port-only", 60, None, Some(25), RoutingAction::Deny),
                    rule(
                        "deny-v6",
                        20,
                        Some("2001:db8::1"),
                        None,
                        RoutingAction::Deny,
                    ),
                ],
            ),
            profile(
                "other",
                vec![rule(
                    "deny-other",
                    1,
                    Some("192.0.2.99"),
                    Some(22),
                    RoutingAction::Deny,
                )],
            ),
        ]);

        let deny = |address: &str, port: Option<u16>, rule_id: &str| DenyIp {
            ip: ip(address),
            port,
            rule_id: rule_id.into(),
        };
        assert_eq!(
            routing.exact_ip_denials("main"),
            vec![
                deny("198.51.100.7", None, "deny-v4-any"),
                deny("2001:db8::1", None, "deny-v6"),
                deny("203.0.113.9", Some(443), "deny-v4-port"),
                deny("203.0.113.50", None, "deny-attested"),
            ]
        );
        assert_eq!(
            routing.exact_ip_denials("other"),
            vec![deny("192.0.2.99", Some(22), "deny-other")],
            "a profile sees only its own rules"
        );
        assert!(routing.exact_ip_denials("absent").is_empty());
    }

    /// Only an exact address AND port on a rule that is not a deny can ever
    /// open a special-use address; every other shape must read as "no".
    #[test]
    fn rule_binding_is_exact_only_for_an_ip_rule_with_a_port_that_is_not_a_deny() {
        let mut suffix = rule("suffix", 6, None, Some(443), exit());
        suffix.domain_suffix = Some("corp.example".into());
        let routing = routing_of(vec![
            profile(
                "main",
                vec![
                    rule(
                        "allow-exact",
                        1,
                        Some("127.0.0.1"),
                        Some(8080),
                        RoutingAction::Direct,
                    ),
                    rule("allow-v6", 2, Some("::1"), Some(53), RoutingAction::Direct),
                    rule("route-exact", 3, Some("10.0.0.5"), Some(22), exit()),
                    rule(
                        "allow-no-port",
                        4,
                        Some("127.0.0.1"),
                        None,
                        RoutingAction::Direct,
                    ),
                    rule(
                        "name",
                        5,
                        Some("localhost.example"),
                        Some(80),
                        RoutingAction::Direct,
                    ),
                    suffix,
                    rule("port-only", 7, None, Some(443), RoutingAction::Direct),
                    rule(
                        "deny-exact",
                        8,
                        Some("127.0.0.1"),
                        Some(8080),
                        RoutingAction::Deny,
                    ),
                    rule(
                        "deny-no-port",
                        9,
                        Some("127.0.0.1"),
                        None,
                        RoutingAction::Deny,
                    ),
                ],
            ),
            profile(
                "other",
                vec![rule(
                    "allow-exact",
                    1,
                    Some("192.0.2.1"),
                    Some(1),
                    RoutingAction::Direct,
                )],
            ),
        ]);

        let table = [
            (
                "allow-exact",
                RuleBinding::Exact {
                    ip: ip("127.0.0.1"),
                    port: 8080,
                },
            ),
            (
                "allow-v6",
                RuleBinding::Exact {
                    ip: ip("::1"),
                    port: 53,
                },
            ),
            (
                "route-exact",
                RuleBinding::Exact {
                    ip: ip("10.0.0.5"),
                    port: 22,
                },
            ),
            ("allow-no-port", RuleBinding::ExactWithoutPort),
            ("name", RuleBinding::NoExactDestination),
            ("suffix", RuleBinding::NoExactDestination),
            ("port-only", RuleBinding::NoExactDestination),
            // A deny never grants an exemption, whatever else it says.
            ("deny-exact", RuleBinding::NoExactDestination),
            ("deny-no-port", RuleBinding::ExactWithoutPort),
            ("no-such-rule", RuleBinding::NoExactDestination),
        ];
        for (rule_id, expected) in table {
            assert_eq!(routing.rule_binding("main", rule_id), expected, "{rule_id}");
        }
        assert_eq!(
            routing.rule_binding("other", "allow-exact"),
            RuleBinding::Exact {
                ip: ip("192.0.2.1"),
                port: 1
            },
            "the same rule id in another profile is another rule"
        );
        assert_eq!(
            routing.rule_binding("absent", "allow-exact"),
            RuleBinding::NoExactDestination
        );
    }

    #[test]
    fn decide_is_evaluate_then_plan() {
        let mut corp = rule("corp", 2, None, None, exit());
        corp.domain_suffix = Some("corp.example".into());
        let routing = routing_of(vec![profile(
            "main",
            vec![
                rule(
                    "loopback",
                    1,
                    Some("127.0.0.1"),
                    None,
                    RoutingAction::Direct,
                ),
                corp,
            ],
        )]);

        for (host, port) in [
            ("127.0.0.1", 80),
            ("api.corp.example", 443),
            ("nothing.example", 1),
        ] {
            let flow = flow(host, port);
            let decision = routing
                .engine("main")
                .expect("profile")
                .evaluate(&flow)
                .expect("evaluates");
            let candidate = routing.orchestrator.plan(&flow, &decision).expect("plans");
            assert_eq!(
                routing.decide("main", &flow).expect("decides"),
                Decided {
                    decision,
                    candidate
                },
                "{host}:{port}"
            );
        }

        let unmatched = routing
            .decide("main", &flow("nothing.example", 1))
            .expect("a denial is an answer, not an error");
        assert!(unmatched.decision.matched_rule.is_none());
        assert!(unmatched.candidate.is_denied());
    }

    #[test]
    fn decide_names_the_step_that_failed() {
        let routing = routing_of(vec![profile(
            "main",
            // Not validated on purpose: validation would refuse the unknown
            // adapter, and this is the only way to make the planner fail.
            vec![rule(
                "broken",
                1,
                Some("127.0.0.1"),
                None,
                RoutingAction::Adapter {
                    adapter_id: "absent".into(),
                },
            )],
        )]);

        let unknown = routing
            .decide("nope", &flow("127.0.0.1", 80))
            .expect_err("unknown profile");
        assert!(matches!(unknown, DecideError::UnknownProfile));
        let ipc = IpcError::from(unknown);
        assert_eq!(
            (ipc.class.as_str(), ipc.code.as_str()),
            ("Usage", "UNKNOWN_PROFILE")
        );

        let plan = routing
            .decide("main", &flow("127.0.0.1", 80))
            .expect_err("planner failure");
        assert!(
            matches!(&plan, DecideError::Plan(NetAdminError::UnknownAdapter(id)) if id == "absent"),
            "{plan:?}"
        );
        assert_eq!(
            plan.to_string(),
            NetAdminError::UnknownAdapter("absent".into()).to_string(),
            "the activation's transition reason embeds this text"
        );
        assert_eq!(IpcError::from(plan).code, "UNKNOWN_ADAPTER");
    }

    #[test]
    fn ingress_executor_deadline_exceeds_the_engine_outer_bound() {
        // (connect_timeout `c`, resolve timeout `r` = min(5 s, c), deadline)
        // for the smallest, the default and the largest configurable `c`.
        let table = [
            (
                Duration::from_millis(100),
                Duration::from_millis(100),
                Duration::from_millis(5200),
            ),
            (
                Duration::from_secs(20),
                Duration::from_secs(5),
                Duration::from_secs(30),
            ),
            (
                Duration::from_secs(120),
                Duration::from_secs(5),
                Duration::from_secs(130),
            ),
        ];
        for (connect, resolve, expected) in table {
            let deadline = ingress_executor_dial_deadline(resolve, connect);
            assert_eq!(deadline, expected, "connect_timeout {connect:?}");
            // The engine's outer bound is `connect_timeout`; the executor's
            // deadline is above it and above both of the executor's own steps
            // by the whole margin, so it is never what ends an ingress dial.
            assert!(deadline > connect, "{deadline:?} <= {connect:?}");
            assert!(
                deadline >= resolve + connect + Duration::from_secs(5),
                "{deadline:?}"
            );
        }
        assert_eq!(
            ingress_executor_dial_deadline(Duration::MAX, Duration::MAX),
            Duration::MAX,
            "a value too large to add saturates and never panics"
        );
    }
}
