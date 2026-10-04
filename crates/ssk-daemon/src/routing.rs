//! Compile the same validated startup routing configuration for planning and
//! execution. This does not create interfaces, install routes or start VPNs.
use ssk_config::routing::{AdapterTransport, RoutingAction, RoutingConfig};
use ssk_ipc::ProfileSummaryDto;
use ssk_netadmin::adapter::{AdapterDescriptor, AdapterKind};
use ssk_netadmin::policy::MatchCriteria;
use ssk_netadmin::route::AdapterRegistryEntry;
use ssk_netadmin::{HopSpec, PolicyAction, PolicyEngine, PolicyRule, RouteOrchestrator};
use ssk_netcore::AdapterRegistry;

pub struct ConfiguredRouting {
    pub default_profile: String,
    profiles: Vec<(ProfileSummaryDto, PolicyEngine)>,
    pub orchestrator: RouteOrchestrator,
    pub adapters: AdapterRegistry,
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
                (
                    ProfileSummaryDto {
                        id: profile.id.clone(),
                        name: profile.name.clone(),
                    },
                    PolicyEngine::new(rules),
                )
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
            .map(|(summary, _)| summary.clone())
            .collect()
    }

    #[must_use]
    pub fn engine(&self, id: &str) -> Option<&PolicyEngine> {
        self.profiles
            .iter()
            .find(|(profile, _)| profile.id == id)
            .map(|(_, engine)| engine)
    }
}
