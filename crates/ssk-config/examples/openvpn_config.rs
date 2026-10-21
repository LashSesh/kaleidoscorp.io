//! Generate a complete, valid configuration of the current version
//! (`ssk_config::CURRENT_CONFIG_VERSION`). The OpenVPN adapter is reserved:
//! this config deliberately fails activation until broker integration ships.
use ssk_config::routing::{AdapterTransport, RoutingAction, RoutingAdapter, RoutingRule};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = ssk_config::AppConfig::default();
    config.routing.default_profile = "corporate".into();
    config.routing.profiles[0].id = "corporate".into();
    config.routing.profiles[0].name = "Corporate OpenVPN (not yet available)".into();
    config.routing.profiles[0].rules.push(RoutingRule {
        id: "require-vpn".into(),
        priority: 10,
        destination: None,
        domain_suffix: None,
        port: None,
        action: RoutingAction::Adapter {
            adapter_id: "corporate-vpn".into(),
        },
        require_attestation: false,
    });
    config.routing.adapters.push(RoutingAdapter {
        id: "corporate-vpn".into(),
        transport: AdapterTransport::OpenVpn {
            profile_id: "company-managed".into(),
        },
    });
    config.validate()?;
    print!("{}", serde_yaml::to_string(&config)?);
    Ok(())
}
