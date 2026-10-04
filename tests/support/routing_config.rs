// Explicit test-only permission. Production defaults remain deny-all.
#[allow(dead_code)]
fn loopback_config() -> ssk_config::LoadedConfig {
    let mut config = ssk_config::AppConfig::default();
    config.routing.profiles[0]
        .rules
        .push(ssk_config::routing::RoutingRule {
            id: "test-loopback".into(),
            priority: 10,
            destination: Some("127.0.0.1".into()),
            domain_suffix: None,
            port: None,
            action: ssk_config::routing::RoutingAction::Direct,
            require_attestation: false,
        });
    ssk_config::LoadedConfig {
        config,
        migrated_from: None,
    }
}

#[allow(dead_code)]
fn write_loopback_config(directory: &std::path::Path) -> std::path::PathBuf {
    let path = directory.join("loopback-test.yaml");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&loopback_config().config).unwrap(),
    )
    .unwrap();
    path
}
