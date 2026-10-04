use serde_json::{json, Value};
use ssk_config::{AppConfig, CURRENT_CONFIG_VERSION};

fn assert_rejected_in_both_formats(value: &Value) {
    let yaml = serde_yaml::to_string(value).unwrap();
    assert!(
        AppConfig::parse_with_migration_yaml(&yaml).is_err(),
        "accepted {yaml}"
    );
    let toml = toml::to_string(value).unwrap();
    assert!(
        AppConfig::parse_with_migration_toml(&toml).is_err(),
        "accepted {toml}"
    );
}

#[test]
fn invalid_modern_documents_cannot_fall_back_to_legacy_defaults() {
    let base = serde_json::to_value(AppConfig::default()).unwrap();
    for version in [3, CURRENT_CONFIG_VERSION, 999] {
        let mut value = base.clone();
        value["version"] = version.into();
        if version == 3 {
            value.as_object_mut().unwrap().remove("routing");
        }
        value["ledger"]["store_payload"] = true.into();
        assert_rejected_in_both_formats(&value);
        value["ledger"]["store_payload"] = false.into();
        value["core"]["expose_core_address"] = true.into();
        assert_rejected_in_both_formats(&value);
    }
    let mut value = base.clone();
    value.as_object_mut().unwrap().remove("routing");
    assert_rejected_in_both_formats(&value);
    let mut value = base.clone();
    value["version"] = json!("4");
    assert_rejected_in_both_formats(&value);
    let mut value = base;
    value["routing"]["default_profle"] = "typo".into();
    assert_rejected_in_both_formats(&value);
}

#[test]
fn old_versions_cannot_smuggle_new_routing_fields() {
    let mut value = serde_json::to_value(AppConfig::default()).unwrap();
    for version in [1, 2, 3] {
        value["version"] = version.into();
        assert_rejected_in_both_formats(&value);
    }
}

#[test]
fn v3_migration_preserves_sections_and_adds_deny_all_routing() {
    let mut value = serde_json::to_value(AppConfig::default()).unwrap();
    value["version"] = 3.into();
    value["policy"]["name"] = "retained-policy".into();
    value.as_object_mut().unwrap().remove("routing");
    let yaml = serde_yaml::to_string(&value).unwrap();
    let toml = toml::to_string(&value).unwrap();
    let from_yaml = AppConfig::parse_with_migration_yaml(&yaml).unwrap();
    let from_toml = AppConfig::parse_with_migration_toml(&toml).unwrap();
    assert_eq!(from_yaml, from_toml);
    assert_eq!(from_yaml.migrated_from, Some(3));
    assert_eq!(from_yaml.config.policy.name, "retained-policy");
    assert!(from_yaml.config.routing.profiles[0].rules.is_empty());
    assert!(from_yaml.config.routing.adapters.is_empty());
}

#[test]
fn routing_rejects_unknown_adapters_duplicate_priorities_paths_and_typos() {
    let mut value = serde_json::to_value(AppConfig::default()).unwrap();
    value["routing"]["profiles"][0]["rules"] = json!([
        {"id":"vpn-only", "priority":10, "action":{"kind":"adapter", "adapter_id":"vpn"}}
    ]);
    assert_rejected_in_both_formats(&value);
    value["routing"]["adapters"] = json!([
        {"id":"vpn", "transport":{"kind":"open_vpn", "profile_id":"enterprise"}}
    ]);
    let yaml = serde_yaml::to_string(&value).unwrap();
    assert!(AppConfig::parse_with_migration_yaml(&yaml).is_ok());
    let mut bad = value.clone();
    bad["routing"]["adapters"][0]["transport"]["profile_id"] = "../../untrusted.ovpn".into();
    assert_rejected_in_both_formats(&bad);
    let mut bad = value.clone();
    bad["routing"]["profiles"][0]["rules"][0]["require_attestaton"] = true.into();
    assert_rejected_in_both_formats(&bad);
    let mut bad = value.clone();
    let mut rule = bad["routing"]["profiles"][0]["rules"][0].clone();
    rule["id"] = "other-rule".into();
    bad["routing"]["profiles"][0]["rules"]
        .as_array_mut()
        .unwrap()
        .push(rule);
    assert_rejected_in_both_formats(&bad);
    let mut bad = value;
    bad["routing"]["profiles"][0]["rules"][0]["port"] = 0.into();
    assert_rejected_in_both_formats(&bad);
}
