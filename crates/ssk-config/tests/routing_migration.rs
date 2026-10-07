use serde_json::{json, Value};
use ssk_config::{AppConfig, LoadedConfig, CURRENT_CONFIG_VERSION};

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
    for version in [3, 4, CURRENT_CONFIG_VERSION, 999] {
        let mut value = base.clone();
        value["version"] = version.into();
        // A document is only as old as its sections: 3 has no routing, 3 and 4
        // have no ingress. Anything else would be rejected for that reason alone
        // and hide the one under test.
        if version == 3 {
            value.as_object_mut().unwrap().remove("routing");
        }
        if version < 5 {
            value.as_object_mut().unwrap().remove("ingress");
        }
        value["ledger"]["store_payload"] = true.into();
        assert_rejected_in_both_formats(&value);
        value["ledger"]["store_payload"] = false.into();
        value["core"]["expose_core_address"] = true.into();
        assert_rejected_in_both_formats(&value);
    }
    // An invalid ingress section in a current document is refused, not read by an
    // older decoder that would drop it and load the rest.
    let mut value = base.clone();
    value["ingress"]["listen"]["address"] = "0.0.0.0".into();
    assert_rejected_in_both_formats(&value);
    let mut value = base.clone();
    value.as_object_mut().unwrap().remove("routing");
    assert_rejected_in_both_formats(&value);
    let mut value = base.clone();
    value.as_object_mut().unwrap().remove("ingress");
    assert_rejected_in_both_formats(&value);
    let mut value = base.clone();
    value["version"] = json!(CURRENT_CONFIG_VERSION.to_string());
    assert_rejected_in_both_formats(&value);
    let mut value = base;
    value["routing"]["default_profle"] = "typo".into();
    assert_rejected_in_both_formats(&value);
}

#[test]
fn old_versions_cannot_smuggle_new_routing_fields() {
    let mut value = serde_json::to_value(AppConfig::default()).unwrap();
    for version in [1, 2, 3, 4] {
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
    value.as_object_mut().unwrap().remove("ingress");
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

/// Both formats load the document, agree, and report the same `migrated_from`.
fn load_in_both_formats(value: &Value) -> LoadedConfig {
    let yaml = serde_yaml::to_string(value).unwrap();
    let toml = toml::to_string(value).unwrap();
    let from_yaml = AppConfig::parse_with_migration_yaml(&yaml)
        .unwrap_or_else(|err| panic!("yaml refused {yaml}: {err}"));
    let from_toml = AppConfig::parse_with_migration_toml(&toml)
        .unwrap_or_else(|err| panic!("toml refused {toml}: {err}"));
    assert_eq!(from_yaml, from_toml);
    from_yaml
}

fn ingress_of(loaded: &LoadedConfig) -> Value {
    serde_json::to_value(&loaded.config).unwrap()["ingress"].clone()
}

fn default_ingress() -> Value {
    serde_json::to_value(AppConfig::default()).unwrap()["ingress"].clone()
}

/// A routing section that is legal in every version and that a careless default
/// of the new section would break: a rule, a proxy, a loopback proxy on the
/// default listener port and an IPv6 literal proxy.
fn routing_of_an_old_file() -> Value {
    json!({
        "default_profile": "work",
        "profiles": [{
            "id": "work", "name": "Work",
            "rules": [
                {"id": "via-corp", "priority": 10, "destination": "example.com", "port": 443,
                 "action": {"kind": "adapter", "adapter_id": "corp"}},
                {"id": "via-local", "priority": 20,
                 "action": {"kind": "adapter", "adapter_id": "local"}},
                {"id": "blocked", "priority": 30, "domain_suffix": "blocked.example",
                 "action": {"kind": "deny"}}
            ]
        }],
        "adapters": [
            {"id": "corp", "transport": {"kind": "socks5", "host": "proxy.example.net", "port": 1080}},
            {"id": "local", "transport": {"kind": "socks5", "host": "127.0.0.1", "port": 10800}},
            {"id": "v6", "transport": {"kind": "tls_tunnel", "host": "2001:db8::1", "port": 8443}}
        ]
    })
}

/// The default document as a file of an older version wrote it.
fn old_document(version: u32) -> Value {
    let mut value = serde_json::to_value(AppConfig::default()).unwrap();
    let object = value.as_object_mut().unwrap();
    object.insert("version".into(), version.into());
    if version < 5 {
        object.remove("ingress");
    }
    if version < 4 {
        object.remove("routing");
    }
    value
}

/// A `version`-less file: the policy fields at the top level.
fn v1_document() -> Value {
    json!({
        "name": "legacy", "fail_closed": true,
        "gate_profile": {"order": ["Core", "Mirror"], "fail_closed": true}
    })
}

fn v2_document() -> Value {
    json!({
        "version": 2,
        "policy": {
            "name": "legacy", "fail_closed": true,
            "gate_profile": {"order": ["Core", "Mirror"], "fail_closed": true}
        },
        "runtime": {"strict_mode": true, "metrics_path": "custom/metrics.json"},
        "interop": {"min_protocol": "1.0.0", "capabilities": ["gate-vector-12", "replay-v1"],
                    "max_clock_skew_secs": 300}
    })
}

#[test]
fn v4_migration_preserves_routing_and_adds_a_disabled_ingress() {
    let mut value = old_document(4);
    value["policy"]["name"] = "retained-policy".into();
    value["routing"] = routing_of_an_old_file();
    let loaded = load_in_both_formats(&value);
    assert_eq!(loaded.migrated_from, Some(4));
    assert_eq!(loaded.config.version, CURRENT_CONFIG_VERSION);
    assert_eq!(loaded.config.policy.name, "retained-policy");
    // The operator's routing is theirs, untouched, including the proxy that sits
    // on the default listener port and the IPv6 literal the default family
    // filter would refuse if the new section were checked against it.
    assert_eq!(
        loaded.config.routing,
        serde_json::from_value(routing_of_an_old_file()).unwrap()
    );
    assert_eq!(ingress_of(&loaded), default_ingress());
    assert_eq!(ingress_of(&loaded)["enabled"], json!(false));
}

#[test]
fn every_old_version_loads_with_a_disabled_ingress() {
    for (from, value) in [
        (1, v1_document()),
        (2, v2_document()),
        (3, old_document(3)),
        (4, old_document(4)),
    ] {
        let loaded = load_in_both_formats(&value);
        assert_eq!(loaded.migrated_from, Some(from), "version {from}");
        assert_eq!(
            loaded.config.version, CURRENT_CONFIG_VERSION,
            "version {from}"
        );
        assert_eq!(
            ingress_of(&loaded)["enabled"],
            json!(false),
            "version {from}"
        );
        assert_eq!(ingress_of(&loaded), default_ingress(), "version {from}");
        assert!(loaded.config.validate().is_ok(), "version {from}");
    }
}

#[test]
fn old_versions_cannot_smuggle_newer_sections() {
    let refused = |value: &Value, names: &str| {
        for (format, result) in [
            (
                "yaml",
                AppConfig::parse_with_migration_yaml(&serde_yaml::to_string(value).unwrap()),
            ),
            (
                "toml",
                AppConfig::parse_with_migration_toml(&toml::to_string(value).unwrap()),
            ),
        ] {
            let err = result.expect_err(&format!("{format} accepted {value}"));
            assert!(
                err.to_string().contains(names),
                "{format}: {err} for {value}"
            );
        }
    };
    let current = serde_json::to_value(AppConfig::default()).unwrap();
    // Each step refuses the section its own version introduces, so a file cannot
    // carry a key its declared version does not know.
    let mut value = old_document(3);
    value["routing"] = current["routing"].clone();
    refused(&value, "routing requires config version 4");
    let mut value = old_document(3);
    value["ingress"] = current["ingress"].clone();
    refused(&value, "ingress requires config version 5");
    let mut value = old_document(4);
    value["ingress"] = current["ingress"].clone();
    refused(&value, "ingress requires config version 5");
    // The typed legacy shapes of versions 1 and 2 know neither section.
    for mut value in [v1_document(), v2_document()] {
        let mut with_ingress = value.clone();
        with_ingress["ingress"] = current["ingress"].clone();
        refused(&with_ingress, "unknown field `ingress`");
        value["routing"] = current["routing"].clone();
        refused(&value, "unknown field `routing`");
    }
}

#[test]
fn ingress_rejects_bad_listen_limits_protocols_and_typos_in_both_formats() {
    // Each mutation names what the message must say, so a document refused for
    // some other reason (an unknown section, say) cannot satisfy it.
    let mutations: [(&str, Value, &str); 11] = [
        (
            "listen.address 0.0.0.0",
            json!({"listen": {"address": "0.0.0.0"}}),
            "ingress.listen.address must be an IPv4 loopback address",
        ),
        (
            "listen.address on the LAN",
            json!({"listen": {"address": "192.168.0.10"}}),
            "ingress.listen.address must be an IPv4 loopback address",
        ),
        (
            "listen.address ::1",
            json!({"listen": {"address": "::1"}}),
            "IPv4 address",
        ),
        (
            "listen.address localhost",
            json!({"listen": {"address": "localhost"}}),
            "IPv4 address",
        ),
        (
            "listen.port past u16",
            json!({"listen": {"port": 65536}}),
            "65536",
        ),
        (
            "limits.max_connections 0",
            json!({"limits": {"max_connections": 0}}),
            "ingress.limits.max_connections must be within 1..=4096 (got 0)",
        ),
        (
            "limits.max_connections 4097",
            json!({"limits": {"max_connections": 4097}}),
            "ingress.limits.max_connections must be within 1..=4096 (got 4097)",
        ),
        (
            "protocols http_connect",
            json!({"protocols": ["http_connect"]}),
            "unsupported ingress protocol `http_connect`; this build supports: socks5",
        ),
        (
            "protocols repeated",
            json!({"protocols": ["socks5", "socks5"]}),
            "ingress.protocols lists `socks5` more than once",
        ),
        (
            "typo ingress.enabeld",
            json!({"enabeld": true}),
            "unknown field `enabeld`",
        ),
        (
            "typo ingress.limits.max_connection",
            json!({"limits": {"max_connection": 8}}),
            "unknown field `max_connection`",
        ),
    ];
    for (name, section, needle) in mutations {
        let mut value = serde_json::to_value(AppConfig::default()).unwrap();
        value["ingress"] = section;
        let yaml = serde_yaml::to_string(&value).unwrap();
        let err = AppConfig::parse_with_migration_yaml(&yaml).expect_err(name);
        assert!(err.to_string().contains(needle), "yaml, {name}: {err}");
        let toml = toml::to_string(&value).unwrap();
        let err = AppConfig::parse_with_migration_toml(&toml).expect_err(name);
        assert!(err.to_string().contains(needle), "toml, {name}: {err}");
    }
}

/// `from` written over `into`, key by key, the way a partial section reads over
/// the defaults.
fn overlay(into: &mut Value, from: &Value) {
    match (into, from) {
        (Value::Object(into), Value::Object(from)) => {
            for (key, value) in from {
                overlay(&mut into[key], value);
            }
        }
        (into, from) => *into = from.clone(),
    }
}

#[test]
fn ingress_accepts_the_values_that_tests_and_operators_need() {
    // What a real-`sskd` test writes: the OS picks the port (design 5.7), the
    // hardening is the one the platform can honour, timeouts are short.
    let tests = json!({
        "enabled": true,
        "listen": {"address": "127.0.0.1", "port": 0},
        "hardening": "best_effort",
        "limits": {"handshake_timeout_ms": 100, "connect_timeout_ms": 100, "idle_timeout_ms": 100}
    });
    // What an operator writes: a second loopback address, hashed destinations, the
    // proxy armed on start, dual-stack Direct, the smallest and the largest limits.
    let operator = json!({
        "enabled": true,
        "listen": {"address": "127.0.0.2", "port": 41080},
        "protocols": ["socks5"],
        "hardening": "required",
        "arm_on_start": true,
        "direct_address_families": "any",
        "limits": {"max_connections": 4096, "accept_rate_per_s": 10_000,
                   "handshake_timeout_ms": 60_000, "connect_timeout_ms": 120_000,
                   "idle_timeout_ms": 86_400_000},
        "audit": {"segment_mib": 256, "retain_segments": 4, "destination_logging": "hashed"}
    });
    let smallest = json!({
        "limits": {"max_connections": 1, "accept_rate_per_s": 1},
        "audit": {"segment_mib": 1, "retain_segments": 2}
    });
    for section in [tests, operator, smallest] {
        let mut value = serde_json::to_value(AppConfig::default()).unwrap();
        value["ingress"] = section.clone();
        let loaded = load_in_both_formats(&value);
        assert_eq!(loaded.migrated_from, None);
        // Every key the document states reads back as stated; the rest is the default.
        let read = ingress_of(&loaded);
        let mut expected = default_ingress();
        overlay(&mut expected, &section);
        assert_eq!(read, expected);
    }
}

#[test]
fn adapter_loops_are_checked_against_the_listener_port() {
    // A proxy on the listener's own address would send the proxy's traffic back
    // into itself. The check needs a known port and an enabled listener.
    let mut value = old_document(CURRENT_CONFIG_VERSION);
    value["routing"] = routing_of_an_old_file();
    value["ingress"]["enabled"] = true.into();
    let yaml = serde_yaml::to_string(&value).unwrap();
    let err = AppConfig::parse_with_migration_yaml(&yaml).expect_err("loop accepted");
    assert!(err.to_string().contains("routing adapter `local`"), "{err}");
    assert_rejected_in_both_formats(&value);
    // Port 0 has no port to compare yet (design 5.3: repeated at bind time).
    value["ingress"]["listen"]["port"] = 0.into();
    // The IPv6 literal adapter of the same routing section is the other
    // cross-check; lift it so this test is about the loop alone.
    value["ingress"]["direct_address_families"] = "any".into();
    load_in_both_formats(&value);
    // The same routing in a file older than v5 is legal and loads, disabled.
    let mut old = old_document(4);
    old["routing"] = routing_of_an_old_file();
    let loaded = load_in_both_formats(&old);
    assert_eq!(loaded.migrated_from, Some(4));
    assert_eq!(ingress_of(&loaded)["enabled"], json!(false));
}
