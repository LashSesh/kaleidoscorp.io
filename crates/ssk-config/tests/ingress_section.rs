//! The `ingress` section of config v5 (design 5.1, 5.3, 5.8, 23.1).
//!
//! The section opens a listener, so every field has a fail-closed default and a
//! typo must never keep one while the operator believes otherwise. These tests
//! work on documents (JSON values written as YAML and as TOML, read through the
//! path the daemon and `ssk config lint` use) so that they state what an
//! operator can write, not how the types are spelled. The numbers are written
//! out here on purpose: they are the contract, and a table that read them back
//! from the code under test could never notice a change.

use serde_json::{json, Value};
use ssk_config::{AppConfig, ConfigError, LoadedConfig};

fn document() -> Value {
    serde_json::to_value(AppConfig::default()).expect("the default config serialises")
}

/// The default document with `ingress` replaced.
fn with_ingress(section: Value) -> Value {
    let mut value = document();
    value["ingress"] = section;
    value
}

fn load(value: &Value) -> [Result<LoadedConfig, ConfigError>; 2] {
    [
        AppConfig::parse_with_migration_yaml(&serde_yaml::to_string(value).expect("yaml")),
        AppConfig::parse_with_migration_toml(&toml::to_string(value).expect("toml")),
    ]
}

/// Both formats load the document and agree on what it means.
fn accepted(value: &Value) -> LoadedConfig {
    let [yaml, toml] = load(value);
    let yaml = yaml.unwrap_or_else(|err| panic!("yaml refused {value}: {err}"));
    let toml = toml.unwrap_or_else(|err| panic!("toml refused {value}: {err}"));
    assert_eq!(yaml, toml, "the formats disagree about {value}");
    yaml
}

/// Both formats refuse the document.
fn refused(value: &Value) {
    for (format, result) in ["yaml", "toml"].into_iter().zip(load(value)) {
        assert!(result.is_err(), "{format} accepted {value}");
    }
}

/// Both formats refuse the document, and both messages contain `needle`.
fn rejected(value: &Value, needle: &str) {
    for (format, result) in ["yaml", "toml"].into_iter().zip(load(value)) {
        match result {
            Ok(_) => panic!("{format} accepted {value}"),
            Err(err) => assert!(
                err.to_string().contains(needle),
                "{format}: `{err}` does not name `{needle}` for {value}"
            ),
        }
    }
}

fn ingress_of(loaded: &LoadedConfig) -> Value {
    serde_json::to_value(&loaded.config).expect("serialises")["ingress"].clone()
}

fn default_ingress() -> Value {
    json!({
        "enabled": false,
        "listen": {"address": "127.0.0.1", "port": 10800},
        "protocols": ["socks5"],
        "hardening": "required",
        "arm_on_start": false,
        "direct_address_families": "ipv4_only",
        "limits": {
            "max_connections": 256,
            "accept_rate_per_s": 50,
            "handshake_timeout_ms": 10_000,
            "connect_timeout_ms": 20_000,
            "idle_timeout_ms": 3_600_000
        },
        "audit": {
            "segment_mib": 32,
            "retain_segments": 8,
            "destination_logging": "plain"
        }
    })
}

#[test]
fn ingress_default_is_disabled_loopback_socks5_required() {
    // The owner's defaults (pending confirmation before the first release tag):
    // 127.0.0.1:10800, IPv4-only Direct, ledger retention by size only, plain
    // destination logging, SOCKS5 first.
    assert_eq!(document()["ingress"], default_ingress());
    assert!(AppConfig::default().validate().is_ok());
    // `ingress: {}` is a valid section and means exactly the default: every
    // field inside it has a default, only the section itself is required.
    assert_eq!(
        ingress_of(&accepted(&with_ingress(json!({})))),
        default_ingress()
    );
}

#[test]
fn the_ingress_section_is_required_in_a_current_document() {
    let mut value = document();
    value.as_object_mut().expect("object").remove("ingress");
    rejected(&value, "missing field `ingress`");
}

#[test]
fn non_loopback_listen_addresses_are_rejected() {
    for address in [
        "0.0.0.0",
        "192.168.1.10",
        "10.0.0.1",
        "8.8.8.8",
        "128.0.0.1",
        "126.255.255.255",
        // Not an IPv4 address in the grammar `Ipv4Addr` reads, which is what keeps
        // a host name, IPv6, brackets, a zone, a port or a numeric alias out.
        "::1",
        "[::1]",
        "localhost",
        "127.0.0.1:10800",
        "127.1",
        "0x7f.0.0.1",
        "127.000.000.001",
        "2130706433",
        " 127.0.0.1",
        "",
    ] {
        refused(&with_ingress(json!({"listen": {"address": address}})));
    }
    // The ones that spell an address but not a loopback one say so.
    for address in ["0.0.0.0", "192.168.1.10", "128.0.0.1"] {
        rejected(
            &with_ingress(json!({"listen": {"address": address}})),
            "ingress.listen.address must be an IPv4 loopback address (127.0.0.0/8)",
        );
    }
    for address in ["127.0.0.1", "127.0.0.2", "127.255.255.254"] {
        let loaded = accepted(&with_ingress(json!({"listen": {"address": address}})));
        assert_eq!(ingress_of(&loaded)["listen"]["address"], json!(address));
    }
}

#[test]
fn every_numeric_bound_is_enforced_at_both_edges() {
    // (section, key, floor, ceiling, a value of the sibling that keeps the
    // ledger product of 5.3 within its limit while this key sits at its ceiling)
    let table = [
        ("limits", "max_connections", 1, 4096, None),
        ("limits", "accept_rate_per_s", 1, 10_000, None),
        ("limits", "handshake_timeout_ms", 100, 60_000, None),
        ("limits", "connect_timeout_ms", 100, 120_000, None),
        ("limits", "idle_timeout_ms", 100, 86_400_000, None),
        ("audit", "segment_mib", 1, 256, Some(("retain_segments", 2))),
        ("audit", "retain_segments", 2, 64, Some(("segment_mib", 1))),
    ];
    for (section, key, floor, ceiling, sibling) in table {
        let at = |number: Value| {
            let mut body = json!({ section: { key: number } });
            if let Some((name, value)) = sibling {
                body[section][name] = json!(value);
            }
            with_ingress(body)
        };
        let path = format!("ingress.{section}.{key}");
        for edge in [floor, ceiling] {
            let loaded = accepted(&at(json!(edge)));
            assert_eq!(ingress_of(&loaded)[section][key], json!(edge), "{path}");
        }
        // Zero is never "unlimited" and the message says so.
        let zero =
            format!("{path} must be within {floor}..={ceiling} (got 0); 0 never means unlimited");
        rejected(&at(json!(0)), &zero);
        if floor > 1 {
            let below = format!(
                "{path} must be within {floor}..={ceiling} (got {})",
                floor - 1
            );
            rejected(&at(json!(floor - 1)), &below);
        }
        let above = format!(
            "{path} must be within {floor}..={ceiling} (got {})",
            ceiling + 1
        );
        rejected(&at(json!(ceiling + 1)), &above);
        // The largest `u32` is out of range, not a wrap to a small number; one past
        // the type, a negative, a fraction and the wrong kind are document errors.
        let largest = format!("{path} must be within {floor}..={ceiling} (got 4294967295)");
        rejected(&at(json!(u32::MAX)), &largest);
        for bad in [
            json!(u64::from(u32::MAX) + 1),
            json!(-1),
            json!(1.5),
            json!("1"),
            json!(null),
        ] {
            let value = at(bad.clone());
            // TOML cannot hold null; the YAML read is enough for that one.
            if bad.is_null() {
                let yaml = serde_yaml::to_string(&value).expect("yaml");
                assert!(
                    AppConfig::parse_with_migration_yaml(&yaml).is_err(),
                    "{path}: null"
                );
            } else {
                refused(&value);
            }
        }
    }
}

#[test]
fn unknown_or_duplicate_protocols_are_rejected_with_a_build_specific_message() {
    let unsupported =
        |name: &str| format!("unsupported ingress protocol `{name}`; this build supports: socks5");
    for name in ["http_connect", "SOCKS5", "socks4", "", "socks5 "] {
        rejected(
            &with_ingress(json!({"protocols": [name]})),
            &unsupported(name),
        );
    }
    // One unsupported name refuses the whole list: a list that mentions it means
    // an operator expects it to work.
    rejected(
        &with_ingress(json!({"protocols": ["socks5", "http_connect"]})),
        &unsupported("http_connect"),
    );
    rejected(
        &with_ingress(json!({"protocols": []})),
        "ingress.protocols must name at least one protocol; this build supports: socks5",
    );
    rejected(
        &with_ingress(json!({"protocols": ["socks5", "socks5"]})),
        "ingress.protocols lists `socks5` more than once",
    );
    // A list, not a bare string or a number.
    for bad in [
        json!("socks5"),
        json!([1]),
        json!([["socks5"]]),
        json!({"socks5": true}),
    ] {
        refused(&with_ingress(json!({"protocols": bad})));
    }
    let loaded = accepted(&with_ingress(json!({"protocols": ["socks5"]})));
    assert_eq!(ingress_of(&loaded)["protocols"], json!(["socks5"]));
}

#[test]
fn typos_are_rejected_at_every_level_of_the_section() {
    // The four structs of the section, by the keys an operator is most likely to
    // misspell. Every field has a default, so without `deny_unknown_fields` each
    // of these would load and silently keep the default.
    for (path, typo) in [
        (&[][..], "enabeld"),
        (&["listen"][..], "adress"),
        (&["limits"][..], "max_connection"),
        (&["audit"][..], "segment_mb"),
    ] {
        let mut section = json!({});
        let mut at = &mut section;
        for step in path {
            at[*step] = json!({});
            at = &mut at[*step];
        }
        at[typo] = json!(1);
        rejected(&with_ingress(section), &format!("unknown field `{typo}`"));
    }
    // And generically: every key the section writes, misspelled, is refused.
    fn misspell(value: &Value, trail: &mut Vec<String>, found: &mut Vec<Vec<String>>) {
        if let Some(object) = value.as_object() {
            for (key, child) in object {
                trail.push(key.clone());
                found.push(trail.clone());
                misspell(child, trail, found);
                trail.pop();
            }
        }
    }
    let mut keys = Vec::new();
    misspell(&default_ingress(), &mut Vec::new(), &mut keys);
    assert_eq!(keys.len(), 18, "the section's keys changed: {keys:?}");
    for trail in keys {
        let mut value = document();
        let mut parent = &mut value["ingress"];
        for step in &trail[..trail.len() - 1] {
            parent = &mut parent[step.as_str()];
        }
        let object = parent.as_object_mut().expect("an object");
        let key = trail.last().expect("a key");
        let child = object.remove(key).expect("the key exists");
        object.insert(format!("{key}x"), child);
        rejected(&value, &format!("unknown field `{key}x`"));
    }
}

fn with_adapter(kind: &str, host: &str, port: u16, enabled: bool, listen_port: u16) -> Value {
    let mut value = with_ingress(json!({"enabled": enabled, "listen": {"port": listen_port}}));
    value["routing"]["adapters"] = json!([
        {"id": "local", "transport": {"kind": kind, "host": host, "port": port}}
    ]);
    value
}

#[test]
fn self_loop_adapters_are_rejected_only_when_the_port_is_known() {
    // The listener's own port, on every spelling of the loopback and every kind
    // of network adapter: the proxy would dial itself.
    for kind in ["socks5", "http_connect", "tls_tunnel"] {
        for host in [
            "127.0.0.1",
            "127.0.0.2",
            "localhost",
            "LOCALHOST",
            "localhost.",
            "0.0.0.0",
        ] {
            rejected(
                &with_adapter(kind, host, 10800, true, 10800),
                "routing adapter `local` points at the ingress listener",
            );
        }
    }
    // Port 0 asks the OS for a port, so there is nothing to compare: the check
    // is repeated at bind time (design 5.3, 6.9.4), not here.
    accepted(&with_adapter("socks5", "127.0.0.1", 10800, true, 0));
    accepted(&with_adapter("socks5", "127.0.0.1", 1, true, 0));
    // A different port, and a host that is not the loopback, are not a loop.
    accepted(&with_adapter("socks5", "127.0.0.1", 1080, true, 10800));
    accepted(&with_adapter("socks5", "example.com", 10800, true, 10800));
    accepted(&with_adapter("socks5", "192.0.2.1", 10800, true, 10800));
    // A configured port that is not the default is compared as well.
    rejected(
        &with_adapter("socks5", "127.0.0.1", 41080, true, 41080),
        "points at the ingress listener",
    );
    accepted(&with_adapter("socks5", "127.0.0.1", 10800, true, 41080));
}

#[test]
fn a_disabled_ingress_is_not_cross_checked_against_routing() {
    // Every file written before v5 migrates to a disabled ingress on the default
    // port, and an adapter on 127.0.0.1:10800 or an IPv6 literal is a legal v4
    // file. Refusing it after an upgrade, for a listener that never opens, would
    // turn the migration promise into a lie; the checks run when the flag does.
    accepted(&with_adapter("socks5", "127.0.0.1", 10800, false, 10800));
    accepted(&with_adapter(
        "tls_tunnel",
        "2001:db8::1",
        8443,
        false,
        10800,
    ));
    rejected(
        &with_adapter("socks5", "127.0.0.1", 10800, true, 10800),
        "points at the ingress listener",
    );
    rejected(
        &with_adapter("tls_tunnel", "2001:db8::1", 8443, true, 10800),
        "ingress.direct_address_families is ipv4_only",
    );
}

#[test]
fn segment_times_retain_over_1024_is_rejected() {
    let sizes = |segment: u64, retain: u64| {
        with_ingress(json!({"audit": {"segment_mib": segment, "retain_segments": retain}}))
    };
    for (segment, retain) in [(32, 32), (64, 16), (128, 8), (256, 4), (1, 64), (16, 64)] {
        accepted(&sizes(segment, retain));
    }
    for (segment, retain) in [
        (32, 33),
        (33, 32),
        (256, 5),
        (65, 16),
        (128, 9),
        (17, 64),
        (256, 64),
    ] {
        rejected(
            &sizes(segment, retain),
            &format!(
                "ingress.audit.segment_mib x ingress.audit.retain_segments must not exceed \
                 1024 MiB (got {segment} x {retain} = {})",
                segment * retain
            ),
        );
    }
}

#[test]
fn direct_address_families_default_is_ipv4_only() {
    assert_eq!(
        ingress_of(&accepted(&with_ingress(json!({}))))["direct_address_families"],
        json!("ipv4_only")
    );
    let any = accepted(&with_ingress(json!({"direct_address_families": "any"})));
    assert_eq!(ingress_of(&any)["direct_address_families"], json!("any"));
}

#[test]
fn unknown_families_value_is_rejected() {
    for bad in [
        json!("all"),
        json!("ipv6_only"),
        json!("IPv4Only"),
        json!("Any"),
        json!(true),
        json!(4),
    ] {
        refused(&with_ingress(json!({"direct_address_families": bad})));
    }
    rejected(
        &with_ingress(json!({"direct_address_families": "ipv6_only"})),
        "unknown variant `ipv6_only`, expected `ipv4_only` or `any`",
    );
}

#[test]
fn adapter_ipv6_literal_with_ipv4_only_is_rejected() {
    // The first hop of a proxy chain obeys the same family filter as a Direct
    // dial (design 6.10), so an IPv6 literal could never be dialled.
    for host in ["2001:db8::1", "::1", "::ffff:192.0.2.1"] {
        rejected(
            &with_adapter("socks5", host, 1080, true, 10800),
            "routing adapter `local` has the IPv6 literal host",
        );
        // `any` lifts the filter; so does a name or an IPv4 literal.
        let mut value = with_adapter("socks5", host, 1080, true, 10800);
        value["ingress"]["direct_address_families"] = json!("any");
        accepted(&value);
    }
    accepted(&with_adapter("socks5", "192.0.2.1", 1080, true, 10800));
    accepted(&with_adapter(
        "socks5",
        "proxy.example.net",
        1080,
        true,
        10800,
    ));
}

#[test]
fn destination_logging_default_is_plain_and_unknown_value_is_rejected() {
    assert_eq!(
        ingress_of(&accepted(&with_ingress(json!({}))))["audit"]["destination_logging"],
        json!("plain")
    );
    let hashed = accepted(&with_ingress(
        json!({"audit": {"destination_logging": "hashed"}}),
    ));
    assert_eq!(
        ingress_of(&hashed)["audit"]["destination_logging"],
        json!("hashed")
    );
    for bad in [
        json!("omitted"),
        json!("Plain"),
        json!("HASHED"),
        json!(""),
        json!(true),
        json!(0),
    ] {
        refused(&with_ingress(
            json!({"audit": {"destination_logging": bad}}),
        ));
    }
    rejected(
        &with_ingress(json!({"audit": {"destination_logging": "omitted"}})),
        "unknown variant `omitted`, expected `plain` or `hashed`",
    );
}

#[test]
fn hardening_is_required_or_best_effort_and_nothing_else() {
    assert_eq!(
        ingress_of(&accepted(&with_ingress(json!({}))))["hardening"],
        json!("required")
    );
    let loaded = accepted(&with_ingress(json!({"hardening": "best_effort"})));
    assert_eq!(ingress_of(&loaded)["hardening"], json!("best_effort"));
    for bad in [
        json!("off"),
        json!("none"),
        json!("BestEffort"),
        json!(false),
        json!(""),
    ] {
        refused(&with_ingress(json!({"hardening": bad})));
    }
}

#[test]
fn a_section_is_read_from_a_map_and_from_nothing_else() {
    // serde reads a struct from a sequence too, in field order, and every field of
    // these has a default: without a guard `ingress: []` would load as the
    // defaults and `ingress: [true]` would switch the listener on. No operator
    // writes that on purpose, and the exported schema says `object`.
    for shape in [
        json!([]),
        json!([true]),
        json!(true),
        json!(0),
        json!("enabled"),
    ] {
        refused(&with_ingress(shape));
    }
    for (section, shape) in [
        ("listen", json!([])),
        ("listen", json!(["127.0.0.1", 10800])),
        ("limits", json!([])),
        ("limits", json!([256, 50])),
        ("audit", json!([])),
        ("audit", json!([32, 8, "plain"])),
    ] {
        refused(&with_ingress(json!({ section: shape })));
    }
    // A null section is not an empty one either (YAML only: TOML has no null).
    let yaml = serde_yaml::to_string(&with_ingress(Value::Null)).expect("yaml");
    assert!(AppConfig::parse_with_migration_yaml(&yaml).is_err());
}
