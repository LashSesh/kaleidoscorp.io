//! One grammar for "a host" in the routing section: rule destinations, domain
//! suffixes and adapter hosts. A spelling the OS resolver dials as an address
//! (`127.1`, `0x7f.0.0.1`, `2130706433`) must not load as a DNS name: the policy
//! engine never lets a suffix match it, so the rule would load and never fire.

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/support/host_corpus.rs"
));

use serde_json::{json, Value};
use ssk_config::routing::{
    valid_host, AdapterTransport, RoutingAction, RoutingAdapter, RoutingConfig, RoutingRule,
};
use ssk_config::{AppConfig, ConfigError};

fn routing_with_rule(destination: Option<&str>, domain_suffix: Option<&str>) -> RoutingConfig {
    let mut routing = RoutingConfig::default();
    routing.profiles[0].rules.push(RoutingRule {
        id: "probe".into(),
        priority: 10,
        destination: destination.map(Into::into),
        domain_suffix: domain_suffix.map(Into::into),
        port: None,
        action: RoutingAction::Deny,
        require_attestation: false,
    });
    routing
}

fn routing_with_adapter(host: &str) -> RoutingConfig {
    let mut routing = RoutingConfig::default();
    routing.adapters.push(RoutingAdapter {
        id: "proxy".into(),
        transport: AdapterTransport::Socks5 {
            host: host.into(),
            port: 1080,
        },
    });
    routing
}

#[test]
fn host_corpus_agrees_everywhere() {
    let corpus = host_corpus();
    // Dropping a group of rows must not be a way to make this pass.
    for class in HostClass::ALL {
        assert!(
            corpus.iter().any(|case| case.class == class),
            "the corpus has no {class:?} row"
        );
    }
    // Collect every disagreement, so one failure shows the whole picture.
    let mut disagreements = Vec::new();
    for case in &corpus {
        let host = case.host.as_str();
        let verdicts = [
            ("valid_host", valid_host(host), case.class.valid_host()),
            (
                "rule destination",
                routing_with_rule(Some(host), None).validate().is_ok(),
                case.class.valid_rule_destination(),
            ),
            (
                "domain suffix",
                routing_with_rule(None, Some(host)).validate().is_ok(),
                case.class.valid_domain_suffix(),
            ),
            (
                "adapter host",
                routing_with_adapter(host).validate().is_ok(),
                case.class.valid_host(),
            ),
        ];
        for (what, accepted, expected) in verdicts {
            if accepted != expected {
                disagreements.push(format!(
                    "{what}: {host:?} ({:?}) accepted={accepted}, expected {expected}",
                    case.class
                ));
            }
        }
    }
    assert!(
        disagreements.is_empty(),
        "{} disagreement(s) with the shared host corpus: {disagreements:#?}",
        disagreements.len()
    );
}

fn document_with_routing(routing: Value) -> Value {
    let mut value = serde_json::to_value(AppConfig::default()).unwrap();
    value["routing"] = routing;
    value
}

/// A whole document with one rule whose `field` (`destination` or
/// `domain_suffix`) is `host`.
fn rule_document(field: &str, host: &str) -> Value {
    document_with_routing(json!({
        "default_profile": "default",
        "adapters": [],
        "profiles": [{
            "id": "default",
            "name": "Default",
            "rules": [{
                "id": "probe",
                "priority": 10,
                field: host,
                "action": {"kind": "deny"}
            }]
        }]
    }))
}

/// A whole document with one adapter of `kind` whose host is `host`.
fn adapter_document(kind: &str, host: &str) -> Value {
    document_with_routing(json!({
        "default_profile": "default",
        "adapters": [{
            "id": "proxy",
            "transport": {"kind": kind, "host": host, "port": 1080}
        }],
        "profiles": [{"id": "default", "name": "Default", "rules": []}]
    }))
}

/// `None` when the document loads in both formats; the routing error text when
/// both refuse it for a routing reason. Anything else (the formats disagreeing,
/// another kind of error) fails the test: the rejection must be the host's.
fn routing_error(value: &Value) -> Option<String> {
    let yaml = AppConfig::parse_with_migration_yaml(&serde_yaml::to_string(value).unwrap());
    let toml = AppConfig::parse_with_migration_toml(&toml::to_string(value).unwrap());
    match (yaml, toml) {
        (Ok(_), Ok(_)) => None,
        (Err(ConfigError::Routing(yaml)), Err(ConfigError::Routing(toml))) => {
            assert_eq!(
                yaml, toml,
                "the two formats explain the rejection differently"
            );
            Some(yaml)
        }
        (yaml, toml) => panic!(
            "formats disagree or failed for another reason: yaml {:?}, toml {:?}",
            yaml.err(),
            toml.err()
        ),
    }
}

#[test]
fn config_rejects_numeric_alias_destination_suffix_and_adapter_host() {
    // Controls: the same documents with a legitimate host load, so a rejection
    // below is about the host and not about the shape of the document.
    let controls = [
        (
            "literal destination",
            rule_document("destination", "127.0.0.1"),
        ),
        (
            "name destination",
            rule_document("destination", "example.com"),
        ),
        ("name suffix", rule_document("domain_suffix", "example.com")),
        (
            "suffix with digit-led inner labels",
            rule_document("domain_suffix", "0.1.example"),
        ),
        ("socks5 literal", adapter_document("socks5", "127.0.0.1")),
        (
            "http_connect name",
            adapter_document("http_connect", "proxy.example"),
        ),
        (
            "tls_tunnel name with a trailing dot",
            adapter_document("tls_tunnel", "proxy.example."),
        ),
    ];
    for (what, document) in &controls {
        assert_eq!(routing_error(document), None, "control `{what}` must load");
    }

    let aliases = [
        "127.1",
        "127.0.1",
        "0x7f.0.0.1",
        "010.0.0.1",
        "2130706433",
        "0x7f000001",
        "0.1",
        "1",
        "127.0.0.1.",
    ];
    let mut loaded = Vec::new();
    for alias in aliases {
        let documents = [
            ("rule destination", rule_document("destination", alias)),
            ("domain suffix", rule_document("domain_suffix", alias)),
            ("socks5 host", adapter_document("socks5", alias)),
            ("http_connect host", adapter_document("http_connect", alias)),
            ("tls_tunnel host", adapter_document("tls_tunnel", alias)),
        ];
        for (what, document) in documents {
            if routing_error(&document).is_none() {
                loaded.push(format!("{what} {alias:?}"));
            }
        }
    }
    assert!(
        loaded.is_empty(),
        "numeric aliases must not load as hosts, but these did: {loaded:#?}"
    );
}

#[test]
fn config_rejects_ipv4_mapped_rule_destination() {
    // Controls. `::1` and a native IPv6 literal must stay valid: only the
    // mapped spelling goes (an implementation built on `Ipv6Addr::to_ipv4`
    // would also refuse `::1`, because that method turns it into 0.0.0.1).
    for (what, document) in [
        ("IPv4 literal", rule_document("destination", "10.0.0.1")),
        ("IPv6 loopback", rule_document("destination", "::1")),
        ("native IPv6", rule_document("destination", "2001:db8::1")),
    ] {
        assert_eq!(routing_error(&document), None, "control `{what}` must load");
    }

    let mut loaded = Vec::new();
    for mapped in [
        "::ffff:10.0.0.1",
        "::FFFF:10.0.0.1",
        "::ffff:a00:1",
        "0:0:0:0:0:ffff:10.0.0.1",
        "::ffff:127.0.0.1",
    ] {
        match routing_error(&rule_document("destination", mapped)) {
            None => loaded.push(mapped),
            Some(message) => assert!(
                message.contains("IPv4-mapped"),
                "{mapped:?} was refused, but the message does not say why: {message}"
            ),
        }
    }
    assert!(
        loaded.is_empty(),
        "IPv4-mapped IPv6 destinations must not load, but these did: {loaded:?}"
    );
}
