//! The configuration fingerprint (design 6.4.8, 5.9, 23.1).
//!
//! The three digests are written into the ledger's `Started` record and the
//! `Armed` record carries a profile digest and a rule table, so what they cover
//! is part of a persisted format: an auditor compares them with an archived
//! configuration file, possibly years later. These tests state that contract in
//! four pieces. What must NOT move a digest (the order of lists, a display
//! name, a section the views do not name). What MUST move one (every field of
//! every rule, every adapter, the default profile, every ingress key; the table
//! is built from the types' own serialised keys, so a field added later fails
//! here until it has a row). What the `Armed` record may say (rule ids, never a
//! destination). And golden vectors, written out as literals so that a silent
//! change of the view format, of the CBOR encoding or of the hash fails loudly
//! instead of making every archived digest unverifiable.

use serde_json::Value;
use ssk_config::fingerprint::{
    armed, of, ArmedFacts, ConfigFingerprint, FingerprintError, RuleRow, RuleTable,
    FINGERPRINT_VERSION, MAX_RULE_ROWS,
};
use ssk_config::ingress::{
    DestinationLogging, DirectAddressFamilies, IngressConfig, IngressHardening,
};
use ssk_config::routing::{
    AdapterTransport, RoutingAction, RoutingAdapter, RoutingConfig, RoutingProfile, RoutingRule,
};
use ssk_config::AppConfig;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

// ---------------------------------------------------------------------------
// The fixture. Every list is written out of order on purpose, and every
// destination string is distinct from every id, action label and number, so
// that a scan of a serialised record for one of them cannot hit by accident.
// ---------------------------------------------------------------------------

const SECRET_EXACT: &str = "secret-db.corp.example";
const SECRET_IP: &str = "10.9.8.7";
const SECRET_SUFFIX_A: &str = "internal.example";
const SECRET_SUFFIX_B: &str = "corp.example.net";
const HOME_EXACT: &str = "printer.local";
const HOME_SUFFIX: &str = "lan.example";
const EDGE_HOST: &str = "edge-proxy.example";
const ALPHA_HOST: &str = "192.0.2.44";
const TLS_HOST: &str = "relay.example.org";
const VPN_PROFILE: &str = "corp-vpn";

fn rule(
    id: &str,
    priority: u32,
    destination: Option<&str>,
    domain_suffix: Option<&str>,
    port: Option<u16>,
    action: RoutingAction,
    require_attestation: bool,
) -> RoutingRule {
    RoutingRule {
        id: id.into(),
        priority,
        destination: destination.map(Into::into),
        domain_suffix: domain_suffix.map(Into::into),
        port,
        action,
        require_attestation,
    }
}

fn adapter(id: &str, transport: AdapterTransport) -> RoutingAdapter {
    RoutingAdapter {
        id: id.into(),
        transport,
    }
}

fn via(adapter_id: &str) -> RoutingAction {
    RoutingAction::Adapter {
        adapter_id: adapter_id.into(),
    }
}

/// `work` (the default profile) uses `edge` and `vpn-a`; `home` uses `alpha`;
/// `tls-1` is referenced by nothing. Names differ from ids on purpose.
fn rich_config() -> AppConfig {
    let routing = RoutingConfig {
        default_profile: "work".into(),
        adapters: vec![
            adapter(
                "edge",
                AdapterTransport::Socks5 {
                    host: EDGE_HOST.into(),
                    port: 1080,
                },
            ),
            adapter(
                "vpn-a",
                AdapterTransport::OpenVpn {
                    profile_id: VPN_PROFILE.into(),
                },
            ),
            adapter(
                "alpha",
                AdapterTransport::HttpConnect {
                    host: ALPHA_HOST.into(),
                    port: 3128,
                },
            ),
            adapter(
                "tls-1",
                AdapterTransport::TlsTunnel {
                    host: TLS_HOST.into(),
                    port: 443,
                },
            ),
        ],
        profiles: vec![
            RoutingProfile {
                id: "work".into(),
                name: "Work laptop".into(),
                rules: vec![
                    rule(
                        "r-deny-secret",
                        30,
                        Some(SECRET_EXACT),
                        None,
                        Some(5432),
                        RoutingAction::Deny,
                        true,
                    ),
                    rule(
                        "r-via-edge",
                        10,
                        None,
                        Some(SECRET_SUFFIX_A),
                        None,
                        via("edge"),
                        false,
                    ),
                    rule(
                        "r-vpn",
                        40,
                        None,
                        Some(SECRET_SUFFIX_B),
                        Some(8443),
                        via("vpn-a"),
                        true,
                    ),
                    rule(
                        "r-direct-ip",
                        20,
                        Some(SECRET_IP),
                        None,
                        None,
                        RoutingAction::Direct,
                        false,
                    ),
                ],
            },
            RoutingProfile {
                id: "home".into(),
                name: "Home".into(),
                rules: vec![
                    rule(
                        "h-lan",
                        6,
                        None,
                        Some(HOME_SUFFIX),
                        None,
                        via("alpha"),
                        false,
                    ),
                    rule(
                        "h-printer",
                        5,
                        Some(HOME_EXACT),
                        None,
                        None,
                        RoutingAction::Direct,
                        false,
                    ),
                ],
            },
        ],
    };
    AppConfig {
        routing,
        ..AppConfig::default()
    }
}

/// Everything the fixture must never let into an `Armed` record.
const DESTINATION_TEXTS: [&str; 10] = [
    SECRET_EXACT,
    SECRET_IP,
    SECRET_SUFFIX_A,
    SECRET_SUFFIX_B,
    HOME_EXACT,
    HOME_SUFFIX,
    EDGE_HOST,
    ALPHA_HOST,
    TLS_HOST,
    VPN_PROFILE,
];

fn fingerprint(config: &AppConfig) -> ConfigFingerprint {
    of(config).expect("a fixture configuration fingerprints")
}

fn armed_for(config: &AppConfig, profile: &str) -> ArmedFacts {
    armed(config, profile).expect("the profile is configured")
}

fn is_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------------------------------------------------------------------------
// What must not move a digest.
// ---------------------------------------------------------------------------

#[test]
fn fingerprint_is_stable_under_rule_adapter_profile_reordering_and_profile_renames() {
    let config = rich_config();
    config.validate().expect("the fixture is a valid config");
    let base = fingerprint(&config);
    let base_armed = armed_for(&config, "work");

    // The control: a fingerprint that is the same for everything proves nothing.
    assert_eq!(base.version, FINGERPRINT_VERSION);
    let digests = [&base.config, &base.routing, &base.ingress];
    for digest in digests {
        assert!(is_digest(digest), "`{digest}` is not 64 lowercase hex");
    }
    assert_eq!(
        digests.iter().collect::<BTreeSet<_>>().len(),
        3,
        "the three digests cover different things and must differ: {base:?}"
    );
    assert_eq!(base, fingerprint(&config), "the same config, twice");

    // Each list alone, so that a missing sort anywhere is caught by its own case.
    type Shuffle = fn(&mut AppConfig);
    let shuffles: [(&str, Shuffle); 6] = [
        ("rules reversed", |c| {
            for profile in &mut c.routing.profiles {
                profile.rules.reverse();
            }
        }),
        ("rules rotated", |c| {
            for profile in &mut c.routing.profiles {
                profile.rules.rotate_left(1);
            }
        }),
        ("adapters reversed", |c| c.routing.adapters.reverse()),
        ("adapters rotated", |c| c.routing.adapters.rotate_left(1)),
        ("profiles reversed", |c| c.routing.profiles.reverse()),
        ("everything reversed", |c| {
            c.routing.profiles.reverse();
            c.routing.adapters.reverse();
            for profile in &mut c.routing.profiles {
                profile.rules.reverse();
            }
        }),
    ];
    for (label, shuffle) in shuffles {
        let mut shuffled = config.clone();
        shuffle(&mut shuffled);
        assert_ne!(shuffled, config, "{label}: the shuffle changed nothing");
        assert_eq!(fingerprint(&shuffled), base, "{label}");
        assert_eq!(armed_for(&shuffled, "work"), base_armed, "{label}: Armed");
    }

    // Display names are not identity: the ledger names profiles by id.
    let mut renamed = config.clone();
    for (i, profile) in renamed.routing.profiles.iter_mut().enumerate() {
        profile.name = format!("Renamed {i} \u{2603} Z\u{fc}rich");
    }
    assert_ne!(renamed, config);
    assert_eq!(fingerprint(&renamed), base, "profile names");
    assert_eq!(
        armed_for(&renamed, "work"),
        base_armed,
        "profile names: Armed"
    );

    // Sections the views do not name cannot move a digest: a key added to
    // `ssk-config` later must not silently change every archived fingerprint.
    let mut elsewhere = config.clone();
    elsewhere.policy.name = "another-policy".into();
    elsewhere.system.name = "another-system".into();
    assert_ne!(elsewhere, config);
    assert_eq!(fingerprint(&elsewhere), base, "sections outside the views");

    // A file migrated from v4 and the same content saved as v5 are one config.
    let mut older = config.clone();
    older.version = 4;
    assert_eq!(fingerprint(&older), base, "the file's version number");
}

// ---------------------------------------------------------------------------
// What must move a digest. One row per leaf key, generated from the types.
// ---------------------------------------------------------------------------

/// Which digests a change is allowed (and required) to move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Effect {
    /// Routing content of the `work` profile or an adapter it references:
    /// `routing`, `config` and the `Armed` profile digest of `work` move.
    Work,
    /// Routing content `work` does not use: `routing` and `config` move, the
    /// `Armed` digest of `work` does not.
    OtherRouting,
    /// An ingress key: `ingress` and `config` move, nothing else.
    Ingress,
}

struct Row {
    /// Dotted leaf path with a scope prefix (`rule.`, `adapter.`, `ingress.`),
    /// or a `structure.` label for changes that are not a leaf of a type.
    key: &'static str,
    effect: Effect,
    /// `false` only where this build cannot spell a different valid value.
    valid: bool,
    change: fn(&mut AppConfig),
}

fn row(key: &'static str, effect: Effect, change: fn(&mut AppConfig)) -> Row {
    Row {
        key,
        effect,
        valid: true,
        change,
    }
}

fn rule_mut<'a>(config: &'a mut AppConfig, id: &str) -> &'a mut RoutingRule {
    config
        .routing
        .profiles
        .iter_mut()
        .flat_map(|profile| profile.rules.iter_mut())
        .find(|rule| rule.id == id)
        .expect("the fixture has this rule")
}

fn adapter_mut<'a>(config: &'a mut AppConfig, id: &str) -> &'a mut RoutingAdapter {
    config
        .routing
        .adapters
        .iter_mut()
        .find(|adapter| adapter.id == id)
        .expect("the fixture has this adapter")
}

fn rows() -> Vec<Row> {
    use Effect::{Ingress, OtherRouting, Work};
    vec![
        // Rule fields, each in every direction a value can move.
        row("rule.id", Work, |c| {
            rule_mut(c, "r-direct-ip").id = "r-direct-ip2".into()
        }),
        row("rule.priority", Work, |c| {
            rule_mut(c, "r-direct-ip").priority = 21
        }),
        row("rule.priority", Work, |c| {
            rule_mut(c, "r-direct-ip").priority = 35
        }),
        row("rule.priority", OtherRouting, |c| {
            rule_mut(c, "h-lan").priority = 7
        }),
        row("rule.destination", Work, |c| {
            rule_mut(c, "r-direct-ip").destination = Some("10.9.8.8".into());
        }),
        row("rule.destination", Work, |c| {
            rule_mut(c, "r-via-edge").destination = Some("gw.internal.example".into());
        }),
        row("rule.destination", Work, |c| {
            rule_mut(c, "r-direct-ip").destination = None
        }),
        row("rule.domain_suffix", Work, |c| {
            rule_mut(c, "r-via-edge").domain_suffix = Some("internal.example.org".into());
        }),
        row("rule.domain_suffix", Work, |c| {
            rule_mut(c, "r-direct-ip").domain_suffix = Some("example.com".into());
        }),
        row("rule.domain_suffix", Work, |c| {
            rule_mut(c, "r-vpn").domain_suffix = None
        }),
        row("rule.port", Work, |c| {
            rule_mut(c, "r-via-edge").port = Some(443)
        }),
        row("rule.port", Work, |c| {
            rule_mut(c, "r-deny-secret").port = Some(5433)
        }),
        row("rule.port", Work, |c| {
            rule_mut(c, "r-deny-secret").port = None
        }),
        row("rule.action.kind", Work, |c| {
            rule_mut(c, "r-direct-ip").action = RoutingAction::Deny;
        }),
        row("rule.action.kind", Work, |c| {
            rule_mut(c, "r-deny-secret").action = RoutingAction::Direct;
        }),
        row("rule.action.kind", Work, |c| {
            rule_mut(c, "r-via-edge").action = RoutingAction::Deny;
        }),
        row("rule.action.adapter_id", Work, |c| {
            rule_mut(c, "r-via-edge").action = via("tls-1");
        }),
        row("rule.require_attestation", Work, |c| {
            rule_mut(c, "r-direct-ip").require_attestation = true;
        }),
        row("rule.require_attestation", Work, |c| {
            rule_mut(c, "r-vpn").require_attestation = false;
        }),
        // Adapter fields.
        row("adapter.id", Work, |c| {
            adapter_mut(c, "edge").id = "edge2".into();
            rule_mut(c, "r-via-edge").action = via("edge2");
        }),
        row("adapter.id", OtherRouting, |c| {
            adapter_mut(c, "alpha").id = "alpha2".into();
            rule_mut(c, "h-lan").action = via("alpha2");
        }),
        // No rule names it, so the id is the only thing that changed.
        row("adapter.id", OtherRouting, |c| {
            adapter_mut(c, "tls-1").id = "tls-2".into();
        }),
        row("adapter.transport.kind", Work, |c| {
            adapter_mut(c, "edge").transport = AdapterTransport::HttpConnect {
                host: EDGE_HOST.into(),
                port: 1080,
            };
        }),
        row("adapter.transport.kind", Work, |c| {
            adapter_mut(c, "edge").transport = AdapterTransport::TlsTunnel {
                host: EDGE_HOST.into(),
                port: 1080,
            };
        }),
        row("adapter.transport.kind", OtherRouting, |c| {
            adapter_mut(c, "alpha").transport = AdapterTransport::Socks5 {
                host: ALPHA_HOST.into(),
                port: 3128,
            };
        }),
        row("adapter.transport.host", Work, |c| {
            adapter_mut(c, "edge").transport = AdapterTransport::Socks5 {
                host: "edge-proxy.example.org".into(),
                port: 1080,
            };
        }),
        row("adapter.transport.port", Work, |c| {
            adapter_mut(c, "edge").transport = AdapterTransport::Socks5 {
                host: EDGE_HOST.into(),
                port: 1081,
            };
        }),
        row("adapter.transport.host", OtherRouting, |c| {
            adapter_mut(c, "tls-1").transport = AdapterTransport::TlsTunnel {
                host: "relay.example.net".into(),
                port: 443,
            };
        }),
        row("adapter.transport.profile_id", Work, |c| {
            adapter_mut(c, "vpn-a").transport = AdapterTransport::OpenVpn {
                profile_id: "corp-vpn-2".into(),
            };
        }),
        // The default profile and the profile id.
        row("default_profile", OtherRouting, |c| {
            c.routing.default_profile = "home".into()
        }),
        row("profile.id", OtherRouting, |c| {
            c.routing.profiles[1].id = "home2".into()
        }),
        // Changes that are not a leaf of any type: members appearing or going.
        row("structure.rule.added", Work, |c| {
            c.routing.profiles[0].rules.push(rule(
                "r-new",
                50,
                None,
                None,
                None,
                RoutingAction::Deny,
                false,
            ));
        }),
        row("structure.rule.removed", Work, |c| {
            c.routing.profiles[0].rules.retain(|r| r.id != "r-vpn");
        }),
        row("structure.rule.added", OtherRouting, |c| {
            c.routing.profiles[1].rules.push(rule(
                "h-new",
                50,
                None,
                None,
                None,
                RoutingAction::Deny,
                false,
            ));
        }),
        row("structure.adapter.added", OtherRouting, |c| {
            c.routing.adapters.push(adapter(
                "unused",
                AdapterTransport::Socks5 {
                    host: "unused.example".into(),
                    port: 9,
                },
            ));
        }),
        row("structure.adapter.removed", OtherRouting, |c| {
            c.routing.adapters.retain(|a| a.id != "tls-1");
        }),
        row("structure.profile.added", OtherRouting, |c| {
            c.routing.profiles.push(RoutingProfile {
                id: "extra".into(),
                name: "Extra".into(),
                rules: vec![],
            });
        }),
        row("structure.profile.removed", OtherRouting, |c| {
            c.routing.profiles.retain(|p| p.id != "home");
            c.routing.adapters.retain(|a| a.id != "alpha");
        }),
        // Ingress: one row per key of the section.
        row("ingress.enabled", Ingress, |c| c.ingress.enabled = true),
        row("ingress.listen.address", Ingress, |c| {
            c.ingress.listen.address = Ipv4Addr::new(127, 0, 0, 2);
        }),
        row("ingress.listen.port", Ingress, |c| {
            c.ingress.listen.port = 10801
        }),
        row("ingress.listen.port", Ingress, |c| {
            c.ingress.listen.port = 0
        }),
        Row {
            // This build speaks one protocol, so no VALID document differs
            // here. The view must still carry the key: `http_connect` arrives
            // without a version bump (design 5.5), and then it has to count.
            valid: false,
            ..row("ingress.protocols", Ingress, |c| {
                c.ingress.protocols = vec![]
            })
        },
        row("ingress.hardening", Ingress, |c| {
            c.ingress.hardening = IngressHardening::BestEffort;
        }),
        row("ingress.arm_on_start", Ingress, |c| {
            c.ingress.arm_on_start = true
        }),
        row("ingress.direct_address_families", Ingress, |c| {
            c.ingress.direct_address_families = DirectAddressFamilies::Any;
        }),
        row("ingress.limits.max_connections", Ingress, |c| {
            c.ingress.limits.max_connections = 257;
        }),
        row("ingress.limits.accept_rate_per_s", Ingress, |c| {
            c.ingress.limits.accept_rate_per_s = 51;
        }),
        row("ingress.limits.handshake_timeout_ms", Ingress, |c| {
            c.ingress.limits.handshake_timeout_ms = 10_001;
        }),
        row("ingress.limits.connect_timeout_ms", Ingress, |c| {
            c.ingress.limits.connect_timeout_ms = 20_001;
        }),
        row("ingress.limits.idle_timeout_ms", Ingress, |c| {
            c.ingress.limits.idle_timeout_ms = 3_600_001;
        }),
        row("ingress.audit.segment_mib", Ingress, |c| {
            c.ingress.audit.segment_mib = 33
        }),
        row("ingress.audit.retain_segments", Ingress, |c| {
            c.ingress.audit.retain_segments = 9;
        }),
        row("ingress.audit.destination_logging", Ingress, |c| {
            c.ingress.audit.destination_logging = DestinationLogging::Hashed;
        }),
    ]
}

/// Every dotted leaf path of a serialised value; arrays are leaves.
fn leaves(value: &Value, prefix: &str, into: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                leaves(child, &path, into);
            }
        }
        _ => {
            into.insert(prefix.to_owned());
        }
    }
}

fn leaf_set<T: serde::Serialize>(samples: &[T], scope: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for sample in samples {
        let value = serde_json::to_value(sample).expect("serialises");
        leaves(&value, "", &mut found);
    }
    found
        .into_iter()
        .map(|leaf| format!("{scope}{leaf}"))
        .collect()
}

/// The keys the rows must cover, read from the types and not from this file.
fn expected_leaf_keys() -> BTreeSet<String> {
    let rule_samples = [
        rule("a", 1, Some("x"), Some("y"), Some(1), via("z"), true),
        rule("a", 1, None, None, None, RoutingAction::Deny, false),
    ];
    let adapter_samples = [
        adapter(
            "a",
            AdapterTransport::Socks5 {
                host: "h".into(),
                port: 1,
            },
        ),
        adapter(
            "a",
            AdapterTransport::HttpConnect {
                host: "h".into(),
                port: 1,
            },
        ),
        adapter(
            "a",
            AdapterTransport::TlsTunnel {
                host: "h".into(),
                port: 1,
            },
        ),
        adapter(
            "a",
            AdapterTransport::OpenVpn {
                profile_id: "p".into(),
            },
        ),
    ];
    let mut keys = leaf_set(&rule_samples, "rule.");
    keys.extend(leaf_set(&adapter_samples, "adapter."));
    keys.extend(leaf_set(&[IngressConfig::default()], "ingress."));
    // The routing section and a profile: their scalar keys have rows, their
    // lists are covered by the `structure.` rows, and `name` is excluded on
    // purpose (the stability test).
    assert_eq!(
        leaf_set(&[RoutingConfig::default()], ""),
        BTreeSet::from(["adapters", "default_profile", "profiles"].map(String::from)),
        "RoutingConfig has a new key: decide whether the fingerprint covers it"
    );
    assert_eq!(
        leaf_set(
            &[RoutingProfile {
                id: "p".into(),
                name: "n".into(),
                rules: vec![],
            }],
            "",
        ),
        BTreeSet::from(["id", "name", "rules"].map(String::from)),
        "RoutingProfile has a new key: decide whether the fingerprint covers it"
    );
    keys.extend(["default_profile", "profile.id"].map(String::from));
    keys
}

#[test]
fn fingerprint_changes_for_every_rule_field_adapter_field_default_profile_and_ingress_key() {
    let base_config = rich_config();
    base_config
        .validate()
        .expect("the fixture is a valid config");
    let base = fingerprint(&base_config);
    let base_work = armed_for(&base_config, "work").profile_digest;

    // The rows cover exactly the keys the types serialise: a field added to a
    // type fails here until someone decides what the fingerprint does with it.
    let table = rows();
    let covered: BTreeSet<String> = table
        .iter()
        .map(|r| r.key)
        .filter(|key| !key.starts_with("structure."))
        .map(String::from)
        .collect();
    let expected = expected_leaf_keys();
    assert_eq!(
        expected.difference(&covered).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "keys of the types that no row changes"
    );
    assert_eq!(
        covered.difference(&expected).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "rows for keys the types do not have"
    );

    let mut failures = Vec::new();
    for (index, row) in table.iter().enumerate() {
        let mut changed = base_config.clone();
        (row.change)(&mut changed);
        let label = format!("row {index} ({})", row.key);
        if changed == base_config {
            failures.push(format!("{label}: the change did not change the config"));
            continue;
        }
        if row.valid {
            if let Err(err) = changed.validate() {
                failures.push(format!("{label}: the changed config is invalid: {err}"));
                continue;
            }
        }
        let after = fingerprint(&changed);
        let work_after = armed(&changed, "work").map(|facts| facts.profile_digest);
        let (routing, ingress, config) = (
            after.routing != base.routing,
            after.ingress != base.ingress,
            after.config != base.config,
        );
        let (want_routing, want_ingress, want_work) = match row.effect {
            Effect::Work => (true, false, true),
            Effect::OtherRouting => (true, false, false),
            Effect::Ingress => (false, true, false),
        };
        if (routing, ingress) != (want_routing, want_ingress) || !config {
            failures.push(format!(
                "{label}: moved routing={routing} ingress={ingress} config={config}, \
                 wanted routing={want_routing} ingress={want_ingress} config=true"
            ));
        }
        if after.version != base.version {
            failures.push(format!("{label}: the version moved"));
        }
        // `work` can vanish from the table only where a row removes it; none does.
        let work_moved = work_after.as_ref().map(|digest| digest != &base_work);
        if work_moved.as_ref().ok() != Some(&want_work) {
            failures.push(format!(
                "{label}: the Armed digest of `work` moved={work_moved:?}, wanted {want_work}"
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

// ---------------------------------------------------------------------------
// The `Armed` record.
// ---------------------------------------------------------------------------

#[test]
fn armed_record_lists_rule_ids_without_destinations() {
    let config = rich_config();
    let facts = armed_for(&config, "work");

    // Rows follow evaluation order: ascending priority, then id.
    let row = |id: &str, priority, action: &str, attestation, exact, suffix, port| RuleRow {
        id: id.into(),
        priority,
        action: action.into(),
        attestation,
        exact_destination: exact,
        suffix,
        port,
    };
    assert_eq!(
        facts.rules.rules,
        vec![
            row("r-via-edge", 10, "adapter:edge", false, false, true, None),
            row("r-direct-ip", 20, "direct", false, true, false, None),
            row("r-deny-secret", 30, "deny", true, true, false, Some(5432)),
            row("r-vpn", 40, "adapter:vpn-a", true, false, true, Some(8443)),
        ]
    );
    assert_eq!((facts.rules.total, facts.rules.truncated), (4, false));
    assert!(is_digest(&facts.profile_digest));

    // The serialised record names the rules and says nothing about where they
    // point: not an exact destination, not a suffix, not an adapter's host.
    let json = serde_json::to_string(&facts).expect("serialises");
    let debug = format!("{facts:?}");
    for body in [&json, &debug] {
        for id in ["r-via-edge", "r-direct-ip", "r-deny-secret", "r-vpn"] {
            assert!(body.contains(id), "rule id {id} is missing from {body}");
        }
        for text in DESTINATION_TEXTS {
            assert!(!body.contains(text), "`{text}` leaked into {body}");
        }
        // Nor the other profile's rules.
        assert!(!body.contains("h-lan"), "{body}");
    }

    // `home` is another profile with another digest and its own rows.
    let home = armed_for(&config, "home");
    assert_ne!(home.profile_digest, facts.profile_digest);
    let home_ids: Vec<&str> = home.rules.rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(home_ids, ["h-printer", "h-lan"]);
}

#[test]
fn armed_for_a_profile_that_is_not_configured_is_a_typed_error() {
    let config = rich_config();
    for missing in ["", "Work", "nope", "work "] {
        match armed(&config, missing) {
            Err(FingerprintError::UnknownProfile(id)) => assert_eq!(id, missing),
            other => panic!("`{missing}`: expected UnknownProfile, got {other:?}"),
        }
    }
}

#[test]
fn the_rule_table_is_capped_at_256_rows_and_says_so() {
    assert_eq!(MAX_RULE_ROWS, 256);
    let with_rules = |count: u32| {
        let mut config = AppConfig::default();
        // Written in descending priority, so the cut cannot be the first 256 written.
        config.routing.profiles[0].rules = (0..count)
            .rev()
            .map(|n| {
                rule(
                    &format!("rule-{n}"),
                    n,
                    None,
                    None,
                    None,
                    RoutingAction::Deny,
                    false,
                )
            })
            .collect();
        config
    };
    let table = |count: u32| armed_for(&with_rules(count), "default").rules;

    let exactly = table(256);
    assert_eq!(
        (exactly.total, exactly.truncated, exactly.rules.len()),
        (256, false, 256)
    );

    let over = table(300);
    assert_eq!(
        (over.total, over.truncated, over.rules.len()),
        (300, true, 256)
    );
    let ids: Vec<&str> = over.rules.iter().map(|r| r.id.as_str()).collect();
    let wanted: Vec<String> = (0..256).map(|n| format!("rule-{n}")).collect();
    assert_eq!(
        ids, wanted,
        "the table keeps the first 256 in evaluation order"
    );

    // The digest still covers all 300 rules, so the cut hides nothing from it.
    let full = armed_for(&with_rules(300), "default").profile_digest;
    let mut one_beyond = with_rules(300);
    one_beyond.routing.profiles[0].rules[0].port = Some(9);
    assert_ne!(armed_for(&one_beyond, "default").profile_digest, full);

    let none = table(0);
    assert_eq!(
        (none.total, none.truncated, none.rules.len()),
        (0, false, 0)
    );
}

// ---------------------------------------------------------------------------
// Golden vectors.
// ---------------------------------------------------------------------------

/// The value of the three digests for the default config and for the fixture,
/// the Armed record of `work`, and the JSON shape of both. If one of these
/// changes, every digest in every ledger written so far stops matching its
/// configuration file: that needs a new `FINGERPRINT_VERSION`, a compatibility
/// matrix entry and a decision, never a quiet edit of the literal.
///
/// The literals are not a snapshot of this implementation: a second one, written
/// from the design text (a BLAKE3 reference port and a CBOR encoder in Python,
/// checked against the published `""` and `"abc"` vectors), reproduces every
/// one of them from the same fixtures.
#[test]
fn golden_vectors_pin_the_persisted_digests_and_record_shapes() {
    let default = fingerprint(&AppConfig::default());
    assert_eq!(
        serde_json::to_string(&default).expect("serialises"),
        concat!(
            r#"{"version":1,"#,
            r#""config":"a77277f0555a00a1e2f33cd6e4cdabe67a758ec30c19a2537c8f9b446ff5422e","#,
            r#""routing":"4cc1fc50acec2b92baa5633542fa80b20c1561b86d95912d4ff3131d75734f28","#,
            r#""ingress":"df2fa5e7b25d7d1b0f0cb1ee7bf9c3b59f080350112aa162d61108575b8cc7dc"}"#
        )
    );

    let rich = fingerprint(&rich_config());
    assert_eq!(
        serde_json::to_string(&rich).expect("serialises"),
        concat!(
            r#"{"version":1,"#,
            r#""config":"92a2910c939e9e0a94468bf7fdfe1aa5d25f71b79917e9c96f6c8464c08c0412","#,
            r#""routing":"9fd61daacf1c8792edd9a297882429f436bf7d1080b5c69b888873f75db56f76","#,
            r#""ingress":"df2fa5e7b25d7d1b0f0cb1ee7bf9c3b59f080350112aa162d61108575b8cc7dc"}"#
        )
    );
    // Read back from the ledger's JSON it is the same value.
    let round: ConfigFingerprint =
        serde_json::from_str(&serde_json::to_string(&rich).expect("serialises")).expect("parses");
    assert_eq!(round, rich);

    // Ingress with every key moved off its default, so a key the view dropped
    // cannot hide behind the default section's digest.
    let mut busy = AppConfig::default();
    busy.ingress.enabled = true;
    busy.ingress.listen.address = Ipv4Addr::new(127, 1, 2, 3);
    busy.ingress.listen.port = 4242;
    busy.ingress.hardening = IngressHardening::BestEffort;
    busy.ingress.arm_on_start = true;
    busy.ingress.direct_address_families = DirectAddressFamilies::Any;
    busy.ingress.limits.max_connections = 17;
    busy.ingress.limits.accept_rate_per_s = 18;
    busy.ingress.limits.handshake_timeout_ms = 19_000;
    busy.ingress.limits.connect_timeout_ms = 21_000;
    busy.ingress.limits.idle_timeout_ms = 23_000;
    busy.ingress.audit.segment_mib = 5;
    busy.ingress.audit.retain_segments = 3;
    busy.ingress.audit.destination_logging = DestinationLogging::Hashed;
    assert_eq!(
        fingerprint(&busy).ingress,
        "4c647070d8e5975cd9def1a6345a28f4e7b4ed197e6e6dc925985acec4d8ac3b"
    );

    let facts = armed_for(&rich_config(), "work");
    assert_eq!(
        facts.profile_digest,
        "07ca114315af956ac9eec76046ca4574aff0a4abf537a69eb5471196de45284b"
    );
    assert_eq!(
        serde_json::to_string(&facts.rules).expect("serialises"),
        concat!(
            r#"{"total":4,"truncated":false,"rules":["#,
            r#"{"id":"r-via-edge","priority":10,"action":"adapter:edge","attestation":false,"exact_destination":false,"suffix":true,"port":null},"#,
            r#"{"id":"r-direct-ip","priority":20,"action":"direct","attestation":false,"exact_destination":true,"suffix":false,"port":null},"#,
            r#"{"id":"r-deny-secret","priority":30,"action":"deny","attestation":true,"exact_destination":true,"suffix":false,"port":5432},"#,
            r#"{"id":"r-vpn","priority":40,"action":"adapter:vpn-a","attestation":true,"exact_destination":false,"suffix":true,"port":8443}]}"#
        )
    );
    // A row and a table read back.
    let table: RuleTable =
        serde_json::from_str(&serde_json::to_string(&facts.rules).expect("serialises"))
            .expect("parses");
    assert_eq!(table, facts.rules);
    let first: &RuleRow = &table.rules[0];
    assert_eq!(first.id, "r-via-edge");
}
