//! The configuration fingerprint (design 6.4.8, 5.9 and MD-8).
//!
//! The ingress ledger's `Started` record stores [`ConfigFingerprint`] and its
//! `Armed` record stores [`ArmedFacts`], so that a later reader can tell which
//! configuration a `matched_rule: rule-3` was written under, and an auditor can
//! recompute the digests from an archived file. It lives here, not in the
//! daemon, because `ssk config lint` prints the same digests and `ssk-cli` does
//! not depend on `ssk-daemon`.
//!
//! **What a digest is.** The blake3 hash (`ssk_types::digest_of`, over the
//! canonical CBOR of the value) of an explicit *view* struct defined below, not
//! of `AppConfig` itself. The views name what they cover, field by field, so a
//! key added to the configuration neither changes every digest nor is ignored
//! by accident: each view is built by destructuring its source without `..`,
//! and a new field is a compile error here until someone decides. The views
//! are part of a persisted format. Changing what a view contains or how it is
//! ordered or spelled makes every digest already written unverifiable, so it
//! needs a new [`FINGERPRINT_VERSION`] and a compatibility-matrix entry; the
//! golden vectors in `tests/fingerprint.rs` fail on any silent change.
//!
//! **What they leave out.** The display `name` of a profile (the ledger names a
//! profile by its id and a rename must not look like a policy change), the
//! order of the three lists (adapters by id, profiles by id, rules by
//! `(priority, id)`: the order the policy engine evaluates in), the file's
//! `version` (a v4 file migrated in memory and the same content saved as v5 are
//! one configuration) and every section outside `routing` and `ingress`.
//!
//! The functions take a validated configuration: ids are unique there, which
//! is what makes the sort keys total. They are pure and allocate only what the
//! digest needs; they never read a file and never look at the clock.
use crate::ingress::{
    DestinationLogging, DirectAddressFamilies, IngressAuditConfig, IngressConfig, IngressHardening,
    IngressLimits, IngressListen, IngressProtocol,
};
use crate::routing::{
    AdapterTransport, RoutingAction, RoutingAdapter, RoutingConfig, RoutingProfile, RoutingRule,
};
use crate::AppConfig;
use serde::{Deserialize, Serialize};
use ssk_types::{digest_of, Digest, HashAlg, TypeError};
use std::collections::BTreeSet;

/// Format version of the views, carried by every view and by the fingerprint
/// itself. Bump it, with a matrix entry, when a view changes.
pub const FINGERPRINT_VERSION: u32 = 1;

/// The most rows an `Armed` record's rule table holds (design 6.4.3); the
/// digest still covers every rule.
pub const MAX_RULE_ROWS: usize = 256;

/// The three digests of one configuration, 64 lowercase hex characters each.
/// Field names and order are the `Started` record's JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigFingerprint {
    pub version: u32,
    /// Routing and ingress together: moves whenever either of them does.
    pub config: String,
    /// `default_profile`, the adapters and the profiles with their rules. The
    /// digest a confirmation is bound to (design 11.4).
    pub routing: String,
    /// The validated ingress section, every key, `destination_logging` included.
    pub ingress: String,
}

/// What the `Armed` record says about the profile it armed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmedFacts {
    /// That profile's view plus the adapters its rules reference: an archived
    /// file recomputes to it, and a change to another profile does not move it.
    pub profile_digest: String,
    pub rules: RuleTable,
}

/// The profile's rules in evaluation order, so that `matched_rule: rule-3` can
/// be read as "rule-3 meant deny" without the configuration file that is gone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleTable {
    /// How many rules the profile has, the rows below included.
    pub total: u32,
    /// `true` when `total` exceeds [`MAX_RULE_ROWS`] and the tail is cut.
    pub truncated: bool,
    pub rules: Vec<RuleRow>,
}

/// One rule, without the text it matches: whether an exact destination or a
/// suffix exists, never which. The record is readable by anyone who can read
/// the ledger, and hashed destination logging must not be undone by it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRow {
    pub id: String,
    pub priority: u32,
    /// `direct`, `deny` or `adapter:<id>`.
    pub action: String,
    pub attestation: bool,
    pub exact_destination: bool,
    pub suffix: bool,
    pub port: Option<u16>,
}

#[derive(Debug, thiserror::Error)]
pub enum FingerprintError {
    /// Serialising a view failed. The views hold only strings, integers and
    /// booleans, so this is not reachable today; it is a variant and not a
    /// panic because a fingerprint that silently fell back to something else
    /// would be worse than none.
    #[error("cannot compute the configuration fingerprint: {0}")]
    Digest(#[from] TypeError),
    #[error("routing profile `{0}` is not configured")]
    UnknownProfile(String),
}

/// The fingerprint of a validated configuration (computed once per boot).
pub fn of(config: &AppConfig) -> Result<ConfigFingerprint, FingerprintError> {
    let routing = digest(&routing_view(&config.routing))?;
    let ingress = digest(&ingress_view(&config.ingress))?;
    // The combined digest commits to the two others and nothing else, so it
    // moves exactly when one of them does.
    let combined = digest(&ConfigView {
        version: FINGERPRINT_VERSION,
        routing,
        ingress,
    })?;
    Ok(ConfigFingerprint {
        version: FINGERPRINT_VERSION,
        config: combined.to_hex(),
        routing: routing.to_hex(),
        ingress: ingress.to_hex(),
    })
}

/// What the `Armed` record carries of `profile_id`'s configuration.
pub fn armed(config: &AppConfig, profile_id: &str) -> Result<ArmedFacts, FingerprintError> {
    let profile = config
        .routing
        .profiles
        .iter()
        .find(|profile| profile.id == profile_id)
        .ok_or_else(|| FingerprintError::UnknownProfile(profile_id.to_owned()))?;
    let rules = in_evaluation_order(&profile.rules);

    let referenced: BTreeSet<&str> = rules
        .iter()
        .filter_map(|rule| match &rule.action {
            RoutingAction::Adapter { adapter_id } => Some(adapter_id.as_str()),
            RoutingAction::Direct | RoutingAction::Deny => None,
        })
        .collect();
    let profile_digest = digest(&ProfileDigestView {
        version: FINGERPRINT_VERSION,
        profile: profile_view(profile),
        adapters: adapter_views(
            config
                .routing
                .adapters
                .iter()
                .filter(|adapter| referenced.contains(adapter.id.as_str())),
        ),
    })?;

    Ok(ArmedFacts {
        profile_digest: profile_digest.to_hex(),
        rules: RuleTable {
            total: u32::try_from(rules.len()).unwrap_or(u32::MAX),
            truncated: rules.len() > MAX_RULE_ROWS,
            rules: rules
                .into_iter()
                .take(MAX_RULE_ROWS)
                .map(rule_row)
                .collect(),
        },
    })
}

fn digest<T: Serialize>(view: &T) -> Result<Digest, FingerprintError> {
    Ok(digest_of(view, HashAlg::Blake3)?)
}

// ---------------------------------------------------------------------------
// The views. Field names, order and spellings are the format: see the module doc.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ConfigView {
    version: u32,
    routing: Digest,
    ingress: Digest,
}

#[derive(Serialize)]
struct RoutingView<'a> {
    version: u32,
    default_profile: &'a str,
    adapters: Vec<AdapterView<'a>>,
    profiles: Vec<ProfileView<'a>>,
}

#[derive(Serialize)]
struct ProfileDigestView<'a> {
    version: u32,
    profile: ProfileView<'a>,
    adapters: Vec<AdapterView<'a>>,
}

/// A profile without its display name.
#[derive(Serialize)]
struct ProfileView<'a> {
    id: &'a str,
    rules: Vec<RuleView<'a>>,
}

/// `kind` is the spelling the configuration file uses; the fields a kind does
/// not have are `null`.
#[derive(Serialize)]
struct AdapterView<'a> {
    id: &'a str,
    kind: &'static str,
    host: Option<&'a str>,
    port: Option<u16>,
    profile_id: Option<&'a str>,
}

#[derive(Serialize)]
struct RuleView<'a> {
    id: &'a str,
    priority: u32,
    destination: Option<&'a str>,
    domain_suffix: Option<&'a str>,
    port: Option<u16>,
    action: String,
    require_attestation: bool,
}

#[derive(Serialize)]
struct IngressView {
    version: u32,
    enabled: bool,
    listen: ListenView,
    protocols: Vec<&'static str>,
    hardening: &'static str,
    arm_on_start: bool,
    direct_address_families: &'static str,
    limits: LimitsView,
    audit: AuditView,
}

#[derive(Serialize)]
struct ListenView {
    address: String,
    port: u16,
}

#[derive(Serialize)]
struct LimitsView {
    max_connections: u32,
    accept_rate_per_s: u32,
    handshake_timeout_ms: u32,
    connect_timeout_ms: u32,
    idle_timeout_ms: u32,
}

#[derive(Serialize)]
struct AuditView {
    segment_mib: u32,
    retain_segments: u32,
    destination_logging: &'static str,
}

fn routing_view(routing: &RoutingConfig) -> RoutingView<'_> {
    let RoutingConfig {
        default_profile,
        profiles,
        adapters,
    } = routing;
    let mut profiles: Vec<&RoutingProfile> = profiles.iter().collect();
    profiles.sort_by_key(|profile| profile.id.as_str());
    RoutingView {
        version: FINGERPRINT_VERSION,
        default_profile,
        adapters: adapter_views(adapters.iter()),
        profiles: profiles.into_iter().map(profile_view).collect(),
    }
}

fn profile_view(profile: &RoutingProfile) -> ProfileView<'_> {
    let RoutingProfile {
        id,
        // Display text, free-form and editable: not identity.
        name: _,
        rules,
    } = profile;
    ProfileView {
        id,
        rules: in_evaluation_order(rules)
            .into_iter()
            .map(rule_view)
            .collect(),
    }
}

/// The order the policy engine evaluates in: lower priority first. Validation
/// makes ids and priorities unique within a profile, so `(priority, id)` is a
/// total order and the order of the file never matters.
fn in_evaluation_order(rules: &[RoutingRule]) -> Vec<&RoutingRule> {
    let mut ordered: Vec<&RoutingRule> = rules.iter().collect();
    ordered.sort_by_key(|rule| (rule.priority, rule.id.as_str()));
    ordered
}

fn adapter_views<'a>(adapters: impl Iterator<Item = &'a RoutingAdapter>) -> Vec<AdapterView<'a>> {
    let mut views: Vec<AdapterView<'a>> = adapters.map(adapter_view).collect();
    views.sort_by_key(|view| view.id);
    views
}

fn adapter_view(adapter: &RoutingAdapter) -> AdapterView<'_> {
    let RoutingAdapter { id, transport } = adapter;
    let (kind, host, port, profile_id) = match transport {
        AdapterTransport::Socks5 { host, port } => {
            ("socks5", Some(host.as_str()), Some(*port), None)
        }
        AdapterTransport::HttpConnect { host, port } => {
            ("http_connect", Some(host.as_str()), Some(*port), None)
        }
        AdapterTransport::TlsTunnel { host, port } => {
            ("tls_tunnel", Some(host.as_str()), Some(*port), None)
        }
        AdapterTransport::OpenVpn { profile_id } => {
            ("open_vpn", None, None, Some(profile_id.as_str()))
        }
    };
    AdapterView {
        id,
        kind,
        host,
        port,
        profile_id,
    }
}

fn rule_view(rule: &RoutingRule) -> RuleView<'_> {
    let RoutingRule {
        id,
        priority,
        destination,
        domain_suffix,
        port,
        action,
        require_attestation,
    } = rule;
    RuleView {
        id,
        priority: *priority,
        destination: destination.as_deref(),
        domain_suffix: domain_suffix.as_deref(),
        port: *port,
        action: action_label(action),
        require_attestation: *require_attestation,
    }
}

/// `direct`, `deny` or `adapter:<id>`. Ids never contain `:` (`valid_id`), so
/// the label cannot be forged by an id.
fn action_label(action: &RoutingAction) -> String {
    match action {
        RoutingAction::Direct => "direct".to_owned(),
        RoutingAction::Deny => "deny".to_owned(),
        RoutingAction::Adapter { adapter_id } => format!("adapter:{adapter_id}"),
    }
}

fn rule_row(rule: &RoutingRule) -> RuleRow {
    RuleRow {
        id: rule.id.clone(),
        priority: rule.priority,
        action: action_label(&rule.action),
        attestation: rule.require_attestation,
        exact_destination: rule.destination.is_some(),
        suffix: rule.domain_suffix.is_some(),
        port: rule.port,
    }
}

fn ingress_view(ingress: &IngressConfig) -> IngressView {
    let IngressConfig {
        enabled,
        listen,
        protocols,
        hardening,
        arm_on_start,
        direct_address_families,
        limits,
        audit,
    } = ingress;
    let IngressListen { address, port } = listen;
    let IngressLimits {
        max_connections,
        accept_rate_per_s,
        handshake_timeout_ms,
        connect_timeout_ms,
        idle_timeout_ms,
    } = limits;
    let IngressAuditConfig {
        segment_mib,
        retain_segments,
        destination_logging,
    } = audit;
    IngressView {
        version: FINGERPRINT_VERSION,
        enabled: *enabled,
        listen: ListenView {
            address: address.to_string(),
            port: *port,
        },
        // File order: with one protocol there is no other order. When a second
        // protocol exists, decide here whether the order of the list matters.
        protocols: protocols
            .iter()
            .map(|protocol| match protocol {
                IngressProtocol::Socks5 => "socks5",
            })
            .collect(),
        hardening: match hardening {
            IngressHardening::Required => "required",
            IngressHardening::BestEffort => "best_effort",
        },
        arm_on_start: *arm_on_start,
        direct_address_families: match direct_address_families {
            DirectAddressFamilies::Ipv4Only => "ipv4_only",
            DirectAddressFamilies::Any => "any",
        },
        limits: LimitsView {
            max_connections: *max_connections,
            accept_rate_per_s: *accept_rate_per_s,
            handshake_timeout_ms: *handshake_timeout_ms,
            connect_timeout_ms: *connect_timeout_ms,
            idle_timeout_ms: *idle_timeout_ms,
        },
        audit: AuditView {
            segment_mib: *segment_mib,
            retain_segments: *retain_segments,
            destination_logging: match destination_logging {
                DestinationLogging::Plain => "plain",
                DestinationLogging::Hashed => "hashed",
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_types::canonical_bytes;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// The layer under the hash, as text a reviewer can decode by hand: a CBOR
    /// map of text keys in the views' field order, the shortest integer forms,
    /// no indefinite lengths. The golden digests in `tests/fingerprint.rs` say
    /// that something changed; these say what. Skipped by rustfmt so that each
    /// key stays next to its comment.
    #[rustfmt::skip]
    #[test]
    fn the_default_views_have_this_exact_canonical_encoding() {
        let routing = canonical_bytes(&routing_view(&RoutingConfig::default()))
            .expect("a view serialises");
        assert_eq!(
            hex(&routing),
            concat!(
                "a4", // map(4)
                "6776657273696f6e", "01", // "version": 1
                "6f64656661756c745f70726f66696c65", "6764656661756c74", // "default_profile": "default"
                "686164617074657273", "80", // "adapters": []
                "6870726f66696c6573", "81", // "profiles": [
                "a2", "626964", "6764656661756c74", // {"id": "default",
                "6572756c6573", "80", // "rules": []}]
            )
        );
        let ingress =
            canonical_bytes(&ingress_view(&IngressConfig::default())).expect("a view serialises");
        assert_eq!(
            hex(&ingress),
            concat!(
                "a9", // map(9)
                "6776657273696f6e", "01", // "version": 1
                "67656e61626c6564", "f4", // "enabled": false
                "666c697374656e", "a2", // "listen": {
                "6761646472657373", "693132372e302e302e31", //   "address": "127.0.0.1"
                "64706f7274", "192a30", //   "port": 10800 }
                "6970726f746f636f6c73", "81", "66736f636b7335", // "protocols": ["socks5"]
                "6968617264656e696e67", "687265717569726564", // "hardening": "required"
                "6c61726d5f6f6e5f7374617274", "f4", // "arm_on_start": false
                "776469726563745f616464726573735f66616d696c696573", "69697076345f6f6e6c79", // "direct_address_families": "ipv4_only"
                "666c696d697473", "a5", // "limits": {
                "6f6d61785f636f6e6e656374696f6e73", "190100", //   "max_connections": 256
                "716163636570745f726174655f7065725f73", "1832", //   "accept_rate_per_s": 50
                "7468616e647368616b655f74696d656f75745f6d73", "192710", //   "handshake_timeout_ms": 10000
                "72636f6e6e6563745f74696d656f75745f6d73", "194e20", //   "connect_timeout_ms": 20000
                "6f69646c655f74696d656f75745f6d73", "1a0036ee80", //   "idle_timeout_ms": 3600000 }
                "656175646974", "a3", // "audit": {
                "6b7365676d656e745f6d6962", "1820", //   "segment_mib": 32
                "6f72657461696e5f7365676d656e7473", "08", //   "retain_segments": 8
                "7364657374696e6174696f6e5f6c6f6767696e67", "65706c61696e", //   "destination_logging": "plain" }
            )
        );
    }
}
