//! The `ingress` section: the local proxy listener (design 5).
//!
//! The section opens a socket on the operator's machine, so it is written to
//! fail closed. Every struct denies unknown keys and every field has a default:
//! without the first, a typo would silently keep a default while the operator
//! believes otherwise; without the second, a v5 document could not be as short
//! as `ingress: {}`, which is a valid and disabled section. The section itself is
//! required, so a v5 document states its stance explicitly (as `routing` does).
//!
//! No key names a VPN, an interface, a source address, a credential or an
//! egress: the proxy's `Direct` dial binds none of them, the operating system's
//! routing table decides, and a key would imply Kaleidoscorp controls that
//! (design 5.2; `ingress_schema_has_no_credential_vpn_or_interface_keys`).
use crate::routing::{AdapterTransport, RoutingConfig};
use crate::ConfigError;
use serde::de::value::MapAccessDeserializer;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;

/// A number of the section: where it lives, what it defaults to and the range
/// that `validate` and the exported schema both accept. The numbers exist here
/// and nowhere else; the `Default` impls, the schema, the error messages and the
/// header of `docs/examples/ingress.example.yaml` all read this table, and the
/// golden schema file pins the result. They are judgments, not measurements
/// (design 5.1); a default is part of the contract once a release is tagged, and
/// changing one then needs a version bump (5.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    /// Dotted path below `ingress`, as an operator writes it.
    pub key: &'static str,
    pub default: u32,
    pub range: RangeInclusive<u32>,
}

impl Bound {
    const fn new(key: &'static str, default: u32, floor: u32, ceiling: u32) -> Self {
        Self {
            key,
            default,
            range: floor..=ceiling,
        }
    }

    fn check(&self, got: u32) -> Result<(), ConfigError> {
        if self.range.contains(&got) {
            return Ok(());
        }
        // Zero is below every floor here and is the usual spelling of "no limit"
        // elsewhere; say once that it is not.
        let zero = if got == 0 {
            "; 0 never means unlimited"
        } else {
            ""
        };
        Err(ConfigError::Ingress(format!(
            "ingress.{} must be within {}..={} (got {got}){zero}",
            self.key,
            self.range.start(),
            self.range.end()
        )))
    }
}

/// The table: every bounded number of the section, in document order.
pub mod bounds {
    use super::Bound;

    /// Open tunnels. Each costs two descriptors; the effective value is to be clamped
    /// to the descriptor budget at start (design 7.3), so a higher value is safe.
    pub const MAX_CONNECTIONS: Bound = Bound::new("limits.max_connections", 256, 1, 4096);
    /// Sustained rate of new admitted connections; the burst is `max_connections`.
    pub const ACCEPT_RATE_PER_S: Bound = Bound::new("limits.accept_rate_per_s", 50, 1, 10_000);
    /// The whole client handshake. The floor is low enough for a test to use 300 ms.
    pub const HANDSHAKE_TIMEOUT_MS: Bound =
        Bound::new("limits.handshake_timeout_ms", 10_000, 100, 60_000);
    /// The whole upstream dial including name resolution. The default equals the
    /// activation deadline so both paths give up together.
    pub const CONNECT_TIMEOUT_MS: Bound =
        Bound::new("limits.connect_timeout_ms", 20_000, 100, 120_000);
    /// No byte either way. An hour keeps idle SSH and database sessions alive.
    pub const IDLE_TIMEOUT_MS: Bound =
        Bound::new("limits.idle_timeout_ms", 3_600_000, 100, 86_400_000);
    /// Size of one ledger segment.
    pub const SEGMENT_MIB: Bound = Bound::new("audit.segment_mib", 32, 1, 256);
    /// Segments kept. Retention is by size only (the owner's decision): there is
    /// no age ceiling and no key for one.
    pub const RETAIN_SEGMENTS: Bound = Bound::new("audit.retain_segments", 8, 2, 64);

    /// The ledger the section may retain, `segment_mib x retain_segments`. Opening
    /// the ledger verifies everything retained, so this bounds start-up time.
    pub const MAX_LEDGER_MIB: u32 = 1024;

    /// Every `Bound`, for code that walks the table (tests, the example header).
    pub const ALL: [&Bound; 7] = [
        &MAX_CONNECTIONS,
        &ACCEPT_RATE_PER_S,
        &HANDSHAKE_TIMEOUT_MS,
        &CONNECT_TIMEOUT_MS,
        &IDLE_TIMEOUT_MS,
        &SEGMENT_MIB,
        &RETAIN_SEGMENTS,
    ];
}

/// Reads a section from a map and from nothing else. serde also reads a struct
/// from a sequence, in field order, and every field of the ingress structs has a
/// default: `ingress: []` would load as the defaults and `ingress: [true]` would
/// switch the listener on. No operator writes that on purpose and the exported
/// schema says `object`, so the sections refuse it instead of guessing.
pub(crate) fn map_only<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct MapOnly<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for MapOnly<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map")
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_map(MapOnly(PhantomData))
}

/// The product's own port: applications are configured once, so it is fixed.
/// 1080, the conventional SOCKS port, is the one every upstream-proxy example in
/// this repository uses and would collide with a local upstream (design 5.1).
/// Owner default, pending confirmation before the first release tag. `0` asks the
/// OS for a port, which tests use and the daemon reports once bound (5.7).
pub const DEFAULT_LISTEN_PORT: u16 = 10800;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct IngressConfig {
    /// An upgrade never opens a listener by itself.
    pub enabled: bool,
    #[serde(deserialize_with = "map_only")]
    pub listen: IngressListen,
    /// Names of the protocols the listener speaks; this build accepts `socks5`.
    pub protocols: Vec<IngressProtocol>,
    pub hardening: IngressHardening,
    /// A restart comes back disarmed unless the operator opts in; arms
    /// `routing.default_profile`. A `bool` and not an optional profile name:
    /// `null` cannot be written in TOML.
    pub arm_on_start: bool,
    pub direct_address_families: DirectAddressFamilies,
    #[serde(deserialize_with = "map_only")]
    pub limits: IngressLimits,
    #[serde(deserialize_with = "map_only")]
    pub audit: IngressAuditConfig,
}

impl Default for IngressConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: IngressListen::default(),
            protocols: vec![IngressProtocol::Socks5],
            hardening: IngressHardening::default(),
            arm_on_start: false,
            direct_address_families: DirectAddressFamilies::default(),
            limits: IngressLimits::default(),
            audit: IngressAuditConfig::default(),
        }
    }
}

/// An `Ipv4Addr` cannot spell a host name, IPv6, brackets, a zone, a port or a
/// numeric alias such as `127.1`, so the listener address needs no parser of ours.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct IngressListen {
    /// Loopback only (`127.0.0.0/8`).
    pub address: Ipv4Addr,
    pub port: u16,
}

impl Default for IngressListen {
    fn default() -> Self {
        Self {
            address: Ipv4Addr::LOCALHOST,
            port: DEFAULT_LISTEN_PORT,
        }
    }
}

/// What the listener does on a platform that cannot prove who connected to the
/// loopback port.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IngressHardening {
    /// The listener stays unavailable where the platform cannot check who connects
    /// (on Windows, until that check is verified): owner decision 1.
    #[default]
    Required,
    /// A visible operator choice.
    BestEffort,
}

/// Which address families a `Direct` dial may use. A dual-stack name dialled over
/// IPv6 may bypass a tunnel that does not cover IPv6; the price of the default is
/// that IPv6-only sites are unreachable through Direct until the operator sets
/// `any`. In the first version because adding the key later needs a new version.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectAddressFamilies {
    #[default]
    Ipv4Only,
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct IngressLimits {
    pub max_connections: u32,
    pub accept_rate_per_s: u32,
    pub handshake_timeout_ms: u32,
    pub connect_timeout_ms: u32,
    pub idle_timeout_ms: u32,
}

impl Default for IngressLimits {
    fn default() -> Self {
        Self {
            max_connections: bounds::MAX_CONNECTIONS.default,
            accept_rate_per_s: bounds::ACCEPT_RATE_PER_S.default,
            handshake_timeout_ms: bounds::HANDSHAKE_TIMEOUT_MS.default,
            connect_timeout_ms: bounds::CONNECT_TIMEOUT_MS.default,
            idle_timeout_ms: bounds::IDLE_TIMEOUT_MS.default,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct IngressAuditConfig {
    pub segment_mib: u32,
    pub retain_segments: u32,
    pub destination_logging: DestinationLogging,
}

impl Default for IngressAuditConfig {
    fn default() -> Self {
        Self {
            segment_mib: bounds::SEGMENT_MIB.default,
            retain_segments: bounds::RETAIN_SEGMENTS.default,
            destination_logging: DestinationLogging::default(),
        }
    }
}

/// What the ledger writes for the destination of an admitted flow (design 5.8).
/// Denials are always plaintext. Read at start; the ledger is append-only, so
/// records written before a switch to `hashed` stay plain until retention prunes
/// them. A third mode later (say `omitted`) is a compatible vocabulary extension.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DestinationLogging {
    /// Host and port in clear (the owner's default, pending confirmation).
    #[default]
    Plain,
    /// A keyed token instead of the host; the port stays in clear.
    Hashed,
}

/// A protocol the listener speaks, parsed from its name. A closed enum behind a
/// string so that an unsupported name is refused with a message that says what
/// this build does support, and adding `http_connect` later is one variant and
/// one entry of `SUPPORTED` (design 5.5), not a version bump: a file that does not
/// mention it means what it meant, and an older build refuses a file that does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum IngressProtocol {
    Socks5,
}

impl IngressProtocol {
    /// What this build can serve, in the order the error message lists it.
    pub const SUPPORTED: &'static [IngressProtocol] = &[IngressProtocol::Socks5];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
        }
    }

    fn supported_names() -> String {
        let names: Vec<&str> = Self::SUPPORTED.iter().map(|p| p.name()).collect();
        names.join(", ")
    }
}

impl TryFrom<String> for IngressProtocol {
    type Error = String;

    fn try_from(name: String) -> Result<Self, String> {
        Self::SUPPORTED
            .iter()
            .copied()
            .find(|protocol| protocol.name() == name)
            .ok_or_else(|| {
                format!(
                    "unsupported ingress protocol `{name}`; this build supports: {}",
                    Self::supported_names()
                )
            })
    }
}

impl From<IngressProtocol> for String {
    fn from(protocol: IngressProtocol) -> Self {
        protocol.name().to_owned()
    }
}

impl IngressConfig {
    /// Always runs, also when `enabled` is `false`: a section that becomes
    /// invalid the moment the flag flips must not be loadable now. An invalid
    /// section makes the whole file invalid (the daemon enters `ConfigInvalid`
    /// and no listener exists), the existing contract for every section.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |message: String| ConfigError::Ingress(message);
        if !self.listen.address.is_loopback() {
            return Err(invalid(format!(
                "ingress.listen.address must be an IPv4 loopback address (127.0.0.0/8), got {}",
                self.listen.address
            )));
        }
        if self.protocols.is_empty() {
            return Err(invalid(format!(
                "ingress.protocols must name at least one protocol; this build supports: {}",
                IngressProtocol::supported_names()
            )));
        }
        for (at, protocol) in self.protocols.iter().enumerate() {
            if self
                .protocols
                .iter()
                .take(at)
                .any(|earlier| earlier == protocol)
            {
                return Err(invalid(format!(
                    "ingress.protocols lists `{}` more than once",
                    protocol.name()
                )));
            }
        }
        bounds::MAX_CONNECTIONS.check(self.limits.max_connections)?;
        bounds::ACCEPT_RATE_PER_S.check(self.limits.accept_rate_per_s)?;
        bounds::HANDSHAKE_TIMEOUT_MS.check(self.limits.handshake_timeout_ms)?;
        bounds::CONNECT_TIMEOUT_MS.check(self.limits.connect_timeout_ms)?;
        bounds::IDLE_TIMEOUT_MS.check(self.limits.idle_timeout_ms)?;
        bounds::SEGMENT_MIB.check(self.audit.segment_mib)?;
        bounds::RETAIN_SEGMENTS.check(self.audit.retain_segments)?;
        let retained = u64::from(self.audit.segment_mib) * u64::from(self.audit.retain_segments);
        if retained > u64::from(bounds::MAX_LEDGER_MIB) {
            return Err(invalid(format!(
                "ingress.audit.segment_mib x ingress.audit.retain_segments must not exceed {} MiB \
                 (got {} x {} = {retained})",
                bounds::MAX_LEDGER_MIB,
                self.audit.segment_mib,
                self.audit.retain_segments
            )));
        }
        Ok(())
    }

    /// Checks of the section against the routing section it will run beside.
    ///
    /// Only an enabled section is checked. Every file written before v5 migrates
    /// to a disabled section on the default port and family filter, and an adapter
    /// on `127.0.0.1:10800` or an IPv6 literal host is legal in those files;
    /// refusing it after an upgrade, for a listener that never opens, would break
    /// the promise that old files keep loading. Flipping `enabled` makes the
    /// section subject to them, which `ssk config lint` reports before a restart.
    pub fn validate_against(&self, routing: &RoutingConfig) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        for adapter in &routing.adapters {
            let (AdapterTransport::Socks5 { host, port }
            | AdapterTransport::HttpConnect { host, port }
            | AdapterTransport::TlsTunnel { host, port }) = &adapter.transport
            else {
                continue;
            };
            // A static check against a known port; with port 0 it is repeated
            // against the real address once bound (design 5.3, 6.9.4). Deliberately
            // conservative: any loopback address of the same port counts, so a second
            // proxy on 127.0.0.2:<same port> is refused too.
            if self.listen.port != 0 && *port == self.listen.port && names_this_host(host) {
                return Err(ConfigError::Ingress(format!(
                    "routing adapter `{}` points at the ingress listener ({host}:{port}); \
                     the proxy would dial itself, give one of them another port",
                    adapter.id
                )));
            }
            // The first hop of a proxy chain obeys the same family filter as a
            // Direct dial (design 6.10): an IPv6 literal could never be dialled.
            if self.direct_address_families == DirectAddressFamilies::Ipv4Only
                && host.parse::<Ipv6Addr>().is_ok()
            {
                return Err(ConfigError::Ingress(format!(
                    "routing adapter `{}` has the IPv6 literal host `{host}` but \
                     ingress.direct_address_families is ipv4_only; write an IPv4 address \
                     or set direct_address_families: any",
                    adapter.id
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn schema_json() -> serde_json::Value {
        use serde_json::json;
        let number = |bound: &Bound| json!({"type": "integer", "minimum": bound.range.start(), "maximum": bound.range.end()});
        let protocols: Vec<&str> = IngressProtocol::SUPPORTED
            .iter()
            .map(|p| p.name())
            .collect();
        json!({
            "type": "object", "additionalProperties": false,
            "properties": {
                "enabled": {"type": "boolean"},
                "listen": {
                    "type": "object", "additionalProperties": false,
                    "properties": {
                        // The octets are range-checked by the parser; a pattern can
                        // say loopback and the shape without alternation.
                        "address": {"type": "string",
                                    "pattern": "^127\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$"},
                        "port": {"type": "integer", "minimum": 0, "maximum": u16::MAX}
                    }
                },
                // A list of distinct supported names, so never longer than that list.
                "protocols": {"type": "array", "minItems": 1, "maxItems": protocols.len(),
                              "items": {"type": "string", "enum": protocols}},
                "hardening": {"type": "string", "enum": ["required", "best_effort"]},
                "arm_on_start": {"type": "boolean"},
                "direct_address_families": {"type": "string", "enum": ["ipv4_only", "any"]},
                "limits": {
                    "type": "object", "additionalProperties": false,
                    "properties": {
                        "max_connections": number(&bounds::MAX_CONNECTIONS),
                        "accept_rate_per_s": number(&bounds::ACCEPT_RATE_PER_S),
                        "handshake_timeout_ms": number(&bounds::HANDSHAKE_TIMEOUT_MS),
                        "connect_timeout_ms": number(&bounds::CONNECT_TIMEOUT_MS),
                        "idle_timeout_ms": number(&bounds::IDLE_TIMEOUT_MS)
                    }
                },
                "audit": {
                    "type": "object", "additionalProperties": false,
                    "properties": {
                        "segment_mib": number(&bounds::SEGMENT_MIB),
                        "retain_segments": number(&bounds::RETAIN_SEGMENTS),
                        "destination_logging": {"type": "string", "enum": ["plain", "hashed"]}
                    }
                }
            }
        })
    }
}

/// `true` when dialling `host` reaches this machine's own loopback: `localhost`
/// in any case, an IPv4 loopback or unspecified literal (Linux connects to
/// `0.0.0.0` as to the local host), or the same address spelled as an IPv4-mapped
/// IPv6 literal, which `valid_host` accepts for an adapter and a dual-stack OS
/// dials as IPv4.
fn names_this_host(host: &str) -> bool {
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let local = |ip: Ipv4Addr| ip.is_loopback() || ip.is_unspecified();
    match name.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => local(ip),
        Ok(IpAddr::V6(ip)) => ip.to_ipv4_mapped().is_some_and(local),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppConfig;
    use serde_json::{json, Value};

    fn at<'a>(value: &'a Value, key: &str) -> &'a Value {
        key.split('.').fold(value, |node, step| &node[step])
    }

    fn section_with(key: &str, number: u64) -> Result<(), ConfigError> {
        let mut value = serde_json::to_value(IngressConfig::default()).expect("serialises");
        let (section, leaf) = key.split_once('.').expect("a dotted key");
        value[section][leaf] = json!(number);
        // Keep the ledger product within its limit so that the key under test is
        // the only thing that can be wrong.
        match key {
            "audit.segment_mib" => value["audit"]["retain_segments"] = json!(2),
            "audit.retain_segments" => value["audit"]["segment_mib"] = json!(1),
            _ => {}
        }
        serde_json::from_value::<IngressConfig>(value)
            .expect("a number of the right type")
            .validate()
    }

    /// The table is the only place the numbers are written: the defaults, the
    /// validator and the schema each read it. A key that one of them does not
    /// read, or reads from a copy, shows here.
    #[test]
    fn the_bounds_table_is_what_the_defaults_the_validator_and_the_schema_read() {
        let defaults = serde_json::to_value(IngressConfig::default()).expect("serialises");
        let schema = IngressConfig::schema_json();
        let mut keys: Vec<&str> = Vec::new();
        for bound in bounds::ALL {
            keys.push(bound.key);
            assert!(bound.range.contains(&bound.default), "{}", bound.key);
            assert_eq!(
                at(&defaults, bound.key),
                &json!(bound.default),
                "{}",
                bound.key
            );
            let (section, leaf) = bound.key.split_once('.').expect("a dotted key");
            let node = &schema["properties"][section]["properties"][leaf];
            assert_eq!(node["minimum"], json!(bound.range.start()), "{}", bound.key);
            assert_eq!(node["maximum"], json!(bound.range.end()), "{}", bound.key);
            // The validator enforces exactly this range, one step either side.
            let (floor, ceiling) = (
                u64::from(*bound.range.start()),
                u64::from(*bound.range.end()),
            );
            for edge in [floor, ceiling] {
                section_with(bound.key, edge)
                    .unwrap_or_else(|err| panic!("{} refused its edge {edge}: {err}", bound.key));
            }
            for outside in [floor - 1, ceiling + 1] {
                assert!(
                    section_with(bound.key, outside).is_err(),
                    "{} {outside}",
                    bound.key
                );
            }
        }
        // The table covers every number of the section and each exactly once.
        let mut numbers: Vec<String> = Vec::new();
        for (section, node) in defaults.as_object().expect("object") {
            if let Some(object) = node.as_object() {
                for (leaf, value) in object {
                    if value.is_u64() && !(section == "listen" && leaf == "port") {
                        numbers.push(format!("{section}.{leaf}"));
                    }
                }
            }
        }
        numbers.sort();
        keys.sort_unstable();
        assert_eq!(numbers, keys);
    }

    #[test]
    fn a_bound_error_names_the_key_the_range_and_that_zero_is_not_unlimited() {
        let err = bounds::MAX_CONNECTIONS.check(0).expect_err("zero");
        assert_eq!(
            err.to_string(),
            "invalid ingress configuration: ingress.limits.max_connections must be within \
             1..=4096 (got 0); 0 never means unlimited"
        );
        let err = bounds::RETAIN_SEGMENTS.check(1).expect_err("one");
        assert_eq!(
            err.to_string(),
            "invalid ingress configuration: ingress.audit.retain_segments must be within \
             2..=64 (got 1)"
        );
    }

    #[test]
    fn an_unsupported_protocol_is_refused_with_what_this_build_supports() {
        assert_eq!(
            IngressProtocol::try_from("socks5".to_owned()),
            Ok(IngressProtocol::Socks5)
        );
        assert_eq!(String::from(IngressProtocol::Socks5), "socks5");
        assert_eq!(
            IngressProtocol::try_from("http_connect".to_owned()),
            Err("unsupported ingress protocol `http_connect`; this build supports: socks5".into())
        );
        // The vocabulary is exact: no case folding, no trimming.
        for name in ["SOCKS5", " socks5", "socks5 ", "socks", ""] {
            assert!(
                IngressProtocol::try_from(name.to_owned()).is_err(),
                "{name:?}"
            );
        }
    }

    #[test]
    fn this_host_is_named_by_localhost_loopback_unspecified_and_their_mapped_forms() {
        for host in [
            "localhost",
            "LocalHost",
            "localhost.",
            "127.0.0.1",
            "127.255.255.254",
            "0.0.0.0",
            "::ffff:127.0.0.1",
            "::ffff:0.0.0.0",
        ] {
            assert!(names_this_host(host), "{host}");
        }
        // Another machine, another loopback family, or a name that merely contains it.
        for host in [
            "example.com",
            "192.0.2.1",
            "10.0.0.1",
            "::1",
            "::ffff:192.0.2.1",
            "notlocalhost",
            "localhost.example.com",
            "128.0.0.1",
        ] {
            assert!(!names_this_host(host), "{host}");
        }
    }

    #[test]
    fn the_default_section_validates_against_the_default_routing() {
        let config = AppConfig::default();
        assert!(config.ingress.validate().is_ok());
        assert!(config.ingress.validate_against(&config.routing).is_ok());
        assert!(!config.ingress.enabled);
    }
}
