//! Operational routing configuration. No rule match means no egress.
use crate::ConfigError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    pub default_profile: String,
    pub profiles: Vec<RoutingProfile>,
    pub adapters: Vec<RoutingAdapter>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            default_profile: "default".into(),
            profiles: vec![RoutingProfile {
                id: "default".into(),
                name: "Default (deny until configured)".into(),
                rules: vec![],
            }],
            adapters: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoutingProfile {
    pub id: String,
    pub name: String,
    pub rules: Vec<RoutingRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoutingAdapter {
    pub id: String,
    pub transport: AdapterTransport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdapterTransport {
    Socks5 {
        host: String,
        port: u16,
    },
    HttpConnect {
        host: String,
        port: u16,
    },
    TlsTunnel {
        host: String,
        port: u16,
    },
    /// Reference to a broker-owned profile, never a path or command line.
    /// Reserved: activation fails explicitly until broker integration ships.
    OpenVpn {
        profile_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoutingRule {
    pub id: String,
    pub priority: u32,
    /// Exact hostname or literal IP. No DNS resolution occurs during matching.
    /// A numeric alias (`127.1`) and an IPv4-mapped IPv6 literal are refused:
    /// write the dotted-quad IPv4 address.
    #[serde(default)]
    pub destination: Option<String>,
    /// Domain itself and subdomains, matched on label boundaries. A DNS name
    /// whose last label starts with a letter, never an address.
    #[serde(default)]
    pub domain_suffix: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    pub action: RoutingAction,
    #[serde(default)]
    pub require_attestation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RoutingAction {
    Direct,
    Deny,
    Adapter { adapter_id: String },
}

#[must_use]
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

#[must_use]
pub fn valid_host(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok() || valid_domain(host)
}

fn valid_domain(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        // The OS resolver dials `127.1`, `0x7f.0.0.1`, `010.0.0.1` and
        // `2130706433` as IPv4 addresses, yet `IpAddr` refuses to parse them, so
        // the label grammar alone takes them for names. Every such spelling ends
        // in a label that starts with a digit and a real TLD never does
        // (punycode `xn--` starts with a letter): one rule keeps them out of
        // destinations, suffixes and adapter hosts. Keep it equal to
        // `is_address_form` in ssk-netadmin's policy.rs; the shared host corpus
        // test pins both.
        && host
            .rsplit('.')
            .next()
            .is_some_and(|label| label.starts_with(|c: char| c.is_ascii_alphabetic()))
}

/// `true` for `::ffff:a.b.c.d` in any spelling. Deliberately not
/// `Ipv6Addr::to_ipv4`, which also turns `::1` into 0.0.0.1.
fn is_ipv4_mapped(host: &str) -> bool {
    matches!(
        host.parse::<std::net::IpAddr>(),
        Ok(std::net::IpAddr::V6(ip)) if ip.to_ipv4_mapped().is_some()
    )
}

impl RoutingConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |message: &str| ConfigError::Routing(message.into());
        let mut adapters = BTreeSet::new();
        for adapter in &self.adapters {
            if !valid_id(&adapter.id) || !adapters.insert(adapter.id.as_str()) {
                return Err(invalid("adapter IDs must be valid and unique"));
            }
            match &adapter.transport {
                AdapterTransport::Socks5 { host, port }
                | AdapterTransport::HttpConnect { host, port }
                | AdapterTransport::TlsTunnel { host, port } => {
                    if !valid_host(host) || *port == 0 {
                        return Err(invalid(
                            "adapter requires a valid host and nonzero port (a DNS name must end in a label that starts with a letter)",
                        ));
                    }
                }
                AdapterTransport::OpenVpn { profile_id } if !valid_id(profile_id) => {
                    return Err(invalid("OpenVPN requires a broker-managed profile ID"));
                }
                AdapterTransport::OpenVpn { .. } => {}
            }
        }
        let mut profiles = BTreeSet::new();
        for profile in &self.profiles {
            if !valid_id(&profile.id)
                || !profiles.insert(profile.id.as_str())
                || profile.name.trim().is_empty()
            {
                return Err(invalid(
                    "profiles require unique valid IDs and nonempty names",
                ));
            }
            let mut rules = BTreeSet::new();
            let mut priorities = BTreeSet::new();
            for rule in &profile.rules {
                if !valid_id(&rule.id)
                    || !rules.insert(rule.id.as_str())
                    || !priorities.insert(rule.priority)
                {
                    return Err(invalid(
                        "rule IDs and priorities must be unique within a profile",
                    ));
                }
                // `::ffff:10.0.0.1` is the address 10.0.0.1 spelled a second way.
                // Policy compares two literals by parsed value and the two are
                // not equal, so a deny rule written like this never fires on
                // the plain IPv4 flow. Refuse it; the IPv4 form is the rule.
                if rule.destination.as_deref().is_some_and(is_ipv4_mapped) {
                    return Err(invalid(
                        "rule destination must not be an IPv4-mapped IPv6 address; write the IPv4 address",
                    ));
                }
                if rule
                    .destination
                    .as_ref()
                    .is_some_and(|host| !valid_host(host))
                    || rule.domain_suffix.as_ref().is_some_and(|host| {
                        !valid_domain(host) || host.parse::<std::net::IpAddr>().is_ok()
                    })
                    || rule.port == Some(0)
                {
                    return Err(invalid(
                        "invalid rule destination, domain suffix or port (a DNS name must end in a label that starts with a letter)",
                    ));
                }
                if let RoutingAction::Adapter { adapter_id } = &rule.action {
                    if !adapters.contains(adapter_id.as_str()) {
                        return Err(invalid("rule refers to an unknown adapter"));
                    }
                }
            }
        }
        if !profiles.contains(self.default_profile.as_str()) {
            return Err(invalid(
                "default_profile must refer to a configured profile",
            ));
        }
        Ok(())
    }
}

pub(crate) fn schema_json() -> serde_json::Value {
    use serde_json::json;
    let id = json!({"type":"string", "pattern":"^[a-z0-9][a-z0-9._-]{0,63}$"});
    let port = json!({"type":"integer", "minimum":1, "maximum":65535});
    let host = json!({"type":"string", "minLength":1, "maxLength":254});
    let mut transports: Vec<_> = ["socks5", "http_connect", "tls_tunnel"]
        .iter()
        .map(|kind| {
            json!({
                "type":"object", "additionalProperties":false, "required":["kind","host","port"],
                "properties":{"kind":{"const":kind}, "host":host, "port":port}
            })
        })
        .collect();
    transports.push(json!({
        "type":"object", "additionalProperties":false, "required":["kind","profile_id"],
        "properties":{"kind":{"const":"open_vpn"}, "profile_id":id}
    }));
    let rules = json!({
                    "type":"array","items":{
                        "type":"object","additionalProperties":false,"required":["id","priority","action"],
                        "properties":{
                            "id":id, "priority":{"type":"integer","minimum":0,"maximum":4294967295_u64},
                            "destination":{"anyOf":[host,{"type":"null"}]},
                            "domain_suffix":{"anyOf":[host,{"type":"null"}]},
                            "port":{"anyOf":[port,{"type":"null"}]},
                            "require_attestation":{"type":"boolean","default":false},
                            "action":{"oneOf":[
                                {"type":"object","additionalProperties":false,"required":["kind"],"properties":{"kind":{"enum":["direct","deny"]}}},
                                {"type":"object","additionalProperties":false,"required":["kind","adapter_id"],"properties":{"kind":{"const":"adapter"},"adapter_id":id}}
                            ]}
                        }
                    }
    });
    json!({
        "type":"object", "additionalProperties":false,
        "required":["default_profile","profiles","adapters"],
        "properties": {
            "default_profile":id,
            "adapters":{"type":"array","items":{
                "type":"object","additionalProperties":false,"required":["id","transport"],
                "properties":{"id":id,"transport":{"oneOf":transports}}
            }},
            "profiles":{"type":"array","minItems":1,"items":{
                "type":"object","additionalProperties":false,"required":["id","name","rules"],
                "properties":{"id":id,"name":{"type":"string","minLength":1},"rules":rules}
            }}
        }
    })
}
