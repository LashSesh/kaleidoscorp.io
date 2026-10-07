//! Target canonicalisation, the special-use table and the two address guards
//! (design 6.2). Pure: no I/O, no tokio, no clock.
//!
//! Every client-supplied destination becomes ONE canonical [`Target`] before
//! the policy engine, the audit writer or any log sees it. Without that, a rule
//! and a flow that name the same address in different spellings do not match
//! (`::1` against `[::1]`, `::ffff:10.0.0.1` against `10.0.0.1`), and the OS
//! dials spellings the policy never recognised (`127.1`, `2130706433`,
//! `0x7f.1` all reach 127.0.0.1 through `getaddrinfo`). A deny rule written in
//! one spelling would be bypassed by another.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::routing::RuleBinding;

/// What a front end read off the wire, untouched. `Name` carries the raw bytes
/// of a SOCKS5 ATYP 3 field (an HTTP CONNECT authority would feed the same
/// variant later); everything that decides what the bytes mean happens in
/// [`canonicalize`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawTarget {
    V4(Ipv4Addr, u16),
    V6(Ipv6Addr, u16),
    Name(Vec<u8>, u16),
}

/// A destination in its one canonical spelling.
///
/// The fields are private on purpose. `host`, `ip` and `kind` agreeing is the
/// whole point of this module (policy reads `host`, the dial reads `ip`), and
/// they agree because [`canonicalize`] is the only constructor: code that could
/// build a `Target` literal could make them diverge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Canonical text, never bracketed: a lower-case DNS name without a
    /// trailing dot, or `IpAddr::to_string()` of the literal.
    host: String,
    /// `Some` exactly when `kind` is not [`TargetKind::Name`].
    ip: Option<IpAddr>,
    port: u16,
    kind: TargetKind,
    provenance: Provenance,
}

impl Target {
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn ip(&self) -> Option<IpAddr> {
        self.ip
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub const fn kind(&self) -> TargetKind {
        self.kind
    }

    #[must_use]
    pub const fn provenance(&self) -> Provenance {
        self.provenance
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Ipv4,
    Ipv6,
    Name,
}

impl TargetKind {
    /// The closed set the ledger records.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Name => "name",
        }
    }
}

/// How the client supplied the destination: by the form it used on the wire,
/// not by what the text turned out to be. A client that sends the domain-typed
/// name `127.0.0.1.` supplied a name that canonicalises to a literal; the
/// ledger keeps both facts (`kind` says ipv4, this says name).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    ClientSuppliedLiteral,
    ClientSuppliedName,
}

impl Provenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientSuppliedLiteral => "client_supplied_literal",
            Self::ClientSuppliedName => "client_supplied_name",
        }
    }
}

/// Why a target is refused before (or right after) the policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Malformed,
    NumericAlias,
    LocalhostName,
    SelfLoop,
    SpecialUse(SpecialUse),
    SpecialUseNeedsPort(SpecialUse),
}

impl Refusal {
    /// The machine code counters, logs and `Denied` records use.
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::Malformed => "TARGET_MALFORMED",
            Self::NumericAlias => "TARGET_NUMERIC_ALIAS",
            Self::LocalhostName => "TARGET_LOCALHOST",
            Self::SelfLoop => "TARGET_SELF_LOOP",
            Self::SpecialUse(_) => "SPECIAL_USE_NEEDS_EXACT_RULE",
            Self::SpecialUseNeedsPort(_) => "SPECIAL_USE_NEEDS_PORT",
        }
    }
}

/// Address ranges that a proxy client must not reach by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialUse {
    Unspecified,
    ThisNetwork,
    Loopback,
    Private,
    SharedAddressSpace,
    LinkLocal,
    Metadata,
    Multicast,
    Reserved,
    Broadcast,
    Documentation,
    FakeIp,
    ProtocolAssignment,
    Translation,
    SiteLocal,
    Discard,
    DummyPrefix,
}

impl SpecialUse {
    pub const ALL: [Self; 17] = [
        Self::Unspecified,
        Self::ThisNetwork,
        Self::Loopback,
        Self::Private,
        Self::SharedAddressSpace,
        Self::LinkLocal,
        Self::Metadata,
        Self::Multicast,
        Self::Reserved,
        Self::Broadcast,
        Self::Documentation,
        Self::FakeIp,
        Self::ProtocolAssignment,
        Self::Translation,
        Self::SiteLocal,
        Self::Discard,
        Self::DummyPrefix,
    ];

    /// The closed, snake_case label the ledger and the status use.
    pub fn code(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::ThisNetwork => "this_network",
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::SharedAddressSpace => "shared_address_space",
            Self::LinkLocal => "link_local",
            Self::Metadata => "metadata",
            Self::Multicast => "multicast",
            Self::Reserved => "reserved",
            Self::Broadcast => "broadcast",
            Self::Documentation => "documentation",
            Self::FakeIp => "fake_ip",
            Self::ProtocolAssignment => "protocol_assignment",
            Self::Translation => "translation",
            Self::SiteLocal => "site_local",
            Self::Discard => "discard",
            Self::DummyPrefix => "dummy_prefix",
        }
    }
}

/// 255 bytes is the longest SOCKS5 domain field.
const MAX_NAME_BYTES: usize = 255;
/// DNS: 253 octets for a name (trailing dot not counted), 63 per label.
const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// An IPv4-mapped IPv6 address is the same host as its IPv4 form. Only the
/// strict `::ffff:a.b.c.d` range is unmapped. The other std conversion of an
/// IPv6 address to IPv4 also turns `::1` into 0.0.0.1, which is a different
/// host; a source scan keeps it out of this module tree.
fn unmap(ip: Ipv6Addr) -> IpAddr {
    match ip.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(ip),
    }
}

/// An address in its one spelling for comparison: the strict mapped IPv6 form
/// becomes IPv4, everything else is unchanged.
pub(crate) fn unmap_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => unmap(v6),
        IpAddr::V4(_) => ip,
    }
}

fn literal(ip: IpAddr, port: u16, provenance: Provenance) -> Target {
    Target {
        host: ip.to_string(),
        ip: Some(ip),
        port,
        kind: match ip {
            IpAddr::V4(_) => TargetKind::Ipv4,
            IpAddr::V6(_) => TargetKind::Ipv6,
        },
        provenance,
    }
}

/// One canonical target, or why there is none. Only `Malformed`,
/// `NumericAlias` and `LocalhostName` come out of here; the guards below
/// produce the other refusals. The order of the steps is part of the contract.
pub fn canonicalize(raw: RawTarget) -> Result<Target, Refusal> {
    match raw {
        // 1. A port of zero is not a destination.
        RawTarget::V4(_, 0) | RawTarget::V6(_, 0) | RawTarget::Name(_, 0) => {
            Err(Refusal::Malformed)
        }
        // 2. Literals: compressed lower-case text, no brackets, mapped IPv6
        //    folded into its IPv4 form.
        RawTarget::V4(ip, port) => Ok(literal(
            IpAddr::V4(ip),
            port,
            Provenance::ClientSuppliedLiteral,
        )),
        RawTarget::V6(ip, port) => Ok(literal(unmap(ip), port, Provenance::ClientSuppliedLiteral)),
        RawTarget::Name(bytes, port) => canonicalize_name(bytes, port),
    }
}

fn canonicalize_name(bytes: Vec<u8>, port: u16) -> Result<Target, Refusal> {
    // 3a. Printable ASCII only, 1..=255 bytes. NUL, controls, space, DEL and
    //     every non-ASCII byte are refused, so UTF-8 IDN never reaches the
    //     policy: policy compares ASCII text only, hence look-alike Unicode
    //     cannot create a match and no IDNA mapping can rewrite the host
    //     behind it. A-labels (`xn--`) are accepted as plain ASCII, undecoded.
    if bytes.is_empty()
        || bytes.len() > MAX_NAME_BYTES
        || !bytes.iter().all(|byte| (0x21..=0x7e).contains(byte))
    {
        return Err(Refusal::Malformed);
    }
    // 3b. Lower case.
    let lowered = String::from_utf8(bytes)
        .map_err(|_| Refusal::Malformed)?
        .to_ascii_lowercase();
    // 3c. Exactly one pair of brackets may wrap an IPv6 literal; what is inside
    //     must contain a colon (the rule of `ssk-netcore`'s `unbracket`).
    let text: &str = match lowered
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        Some(inner) if inner.contains(':') => inner,
        Some(_) => return Err(Refusal::Malformed),
        None => &lowered,
    };
    // 3d. A colon means IPv6: strict parse (a zone id fails it), or nothing.
    //     This is also what refuses `host:80` and `http://host`.
    if text.contains(':') {
        let ip = text.parse::<Ipv6Addr>().map_err(|_| Refusal::Malformed)?;
        return Ok(literal(unmap(ip), port, Provenance::ClientSuppliedName));
    }
    // 3e. Remove exactly one trailing dot.
    let name = text.strip_suffix('.').unwrap_or(text);
    if name.is_empty() || name.ends_with('.') {
        return Err(Refusal::Malformed);
    }
    // 3f. A strict dotted quad (four decimal octets, no leading zeros) is a
    //     literal, whichever way the client typed it.
    if let Ok(ip) = name.parse::<Ipv4Addr>() {
        return Ok(literal(
            IpAddr::V4(ip),
            port,
            Provenance::ClientSuppliedName,
        ));
    }
    // 3g. DNS label grammar: 1..=253 bytes, labels of 1..=63 bytes, letters,
    //     digits and inner hyphens. Underscores and everything else are
    //     refused (a stated limitation, design 6.10).
    if name.len() > MAX_NAME_LEN || !name.split('.').all(valid_label) {
        return Err(Refusal::Malformed);
    }
    // 3h. The FINAL label must start with a letter. One rule kills every
    //     `inet_aton` spelling (decimal, octal, hex, short, single integer):
    //     each of them ends in a component that starts with a digit, and a
    //     real top-level domain never does.
    let final_label = name.rsplit('.').next().unwrap_or(name);
    if !final_label
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
    {
        return Err(Refusal::NumericAlias);
    }
    // 3i. `localhost` and `*.localhost` are the local host under any resolver.
    if name == "localhost" || name.ends_with(".localhost") {
        return Err(Refusal::LocalhostName);
    }
    Ok(Target {
        host: name.to_owned(),
        ip: None,
        port,
        kind: TargetKind::Name,
        provenance: Provenance::ClientSuppliedName,
    })
}

fn valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    bytes.len() <= MAX_LABEL_LEN
        && first.is_ascii_alphanumeric()
        && last.is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

/// Which special-use range an address belongs to, if any. An IPv4-mapped IPv6
/// address is unmapped first.
///
/// IPv6 fails closed: everything outside the global unicast block 2000::/3 that
/// is not otherwise named is `Reserved` (no destination lives there), and the
/// whole 64:ff9b::/96 NAT64 range needs an exact rule. When the embedded IPv4
/// address is itself special-use the refusal names that reason; otherwise it
/// is `Translation`. Never "not special": `64:ff9b::808:808` reaches 8.8.8.8
/// through a translator, but it is a different spelling from `8.8.8.8` and a
/// deny rule for the IPv4 address does not match it.
///
/// The prefixes follow the IANA special-purpose registries (checked against the
/// registry XML on 2026-10-07, which lists `100:0:0:1::/64`, RFC 9780); there is
/// no registry lookup at run time.
pub fn classify_ip(ip: IpAddr) -> Option<SpecialUse> {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => classify_v4(v4),
            None => classify_v6(v6),
        },
    }
}

fn classify_v4(ip: Ipv4Addr) -> Option<SpecialUse> {
    let bits = u32::from(ip);
    let in_net = |net: u32, mask: u32| bits & mask == net;
    if bits == 0 {
        Some(SpecialUse::Unspecified)
    } else if in_net(0x0000_0000, 0xff00_0000) {
        Some(SpecialUse::ThisNetwork)
    } else if in_net(0x7f00_0000, 0xff00_0000) {
        Some(SpecialUse::Loopback)
    } else if in_net(0x0a00_0000, 0xff00_0000)
        || in_net(0xac10_0000, 0xfff0_0000)
        || in_net(0xc0a8_0000, 0xffff_0000)
    {
        Some(SpecialUse::Private)
    } else if in_net(0x6440_0000, 0xffc0_0000) {
        Some(SpecialUse::SharedAddressSpace)
    } else if bits == 0xa9fe_a9fe {
        // 169.254.169.254, checked before the link-local range it sits in.
        Some(SpecialUse::Metadata)
    } else if in_net(0xa9fe_0000, 0xffff_0000) {
        Some(SpecialUse::LinkLocal)
    } else if in_net(0xe000_0000, 0xf000_0000) {
        Some(SpecialUse::Multicast)
    } else if bits == u32::MAX {
        Some(SpecialUse::Broadcast)
    } else if in_net(0xf000_0000, 0xf000_0000) {
        Some(SpecialUse::Reserved)
    } else if in_net(0xc000_0200, 0xffff_ff00)
        || in_net(0xc633_6400, 0xffff_ff00)
        || in_net(0xcb00_7100, 0xffff_ff00)
    {
        Some(SpecialUse::Documentation)
    } else if in_net(0xc612_0000, 0xfffe_0000) {
        Some(SpecialUse::FakeIp)
    } else if in_net(0xc000_0000, 0xffff_ff00) {
        Some(SpecialUse::ProtocolAssignment)
    } else if in_net(0xc058_6300, 0xffff_ff00) {
        Some(SpecialUse::Translation)
    } else {
        None
    }
}

fn classify_v6(ip: Ipv6Addr) -> Option<SpecialUse> {
    let [a, b, c, d, e, f, g, h] = ip.segments();
    let low_six_zero = b == 0 && c == 0 && d == 0 && e == 0 && f == 0;
    if a == 0 && low_six_zero && g == 0 && h == 0 {
        Some(SpecialUse::Unspecified)
    } else if a == 0 && low_six_zero && g == 0 && h == 1 {
        Some(SpecialUse::Loopback)
    } else if a == 0x64 && b == 0xff9b && c == 0 && d == 0 && e == 0 && f == 0 {
        // NAT64 well-known prefix. Always special; the embedded IPv4 address
        // only decides which reason is named.
        let [hi_a, hi_b] = g.to_be_bytes();
        let [lo_a, lo_b] = h.to_be_bytes();
        classify_v4(Ipv4Addr::new(hi_a, hi_b, lo_a, lo_b)).or(Some(SpecialUse::Translation))
    } else if a == 0x64 && b == 0xff9b && c == 1 {
        // 64:ff9b:1::/48, the local-use NAT64 prefix.
        Some(SpecialUse::Translation)
    } else if a & 0xfe00 == 0xfc00 {
        Some(SpecialUse::Private)
    } else if a & 0xffc0 == 0xfe80 {
        Some(SpecialUse::LinkLocal)
    } else if a & 0xffc0 == 0xfec0 {
        Some(SpecialUse::SiteLocal)
    } else if a & 0xff00 == 0xff00 {
        Some(SpecialUse::Multicast)
    } else if (a == 0x2001 && b == 0x0db8) || (a == 0x3fff && b & 0xf000 == 0) {
        Some(SpecialUse::Documentation)
    } else if a == 0x2001 && b & 0xfe00 == 0 {
        // 2001::/23, which covers Teredo (2001::/32).
        Some(SpecialUse::ProtocolAssignment)
    } else if a == 0x2002 {
        // 6to4.
        Some(SpecialUse::Translation)
    } else if a == 0x100 && b == 0 && c == 0 && d == 0 {
        Some(SpecialUse::Discard)
    } else if a == 0x100 && b == 0 && c == 0 && d == 1 {
        // 100:0:0:1::/64, the dummy IPv6 prefix of RFC 9780.
        Some(SpecialUse::DummyPrefix)
    } else if a & 0xe000 != 0x2000 {
        // Outside 2000::/3 and not named above: nothing is allocated there.
        // That is ::/8 (the deprecated IPv4-compatible ::/96, the IPv4-translated
        // ::ffff:0:0:0/96; the IPv4-mapped ::ffff:0:0/96 never gets here,
        // `classify_ip` unmaps it), 100::/8 apart from its two named /64s,
        // 5f00::/16 (SRv6 SIDs), 4000::/2, 8000::/1 and so on.
        Some(SpecialUse::Reserved)
    } else {
        None
    }
}

/// Runs BEFORE the policy and no rule can override it: a literal that points
/// back at the listener would make the proxy connect to itself and exhaust its
/// descriptors. A superset of the one address that could loop (`0.0.0.0:port`
/// connects to the local host on Linux), harmless otherwise. A name cannot be
/// checked before resolution; the resolved-address guard of the ingress
/// executor (`guard::IngressDirectGuard`) covers a name that resolves to
/// loopback or to the listener. A name routed through an upstream proxy is
/// resolved there and cannot be checked locally (design 6.11).
pub fn guard_self_loop(target: &Target, listener: SocketAddr) -> Result<(), Refusal> {
    let Some(ip) = target.ip else {
        return Ok(());
    };
    if target.port == listener.port()
        && (ip == listener.ip() || ip.is_loopback() || ip.is_unspecified())
    {
        return Err(Refusal::SelfLoop);
    }
    Ok(())
}

/// Runs AFTER the policy decision, because it needs the matched rule. A
/// literal in a special-use range is allowed ONLY when the matching rule names
/// exactly that address and port (`RuleBinding::Exact`). A rule with the
/// address but no port, a port-only rule, a suffix rule, a deny rule, or an
/// exact rule that is not the first match never opens one. Names are never
/// exempt: the exemption names an address and a name's address is not known
/// before the dial.
pub fn guard_special_use(target: &Target, binding: RuleBinding) -> Result<(), Refusal> {
    let Some(ip) = target.ip else {
        return Ok(());
    };
    let Some(special) = classify_ip(ip) else {
        return Ok(());
    };
    match binding {
        RuleBinding::Exact {
            ip: rule_ip,
            port: rule_port,
        } if rule_ip == ip && rule_port == target.port => Ok(()),
        RuleBinding::ExactWithoutPort => Err(Refusal::SpecialUseNeedsPort(special)),
        RuleBinding::NoExactDestination | RuleBinding::Exact { .. } => {
            Err(Refusal::SpecialUse(special))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // The shared table of host spellings (config, policy, resolver and this
    // module read the same one).
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/support/host_corpus.rs"
    ));

    fn name(text: &str) -> Result<Target, Refusal> {
        canonicalize(RawTarget::Name(text.as_bytes().to_vec(), 443))
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address")
    }

    fn host_of(text: &str) -> String {
        name(text).expect("canonical").host
    }

    #[test]
    fn port_zero_is_malformed_for_every_form() {
        let v4 = RawTarget::V4(Ipv4Addr::LOCALHOST, 0);
        let v6 = RawTarget::V6(Ipv6Addr::LOCALHOST, 0);
        let nm = RawTarget::Name(b"example.com".to_vec(), 0);
        for raw in [v4, v6, nm] {
            assert_eq!(canonicalize(raw), Err(Refusal::Malformed));
        }
    }

    #[test]
    fn typed_literals_canonicalise_and_fold_mapped_ipv6() {
        let cases = [
            (
                RawTarget::V4(Ipv4Addr::new(10, 0, 0, 1), 80),
                "10.0.0.1",
                TargetKind::Ipv4,
            ),
            (
                RawTarget::V6(Ipv6Addr::LOCALHOST, 80),
                "::1",
                TargetKind::Ipv6,
            ),
            (
                RawTarget::V6("2001:DB8:0:0:0:0:0:A".parse().unwrap(), 80),
                "2001:db8::a",
                TargetKind::Ipv6,
            ),
            (
                // IPv4-mapped IPv6 is the same host as its IPv4 form.
                RawTarget::V6("::ffff:10.0.0.1".parse().unwrap(), 80),
                "10.0.0.1",
                TargetKind::Ipv4,
            ),
        ];
        for (raw, host, kind) in cases {
            let target = canonicalize(raw.clone()).expect("literal");
            assert_eq!((target.host.as_str(), target.kind), (host, kind), "{raw:?}");
            assert_eq!(target.provenance, Provenance::ClientSuppliedLiteral);
            assert!(target.ip.is_some());
        }
    }

    #[test]
    fn the_plain_ipv6_loopback_is_not_turned_into_an_ipv4_address() {
        // The lossy std conversion would answer 0.0.0.1 for ::1 and 0.0.0.0 for ::.
        let target = canonicalize(RawTarget::V6(Ipv6Addr::LOCALHOST, 80)).expect("literal");
        assert_eq!(target.ip, Some(ip("::1")));
        let target = canonicalize(RawTarget::V6(Ipv6Addr::UNSPECIFIED, 80)).expect("literal");
        assert_eq!(target.ip, Some(ip("::")));
    }

    #[test]
    fn every_spelling_of_one_address_gives_the_same_canonical_host() {
        let loopback6 = [
            "::1",
            "[::1]",
            "0:0:0:0:0:0:0:1",
            "[0:0:0:0:0:0:0:1]",
            "0000:0000:0000:0000:0000:0000:0000:0001",
        ];
        for spelling in loopback6 {
            assert_eq!(host_of(spelling), "::1", "{spelling}");
        }
        // The IPv4 forms, including the domain-typed one with a trailing dot
        // and the mapped IPv6 spellings of the same address.
        for spelling in [
            "10.0.0.1",
            "10.0.0.1.",
            "::ffff:10.0.0.1",
            "[::ffff:10.0.0.1]",
            "::FFFF:10.0.0.1",
            "::ffff:a00:1",
            "0:0:0:0:0:ffff:10.0.0.1",
        ] {
            assert_eq!(host_of(spelling), "10.0.0.1", "{spelling}");
        }
        let v4 = canonicalize(RawTarget::V4(Ipv4Addr::new(10, 0, 0, 1), 443)).unwrap();
        let v6 = canonicalize(RawTarget::V6("::ffff:10.0.0.1".parse().unwrap(), 443)).unwrap();
        assert_eq!(v4.host, v6.host);
        assert_eq!(v4.ip, v6.ip);
    }

    #[test]
    fn a_name_is_lower_cased_and_loses_one_trailing_dot() {
        assert_eq!(host_of("EXAMPLE.COM"), "example.com");
        assert_eq!(host_of("Api.Corp.Example."), "api.corp.example");
        let target = name("Example.Com").unwrap();
        assert_eq!(target.kind, TargetKind::Name);
        assert_eq!(target.ip, None);
        assert_eq!(target.provenance, Provenance::ClientSuppliedName);
        assert_eq!(target.port, 443);
    }

    #[test]
    fn a_name_that_is_really_an_address_keeps_both_facts() {
        let target = name("127.0.0.1.").unwrap();
        assert_eq!(target.kind, TargetKind::Ipv4);
        assert_eq!(target.ip, Some(ip("127.0.0.1")));
        assert_eq!(target.provenance, Provenance::ClientSuppliedName);
    }

    #[test]
    fn numeric_aliases_are_refused_whatever_the_spelling() {
        for text in [
            "127.1",
            "127.0.1",
            "0.1",
            "1",
            "0",
            "0x7f.0.0.1",
            "0X7F.0.0.1",
            "0x7f.1",
            "010.0.0.1",
            "0177.0.0.1",
            "2130706433",
            "0x7f000001",
            "2852039166",
            "127.1.",
            "256.256.256.256",
            "1.2.3.4.5",
            "intranet.3com",
        ] {
            assert_eq!(name(text), Err(Refusal::NumericAlias), "{text}");
        }
    }

    #[test]
    fn localhost_is_refused_in_every_form() {
        for text in [
            "localhost",
            "LOCALHOST",
            "localhost.",
            "foo.localhost",
            "a.b.localhost.",
        ] {
            assert_eq!(name(text), Err(Refusal::LocalhostName), "{text}");
        }
        // Only the label `localhost` itself, and only as the last one.
        assert!(name("localhost.example").is_ok());
        assert!(name("notlocalhost").is_ok());
        assert!(name("mylocalhost.com").is_ok());
    }

    #[test]
    fn hostile_names_are_malformed() {
        let mut cases: Vec<Vec<u8>> = [
            "",
            ".",
            "..",
            "a..b",
            ".example.com",
            "example.com..",
            "-a.example",
            "a-.example",
            "a_b.example",
            "exa mple.com",
            " example.com",
            "example.com\n",
            "example.com\r\nHost: evil",
            "example.com:443",
            "1.2.3.4:80",
            "http://example.com",
            "user@example.com",
            "*.example.com",
            "[example.com]",
            "[]",
            "[",
            "]",
            "[::1",
            "::1]",
            "::1.",
            "fe80::1%eth0",
            "[fe80::1%eth0]",
            "::1::1",
            "1:2:3:4:5:6:7:8:9",
            "xn--",
        ]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
        // NUL, control bytes, DEL and every non-ASCII byte.
        cases.push(b"a\0b.example".to_vec());
        cases.push(vec![0x7f]);
        cases.push("b\u{fc}cher.example".as_bytes().to_vec());
        cases.push("\u{4f8b}\u{3048}.jp".as_bytes().to_vec());
        cases.push(vec![0xff, 0xfe, 0x00]);
        for bytes in cases {
            assert_eq!(
                canonicalize(RawTarget::Name(bytes.clone(), 443)),
                Err(Refusal::Malformed),
                "{:?}",
                String::from_utf8_lossy(&bytes)
            );
        }
    }

    #[test]
    fn name_and_label_length_limits_are_exact() {
        let label63 = "a".repeat(63);
        let label64 = "a".repeat(64);
        let name253 = format!("{label63}.{label63}.{label63}.{}", "a".repeat(61));
        let name254 = format!("{label63}.{label63}.{label63}.{}", "a".repeat(62));
        assert_eq!((name253.len(), name254.len()), (253, 254));
        assert!(name(&name253).is_ok());
        assert!(
            name(&format!("{name253}.")).is_ok(),
            "one trailing dot is free"
        );
        assert_eq!(name(&name254), Err(Refusal::Malformed));
        assert_eq!(name(&format!("{label64}.example")), Err(Refusal::Malformed));
        assert!(name(&format!("{label63}.example")).is_ok());
        // 255 bytes is the SOCKS5 maximum; 256 cannot be sent, but the
        // function must not trust the caller.
        assert_eq!(name(&"a".repeat(256)), Err(Refusal::Malformed));
    }

    #[test]
    fn punycode_a_labels_pass_undecoded() {
        assert_eq!(host_of("xn--bcher-kva.example"), "xn--bcher-kva.example");
        assert_eq!(host_of("XN--P1AI"), "xn--p1ai");
    }

    #[test]
    fn the_ingress_agrees_with_the_shared_host_corpus() {
        for case in host_corpus() {
            let result = name(&case.host);
            match case.class {
                HostClass::Name => {
                    let lowered = case.host.to_ascii_lowercase();
                    let bare = lowered.strip_suffix('.').unwrap_or(&lowered);
                    if bare == "localhost" || bare.ends_with(".localhost") {
                        assert_eq!(result, Err(Refusal::LocalhostName), "{}", case.host);
                    } else {
                        let target = result.unwrap_or_else(|e| panic!("{}: {e:?}", case.host));
                        assert_eq!(target.kind, TargetKind::Name, "{}", case.host);
                    }
                }
                HostClass::IpLiteral | HostClass::MappedIpv6 => {
                    let target = result.unwrap_or_else(|e| panic!("{}: {e:?}", case.host));
                    assert!(target.ip.is_some(), "{}", case.host);
                    assert_ne!(target.kind, TargetKind::Name, "{}", case.host);
                    // A mapped spelling is folded into the IPv4 form.
                    if case.class == HostClass::MappedIpv6 {
                        assert_eq!(target.kind, TargetKind::Ipv4, "{}", case.host);
                    }
                }
                HostClass::NumericAlias => {
                    // Config grammar calls `127.0.0.1.` a numeric alias; here a
                    // strict dotted quad with its one trailing dot is the
                    // literal of design 6.2 step 3f. Every other member is an
                    // alias.
                    if case.host == "127.0.0.1." {
                        assert_eq!(result.map(|t| t.host), Ok("127.0.0.1".to_owned()));
                    } else {
                        assert_eq!(result, Err(Refusal::NumericAlias), "{}", case.host);
                    }
                }
                HostClass::AddressSpelling => {
                    if case.host.contains('%') {
                        assert_eq!(result, Err(Refusal::Malformed), "{}", case.host);
                    } else {
                        let target = result.unwrap_or_else(|e| panic!("{}: {e:?}", case.host));
                        assert!(target.ip.is_some(), "{}", case.host);
                    }
                }
                HostClass::Malformed => {
                    assert_eq!(result, Err(Refusal::Malformed), "{}", case.host);
                }
            }
        }
        // The table must still exercise every class.
        let classes: Vec<_> = host_corpus().into_iter().map(|c| c.class).collect();
        for class in HostClass::ALL {
            assert!(classes.contains(&class), "{class:?} has no case");
        }
    }

    #[test]
    fn special_use_table_ipv4() {
        let cases = [
            ("0.0.0.0", Some(SpecialUse::Unspecified)),
            ("0.1.2.3", Some(SpecialUse::ThisNetwork)),
            ("127.0.0.1", Some(SpecialUse::Loopback)),
            ("127.255.255.255", Some(SpecialUse::Loopback)),
            ("10.0.0.1", Some(SpecialUse::Private)),
            ("10.255.255.255", Some(SpecialUse::Private)),
            ("172.15.255.255", None),
            ("172.16.0.1", Some(SpecialUse::Private)),
            ("172.31.255.255", Some(SpecialUse::Private)),
            ("172.32.0.0", None),
            ("192.168.1.1", Some(SpecialUse::Private)),
            ("100.63.255.255", None),
            ("100.64.0.1", Some(SpecialUse::SharedAddressSpace)),
            ("100.127.255.255", Some(SpecialUse::SharedAddressSpace)),
            ("100.128.0.0", None),
            ("169.254.169.254", Some(SpecialUse::Metadata)),
            ("169.254.169.253", Some(SpecialUse::LinkLocal)),
            ("169.254.0.1", Some(SpecialUse::LinkLocal)),
            ("169.253.255.255", None),
            ("224.0.0.1", Some(SpecialUse::Multicast)),
            ("239.255.255.255", Some(SpecialUse::Multicast)),
            ("240.0.0.1", Some(SpecialUse::Reserved)),
            ("255.255.255.254", Some(SpecialUse::Reserved)),
            ("255.255.255.255", Some(SpecialUse::Broadcast)),
            ("192.0.2.1", Some(SpecialUse::Documentation)),
            ("198.51.100.1", Some(SpecialUse::Documentation)),
            ("203.0.113.1", Some(SpecialUse::Documentation)),
            ("198.17.255.255", None),
            ("198.18.0.1", Some(SpecialUse::FakeIp)),
            ("198.19.255.255", Some(SpecialUse::FakeIp)),
            ("198.20.0.0", None),
            ("192.0.0.1", Some(SpecialUse::ProtocolAssignment)),
            ("192.0.1.1", None),
            ("192.88.99.1", Some(SpecialUse::Translation)),
            ("8.8.8.8", None),
            ("1.1.1.1", None),
            ("93.184.216.34", None),
        ];
        for (text, expected) in cases {
            assert_eq!(classify_ip(ip(text)), expected, "{text}");
        }
    }

    #[test]
    fn special_use_table_ipv6() {
        let cases = [
            ("::", Some(SpecialUse::Unspecified)),
            ("::1", Some(SpecialUse::Loopback)),
            ("::2", Some(SpecialUse::Reserved)),
            ("::1.2.3.4", Some(SpecialUse::Reserved)),
            ("fc00::1", Some(SpecialUse::Private)),
            ("fd12:3456::1", Some(SpecialUse::Private)),
            ("fe80::1", Some(SpecialUse::LinkLocal)),
            ("febf::1", Some(SpecialUse::LinkLocal)),
            ("fec0::1", Some(SpecialUse::SiteLocal)),
            ("ff02::1", Some(SpecialUse::Multicast)),
            ("5f00::1", Some(SpecialUse::Reserved)),
            ("2001:db8::1", Some(SpecialUse::Documentation)),
            ("3fff::1", Some(SpecialUse::Documentation)),
            ("3fff:fff::1", Some(SpecialUse::Documentation)),
            ("3fff:1000::1", None),
            ("2001::1", Some(SpecialUse::ProtocolAssignment)),
            ("2001:1ff::1", Some(SpecialUse::ProtocolAssignment)),
            ("2001:200::1", None),
            ("2002::1", Some(SpecialUse::Translation)),
            ("64:ff9b:1::1", Some(SpecialUse::Translation)),
            ("100::1", Some(SpecialUse::Discard)),
            ("100:0:0:1::1", Some(SpecialUse::DummyPrefix)),
            (
                "100:0:0:1:ffff:ffff:ffff:ffff",
                Some(SpecialUse::DummyPrefix),
            ),
            ("100:0:0:2::1", Some(SpecialUse::Reserved)),
            ("100::", Some(SpecialUse::Discard)),
            ("100:0:0:0:ffff:ffff:ffff:ffff", Some(SpecialUse::Discard)),
            // Outside 2000::/3 nothing is allocated; IPv4-translated (SIIT) is in ::/8.
            ("::ffff:0:808:808", Some(SpecialUse::Reserved)),
            ("4000::1", Some(SpecialUse::Reserved)),
            ("8000::1", Some(SpecialUse::Reserved)),
            ("1fff::1", Some(SpecialUse::Reserved)),
            ("2000::1", None),
            ("3fff:2000::1", None),
            ("64:ff9b::808:808", Some(SpecialUse::Translation)),
            ("2606:4700:4700::1111", None),
            ("2a00:1450:4001::1", None),
        ];
        for (text, expected) in cases {
            assert_eq!(classify_ip(ip(text)), expected, "{text}");
        }
    }

    #[test]
    fn mapped_addresses_classify_as_ipv4_and_nat64_is_always_special() {
        // Mapped: the IPv4 verdict.
        assert_eq!(
            classify_ip(ip("::ffff:127.0.0.1")),
            Some(SpecialUse::Loopback)
        );
        assert_eq!(
            classify_ip(ip("::ffff:10.0.0.1")),
            Some(SpecialUse::Private)
        );
        assert_eq!(classify_ip(ip("::ffff:8.8.8.8")), None);
        // NAT64 64:ff9b::/96 reaches the embedded IPv4 address through a
        // translator, but it is another spelling than the IPv4 one and a deny
        // rule for 8.8.8.8 does not match it: it needs an exact rule even when
        // the embedded address is public.
        assert_eq!(
            classify_ip(ip("64:ff9b::808:808")),
            Some(SpecialUse::Translation)
        );
        // ... and a special-use embedded address names its own reason.
        assert_eq!(
            classify_ip(ip("64:ff9b::7f00:1")),
            Some(SpecialUse::Loopback)
        );
        assert_eq!(classify_ip(ip("64:ff9b::a00:1")), Some(SpecialUse::Private));
        assert_eq!(
            classify_ip(ip("64:ff9b::a9fe:a9fe")),
            Some(SpecialUse::Metadata)
        );
        // The refusal reaches the guard: no rule, no NAT64 destination.
        assert_eq!(
            guard_special_use(
                &lit("64:ff9b::808:808", 443),
                RuleBinding::NoExactDestination
            ),
            Err(Refusal::SpecialUse(SpecialUse::Translation))
        );
        let exact = RuleBinding::Exact {
            ip: ip("64:ff9b::808:808"),
            port: 443,
        };
        assert_eq!(
            guard_special_use(&lit("64:ff9b::808:808", 443), exact),
            Ok(())
        );
    }

    #[test]
    fn special_use_codes_are_unique_snake_case_and_all_lists_every_variant() {
        // An exhaustive match: adding a variant without listing it in ALL
        // leaves a hole in the index set below, and forgetting the match arm is
        // a compile error.
        fn index(special: SpecialUse) -> usize {
            match special {
                SpecialUse::Unspecified => 0,
                SpecialUse::ThisNetwork => 1,
                SpecialUse::Loopback => 2,
                SpecialUse::Private => 3,
                SpecialUse::SharedAddressSpace => 4,
                SpecialUse::LinkLocal => 5,
                SpecialUse::Metadata => 6,
                SpecialUse::Multicast => 7,
                SpecialUse::Reserved => 8,
                SpecialUse::Broadcast => 9,
                SpecialUse::Documentation => 10,
                SpecialUse::FakeIp => 11,
                SpecialUse::ProtocolAssignment => 12,
                SpecialUse::Translation => 13,
                SpecialUse::SiteLocal => 14,
                SpecialUse::Discard => 15,
                SpecialUse::DummyPrefix => 16,
            }
        }
        let indices: Vec<usize> = SpecialUse::ALL.iter().map(|s| index(*s)).collect();
        assert_eq!(indices, (0..SpecialUse::ALL.len()).collect::<Vec<_>>());

        let mut seen = std::collections::BTreeSet::new();
        for special in SpecialUse::ALL {
            let code = special.code();
            assert!(
                code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{code}"
            );
            assert!(seen.insert(code), "{code} is used twice");
        }
        assert_eq!(seen.len(), 17);
        assert_eq!(SpecialUse::DummyPrefix.code(), "dummy_prefix");
    }

    fn listener() -> SocketAddr {
        "127.0.0.1:10800".parse().unwrap()
    }

    fn lit(text: &str, port: u16) -> Target {
        let ip = ip(text);
        super::literal(ip, port, Provenance::ClientSuppliedLiteral)
    }

    #[test]
    fn a_literal_pointing_at_the_listener_is_a_self_loop() {
        for text in ["127.0.0.1", "127.5.5.5", "0.0.0.0", "::1", "::"] {
            assert_eq!(
                guard_self_loop(&lit(text, 10800), listener()),
                Err(Refusal::SelfLoop),
                "{text}"
            );
        }
        // Another port is not the listener, whatever the address.
        assert_eq!(
            guard_self_loop(&lit("127.0.0.1", 10801), listener()),
            Ok(())
        );
        // A public address on the listener's port is somebody else's service.
        assert_eq!(
            guard_self_loop(&lit("93.184.216.34", 10800), listener()),
            Ok(())
        );
        // A name cannot be judged before resolution.
        assert_eq!(
            guard_self_loop(&name("example.com").unwrap(), listener()),
            Ok(())
        );
        // The listener's own non-loopback address, if it were bound there.
        let lan: SocketAddr = "192.168.1.5:10800".parse().unwrap();
        assert_eq!(
            guard_self_loop(&lit("192.168.1.5", 10800), lan),
            Err(Refusal::SelfLoop)
        );
    }

    #[test]
    fn special_use_is_opened_only_by_an_exact_rule_with_the_same_port() {
        let target = lit("10.0.0.5", 5432);
        let exact = RuleBinding::Exact {
            ip: ip("10.0.0.5"),
            port: 5432,
        };
        assert_eq!(guard_special_use(&target, exact), Ok(()));
        // Same address, other port in the rule.
        assert_eq!(
            guard_special_use(
                &target,
                RuleBinding::Exact {
                    ip: ip("10.0.0.5"),
                    port: 80
                }
            ),
            Err(Refusal::SpecialUse(SpecialUse::Private))
        );
        // Another address in the rule.
        assert_eq!(
            guard_special_use(
                &target,
                RuleBinding::Exact {
                    ip: ip("10.0.0.6"),
                    port: 5432
                }
            ),
            Err(Refusal::SpecialUse(SpecialUse::Private))
        );
        // The address without a port opens nothing.
        assert_eq!(
            guard_special_use(&target, RuleBinding::ExactWithoutPort),
            Err(Refusal::SpecialUseNeedsPort(SpecialUse::Private))
        );
        // A port-only, suffix or deny rule has no exact destination.
        assert_eq!(
            guard_special_use(&target, RuleBinding::NoExactDestination),
            Err(Refusal::SpecialUse(SpecialUse::Private))
        );
    }

    #[test]
    fn public_literals_and_every_name_pass_the_special_use_guard() {
        for binding in [
            RuleBinding::NoExactDestination,
            RuleBinding::ExactWithoutPort,
        ] {
            assert_eq!(
                guard_special_use(&lit("93.184.216.34", 443), binding),
                Ok(())
            );
            assert_eq!(
                guard_special_use(&name("example.com").unwrap(), binding),
                Ok(())
            );
        }
        // A name is never exempt AND never refused here: its address is not
        // known before the dial, the resolved-address guard decides.
        let exact = RuleBinding::Exact {
            ip: ip("10.0.0.5"),
            port: 443,
        };
        assert_eq!(
            guard_special_use(&name("intranet.example").unwrap(), exact),
            Ok(())
        );
    }

    #[test]
    fn every_special_use_range_is_refused_for_a_matching_name_rule_free_literal() {
        for text in [
            "0.0.0.0",
            "127.0.0.1",
            "10.1.1.1",
            "100.64.0.1",
            "169.254.169.254",
            "224.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
        ] {
            assert!(
                matches!(
                    guard_special_use(&lit(text, 443), RuleBinding::NoExactDestination),
                    Err(Refusal::SpecialUse(_))
                ),
                "{text}"
            );
        }
    }

    #[test]
    fn refusal_codes_are_the_documented_ones() {
        assert_eq!(Refusal::Malformed.reason_code(), "TARGET_MALFORMED");
        assert_eq!(Refusal::NumericAlias.reason_code(), "TARGET_NUMERIC_ALIAS");
        assert_eq!(Refusal::LocalhostName.reason_code(), "TARGET_LOCALHOST");
        assert_eq!(Refusal::SelfLoop.reason_code(), "TARGET_SELF_LOOP");
        assert_eq!(
            Refusal::SpecialUse(SpecialUse::Private).reason_code(),
            "SPECIAL_USE_NEEDS_EXACT_RULE"
        );
        assert_eq!(
            Refusal::SpecialUseNeedsPort(SpecialUse::Private).reason_code(),
            "SPECIAL_USE_NEEDS_PORT"
        );
        assert_eq!(TargetKind::Ipv4.as_str(), "ipv4");
        assert_eq!(TargetKind::Ipv6.as_str(), "ipv6");
        assert_eq!(TargetKind::Name.as_str(), "name");
    }

    // ----- the special-use table against an independent statement of it -----
    //
    // `classify_v4` and `classify_v6` are chains of masks. The tables below say the
    // same thing as (prefix, length, class) rows copied from the IANA
    // special-purpose registries and resolved by longest prefix, so a mask that
    // is a bit too narrow or too wide in either place is a disagreement. The
    // probes are the places where a classification can change: the first and
    // last address of every prefix, the addresses next to them, and the
    // address with each prefix bit flipped.

    type Row4 = (&'static str, u8, SpecialUse);

    const V4_ORACLE: &[Row4] = &[
        ("0.0.0.0", 32, SpecialUse::Unspecified),
        ("0.0.0.0", 8, SpecialUse::ThisNetwork),
        ("10.0.0.0", 8, SpecialUse::Private),
        ("100.64.0.0", 10, SpecialUse::SharedAddressSpace),
        ("127.0.0.0", 8, SpecialUse::Loopback),
        ("169.254.0.0", 16, SpecialUse::LinkLocal),
        ("169.254.169.254", 32, SpecialUse::Metadata),
        ("172.16.0.0", 12, SpecialUse::Private),
        ("192.0.0.0", 24, SpecialUse::ProtocolAssignment),
        ("192.0.2.0", 24, SpecialUse::Documentation),
        ("192.88.99.0", 24, SpecialUse::Translation),
        ("192.168.0.0", 16, SpecialUse::Private),
        ("198.18.0.0", 15, SpecialUse::FakeIp),
        ("198.51.100.0", 24, SpecialUse::Documentation),
        ("203.0.113.0", 24, SpecialUse::Documentation),
        ("224.0.0.0", 4, SpecialUse::Multicast),
        ("240.0.0.0", 4, SpecialUse::Reserved),
        ("255.255.255.255", 32, SpecialUse::Broadcast),
    ];

    const V6_ORACLE: &[Row4] = &[
        ("::", 128, SpecialUse::Unspecified),
        ("::1", 128, SpecialUse::Loopback),
        ("::", 8, SpecialUse::Reserved),
        ("64:ff9b::", 96, SpecialUse::Translation),
        ("64:ff9b:1::", 48, SpecialUse::Translation),
        ("100::", 64, SpecialUse::Discard),
        ("100:0:0:1::", 64, SpecialUse::DummyPrefix),
        ("2001::", 23, SpecialUse::ProtocolAssignment),
        ("2001:db8::", 32, SpecialUse::Documentation),
        ("2002::", 16, SpecialUse::Translation),
        ("3fff::", 20, SpecialUse::Documentation),
        ("fc00::", 7, SpecialUse::Private),
        ("fe80::", 10, SpecialUse::LinkLocal),
        ("fec0::", 10, SpecialUse::SiteLocal),
        ("ff00::", 8, SpecialUse::Multicast),
    ];

    fn mask128(len: u8) -> u128 {
        if len == 0 {
            0
        } else {
            u128::MAX << (128 - u32::from(len))
        }
    }

    fn oracle_v4(addr: Ipv4Addr) -> Option<SpecialUse> {
        let bits = u128::from(u32::from(addr));
        V4_ORACLE
            .iter()
            .filter(|(net, len, _)| {
                let net: Ipv4Addr = net.parse().expect("oracle row");
                let mask = mask128(*len + 96) & u128::from(u32::MAX);
                (bits & mask) == (u128::from(u32::from(net)) & mask)
            })
            .max_by_key(|(_, len, _)| *len)
            .map(|(_, _, class)| *class)
    }

    fn oracle_v6(addr: Ipv6Addr) -> Option<SpecialUse> {
        if let Some(v4) = addr.to_ipv4_mapped() {
            return oracle_v4(v4);
        }
        let bits = u128::from(addr);
        let row = V6_ORACLE
            .iter()
            .filter(|(net, len, _)| {
                let net: Ipv6Addr = net.parse().expect("oracle row");
                (bits & mask128(*len)) == (u128::from(net) & mask128(*len))
            })
            .max_by_key(|(_, len, _)| *len);
        match row {
            // NAT64: a special-use embedded address names its own reason.
            Some(("64:ff9b::", 96, class)) => {
                let embedded = Ipv4Addr::from(u32::try_from(bits & 0xffff_ffff).expect("32 bits"));
                oracle_v4(embedded).or(Some(*class))
            }
            Some((_, _, class)) => Some(*class),
            // Outside 2000::/3 nothing is allocated.
            None if bits >> 125 != 0b001 => Some(SpecialUse::Reserved),
            None => None,
        }
    }

    fn v4_probes() -> Vec<u32> {
        let mut out = Vec::new();
        for (net, len, _) in V4_ORACLE {
            let net: Ipv4Addr = net.parse().expect("oracle row");
            let host_bits = 32 - u32::from(*len);
            let first = u32::from(net);
            let last = first | u32::MAX.checked_shr(32 - host_bits).unwrap_or(0);
            let last = if host_bits == 0 { first } else { last };
            out.extend([first, last, first.wrapping_sub(1), last.wrapping_add(1)]);
            for bit in host_bits..32 {
                out.push(first ^ (1 << bit));
                out.push(last ^ (1 << bit));
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    fn v6_probes() -> Vec<u128> {
        let mut out = Vec::new();
        for (net, len, _) in V6_ORACLE {
            let net: Ipv6Addr = net.parse().expect("oracle row");
            let first = u128::from(net) & mask128(*len);
            let last = first | !mask128(*len);
            out.extend([first, last, first.wrapping_sub(1), last.wrapping_add(1)]);
            for bit in (128 - u32::from(*len))..128 {
                out.push(first ^ (1 << bit));
                out.push(last ^ (1 << bit));
            }
        }
        // The NAT64 range around every IPv4 boundary.
        for probe in v4_probes() {
            out.push(0x0064_ff9b_u128 << 96 | u128::from(probe));
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    #[test]
    fn the_oracle_rows_are_the_iana_registry_rows() {
        // Prefixes are aligned: a row whose host bits are not zero is a typo.
        for (net, len, _) in V4_ORACLE {
            let net: Ipv4Addr = net.parse().expect("row");
            let host = u32::MAX.checked_shr(u32::from(*len)).unwrap_or(0);
            assert_eq!(u32::from(net) & host, 0, "{net}/{len} is not aligned");
        }
        for (net, len, _) in V6_ORACLE {
            let net: Ipv6Addr = net.parse().expect("row");
            assert_eq!(u128::from(net) & !mask128(*len), 0, "{net}/{len}");
        }
        // Every class of SpecialUse except the two that exist only because
        // their range is split off a wider one is exercised by some row.
        let used: Vec<SpecialUse> = V4_ORACLE
            .iter()
            .chain(V6_ORACLE)
            .map(|(_, _, class)| *class)
            .collect();
        for class in SpecialUse::ALL {
            assert!(used.contains(&class), "no oracle row yields {class:?}");
        }
    }

    #[test]
    fn ipv4_classification_matches_the_registry_at_every_boundary() {
        let probes = v4_probes();
        assert!(probes.len() > 400, "{} probes", probes.len());
        for bits in probes {
            let addr = Ipv4Addr::from(bits);
            let expected = oracle_v4(addr);
            assert_eq!(classify_ip(IpAddr::V4(addr)), expected, "{addr}");
            // The mapped spelling is the same host.
            assert_eq!(
                classify_ip(IpAddr::V6(addr.to_ipv6_mapped())),
                expected,
                "::ffff:{addr}"
            );
        }
    }

    #[test]
    fn ipv4_classification_matches_the_registry_across_the_whole_space() {
        // Every /16 block at its first, middle and last address.
        for block in 0_u32..=0xffff {
            for low in [0, 0x8000, 0xffff] {
                let addr = Ipv4Addr::from(block << 16 | low);
                assert_eq!(classify_ip(IpAddr::V4(addr)), oracle_v4(addr), "{addr}");
            }
        }
    }

    #[test]
    fn ipv6_classification_matches_the_registry_at_every_boundary() {
        let probes = v6_probes();
        assert!(probes.len() > 1000, "{} probes", probes.len());
        for bits in probes {
            let addr = Ipv6Addr::from(bits);
            assert_eq!(classify_ip(IpAddr::V6(addr)), oracle_v6(addr), "{addr}");
        }
    }

    #[test]
    fn the_nat64_range_is_never_unclassified() {
        // The deny-rule hole: whatever IPv4 address is embedded, the NAT64
        // spelling of it needs an exact rule.
        for bits in v4_probes() {
            let embedded = Ipv4Addr::from(bits);
            let nat64 = Ipv6Addr::from(0x0064_ff9b_u128 << 96 | u128::from(bits));
            let class = classify_ip(IpAddr::V6(nat64));
            assert!(class.is_some(), "{nat64} (embeds {embedded})");
            if let Some(inner) = classify_ip(IpAddr::V4(embedded)) {
                assert_eq!(class, Some(inner), "{nat64}");
            } else {
                assert_eq!(class, Some(SpecialUse::Translation), "{nat64}");
            }
        }
    }

    // ----- properties (PROPTEST_CASES=32 in the CI smoke job) -----
    //
    // With 32 cases a property is only worth anything if most of its inputs are
    // accepted: uniformly random bytes are accepted about once in 150 draws, so
    // the generators below build host-shaped text (names, IPv6 spellings,
    // numeric aliases) and `generators_produce_mostly_acceptable_input` keeps
    // that true.

    fn raw_bytes() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..300),
            "[A-Za-z0-9.:%\\[\\]_ -]{0,80}".prop_map(String::into_bytes),
        ]
    }

    /// A valid DNS name: one to four labels and a final label that starts with a
    /// letter, in random case, with or without the trailing dot.
    fn valid_name() -> impl Strategy<Value = String> {
        (
            proptest::collection::vec("[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?", 0..4),
            "[a-z]([a-z0-9-]{0,10}[a-z0-9])?",
            any::<bool>(),
            proptest::collection::vec(any::<bool>(), 64),
        )
            .prop_map(|(mut labels, last, dot, flips)| {
                labels.push(last);
                let mut text = labels.join(".");
                if dot {
                    text.push('.');
                }
                text.chars()
                    .zip(flips.iter().chain(std::iter::repeat(&false)))
                    .map(|(c, flip)| if *flip { c.to_ascii_uppercase() } else { c })
                    .collect()
            })
    }

    /// An IPv6 address in one of the spellings a client may use in a name field.
    fn ipv6_spelling() -> impl Strategy<Value = (Ipv6Addr, String)> {
        (
            proptest::array::uniform8(any::<u16>()),
            0_u8..5,
            any::<bool>(),
        )
            .prop_map(|(segments, style, upper)| {
                let addr = Ipv6Addr::from(segments);
                let full = segments.map(|s| format!("{s:04x}")).join(":");
                let text = match style {
                    0 => full,
                    1 => addr.to_string(),
                    2 => format!("[{addr}]"),
                    3 => format!("[{full}]"),
                    _ => segments.map(|s| format!("{s:x}")).join(":"),
                };
                (addr, if upper { text.to_uppercase() } else { text })
            })
    }

    /// An IPv4-mapped IPv6 address in dotted-tail spellings.
    fn mapped_spelling() -> impl Strategy<Value = (Ipv4Addr, String)> {
        (proptest::array::uniform4(any::<u8>()), 0_u8..4).prop_map(|(octets, style)| {
            let v4 = Ipv4Addr::from(octets);
            let text = match style {
                0 => format!("::ffff:{v4}"),
                1 => format!("0:0:0:0:0:ffff:{v4}"),
                2 => format!("[::ffff:{v4}]"),
                _ => format!("::FFFF:{v4}"),
            };
            (v4, text)
        })
    }

    /// A numeric alias: one to four components in decimal, hex or octal, never
    /// anything that starts with a letter.
    fn alias_text() -> impl Strategy<Value = String> {
        proptest::collection::vec(
            (0_u8..3, 0_u32..2_000_000).prop_map(|(radix, n)| match radix {
                0 => n.to_string(),
                1 => format!("0x{n:x}"),
                _ => format!("0{n:o}"),
            }),
            1..5,
        )
        .prop_map(|parts| parts.join("."))
    }

    fn host_bytes() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            1 => raw_bytes(),
            3 => valid_name().prop_map(String::into_bytes),
            2 => ipv6_spelling().prop_map(|(_, text)| text.into_bytes()),
            1 => mapped_spelling().prop_map(|(_, text)| text.into_bytes()),
            1 => alias_text().prop_map(String::into_bytes),
        ]
    }

    #[test]
    fn generators_produce_mostly_acceptable_input() {
        use proptest::strategy::ValueTree;
        use proptest::test_runner::TestRunner;

        fn accepted<S: Strategy<Value = Vec<u8>>>(strategy: S, draws: u32) -> u32 {
            let mut runner = TestRunner::deterministic();
            (0..draws)
                .filter(|_| {
                    let bytes = strategy.new_tree(&mut runner).expect("tree").current();
                    canonicalize(RawTarget::Name(bytes, 443)).is_ok()
                })
                .count()
                .try_into()
                .expect("fits")
        }

        let draws = 600;
        // Names are accepted unless they happen to be `localhost`.
        assert!(accepted(valid_name().prop_map(String::into_bytes), draws) >= draws - 2);
        // Every spelling of an address is accepted.
        assert_eq!(
            accepted(ipv6_spelling().prop_map(|(_, t)| t.into_bytes()), draws),
            draws
        );
        assert_eq!(
            accepted(mapped_spelling().prop_map(|(_, t)| t.into_bytes()), draws),
            draws
        );
        // The mixture the properties draw from is mostly accepted, unlike raw bytes.
        let mixed = accepted(host_bytes(), draws);
        assert!(mixed * 2 >= draws, "only {mixed} of {draws} accepted");
        let raw = accepted(raw_bytes(), draws);
        assert!(raw * 20 < draws, "raw bytes unexpectedly accepted: {raw}");
    }

    proptest! {
        #[test]
        fn canonicalize_never_panics_on_arbitrary_bytes(bytes in host_bytes(), port in any::<u16>()) {
            let _ = canonicalize(RawTarget::Name(bytes, port));
        }

        #[test]
        fn an_accepted_host_re_canonicalises_to_itself(bytes in host_bytes()) {
            if let Ok(target) = canonicalize(RawTarget::Name(bytes, 443)) {
                let again = canonicalize(RawTarget::Name(target.host.clone().into_bytes(), 443))
                    .expect("a canonical host is accepted again");
                prop_assert_eq!(again.host, target.host);
                prop_assert_eq!(again.kind, target.kind);
                prop_assert_eq!(again.ip, target.ip);
            }
        }

        #[test]
        fn an_accepted_host_is_in_the_canonical_alphabet(bytes in host_bytes()) {
            if let Ok(target) = canonicalize(RawTarget::Name(bytes, 443)) {
                prop_assert!(!target.host.contains('['));
                prop_assert!(!target.host.contains(']'));
                prop_assert!(!target.host.ends_with('.'));
                prop_assert!(!target.host.bytes().any(|b| b.is_ascii_uppercase()));
                prop_assert!(!target.host.is_empty());
            }
        }

        #[test]
        fn an_accepted_name_is_never_an_address_and_ends_in_a_letter(bytes in host_bytes()) {
            if let Ok(target) = canonicalize(RawTarget::Name(bytes, 443)) {
                if target.kind == TargetKind::Name {
                    prop_assert!(target.host.parse::<IpAddr>().is_err());
                    prop_assert!(target.ip.is_none());
                    let last = target.host.rsplit('.').next().unwrap_or("");
                    prop_assert!(last.as_bytes().first().is_some_and(u8::is_ascii_alphabetic));
                    prop_assert!(target.host != "localhost" && !target.host.ends_with(".localhost"));
                } else {
                    prop_assert!(target.ip.is_some());
                    prop_assert_eq!(target.ip.map(|ip| ip.to_string()), Some(target.host.clone()));
                }
            }
        }

        #[test]
        fn a_valid_name_is_lower_cased_and_loses_one_trailing_dot(text in valid_name()) {
            let expected = text.to_ascii_lowercase();
            let expected = expected.strip_suffix('.').unwrap_or(&expected).to_owned();
            let result = canonicalize(RawTarget::Name(text.clone().into_bytes(), 443));
            if expected == "localhost" || expected.ends_with(".localhost") {
                prop_assert_eq!(result, Err(Refusal::LocalhostName));
            } else {
                let target = result.expect("a valid name");
                prop_assert_eq!(target.host, expected);
                prop_assert_eq!(target.kind, TargetKind::Name);
                prop_assert_eq!(target.ip, None);
                prop_assert_eq!(target.provenance, Provenance::ClientSuppliedName);
                prop_assert_eq!(target.port, 443);
            }
        }

        #[test]
        fn every_spelling_of_an_ipv6_address_gives_the_typed_host((addr, text) in ipv6_spelling()) {
            let typed = canonicalize(RawTarget::V6(addr, 80)).expect("typed");
            let named = canonicalize(RawTarget::Name(text.into_bytes(), 80)).expect("spelled");
            prop_assert_eq!(&named.host, &typed.host);
            prop_assert_eq!(named.ip, typed.ip);
            prop_assert_eq!(named.kind, typed.kind);
            prop_assert_eq!(named.provenance, Provenance::ClientSuppliedName);
        }

        #[test]
        fn every_spelling_of_a_mapped_address_gives_the_ipv4_host((v4, text) in mapped_spelling()) {
            let typed = canonicalize(RawTarget::V4(v4, 80)).expect("typed");
            let named = canonicalize(RawTarget::Name(text.into_bytes(), 80)).expect("spelled");
            prop_assert_eq!(&named.host, &typed.host);
            prop_assert_eq!(named.kind, TargetKind::Ipv4);
            prop_assert_eq!(named.ip, Some(IpAddr::V4(v4)));
        }

        #[test]
        fn a_numeric_alias_is_refused_or_is_a_strict_dotted_quad(text in alias_text()) {
            match canonicalize(RawTarget::Name(text.clone().into_bytes(), 80)) {
                Ok(target) => {
                    // Only the strict, decimal, four-part form is an address.
                    prop_assert_eq!(target.kind, TargetKind::Ipv4);
                    prop_assert_eq!(text.parse::<Ipv4Addr>().ok().map(IpAddr::V4), target.ip);
                }
                Err(refusal) => prop_assert_eq!(refusal, Refusal::NumericAlias),
            }
        }

        #[test]
        fn two_spellings_of_one_ipv6_address_give_identical_hosts(segments in proptest::array::uniform8(any::<u16>())) {
            let addr = Ipv6Addr::from(segments);
            let from_typed = canonicalize(RawTarget::V6(addr, 80)).expect("typed");
            let full = addr.segments().map(|s| format!("{s:04x}")).join(":");
            let from_name = canonicalize(RawTarget::Name(full.into_bytes(), 80)).expect("name");
            let bracketed = canonicalize(RawTarget::Name(format!("[{addr}]").into_bytes(), 80)).expect("bracketed");
            prop_assert_eq!(&from_typed.host, &from_name.host);
            prop_assert_eq!(&from_typed.host, &bracketed.host);
        }

        #[test]
        fn two_spellings_of_one_ipv4_address_give_identical_hosts(octets in proptest::array::uniform4(any::<u8>())) {
            let addr = Ipv4Addr::from(octets);
            let typed = canonicalize(RawTarget::V4(addr, 80)).expect("typed");
            let named = canonicalize(RawTarget::Name(addr.to_string().into_bytes(), 80)).expect("named");
            let dotted = canonicalize(RawTarget::Name(format!("{addr}.").into_bytes(), 80)).expect("dotted");
            let mapped = canonicalize(RawTarget::V6(addr.to_ipv6_mapped(), 80)).expect("mapped");
            prop_assert_eq!(&typed.host, &named.host);
            prop_assert_eq!(&typed.host, &dotted.host);
            prop_assert_eq!(&typed.host, &mapped.host);
        }

        #[test]
        fn random_ipv4_addresses_classify_as_the_registry_says(bits in any::<u32>()) {
            let addr = Ipv4Addr::from(bits);
            prop_assert_eq!(classify_ip(IpAddr::V4(addr)), oracle_v4(addr));
            prop_assert_eq!(classify_ip(IpAddr::V6(addr.to_ipv6_mapped())), oracle_v4(addr));
        }

        #[test]
        fn addresses_inside_a_registry_prefix_classify_as_the_registry_says(
            row in 0..V6_ORACLE.len(),
            noise in any::<u128>(),
        ) {
            let (net, len, _) = V6_ORACLE[row];
            let net: Ipv6Addr = net.parse().expect("row");
            let bits = (u128::from(net) & mask128(len)) | (noise & !mask128(len));
            let addr = Ipv6Addr::from(bits);
            prop_assert_eq!(classify_ip(IpAddr::V6(addr)), oracle_v6(addr), "{}", addr);
        }

        #[test]
        fn any_ipv6_address_classifies_as_the_registry_says(bits in any::<u128>()) {
            let addr = Ipv6Addr::from(bits);
            prop_assert_eq!(classify_ip(IpAddr::V6(addr)), oracle_v6(addr));
        }
    }
}
