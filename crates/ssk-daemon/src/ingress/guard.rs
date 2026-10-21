//! The address guard of the ingress's own executor (design 6.10), and the one
//! function that assembles that executor.
//!
//! A `Direct` route to a NAME is resolved by `sskd`, once, and every answer must
//! pass this guard before a socket exists. The guard refuses an answer that is
//! special-use (the one table of `target::classify_ip`), that is the listener, or
//! that equals an exact-IP `deny` rule of the profile that is armed NOW. The last
//! one is the direction the policy engine cannot cover: a name flow never equals
//! an IP rule, so a deny rule written for an address would otherwise be walked
//! around by sending a name that resolves to it. The check can only refuse more,
//! never admit more, so it applies at any rule priority.
//!
//! The first hop of a proxy chain (`DialPurpose::FirstHop`) is the operator's own
//! configuration: a local, LAN or shared-space proxy is legitimate, so it is
//! asked only about the self-loop and about the classes that are never a proxy
//! (unspecified, this-network, metadata, multicast, broadcast, reserved, discard).
//!
//! There is no exemption mechanism, on purpose: a literal may be opened by an
//! exact rule (`target::guard_special_use`), a name's answer never.
//!
//! The guard keeps no lifecycle state of its own. It reads the armed profile
//! from the gate itself (a `watch::Receiver` that the host hands over once) and
//! the listener from a cell the host fills after the bind. Anything missing
//! refuses: an unset gate, an unset listener, a gate that is not `Armed`.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddrV4};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ssk_config::ingress::DirectAddressFamilies;
use ssk_netcore::{
    AdapterRegistry, AddrRefusal, AddressFamilies, DialPurpose, DirectAddrGuard, RouteExecutor,
    RESOLVE_TIMEOUT,
};
use tokio::sync::watch;

use super::target::{classify_ip, unmap_ip, SpecialUse};
use super::types::{lock_unpoisoned, Gate, GateMode, IngressCfgView};
use crate::routing::{ingress_executor_dial_deadline, ConfiguredRouting, DenyIp};

/// Refusal labels beyond the special-use codes. Closed; they land in
/// `Result.refusal` and never carry an address.
pub const REFUSAL_LISTENER: &str = "listener";
pub const REFUSAL_DENY_RULE: &str = "deny_rule";
pub const REFUSAL_NOT_ARMED: &str = "not_armed";

/// What the guard reads that it does not own: where the listener is, and the
/// gate.
#[derive(Debug, Default)]
pub struct GuardCells {
    listener: Mutex<Option<SocketAddrV4>>,
    gate: OnceLock<watch::Receiver<Gate>>,
}

impl GuardCells {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Written by the host after the bind.
    pub fn set_listener(&self, addr: SocketAddrV4) {
        *lock_unpoisoned(&self.listener) = Some(addr);
    }

    /// Written by the host when the listener is gone.
    pub fn clear_listener(&self) {
        *lock_unpoisoned(&self.listener) = None;
    }

    #[must_use]
    pub fn listener(&self) -> Option<SocketAddrV4> {
        *lock_unpoisoned(&self.listener)
    }

    /// Hands the guard the gate. Once: the first receiver stays and a second
    /// call returns `false`, so a later change cannot swap the gate under a
    /// running guard.
    pub fn set_gate(&self, gate: watch::Receiver<Gate>) -> bool {
        self.gate.set(gate).is_ok()
    }
}

/// The guard of the ingress executor.
#[derive(Debug)]
pub struct IngressDirectGuard {
    cells: Arc<GuardCells>,
    /// Per profile, in evaluation order, computed once at start.
    denials: BTreeMap<String, Vec<DenyIp>>,
}

impl IngressDirectGuard {
    #[must_use]
    pub fn new(cells: Arc<GuardCells>, denials: BTreeMap<String, Vec<DenyIp>>) -> Self {
        Self { cells, denials }
    }

    /// Takes the deny sets of `profile_ids` from the hoisted routing.
    #[must_use]
    pub fn from_routing<'a>(
        cells: Arc<GuardCells>,
        routing: &ConfiguredRouting,
        profile_ids: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let denials = profile_ids
            .into_iter()
            .map(|id| (id.to_owned(), routing.exact_ip_denials(id)))
            .collect();
        Self::new(cells, denials)
    }

    fn refuse(code: &'static str) -> Result<(), AddrRefusal> {
        Err(AddrRefusal { code })
    }

    /// An address that points back at the listener: its own address and port, or
    /// loopback or the unspecified address on its port (which connects to the
    /// local host on Linux).
    fn loops_back(listener: SocketAddrV4, ip: IpAddr, port: u16) -> bool {
        port == listener.port()
            && (ip == IpAddr::V4(*listener.ip()) || ip.is_loopback() || ip.is_unspecified())
    }

    fn check_target(&self, ip: IpAddr, port: u16) -> Result<(), AddrRefusal> {
        let Some(listener) = self.cells.listener() else {
            return Self::refuse(REFUSAL_NOT_ARMED);
        };
        let Some(gate) = self.cells.gate.get() else {
            return Self::refuse(REFUSAL_NOT_ARMED);
        };
        // A gate whose sender is gone is not armed: the host that owned it has
        // stopped, and `has_changed` is the receiver's way of saying so. (The pump
        // treats the same condition as a gate change.)
        if gate.has_changed().is_err() {
            return Self::refuse(REFUSAL_NOT_ARMED);
        }
        // The profile that is armed now. The borrow is released before any other
        // work: the guard holds nothing across a call.
        let profile = match &gate.borrow().mode {
            GateMode::Armed { profile } => Arc::clone(profile),
            _ => return Self::refuse(REFUSAL_NOT_ARMED),
        };
        // A profile the guard holds no deny set for (not even an empty one) is a
        // profile it was not built for: refuse, do not assume it has no denials.
        let Some(denials) = self.denials.get(&*profile) else {
            return Self::refuse(REFUSAL_NOT_ARMED);
        };
        let ip = unmap_ip(ip);
        // The more specific label first: a self-loop is also loopback.
        if ip == IpAddr::V4(*listener.ip()) && port == listener.port() {
            return Self::refuse(REFUSAL_LISTENER);
        }
        if let Some(special) = classify_ip(ip) {
            return Self::refuse(special.code());
        }
        // A rule's own address is compared in the same spelling, whatever it was
        // written as (the configuration refuses a mapped one; this does not rely
        // on that).
        let denied = denials
            .iter()
            .any(|deny| unmap_ip(deny.ip) == ip && deny.port.is_none_or(|p| p == port));
        if denied {
            return Self::refuse(REFUSAL_DENY_RULE);
        }
        Ok(())
    }

    fn check_first_hop(&self, ip: IpAddr, port: u16) -> Result<(), AddrRefusal> {
        let Some(listener) = self.cells.listener() else {
            return Self::refuse(REFUSAL_NOT_ARMED);
        };
        let ip = unmap_ip(ip);
        if Self::loops_back(listener, ip, port) {
            return Self::refuse(REFUSAL_LISTENER);
        }
        // A local, LAN or shared-space proxy is legitimate, so special-use as a
        // whole is not refused here. These classes are never a proxy, and a
        // hostile answer for the proxy's NAME could otherwise aim the handshake
        // bytes at the metadata service or a broadcast address.
        match classify_ip(ip) {
            Some(
                special @ (SpecialUse::Unspecified
                | SpecialUse::ThisNetwork
                | SpecialUse::Metadata
                | SpecialUse::Multicast
                | SpecialUse::Broadcast
                | SpecialUse::Reserved
                | SpecialUse::Discard
                | SpecialUse::DummyPrefix),
            ) => Self::refuse(special.code()),
            _ => Ok(()),
        }
    }
}

impl DirectAddrGuard for IngressDirectGuard {
    fn check(&self, purpose: DialPurpose, ip: IpAddr, port: u16) -> Result<(), AddrRefusal> {
        match purpose {
            DialPurpose::Target => self.check_target(ip, port),
            // The first hop is the configured proxy's own address: special-use
            // there is legitimate operator configuration (a local proxy, a LAN
            // proxy). Only the loop is refused.
            DialPurpose::FirstHop => self.check_first_hop(ip, port),
        }
    }
}

/// `direct_address_families` as the executor spells it.
#[must_use]
pub const fn address_families(families: DirectAddressFamilies) -> AddressFamilies {
    match families {
        DirectAddressFamilies::Ipv4Only => AddressFamilies::Ipv4Only,
        DirectAddressFamilies::Any => AddressFamilies::Any,
    }
}

/// The ingress's own `RouteExecutor`: the SAME adapters as the activation path,
/// but guarded, with the configured address families and its own timeouts. One
/// library function, so that a test can assert what the daemon builds: a guard
/// missing or a family filter left at `any` is a regression that must fail a test.
///
/// The activation executor stays unguarded on purpose: one executor with a guard
/// would silently change what `ssk activate --dest name` may reach.
#[must_use]
pub fn build_ingress_executor(
    adapters: AdapterRegistry,
    cfg: &IngressCfgView,
    guard: Arc<dyn DirectAddrGuard>,
) -> RouteExecutor {
    let connect = Duration::from_millis(u64::from(cfg.limits.connect_timeout_ms));
    let resolve = RESOLVE_TIMEOUT.min(connect);
    RouteExecutor::new(adapters)
        .with_connect_timeout(connect)
        .with_resolve_timeout(resolve)
        .with_dial_deadline(ingress_executor_dial_deadline(resolve, connect))
        .with_direct_guard(guard)
        .with_address_families(address_families(cfg.families))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::target::SpecialUse;
    use crate::ingress::types::{TripReason, UnavailableCode};
    use ssk_config::routing::{
        AdapterTransport, RoutingAction, RoutingAdapter, RoutingConfig, RoutingProfile, RoutingRule,
    };
    use ssk_netadmin::RouteKind;
    use ssk_netcore::{DataPlane, NetcoreDataPlane, NetcoreError, ResolutionMode};
    use std::net::SocketAddr;

    // The doubles of the two netcore seams (shared with the integration tests).
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/support/net_fakes.rs"
    ));
    use net_fakes::{FakeResolver, RecordingConnector};

    const LISTENER: &str = "127.0.0.1:10800";
    const PUBLIC: &str = "93.184.216.34";

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address")
    }

    fn gate(epoch: u64, mode: GateMode) -> Gate {
        Gate { epoch, mode }
    }

    fn armed(profile: &str) -> GateMode {
        GateMode::Armed {
            profile: Arc::from(profile),
        }
    }

    fn rule(
        id: &str,
        priority: u32,
        destination: &str,
        port: Option<u16>,
        action: RoutingAction,
    ) -> RoutingRule {
        RoutingRule {
            id: id.into(),
            priority,
            destination: Some(destination.into()),
            domain_suffix: None,
            port,
            action,
            require_attestation: false,
        }
    }

    fn routing(profiles: Vec<(&str, Vec<RoutingRule>)>) -> ConfiguredRouting {
        let profiles: Vec<RoutingProfile> = profiles
            .into_iter()
            .map(|(id, rules)| RoutingProfile {
                id: id.into(),
                name: id.into(),
                rules,
            })
            .collect();
        ConfiguredRouting::new(&RoutingConfig {
            default_profile: profiles[0].id.clone(),
            profiles,
            adapters: vec![RoutingAdapter {
                id: "exit".into(),
                transport: AdapterTransport::Socks5 {
                    host: "proxy.example".into(),
                    port: 1080,
                },
            }],
        })
    }

    /// A guard over `routing`, with the listener bound at [`LISTENER`] and the
    /// gate in `mode`. Returns the sender so a test can move the gate.
    fn guard_in(
        routing: &ConfiguredRouting,
        mode: GateMode,
    ) -> (IngressDirectGuard, watch::Sender<Gate>, Arc<GuardCells>) {
        let cells = GuardCells::new();
        cells.set_listener(LISTENER.parse().expect("listener"));
        let (tx, rx) = watch::channel(gate(1, mode));
        assert!(cells.set_gate(rx));
        let guard =
            IngressDirectGuard::from_routing(Arc::clone(&cells), routing, ["main", "other"]);
        (guard, tx, cells)
    }

    fn target(guard: &IngressDirectGuard, address: &str, port: u16) -> Result<(), &'static str> {
        guard
            .check(DialPurpose::Target, ip(address), port)
            .map_err(|refusal| refusal.code)
    }

    fn first_hop(guard: &IngressDirectGuard, address: &str, port: u16) -> Result<(), &'static str> {
        guard
            .check(DialPurpose::FirstHop, ip(address), port)
            .map_err(|refusal| refusal.code)
    }

    fn plain() -> ConfiguredRouting {
        routing(vec![("main", vec![]), ("other", vec![])])
    }

    // -- the target direction -----------------------------------------------

    #[test]
    fn a_public_answer_passes_and_every_special_use_range_is_refused_with_its_code() {
        let (guard, _tx, _) = guard_in(&plain(), armed("main"));
        assert_eq!(target(&guard, PUBLIC, 443), Ok(()));
        assert_eq!(target(&guard, "2606:4700:4700::1111", 443), Ok(()));
        let samples = [
            ("0.0.0.0", SpecialUse::Unspecified),
            ("0.1.2.3", SpecialUse::ThisNetwork),
            ("127.0.0.1", SpecialUse::Loopback),
            ("127.1.2.3", SpecialUse::Loopback),
            ("10.1.2.3", SpecialUse::Private),
            ("172.16.0.1", SpecialUse::Private),
            ("192.168.1.1", SpecialUse::Private),
            ("100.64.0.1", SpecialUse::SharedAddressSpace),
            ("169.254.169.254", SpecialUse::Metadata),
            ("169.254.1.1", SpecialUse::LinkLocal),
            ("224.0.0.1", SpecialUse::Multicast),
            ("255.255.255.255", SpecialUse::Broadcast),
            ("198.18.0.1", SpecialUse::FakeIp),
            ("192.0.2.1", SpecialUse::Documentation),
            ("::1", SpecialUse::Loopback),
            ("::", SpecialUse::Unspecified),
            ("fe80::1", SpecialUse::LinkLocal),
            ("fc00::1", SpecialUse::Private),
            ("64:ff9b::808:808", SpecialUse::Translation),
            ("100:0:0:1::1", SpecialUse::DummyPrefix),
            // The mapped spelling is the same address.
            ("::ffff:127.0.0.1", SpecialUse::Loopback),
            ("::ffff:10.0.0.1", SpecialUse::Private),
        ];
        for (address, special) in samples {
            assert_eq!(
                target(&guard, address, 443),
                Err(special.code()),
                "{address}"
            );
        }
    }

    #[test]
    fn the_listener_itself_is_refused_under_its_own_label() {
        let (guard, _tx, _) = guard_in(&plain(), armed("main"));
        assert_eq!(target(&guard, "127.0.0.1", 10800), Err(REFUSAL_LISTENER));
        assert_eq!(
            target(&guard, "::ffff:127.0.0.1", 10800),
            Err(REFUSAL_LISTENER)
        );
        // Another loopback port is loopback, not a self-loop.
        assert_eq!(target(&guard, "127.0.0.1", 10801), Err("loopback"));
        // And the listener's port on a public address is not the listener.
        assert_eq!(target(&guard, PUBLIC, 10800), Ok(()));
    }

    #[test]
    fn exact_ip_deny_applies_to_resolved_names_at_any_priority() {
        // A deny rule that names an address is the one rule the policy engine can
        // never apply to a flow that arrived as a NAME. Whatever its priority and
        // whatever allows precede it, an answer equal to it is refused.
        for priority in [1, 50, 999] {
            let routing = routing(vec![
                (
                    "main",
                    vec![
                        rule("allow-all", 1, "93.184.216.0", None, RoutingAction::Direct),
                        rule("deny-one", priority, PUBLIC, None, RoutingAction::Deny),
                        rule(
                            "deny-v6",
                            priority,
                            "2606:4700::1",
                            None,
                            RoutingAction::Deny,
                        ),
                    ],
                ),
                ("other", vec![]),
            ]);
            let (guard, _tx, _) = guard_in(&routing, armed("main"));
            assert_eq!(
                target(&guard, PUBLIC, 443),
                Err(REFUSAL_DENY_RULE),
                "priority {priority}"
            );
            assert_eq!(
                target(&guard, PUBLIC, 80),
                Err(REFUSAL_DENY_RULE),
                "any port"
            );
            assert_eq!(
                target(&guard, "::ffff:93.184.216.34", 443),
                Err(REFUSAL_DENY_RULE),
                "mapped"
            );
            assert_eq!(target(&guard, "2606:4700::1", 443), Err(REFUSAL_DENY_RULE));
            // A neighbour is not the denied address.
            assert_eq!(target(&guard, "93.184.216.35", 443), Ok(()));
            assert_eq!(target(&guard, "2606:4700::2", 443), Ok(()));
        }
    }

    #[test]
    fn a_deny_rule_with_a_port_denies_only_that_port() {
        let routing = routing(vec![
            (
                "main",
                vec![rule(
                    "deny-8443",
                    10,
                    PUBLIC,
                    Some(8443),
                    RoutingAction::Deny,
                )],
            ),
            ("other", vec![]),
        ]);
        let (guard, _tx, _) = guard_in(&routing, armed("main"));
        assert_eq!(target(&guard, PUBLIC, 8443), Err(REFUSAL_DENY_RULE));
        assert_eq!(target(&guard, PUBLIC, 443), Ok(()));
        assert_eq!(target(&guard, PUBLIC, 8444), Ok(()));
    }

    #[test]
    fn only_deny_rules_and_only_addresses_make_a_denial() {
        let routing = routing(vec![
            (
                "main",
                vec![
                    // An allow and a route rule for the same address deny nothing.
                    rule("allow", 1, PUBLIC, None, RoutingAction::Direct),
                    rule(
                        "exit",
                        2,
                        "93.184.216.40",
                        None,
                        RoutingAction::Adapter {
                            adapter_id: "exit".into(),
                        },
                    ),
                    // A deny for a NAME is the policy engine's, before resolution.
                    rule("deny-name", 3, "blocked.example", None, RoutingAction::Deny),
                ],
            ),
            ("other", vec![]),
        ]);
        let (guard, _tx, _) = guard_in(&routing, armed("main"));
        assert_eq!(target(&guard, PUBLIC, 443), Ok(()));
        assert_eq!(target(&guard, "93.184.216.40", 443), Ok(()));
    }

    #[test]
    fn deny_set_follows_the_armed_profile_and_refuses_when_unarmed() {
        let routing = routing(vec![
            (
                "main",
                vec![rule("deny-main", 10, PUBLIC, None, RoutingAction::Deny)],
            ),
            (
                "other",
                vec![rule(
                    "deny-other",
                    10,
                    "93.184.216.50",
                    None,
                    RoutingAction::Deny,
                )],
            ),
        ]);
        let (guard, tx, _) = guard_in(&routing, armed("main"));
        assert_eq!(target(&guard, PUBLIC, 443), Err(REFUSAL_DENY_RULE));
        assert_eq!(
            target(&guard, "93.184.216.50", 443),
            Ok(()),
            "other's denial is not main's"
        );

        // Re-armed to the other profile: the sets swap, with no restart.
        tx.send(gate(2, armed("other"))).expect("receiver alive");
        assert_eq!(target(&guard, PUBLIC, 443), Ok(()));
        assert_eq!(target(&guard, "93.184.216.50", 443), Err(REFUSAL_DENY_RULE));

        // A profile the guard has no set for is refused (see the test of its own).
        tx.send(gate(3, armed("unknown"))).expect("receiver alive");
        assert_eq!(target(&guard, PUBLIC, 443), Err(REFUSAL_NOT_ARMED));

        // Not armed: everything is refused, every mode, every address.
        let unarmed = [
            GateMode::Disabled,
            GateMode::Starting,
            GateMode::Unavailable(UnavailableCode::BindFailed),
            GateMode::Disarmed,
            GateMode::Tripped(TripReason::AuditStalled),
            GateMode::Closing,
        ];
        for (n, mode) in unarmed.into_iter().enumerate() {
            tx.send(gate(10 + u64::try_from(n).expect("small"), mode.clone()))
                .expect("receiver alive");
            for address in [PUBLIC, "93.184.216.50", "8.8.8.8", "2606:4700::1"] {
                assert_eq!(
                    target(&guard, address, 443),
                    Err(REFUSAL_NOT_ARMED),
                    "{mode:?} {address}"
                );
            }
        }
    }

    #[test]
    fn nothing_is_allowed_before_the_host_has_wired_the_cells() {
        let guard = IngressDirectGuard::new(GuardCells::new(), BTreeMap::new());
        assert_eq!(
            target(&guard, PUBLIC, 443),
            Err(REFUSAL_NOT_ARMED),
            "no listener, no gate"
        );
        assert_eq!(first_hop(&guard, PUBLIC, 1080), Err(REFUSAL_NOT_ARMED));

        // A listener without a gate.
        let cells = GuardCells::new();
        cells.set_listener(LISTENER.parse().expect("listener"));
        let guard = IngressDirectGuard::new(Arc::clone(&cells), BTreeMap::new());
        assert_eq!(target(&guard, PUBLIC, 443), Err(REFUSAL_NOT_ARMED));

        // A gate without a listener.
        let cells = GuardCells::new();
        let (_tx, rx) = watch::channel(gate(1, armed("main")));
        assert!(cells.set_gate(rx));
        let guard = IngressDirectGuard::new(cells, BTreeMap::new());
        assert_eq!(target(&guard, PUBLIC, 443), Err(REFUSAL_NOT_ARMED));
    }

    #[test]
    fn a_listener_that_died_refuses_everything_again() {
        let (guard, _tx, cells) = guard_in(&plain(), armed("main"));
        assert_eq!(target(&guard, PUBLIC, 443), Ok(()));
        cells.clear_listener();
        assert_eq!(target(&guard, PUBLIC, 443), Err(REFUSAL_NOT_ARMED));
        assert_eq!(first_hop(&guard, "10.0.0.5", 1080), Err(REFUSAL_NOT_ARMED));
        cells.set_listener("127.0.0.1:10900".parse().expect("listener"));
        assert_eq!(target(&guard, PUBLIC, 443), Ok(()));
        assert_eq!(
            target(&guard, "127.0.0.1", 10900),
            Err(REFUSAL_LISTENER),
            "the new listener"
        );
        assert_eq!(
            target(&guard, "127.0.0.1", 10800),
            Err("loopback"),
            "no longer the listener"
        );
    }

    #[test]
    fn the_gate_is_handed_over_once() {
        let cells = GuardCells::new();
        let (_a, rx_a) = watch::channel(gate(1, armed("main")));
        let (_b, rx_b) = watch::channel(gate(1, GateMode::Disarmed));
        assert!(cells.set_gate(rx_a));
        assert!(!cells.set_gate(rx_b), "the first receiver stays");
        cells.set_listener(LISTENER.parse().expect("listener"));
        let guard =
            IngressDirectGuard::new(cells, BTreeMap::from([("main".to_owned(), Vec::new())]));
        assert_eq!(
            target(&guard, PUBLIC, 443),
            Ok(()),
            "still the armed gate of the first receiver"
        );
    }

    #[test]
    fn a_gate_whose_sender_is_gone_is_not_armed() {
        // The host that owned the gate has stopped; the pump cancels flows on the
        // same condition, and the guard must not keep admitting on a stale "armed".
        let (guard, tx, _) = guard_in(&plain(), armed("main"));
        assert_eq!(target(&guard, PUBLIC, 443), Ok(()));
        drop(tx);
        assert_eq!(target(&guard, PUBLIC, 443), Err(REFUSAL_NOT_ARMED));
        assert_eq!(target(&guard, "8.8.8.8", 443), Err(REFUSAL_NOT_ARMED));
    }

    #[test]
    fn an_armed_profile_the_guard_was_not_built_for_refuses() {
        let (guard, tx, _) = guard_in(&plain(), armed("main"));
        tx.send(gate(2, armed("ghost"))).expect("receiver alive");
        assert_eq!(target(&guard, PUBLIC, 443), Err(REFUSAL_NOT_ARMED));
        // A profile that has an (empty) set is a profile it was built for.
        tx.send(gate(3, armed("other"))).expect("receiver alive");
        assert_eq!(target(&guard, PUBLIC, 443), Ok(()));
    }

    #[test]
    fn a_deny_rule_is_not_hidden_by_an_allow_for_the_same_address() {
        // The allow comes first (lower priority number) and names the very
        // address that a later deny names; the guard is not the policy engine and
        // must refuse the answer anyway.
        let routing = routing(vec![
            (
                "main",
                vec![
                    rule("allow", 1, PUBLIC, None, RoutingAction::Direct),
                    rule("deny", 10, PUBLIC, None, RoutingAction::Deny),
                ],
            ),
            ("other", vec![]),
        ]);
        let (guard, _tx, _) = guard_in(&routing, armed("main"));
        assert_eq!(target(&guard, PUBLIC, 443), Err(REFUSAL_DENY_RULE));
        // Same with a port-specific allow in front of an all-port deny.
        let routing = self::routing(vec![
            (
                "main",
                vec![
                    rule("allow", 1, PUBLIC, Some(443), RoutingAction::Direct),
                    rule("deny", 10, PUBLIC, None, RoutingAction::Deny),
                ],
            ),
            ("other", vec![]),
        ]);
        let (guard, _tx, _) = guard_in(&routing, armed("main"));
        assert_eq!(target(&guard, PUBLIC, 443), Err(REFUSAL_DENY_RULE));
        assert_eq!(target(&guard, PUBLIC, 80), Err(REFUSAL_DENY_RULE));
    }

    #[test]
    fn a_deny_rule_written_in_the_mapped_spelling_still_matches() {
        // The configuration refuses such a rule; the guard does not rely on that.
        let mut denials = BTreeMap::new();
        denials.insert(
            "main".to_owned(),
            vec![DenyIp {
                ip: ip("::ffff:93.184.216.34"),
                port: None,
                rule_id: "mapped".into(),
            }],
        );
        let cells = GuardCells::new();
        cells.set_listener(LISTENER.parse().expect("listener"));
        let (_tx, rx) = watch::channel(gate(1, armed("main")));
        assert!(cells.set_gate(rx));
        let guard = IngressDirectGuard::new(cells, denials);
        assert_eq!(target(&guard, PUBLIC, 443), Err(REFUSAL_DENY_RULE));
        assert_eq!(
            target(&guard, "::ffff:93.184.216.34", 443),
            Err(REFUSAL_DENY_RULE)
        );
    }

    // -- the first hop ------------------------------------------------------

    #[test]
    fn first_hop_refuses_only_the_self_loop() {
        let (guard, _tx, _) = guard_in(&plain(), armed("main"));
        // A local or LAN proxy is legitimate configuration.
        assert_eq!(first_hop(&guard, "10.0.0.5", 1080), Ok(()));
        assert_eq!(first_hop(&guard, "192.168.1.9", 1080), Ok(()));
        assert_eq!(first_hop(&guard, "127.0.0.1", 1080), Ok(()));
        assert_eq!(first_hop(&guard, "::1", 1080), Ok(()));
        assert_eq!(first_hop(&guard, PUBLIC, 1080), Ok(()));
        // The listener, loopback on its port, the unspecified address on its port.
        for address in [
            "127.0.0.1",
            "127.9.9.9",
            "::1",
            "0.0.0.0",
            "::",
            "::ffff:127.0.0.1",
        ] {
            assert_eq!(
                first_hop(&guard, address, 10800),
                Err(REFUSAL_LISTENER),
                "{address}"
            );
        }
        // The same port on another host is not a loop.
        assert_eq!(first_hop(&guard, "192.168.1.9", 10800), Ok(()));
        assert_eq!(first_hop(&guard, PUBLIC, 10800), Ok(()));
    }

    #[test]
    fn first_hop_refuses_the_classes_that_are_never_a_proxy() {
        let (guard, _tx, _) = guard_in(&plain(), armed("main"));
        for (address, special) in [
            ("0.0.0.0", SpecialUse::Unspecified),
            ("0.9.9.9", SpecialUse::ThisNetwork),
            ("169.254.169.254", SpecialUse::Metadata),
            ("224.0.0.251", SpecialUse::Multicast),
            ("ff02::fb", SpecialUse::Multicast),
            ("255.255.255.255", SpecialUse::Broadcast),
            ("240.0.0.1", SpecialUse::Reserved),
            ("::", SpecialUse::Unspecified),
            ("100::1", SpecialUse::Discard),
            ("100:0:0:1::1", SpecialUse::DummyPrefix),
            ("::ffff:169.254.169.254", SpecialUse::Metadata),
        ] {
            assert_eq!(
                first_hop(&guard, address, 1080),
                Err(special.code()),
                "{address}"
            );
        }
        // And the legitimate ones stay legitimate: local, LAN, shared space,
        // link-local other than the metadata address, public.
        for address in [
            "127.0.0.1",
            "::1",
            "10.1.2.3",
            "192.168.1.9",
            "100.64.0.9",
            "169.254.1.1",
            "fe80::1",
            "fd00::1",
            PUBLIC,
        ] {
            assert_eq!(first_hop(&guard, address, 1080), Ok(()), "{address}");
        }
    }

    #[test]
    fn first_hop_does_not_look_at_the_gate_or_the_deny_rules() {
        let routing = routing(vec![
            (
                "main",
                vec![rule("deny", 1, "10.0.0.5", None, RoutingAction::Deny)],
            ),
            ("other", vec![]),
        ]);
        let (guard, tx, _) = guard_in(&routing, GateMode::Disarmed);
        assert_eq!(first_hop(&guard, "10.0.0.5", 1080), Ok(()));
        tx.send(gate(2, armed("main"))).expect("receiver alive");
        assert_eq!(
            first_hop(&guard, "10.0.0.5", 1080),
            Ok(()),
            "a deny rule is about targets"
        );
    }

    // -- vocabulary ---------------------------------------------------------

    #[test]
    fn refusal_labels_are_a_closed_set_without_forbidden_words() {
        let mut labels: Vec<&str> = SpecialUse::ALL.iter().map(|s| s.code()).collect();
        labels.extend([REFUSAL_LISTENER, REFUSAL_DENY_RULE, REFUSAL_NOT_ARMED]);
        let mut unique = labels.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), labels.len());
        for label in labels {
            assert!(
                label.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{label}"
            );
            assert_eq!(
                crate::ingress::types::contains_forbidden_word(label),
                None,
                "{label}"
            );
        }
    }

    // -- the executor -------------------------------------------------------

    #[test]
    fn ingress_executor_builder_installs_guard_and_family_filter() {
        let (guard, _tx, _) = guard_in(&plain(), armed("main"));
        let guard: Arc<dyn DirectAddrGuard> = Arc::new(guard);
        for (families, expected) in [
            (DirectAddressFamilies::Ipv4Only, AddressFamilies::Ipv4Only),
            (DirectAddressFamilies::Any, AddressFamilies::Any),
        ] {
            let mut cfg = IngressCfgView::for_tests();
            cfg.families = families;
            let executor = build_ingress_executor(AdapterRegistry::new(), &cfg, Arc::clone(&guard));
            assert!(executor.has_direct_guard());
            assert_eq!(executor.address_families(), expected);
            // The defaults: connect 20 s, so lookups are bounded by 5 s and the
            // whole dial by 5 + 20 + 5.
            assert_eq!(executor.connect_timeout(), Duration::from_secs(20));
            assert_eq!(executor.resolve_timeout(), Duration::from_secs(5));
            assert_eq!(executor.dial_deadline(), Duration::from_secs(30));
            // Through the data plane, the way the engine asks.
            let plane = NetcoreDataPlane::new(Arc::new(executor));
            assert!(plane.guards_direct_names());
        }
        // The activation executor is a different one and stays unguarded.
        let activation = RouteExecutor::new(AdapterRegistry::new());
        assert!(!activation.has_direct_guard());
        assert_eq!(activation.address_families(), AddressFamilies::Any);
        assert!(!NetcoreDataPlane::new(Arc::new(activation)).guards_direct_names());
    }

    // -- the executor and the guard together ---------------------------------

    /// The ingress executor of `build_ingress_executor` over the doubles, guarded
    /// by a real `IngressDirectGuard`.
    fn dialing(
        families: DirectAddressFamilies,
        routing: &ConfiguredRouting,
        mode: GateMode,
        resolver: &Arc<FakeResolver>,
        connector: &Arc<RecordingConnector>,
    ) -> (RouteExecutor, watch::Sender<Gate>) {
        let (guard, tx, _) = guard_in(routing, mode);
        let mut cfg = IngressCfgView::for_tests();
        cfg.families = families;
        let resolver: Arc<dyn ssk_netcore::NameResolver> = resolver.clone();
        let connector: Arc<dyn ssk_netcore::TcpConnector> = connector.clone();
        let executor = build_ingress_executor(AdapterRegistry::new(), &cfg, Arc::new(guard))
            .with_resolver(resolver)
            .with_connector(connector);
        (executor, tx)
    }

    async fn dial(
        executor: &RouteExecutor,
        name: &str,
    ) -> Result<ssk_netcore::EgressSession, NetcoreError> {
        executor.connect(&RouteKind::Direct, (name, 443)).await
    }

    #[tokio::test]
    async fn a_mixed_answer_is_refused_as_a_whole_and_nothing_is_dialled() {
        // The DNS-rebinding signature: a public address next to a private one.
        let resolver =
            Arc::new(FakeResolver::new().answering("rebind.example", &[PUBLIC, "10.0.0.7"]));
        let connector = Arc::new(RecordingConnector::new());
        let (executor, _tx) = dialing(
            DirectAddressFamilies::Any,
            &plain(),
            armed("main"),
            &resolver,
            &connector,
        );
        let refused = dial(&executor, "rebind.example")
            .await
            .expect_err("refused");
        assert!(
            matches!(
                refused,
                NetcoreError::AddressRefused {
                    code: "private",
                    refused: 1,
                    answers: 2
                }
            ),
            "{refused:?}"
        );
        assert_eq!(refused.code(), "NETCORE_ADDR_REFUSED");
        assert!(
            connector.started().is_empty(),
            "no socket for the allowed half either"
        );
        assert_eq!(
            resolver.calls(),
            vec![("rebind.example".to_owned(), 443)],
            "resolved exactly once"
        );
    }

    #[tokio::test]
    async fn a_name_that_resolves_into_loopback_or_the_listener_is_refused() {
        let resolver = Arc::new(
            FakeResolver::new()
                .answering("dev.example", &["127.0.0.1"])
                .answering("self.example", &["127.0.0.1"])
                .answering("meta.example", &["169.254.169.254"])
                .answering("v6.example", &["::1"]),
        );
        let connector = Arc::new(RecordingConnector::new());
        let (executor, _tx) = dialing(
            DirectAddressFamilies::Any,
            &plain(),
            armed("main"),
            &resolver,
            &connector,
        );
        for (name, code) in [
            ("dev.example", "loopback"),
            ("meta.example", "metadata"),
            ("v6.example", "loopback"),
        ] {
            let error = dial(&executor, name).await.expect_err("refused");
            assert!(
                matches!(error, NetcoreError::AddressRefused { code: c, .. } if c == code),
                "{name}: {error:?}"
            );
        }
        assert!(connector.started().is_empty());
    }

    #[tokio::test]
    async fn an_allowed_name_is_dialled_at_the_address_that_was_checked() {
        let resolver = Arc::new(FakeResolver::new().answering("ok.example", &[PUBLIC]));
        let connector = Arc::new(RecordingConnector::new());
        let (executor, _tx) = dialing(
            DirectAddressFamilies::Any,
            &plain(),
            armed("main"),
            &resolver,
            &connector,
        );
        let session = dial(&executor, "ok.example").await.expect("dialled");
        assert_eq!(connector.started(), vec![SocketAddr::new(ip(PUBLIC), 443)]);
        let resolution = session.resolution();
        assert_eq!(resolution.target.mode, ResolutionMode::OsResolver);
        assert_eq!(
            resolution.target.dialed,
            Some(SocketAddr::new(ip(PUBLIC), 443))
        );
        assert_eq!(resolution.target.answers, 1);
        assert_eq!(resolver.calls().len(), 1, "never resolved again");
    }

    #[tokio::test]
    async fn an_exact_ip_deny_rule_refuses_a_name_that_resolves_to_it() {
        let routing = routing(vec![
            (
                "main",
                vec![rule("deny-one", 10, PUBLIC, None, RoutingAction::Deny)],
            ),
            ("other", vec![]),
        ]);
        let resolver = Arc::new(
            FakeResolver::new()
                .answering("denied.example", &[PUBLIC])
                .answering("fine.example", &["93.184.216.99"]),
        );
        let connector = Arc::new(RecordingConnector::new());
        let (executor, _tx) = dialing(
            DirectAddressFamilies::Any,
            &routing,
            armed("main"),
            &resolver,
            &connector,
        );
        let refused = dial(&executor, "denied.example")
            .await
            .expect_err("refused");
        assert!(
            matches!(
                refused,
                NetcoreError::AddressRefused {
                    code: "deny_rule",
                    ..
                }
            ),
            "{refused:?}"
        );
        assert!(connector.started().is_empty());
        dial(&executor, "fine.example")
            .await
            .expect("another address is fine");
    }

    #[tokio::test]
    async fn a_disarmed_gate_refuses_a_dial_that_was_in_flight() {
        let resolver = Arc::new(FakeResolver::new().answering("ok.example", &[PUBLIC]));
        let connector = Arc::new(RecordingConnector::new());
        let (executor, tx) = dialing(
            DirectAddressFamilies::Any,
            &plain(),
            armed("main"),
            &resolver,
            &connector,
        );
        tx.send(gate(2, GateMode::Disarmed))
            .expect("receiver alive");
        let refused = dial(&executor, "ok.example").await.expect_err("refused");
        assert!(
            matches!(
                refused,
                NetcoreError::AddressRefused {
                    code: "not_armed",
                    ..
                }
            ),
            "{refused:?}"
        );
        assert!(connector.started().is_empty());
    }

    #[tokio::test]
    async fn ipv4_only_drops_ipv6_answers_before_anything_is_dialled() {
        let resolver = Arc::new(
            FakeResolver::new()
                .answering("v6only.example", &["2606:4700::1"])
                .answering("dual.example", &["2606:4700::1", PUBLIC]),
        );
        let connector = Arc::new(RecordingConnector::new());
        let (executor, _tx) = dialing(
            DirectAddressFamilies::Ipv4Only,
            &plain(),
            armed("main"),
            &resolver,
            &connector,
        );
        let error = dial(&executor, "v6only.example")
            .await
            .expect_err("filtered");
        assert!(matches!(error, NetcoreError::FamilyDisabled), "{error:?}");
        assert!(connector.started().is_empty());
        dial(&executor, "dual.example")
            .await
            .expect("the IPv4 answer is dialled");
        assert_eq!(connector.started(), vec![SocketAddr::new(ip(PUBLIC), 443)]);

        // With `any` the same IPv6-only name is dialled.
        let connector = Arc::new(RecordingConnector::new());
        let (executor, _tx) = dialing(
            DirectAddressFamilies::Any,
            &plain(),
            armed("main"),
            &resolver,
            &connector,
        );
        dial(&executor, "v6only.example")
            .await
            .expect("dialled over IPv6");
        assert_eq!(
            connector.started(),
            vec![SocketAddr::new(ip("2606:4700::1"), 443)]
        );
    }

    #[tokio::test]
    async fn the_unguarded_activation_executor_would_have_dialled_the_loopback_answer() {
        // The reason there are two executors: the same name, resolved the same
        // way, is dialled by the activation executor and refused by the ingress.
        let resolver = Arc::new(FakeResolver::new().answering("dev.example", &["127.0.0.1"]));
        let connector = Arc::new(RecordingConnector::new());
        let resolver_dyn: Arc<dyn ssk_netcore::NameResolver> = resolver.clone();
        let connector_dyn: Arc<dyn ssk_netcore::TcpConnector> = connector.clone();
        let activation = RouteExecutor::new(AdapterRegistry::new())
            .with_resolver(resolver_dyn)
            .with_connector(connector_dyn);
        dial(&activation, "dev.example").await.expect("unguarded");
        assert_eq!(connector.started().len(), 1);
    }

    #[test]
    fn the_timeouts_follow_the_configured_connect_timeout() {
        let guard: Arc<dyn DirectAddrGuard> =
            Arc::new(IngressDirectGuard::new(GuardCells::new(), BTreeMap::new()));
        // A short connect timeout also shortens the lookup bound (never longer
        // than the connect), and the dial deadline is resolve + connect + 5 s.
        let mut cfg = IngressCfgView::for_tests();
        cfg.limits.connect_timeout_ms = 3_000;
        let executor = build_ingress_executor(AdapterRegistry::new(), &cfg, Arc::clone(&guard));
        assert_eq!(executor.connect_timeout(), Duration::from_secs(3));
        assert_eq!(executor.resolve_timeout(), Duration::from_secs(3));
        assert_eq!(executor.dial_deadline(), Duration::from_secs(11));
        // A long one leaves the lookup at its own 5 s.
        cfg.limits.connect_timeout_ms = 60_000;
        let executor = build_ingress_executor(AdapterRegistry::new(), &cfg, guard);
        assert_eq!(executor.connect_timeout(), Duration::from_secs(60));
        assert_eq!(executor.resolve_timeout(), Duration::from_secs(5));
        assert_eq!(executor.dial_deadline(), Duration::from_secs(70));
    }

    #[test]
    fn the_family_setting_maps_one_to_one() {
        assert_eq!(
            address_families(DirectAddressFamilies::Ipv4Only),
            AddressFamilies::Ipv4Only
        );
        assert_eq!(
            address_families(DirectAddressFamilies::Any),
            AddressFamilies::Any
        );
    }
}
