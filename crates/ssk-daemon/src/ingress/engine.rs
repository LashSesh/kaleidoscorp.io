//! The engine of the local ingress (design 6.7): what one flow is allowed to do,
//! the durable record that says so, and the dial. It knows no socket: a front end
//! hands it a canonical [`Target`] and, afterwards, a reply code to send.
//!
//! * **[`decide`] is pure.** It writes nothing, resolves nothing and dials
//!   nothing. A refusal is a [`Denied`], and the front end records it
//!   ([`EngineCtx::record_denial`]) before it answers, so that a client that has
//!   seen a refusal for a fresh key has a durable record of it.
//! * **[`open_tunnel`] is the only place a connect starts.** The order is fixed:
//!   the `Pending` record is durable, the receipt is checked against the very token
//!   that is about to be dialled, the dial is marked started, the token is
//!   consumed by exactly one `connect_route` call (no retry, no second route), the
//!   `Result` record is durable, and only then is a [`ResultReceipt`] returned.
//!   That receipt is the proof that the success reply and the first byte demand.
//! * **Every way out leaves a closed story.** The receipts compensate when they
//!   are dropped (`audit/writer.rs`), so an early return, a cancelled future or a
//!   panic cannot leave a `Pending` without a `Result`.
//!
//! Neither a [`NetcoreError`] nor a route is ever formatted with `{:?}` or
//! `{}` here: the derived `Debug` of a route prints `HopSpec.auth`, and the text
//! of a network error names addresses. Records get closed codes, the client gets
//! a reply code.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ssk_config::ingress::DirectAddressFamilies;
use ssk_ipc::{DenialSummaryDto, FlowInspectionDto};
use ssk_netadmin::admission::AdmissionToken;
use ssk_netadmin::audit::summarise_route;
use ssk_netadmin::{
    AdapterKind, FlowDescriptor, FlowRecord, HopSpec, NetAdminError, ProtocolKind, RiskLevel,
    RouteKind,
};
use ssk_netcore::{
    is_resolvable_name, DataPlane, EgressSession, NetcoreError, ResolutionMode, SessionResolution,
};
use tokio::sync::watch;

use super::audit::input::{ConnectedEvent, DeniedEvent, FailedEvent, PendingInput};
use super::audit::writer::{AuditError, FlowAuditWriter, PendingReceipt, ResultReceipt, Waits};
use super::limits::{DenialCoalescer, DenialKey, DenialSummary, Disposition};
use super::pump::{gate_changed, gate_unchanged, ByteCounts};
use super::shared::{Counters, IngressShared, Installed};
use super::socks5::Rep;
use super::target::{guard_self_loop, guard_special_use, Refusal, Target, TargetKind};
use super::types::{
    lock_unpoisoned, Clock, Gate, Observation, PeerStamp, Resolution, OBSERVATION_EGRESS_LOCAL,
};
use crate::routing::{ConfiguredRouting, DecideError, RuleBinding};

/// The application a flow is attributed to. There is no process attribution on a
/// loopback listener, so every flow is the same unnamed application; a client
/// cannot choose it (`client_cannot_influence_profile_or_app_id`).
pub const ENGINE_APP_ID: &str = "local-proxy:unattributed";

/// `Denied.reason_code` values the engine produces besides those of
/// [`Refusal::reason_code`]. All are in the ledger's closed list
/// (`DENIED_REASON_CODES`), and a test says so.
pub const REASON_POLICY_DENY: &str = "POLICY_DENY";
pub const REASON_NO_VIABLE_ROUTE: &str = "NO_VIABLE_ROUTE";
pub const REASON_ATTESTATION_REQUIRED: &str = "ATTESTATION_REQUIRED";
pub const REASON_NOT_ARMED: &str = "NOT_ARMED";
pub const REASON_ROUTE_NOT_DIALABLE: &str = "ROUTE_NOT_DIALABLE";
pub const REASON_OPENVPN_NOT_READY: &str = "OPENVPN_NOT_READY";
pub const REASON_DIRECT_GUARD_MISSING: &str = "DIRECT_GUARD_MISSING";
pub const REASON_DIRECT_NAME_NOT_RESOLVABLE: &str = "DIRECT_NAME_NOT_RESOLVABLE";
pub const REASON_DIRECT_FAMILY_DISABLED: &str = "DIRECT_FAMILY_DISABLED";

/// `Result.error_code` values the engine writes itself (the rest come from
/// `NetcoreError::code()`). All are in `RESULT_ERROR_CODES`.
pub const CODE_GATE_CLOSED: &str = "GATE_CLOSED";
pub const CODE_RECEIPT_MISMATCH: &str = "RECEIPT_MISMATCH";
pub const CODE_CONNECT_DEADLINE: &str = "CONNECT_DEADLINE";

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Which SOCKS reply a refusal gets (design 6.7.1, MD-18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyClass {
    /// The policy said no, or there is no rule, or the route cannot be planned:
    /// `02`.
    Policy,
    /// The target is one the proxy never serves (special-use, self-loop, a name
    /// the OS resolver must not be asked for): `02`.
    Guard,
    /// The route cannot be executed here (OpenVPN, not dialable, no guard on
    /// names, nothing armed): `01`.
    Route,
    /// The kind of address cannot be served (a spelling that is refused, an IPv6
    /// literal under `ipv4_only`): `08`.
    Address,
}

/// A flow the engine refuses. Nothing was written, resolved or dialled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    /// A closed machine code (`DENIED_REASON_CODES`).
    pub reason: &'static str,
    pub class: DenyClass,
    /// The rule that matched, when one did.
    pub rule: Option<String>,
    /// The planned route (`summarise_route`), when there was one.
    pub route: Option<String>,
}

impl Denied {
    fn new(reason: &'static str, class: DenyClass) -> Self {
        Self {
            reason,
            class,
            rule: None,
            route: None,
        }
    }

    fn with_rule(mut self, rule: Option<String>) -> Self {
        self.rule = rule;
        self
    }

    fn with_route(mut self, route: &RouteKind) -> Self {
        self.route = Some(summarise_route(route));
        self
    }

    /// A target refusal, as the front end would count it.
    fn from_refusal(refusal: Refusal) -> Self {
        let class = match refusal {
            Refusal::Malformed | Refusal::NumericAlias | Refusal::LocalhostName => {
                DenyClass::Address
            }
            Refusal::SelfLoop | Refusal::SpecialUse(_) | Refusal::SpecialUseNeedsPort(_) => {
                DenyClass::Guard
            }
        };
        Self::new(refusal.reason_code(), class)
    }

    /// The SOCKS reply for this refusal.
    #[must_use]
    pub const fn reply(&self) -> Rep {
        match self.class {
            DenyClass::Policy | DenyClass::Guard => Rep::NotAllowed,
            DenyClass::Route => Rep::GeneralFailure,
            DenyClass::Address => Rep::AddressTypeNotSupported,
        }
    }
}

// ---------------------------------------------------------------------------
// The context
// ---------------------------------------------------------------------------

/// What the engine reads and writes besides the flow. One per started host.
pub struct EngineCtx {
    routing: Arc<ConfiguredRouting>,
    data_plane: Arc<dyn DataPlane>,
    shared: Arc<IngressShared>,
    denials: Mutex<DenialCoalescer>,
    clock: Arc<dyn Clock>,
    /// The BOUND address (with `listen.port == 0` that is not the configured one).
    listener: SocketAddr,
}

impl EngineCtx {
    #[must_use]
    pub fn new(
        routing: Arc<ConfiguredRouting>,
        data_plane: Arc<dyn DataPlane>,
        shared: Arc<IngressShared>,
        listener: SocketAddr,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let denials = Mutex::new(DenialCoalescer::new(shared.tuning(), clock.now()));
        Self {
            routing,
            data_plane,
            shared,
            denials,
            clock,
            listener,
        }
    }

    #[must_use]
    pub fn shared(&self) -> &Arc<IngressShared> {
        &self.shared
    }

    /// A flow id of the installed writer's boot, or `None` while there is no
    /// writer (a flow cannot be recorded then, so it is not started).
    #[must_use]
    pub fn mint_flow_id(&self) -> Option<String> {
        self.shared
            .ledger_slot()
            .current()
            .map(|installed| installed.writer.next_flow_id())
    }

    /// The refusals that were counted and not written since the last call, for the
    /// `Summary` record; the host calls this on its tick.
    pub fn denial_summary(&self) -> Option<DenialSummary> {
        lock_unpoisoned(&self.denials).take_summary(self.clock.now())
    }

    fn waits(&self) -> Waits {
        let tuning = self.shared.tuning();
        Waits {
            queue_wait: tuning.audit_queue_wait,
            sync_wait: tuning.audit_sync_wait,
        }
    }

    fn connect_timeout(&self) -> Duration {
        Duration::from_millis(u64::from(self.shared.cfg().limits.connect_timeout_ms))
    }

    fn families(&self) -> DirectAddressFamilies {
        self.shared.cfg().families
    }

    /// Counts what an append that did not give a receipt came to. A write fault
    /// has already tripped the gate (the writer's own trip callback); these are the
    /// ones that only cost the flow.
    fn note_audit(&self, error: AuditError) {
        let counters = self.shared.counters();
        match error {
            AuditError::Busy | AuditError::QueueFull | AuditError::Capacity => {
                Counters::bump(&counters.audit_busy);
            }
            AuditError::Timeout => Counters::bump(&counters.audit_timeouts),
            AuditError::OverQuota
            | AuditError::Closing
            | AuditError::RecordTooLarge
            | AuditError::Invalid(_)
            | AuditError::WriterDown
            | AuditError::SeqExhausted
            | AuditError::Io(_) => {}
        }
    }

    /// Counts a refusal and, for the first occurrence of its key, writes it before
    /// returning (design 7.2 state 4). A repeat or a refusal beyond the burst is
    /// only counted and reaches the ledger as part of a `Summary`. The client's
    /// reply does not depend on the outcome. Returns what became of the occurrence:
    /// only `FirstDurable` is worth a row in the registry of recent flows.
    pub async fn record_denial(
        &self,
        peer: &PeerStamp,
        profile: &str,
        target: &Target,
        denied: &Denied,
    ) -> Disposition {
        let counters = self.shared.counters();
        Counters::bump(&counters.denied);
        self.shared.set_last_denial(DenialSummaryDto {
            host: target.host().to_owned(),
            port: target.port(),
            reason_code: denied.reason.to_owned(),
            rule_id: denied.rule.clone(),
        });
        let key = DenialKey {
            profile: profile.to_owned(),
            host: target.host().to_owned(),
            port: target.port(),
            reason: denied.reason,
            rule: denied.rule.clone(),
        };
        let disposition = lock_unpoisoned(&self.denials).classify(key, self.clock.now());
        if disposition != Disposition::FirstDurable {
            Counters::bump(&counters.denied_suppressed);
            return disposition;
        }
        let Some(Installed { writer, .. }) = self.shared.ledger_slot().current() else {
            self.note_audit(AuditError::Closing);
            return disposition;
        };
        let event = DeniedEvent {
            peer: &peer.peer,
            peer_verified: peer.verified,
            target,
            profile,
            matched_rule: denied.rule.as_deref(),
            reason_code: denied.reason,
            route: denied.route.clone(),
            coalesced: false,
        };
        if let Err(error) = writer.append_denied(event, self.waits()).await {
            self.note_audit(error);
        }
        disposition
    }
}

// ---------------------------------------------------------------------------
// Deciding
// ---------------------------------------------------------------------------

/// A flow the policy allows and the route guard accepts, with the token that
/// authorises exactly this destination over exactly this route. Not `Debug`: a
/// derived `Debug` would print the route, and with it `HopSpec.auth`.
pub struct Admitted {
    token: AdmissionToken,
    flow_id: String,
    rule: Option<String>,
    adapters: Vec<String>,
    target: Target,
    resolution: Resolution,
    epoch: u64,
    inspection: FlowInspectionDto,
}

impl std::fmt::Debug for Admitted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admitted")
            .field("flow_id", &self.flow_id)
            .field("rule", &self.rule)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl Admitted {
    #[must_use]
    pub fn flow_id(&self) -> &str {
        &self.flow_id
    }

    /// The rule that matched. `None` is possible only for a route the implicit
    /// rule produced, and the implicit rule denies.
    #[must_use]
    pub fn rule(&self) -> Option<&str> {
        self.rule.as_deref()
    }

    /// The gate epoch the flow was admitted under.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// What `InspectFlow` shows for this flow: the descriptor the policy saw, the
    /// rule, the action, the route, whether attestation was required.
    #[must_use]
    pub fn inspection(&self) -> &FlowInspectionDto {
        &self.inspection
    }

    #[must_use]
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// The adapter ids of the planned route, in order; empty for `Direct`.
    #[must_use]
    pub fn adapters(&self) -> &[String] {
        &self.adapters
    }

    /// `Direct`, `SingleHop(id)` or `MultiHop(a->b)`: the text of the record.
    #[must_use]
    pub fn route_summary(&self) -> String {
        summarise_route(self.token.route())
    }

    /// The only bridge from the engine to the audit module (design 6.4.7).
    #[must_use]
    pub fn pending_input<'a>(&'a self, peer: &'a PeerStamp, profile: &'a str) -> PendingInput<'a> {
        PendingInput {
            token: &self.token,
            flow_id: &self.flow_id,
            profile,
            matched_rule: self.rule.as_deref(),
            peer: &peer.peer,
            peer_verified: peer.verified,
            target_kind: self.target.kind(),
            provenance: self.target.provenance(),
            resolution: self.resolution,
            planned_adapters: &self.adapters,
        }
    }
}

/// The ids of the hops of `route`, in order.
fn adapter_ids(route: &RouteKind) -> Vec<String> {
    match route {
        RouteKind::SingleHop(hop) => vec![hop.adapter_id.clone()],
        RouteKind::MultiHop(hops) => hops.iter().map(|hop| hop.adapter_id.clone()).collect(),
        RouteKind::Direct
        | RouteKind::OpenVpn { .. }
        | RouteKind::Fallback { .. }
        | RouteKind::Denied { .. } => Vec::new(),
    }
}

/// What the record says will happen to the name: a literal is dialled as it is, a
/// name on `Direct` is resolved once by this daemon and dialled pinned, a name on
/// a proxied route is forwarded unresolved.
fn planned_resolution(route: &RouteKind, target: &Target) -> Resolution {
    if target.ip().is_some() {
        return Resolution::Literal;
    }
    match route {
        RouteKind::Direct => Resolution::LocalPinned,
        _ => Resolution::ProxyResolved,
    }
}

/// `true` for a name the OS resolver may be asked for under `Direct`: a fully
/// qualified one. `.onion` must never reach DNS, and a single label or `.local`
/// name may be answered by multicast or link-local mechanisms instead of the
/// configured resolver (design 6.10).
fn direct_name_eligible(host: &str) -> bool {
    host.contains('.')
        && !host.ends_with(".local")
        && !host.ends_with(".onion")
        && is_resolvable_name(host)
}

/// The route guard of design 6.7.1.
fn route_guard(
    ctx: &EngineCtx,
    route: &RouteKind,
    target: &Target,
) -> Result<(), (&'static str, DenyClass)> {
    match route {
        RouteKind::Denied { .. } | RouteKind::Fallback { .. } => {
            Err((REASON_ROUTE_NOT_DIALABLE, DenyClass::Route))
        }
        RouteKind::OpenVpn { .. } => Err((REASON_OPENVPN_NOT_READY, DenyClass::Route)),
        RouteKind::Direct => match target.kind() {
            TargetKind::Ipv6 if ctx.families() == DirectAddressFamilies::Ipv4Only => {
                Err((REASON_DIRECT_FAMILY_DISABLED, DenyClass::Address))
            }
            TargetKind::Ipv4 | TargetKind::Ipv6 => Ok(()),
            TargetKind::Name => {
                if !ctx.data_plane.guards_direct_names() {
                    Err((REASON_DIRECT_GUARD_MISSING, DenyClass::Route))
                } else if !direct_name_eligible(target.host()) {
                    Err((REASON_DIRECT_NAME_NOT_RESOLVABLE, DenyClass::Guard))
                } else {
                    Ok(())
                }
            }
        },
        RouteKind::SingleHop(hop) => last_hop_dialable(ctx, hop),
        RouteKind::MultiHop(hops) => match hops.last() {
            Some(hop) => last_hop_dialable(ctx, hop),
            None => Err((REASON_ROUTE_NOT_DIALABLE, DenyClass::Route)),
        },
    }
}

/// The destination reaches the far end only through a proxy that is told where to
/// connect. A last hop that merely wraps the previous transport (TLS) would end
/// the client's bytes at the hop's own address (design 6.7.1).
fn last_hop_dialable(ctx: &EngineCtx, hop: &HopSpec) -> Result<(), (&'static str, DenyClass)> {
    match ctx.routing.adapters.get(&hop.adapter_id).map(|d| d.kind) {
        Some(AdapterKind::Socks5 | AdapterKind::HttpConnect) => Ok(()),
        Some(
            AdapterKind::Direct
            | AdapterKind::TlsTunnel
            | AdapterKind::DnsOverride
            | AdapterKind::OpenVpn,
        )
        | None => Err((REASON_ROUTE_NOT_DIALABLE, DenyClass::Route)),
    }
}

/// Decides one flow (design 6.7.1). The caller has run `canonicalize`, minted
/// `flow_id` ([`EngineCtx::mint_flow_id`]) and taken `profile` and `epoch` from
/// one borrow of the gate.
///
/// The order is fixed: self-loop, policy, attestation, special-use, route guard,
/// admission. Pure: no record, no socket, no resolver, no token consumed.
///
/// # Errors
/// [`Denied`], with the reason the client's reply and the record are built from.
pub fn decide(
    ctx: &EngineCtx,
    profile: &str,
    epoch: u64,
    flow_id: String,
    target: &Target,
) -> Result<Admitted, Denied> {
    // 1. A literal that points back at the listener, before any rule.
    guard_self_loop(target, ctx.listener).map_err(Denied::from_refusal)?;
    // 2. The flow, as the policy engine sees it.
    let flow = FlowRecord::new(
        flow_id,
        0,
        FlowDescriptor::new(
            ENGINE_APP_ID,
            target.host(),
            target.port(),
            ProtocolKind::Tcp,
            RiskLevel::Low,
        ),
    );
    // 3. Policy and plan. A plan error is a recorded denial here (unlike an
    //    activation, which reports it).
    let decided = match ctx.routing.decide(profile, &flow) {
        Ok(decided) => decided,
        Err(DecideError::UnknownProfile) => {
            return Err(Denied::new(REASON_NOT_ARMED, DenyClass::Route));
        }
        Err(DecideError::Evaluate(_)) => {
            return Err(Denied::new(REASON_NO_VIABLE_ROUTE, DenyClass::Policy));
        }
        Err(DecideError::Plan(_)) => {
            // The rule that matched is still the useful part of the record.
            let rule = ctx
                .routing
                .engine(profile)
                .and_then(|engine| engine.evaluate(&flow).ok())
                .and_then(|decision| decision.matched_rule);
            return Err(Denied::new(REASON_NO_VIABLE_ROUTE, DenyClass::Policy).with_rule(rule));
        }
    };
    let rule = decided.decision.matched_rule.clone();
    let route = &decided.candidate.route;
    if decided.candidate.is_denied() {
        return Err(Denied::new(REASON_POLICY_DENY, DenyClass::Policy).with_rule(rule));
    }
    if decided.candidate.requires_attestation {
        return Err(Denied::new(REASON_ATTESTATION_REQUIRED, DenyClass::Policy)
            .with_rule(rule)
            .with_route(route));
    }
    // 4. A literal in a special-use range needs an exact rule for it.
    let binding = rule
        .as_deref()
        .map_or(RuleBinding::NoExactDestination, |id| {
            ctx.routing.rule_binding(profile, id)
        });
    if let Err(refusal) = guard_special_use(target, binding) {
        return Err(Denied::from_refusal(refusal)
            .with_rule(rule)
            .with_route(route));
    }
    // 5. The route guard.
    if let Err((reason, class)) = route_guard(ctx, route, target) {
        return Err(Denied::new(reason, class).with_rule(rule).with_route(route));
    }
    // 6. Admission: the token is minted here and only here.
    let token = match ctx.routing.orchestrator.admit(&flow, &decided.decision) {
        Ok(token) => token,
        Err(error) => {
            let reason = match error {
                NetAdminError::AttestationRequired(_) => REASON_ATTESTATION_REQUIRED,
                NetAdminError::FailClosed(_) => REASON_POLICY_DENY,
                _ => REASON_NO_VIABLE_ROUTE,
            };
            return Err(Denied::new(reason, DenyClass::Policy)
                .with_rule(rule)
                .with_route(route));
        }
    };
    let inspection = FlowInspectionDto {
        descriptor: flow.descriptor,
        matched_rule: rule.clone(),
        action: decided.decision.action,
        route: token.route().clone(),
        requires_attestation: decided.candidate.requires_attestation,
    };
    Ok(Admitted {
        flow_id: flow.flow_id,
        adapters: adapter_ids(token.route()),
        resolution: planned_resolution(token.route(), target),
        token,
        rule,
        target: target.clone(),
        epoch,
        inspection,
    })
}

// ---------------------------------------------------------------------------
// Dialling
// ---------------------------------------------------------------------------

/// Why a flow did not become a tunnel.
pub enum DialFault {
    /// No `Pending` was written, so nothing was dialled: the ledger refused (or
    /// has no writer). The client gets `01`.
    Audit(AuditError),
    /// The dial failed and the failure is on record (or the record is owed by the
    /// `Pending`'s drop). The client gets the mapped reply.
    Dial(NetcoreError),
    /// The tunnel was established and its `Result` could not be written, so it was
    /// dropped. The client gets nothing: no reply, no byte.
    ResultLost(AuditError),
    /// The gate moved on (disarm, trip, re-arm, a recover that installed another
    /// writer). The client gets nothing.
    Cancelled,
    /// `connect_timeout` ended the dial. The client gets `04`.
    Deadline,
    /// The record did not name this destination and route; nothing was dialled.
    ReceiptMismatch,
}

impl std::fmt::Debug for DialFault {
    // The code only: the text of a network error names addresses.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Audit(error) => f.debug_tuple("Audit").field(&error.code()).finish(),
            Self::Dial(error) => f.debug_tuple("Dial").field(&error.code()).finish(),
            Self::ResultLost(error) => f.debug_tuple("ResultLost").field(&error.code()).finish(),
            Self::Cancelled => f.write_str("Cancelled"),
            Self::Deadline => f.write_str("Deadline"),
            Self::ReceiptMismatch => f.write_str("ReceiptMismatch"),
        }
    }
}

impl DialFault {
    /// The closed machine code the registry row of the flow carries.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Audit(error) | Self::ResultLost(error) => error.code(),
            Self::Dial(error) => error.code(),
            Self::Cancelled => CODE_GATE_CLOSED,
            Self::Deadline => CODE_CONNECT_DEADLINE,
            Self::ReceiptMismatch => CODE_RECEIPT_MISMATCH,
        }
    }

    /// The outcome word of the flow's row (`FlowSummaryDto.outcome`): `refused`
    /// when nothing was dialled, `connect_failed` when a dial failed or its result
    /// could not be recorded, `cancelled` when the gate moved on.
    #[must_use]
    pub const fn outcome(&self) -> &'static str {
        match self {
            Self::Audit(_) | Self::ReceiptMismatch => "refused",
            Self::Dial(_) | Self::Deadline | Self::ResultLost(_) => "connect_failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// The SOCKS reply, or `None` when the connection is just closed.
    #[must_use]
    pub fn reply(&self) -> Option<Rep> {
        match self {
            Self::Audit(_) | Self::ReceiptMismatch => Some(Rep::GeneralFailure),
            Self::Dial(error) => Some(reply_for_error(error)),
            Self::Deadline => Some(Rep::HostUnreachable),
            Self::ResultLost(_) | Self::Cancelled => None,
        }
    }
}

/// A tunnel whose `Result` is durable: the only thing a success reply and a byte
/// may follow.
pub struct Established {
    pub session: EgressSession,
    /// The proof; `closed` consumes it when the tunnel ends.
    pub result: ResultReceipt,
    /// `AdapterKind` words of the chain that was really traversed.
    pub chain_kinds: Vec<&'static str>,
    /// Shared with the receipt, which writes the real byte counts if the flow
    /// dies without closing the tunnel.
    pub counts: Arc<ByteCounts>,
    /// The ledger sequence number of the flow's `Pending` record.
    pub pending_seq: u64,
    /// The source address the OS gave the upstream socket (an observation).
    pub egress_local: Option<String>,
}

impl std::fmt::Debug for Established {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Established")
            .field("chain_kinds", &self.chain_kinds)
            .finish_non_exhaustive()
    }
}

/// The SOCKS reply for a failed dial (design 6.10, "Errors to SOCKS replies").
/// A match without a wildcard: a new error stops compiling here until it has a
/// reply. Upstream detail, adapter addresses and credentials never reach the
/// client.
#[must_use]
pub fn reply_for_error(error: &NetcoreError) -> Rep {
    match error {
        NetcoreError::DialFailed { source, .. } => reply_for_error(source),
        NetcoreError::AddressRefused { .. } => Rep::NotAllowed,
        NetcoreError::DnsResolutionFailed(..)
        | NetcoreError::Timeout(..)
        | NetcoreError::FamilyDisabled => Rep::HostUnreachable,
        NetcoreError::ConnectionRefused(..) => Rep::ConnectionRefused,
        NetcoreError::Io(_, source) => match source.kind() {
            std::io::ErrorKind::NetworkUnreachable => Rep::NetUnreachable,
            std::io::ErrorKind::HostUnreachable => Rep::HostUnreachable,
            _ => Rep::GeneralFailure,
        },
        NetcoreError::ResolverBusy
        | NetcoreError::OpenVpnNotReady(_)
        | NetcoreError::TlsHandshakeFailed(..)
        | NetcoreError::ProxyRejected(..)
        | NetcoreError::Unsupported(_)
        | NetcoreError::PolicyDenied(_)
        | NetcoreError::NoRoute(_)
        | NetcoreError::UnknownAdapter(_)
        | NetcoreError::ProtocolError(..)
        | NetcoreError::InvalidTarget(_) => Rep::GeneralFailure,
    }
}

/// The word of an adapter kind in `Result.chain_kinds`. An exhaustive match, not
/// `{:?}`.
const fn kind_word(kind: AdapterKind) -> &'static str {
    match kind {
        AdapterKind::Direct => "direct",
        AdapterKind::Socks5 => "socks5",
        AdapterKind::HttpConnect => "http_connect",
        AdapterKind::TlsTunnel => "tls_tunnel",
        AdapterKind::DnsOverride => "dns_override",
        AdapterKind::OpenVpn => "open_vpn",
    }
}

/// The source address the OS gave the socket this process opened: the target's for
/// a `Direct` dial, the first hop's for a proxy chain. An observation, not a
/// statement about any adapter (design 10.5).
fn egress_local(resolution: &SessionResolution) -> Option<Observation> {
    let local = resolution.target.local_addr.or_else(|| {
        resolution
            .first_hop
            .as_ref()
            .and_then(|first_hop| first_hop.local_addr)
    })?;
    Observation::new(OBSERVATION_EGRESS_LOCAL, &local.ip().to_string())
}

fn connected_event(session: &EgressSession, chain_kinds: &[&'static str]) -> ConnectedEvent {
    let resolution = session.resolution();
    let target = &resolution.target;
    ConnectedEvent {
        chain_kinds: chain_kinds.to_vec(),
        dialed: target.dialed,
        attempted: target.attempted.clone(),
        // Only a lookup this daemon did has answers to count.
        answers: (target.mode == ResolutionMode::OsResolver).then_some(target.answers),
        observations: egress_local(resolution).into_iter().collect(),
    }
}

/// `0` answers means nothing was looked up.
fn answers_of(count: u8) -> Option<u8> {
    (count > 0).then_some(count)
}

/// `true` for the errors a connect that was started produces. The others (a
/// refusal by the guard or the family filter, a bad target, a busy resolver) end a
/// dial before any socket exists.
const fn connect_was_started(error: &NetcoreError) -> bool {
    matches!(
        error,
        NetcoreError::ConnectionRefused(..) | NetcoreError::Timeout(..) | NetcoreError::Io(..)
    )
}

/// The address of a `Direct` dial to a literal, which is the one dial whose failure
/// carries no `DialAttempts` (design 6.10): the engine writes what was tried.
fn literal_direct(token: &AdmissionToken) -> Option<SocketAddr> {
    let (host, port) = token.target();
    match token.route() {
        RouteKind::Direct => host
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, port)),
        _ => None,
    }
}

fn failed_event(error: &NetcoreError, literal: Option<SocketAddr>) -> FailedEvent {
    let (inner, attempts) = match error {
        NetcoreError::DialFailed { source, attempts } => (&**source, Some(attempts)),
        other => (other, None),
    };
    let (refusal, refused_answers) = match inner {
        NetcoreError::AddressRefused { code, answers, .. } => (Some(*code), answers_of(*answers)),
        _ => (None, None),
    };
    let attempted = match attempts {
        Some(attempts) => attempts.attempted.clone(),
        None if connect_was_started(inner) => literal.into_iter().collect(),
        None => Vec::new(),
    };
    FailedEvent {
        error_code: error.code(),
        refusal,
        attempted,
        answers: refused_answers.or_else(|| attempts.and_then(|a| answers_of(a.answers))),
        observations: Vec::new(),
    }
}

/// The boot prefix a flow id carries: `ingress:b<seq>:<n>` gives `b<seq>`.
fn flow_id_boot(flow_id: &str) -> Option<&str> {
    flow_id
        .strip_prefix("ingress:")?
        .split_once(':')
        .map(|(boot, _)| boot)
}

/// The dial of design 6.7.2 (c): the one place a connect starts.
///
/// The record must name exactly the destination and route of the token that is
/// about to be consumed; then the dial is marked started (from here a drop without
/// a result means `Aborted`, not `NotDialed`) and the token is spent by the one
/// `connect_route` call of the flow: no retry, no second route. The call is raced
/// against the gate (a dial of an old epoch is cancelled, and dropping the future
/// closes every socket it opened) and bounded by `connect_timeout`, which covers
/// resolution and every proxy handshake. A dial that failed or ran out of time is
/// recorded here, as `Failed`; a dial the gate cancelled is left to the `Pending`'s
/// drop, which writes `Aborted`.
async fn dial(
    ctx: &EngineCtx,
    writer: &FlowAuditWriter,
    pending: &PendingReceipt,
    token: AdmissionToken,
    gate: &mut watch::Receiver<Gate>,
    epoch: u64,
) -> Result<EgressSession, DialFault> {
    let waits = ctx.waits();
    if !pending.matches(&token) {
        let _ = writer
            .append_not_dialed(
                pending,
                CODE_RECEIPT_MISMATCH,
                ctx.shared.tuning().closed_deadline,
            )
            .await;
        return Err(DialFault::ReceiptMismatch);
    }
    pending.mark_dial_started();
    let literal = literal_direct(&token);
    let counters = ctx.shared.counters();
    let dialled = tokio::select! {
        biased;
        () = gate_changed(gate, epoch) => return Err(DialFault::Cancelled),
        done = tokio::time::timeout(ctx.connect_timeout(), ctx.data_plane.connect_route(token)) => done,
    };
    match dialled {
        Ok(Ok(session)) => Ok(session),
        Ok(Err(error)) => {
            Counters::bump(&counters.connect_failed);
            if matches!(error, NetcoreError::ResolverBusy) {
                Counters::bump(&counters.resolver_busy);
            }
            if let Err(audit) = writer
                .append_failed(pending, failed_event(&error, literal), waits)
                .await
            {
                ctx.note_audit(audit);
            }
            Err(DialFault::Dial(error))
        }
        Err(_) => {
            Counters::bump(&counters.connect_failed);
            let event = FailedEvent {
                attempted: literal.into_iter().collect(),
                ..FailedEvent::code(CODE_CONNECT_DEADLINE)
            };
            if let Err(audit) = writer.append_failed(pending, event, waits).await {
                ctx.note_audit(audit);
            }
            Err(DialFault::Deadline)
        }
    }
}

/// Authorises, dials and records one admitted flow (design 6.7.2).
///
/// On `Ok` the upstream tunnel exists and its `Result` is durable. On `Err` the
/// fault says what the client is told ([`DialFault::reply`]); nothing is left
/// open and every story that was begun is closed by its receipt.
///
/// # Errors
/// [`DialFault`].
pub async fn open_tunnel(
    ctx: &EngineCtx,
    adm: Admitted,
    peer: &PeerStamp,
    profile: &str,
    gate: &mut watch::Receiver<Gate>,
) -> Result<Established, DialFault> {
    let waits = ctx.waits();
    let closed_deadline = ctx.shared.tuning().closed_deadline;
    // (a) The writer this flow was minted for, and the gate it was admitted under.
    //     A flow whose writer was replaced (a recover) or whose gate moved on is
    //     not recorded into a chain it does not belong to.
    let Some(Installed { writer, boot }) = ctx.shared.ledger_slot().current() else {
        return Err(DialFault::Audit(AuditError::Closing));
    };
    if flow_id_boot(&adm.flow_id) != Some(&*boot) || !gate_unchanged(gate, adm.epoch) {
        return Err(DialFault::Cancelled);
    }
    let pending = writer
        .append_pending(adm.pending_input(peer, profile), waits)
        .await
        .map_err(|error| {
            ctx.note_audit(error);
            DialFault::Audit(error)
        })?;
    // (b) Durable now. If the gate moved while the record was being written, the
    //     flow does not dial: its story is closed as not dialled.
    if !gate_unchanged(gate, adm.epoch) {
        // A failure of this append is covered by the `Pending`'s drop, which
        // writes the same code.
        let _ = writer
            .append_not_dialed(&pending, CODE_GATE_CLOSED, closed_deadline)
            .await;
        return Err(DialFault::Cancelled);
    }
    let Admitted { token, epoch, .. } = adm;
    // (c) The dial, bound to the record.
    let session = dial(ctx, &writer, &pending, token, gate, epoch).await?;
    // (d) The tunnel exists. A gate that moved while the dial finished discards it.
    if !gate_unchanged(gate, epoch) {
        drop(session);
        return Err(DialFault::Cancelled);
    }
    let chain_kinds: Vec<&'static str> = session
        .chain()
        .iter()
        .map(|kind| kind_word(*kind))
        .collect();
    let counts = Arc::new(ByteCounts::default());
    let egress = egress_local(session.resolution()).map(|observation| observation.value);
    match writer
        .append_connected(
            &pending,
            connected_event(&session, &chain_kinds),
            Arc::clone(&counts),
            waits,
        )
        .await
    {
        Ok(result) => Ok(Established {
            session,
            result,
            chain_kinds,
            counts,
            pending_seq: pending.seq(),
            egress_local: egress,
        }),
        Err(error) => {
            // The tunnel is dropped first (the upstream closes), and the client
            // is told nothing: a byte or a reply without a durable result would
            // be exactly what the ledger exists to prevent.
            drop(session);
            ctx.note_audit(error);
            Err(DialFault::ResultLost(error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::io;
    use std::sync::atomic::Ordering;

    use ssk_config::ingress::DestinationLogging;
    use ssk_config::routing::{AdapterTransport, RoutingAction};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::ingress::audit::dest::DestSealer;
    use crate::ingress::audit::input::{
        CloseReason, ClosedEvent, DENIED_REASON_CODES, RESULT_ERROR_CODES, RESULT_REFUSALS,
    };
    use crate::ingress::audit::record::FlowAuditEvent;
    use crate::ingress::audit::testing::FakeIo;
    use crate::ingress::audit::writer::Replayed;
    use crate::ingress::target::{canonicalize, RawTarget};
    use crate::ingress::test_rig::net_fakes::{FakeResolver, Outcome, RecordingConnector};
    use crate::ingress::test_rig::*;
    use crate::ingress::types::{
        DisarmCause, GateMode, IngressCfgView, ResultOutcome, SystemClock, TripReason, Tuning,
        Unresolved,
    };

    // -- vocabularies -------------------------------------------------------------

    #[test]
    fn every_reason_the_engine_writes_is_in_the_ledgers_closed_lists() {
        for reason in [
            REASON_POLICY_DENY,
            REASON_NO_VIABLE_ROUTE,
            REASON_ATTESTATION_REQUIRED,
            REASON_NOT_ARMED,
            REASON_ROUTE_NOT_DIALABLE,
            REASON_OPENVPN_NOT_READY,
            REASON_DIRECT_GUARD_MISSING,
            REASON_DIRECT_NAME_NOT_RESOLVABLE,
            REASON_DIRECT_FAMILY_DISABLED,
        ] {
            assert!(DENIED_REASON_CODES.contains(&reason), "{reason}");
        }
        for code in [
            CODE_GATE_CLOSED,
            CODE_RECEIPT_MISMATCH,
            CODE_CONNECT_DEADLINE,
        ] {
            assert!(RESULT_ERROR_CODES.contains(&code), "{code}");
        }
        // The refusals of the target module are the same words.
        for refusal in [
            Refusal::Malformed,
            Refusal::NumericAlias,
            Refusal::LocalhostName,
            Refusal::SelfLoop,
        ] {
            assert!(
                DENIED_REASON_CODES.contains(&refusal.reason_code()),
                "{}",
                refusal.reason_code()
            );
        }
    }

    #[test]
    fn the_words_of_a_chain_are_the_documented_ones_and_free_of_forbidden_words() {
        let words: Vec<&str> = [
            AdapterKind::Direct,
            AdapterKind::Socks5,
            AdapterKind::HttpConnect,
            AdapterKind::TlsTunnel,
            AdapterKind::DnsOverride,
            AdapterKind::OpenVpn,
        ]
        .into_iter()
        .map(kind_word)
        .collect();
        assert_eq!(
            words,
            [
                "direct",
                "socks5",
                "http_connect",
                "tls_tunnel",
                "dns_override",
                "open_vpn"
            ]
        );
    }

    #[test]
    fn a_refusal_gets_the_reply_of_its_class() {
        let reply = |class| Denied::new("X", class).reply();
        assert_eq!(reply(DenyClass::Policy), Rep::NotAllowed);
        assert_eq!(reply(DenyClass::Guard), Rep::NotAllowed);
        assert_eq!(reply(DenyClass::Route), Rep::GeneralFailure);
        assert_eq!(reply(DenyClass::Address), Rep::AddressTypeNotSupported);
        // The three refusals canonicalisation produces are `08`, the others `02`.
        for (refusal, rep) in [
            (Refusal::Malformed, Rep::AddressTypeNotSupported),
            (Refusal::NumericAlias, Rep::AddressTypeNotSupported),
            (Refusal::LocalhostName, Rep::AddressTypeNotSupported),
            (Refusal::SelfLoop, Rep::NotAllowed),
        ] {
            assert_eq!(Denied::from_refusal(refusal).reply(), rep);
        }
    }

    #[test]
    fn a_dial_error_maps_to_the_reply_of_the_design_table() {
        let io = |kind| NetcoreError::Io("h:1".into(), io::Error::from(kind));
        let wrap = |source: NetcoreError| NetcoreError::DialFailed {
            source: Box::new(source),
            attempts: ssk_netcore::DialAttempts {
                answers: 1,
                attempted: Vec::new(),
            },
        };
        let table: Vec<(NetcoreError, Rep)> = vec![
            (
                NetcoreError::AddressRefused {
                    code: "loopback",
                    refused: 1,
                    answers: 1,
                },
                Rep::NotAllowed,
            ),
            (
                NetcoreError::DnsResolutionFailed("n".into(), "os".into(), "x".into()),
                Rep::HostUnreachable,
            ),
            (
                NetcoreError::Timeout("h:1".into(), Duration::ZERO),
                Rep::HostUnreachable,
            ),
            (NetcoreError::FamilyDisabled, Rep::HostUnreachable),
            (NetcoreError::ResolverBusy, Rep::GeneralFailure),
            (
                NetcoreError::ConnectionRefused("h:1".into(), "x".into()),
                Rep::ConnectionRefused,
            ),
            (io(io::ErrorKind::NetworkUnreachable), Rep::NetUnreachable),
            (io(io::ErrorKind::HostUnreachable), Rep::HostUnreachable),
            (io(io::ErrorKind::BrokenPipe), Rep::GeneralFailure),
            (
                NetcoreError::ProxyRejected("h:1".into(), "x".into()),
                Rep::GeneralFailure,
            ),
            (
                NetcoreError::TlsHandshakeFailed("h:1".into(), "x".into()),
                Rep::GeneralFailure,
            ),
            (
                NetcoreError::ProtocolError("h:1".into(), "x".into()),
                Rep::GeneralFailure,
            ),
            (
                NetcoreError::OpenVpnNotReady("p".into()),
                Rep::GeneralFailure,
            ),
            (NetcoreError::InvalidTarget("x".into()), Rep::GeneralFailure),
        ];
        for (error, rep) in table {
            assert_eq!(reply_for_error(&error), rep, "{}", error.code());
            // A wrapper maps by its source.
            assert_eq!(reply_for_error(&wrap(error)), rep);
        }
    }

    #[test]
    fn a_fault_says_what_the_client_is_told() {
        assert_eq!(
            DialFault::Audit(AuditError::Busy).reply(),
            Some(Rep::GeneralFailure)
        );
        assert_eq!(
            DialFault::ReceiptMismatch.reply(),
            Some(Rep::GeneralFailure)
        );
        assert_eq!(DialFault::Deadline.reply(), Some(Rep::HostUnreachable));
        assert_eq!(
            DialFault::Dial(NetcoreError::FamilyDisabled).reply(),
            Some(Rep::HostUnreachable)
        );
        // Nothing is said when the result is not durable or the gate moved on.
        assert_eq!(DialFault::ResultLost(AuditError::Io("X")).reply(), None);
        assert_eq!(DialFault::Cancelled.reply(), None);
    }

    #[test]
    fn a_fault_prints_its_code_and_never_the_text_of_a_network_error() {
        let fault = DialFault::Dial(NetcoreError::ConnectionRefused(
            "93.184.216.34:443".into(),
            "secret-detail".into(),
        ));
        let printed = format!("{fault:?}");
        assert!(printed.contains("NETCORE_CONNECTION_REFUSED"), "{printed}");
        assert!(!printed.contains("93.184"), "{printed}");
        assert!(!printed.contains("secret"), "{printed}");
    }

    // -- the route guard -----------------------------------------------------------

    fn guard_rig(guards_names: bool, families: DirectAddressFamilies) -> impl Future<Output = Rig> {
        let mut spec = Spec::new();
        spec.guards_names = guards_names;
        spec.families = families;
        spec.adapters = vec![
            adapter("exit", socks(PROXY, 1080)),
            adapter(
                "wrap",
                AdapterTransport::TlsTunnel {
                    host: PROXY.into(),
                    port: 443,
                },
            ),
            adapter(
                "pipe",
                AdapterTransport::HttpConnect {
                    host: PROXY.into(),
                    port: 3128,
                },
            ),
            adapter(
                "ovpn",
                AdapterTransport::OpenVpn {
                    profile_id: "work".into(),
                },
            ),
        ];
        Rig::new(spec)
    }

    fn name_target(host: &str) -> Target {
        canonicalize(RawTarget::Name(host.as_bytes().to_vec(), 443)).expect("canonical")
    }

    fn hop(id: &str) -> HopSpec {
        HopSpec::new(id, PROXY, 1080)
    }

    #[tokio::test]
    async fn the_route_guard_refuses_what_cannot_be_executed() {
        let rig = guard_rig(true, DirectAddressFamilies::Ipv4Only).await;
        let target = name_target("site.example");
        let refused = |route: &RouteKind| route_guard(&rig.ctx, route, &target);
        // Routes the executor never runs.
        assert_eq!(
            refused(&RouteKind::Denied { reason: "x".into() }),
            Err((REASON_ROUTE_NOT_DIALABLE, DenyClass::Route))
        );
        assert_eq!(
            refused(&RouteKind::Fallback {
                primary: Box::new(RouteKind::Direct),
                fallback: Box::new(RouteKind::Direct),
            }),
            Err((REASON_ROUTE_NOT_DIALABLE, DenyClass::Route))
        );
        assert_eq!(
            refused(&RouteKind::OpenVpn {
                adapter_id: "ovpn".into(),
                profile_id: "work".into()
            }),
            Err((REASON_OPENVPN_NOT_READY, DenyClass::Route))
        );
        // A last hop must be told where to connect: a TLS wrapper is not, an
        // unknown adapter is not, a chain with no hop is not.
        assert_eq!(
            refused(&RouteKind::SingleHop(hop("wrap"))),
            Err((REASON_ROUTE_NOT_DIALABLE, DenyClass::Route))
        );
        assert_eq!(
            refused(&RouteKind::SingleHop(hop("ghost"))),
            Err((REASON_ROUTE_NOT_DIALABLE, DenyClass::Route))
        );
        assert_eq!(
            refused(&RouteKind::MultiHop(vec![hop("exit"), hop("wrap")])),
            Err((REASON_ROUTE_NOT_DIALABLE, DenyClass::Route))
        );
        assert_eq!(
            refused(&RouteKind::MultiHop(Vec::new())),
            Err((REASON_ROUTE_NOT_DIALABLE, DenyClass::Route))
        );
        // Only the LAST hop decides: a wrapper in front of a proxy is fine.
        assert_eq!(
            refused(&RouteKind::MultiHop(vec![hop("wrap"), hop("pipe")])),
            Ok(())
        );
        assert_eq!(refused(&RouteKind::SingleHop(hop("exit"))), Ok(()));
        assert_eq!(refused(&RouteKind::SingleHop(hop("pipe"))), Ok(()));
    }

    #[tokio::test]
    async fn direct_to_a_name_needs_a_guarded_data_plane_and_a_name_the_resolver_may_see() {
        let guarded = guard_rig(true, DirectAddressFamilies::Ipv4Only).await;
        let unguarded = guard_rig(false, DirectAddressFamilies::Ipv4Only).await;
        let check =
            |rig: &Rig, host: &str| route_guard(&rig.ctx, &RouteKind::Direct, &name_target(host));
        assert_eq!(check(&guarded, "site.example"), Ok(()));
        assert_eq!(check(&guarded, "a.b.c.example"), Ok(()));
        // The data plane is asked first, and says so by a route-class refusal.
        assert_eq!(
            check(&unguarded, "site.example"),
            Err((REASON_DIRECT_GUARD_MISSING, DenyClass::Route))
        );
        // Names the OS resolver must not see: one label, mDNS, an onion service.
        for host in ["intranet", "printer.local", "hidden.onion", "a.b.local"] {
            assert_eq!(
                check(&guarded, host),
                Err((REASON_DIRECT_NAME_NOT_RESOLVABLE, DenyClass::Guard)),
                "{host}"
            );
        }
        // A name that merely ends in the letters is a different name.
        assert_eq!(check(&guarded, "notlocal.example"), Ok(()));
        assert_eq!(check(&guarded, "localhost.example"), Ok(()));
    }

    #[test]
    fn name_eligibility_is_the_dot_the_two_suffixes_and_the_resolvers_own_rule() {
        for host in [
            "site.example",
            "x.y",
            "a-b.example",
            "xn--bcher-kva.example",
        ] {
            assert!(direct_name_eligible(host), "{host}");
        }
        for host in [
            "intranet",
            "host.local",
            "x.onion",
            "",
            ".",
            "a..b",
            "-a.example",
            "a b.example",
            "a.1",
        ] {
            assert!(!direct_name_eligible(host), "{host:?}");
        }
    }

    #[tokio::test]
    async fn an_ipv6_literal_is_refused_on_direct_under_ipv4_only_and_served_under_any() {
        let only = guard_rig(true, DirectAddressFamilies::Ipv4Only).await;
        let any = guard_rig(true, DirectAddressFamilies::Any).await;
        let v6 = canonicalize(RawTarget::V6(
            "2606:4700:4700::1111".parse().expect("address"),
            443,
        ))
        .expect("canonical");
        let v4 = canonicalize(RawTarget::V4(PUBLIC.parse().expect("address"), 443)).expect("v4");
        assert_eq!(
            route_guard(&only.ctx, &RouteKind::Direct, &v6),
            Err((REASON_DIRECT_FAMILY_DISABLED, DenyClass::Address))
        );
        assert_eq!(route_guard(&only.ctx, &RouteKind::Direct, &v4), Ok(()));
        assert_eq!(route_guard(&any.ctx, &RouteKind::Direct, &v6), Ok(()));
        // The family only matters on `Direct`: a proxy dials the address itself.
        assert_eq!(
            route_guard(&only.ctx, &RouteKind::SingleHop(hop("exit")), &v6),
            Ok(())
        );
    }

    // -- decide --------------------------------------------------------------------

    #[tokio::test]
    async fn an_allowed_literal_is_admitted_with_its_rule_and_a_plan() {
        let rig = Rig::new(Spec::new()).await;
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        assert_eq!(adm.rule(), Some("allow-web"));
        assert_eq!(adm.route_summary(), "Direct");
        assert!(adm.adapters().is_empty());
        assert_eq!(adm.epoch(), rig.epoch());
        assert_eq!(adm.resolution, Resolution::Literal);
        assert!(adm.flow_id().starts_with("ingress:b"), "{}", adm.flow_id());
        // `decide` is pure: no record, no dial.
        assert_eq!(rig.count("pending"), 0);
        assert_eq!(rig.count("denied"), 0);
        assert!(rig.plane.calls().is_empty());
        // The Debug form carries no route.
        let printed = format!("{adm:?}");
        assert!(!printed.contains("Direct"), "{printed}");
    }

    #[tokio::test]
    async fn the_input_for_the_ledger_is_built_from_the_admission_alone() {
        let mut spec = Spec::new();
        spec.rules.push(rule(
            "via-exit",
            5,
            None,
            Some("proxied.test"),
            None,
            adapter_action("exit"),
        ));
        let rig = Rig::new(spec).await;
        let adm = rig.admit_name("api.proxied.test", 443).expect("admitted");
        let peer = Rig::peer();
        let input = adm.pending_input(&peer, "main");
        assert_eq!(input.flow_id, adm.flow_id());
        assert_eq!(input.profile, "main");
        assert_eq!(input.matched_rule, Some("via-exit"));
        assert_eq!(input.peer, "127.0.0.1:50000");
        assert!(input.peer_verified);
        assert_eq!(input.target_kind, TargetKind::Name);
        assert_eq!(input.provenance.as_str(), "client_supplied_name");
        assert_eq!(input.resolution, Resolution::ProxyResolved);
        assert_eq!(input.planned_adapters, ["exit".to_owned()]);
        assert_eq!(input.token.target(), ("api.proxied.test", 443));
        assert_eq!(adm.route_summary(), "SingleHop(exit)");
    }

    #[tokio::test]
    async fn a_name_on_direct_is_planned_as_resolved_here_and_a_proxied_name_is_not() {
        let mut spec = Spec::new();
        spec.rules.push(rule(
            "via-exit",
            5,
            None,
            Some("proxied.test"),
            None,
            adapter_action("exit"),
        ));
        let rig = Rig::new(spec).await;
        let direct = rig.admit_name("www.example.test", 443).expect("admitted");
        assert_eq!(direct.resolution, Resolution::LocalPinned);
        assert_eq!(direct.rule(), Some("allow-names"));
        let proxied = rig.admit_name("api.proxied.test", 443).expect("admitted");
        assert_eq!(proxied.resolution, Resolution::ProxyResolved);
        // An address on a proxied route is a literal whatever the route is.
        let mut spec = Spec::new();
        spec.rules.push(rule(
            "ip-via-exit",
            5,
            Some(OTHER),
            None,
            None,
            adapter_action("exit"),
        ));
        let rig = Rig::new(spec).await;
        let literal = rig.admit_v4(OTHER, 80).expect("admitted");
        assert_eq!(literal.resolution, Resolution::Literal);
        assert_eq!(literal.adapters(), ["exit".to_owned()]);
    }

    #[tokio::test]
    async fn no_matching_rule_is_a_default_deny_without_a_rule_id() {
        let rig = Rig::new(Spec::new()).await;
        let denied = rig.admit_v4("8.8.8.8", 443).expect_err("denied");
        assert_eq!(denied.reason, REASON_POLICY_DENY);
        assert_eq!(denied.class, DenyClass::Policy);
        assert_eq!(denied.rule, None);
        assert_eq!(denied.reply(), Rep::NotAllowed);
    }

    #[tokio::test]
    async fn a_deny_rule_refuses_with_its_id_and_a_name_rule_never_matches_an_address() {
        let rig = Rig::new(Spec::new()).await;
        let denied = rig.admit_v4(OTHER, 443).expect_err("denied");
        assert_eq!(denied.reason, REASON_POLICY_DENY);
        assert_eq!(denied.rule.as_deref(), Some("deny-other"));
        // `allow-names` is a suffix rule: a client that sends an address is not
        // matched by it, and default-deny applies.
        let by_address = rig.admit_v4("8.8.4.4", 443).expect_err("denied");
        assert_eq!(by_address.rule, None);
    }

    #[tokio::test]
    async fn a_rule_that_needs_attestation_is_denied() {
        let mut spec = Spec::new();
        let mut attested = rule(
            "attested",
            5,
            Some(PUBLIC),
            None,
            Some(8443),
            RoutingAction::Direct,
        );
        attested.require_attestation = true;
        spec.rules.insert(0, attested);
        let rig = Rig::new(spec).await;
        let denied = rig.admit_v4(PUBLIC, 8443).expect_err("denied");
        assert_eq!(denied.reason, REASON_ATTESTATION_REQUIRED);
        assert_eq!(denied.class, DenyClass::Policy);
        assert_eq!(denied.rule.as_deref(), Some("attested"));
        assert_eq!(denied.route.as_deref(), Some("Direct"));
        assert_eq!(denied.reply(), Rep::NotAllowed);
    }

    #[tokio::test]
    async fn an_unknown_adapter_is_a_denial_that_keeps_the_rule_and_never_falls_back_to_direct() {
        let mut spec = Spec::new();
        spec.rules.insert(
            0,
            rule(
                "to-ghost",
                5,
                Some(PUBLIC),
                None,
                Some(8080),
                adapter_action("ghost"),
            ),
        );
        // A lower-priority Direct rule for the same destination exists and must
        // not be consulted: first match wins.
        spec.rules.push(rule(
            "fallback-direct",
            50,
            Some(PUBLIC),
            None,
            Some(8080),
            RoutingAction::Direct,
        ));
        let rig = Rig::new(spec).await;
        let denied = rig.admit_v4(PUBLIC, 8080).expect_err("denied");
        assert_eq!(denied.reason, REASON_NO_VIABLE_ROUTE);
        assert_eq!(denied.rule.as_deref(), Some("to-ghost"));
        assert_eq!(denied.reply(), Rep::NotAllowed);
        assert!(rig.plane.calls().is_empty());
    }

    #[tokio::test]
    async fn a_profile_the_routing_does_not_hold_is_not_armed() {
        let rig = Rig::new(Spec::new()).await;
        let target =
            canonicalize(RawTarget::V4(PUBLIC.parse().expect("address"), 443)).expect("v4");
        let id = rig.ctx.mint_flow_id().expect("a writer");
        let denied = decide(&rig.ctx, "other", 1, id, &target).expect_err("denied");
        assert_eq!(denied.reason, REASON_NOT_ARMED);
        assert_eq!(denied.class, DenyClass::Route);
        assert_eq!(denied.reply(), Rep::GeneralFailure);
    }

    #[tokio::test]
    async fn a_literal_that_points_back_at_the_listener_is_refused_before_any_rule() {
        let mut spec = Spec::new();
        // A rule that names the listener exactly, and a catch-all: neither may help.
        spec.rules.insert(
            0,
            rule(
                "to-listener",
                1,
                Some("127.0.0.1"),
                None,
                Some(10800),
                RoutingAction::Direct,
            ),
        );
        let rig = Rig::new(spec).await;
        for (ip, port) in [
            ("127.0.0.1", 10800),
            ("0.0.0.0", 10800),
            ("127.9.9.9", 10800),
        ] {
            let denied = rig.admit_v4(ip, port).expect_err("refused");
            assert_eq!(denied.reason, "TARGET_SELF_LOOP", "{ip}");
            assert_eq!(denied.class, DenyClass::Guard);
            assert_eq!(denied.rule, None, "refused before the policy ran");
            assert_eq!(denied.reply(), Rep::NotAllowed);
        }
        let v6 = rig
            .admit(RawTarget::V6(std::net::Ipv6Addr::LOCALHOST, 10800))
            .expect_err("refused");
        assert_eq!(v6.reason, "TARGET_SELF_LOOP");
    }

    #[tokio::test]
    async fn a_special_use_literal_needs_an_exact_rule_with_a_port() {
        let mut spec = Spec::new();
        spec.rules = vec![
            rule(
                "lan-printer",
                10,
                Some("192.168.1.50"),
                None,
                Some(9100),
                RoutingAction::Direct,
            ),
            rule(
                "lan-no-port",
                11,
                Some("192.168.1.60"),
                None,
                None,
                RoutingAction::Direct,
            ),
            rule(
                "lan-denied",
                12,
                Some("192.168.1.70"),
                None,
                Some(80),
                RoutingAction::Deny,
            ),
            rule("anything", 90, None, None, None, RoutingAction::Direct),
        ];
        let rig = Rig::new(spec).await;
        // The exact rule with its port opens exactly that address and port.
        let adm = rig
            .admit_v4("192.168.1.50", 9100)
            .expect("opened by its rule");
        assert_eq!(adm.rule(), Some("lan-printer"));
        // The same address on another port falls to the catch-all, which opens
        // nothing special-use.
        let other_port = rig.admit_v4("192.168.1.50", 9101).expect_err("refused");
        assert_eq!(other_port.reason, "SPECIAL_USE_NEEDS_EXACT_RULE");
        assert_eq!(other_port.rule.as_deref(), Some("anything"));
        assert_eq!(other_port.class, DenyClass::Guard);
        assert_eq!(other_port.route.as_deref(), Some("Direct"));
        // A rule for the address without a port is not enough.
        let no_port = rig.admit_v4("192.168.1.60", 80).expect_err("refused");
        assert_eq!(no_port.reason, "SPECIAL_USE_NEEDS_PORT");
        assert_eq!(no_port.rule.as_deref(), Some("lan-no-port"));
        // A deny rule is a denial, not an exemption.
        let denied = rig.admit_v4("192.168.1.70", 80).expect_err("denied");
        assert_eq!(denied.reason, REASON_POLICY_DENY);
        // Loopback and the metadata address are special-use too.
        for ip in ["127.0.0.1", "169.254.169.254", "10.0.0.1", "100.64.0.1"] {
            let refused = rig.admit_v4(ip, 8080).expect_err("refused");
            assert_eq!(refused.reason, "SPECIAL_USE_NEEDS_EXACT_RULE", "{ip}");
        }
    }

    #[tokio::test]
    async fn spellings_of_one_address_meet_the_one_rule() {
        let mut spec = Spec::new();
        spec.rules.insert(
            0,
            rule(
                "v6-rule",
                5,
                Some("2606:4700:4700::1111"),
                None,
                Some(443),
                RoutingAction::Direct,
            ),
        );
        spec.families = DirectAddressFamilies::Any;
        let rig = Rig::new(spec).await;
        // An IPv4-mapped IPv6 address is the IPv4 address, so the IPv4 rule applies.
        let mapped = "::ffff:93.184.216.34".parse().expect("address");
        let adm = rig.admit(RawTarget::V6(mapped, 443)).expect("admitted");
        assert_eq!(adm.rule(), Some("allow-web"));
        assert_eq!(adm.target().host(), PUBLIC);
        // A long spelling of an IPv6 address is its compressed form.
        let long = "2606:4700:4700:0:0:0:0:1111".parse().expect("address");
        let adm = rig.admit(RawTarget::V6(long, 443)).expect("admitted");
        assert_eq!(adm.rule(), Some("v6-rule"));
    }

    #[tokio::test]
    async fn the_route_guard_runs_after_policy_so_a_denial_says_why_first() {
        let mut spec = Spec::new();
        spec.rules.insert(
            0,
            rule(
                "to-ovpn",
                5,
                Some(PUBLIC),
                None,
                Some(8000),
                adapter_action("ovpn"),
            ),
        );
        spec.adapters.push(adapter(
            "ovpn",
            AdapterTransport::OpenVpn {
                profile_id: "work".into(),
            },
        ));
        spec.rules.insert(
            1,
            rule(
                "to-wrap",
                6,
                Some(PUBLIC),
                None,
                Some(8001),
                adapter_action("wrap"),
            ),
        );
        spec.adapters.push(adapter(
            "wrap",
            AdapterTransport::TlsTunnel {
                host: PROXY.into(),
                port: 443,
            },
        ));
        let rig = Rig::new(spec).await;
        let ovpn = rig.admit_v4(PUBLIC, 8000).expect_err("refused");
        assert_eq!(ovpn.reason, REASON_OPENVPN_NOT_READY);
        assert_eq!(ovpn.rule.as_deref(), Some("to-ovpn"));
        assert_eq!(ovpn.class, DenyClass::Route);
        assert_eq!(ovpn.reply(), Rep::GeneralFailure);
        assert_eq!(ovpn.route.as_deref(), Some("openvpn:ovpn:work"));
        let wrap = rig.admit_v4(PUBLIC, 8001).expect_err("refused");
        assert_eq!(wrap.reason, REASON_ROUTE_NOT_DIALABLE);
        assert_eq!(wrap.route.as_deref(), Some("SingleHop(wrap)"));
        // Nothing was written, resolved or dialled for either.
        assert_eq!(rig.count("pending"), 0);
        assert!(rig.plane.calls().is_empty());
    }

    #[tokio::test]
    async fn a_name_on_direct_is_refused_without_a_guarded_plane_and_for_names_the_os_must_not_see()
    {
        let mut spec = Spec::new();
        spec.rules = vec![rule(
            "names",
            10,
            None,
            Some("example.test"),
            None,
            RoutingAction::Direct,
        )];
        spec.guards_names = false;
        let rig = Rig::new(spec).await;
        let unguarded = rig
            .admit_name("www.example.test", 443)
            .expect_err("refused");
        assert_eq!(unguarded.reason, REASON_DIRECT_GUARD_MISSING);
        assert_eq!(unguarded.reply(), Rep::GeneralFailure);

        let mut spec = Spec::new();
        spec.rules = vec![rule("all", 10, None, None, None, RoutingAction::Direct)];
        let rig = Rig::new(spec).await;
        for host in ["intranet", "printer.local", "x.onion"] {
            let refused = rig.admit_name(host, 443).expect_err("refused");
            assert_eq!(refused.reason, REASON_DIRECT_NAME_NOT_RESOLVABLE, "{host}");
            assert_eq!(refused.reply(), Rep::NotAllowed);
        }
        assert!(rig.admit_name("www.example.org", 443).is_ok());
    }

    #[tokio::test]
    async fn an_ipv6_literal_on_direct_is_refused_with_reply_08_under_ipv4_only() {
        let mut spec = Spec::new();
        spec.rules = vec![rule("all", 10, None, None, None, RoutingAction::Direct)];
        let rig = Rig::new(spec).await;
        let v6 = "2606:4700:4700::1111".parse().expect("address");
        let denied = rig.admit(RawTarget::V6(v6, 443)).expect_err("refused");
        assert_eq!(denied.reason, REASON_DIRECT_FAMILY_DISABLED);
        assert_eq!(denied.reply(), Rep::AddressTypeNotSupported);
        assert_eq!(denied.rule.as_deref(), Some("all"));
    }

    // -- recording refusals ------------------------------------------------------------

    fn denied_events(rig: &Rig) -> Vec<FlowAuditEvent> {
        rig.events()
            .into_iter()
            .filter(|event| event.kind() == "denied")
            .collect()
    }

    #[tokio::test]
    async fn the_first_refusal_of_a_key_is_durable_when_the_call_returns_and_repeats_are_counted() {
        let rig = Rig::new(Spec::new()).await;
        let target = canonicalize(RawTarget::V4(OTHER.parse().expect("address"), 443)).expect("v4");
        let denied = rig.admit_v4(OTHER, 443).expect_err("denied");
        let peer = Rig::peer();

        rig.ctx.record_denial(&peer, "main", &target, &denied).await;
        // No polling: the record is on the disk when the call has returned.
        let first = denied_events(&rig);
        assert_eq!(first.len(), 1, "{first:?}");
        let FlowAuditEvent::Denied {
            peer: p,
            peer_verified,
            dest,
            target_kind,
            profile,
            matched_rule,
            reason_code,
            coalesced,
            ..
        } = &first[0]
        else {
            panic!("a denied record");
        };
        assert_eq!(p, "127.0.0.1:50000");
        assert!(*peer_verified);
        assert_eq!(
            dest,
            &crate::ingress::types::DestRef::Plain {
                host: OTHER.into(),
                port: 443
            }
        );
        assert_eq!(target_kind, "ipv4");
        assert_eq!(profile, "main");
        assert_eq!(matched_rule.as_deref(), Some("deny-other"));
        assert_eq!(reason_code, REASON_POLICY_DENY);
        assert!(!*coalesced);

        for _ in 0..4 {
            rig.ctx.record_denial(&peer, "main", &target, &denied).await;
        }
        assert_eq!(denied_events(&rig).len(), 1, "repeats are not written");
        let counters = rig.shared.counters().dto();
        assert_eq!((counters.denied, counters.denied_suppressed), (5, 4));
        // They reach the ledger as one summary, which the host asks for.
        let summary = rig.ctx.denial_summary().expect("a summary");
        assert_eq!(summary.suppressed.get(REASON_POLICY_DENY), Some(&4));
        assert_eq!(summary.repeated.len(), 1);
        assert_eq!(summary.repeated[0].count, 4);
        assert_eq!(rig.ctx.denial_summary(), None, "drained");
        // The newest refusal is what status shows.
        let shown = rig.shared.snapshot().last_denial.expect("last denial");
        assert_eq!(
            (shown.host.as_str(), shown.port, shown.reason_code.as_str()),
            (OTHER, 443, REASON_POLICY_DENY)
        );
        assert_eq!(shown.rule_id.as_deref(), Some("deny-other"));
    }

    #[tokio::test]
    async fn a_different_reason_rule_or_destination_is_a_different_key() {
        let rig = Rig::new(Spec::new()).await;
        let peer = Rig::peer();
        let a = canonicalize(RawTarget::V4(OTHER.parse().expect("address"), 443)).expect("v4");
        let b = canonicalize(RawTarget::V4(OTHER.parse().expect("address"), 444)).expect("v4");
        let denied = Denied::new(REASON_POLICY_DENY, DenyClass::Policy);
        let other_reason = Denied::new(REASON_NO_VIABLE_ROUTE, DenyClass::Policy);
        let other_rule =
            Denied::new(REASON_POLICY_DENY, DenyClass::Policy).with_rule(Some("r".into()));
        for (target, denied) in [
            (&a, &denied),
            (&b, &denied),
            (&a, &other_reason),
            (&a, &other_rule),
        ] {
            rig.ctx.record_denial(&peer, "main", target, denied).await;
        }
        assert_eq!(denied_events(&rig).len(), 4);
        // The same key under another profile is another key.
        rig.ctx.record_denial(&peer, "alt", &a, &denied).await;
        assert_eq!(denied_events(&rig).len(), 5);
        assert_eq!(rig.shared.counters().dto().denied_suppressed, 0);
    }

    #[tokio::test]
    async fn a_refusal_flood_is_bounded_and_every_refusal_is_accounted_for() {
        let rig = Rig::new(Spec::new()).await;
        let peer = Rig::peer();
        let denied = Denied::new(REASON_POLICY_DENY, DenyClass::Policy);
        for n in 0..200_u16 {
            let target = canonicalize(RawTarget::Name(
                format!("host{n}.example").into_bytes(),
                443,
            ))
            .expect("name");
            rig.ctx.record_denial(&peer, "main", &target, &denied).await;
        }
        let written = denied_events(&rig).len();
        let counters = rig.shared.counters().dto();
        // The burst is 20 and the refill one per second.
        assert!((20..=24).contains(&written), "{written}");
        assert_eq!(counters.denied, 200);
        assert_eq!(
            counters.denied_suppressed + u64::try_from(written).expect("fits"),
            200,
            "written plus counted is every refusal"
        );
        let summary = rig.ctx.denial_summary().expect("a summary");
        assert_eq!(
            summary.suppressed.values().sum::<u64>(),
            counters.denied_suppressed
        );
    }

    #[tokio::test]
    async fn a_refusal_with_no_writer_is_counted_and_nothing_panics() {
        let rig = Rig::new(Spec::new()).await;
        // A host that has not installed a writer (a recover that failed half way).
        let empty = Arc::new(crate::ingress::shared::LedgerSlot::new());
        let (events, _) = tokio::sync::broadcast::channel(4);
        let bare = IngressShared::with_ledger(
            IngressCfgView::for_tests(),
            Tuning::default(),
            events,
            Arc::clone(&empty),
            empty,
        );
        let ctx = EngineCtx::new(
            Arc::clone(&rig.ctx.routing),
            Arc::clone(&rig.ctx.data_plane),
            bare,
            sa(LISTENER),
            Arc::new(SystemClock),
        );
        assert_eq!(
            ctx.mint_flow_id(),
            None,
            "no flow is started without a writer"
        );
        let target = canonicalize(RawTarget::V4(OTHER.parse().expect("address"), 443)).expect("v4");
        ctx.record_denial(
            &Rig::peer(),
            "main",
            &target,
            &Denied::new(REASON_POLICY_DENY, DenyClass::Policy),
        )
        .await;
        assert_eq!(ctx.shared().counters().dto().denied, 1);
    }

    // -- the tunnel ---------------------------------------------------------------------

    fn verified(rig: &Rig) -> crate::ingress::audit::verify::Verified {
        crate::ingress::audit::verify::verify_dir(
            &rig.io.view(),
            crate::ingress::audit::verify::VerifyMode::Open,
        )
        .expect("the ledger verifies")
    }

    fn direct_spec() -> (Spec, Arc<FakeResolver>, Arc<KeepingConnector>) {
        let resolver = Arc::new(FakeResolver::new());
        let connector = KeepingConnector::new();
        let spec = Spec::new().over(resolver.clone(), connector.clone());
        (spec, resolver, connector)
    }

    fn result_of(rig: &Rig, n: usize) -> FlowAuditEvent {
        rig.events()
            .into_iter()
            .filter(|event| event.kind() == "result")
            .nth(n)
            .expect("a result record")
    }

    #[tokio::test]
    async fn a_direct_flow_leaves_pending_connected_and_closed_in_order_under_one_flow_id() {
        let (spec, _resolver, connector) = direct_spec();
        let rig = Rig::new(spec).await;
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        let flow_id = adm.flow_id().to_owned();
        let established = rig.open(adm).await.expect("established");

        assert_eq!(established.chain_kinds, ["direct"]);
        assert_eq!(
            connector.started.lock().expect("lock").clone(),
            [sa("93.184.216.34:443")]
        );
        let records = rig.io.records();
        let flow: Vec<_> = records.iter().filter(|r| r.flow_id == flow_id).collect();
        assert_eq!(
            flow.iter().map(|r| r.event.kind()).collect::<Vec<_>>(),
            ["pending", "result"],
            "the result is durable before the tunnel is handed over"
        );
        let FlowAuditEvent::Pending {
            peer,
            peer_verified,
            dest,
            target_provenance,
            target_kind,
            resolution,
            profile,
            matched_rule,
            route,
            planned_adapters,
        } = &flow[0].event
        else {
            panic!("a pending record");
        };
        assert_eq!(peer, "127.0.0.1:50000");
        assert!(*peer_verified);
        assert_eq!(
            dest,
            &crate::ingress::types::DestRef::Plain {
                host: PUBLIC.into(),
                port: 443
            }
        );
        assert_eq!(target_provenance, "client_supplied_literal");
        assert_eq!(target_kind, "ipv4");
        assert_eq!(*resolution, Resolution::Literal);
        assert_eq!(profile, "main");
        assert_eq!(matched_rule.as_deref(), Some("allow-web"));
        assert_eq!(route, "Direct");
        assert!(planned_adapters.is_empty());
        let FlowAuditEvent::Result {
            outcome,
            error_code,
            refusal,
            chain_kinds,
            dialed,
            attempted,
            answers,
            observations,
        } = &flow[1].event
        else {
            panic!("a result record");
        };
        assert_eq!(*outcome, ResultOutcome::Connected);
        assert_eq!((error_code, refusal), (&None, &None));
        assert_eq!(chain_kinds, &["direct".to_owned()]);
        let plain = |ip: &str| crate::ingress::types::AddrRef::Plain {
            ip: ip.into(),
            port: 443,
        };
        assert_eq!(dialed, &Some(plain(PUBLIC)));
        assert_eq!(attempted, &[plain(PUBLIC)]);
        assert_eq!(*answers, None, "a literal has no lookup to count");
        assert_eq!(
            observations,
            &[Observation::new("egress_local", "192.0.2.99").expect("valid")]
        );

        // The tunnel ends: the close record carries the counted bytes.
        established
            .result
            .closed(
                ClosedEvent {
                    bytes_up: 5,
                    bytes_down: 7,
                    reason: CloseReason::Eof,
                },
                Duration::from_secs(1),
            )
            .await;
        let closed: Vec<_> = rig
            .io
            .records()
            .into_iter()
            .filter(|r| r.flow_id == flow_id && r.event.kind() == "closed")
            .collect();
        assert_eq!(closed.len(), 1);
        let FlowAuditEvent::Closed {
            bytes_up,
            bytes_down,
            reason,
            ..
        } = &closed[0].event
        else {
            panic!("a closed record");
        };
        assert_eq!((*bytes_up, *bytes_down, reason.as_str()), (5, 7, "eof"));
        let verified = verified(&rig);
        assert_eq!(verified.unresolved, Unresolved::default());
        let counters = rig.shared.counters().dto();
        assert_eq!(counters.connect_failed, 0);
    }

    #[tokio::test]
    async fn bytes_flow_only_after_the_result_and_the_close_record_carries_the_counts() {
        let (spec, _resolver, connector) = direct_spec();
        let rig = Rig::new(spec).await;
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        let epoch = adm.epoch();
        let mut est = rig.open(adm).await.expect("established");
        let mut far = connector.take_far();
        let (mut client_far, mut client_near) = tokio::io::duplex(4096);
        let mut gate = rig.shared.gate();

        let driver = async {
            client_far.write_all(b"hello").await.expect("write");
            let mut up = [0u8; 5];
            far.read_exact(&mut up).await.expect("read");
            assert_eq!(&up, b"hello");
            far.write_all(b"goodbye").await.expect("write");
            let mut down = [0u8; 7];
            client_far.read_exact(&mut down).await.expect("read");
            assert_eq!(&down, b"goodbye");
            drop(client_far);
            drop(far);
        };
        let pumped = crate::ingress::pump::pump(
            &mut client_near,
            est.session.transport_mut(),
            &est.result,
            Duration::from_secs(5),
            &mut gate,
            epoch,
            &est.counts,
        );
        let (end, ()) = tokio::join!(pumped, driver);
        assert_eq!(end, crate::ingress::pump::PumpEnd::Eof);
        let (up, down) = (est.counts.up(), est.counts.down());
        assert_eq!((up, down), (5, 7));
        est.result
            .closed(
                ClosedEvent {
                    bytes_up: up,
                    bytes_down: down,
                    reason: end.into(),
                },
                Duration::from_secs(1),
            )
            .await;
        let FlowAuditEvent::Closed {
            bytes_up,
            bytes_down,
            ..
        } = rig
            .events()
            .into_iter()
            .find(|e| e.kind() == "closed")
            .expect("closed")
        else {
            panic!("closed");
        };
        assert_eq!((bytes_up, bytes_down), (5, 7));
    }

    #[tokio::test]
    async fn a_tunnel_that_is_dropped_leaves_a_closed_record_of_its_own() {
        let (spec, _resolver, _connector) = direct_spec();
        let rig = Rig::new(spec).await;
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        let established = rig.open(adm).await.expect("established");
        drop(established);
        rig.until("a close record", |rig| rig.count("closed") == 1)
            .await;
        let FlowAuditEvent::Closed {
            bytes_up,
            bytes_down,
            reason,
            ..
        } = rig
            .events()
            .into_iter()
            .find(|e| e.kind() == "closed")
            .expect("closed")
        else {
            panic!("closed");
        };
        assert_eq!((bytes_up, bytes_down, reason.as_str()), (0, 0, "aborted"));
        assert_eq!(verified(&rig).unresolved, Unresolved::default());
    }

    #[tokio::test]
    async fn the_dial_does_not_start_before_the_pending_record_is_durable() {
        let (spec, _resolver, connector) = direct_spec();
        let rig = Arc::new(Rig::new(spec).await);
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        rig.io.block();
        let task = {
            let rig = Arc::clone(&rig);
            tokio::spawn(async move { rig.open(adm).await })
        };
        rig.wait_in_sync().await;
        // The record is appended and waiting for its sync: nothing is dialled.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(rig.plane.calls().is_empty());
        assert!(connector.started.lock().expect("lock").is_empty());
        rig.io.release();
        let established = task.await.expect("joins").expect("established");
        assert_eq!(rig.plane.calls().len(), 1);
        drop(established);
    }

    #[tokio::test]
    async fn a_name_is_not_looked_up_before_the_pending_record_is_durable() {
        let resolver = Arc::new(FakeResolver::new().answering("www.example.test", &[PUBLIC]));
        let connector = KeepingConnector::new();
        let rig = Arc::new(Rig::new(Spec::new().over(resolver.clone(), connector.clone())).await);
        let adm = rig.admit_name("www.example.test", 443).expect("admitted");
        rig.io.block();
        let task = {
            let rig = Arc::clone(&rig);
            tokio::spawn(async move { rig.open(adm).await })
        };
        rig.wait_in_sync().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            resolver.calls().is_empty(),
            "the DNS query is an audited event"
        );
        rig.io.release();
        let established = task.await.expect("joins").expect("established");
        assert_eq!(resolver.calls(), [("www.example.test".to_owned(), 443)]);
        drop(established);
    }

    #[tokio::test]
    async fn a_failed_pending_write_prevents_the_dial_and_trips() {
        let (spec, _resolver, connector) = direct_spec();
        let rig = Rig::new(spec).await;
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        rig.io.with(|d| d.fail_append_at = Some(d.appends + 1));
        let fault = rig.open(adm).await.expect_err("refused");
        assert!(
            matches!(fault, DialFault::Audit(AuditError::Io(_))),
            "{fault:?}"
        );
        assert_eq!(fault.reply(), Some(Rep::GeneralFailure));
        assert!(rig.plane.calls().is_empty(), "nothing was dialled");
        assert!(connector.started.lock().expect("lock").is_empty());
        assert_eq!(
            *rig.trips.lock().expect("lock"),
            [TripReason::AuditWriteFailed]
        );
        assert!(!matches!(
            rig.shared.gate().borrow().mode,
            GateMode::Armed { .. }
        ));
    }

    #[tokio::test]
    async fn a_failed_result_write_closes_the_upstream_and_tells_the_client_nothing() {
        let (spec, _resolver, connector) = direct_spec();
        let rig = Rig::new(spec).await;
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        // The pending is the next append and the result the one after it.
        rig.io.with(|d| d.fail_append_at = Some(d.appends + 2));
        let fault = rig.open(adm).await.expect_err("refused");
        assert!(
            matches!(fault, DialFault::ResultLost(AuditError::Io(_))),
            "{fault:?}"
        );
        assert_eq!(fault.reply(), None, "no reply and no byte");
        assert_eq!(rig.plane.calls().len(), 1);
        // The upstream connection was dropped: its far end reads end-of-file.
        let mut far = connector.take_far();
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), far.read(&mut byte))
            .await
            .expect("closed promptly")
            .expect("read");
        assert_eq!(read, 0);
        assert_eq!(
            *rig.trips.lock().expect("lock"),
            [TripReason::AuditWriteFailed]
        );
    }

    #[tokio::test]
    async fn one_audit_timeout_fails_only_its_flow() {
        let (mut spec, _resolver, connector) = direct_spec();
        spec.tuning.audit_queue_wait = Duration::from_millis(80);
        spec.tuning.audit_sync_wait = Duration::from_millis(80);
        let rig = Rig::new(spec).await;
        let first = rig.admit_v4(PUBLIC, 443).expect("admitted");
        let flow_id = first.flow_id().to_owned();
        rig.io.block();
        // Claimed and stuck in its sync: this one times out.
        let fault = rig.open(first).await.expect_err("timed out");
        assert!(
            matches!(fault, DialFault::Audit(AuditError::Timeout)),
            "{fault:?}"
        );
        assert_eq!(fault.reply(), Some(Rep::GeneralFailure));
        assert!(rig.plane.calls().is_empty(), "no durable record, no dial");
        // Queued behind it and never claimed: this one is busy.
        let second = rig.admit_v4(PUBLIC, 443).expect("admitted");
        let fault = rig.open(second).await.expect_err("busy");
        assert!(
            matches!(fault, DialFault::Audit(AuditError::Busy)),
            "{fault:?}"
        );
        let counters = rig.shared.counters().dto();
        assert_eq!((counters.audit_timeouts, counters.audit_busy), (1, 1));
        // The disk comes back: the writer is not tripped, the next flow works, and
        // the record that landed late was closed by its own receipt.
        rig.io.release();
        assert!(rig.trips.lock().expect("lock").is_empty());
        let third = rig.admit_v4(PUBLIC, 443).expect("admitted");
        let established = rig.open(third).await.expect("established");
        rig.until("the late story to close", |rig| {
            rig.results().iter().any(|(outcome, code)| {
                *outcome == ResultOutcome::NotDialed && code.as_deref() == Some("AUDIT_ABANDONED")
            })
        })
        .await;
        let late: Vec<_> = rig
            .io
            .records()
            .into_iter()
            .filter(|r| r.flow_id == flow_id)
            .map(|r| r.event.kind())
            .collect();
        assert_eq!(late, ["pending", "result"]);
        assert_eq!(connector.started.lock().expect("lock").len(), 1);
        drop(established);
    }

    #[tokio::test]
    async fn a_failed_dial_is_recorded_once_mapped_and_never_retried() {
        let cases: Vec<(&str, Maker, &str, Rep)> = vec![
            (
                "refused",
                Arc::new(|| NetcoreError::ConnectionRefused("h:1".into(), "x".into())),
                "NETCORE_CONNECTION_REFUSED",
                Rep::ConnectionRefused,
            ),
            (
                "timeout",
                Arc::new(|| NetcoreError::Timeout("h:1".into(), Duration::ZERO)),
                "NETCORE_TIMEOUT",
                Rep::HostUnreachable,
            ),
            (
                "busy",
                Arc::new(|| NetcoreError::ResolverBusy),
                "NETCORE_RESOLVER_BUSY",
                Rep::GeneralFailure,
            ),
            (
                "rejected",
                Arc::new(|| NetcoreError::ProxyRejected("h:1".into(), "x".into())),
                "NETCORE_PROXY_REJECTED",
                Rep::GeneralFailure,
            ),
        ];
        for (name, maker, code, rep) in cases {
            let maker2 = Arc::clone(&maker);
            let rig = Rig::new(Spec::new().fails_with(move || maker2())).await;
            let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
            let fault = rig.open(adm).await.expect_err("failed");
            assert_eq!(fault.reply(), Some(rep), "{name}");
            assert_eq!(rig.plane.calls().len(), 1, "{name}: one dial and no retry");
            let FlowAuditEvent::Result {
                outcome,
                error_code,
                dialed,
                ..
            } = result_of(&rig, 0)
            else {
                panic!("a result");
            };
            assert_eq!(outcome, ResultOutcome::Failed, "{name}");
            assert_eq!(error_code.as_deref(), Some(code), "{name}");
            assert_eq!(dialed, None);
            assert_eq!(rig.results().len(), 1, "{name}: exactly one result");
            assert_eq!(rig.count("pending"), 1, "{name}");
            let counters = rig.shared.counters().dto();
            assert_eq!(counters.connect_failed, 1, "{name}");
            assert_eq!(counters.resolver_busy, u64::from(name == "busy"), "{name}");
            assert!(
                rig.trips.lock().expect("lock").is_empty(),
                "{name}: a failed dial does not trip"
            );
            assert_eq!(verified(&rig).unresolved, Unresolved::default(), "{name}");
        }
    }

    #[tokio::test]
    async fn a_lost_failure_record_still_gives_the_client_its_reply_and_a_closed_story() {
        let rig = Rig::new(Spec::new().fails_with(|| NetcoreError::FamilyDisabled)).await;
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        // The pending is durable; the failed result's append fails.
        rig.io.with(|d| d.fail_append_at = Some(d.appends + 2));
        let fault = rig.open(adm).await.expect_err("failed");
        assert!(
            matches!(fault, DialFault::Dial(NetcoreError::FamilyDisabled)),
            "{fault:?}"
        );
        assert_eq!(fault.reply(), Some(Rep::HostUnreachable));
        assert_eq!(
            *rig.trips.lock().expect("lock"),
            [TripReason::AuditWriteFailed]
        );
    }

    #[tokio::test]
    async fn dead_adapter_plus_lower_priority_direct_never_reaches_the_target() {
        let mut spec = Spec::new();
        spec.rules = vec![
            rule(
                "via-exit",
                10,
                Some(PUBLIC),
                None,
                Some(443),
                adapter_action("exit"),
            ),
            rule(
                "direct-too",
                20,
                Some(PUBLIC),
                None,
                Some(443),
                RoutingAction::Direct,
            ),
        ];
        // The proxy is somewhere else: connecting to the configured one is refused.
        let proxy = FakeProxy::new("203.0.113.9:1");
        let resolver = Arc::new(FakeResolver::new());
        let rig = Rig::new(spec.over(resolver.clone(), proxy.clone())).await;
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        assert_eq!(adm.rule(), Some("via-exit"));
        let fault = rig.open(adm).await.expect_err("failed");
        assert!(
            matches!(&fault, DialFault::Dial(e) if e.code() == "NETCORE_CONNECTION_REFUSED"),
            "{fault:?}"
        );
        assert_eq!(fault.reply(), Some(Rep::ConnectionRefused));
        assert_eq!(
            proxy.started(),
            [sa("198.51.100.7:1080")],
            "only the configured proxy was tried, never the destination"
        );
        assert_eq!(rig.plane.calls().len(), 1);
        assert_eq!((rig.count("pending"), rig.results().len()), (1, 1));
        assert!(resolver.calls().is_empty());
    }

    #[tokio::test]
    async fn a_proxied_name_is_forwarded_unresolved_and_the_chain_is_the_adapter() {
        let mut spec = Spec::new();
        spec.rules.insert(
            0,
            rule(
                "via-exit",
                5,
                None,
                Some("proxied.test"),
                None,
                adapter_action("exit"),
            ),
        );
        let proxy = FakeProxy::new("198.51.100.7:1080");
        let resolver = Arc::new(FakeResolver::new());
        let rig = Rig::new(spec.over(resolver.clone(), proxy.clone())).await;
        let adm = rig.admit_name("api.proxied.test", 443).expect("admitted");
        let established = rig.open(adm).await.expect("established");
        assert_eq!(established.chain_kinds, ["socks5"]);
        assert_eq!(proxy.requests(), [(3, "api.proxied.test".to_owned(), 443)]);
        assert!(
            resolver.calls().is_empty(),
            "the proxy resolves it, not this daemon"
        );
        assert_eq!(proxy.started(), [sa("198.51.100.7:1080")]);
        let FlowAuditEvent::Result {
            chain_kinds,
            dialed,
            answers,
            observations,
            ..
        } = result_of(&rig, 0)
        else {
            panic!("a result");
        };
        assert_eq!(chain_kinds, ["socks5".to_owned()]);
        assert_eq!(
            dialed, None,
            "this daemon dialled the proxy, not the destination"
        );
        assert_eq!(answers, None);
        assert_eq!(
            observations,
            [Observation::new("egress_local", "192.0.2.99").expect("valid")],
            "the first hop's source address"
        );
        drop(established);
    }

    #[tokio::test]
    async fn direct_by_name_resolves_once_dials_the_pinned_address_and_records_what_it_did() {
        let resolver = Arc::new(FakeResolver::new().answering("www.example.test", &[PUBLIC]));
        let connector = Arc::new(RecordingConnector::new());
        let rig = Rig::new(Spec::new().over(resolver.clone(), connector.clone())).await;
        let adm = rig.admit_name("www.example.test", 443).expect("admitted");
        let established = rig.open(adm).await.expect("established");
        assert_eq!(resolver.calls(), [("www.example.test".to_owned(), 443)]);
        assert_eq!(connector.started(), [sa("93.184.216.34:443")]);
        let FlowAuditEvent::Pending {
            resolution, dest, ..
        } = rig
            .events()
            .into_iter()
            .find(|e| e.kind() == "pending")
            .expect("pending")
        else {
            panic!("pending");
        };
        assert_eq!(resolution, Resolution::LocalPinned);
        assert_eq!(
            dest,
            crate::ingress::types::DestRef::Plain {
                host: "www.example.test".into(),
                port: 443
            }
        );
        let FlowAuditEvent::Result {
            dialed,
            attempted,
            answers,
            ..
        } = result_of(&rig, 0)
        else {
            panic!("a result");
        };
        let plain = crate::ingress::types::AddrRef::Plain {
            ip: PUBLIC.into(),
            port: 443,
        };
        assert_eq!(dialed, Some(plain.clone()));
        assert_eq!(attempted, [plain]);
        assert_eq!(answers, Some(1));
        drop(established);
    }

    #[tokio::test]
    async fn a_name_that_resolves_to_a_forbidden_address_fails_with_the_guard_label_and_no_socket()
    {
        let mut spec = Spec::new();
        spec.rules.insert(
            0,
            rule("deny-ip", 5, Some(OTHER), None, None, RoutingAction::Deny),
        );
        let resolver = Arc::new(
            FakeResolver::new()
                .answering("dev.example.test", &["127.0.0.1"])
                .answering("mixed.example.test", &[PUBLIC, "10.0.0.7"])
                .answering("denied.example.test", &[OTHER]),
        );
        let connector = Arc::new(RecordingConnector::new());
        let rig = Rig::new(spec.over(resolver.clone(), connector.clone())).await;
        for (name, label, answers) in [
            ("dev.example.test", "loopback", Some(1)),
            ("mixed.example.test", "private", Some(2)),
            ("denied.example.test", "deny_rule", Some(1)),
        ] {
            let adm = rig.admit_name(name, 443).expect("admitted by name");
            let fault = rig.open(adm).await.expect_err("refused");
            assert_eq!(fault.reply(), Some(Rep::NotAllowed), "{name}");
            let events = rig.events();
            let FlowAuditEvent::Result {
                outcome,
                error_code,
                refusal,
                answers: recorded,
                ..
            } = events
                .iter()
                .rev()
                .find(|e| e.kind() == "result")
                .expect("a result")
                .clone()
            else {
                panic!("a result");
            };
            assert_eq!(outcome, ResultOutcome::Failed, "{name}");
            assert_eq!(
                error_code.as_deref(),
                Some("NETCORE_ADDR_REFUSED"),
                "{name}"
            );
            assert_eq!(refusal.as_deref(), Some(label), "{name}");
            assert_eq!(recorded, answers, "{name}");
            assert!(RESULT_REFUSALS.contains(&label));
        }
        assert!(connector.started().is_empty(), "no socket for any of them");
        assert_eq!(resolver.calls().len(), 3, "one lookup each");
    }

    #[tokio::test]
    async fn a_refused_name_is_never_looked_up() {
        let resolver = Arc::new(FakeResolver::new().answering("www.example.org", &[PUBLIC]));
        let connector = Arc::new(RecordingConnector::new());
        let rig = Rig::new(Spec::new().over(resolver.clone(), connector.clone())).await;
        // No rule for the name, a name the OS must not see, and an address.
        for name in ["www.example.org", "intranet", "x.onion"] {
            assert!(rig.admit_name(name, 443).is_err(), "{name}");
        }
        assert!(resolver.calls().is_empty());
        assert!(connector.started().is_empty());
    }

    #[tokio::test]
    async fn the_hashed_mode_hashes_the_dialled_address_too_and_a_refusal_stays_plain() {
        let resolver = Arc::new(FakeResolver::new().answering("www.example.test", &[PUBLIC]));
        let connector = Arc::new(RecordingConnector::new());
        let mut spec = Spec::new().over(resolver, connector);
        spec.logging = DestinationLogging::Hashed;
        let rig = Rig::new(spec).await;
        let adm = rig.admit_name("www.example.test", 443).expect("admitted");
        let established = rig.open(adm).await.expect("established");
        drop(established);
        let denied = rig.admit_v4("8.8.8.8", 443).expect_err("denied");
        let target =
            canonicalize(RawTarget::V4("8.8.8.8".parse().expect("address"), 443)).expect("v4");
        rig.ctx
            .record_denial(&Rig::peer(), "main", &target, &denied)
            .await;
        let text = rig.io.text();
        assert!(!text.contains("www.example.test"), "{text}");
        assert!(
            !text.contains(PUBLIC),
            "the pinned address is destination data: {text}"
        );
        assert!(text.contains("\"mode\":\"hashed\""), "{text}");
        assert!(
            text.contains("8.8.8.8"),
            "a refusal is evidence and stays plain"
        );
        let FlowAuditEvent::Result { dialed, .. } = result_of(&rig, 0) else {
            panic!("a result");
        };
        assert!(
            matches!(dialed, Some(crate::ingress::types::AddrRef::Hashed { .. })),
            "{dialed:?}"
        );
    }

    // -- the gate -----------------------------------------------------------------------

    #[tokio::test]
    async fn a_gate_change_during_the_dial_cancels_it_and_no_socket_outlives_it() {
        let rig = Arc::new(Rig::new(Spec::new().hangs()).await);
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        let task = {
            let rig = Arc::clone(&rig);
            tokio::spawn(async move { rig.open(adm).await })
        };
        for _ in 0..500 {
            if rig.plane.hung.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(rig.plane.hung.load(Ordering::SeqCst), 1, "the dial started");
        assert_eq!(rig.plane.hung_dropped.load(Ordering::SeqCst), 0);
        rig.shared.disarm(DisarmCause::Operator).await;
        let fault = task.await.expect("joins").expect_err("cancelled");
        assert!(matches!(fault, DialFault::Cancelled), "{fault:?}");
        assert_eq!(fault.reply(), None);
        assert_eq!(
            rig.plane.hung_dropped.load(Ordering::SeqCst),
            1,
            "the dial future, and with it every socket it owned, is gone"
        );
        // The story is closed by the receipt: a dial was started, no outcome known.
        rig.until("the aborted result", |rig| {
            rig.results().contains(&(
                ResultOutcome::Aborted,
                Some("DIAL_NOT_COMPLETED".to_owned()),
            ))
        })
        .await;
        assert_eq!(verified(&rig).unresolved, Unresolved::default());
    }

    #[tokio::test]
    async fn a_gate_change_during_the_lookup_cancels_the_dial_and_no_connect_follows_it() {
        let resolver = GatedResolver::new(PUBLIC);
        let connector = Arc::new(RecordingConnector::new());
        let rig = Arc::new(Rig::new(Spec::new().over(resolver.clone(), connector.clone())).await);
        let adm = rig.admit_name("www.example.test", 443).expect("admitted");
        let task = {
            let rig = Arc::clone(&rig);
            tokio::spawn(async move { rig.open(adm).await })
        };
        for _ in 0..500 {
            if resolver.entered() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(resolver.entered(), "the lookup is running");
        // The profile that is armed changes while the lookup is in flight.
        rig.shared.disarm(DisarmCause::Operator).await;
        let fault = task.await.expect("joins").expect_err("cancelled");
        assert!(matches!(fault, DialFault::Cancelled), "{fault:?}");
        // The lookup now returns, into a dial that no longer exists.
        resolver.release();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            connector.started().is_empty(),
            "no connect survives the change"
        );
    }

    #[tokio::test]
    async fn connect_timeout_ends_the_dial_and_the_failure_is_recorded() {
        let mut spec = Spec::new().hangs();
        spec.connect_timeout_ms = 100;
        let rig = Rig::new(spec).await;
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        let fault = rig.open(adm).await.expect_err("timed out");
        assert!(matches!(fault, DialFault::Deadline), "{fault:?}");
        assert_eq!(fault.reply(), Some(Rep::HostUnreachable));
        assert_eq!(rig.plane.hung_dropped.load(Ordering::SeqCst), 1);
        assert_eq!(
            rig.results(),
            [(ResultOutcome::Failed, Some("CONNECT_DEADLINE".to_owned()))]
        );
        assert_eq!(rig.shared.counters().dto().connect_failed, 1);
        assert!(rig.trips.lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn a_gate_that_moved_before_the_record_was_written_dials_nothing_and_records_nothing() {
        let (spec, _resolver, connector) = direct_spec();
        let rig = Rig::new(spec).await;
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        rig.shared.disarm(DisarmCause::Operator).await;
        let fault = rig.open(adm).await.expect_err("cancelled");
        assert!(matches!(fault, DialFault::Cancelled), "{fault:?}");
        assert_eq!(rig.count("pending"), 0);
        assert!(rig.plane.calls().is_empty());
        assert!(connector.started.lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn a_gate_that_moved_while_the_pending_was_written_closes_the_story_as_not_dialed() {
        let (spec, _resolver, connector) = direct_spec();
        let rig = Arc::new(Rig::new(spec).await);
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        rig.io.block();
        let task = {
            let rig = Arc::clone(&rig);
            tokio::spawn(async move { rig.open(adm).await })
        };
        rig.wait_in_sync().await;
        rig.shared.disarm(DisarmCause::Operator).await;
        rig.io.release();
        let fault = task.await.expect("joins").expect_err("cancelled");
        assert!(matches!(fault, DialFault::Cancelled), "{fault:?}");
        rig.until("the not-dialled result", |rig| {
            rig.results()
                .contains(&(ResultOutcome::NotDialed, Some("GATE_CLOSED".to_owned())))
        })
        .await;
        assert!(rig.plane.calls().is_empty());
        assert!(connector.started.lock().expect("lock").is_empty());
        assert_eq!(verified(&rig).unresolved, Unresolved::default());
    }

    #[tokio::test]
    async fn a_gate_that_moved_while_the_dial_finished_discards_the_tunnel() {
        // The dial completes at once, but the gate has moved by the time the engine
        // looks: the connected tunnel is dropped, no result says "connected".
        let (spec, _resolver, connector) = direct_spec();
        let rig = Rig::new(spec).await;
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        let mut gate = rig.shared.gate();
        let epoch = adm.epoch();
        rig.shared.disarm(DisarmCause::Operator).await;
        // A receiver that never saw the change still compares epochs, so the
        // pre-check of `open_tunnel` catches it first; the check after the dial is
        // the same predicate, exercised here through `gate_unchanged`.
        assert!(!gate_unchanged(&gate, epoch));
        let fault = open_tunnel(&rig.ctx, adm, &Rig::peer(), "main", &mut gate)
            .await
            .expect_err("cancelled");
        assert!(matches!(fault, DialFault::Cancelled));
        assert!(connector.started.lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn a_flow_minted_for_another_writer_is_not_recorded_into_this_one() {
        let (spec, _resolver, connector) = direct_spec();
        let rig = Rig::new(spec).await;
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        // A recover installed a fresh writer, which continues the numbering.
        let io = FakeIo::new();
        let mut replayed = Replayed::fresh();
        replayed.last_seq = Some(40);
        let writer = FlowAuditWriter::open_with(
            io.clone(),
            replayed,
            &open_cfg(DestinationLogging::Plain),
            DestSealer::Plain,
            Arc::new(|_| {}),
        )
        .expect("opens");
        let boot: Arc<str> = Arc::from(format!("b{}", writer.boot_seq()));
        assert_ne!(
            flow_id_boot(adm.flow_id()),
            Some(&*boot),
            "the new boot has another prefix"
        );
        rig.shared.ledger_slot().install(Installed {
            writer: Arc::new(writer),
            boot,
        });
        let fault = rig.open(adm).await.expect_err("cancelled");
        assert!(matches!(fault, DialFault::Cancelled), "{fault:?}");
        assert!(!io.text().contains("\"event\":\"pending\""));
        assert_eq!(rig.count("pending"), 0);
        assert!(connector.started.lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn no_writer_means_no_flow() {
        let rig = Rig::new(Spec::new()).await;
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        let empty = Arc::new(crate::ingress::shared::LedgerSlot::new());
        let (events, _) = tokio::sync::broadcast::channel(4);
        let bare = IngressShared::with_ledger(
            IngressCfgView::for_tests(),
            Tuning::default(),
            events,
            Arc::clone(&empty),
            empty,
        );
        let ctx = EngineCtx::new(
            Arc::clone(&rig.ctx.routing),
            Arc::clone(&rig.ctx.data_plane),
            bare,
            sa(LISTENER),
            Arc::new(SystemClock),
        );
        let mut gate = rig.shared.gate();
        let fault = open_tunnel(&ctx, adm, &Rig::peer(), "main", &mut gate)
            .await
            .expect_err("refused");
        assert!(
            matches!(fault, DialFault::Audit(AuditError::Closing)),
            "{fault:?}"
        );
        assert!(rig.plane.calls().is_empty());
    }

    #[tokio::test]
    async fn the_dial_refuses_a_token_that_the_record_does_not_name() {
        let (spec, _resolver, connector) = direct_spec();
        let mut spec = spec;
        spec.rules.push(rule(
            "second",
            40,
            Some("9.9.9.9"),
            None,
            Some(443),
            RoutingAction::Direct,
        ));
        let rig = Rig::new(spec).await;
        let authorised = rig.admit_v4(PUBLIC, 443).expect("admitted");
        let other = rig.admit_v4("9.9.9.9", 443).expect("admitted");
        let installed = rig.shared.ledger_slot().current().expect("a writer");
        let peer = Rig::peer();
        let pending = installed
            .writer
            .append_pending(authorised.pending_input(&peer, "main"), rig.ctx.waits())
            .await
            .expect("durable");
        let mut gate = rig.shared.gate();
        let epoch = other.epoch();
        // The record names 93.184.216.34; the token says 9.9.9.9.
        let fault = dial(
            &rig.ctx,
            &installed.writer,
            &pending,
            other.token,
            &mut gate,
            epoch,
        )
        .await
        .expect_err("refused");
        assert!(matches!(fault, DialFault::ReceiptMismatch), "{fault:?}");
        assert!(rig.plane.calls().is_empty(), "nothing was dialled");
        assert!(connector.started.lock().expect("lock").is_empty());
        assert!(rig.results().contains(&(
            ResultOutcome::NotDialed,
            Some("RECEIPT_MISMATCH".to_owned())
        )));
    }

    #[tokio::test]
    async fn a_gate_that_moves_as_the_dial_completes_discards_the_tunnel_and_says_nothing() {
        let (spec, _resolver, connector) = direct_spec();
        let rig = Rig::new(spec).await;
        *lock_unpoisoned(&rig.plane.mover) = Some(Arc::clone(&rig.shared));
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        let fault = rig.open(adm).await.expect_err("cancelled");
        assert!(matches!(fault, DialFault::Cancelled), "{fault:?}");
        assert_eq!(fault.reply(), None);
        // The dial happened; no result says it connected, and the upstream is shut.
        assert_eq!(rig.plane.calls().len(), 1);
        let mut far = connector.take_far();
        let mut byte = [0u8; 1];
        assert_eq!(far.read(&mut byte).await.expect("read"), 0);
        rig.until("the aborted result", |rig| {
            rig.results().contains(&(
                ResultOutcome::Aborted,
                Some("DIAL_NOT_COMPLETED".to_owned()),
            ))
        })
        .await;
        assert!(!rig
            .results()
            .iter()
            .any(|(outcome, _)| *outcome == ResultOutcome::Connected));
    }

    #[tokio::test]
    async fn a_failed_race_records_every_address_that_was_tried() {
        let resolver =
            Arc::new(FakeResolver::new().answering("www.example.test", &[PUBLIC, "8.8.8.8"]));
        let connector = Arc::new(
            RecordingConnector::new()
                .script(
                    "93.184.216.34:443",
                    Outcome::Fail(io::ErrorKind::ConnectionRefused),
                )
                .script(
                    "8.8.8.8:443",
                    Outcome::Fail(io::ErrorKind::ConnectionRefused),
                ),
        );
        let rig = Rig::new(Spec::new().over(resolver, connector.clone())).await;
        let adm = rig.admit_name("www.example.test", 443).expect("admitted");
        let fault = rig.open(adm).await.expect_err("failed");
        assert_eq!(fault.reply(), Some(Rep::ConnectionRefused));
        let FlowAuditEvent::Result {
            outcome,
            error_code,
            refusal,
            attempted,
            answers,
            ..
        } = result_of(&rig, 0)
        else {
            panic!("a result");
        };
        assert_eq!(outcome, ResultOutcome::Failed);
        assert_eq!(error_code.as_deref(), Some("NETCORE_CONNECTION_REFUSED"));
        assert_eq!(refusal, None, "a refused connect is not an address refusal");
        let plain = |ip: &str| crate::ingress::types::AddrRef::Plain {
            ip: ip.into(),
            port: 443,
        };
        let mut tried = attempted.clone();
        tried.sort_by_key(|a| format!("{a:?}"));
        assert_eq!(tried.len(), 2, "{attempted:?}");
        assert!(attempted.contains(&plain(PUBLIC)) && attempted.contains(&plain("8.8.8.8")));
        assert_eq!(answers, Some(2));
        assert_eq!(connector.started().len(), 2);
    }

    #[tokio::test]
    async fn an_audit_error_is_counted_by_what_it_cost_the_flow() {
        let rig = Rig::new(Spec::new()).await;
        let note = |error| rig.ctx.note_audit(error);
        for error in [
            AuditError::Busy,
            AuditError::QueueFull,
            AuditError::Capacity,
        ] {
            note(error);
        }
        note(AuditError::Timeout);
        // These cost the flow, but are not counted here: a fault has tripped the
        // gate already, and a closing or invalid writer is not load.
        for error in [
            AuditError::OverQuota,
            AuditError::Closing,
            AuditError::RecordTooLarge,
            AuditError::Invalid("x"),
            AuditError::WriterDown,
            AuditError::SeqExhausted,
            AuditError::Io("X"),
        ] {
            note(error);
        }
        let counters = rig.shared.counters().dto();
        assert_eq!((counters.audit_busy, counters.audit_timeouts), (3, 1));
    }

    #[tokio::test]
    async fn the_audit_waits_are_the_tunings_in_the_right_order() {
        let mut spec = Spec::new();
        spec.tuning.audit_queue_wait = Duration::from_millis(111);
        spec.tuning.audit_sync_wait = Duration::from_millis(222);
        let rig = Rig::new(spec).await;
        assert_eq!(
            rig.ctx.waits(),
            Waits {
                queue_wait: Duration::from_millis(111),
                sync_wait: Duration::from_millis(222),
            }
        );
        assert_eq!(rig.ctx.connect_timeout(), Duration::from_millis(2_000));
        assert_eq!(rig.ctx.families(), DirectAddressFamilies::Ipv4Only);
    }

    #[tokio::test]
    async fn a_refusal_that_knows_its_route_records_it() {
        let rig = Rig::new(Spec::new()).await;
        let target =
            canonicalize(RawTarget::V4(PUBLIC.parse().expect("address"), 443)).expect("v4");
        let mut denied =
            Denied::new(REASON_ROUTE_NOT_DIALABLE, DenyClass::Route).with_rule(Some("r1".into()));
        denied.route = Some("SingleHop(wrap)".into());
        rig.ctx
            .record_denial(&Rig::peer(), "main", &target, &denied)
            .await;
        let FlowAuditEvent::Denied {
            route,
            matched_rule,
            reason_code,
            ..
        } = denied_events(&rig).remove(0)
        else {
            panic!("a denied record");
        };
        assert_eq!(route.as_deref(), Some("SingleHop(wrap)"));
        assert_eq!(matched_rule.as_deref(), Some("r1"));
        assert_eq!(reason_code, REASON_ROUTE_NOT_DIALABLE);
    }

    #[tokio::test]
    async fn a_failed_dial_of_a_literal_records_the_address_the_engine_tried() {
        // The executor reports no attempts for a literal; the engine fills them in.
        let connector = Arc::new(RecordingConnector::new().script(
            "93.184.216.34:443",
            Outcome::Fail(io::ErrorKind::ConnectionRefused),
        ));
        let rig =
            Rig::new(Spec::new().over(Arc::new(FakeResolver::new()), connector.clone())).await;
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        rig.open(adm).await.expect_err("failed");
        let FlowAuditEvent::Result {
            outcome,
            attempted,
            answers,
            ..
        } = result_of(&rig, 0)
        else {
            panic!("a result");
        };
        assert_eq!(outcome, ResultOutcome::Failed);
        assert_eq!(
            attempted,
            [crate::ingress::types::AddrRef::Plain {
                ip: PUBLIC.into(),
                port: 443
            }]
        );
        assert_eq!(answers, None);
        assert_eq!(connector.started(), [sa("93.184.216.34:443")]);
    }

    #[tokio::test]
    async fn a_literal_dial_that_ended_before_any_connect_lists_nothing_and_a_proxied_one_lists_the_proxy_only(
    ) {
        let literal = Some(sa("93.184.216.34:443"));
        // Errors of a dial that never reached a socket.
        for error in [
            NetcoreError::FamilyDisabled,
            NetcoreError::ResolverBusy,
            NetcoreError::InvalidTarget("x".into()),
            NetcoreError::AddressRefused {
                code: "loopback",
                refused: 1,
                answers: 0,
            },
        ] {
            assert!(
                failed_event(&error, literal).attempted.is_empty(),
                "{}",
                error.code()
            );
        }
        // Errors a connect produces.
        for error in [
            NetcoreError::ConnectionRefused("h".into(), "x".into()),
            NetcoreError::Timeout("h".into(), Duration::ZERO),
            NetcoreError::Io("h".into(), io::Error::from(io::ErrorKind::BrokenPipe)),
        ] {
            assert_eq!(
                failed_event(&error, literal).attempted,
                vec![sa("93.184.216.34:443")]
            );
            assert!(
                failed_event(&error, None).attempted.is_empty(),
                "no literal, no claim"
            );
        }
        // The route decides: only `Direct` to a literal has an address of its own.
        let mut spec = Spec::new();
        spec.rules.insert(
            0,
            rule(
                "ip-via-exit",
                5,
                Some(OTHER),
                None,
                None,
                adapter_action("exit"),
            ),
        );
        let rig = Rig::new(spec).await;
        let proxied = rig.admit_v4(OTHER, 80).expect("admitted");
        assert_eq!(literal_direct(&proxied.token), None);
        let direct = rig.admit_v4(PUBLIC, 443).expect("admitted");
        assert_eq!(literal_direct(&direct.token), literal);
        let named = rig.admit_name("www.example.test", 443).expect("admitted");
        assert_eq!(
            literal_direct(&named.token),
            None,
            "a name has no address of its own"
        );
        let v6 = {
            let mut spec = Spec::new();
            spec.families = DirectAddressFamilies::Any;
            spec.rules = vec![rule("all", 10, None, None, None, RoutingAction::Direct)];
            let rig = Rig::new(spec).await;
            let adm = rig
                .admit(RawTarget::V6(
                    "2606:4700:4700::1111".parse().expect("address"),
                    443,
                ))
                .expect("admitted");
            literal_direct(&adm.token)
        };
        assert_eq!(v6, Some(sa("[2606:4700:4700::1111]:443")));
    }

    #[tokio::test]
    async fn a_dial_that_ran_out_of_time_lists_the_literal_it_was_dialling() {
        let mut spec = Spec::new().hangs();
        spec.connect_timeout_ms = 100;
        let rig = Rig::new(spec).await;
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        rig.open(adm).await.expect_err("timed out");
        let FlowAuditEvent::Result { attempted, .. } = result_of(&rig, 0) else {
            panic!("a result");
        };
        assert_eq!(attempted.len(), 1);
    }

    #[tokio::test]
    async fn a_peer_that_was_not_verified_is_recorded_as_unverified_in_refusals_and_pending_records(
    ) {
        let (spec, _resolver, _connector) = direct_spec();
        let rig = Rig::new(spec).await;
        let peer = PeerStamp {
            peer: Arc::from("127.0.0.1:50001"),
            verified: false,
        };
        let target = canonicalize(RawTarget::V4(OTHER.parse().expect("address"), 443)).expect("v4");
        let denied = rig.admit_v4(OTHER, 443).expect_err("denied");
        rig.ctx.record_denial(&peer, "main", &target, &denied).await;
        let FlowAuditEvent::Denied {
            peer: who,
            peer_verified,
            ..
        } = denied_events(&rig).remove(0)
        else {
            panic!("a denied record");
        };
        assert_eq!((who.as_str(), peer_verified), ("127.0.0.1:50001", false));

        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        let mut gate = rig.shared.gate();
        let est = open_tunnel(&rig.ctx, adm, &peer, "main", &mut gate)
            .await
            .expect("established");
        let FlowAuditEvent::Pending {
            peer: who,
            peer_verified,
            ..
        } = rig
            .events()
            .into_iter()
            .find(|e| e.kind() == "pending")
            .expect("pending")
        else {
            panic!("pending");
        };
        assert_eq!((who.as_str(), peer_verified), ("127.0.0.1:50001", false));
        drop(est);
    }

    #[tokio::test]
    async fn a_refusal_the_ledger_cannot_take_in_time_is_counted_and_still_answered() {
        let mut spec = Spec::new();
        spec.tuning.audit_queue_wait = Duration::from_millis(80);
        spec.tuning.audit_sync_wait = Duration::from_millis(80);
        let rig = Rig::new(spec).await;
        let target = canonicalize(RawTarget::V4(OTHER.parse().expect("address"), 443)).expect("v4");
        let denied = rig.admit_v4(OTHER, 443).expect_err("denied");
        rig.io.block();
        // The call returns (the reply does not depend on the record) and says what
        // it cost.
        rig.ctx
            .record_denial(&Rig::peer(), "main", &target, &denied)
            .await;
        rig.io.release();
        let counters = rig.shared.counters().dto();
        assert_eq!((counters.denied, counters.audit_timeouts), (1, 1));
        assert!(
            rig.trips.lock().expect("lock").is_empty(),
            "a timeout does not trip"
        );
    }

    #[test]
    fn the_planned_adapters_are_the_hops_of_the_route_in_order() {
        // A multi-hop route cannot be configured today, so `decide` never makes
        // one; the list is still the record's statement of the plan.
        assert_eq!(
            adapter_ids(&RouteKind::MultiHop(vec![hop("a"), hop("b"), hop("c")])),
            ["a", "b", "c"]
        );
        assert_eq!(adapter_ids(&RouteKind::SingleHop(hop("a"))), ["a"]);
        for route in [
            RouteKind::Direct,
            RouteKind::OpenVpn {
                adapter_id: "x".into(),
                profile_id: "y".into(),
            },
            RouteKind::Denied { reason: "z".into() },
        ] {
            assert!(adapter_ids(&route).is_empty());
        }
    }

    #[tokio::test]
    async fn attestation_is_judged_before_the_address_and_the_route() {
        // The policy's verdict comes first: a rule that needs attestation is said
        // to need it even where the address or the route would also be refused.
        let mut spec = Spec::new();
        spec.adapters.push(adapter(
            "wrap",
            AdapterTransport::TlsTunnel {
                host: PROXY.into(),
                port: 443,
            },
        ));
        let mut lan = rule(
            "attested-lan",
            5,
            Some("192.168.1.50"),
            None,
            Some(9100),
            RoutingAction::Direct,
        );
        lan.require_attestation = true;
        let mut wrapped = rule(
            "attested-wrap",
            6,
            Some(PUBLIC),
            None,
            Some(8001),
            adapter_action("wrap"),
        );
        wrapped.require_attestation = true;
        spec.rules.insert(0, lan);
        spec.rules.insert(1, wrapped);
        let rig = Rig::new(spec).await;
        for (ip, port, rule_id) in [
            ("192.168.1.50", 9100, "attested-lan"),
            (PUBLIC, 8001, "attested-wrap"),
        ] {
            let denied = rig.admit_v4(ip, port).expect_err("denied");
            assert_eq!(denied.reason, REASON_ATTESTATION_REQUIRED, "{ip}");
            assert_eq!(denied.rule.as_deref(), Some(rule_id));
        }
    }

    /// Holds the disk when the dial starts, so that the record that follows it is
    /// the one that times out.
    fn hold_disk_at_dial(rig: &Rig) {
        let io = rig.io.clone();
        *lock_unpoisoned(&rig.plane.on_dial) = Some(Arc::new(move || io.block()));
    }

    fn quick_audit_spec(spec: Spec) -> Spec {
        let mut spec = spec;
        spec.tuning.audit_queue_wait = Duration::from_millis(60);
        spec.tuning.audit_sync_wait = Duration::from_millis(60);
        spec
    }

    #[tokio::test]
    async fn a_failure_record_that_times_out_is_counted_and_the_client_still_gets_its_reply() {
        let rig =
            Rig::new(quick_audit_spec(Spec::new().fails_with(|| {
                NetcoreError::ConnectionRefused("h".into(), "x".into())
            })))
            .await;
        hold_disk_at_dial(&rig);
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        let fault = rig.open(adm).await.expect_err("failed");
        assert_eq!(fault.reply(), Some(Rep::ConnectionRefused));
        rig.io.release();
        let counters = rig.shared.counters().dto();
        assert_eq!((counters.connect_failed, counters.audit_timeouts), (1, 1));
        assert!(rig.trips.lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn a_deadline_record_that_times_out_is_counted_too() {
        let mut spec = quick_audit_spec(Spec::new().hangs());
        spec.connect_timeout_ms = 100;
        let rig = Rig::new(spec).await;
        hold_disk_at_dial(&rig);
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        let fault = rig.open(adm).await.expect_err("timed out");
        assert!(matches!(fault, DialFault::Deadline), "{fault:?}");
        rig.io.release();
        let counters = rig.shared.counters().dto();
        assert_eq!((counters.connect_failed, counters.audit_timeouts), (1, 1));
    }

    #[tokio::test]
    async fn a_result_record_that_times_out_drops_the_tunnel_and_is_counted() {
        let (spec, _resolver, connector) = direct_spec();
        let rig = Rig::new(quick_audit_spec(spec)).await;
        hold_disk_at_dial(&rig);
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        let fault = rig.open(adm).await.expect_err("lost");
        assert!(
            matches!(fault, DialFault::ResultLost(AuditError::Timeout)),
            "{fault:?}"
        );
        assert_eq!(fault.reply(), None);
        assert_eq!(rig.shared.counters().dto().audit_timeouts, 1);
        // The upstream is closed whether or not the record lands later.
        let mut far = connector.take_far();
        let mut byte = [0u8; 1];
        assert_eq!(far.read(&mut byte).await.expect("read"), 0);
        // The disk returns: the late record closes its own story and nothing trips.
        rig.io.release();
        rig.until("the late story to close", |rig| rig.count("closed") == 1)
            .await;
        assert!(rig.trips.lock().expect("lock").is_empty());
        assert_eq!(verified(&rig).unresolved, Unresolved::default());
    }

    #[test]
    fn zero_answers_means_nothing_was_looked_up_and_is_not_recorded() {
        let wrap = |source: NetcoreError, answers: u8| NetcoreError::DialFailed {
            source: Box::new(source),
            attempts: ssk_netcore::DialAttempts {
                answers,
                attempted: Vec::new(),
            },
        };
        let refused = |answers| NetcoreError::AddressRefused {
            code: "private",
            refused: 1,
            answers,
        };
        assert_eq!(failed_event(&refused(0), None).answers, None);
        assert_eq!(failed_event(&refused(3), None).answers, Some(3));
        let refused_connect = || NetcoreError::ConnectionRefused("h".into(), "x".into());
        assert_eq!(
            failed_event(&wrap(refused_connect(), 0), None).answers,
            None
        );
        assert_eq!(
            failed_event(&wrap(refused_connect(), 2), None).answers,
            Some(2)
        );
        assert_eq!(failed_event(&refused_connect(), None).answers, None);
    }

    #[test]
    fn a_fault_names_the_outcome_and_the_code_of_its_registry_row() {
        let table: Vec<(DialFault, &str, &str)> = vec![
            (DialFault::Audit(AuditError::Busy), "refused", "AUDIT_BUSY"),
            (DialFault::ReceiptMismatch, "refused", "RECEIPT_MISMATCH"),
            (
                DialFault::Dial(NetcoreError::FamilyDisabled),
                "connect_failed",
                "NETCORE_FAMILY_DISABLED",
            ),
            (DialFault::Deadline, "connect_failed", "CONNECT_DEADLINE"),
            (
                DialFault::ResultLost(AuditError::Timeout),
                "connect_failed",
                "AUDIT_TIMEOUT",
            ),
            (DialFault::Cancelled, "cancelled", "GATE_CLOSED"),
        ];
        for (fault, outcome, code) in table {
            assert_eq!(
                (fault.outcome(), fault.reason_code()),
                (outcome, code),
                "{fault:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_admission_carries_what_inspect_flow_shows_and_the_tunnel_what_the_row_needs() {
        let (spec, _resolver, _connector) = direct_spec();
        let rig = Rig::new(spec).await;
        let adm = rig.admit_v4(PUBLIC, 443).expect("admitted");
        let inspection = adm.inspection().clone();
        assert_eq!(inspection.descriptor.app_id, ENGINE_APP_ID);
        assert_eq!(inspection.descriptor.destination_host, PUBLIC);
        assert_eq!(inspection.descriptor.destination_port, 443);
        assert_eq!(inspection.matched_rule.as_deref(), Some("allow-web"));
        assert_eq!(inspection.action, ssk_netadmin::PolicyAction::Allow);
        assert_eq!(inspection.route, RouteKind::Direct);
        assert!(!inspection.requires_attestation);
        let established = rig.open(adm).await.expect("established");
        // The pending record is the one before the result.
        let records = rig.io.records();
        let pending = records
            .iter()
            .find(|r| r.event.kind() == "pending")
            .expect("pending")
            .seq;
        assert_eq!(established.pending_seq, pending);
        assert_eq!(
            established.result.seq(),
            pending.checked_add(1).expect("fits")
        );
        assert_eq!(established.egress_local.as_deref(), Some("192.0.2.99"));
    }

    #[tokio::test]
    async fn only_the_first_refusal_of_a_key_says_so() {
        let rig = Rig::new(Spec::new()).await;
        let target = canonicalize(RawTarget::V4(OTHER.parse().expect("address"), 443)).expect("v4");
        let denied = rig.admit_v4(OTHER, 443).expect_err("denied");
        let peer = Rig::peer();
        let first = rig.ctx.record_denial(&peer, "main", &target, &denied).await;
        let again = rig.ctx.record_denial(&peer, "main", &target, &denied).await;
        assert_eq!(first, Disposition::FirstDurable);
        assert_eq!(again, Disposition::Repeat);
    }
}
