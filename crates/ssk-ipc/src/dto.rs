#![forbid(unsafe_code)]

//! DTOs for the GUI backend API (`docs/DESKTOP_CLIENT_ARCHITECTURE.md` section J),
//! commands 1-4 and 15-22 (Phase 2 scope). Reuses `ssk-netadmin`'s public
//! types directly wherever possible instead of re-declaring them.

use serde::{Deserialize, Serialize};

use crate::error::IpcError;
use crate::state::DaemonState;

/// The IPC protocol this build speaks, announced in [`StatusDto::protocol`].
///
/// `0` is every build up to and including `b62c4c8`, which has no such field (an
/// absent one decodes as 0). Protocol 1 is the wire of the local proxy: the
/// `ingress` block of the status, `Request::SetIngress`,
/// `Request::GetIngressAudit` and the additive fields below. Raise it for a
/// change an older peer cannot ignore, with an entry in
/// `docs/COMPATIBILITY_MATRIX.md`; until the first release tag, protocol 1 is
/// "M2" and further additions to it are still additive.
pub const IPC_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterHealthSummaryDto {
    pub id: String,
    pub health: String,
}

/// Response to `get_status` (command 1).
///
/// `Default` is a daemon that is idle, speaks protocol 0 and reports nothing
/// else. It exists so that a test literal and a decoder fill in what is absent
/// with the old daemon and not with a claim; the daemon's own two literals
/// (`Inner::status`, `activating_status`) stay complete on purpose, so a field
/// added here makes them say what it is.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatusDto {
    pub state: DaemonState,
    pub active_profile: Option<String>,
    pub adapters: Vec<AdapterHealthSummaryDto>,
    pub dns_protected: bool,
    pub kill_switch: bool,
    pub audit_head: Option<String>,
    pub version: String,
    pub last_error: Option<IpcError>,
    /// The IPC protocol the daemon speaks ([`IPC_PROTOCOL_VERSION`]). Absent
    /// from a daemon that predates it, which is protocol 0. A client that needs
    /// more than protocol 0 reads this first ([`StatusDto::require_protocol`]);
    /// nothing else tells an old daemon from a new one, because `version` is the
    /// workspace version and does not change with every build.
    #[serde(default)]
    pub protocol: u32,
    /// The local proxy's block. `Some` is also the capability marker: `None` means
    /// only "this daemon predates the proxy" and a daemon of protocol 1 never
    /// answers it (a proxy that is off is `Some` with state `disabled`). It is
    /// the proxy's own record: it is never merged into `last_error` or
    /// `state`.
    #[serde(default)]
    pub ingress: Option<IngressStatusDto>,
}

impl StatusDto {
    /// `Ok(())` when the daemon speaks at least protocol `needed`. A client that
    /// needs a feature of protocol 1 calls this on a `GetStatus` answer before it
    /// sends the request: an older daemon drops the connection on a request it
    /// cannot decode, which a client would otherwise report as a network failure,
    /// and silently ignores a field it does not know, which would read as an
    /// answer.
    pub fn require_protocol(&self, needed: u32) -> Result<(), IpcError> {
        if self.protocol >= needed {
            return Ok(());
        }
        Err(IpcError::new(
            "Runtime",
            "DAEMON_TOO_OLD",
            format!(
                "the running sskd speaks IPC protocol {} but this client needs {needed}",
                self.protocol
            ),
        )
        .with_next_step(
            "Restart sskd: a running daemon keeps executing the binary it was started from.",
        ))
    }
}

/// Request for `activate_profile` (command 2).
///
/// `dest_host`/`dest_port` name the real destination the daemon should
/// establish protected egress to. This is required for the daemon to enter
/// `Active`/`Protected` for real: with no destination there is nothing to
/// protect, so activation without one fails closed rather than reporting a
/// fabricated `Protected` status (see `Supervisor::handle`'s
/// `ActivateProfile` arm).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivateProfileRequest {
    pub profile_id: String,
    #[serde(default)]
    pub dest_host: Option<String>,
    #[serde(default)]
    pub dest_port: Option<u16>,
}

/// Request for `deactivate` (command 3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeactivateRequest {
    pub release_kill_switch: bool,
}

/// One entry of `list_profiles` (command 4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSummaryDto {
    pub id: String,
    pub name: String,
}

/// Response to `inspect_flow` (command 15). Reuses `ssk-netadmin`'s real
/// descriptor/action/route types rather than re-declaring them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowInspectionDto {
    pub descriptor: ssk_netadmin::FlowDescriptor,
    pub matched_rule: Option<String>,
    pub action: ssk_netadmin::PolicyAction,
    pub route: ssk_netadmin::RouteKind,
    pub requires_attestation: bool,
}

/// Request for `trace_route` (command 16).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteTraceRequest {
    pub app_id: Option<String>,
    pub dest_host: String,
    pub dest_port: u16,
    pub protocol: String,
    pub risk: String,
    /// The profile to evaluate. A daemon older than protocol 1 ignores it and
    /// answers for its own choice, which is a wrong answer and not an error, so
    /// a client sets it only after `require_protocol(1)` and treats an answer
    /// whose `profile_used` is absent or another profile as "not honoured".
    #[serde(default)]
    pub profile_id: Option<String>,
}

/// Response to `trace_route` (command 16).
///
/// The fields after `requires_attestation` say which inputs the preview used
/// (protocol 1). A daemon that predates them sends none, and each reads as
/// absent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteTraceDto {
    pub route: ssk_netadmin::RouteKind,
    pub hops: Vec<String>,
    pub requires_attestation: bool,
    /// The profile the preview was computed under.
    #[serde(default)]
    pub profile_used: Option<String>,
    /// How that profile was chosen: `request`, `armed_ingress`, `active_session`
    /// or `default_profile`.
    #[serde(default)]
    pub profile_source: Option<String>,
    /// Which evaluation produced the answer: `legacy_activation` or `ingress`.
    #[serde(default)]
    pub evaluated_as: Option<String>,
    /// The application id the flow was evaluated with.
    #[serde(default)]
    pub app_id_used: Option<String>,
    /// The `Denied` reason code of a guard or policy refusal, when `route` is
    /// `Denied`.
    #[serde(default)]
    pub refusal: Option<String>,
    /// Guards the preview could not run, by name (`self_loop` while no listener
    /// is bound).
    #[serde(default)]
    pub guards_skipped: Vec<String>,
}

/// One entry of `list_recent_flows` (command 17). Empty until `ssk-capture`
/// (Phase 4) provides real traffic ingress — no flows are fabricated.
///
/// The fields after `outcome` are protocol 1's and all optional on the wire (an
/// absent one is the default). `outcome` is one of `denied`, `refused`,
/// `connect_failed`, `active`, `closed`, `cancelled`; `app_id` is never client
/// data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowSummaryDto {
    pub flow_id: String,
    pub app_id: String,
    pub destination: String,
    pub outcome: String,
    /// Who connected: the verified principal when there is one (`uid:1000`).
    #[serde(default)]
    pub peer: String,
    /// Whether the transport could verify `peer`.
    #[serde(default)]
    pub peer_verified: bool,
    /// The route the flow was planned onto, as a short summary (`Direct`).
    #[serde(default)]
    pub route: String,
    #[serde(default)]
    pub matched_rule: Option<String>,
    /// The closed machine code of a refusal or failure.
    #[serde(default)]
    pub reason_code: Option<String>,
    #[serde(default)]
    pub bytes_up: u64,
    #[serde(default)]
    pub bytes_down: u64,
    /// Wall-clock milliseconds since the Unix epoch, untrusted.
    #[serde(default)]
    pub started_ms: u64,
    #[serde(default)]
    pub ended_ms: Option<u64>,
    /// The ledger sequence numbers of the flow's `Pending` and `Result`
    /// records, when they exist.
    #[serde(default)]
    pub audit_pending_seq: Option<u64>,
    #[serde(default)]
    pub audit_result_seq: Option<u64>,
    /// The front end the client used (`socks5`).
    #[serde(default)]
    pub front_end: String,
    /// The local address the operating system gave the flow's upstream socket:
    /// an observation, not a statement about any interface.
    #[serde(default)]
    pub egress_local: Option<String>,
    /// `plain` or `hashed`: whether `destination` is the host or its token.
    #[serde(default)]
    pub destination_form: String,
}

/// One entry of `get_audit_entries` (command 18).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntryDto {
    pub entry_id: String,
    pub flow_id: String,
    pub outcome: String,
    pub route_kind_summary: String,
    pub epoch: u64,
    pub prev_hash: String,
    pub entry_hash: String,
}

impl From<&ssk_netadmin::ForensicEntry> for AuditEntryDto {
    fn from(e: &ssk_netadmin::ForensicEntry) -> Self {
        Self {
            entry_id: e.entry_id.clone(),
            flow_id: e.flow_id.clone(),
            outcome: format!("{:?}", e.outcome),
            route_kind_summary: e.route_kind_summary.clone(),
            epoch: e.epoch,
            prev_hash: e.prev_hash.clone(),
            entry_hash: e.entry_hash.clone(),
        }
    }
}

/// Response to `verify_audit_chain` (command 19).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyAuditChainResponse {
    pub ok: bool,
    pub head: Option<String>,
    pub broken_at: Option<String>,
}

/// One check within `run_doctor` (command 20).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorCheckDto {
    pub name: String,
    pub ok: bool,
    pub detail: String,
    pub next_step: Option<String>,
}

/// Response to `run_doctor` (command 20).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReportDto {
    pub checks: Vec<DoctorCheckDto>,
}

/// Request for `explain_error` (command 21).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainRequest {
    pub code: String,
}

/// Response to `explain_error` (command 21).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainResponse {
    pub summary: String,
    pub details: String,
    pub next_steps: Vec<String>,
}

/// Request for `subscribe_events` (command 22).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeEventsRequest {
    pub kinds: Option<Vec<String>>,
}

// --- The local proxy (IPC protocol 1) ----------------------------------------
//
// Design `docs/M2_LOCAL_INGRESS_DESIGN.md` 10.4, 10.5, 11.4 and 11.8.
//
// Rules that every type below keeps (11.2):
//
// * Nothing denies unknown fields, in either direction, so a field added later
//   is safe for an older reader and a newer reader of an older writer.
// * The status types are `#[serde(default)]` as a whole: an absent key is the
//   default, and the default of every one is the unknown answer, never one that
//   reads well. `state` and `coverage` are `""` (the client renders "unknown,
//   not covered"), every flag is `false`, every counter is 0.
// * Vocabularies are `String`s with a documented closed set, not enums: a new
//   word must not break an older client's decoder (R6), and a client renders a
//   word it does not know as unknown.

/// The local proxy as the daemon reports it. A separate block, never merged into
/// the daemon's own `state` or `last_error`; it says what the proxy is doing and
/// nothing about any other software, a VPN least of all.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IngressStatusDto {
    /// `disabled`, `starting`, `unavailable`, `disarmed`, `armed`, `tripped` or
    /// `stopping`.
    pub state: String,
    /// `none` or `proxy_clients_only`; the latter only while `state` is `armed`
    /// and the proxy is healthy.
    pub coverage: String,
    /// Constant `false`: this product never claims system-wide coverage, and a
    /// client that reads `true` must not believe it.
    pub system_wide: bool,
    /// The fixed sentence that says what the coverage is and is not.
    pub notice: String,
    /// `127.0.0.1:<port>`, only while a listener is bound.
    pub listen: Option<String>,
    /// The configured address, shown when `listen` is absent after a bind
    /// failure.
    pub configured_listen: Option<String>,
    /// The front ends in use (`socks5`).
    pub protocols: Vec<String>,
    pub armed_profile: Option<String>,
    /// The profile an arm that names none would use.
    pub arm_profile: Option<String>,
    pub controls: IngressControlsDto,
    pub counters: IngressCountersDto,
    pub audit: IngressAuditDto,
    /// The proxy's own last error; never merged into `StatusDto::last_error`.
    pub last_error: Option<IpcError>,
    pub last_denial: Option<DenialSummaryDto>,
    pub retry_hint: Option<String>,
    /// Changes on every gate transition, a disarm of an already disarmed gate
    /// included, so a poller can tell that something happened between two reads.
    pub epoch: u64,
    /// Trips since this boot: shows a trip followed by a re-arm that a poller
    /// missed.
    pub trips: u64,
    pub last_transition: Option<LastTransitionDto>,
    /// Only while `starting`: `verifying_ledger` or `binding`.
    pub phase: Option<String>,
    pub limits: IngressLimitsDto,
    pub config: ConfigDigestsDto,
    pub egress: IngressEgressDto,
    pub observations: IngressObservationsDto,
    pub warnings: Vec<IngressWarningDto>,
}

/// The hardening controls of the listener, each true only when it is verified to
/// be in force.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IngressControlsDto {
    pub exclusive_bind: bool,
    pub peer_check: bool,
    pub private_audit_store: bool,
    /// `required` or `best_effort`: what the configuration asked for.
    pub hardening: String,
}

/// Counts since this boot. A client clamps what it displays.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IngressCountersDto {
    pub accepted: u64,
    pub refused_disarmed: u64,
    pub refused_peer_budget: u64,
    pub refused_peer: u64,
    pub refused_rate: u64,
    pub refused_capacity: u64,
    pub malformed: u64,
    pub rejected_target: RejectedTargetDto,
    pub denied: u64,
    pub denied_suppressed: u64,
    pub admitted: u64,
    pub connect_failed: u64,
    pub active_flows: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub panics: u64,
    pub accept_errors: u64,
    pub audit_close_lost: u64,
    pub audit_busy: u64,
    pub audit_timeouts: u64,
    pub disarm_record_lost: u64,
    pub trips: u64,
    pub evicted_handshake: u64,
    pub resolver_busy: u64,
    pub resolver_zombies: u64,
}

/// Targets refused before any policy, counted by kind and never recorded one by
/// one (their text is client-controlled).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RejectedTargetDto {
    pub malformed: u64,
    pub numeric_alias: u64,
    pub localhost: u64,
}

/// The flow ledger's own status. No field carries the key, a path or a
/// destination.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IngressAuditDto {
    /// `ok`, `starting`, `stalled`, `tripped`, `corrupt`, `unavailable` or
    /// `closing`.
    pub state: String,
    pub entries: u64,
    pub head: Option<String>,
    pub segments: u32,
    pub bytes: u64,
    /// The wall clock of the oldest retained record: untrusted.
    pub oldest_ts_ms: Option<u64>,
    pub pruned_entries: u64,
    pub prune_deferred: u32,
    /// `plain` or `hashed`.
    pub destination_logging: String,
    pub dest_key_id: Option<String>,
    pub refusal_quota_used_percent: u8,
    pub denials_over_quota: u64,
    pub busy: u64,
    pub timeouts: u64,
    pub sync_last_ms: u64,
    pub sync_max_ms: u64,
    /// `fsync` or `unavailable`.
    pub dir_sync: String,
}

/// The newest refusal, for a status line. `host` is the destination text the
/// ledger was told to keep (the token in `hashed` mode).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DenialSummaryDto {
    pub host: String,
    pub port: u16,
    pub reason_code: String,
    pub rule_id: Option<String>,
}

/// The newest change of the gate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LastTransitionDto {
    pub epoch: u64,
    /// `started`, `armed`, `disarmed`, `tripped`, `recovered`, `unavailable` or
    /// `stopping`.
    pub kind: String,
    pub reason_code: String,
    /// Who asked, as the verified principal (`uid:1000`); absent when nobody did.
    pub actor: Option<String>,
}

/// Capacity: what was configured and what the descriptor budget allows.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IngressLimitsDto {
    /// As configured.
    pub max_connections: u32,
    pub max_connections_effective: u32,
    pub accept_rate_per_s: u32,
    /// `fd_limit` when the process's descriptor limit cut the configured value.
    pub clamped_by: Option<String>,
    pub fd_soft_limit: Option<u64>,
    pub fd_needed: u64,
}

/// The three digests of the configuration the daemon is running, each 64
/// lowercase hex characters (`ssk_config::fingerprint`); empty when not
/// reported.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ConfigDigestsDto {
    pub config: String,
    pub routing: String,
    pub ingress: String,
}

/// Facts about this daemon's own behaviour, not about any other software.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IngressEgressDto {
    /// Constant `false`: no dial is bound to an interface.
    pub binds_interface: bool,
    /// Constant `false`: no dial is bound to a source address.
    pub binds_source_address: bool,
    /// Constant `operating_system`.
    pub direct_resolver: String,
    /// `ipv4_only` or `any`, from the configuration.
    pub direct_address_families: String,
}

/// Facts read from the operating system and from the daemon's own sockets. They
/// describe what was seen, not what any other software is doing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IngressObservationsDto {
    pub label: String,
    /// The route lookup for the IPv4 documentation address `192.0.2.1`.
    pub route_v4: ObservedRouteDto,
    /// The route lookup for the IPv6 documentation address `2001:db8::1`.
    pub route_v6: ObservedRouteDto,
    pub last_direct_source: Option<ObservedSourceDto>,
}

/// One route lookup. The probe is a documentation address, so what it selects
/// says nothing about any real destination.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ObservedRouteDto {
    /// `not_sampled`, `observed`, `stale`, `no_route`, `unsupported` or `failed`.
    pub status: String,
    pub probe: String,
    pub interface_index: Option<u32>,
    /// Operating-system text: untrusted data, never part of a sentence.
    pub interface_alias: Option<String>,
    pub sampled_age_ms: Option<u64>,
    pub unchanged_for_ms: Option<u64>,
    pub previous: Option<PreviousRouteDto>,
}

/// What the lookup selected before it last changed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PreviousRouteDto {
    pub interface_index: Option<u32>,
    pub interface_alias: Option<String>,
    pub replaced_ago_ms: u64,
}

/// The local address the operating system gave the newest upstream socket.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ObservedSourceDto {
    pub address: String,
    /// `direct` or `first_hop`.
    pub kind: String,
    pub flow_id: String,
    pub age_ms: u64,
}

/// A fixed warning: `text` is one sentence per `code`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IngressWarningDto {
    pub code: String,
    pub text: String,
}

/// Request for `set_ingress`: declarative and idempotent, answered with a
/// `Response::Status`.
///
/// `armed` has no default: a request without it is not a disarm. The four
/// optional fields are absent from the bytes of a request that does not use them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetIngressRequest {
    pub armed: bool,
    /// The profile to arm; absent means the configured default. A disarm that
    /// names one is a usage error (`INGRESS_ARGUMENT`).
    #[serde(default)]
    pub profile_id: Option<String>,
    /// The caller's self-declared label (`cli` or `desktop`); the daemon maps
    /// anything else to `unknown`. Never verified.
    #[serde(default)]
    pub client: Option<String>,
    /// Refuse (`INGRESS_CONFIG_CONFLICT`) when the daemon's default profile is
    /// not this one: binds the request to what the caller showed its user.
    #[serde(default)]
    pub expect_profile: Option<String>,
    /// The same for the routing digest of the running configuration.
    #[serde(default)]
    pub expect_routing_digest: Option<String>,
}

/// Response to `get_ingress_audit`: one page of the ingress ledger, newest
/// first.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IngressAuditPageDto {
    pub entries: Vec<IngressAuditEntryDto>,
    pub head: Option<String>,
    pub entries_total: u64,
    pub oldest_seq: Option<u64>,
    pub truncated_by_bytes: bool,
    pub verification: Option<IngressVerifyDto>,
}

/// One ledger record as stored. `body` is the stored body bytes, as UTF-8 and
/// verbatim, so a client can recompute `blake3(prev_hash ++ body)` itself. It
/// is untrusted text: a client that prints it escapes control and
/// bidirectional characters first.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IngressAuditEntryDto {
    pub seq: u64,
    pub entry_hash: String,
    pub prev_hash: String,
    pub body: String,
}

/// The result of verifying the ledger while a page was read.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IngressVerifyDto {
    pub ok: bool,
    /// The verification stopped at its deadline and covers a prefix.
    pub partial: bool,
    pub entries_checked: u64,
    pub anchored_at_continue: bool,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Protocol 1 is "M2" until the first release tag; the matrix says so, and a
    /// client that needs more refuses an older daemon by comparing against this.
    #[test]
    fn this_build_speaks_protocol_one_and_refuses_what_it_does_not() {
        assert_eq!(IPC_PROTOCOL_VERSION, 1);
        let status = StatusDto {
            protocol: IPC_PROTOCOL_VERSION,
            ..StatusDto::default()
        };
        assert!(status.require_protocol(0).is_ok());
        assert!(status.require_protocol(IPC_PROTOCOL_VERSION).is_ok());

        let refusal = status
            .require_protocol(IPC_PROTOCOL_VERSION + 1)
            .expect_err("a daemon cannot speak a protocol newer than itself");
        assert_eq!(refusal.code, "DAEMON_TOO_OLD");
        assert_eq!(refusal.class, "Runtime");
        assert!(refusal
            .message
            .contains("protocol 1 but this client needs 2"));
        assert!(
            !refusal.retriable,
            "asking again does not change which binary is running"
        );
    }

    /// `Default` is what a test literal and a decoder fill in for a field that is
    /// absent, so it must be the old daemon: protocol 0, nothing claimed, and no
    /// ingress block (which is the "predates ingress" marker).
    #[test]
    fn a_default_status_is_idle_protocol_zero_with_no_ingress_block() {
        let status = StatusDto::default();
        assert_eq!(status.state, DaemonState::Inactive);
        assert_eq!(status.protocol, 0);
        assert!(status.ingress.is_none());
        assert!(!status.dns_protected && !status.kill_switch);
        assert!(status.last_error.is_none() && status.adapters.is_empty());
        assert!(status.require_protocol(1).is_err());
    }
}
