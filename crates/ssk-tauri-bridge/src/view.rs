//! The view core: pure projection functions from the SSK security surfaces into
//! presentation DTOs. No I/O, no webview, no Windows — this is the entire
//! Linux-CI-tested surface (SPEC_TAURI_GUI.md §9, §10).

use ssk_boundary::{BoundaryAuditEntry, EnforcementReceipt, KillSwitchState};
use ssk_crown::EmissionDecision;
use ssk_meta_resonance::ResonanceAction;
use ssk_netd_helper::{KillSwitchStatus, Recovery};
use ssk_system::SystemVerdict;
use ssk_types::{Digest, GateOutcomeKind};
use ssk_winhost::connections::{parse_tcp_table, parse_udp_table, FlowRow};

use crate::dto::{
    AuditEntryDto, AuditIntegrityDto, AuditViewDto, ConnectionRowDto, ConnectionsViewDto,
    DecisionDto, GateOutcomeDto, KillSwitchViewDto, LogicalStateDto, OsRuleDto, ReceiptDto,
    RecoveryDto, ResonanceActionDto, SeverityDto, SystemVerdictViewDto,
};

fn logical_state(s: KillSwitchState) -> LogicalStateDto {
    match s {
        KillSwitchState::Armed => LogicalStateDto::Armed,
        KillSwitchState::Engaged => LogicalStateDto::Engaged,
        KillSwitchState::Released => LogicalStateDto::Released,
    }
}

fn recovery(r: Recovery) -> RecoveryDto {
    match r {
        Recovery::Consistent => RecoveryDto::Consistent,
        Recovery::Reconciled => RecoveryDto::Reconciled,
        Recovery::Inconsistent => RecoveryDto::Inconsistent,
    }
}

fn os_rule(present: Option<bool>) -> OsRuleDto {
    match present {
        Some(true) => OsRuleDto::Present,
        Some(false) => OsRuleDto::Absent,
        None => OsRuleDto::Unknown,
    }
}

fn receipt(r: &EnforcementReceipt) -> ReceiptDto {
    ReceiptDto {
        receipt_id_hex: r.receipt_id.to_hex(),
        scope_label: r.scope_label.clone(),
        prior_state: r.prior_state.clone(),
    }
}

/// Project the authoritative kill-switch status into the panel DTO.
///
/// The `severity` is **defensively re-derived** from `(logical_state, os_rule,
/// recovery)` rather than copied from any upstream alarm flag: an engaged switch
/// whose OS rule is not confirmed present is an `Alarm` even if the upstream
/// reconciliation somehow said otherwise. `protection_confirmed` is the *only*
/// field that may drive a green affordance.
#[must_use]
pub fn kill_switch_view(status: &KillSwitchStatus) -> KillSwitchViewDto {
    let logical_state = logical_state(status.logical_state);
    let os = os_rule(status.os_rule_present);
    let recovery = recovery(status.recovery);

    let journal_claims_engaged = matches!(status.logical_state, KillSwitchState::Engaged);
    let protection_confirmed = journal_claims_engaged
        && status.os_rule_present == Some(true)
        && matches!(status.recovery, Recovery::Consistent);

    // Fail-closed severity (defense in depth): any incoherence is an Alarm.
    let severity = if matches!(status.recovery, Recovery::Inconsistent)
        || (journal_claims_engaged && status.os_rule_present != Some(true))
    {
        SeverityDto::Alarm
    } else if matches!(status.recovery, Recovery::Reconciled) {
        SeverityDto::Notice
    } else {
        SeverityDto::Ok
    };

    KillSwitchViewDto {
        logical_state,
        os_rule: os,
        recovery,
        severity,
        journal_claims_engaged,
        protection_confirmed,
        is_alarm: matches!(severity, SeverityDto::Alarm),
        state_version: status.state_version,
        audit_len: status.audit_len,
        audit_head_hex: status.audit_head.to_hex(),
        receipt: status.receipt.as_ref().map(receipt),
    }
}

/// Project the boundary audit ledger. `verified` is the result of
/// [`ssk_boundary::KillSwitch::verify_audit`] — it is passed in, never
/// re-implemented here. The entries are always projected, even when unverified,
/// so a tampered chain is visible rather than hidden.
#[must_use]
pub fn audit_view(entries: &[BoundaryAuditEntry], verified: bool) -> AuditViewDto {
    let head = entries.last().map_or(Digest::GENESIS, |e| e.entry_hash);
    let projected = entries
        .iter()
        .map(|e| AuditEntryDto {
            seq: e.seq,
            kind: e.event.kind.clone(),
            from_state: e.event.from_state.clone(),
            to_state: e.event.to_state.clone(),
            actor: e.event.actor.clone(),
            reason: e.event.reason.clone(),
            entry_hash_hex: e.entry_hash.to_hex(),
        })
        .collect();
    AuditViewDto {
        entry_count: entries.len() as u64,
        head_hex: head.to_hex(),
        integrity: if verified {
            AuditIntegrityDto::Verified
        } else {
            AuditIntegrityDto::Unverified
        },
        entries: projected,
    }
}

fn decision(d: EmissionDecision) -> DecisionDto {
    match d {
        EmissionDecision::Emit => DecisionDto::Emit,
        EmissionDecision::Hold => DecisionDto::Hold,
        EmissionDecision::Deny => DecisionDto::Deny,
    }
}

fn gate_outcome(g: GateOutcomeKind) -> GateOutcomeDto {
    match g {
        GateOutcomeKind::Pass => GateOutcomeDto::Pass,
        GateOutcomeKind::Hold => GateOutcomeDto::Hold,
        GateOutcomeKind::Refine => GateOutcomeDto::Refine,
        GateOutcomeKind::Reject => GateOutcomeDto::Reject,
        GateOutcomeKind::Quarantine => GateOutcomeDto::Quarantine,
    }
}

fn resonance_action(a: ResonanceAction) -> ResonanceActionDto {
    match a {
        ResonanceAction::Stabilize => ResonanceActionDto::Stabilize,
        ResonanceAction::Delay => ResonanceActionDto::Delay,
        ResonanceAction::Hold => ResonanceActionDto::Hold,
    }
}

/// Project an end-to-end [`SystemVerdict`] into the panel DTO. `SystemVerdict` is
/// not itself `Serialize`, so this is a hand-written projection with total
/// (no-wildcard) enum matches, pinning the wire strings the frontend binds to.
#[must_use]
pub fn system_verdict_view(v: &SystemVerdict) -> SystemVerdictViewDto {
    SystemVerdictViewDto {
        decision: decision(v.decision),
        host_downgraded: v.host_downgraded,
        signature_gate: gate_outcome(v.signature_gate),
        qlogic_gate: gate_outcome(v.qlogic_gate),
        resonance_action: resonance_action(v.resonance_action),
        field_digest_hex: v.field_digest.to_hex(),
        reasons: v.reasons.clone(),
    }
}

/// The declared entry count in a length-prefixed IP Helper table (`dwNumEntries`,
/// a leading little-endian `u32`), or `0` if the buffer is too short to hold it.
fn declared_count(bytes: &[u8]) -> usize {
    if bytes.len() >= 4 {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
    } else {
        0
    }
}

/// A coarse, honest label for a TCP connection state (`MIB_TCP_STATE`).
fn tcp_status(state: u32) -> &'static str {
    match state {
        1 => "closed",
        2 => "listen",
        3 => "syn_sent",
        4 => "syn_rcvd",
        5 => "established",
        8 => "close_wait",
        6 | 7 | 9..=12 => "closing",
        _ => "unknown",
    }
}

fn row_dto(flow: &FlowRow, status: &str) -> ConnectionRowDto {
    ConnectionRowDto {
        protocol: flow.protocol.to_owned(),
        local: format!("{}:{}", flow.local_addr, flow.local_port),
        remote: format!("{}:{}", flow.remote_addr, flow.remote_port),
        pid: flow.pid,
        status: status.to_owned(),
    }
}

/// Project raw TCP/UDP IP Helper table bytes into the connections view.
///
/// `live_supported` is passed in honestly by the caller: off-Windows the live
/// source yields no rows, so the panel says "live capture unsupported here"
/// rather than a green "no connections". `parse_anomaly` fires when the table's
/// declared entry count exceeds the rows actually parsed (a possibly-corrupt or
/// truncated table) — named as an anomaly, not dismissed as benign.
#[must_use]
pub fn connections_view(
    tcp: &[u8],
    udp: &[u8],
    source_id: &str,
    live_supported: bool,
) -> ConnectionsViewDto {
    let tcp_rows = parse_tcp_table(tcp);
    let udp_rows = parse_udp_table(udp);
    let parse_anomaly =
        declared_count(tcp) > tcp_rows.len() || declared_count(udp) > udp_rows.len();

    let mut rows = Vec::with_capacity(tcp_rows.len() + udp_rows.len());
    rows.extend(tcp_rows.iter().map(|f| row_dto(f, tcp_status(f.state))));
    rows.extend(udp_rows.iter().map(|f| row_dto(f, "stateless")));

    ConnectionsViewDto {
        source_id: source_id.to_owned(),
        live_supported,
        parse_anomaly,
        rows,
    }
}
