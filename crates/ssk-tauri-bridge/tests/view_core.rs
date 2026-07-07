//! P1 view-core tests (SPEC_TAURI_GUI.md §9, §10): the entire Linux-CI-verified
//! surface. Covers the projections, the fail-closed guarantees the review
//! demanded, the pinned JSON wire strings the frontend binds to, the panel state
//! machine, and a machine-generated golden-fixture round-trip guard.

use std::path::PathBuf;

use ssk_boundary::{BoundaryAuditEntry, BoundaryEvent, EnforcementReceipt, KillSwitchState};
use ssk_netd_helper::{KillSwitchStatus, Recovery};
use ssk_types::Digest;

use ssk_tauri_bridge::dto::{
    AuditIntegrityDto, LogicalStateDto, OsRuleDto, RecoveryDto, SeverityDto,
};
use ssk_tauri_bridge::state::{classify, transition, PanelEvent, PanelState};
use ssk_tauri_bridge::view::{audit_view, connections_view, kill_switch_view};

// ── helpers ──────────────────────────────────────────────────────────────────

fn status(logical: KillSwitchState, os: Option<bool>, recovery: Recovery) -> KillSwitchStatus {
    KillSwitchStatus {
        logical_state: logical,
        receipt: None,
        os_rule_present: os,
        audit_head: Digest::GENESIS,
        audit_len: 0,
        state_version: 0,
        recovery,
    }
}

fn engaged_receipt() -> EnforcementReceipt {
    EnforcementReceipt {
        receipt_id: Digest::GENESIS,
        scope_label: "all-egress".to_owned(),
        prior_state: "flowing".to_owned(),
    }
}

fn audit_entry(seq: u64, kind: &str) -> BoundaryAuditEntry {
    BoundaryAuditEntry {
        seq,
        prev_hash: Digest::GENESIS,
        event: BoundaryEvent {
            kind: kind.to_owned(),
            from_state: "armed".to_owned(),
            to_state: "engaged".to_owned(),
            actor: "operator".to_owned(),
            reason: None,
        },
        entry_hash: Digest::GENESIS,
    }
}

/// One TCP fixture row: (state, local_addr, local_port, remote_addr, remote_port, pid).
type TcpFixtureRow = (u32, [u8; 4], u16, [u8; 4], u16, u32);

/// Build a length-prefixed MIB_TCPTABLE_OWNER_PID byte image.
fn tcp_table(rows: &[TcpFixtureRow]) -> Vec<u8> {
    let mut b = (rows.len() as u32).to_le_bytes().to_vec();
    for &(state, la, lp, ra, rp, pid) in rows {
        b.extend_from_slice(&state.to_le_bytes());
        b.extend_from_slice(&la);
        b.extend_from_slice(&lp.to_be_bytes());
        b.extend_from_slice(&[0, 0]); // port high WORD
        b.extend_from_slice(&ra);
        b.extend_from_slice(&rp.to_be_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&pid.to_le_bytes());
    }
    b
}

fn udp_table(rows: &[([u8; 4], u16, u32)]) -> Vec<u8> {
    let mut b = (rows.len() as u32).to_le_bytes().to_vec();
    for &(la, lp, pid) in rows {
        b.extend_from_slice(&la);
        b.extend_from_slice(&lp.to_be_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&pid.to_le_bytes());
    }
    b
}

// ── kill-switch projection + fail-closed safety framing ──────────────────────

#[test]
fn engaged_and_confirmed_is_ok_and_protection_confirmed() {
    let mut s = status(KillSwitchState::Engaged, Some(true), Recovery::Consistent);
    s.receipt = Some(engaged_receipt());
    let v = kill_switch_view(&s);
    assert_eq!(v.logical_state, LogicalStateDto::Engaged);
    assert_eq!(v.os_rule, OsRuleDto::Present);
    assert!(v.journal_claims_engaged);
    assert!(v.protection_confirmed, "engaged + present + consistent");
    assert_eq!(v.severity, SeverityDto::Ok);
    assert!(!v.is_alarm);
    assert!(v.receipt.is_some());
}

// Review must-fix: journal-only engagement with an unconfirmed OS rule must be
// an ALARM with protection NOT confirmed — the alarm dominates the journal claim.
#[test]
fn engaged_without_confirmed_os_rule_is_alarm_not_protected() {
    for os in [Some(false), None] {
        let s = status(KillSwitchState::Engaged, os, Recovery::Consistent);
        let v = kill_switch_view(&s);
        assert!(v.journal_claims_engaged, "the journal still claims engaged");
        assert!(
            !v.protection_confirmed,
            "protection is NOT confirmed when the OS rule is {os:?}"
        );
        assert_eq!(v.severity, SeverityDto::Alarm, "os_rule {os:?} -> alarm");
        assert!(v.is_alarm);
    }
}

#[test]
fn inconsistent_recovery_is_always_alarm() {
    let s = status(KillSwitchState::Engaged, Some(true), Recovery::Inconsistent);
    let v = kill_switch_view(&s);
    assert_eq!(v.recovery, RecoveryDto::Inconsistent);
    assert_eq!(v.severity, SeverityDto::Alarm);
    assert!(v.is_alarm);
    assert!(
        !v.protection_confirmed,
        "an inconsistent status is never protected"
    );
}

#[test]
fn reconciled_is_a_notice_not_an_alarm() {
    let s = status(KillSwitchState::Engaged, Some(true), Recovery::Reconciled);
    let v = kill_switch_view(&s);
    assert_eq!(v.severity, SeverityDto::Notice);
    assert!(!v.is_alarm);
}

#[test]
fn armed_baseline_is_ok_with_no_receipt() {
    let v = kill_switch_view(&status(
        KillSwitchState::Armed,
        Some(false),
        Recovery::Consistent,
    ));
    assert_eq!(v.logical_state, LogicalStateDto::Armed);
    assert!(!v.journal_claims_engaged);
    assert!(!v.protection_confirmed);
    assert_eq!(v.severity, SeverityDto::Ok);
    assert!(v.receipt.is_none());
    assert_eq!(v.audit_head_hex.len(), 64, "digest renders as 64-hex");
}

// ── audit projection: tampered chain stays visible ───────────────────────────

#[test]
fn audit_view_verified_projects_all_entries() {
    let entries = vec![audit_entry(0, "engage"), audit_entry(1, "release")];
    let v = audit_view(&entries, true);
    assert_eq!(v.entry_count, 2);
    assert_eq!(v.integrity, AuditIntegrityDto::Verified);
    assert_eq!(v.entries.len(), 2);
    assert_eq!(v.head_hex.len(), 64);
}

#[test]
fn audit_view_unverified_still_shows_every_row() {
    let entries = vec![audit_entry(0, "engage")];
    let v = audit_view(&entries, false);
    assert_eq!(v.integrity, AuditIntegrityDto::Unverified);
    assert_eq!(
        v.entries.len(),
        1,
        "a tampered/unverified chain is shown, never hidden"
    );
}

#[test]
fn audit_view_empty_ledger_is_honest() {
    let v = audit_view(&[], true);
    assert_eq!(v.entry_count, 0);
    // Empty ledger head is GENESIS (all-zero), rendered honestly, verify true.
    assert_eq!(v.head_hex, Digest::GENESIS.to_hex());
    assert_eq!(v.integrity, AuditIntegrityDto::Verified);
}

// ── connections projection ───────────────────────────────────────────────────

#[test]
fn connections_view_projects_tcp_and_udp_rows_with_pid() {
    let tcp = tcp_table(&[
        (5, [10, 0, 0, 1], 55000, [93, 184, 216, 34], 443, 4321), // established
        (2, [0, 0, 0, 0], 8080, [0, 0, 0, 0], 0, 4),              // listen
    ]);
    let udp = udp_table(&[([10, 0, 0, 1], 53, 900)]);
    let v = connections_view(&tcp, &udp, "mock-source", true);
    assert!(v.live_supported);
    assert!(!v.parse_anomaly);
    assert_eq!(v.rows.len(), 3);
    let established = &v.rows[0];
    assert_eq!(established.protocol, "tcp");
    assert_eq!(established.remote, "93.184.216.34:443");
    assert_eq!(established.pid, 4321, "pid survives the projection");
    assert_eq!(established.status, "established");
    assert_eq!(v.rows[1].status, "listen");
    let udp_row = v.rows.iter().find(|r| r.protocol == "udp").unwrap();
    assert_eq!(udp_row.status, "stateless");
    assert_eq!(udp_row.pid, 900);
}

// Off-Windows (and until the P3 live seam), the source yields no rows — that is
// rendered as "live unsupported", never a green "no connections / all clear".
#[test]
fn connections_view_unsupported_source_is_not_a_green_all_clear() {
    let v = connections_view(&[], &[], "linux-nolive", false);
    assert!(
        !v.live_supported,
        "must flag that live capture is unavailable"
    );
    assert!(v.rows.is_empty());
    // The frontend binds the "unsupported" banner to live_supported==false, not
    // to rows.is_empty() (which would read as a reassuring empty list).
}

#[test]
fn connections_view_flags_a_parse_anomaly() {
    // Declared 3 rows, but only one row's worth of bytes present.
    let mut bytes = 3u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0u8; 24]); // one row
    let v = connections_view(&bytes, &[], "corrupt", true);
    assert!(v.parse_anomaly, "declared > parsed must flag an anomaly");
    assert_eq!(v.rows.len(), 1, "only the fully-present row is surfaced");
}

#[test]
fn connections_parser_never_panics_on_junk() {
    for junk in [vec![], vec![0xff], vec![0xff; 3], vec![9u8; 40]] {
        let _ = connections_view(&junk, &junk, "junk", true);
    }
}

// ── pinned JSON wire strings (the contract the frontend binds to) ────────────

#[test]
fn enum_wire_strings_are_snake_case_and_pinned() {
    use serde_json::to_value;
    assert_eq!(to_value(LogicalStateDto::Engaged).unwrap(), "engaged");
    assert_eq!(to_value(OsRuleDto::Unknown).unwrap(), "unknown");
    assert_eq!(to_value(RecoveryDto::Inconsistent).unwrap(), "inconsistent");
    assert_eq!(to_value(SeverityDto::Alarm).unwrap(), "alarm");
    assert_eq!(to_value(PanelState::Degraded).unwrap(), "degraded");
    // The audit integrity is internally tagged, and Unverified must NOT be a
    // default — the exact wire shape is pinned.
    assert_eq!(
        to_value(AuditIntegrityDto::Unverified).unwrap(),
        serde_json::json!({ "status": "unverified" })
    );
}

// ── panel state machine ──────────────────────────────────────────────────────

#[test]
fn classify_prioritises_the_inconsistent_alarm() {
    let s = status(KillSwitchState::Engaged, Some(true), Recovery::Inconsistent);
    assert_eq!(classify(&s), PanelState::Inconsistent);
    let ok = status(KillSwitchState::Engaged, Some(true), Recovery::Consistent);
    assert_eq!(classify(&ok), PanelState::Engaged);
    let armed = status(KillSwitchState::Armed, Some(false), Recovery::Consistent);
    assert_eq!(classify(&armed), PanelState::Ready);
}

#[test]
fn unknown_or_unreachable_routes_to_degraded_never_ready() {
    // A dropped broker / unverified ledger / unknown verdict never yields a
    // green Ready — it degrades.
    for ev in [
        PanelEvent::Unreachable,
        PanelEvent::LedgerUnverified,
        PanelEvent::VerdictUnknown,
    ] {
        assert_eq!(
            transition(PanelState::Ready, &ev).unwrap(),
            PanelState::Degraded
        );
    }
    // From Degraded, Retry re-connects; a fresh observation reclassifies.
    assert_eq!(
        transition(PanelState::Degraded, &PanelEvent::Retry).unwrap(),
        PanelState::Connecting
    );
}

#[test]
fn happy_path_and_illegal_transitions() {
    assert_eq!(
        transition(PanelState::Disconnected, &PanelEvent::Connect).unwrap(),
        PanelState::Connecting
    );
    let obs = PanelEvent::Observed(Box::new(status(
        KillSwitchState::Engaged,
        Some(true),
        Recovery::Consistent,
    )));
    assert_eq!(
        transition(PanelState::Connecting, &obs).unwrap(),
        PanelState::Engaged
    );
    // Illegal: you cannot Connect while already Engaged.
    let err = transition(PanelState::Engaged, &PanelEvent::Connect).unwrap_err();
    assert_eq!(err.from, PanelState::Engaged);
    assert_eq!(err.event, "connect");
}

// ── machine-generated golden fixtures + round-trip guard ─────────────────────

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Canonical DTOs whose serialization is committed as golden fixtures. These are
/// deterministic presentation DTOs (no captured pipeline output, no fabricated
/// digests), so machine-generating them is honest.
fn goldens() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::to_value;
    let engaged = {
        let mut s = status(KillSwitchState::Engaged, Some(true), Recovery::Consistent);
        s.receipt = Some(engaged_receipt());
        s.audit_len = 1;
        s.state_version = 1;
        kill_switch_view(&s)
    };
    let inconsistent = kill_switch_view(&status(
        KillSwitchState::Engaged,
        None,
        Recovery::Inconsistent,
    ));
    let audit_unverified = audit_view(&[audit_entry(0, "engage")], false);
    let connections_ready = connections_view(
        &tcp_table(&[(5, [10, 0, 0, 1], 55000, [93, 184, 216, 34], 443, 4321)]),
        &[],
        "mock-source",
        true,
    );
    let connections_unsupported = connections_view(&[], &[], "linux-nolive", false);
    vec![
        ("kill_switch_engaged", to_value(&engaged).unwrap()),
        ("kill_switch_inconsistent", to_value(&inconsistent).unwrap()),
        ("audit_unverified", to_value(&audit_unverified).unwrap()),
        ("connections_ready", to_value(&connections_ready).unwrap()),
        (
            "connections_unsupported",
            to_value(&connections_unsupported).unwrap(),
        ),
    ]
}

/// Regenerate the golden fixtures from code. Ignored by default; run with
/// `cargo test -p ssk-tauri-bridge write_goldens -- --ignored` after a DTO
/// change, then commit the updated `tests/fixtures/*.json`.
#[test]
#[ignore = "write-golden harness; run explicitly to regenerate committed fixtures"]
fn write_goldens() {
    let dir = fixtures_dir();
    std::fs::create_dir_all(&dir).unwrap();
    for (name, value) in goldens() {
        let path = dir.join(format!("{name}.json"));
        let pretty = serde_json::to_string_pretty(&value).unwrap();
        std::fs::write(&path, format!("{pretty}\n")).unwrap();
    }
    // Panel states as their own tiny fixtures.
    for st in [
        PanelState::Disconnected,
        PanelState::Connecting,
        PanelState::Ready,
        PanelState::Engaged,
        PanelState::Released,
        PanelState::Inconsistent,
        PanelState::Degraded,
    ] {
        let name = serde_json::to_value(st).unwrap();
        let path = dir.join(format!("panel_{}.json", name.as_str().unwrap()));
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&name).unwrap()),
        )
        .unwrap();
    }
}

/// Every committed golden must parse under `deny_unknown_fields` and re-serialize
/// to the identical JSON value — so a DTO change that is not reflected in the
/// committed fixtures (schema/fixture drift) fails CI.
#[test]
fn committed_goldens_round_trip() {
    for (name, expected) in goldens() {
        let path = fixtures_dir().join(format!("{name}.json"));
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("missing committed golden {name}.json (run write_goldens)"));
        let on_disk: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            on_disk, expected,
            "golden {name}.json drifted from the DTO projection"
        );
    }
}
