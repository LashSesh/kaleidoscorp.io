//! Presentation DTOs — the single source of the JS↔Rust JSON contract
//! (`SPEC_TAURI_GUI.md` §10).
//!
//! Every DTO derives `Serialize + Deserialize` with `#[serde(deny_unknown_fields)]`
//! and `rename_all = "snake_case"` on enums, so the JSON wire strings the
//! frontend consumes are pinned and tested (see `tests/view_core.rs`). Tauri
//! IPC is **JSON**, not CBOR. `Digest`s render as lowercase 64-hex strings,
//! never byte arrays. TypeScript generation (ts-rs) is a later, opt-in step; the
//! Rust-side wire strings tested here are the contract the frontend binds to.

use serde::{Deserialize, Serialize};

/// The kill-switch logical state (journal-derived).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogicalStateDto {
    Armed,
    Engaged,
    Released,
}

/// The observed OS-rule presence. `Unknown` is a fail-closed value — it is never
/// treated as "absent" or "present".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsRuleDto {
    Present,
    Absent,
    Unknown,
}

/// The reconciliation verdict between journal and OS reality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryDto {
    Consistent,
    Reconciled,
    Inconsistent,
}

/// The panel severity the UI binds its colour to. **Defensively derived** from
/// `(logical_state, os_rule, recovery)` — not merely copied from an upstream
/// flag — so a malformed status can never render as safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeverityDto {
    /// Coherent and either not engaged, or engaged with a confirmed OS rule.
    Ok,
    /// Engaged and reconciled after a restart — worth a glance, not an alarm.
    Notice,
    /// A journal/OS disagreement, or an engagement whose protection is not
    /// confirmed — a fail-closed red alarm.
    Alarm,
}

/// The held rollback receipt, projected for display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptDto {
    pub receipt_id_hex: String,
    pub scope_label: String,
    pub prior_state: String,
}

/// The kill-switch security panel view.
///
/// Safety framing (SPEC §7, review must-fix): `journal_claims_engaged` is a
/// *journal-only* claim — it does **not** assert egress is actually cut. Only
/// `protection_confirmed` (engaged **and** OS rule present **and** consistent)
/// may drive a "protected/green" affordance. Any incoherence is an `Alarm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KillSwitchViewDto {
    pub logical_state: LogicalStateDto,
    pub os_rule: OsRuleDto,
    pub recovery: RecoveryDto,
    pub severity: SeverityDto,
    /// The journal says engaged. NOT a verified-protection claim.
    pub journal_claims_engaged: bool,
    /// Egress is *verifiably* cut: engaged ∧ OS rule present ∧ consistent.
    pub protection_confirmed: bool,
    /// A fail-closed alarm the UI must render red (equals `severity == Alarm`).
    pub is_alarm: bool,
    pub state_version: u64,
    pub audit_len: u64,
    pub audit_head_hex: String,
    pub receipt: Option<ReceiptDto>,
}

/// The audit-chain integrity verdict. Internally tagged, **no `Default`** — an
/// unverified chain can never be silently treated as verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuditIntegrityDto {
    Verified,
    Unverified,
}

/// One projected boundary audit entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntryDto {
    pub seq: u64,
    pub kind: String,
    pub from_state: String,
    pub to_state: String,
    pub actor: String,
    pub reason: Option<String>,
    pub entry_hash_hex: String,
}

/// The audit ledger view. The `entries` are **always** projected — even when
/// integrity is `Unverified` — so a tampered chain is visible, never hidden.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditViewDto {
    pub entry_count: u64,
    pub head_hex: String,
    pub integrity: AuditIntegrityDto,
    pub entries: Vec<AuditEntryDto>,
}

/// One projected connection/flow row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionRowDto {
    pub protocol: String,
    pub local: String,
    pub remote: String,
    pub pid: u32,
    pub status: String,
}

/// The connections panel view.
///
/// `live_supported` is honest: off-Windows (and until the P3 live seam lands)
/// the live source yields no rows, so the panel shows "live capture
/// unsupported here" — never a green "no connections / all clear". `parse_anomaly`
/// flags a declared-count vs parsed-rows mismatch (a possibly-corrupt table),
/// named for what it is, not dismissed as benign truncation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionsViewDto {
    pub source_id: String,
    pub live_supported: bool,
    pub parse_anomaly: bool,
    pub rows: Vec<ConnectionRowDto>,
}
