#![forbid(unsafe_code)]

//! # ssk-tauri-bridge — the read-only desktop panel backend (P1)
//!
//! The portable, synchronous **view core** of the Tauri GUI
//! (`SPEC_TAURI_GUI.md` §9, §10): pure projection functions that turn the SSK
//! security surfaces into presentation [`dto`]s, plus the [`state`] machine that
//! keeps the panel fail-closed and the [`error`] type that makes "never
//! fabricate a green" a typed value.
//!
//! **Nothing here launches a webview or touches Windows.** The `#[tauri::command]`
//! glue and the WebView2 window remain pending (`ui/INTEGRATION.md`).
//! The standalone frontend is in `ui/desktop` at the repository root; its
//! wire types live in `ssk-ui-contract`. Linux CI verifies the
//! pure projection logic + the DTO/JSON wire contract + the state machine, and
//! nothing more.
//!
//! ## Fail-closed discipline (SPEC §7, defense-in-depth)
//! The views never merely *trust* an upstream flag. The kill-switch view
//! re-derives its [`SeverityDto`](dto::SeverityDto) from `(logical_state,
//! os_rule)` so a malformed status can never render "protected"; a
//! journal-claimed engagement is `journal_claims_engaged`, distinct from the
//! verified `protection_confirmed`; an unverified ledger renders `Unverified`
//! with its rows still present; an unknown/unreachable source routes to
//! [`PanelState::Degraded`](state::PanelState::Degraded), never a fabricated
//! `Ready`.

pub mod control;
pub mod dto;
pub mod error;
pub mod state;
pub mod view;

pub use control::{ControlClient, ControlError, KillSwitchControl, NonceSource};
pub use dto::{
    AuditEntryDto, AuditIntegrityDto, AuditViewDto, ConnectionRowDto, ConnectionsViewDto,
    DecisionDto, GateOutcomeDto, KillSwitchViewDto, LogicalStateDto, OsRuleDto, ReceiptDto,
    RecoveryDto, ResonanceActionDto, SeverityDto, SystemVerdictViewDto,
};
pub use error::{BridgeError, BridgeErrorDto};
pub use state::{classify, transition, IllegalTransition, PanelEvent, PanelState};
pub use view::{audit_view, connections_view, kill_switch_view, system_verdict_view};
