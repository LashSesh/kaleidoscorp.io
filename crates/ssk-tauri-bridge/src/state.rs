//! The panel UI state machine (`SPEC_TAURI_GUI.md` §10). Rendered strictly from
//! this model, so an uncovered/unknown situation routes to a visible
//! [`PanelState::Degraded`] — never a fabricated `Ready`/green.
//!
//! The `transition` match over [`PanelState`] is **exhaustive with no wildcard**,
//! so adding a state fails to compile until every case is handled.

use ssk_boundary::KillSwitchState;
use ssk_netd_helper::{KillSwitchStatus, Recovery};
pub use ssk_ui_contract::PanelState;

/// A control event driving the panel machine. `Observed` carries the freshly
/// read authoritative status (boxed to keep the enum small).
#[derive(Debug, Clone)]
pub enum PanelEvent {
    Connect,
    Observed(Box<KillSwitchStatus>),
    Unreachable,
    LedgerUnverified,
    VerdictUnknown,
    Retry,
    Reset,
}

impl PanelEvent {
    fn name(&self) -> &'static str {
        match self {
            PanelEvent::Connect => "connect",
            PanelEvent::Observed(_) => "observed",
            PanelEvent::Unreachable => "unreachable",
            PanelEvent::LedgerUnverified => "ledger_unverified",
            PanelEvent::VerdictUnknown => "verdict_unknown",
            PanelEvent::Retry => "retry",
            PanelEvent::Reset => "reset",
        }
    }
}

/// A rejected transition — a visible defect value, never a blank.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("illegal transition from {from:?} on event '{event}'")]
pub struct IllegalTransition {
    pub from: PanelState,
    pub event: String,
}

/// Classify an authoritative status into the coherent panel state it implies.
/// An `Inconsistent` reconciliation always wins (fail-closed).
#[must_use]
pub fn classify(status: &KillSwitchStatus) -> PanelState {
    if matches!(status.recovery, Recovery::Inconsistent) {
        return PanelState::Inconsistent;
    }
    match status.logical_state {
        KillSwitchState::Engaged => PanelState::Engaged,
        KillSwitchState::Released => PanelState::Released,
        KillSwitchState::Armed => PanelState::Ready,
    }
}

/// The panel transition function. The outer match over [`PanelState`] is
/// exhaustive with no wildcard.
///
/// # Errors
/// [`IllegalTransition`] if the event is not admissible in the current state.
pub fn transition(state: PanelState, event: &PanelEvent) -> Result<PanelState, IllegalTransition> {
    let illegal = || {
        Err(IllegalTransition {
            from: state,
            event: event.name().to_owned(),
        })
    };
    match state {
        PanelState::Disconnected => match event {
            PanelEvent::Connect => Ok(PanelState::Connecting),
            PanelEvent::Reset => Ok(PanelState::Disconnected),
            _ => illegal(),
        },
        PanelState::Connecting => match event {
            PanelEvent::Observed(s) => Ok(classify(s)),
            PanelEvent::Unreachable => Ok(PanelState::Degraded),
            PanelEvent::Reset => Ok(PanelState::Disconnected),
            _ => illegal(),
        },
        PanelState::Ready | PanelState::Engaged | PanelState::Released => match event {
            PanelEvent::Observed(s) => Ok(classify(s)),
            PanelEvent::Unreachable | PanelEvent::LedgerUnverified | PanelEvent::VerdictUnknown => {
                Ok(PanelState::Degraded)
            }
            PanelEvent::Reset => Ok(PanelState::Disconnected),
            _ => illegal(),
        },
        PanelState::Inconsistent => match event {
            // Sticky alarm: only a fresh coherent observation or an explicit
            // reset clears it; a transient unreachable degrades.
            PanelEvent::Observed(s) => Ok(classify(s)),
            PanelEvent::Unreachable => Ok(PanelState::Degraded),
            PanelEvent::Reset => Ok(PanelState::Disconnected),
            _ => illegal(),
        },
        PanelState::Degraded => match event {
            PanelEvent::Retry => Ok(PanelState::Connecting),
            PanelEvent::Observed(s) => Ok(classify(s)),
            PanelEvent::Reset => Ok(PanelState::Disconnected),
            _ => illegal(),
        },
    }
}
