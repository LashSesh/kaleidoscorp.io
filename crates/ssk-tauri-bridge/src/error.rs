//! The bridge error type — "never fabricate a green" (SPEC_TAURI_GUI.md §7.1)
//! made a typed value rather than a silent default. A degraded panel is reached
//! *through* one of these, not by emitting a clear/OK DTO.

use serde::{Deserialize, Serialize};

/// A fail-closed reason the panel could not produce a trustworthy view.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BridgeError {
    /// The privileged broker could not be reached — status is unknown, not "ok".
    #[error("privileged broker unreachable")]
    BrokerUnreachable,
    /// The audit ledger failed verification — integrity is unknown, not "ok".
    #[error("audit ledger failed verification")]
    LedgerUnverified,
    /// A system verdict could not be obtained — the verdict is unknown, not a Pass.
    #[error("system verdict unavailable")]
    VerdictUnknown,
}

impl BridgeError {
    /// A stable machine code for the frontend to switch on.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            BridgeError::BrokerUnreachable => "broker_unreachable",
            BridgeError::LedgerUnverified => "ledger_unverified",
            BridgeError::VerdictUnknown => "verdict_unknown",
        }
    }
}

/// The serde projection of a [`BridgeError`] sent to the frontend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeErrorDto {
    pub code: String,
    pub message: String,
}

impl From<&BridgeError> for BridgeErrorDto {
    fn from(e: &BridgeError) -> Self {
        BridgeErrorDto {
            code: e.code().to_owned(),
            message: e.to_string(),
        }
    }
}
