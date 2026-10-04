#![forbid(unsafe_code)]
//! Versioned presentation data only. No host, IPC, policy or Tauri dependency.
//! A snapshot is an observation for display, never an authorization to act.
use serde::{Deserialize, Serialize};
mod desktop;
mod dto;
pub use desktop::*;
pub use dto::*;

/// The panel's presentation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PanelState {
    /// No connection to the broker yet.
    Disconnected,
    /// Connecting / first observation in flight.
    Connecting,
    /// Coherent, kill-switch armed (not engaged).
    Ready,
    /// Coherent, kill-switch engaged with a confirmed OS rule.
    Engaged,
    /// Coherent, kill-switch released.
    Released,
    /// Journal/OS disagreement — a fail-closed red alarm (sticky).
    Inconsistent,
    /// The source is unreachable, the ledger is unverified, or a verdict is
    /// unknown — never rendered as a safe/green state.
    Degraded,
}

/// Only wire version 1 is understood. Unknown versions fail deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct SchemaVersion;

impl TryFrom<u32> for SchemaVersion {
    type Error = &'static str;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == 1 {
            Ok(Self)
        } else {
            Err("unsupported panel schema version")
        }
    }
}

impl From<SchemaVersion> for u32 {
    fn from(_: SchemaVersion) -> Self {
        1
    }
}

/// Replace the whole observation, including missing sections; never merge
/// absent data into a previously confirmed protection state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PanelSnapshotV1 {
    pub schema_version: SchemaVersion,
    pub panel_state: PanelState,
    pub kill_switch: Option<KillSwitchViewDto>,
    pub audit: Option<AuditViewDto>,
    pub connections: Option<ConnectionsViewDto>,
}
