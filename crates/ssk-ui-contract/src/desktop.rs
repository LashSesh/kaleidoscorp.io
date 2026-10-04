//! Desktop observation v2. Daemon claims are not verified OS protection.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct DesktopSchemaVersion;
impl TryFrom<u32> for DesktopSchemaVersion {
    type Error = &'static str;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == 2 {
            Ok(Self)
        } else {
            Err("unsupported desktop schema version")
        }
    }
}
impl From<DesktopSchemaVersion> for u32 {
    fn from(_: DesktopSchemaVersion) -> Self {
        2
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportedDaemonState {
    Inactive,
    Activating,
    Active,
    Protected,
    Degraded,
    FailClosed,
    ConfigInvalid,
    RecoveryMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonViewDto {
    pub reported_state: ReportedDaemonState,
    pub version: String,
    pub active_profile: Option<String>,
    pub adapter_count: u32,
    pub last_error_code: Option<String>,
}

/// A daemon summary alone cannot establish any security-ready panel state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopPanelState {
    Degraded,
}

/// Only a local IPC response was obtained. This version deliberately carries
/// no KillSwitchViewDto, audit verification or process-wide connection table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopSnapshotV2 {
    pub schema_version: DesktopSchemaVersion,
    pub panel_state: DesktopPanelState,
    pub daemon: DaemonViewDto,
}
