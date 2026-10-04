//! Shared, untrusted controller statistics. No authority is encoded here.
#[cfg(any(windows, test))]
use serde::{Deserialize, Serialize};

pub(super) const PROCESS_NETWORK_FLAGS: u32 = 0x1001_0001;
pub(super) const SYSTEM_LOGGER: u32 = 0x0200_0000;
#[cfg(any(windows, test))]
pub(super) const PRIVATE_MODE: u32 = 0x0002_0801;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg(any(windows, test))]
pub(super) struct Snapshot {
    pub api_status: u32,
    pub properties: Option<Properties>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg(any(windows, test))]
pub(super) struct Properties {
    pub session_guid: String,
    pub log_file_mode: u32,
    pub enable_flags: u32,
    pub events_lost: u32,
    pub log_buffers_lost: u32,
    pub realtime_buffers_lost: u32,
    pub buffers_written: u32,
}
