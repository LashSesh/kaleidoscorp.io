#![forbid(unsafe_code)]

use std::time::Duration;

/// Real, three-way health outcome — never a bare `bool` — so a caller can
/// distinguish "fully live" from "reachable but degraded" from "down", each
/// with a truthful reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStatus {
    /// The full adapter chain really connected (and, where applicable,
    /// really handshook) within the timeout.
    Live,
    /// The transport connected but a non-fatal irregularity was observed
    /// (currently unused by the executors in this crate; reserved for a
    /// future latency/jitter threshold once one is defined — no code path
    /// produces this today, so it must not be presented as evidence of a
    /// capability that does not yet exist).
    Degraded,
    /// The real attempt failed; `reason` names the typed cause.
    Down,
}

/// The result of [`crate::RouteExecutor::probe`]: a real attempt was made,
/// and this is its real, timestamped-by-latency outcome.
#[derive(Debug, Clone)]
pub struct ProbeReport {
    pub status: ProbeStatus,
    pub latency: Option<Duration>,
    pub reason: String,
}

impl ProbeReport {
    #[must_use]
    pub fn live(latency: Duration, reason: impl Into<String>) -> Self {
        Self {
            status: ProbeStatus::Live,
            latency: Some(latency),
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn down(reason: impl Into<String>) -> Self {
        Self {
            status: ProbeStatus::Down,
            latency: None,
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn is_live(&self) -> bool {
        self.status == ProbeStatus::Live
    }
}
