#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Live daemon product state — the data-plane-independent subset of the full
/// 18-state model (`docs/DESKTOP_CLIENT_ARCHITECTURE.md` section K.1) that is
/// meaningful before the real data plane (`ssk-netcore`, Phase 3) exists.
///
/// Defined here rather than in `ssk-daemon` so both `ssk-cli` and a future
/// `ssk-tauri-bridge` can share this wire type without depending on the
/// daemon binary crate (`ssk-daemon` depends on `ssk-ipc`, never the reverse).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaemonState {
    /// Protection off, daemon idle.
    Inactive,
    /// Bringing protection up.
    Activating,
    /// Protection on, routing engaged.
    Active,
    /// The daemon holds ONE open egress session that an activation
    /// established through the profile's route to the requested destination,
    /// and whose audit result is durable. It says nothing wider: it is not
    /// system-wide coverage (other traffic on the machine is neither captured
    /// nor routed by it, and the kill switch is a separate mechanism reported
    /// in `StatusDto::kill_switch`), and it is not verified DNS
    /// (`StatusDto::dns_protected` can be `false` here, e.g. for a hostname
    /// destination reached without a DNS-override adapter). The session is
    /// not monitored after activation, so this is the state at the moment it
    /// was established, not a liveness guarantee.
    Protected,
    /// Active but a non-fatal issue reduced protection.
    Degraded,
    /// Cannot guarantee protection; traffic blocked.
    FailClosed,
    /// Config failed validation; protection off.
    ConfigInvalid,
    /// Came up after a crash while previously armed; blocked until released.
    RecoveryMode,
}

/// Server-push event delivered to clients that called `subscribe_events`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    StateChanged {
        from: DaemonState,
        to: DaemonState,
        reason: String,
    },
    AuditAppended {
        seq: u64,
        entry_hash: String,
    },
    Warning {
        code: String,
        message: String,
    },
    /// Backpressure marker: the subscriber fell behind and this many events
    /// were dropped before it could catch up (`tokio::sync::broadcast`'s
    /// `RecvError::Lagged`, translated to a DTO clients can render).
    Lagged {
        skipped: u64,
    },
}
