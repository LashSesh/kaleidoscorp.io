#![forbid(unsafe_code)]

//! # ssk-netd-helper — the elevated privileged broker (P0 security core)
//!
//! The single authoritative owner of the kill-switch security domain
//! (`SPEC_TAURI_GUI.md` §2, §12). It is the portable, synchronous core that the
//! async `ssk-ipc` named-pipe transport (with client-SID auth) wraps at a later
//! phase; the real Windows firewall edge lives in `ssk-winhost`, injected as a
//! [`ssk_boundary::BoundaryEnforcer`].
//!
//! A privileged verb travels through, in order (SPEC §5, §8):
//! command-auth → anti-replay nonce → idempotency → `expected_state_version` →
//! the `ssk-boundary` authorization gate + hash-chained audit → the enforcer →
//! **durable persist** → version bump → the authoritative [`KillSwitchStatus`].
//!
//! Durability and recovery (SPEC §3, §4, §6): every transition is written whole,
//! atomically, to an ACL-protected ProgramData store *after* the OS effect
//! succeeds, so a crash never leaves a half-committed journal. On restart
//! [`Broker::recover`] rehydrates the switch from the durable snapshot (via
//! [`ssk_boundary::KillSwitch::rehydrate`]) and reconciles the persisted state
//! against the observed OS rule — a disagreement is a fail-closed
//! [`Recovery::Inconsistent`] alarm, never silently smoothed.

pub mod broker;
pub mod error;
pub mod protocol;
pub mod status;
pub mod store;

pub use broker::{Broker, BrokerConfig};
pub use error::HelperError;
pub use protocol::{
    decode_envelope, encode_envelope, BrokerResponse, CapabilityToken, Command, CommandEnvelope,
    IdempotencyKey, Nonce, RejectReason, MAX_PRIV_FRAME,
};
pub use status::{EgressObserver, KillSwitchStatus, Recovery};
pub use store::{default_state_dir, FileReceiptStore, PersistedState, ReceiptStore};
