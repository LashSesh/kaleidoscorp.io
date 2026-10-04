#![forbid(unsafe_code)]

//! # ssk-netd-helper — the elevated privileged broker (P0 security core)
//!
//! The single authoritative owner of the kill-switch security domain
//! (`SPEC_TAURI_GUI.md` §2, §12). It is the portable, synchronous core that a
//! transport wraps; the real Windows firewall edge and the real named-pipe I/O
//! live in `ssk-winhost`, injected as a [`ssk_boundary::BoundaryEnforcer`] and
//! as a [`framing::FrameTransport`].
//!
//! A privileged verb travels through, in order (SPEC §5, §8):
//! **peer authorization** ([`authz`]) → command-auth (constant-time) →
//! actuation authorization → session budget → anti-replay nonce → idempotency
//! (bound to the command) → `expected_state_version` → the `ssk-boundary`
//! authorization gate + hash-chained audit → the enforcer → **durable persist**
//! → version bump → the authoritative [`KillSwitchStatus`].
//!
//! Durability and recovery (SPEC §3, §4, §6): every transition is written whole,
//! atomically, to an ACL-protected ProgramData store *after* the OS effect
//! succeeds, so a crash never leaves a half-committed journal. The store is
//! **provisioned** (elevated, once — [`FileReceiptStore::provision`]) separately
//! from being **opened** (unprivileged of ACLs —
//! [`FileReceiptStore::open_existing`]); conflating the two is what locked the
//! broker out of its own store before P1. On restart
//! [`Broker::recover`] rehydrates the switch from the durable snapshot (via
//! [`ssk_boundary::KillSwitch::rehydrate`]) and reconciles the persisted state
//! against the observed OS rule — a disagreement is a fail-closed
//! [`Recovery::Inconsistent`] alarm, never silently smoothed.
//!
//! # What P3 added, and where the seam runs
//!
//! | Concern | Module | Runs where |
//! |---|---|---|
//! | who may command which verb | [`authz`] | here — pure, no syscall |
//! | cross-session refcounting | [`lease`] | here |
//! | startup reconciliation | [`recover`] + [`Broker::reconcile_startup`] | here |
//! | frame caps, connection cap | [`framing`] | here |
//! | versioned handshake | [`handshake`] | here |
//! | request/response loops | [`client`], [`server`] | here |
//! | pipe creation, SDDL, peer token, read timeout, owner check | — | `ssk-winhost` |
//!
//! That split is deliberate. Almost none of a LocalSystem broker's *environment*
//! can be exercised on an unelevated developer machine, so every **decision** is
//! kept on this side of the seam — pure, injected, exhaustively testable — and
//! the un-runnable side is reduced to syscalls with no branches in them.
//! `#![forbid(unsafe_code)]` is what keeps that split honest: it is not possible
//! to accidentally move a decision across it.

pub mod authz;
pub mod broker;
pub mod client;
pub mod error;
pub mod framing;
pub mod handshake;
pub mod lease;
pub mod protocol;
pub mod recover;
pub mod server;
pub mod status;
pub mod store;
pub mod vpn;

#[cfg(test)]
pub(crate) mod testing;

pub use authz::{
    AuthenticatedPeer, AuthzDenied, ControlVerb, Grant, PeerAuthorizer, PeerIdentity, PeerToken,
    TieredSidAuthorizer,
};
pub use broker::{
    ActuationAuthority, Broker, BrokerConfig, LeaseAdoptError, MAX_SESSION_MUTATIONS,
};
pub use client::{ClientError, NonceSource, PrivilegedClient};
pub use error::HelperError;
pub use framing::{
    ConnectionLimiter, ConnectionPermit, FrameError, FrameTransport, TransportError,
    MAX_HANDSHAKE_FRAME, MAX_PRIV_CONNECTIONS, PRIV_READ_TIMEOUT,
};
pub use handshake::{
    ClientHello, HandshakeReject, ServerHandshake, ServerHello, PRIV_MIN_PROTOCOL_VERSION,
    PRIV_PROTOCOL_VERSION,
};
pub use lease::{Lease, LeaseId, LeaseKind, LeaseSet};
pub use protocol::{
    decode_envelope, encode_envelope, BrokerResponse, CapabilityToken, Command, CommandEnvelope,
    IdempotencyKey, Nonce, RejectReason, MAX_PRIV_FRAME,
};
pub use recover::{BoundaryRecoverer, ReconcileAction, ReconcilePolicy, ReconcileReport};
pub use server::{ConnectionOutcome, LeaseIdSource, PrivilegedServer, SequentialLeaseIds};
pub use status::{EgressObserver, KillSwitchStatus, Recovery};
pub use store::{
    default_provision_chain, default_state_dir, lockdown_args, setowner_args, AclRunner, Elevation,
    FileReceiptStore, PersistedState, ReceiptStore,
};
