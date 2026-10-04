#![forbid(unsafe_code)]

//! OpenVPN 2.x management, strict profiles and owned-process supervision.
//!
//! This portable library does not spawn executables, change OS networking,
//! or grant egress admission. The Windows host provides protected storage and
//! a job-contained ChildProcess implementation; broker wiring remains pending.
//! A reported CONNECTED state is explicitly unverified:
//! process ownership, interface binding, routes, DNS and kill-switch enforcement
//! must be established separately by the privileged host.
//!
//! The supported startup contract is a fresh client using management password
//! authentication and management-hold. Only fixed control commands are emitted;
//! interactive VPN credentials and signing challenges fail closed for now.

mod client;
mod lifecycle;
mod process;
mod profile;
mod protocol;

pub use client::{Client, ManagementTransport, TcpTransport};
pub use lifecycle::{Command, Failure, ManagementPassword, Session, Snapshot, Stage, Timeouts};
pub use process::{ChildProcess, ManagedProcess, ProcessFailure, ProcessSnapshot, ProcessStage};
pub use profile::{Profile, ProfileError, ProfileId, MAX_PROFILE_BYTES};
pub use protocol::{CredentialKind, Decoder, Event, ProtocolError, VpnState, MAX_LINE_BYTES};
