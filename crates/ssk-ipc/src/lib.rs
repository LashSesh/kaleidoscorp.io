#![forbid(unsafe_code)]

//! `ssk-ipc` — shared DTOs, wire protocol, transport, and local authentication
//! between the Kaleidoscorp daemon (`ssk-daemon`) and its clients (`ssk-cli`,
//! and later a Tauri GUI bridge). Defines the request/response contract once
//! so every client speaks the identical protocol — no CLI-shell-improvisation.
//!
//! Layering: this crate depends only on the control-plane crates
//! (`ssk-netadmin`, `ssk-config`, `ssk-types`) plus `tokio`/`ciborium`. It
//! never depends on `ssk-daemon` — `ssk-daemon` depends on this crate. It also
//! does not depend on `ssk-winhost`: the Windows FFI this crate *needs* (peer
//! SID lookup, pipe creation with a DACL) arrives as the trait objects in
//! [`transport_win`], injected at the composition root, so `ssk-ipc` stays
//! `#![forbid(unsafe_code)]` while still owning the security decision and its
//! tests.

pub mod auth;
pub mod client;
pub mod dto;
pub mod error;
pub mod framing;
pub mod paths;
pub mod server;
pub mod state;
#[cfg(windows)]
pub mod transport_win;

pub use auth::PeerIdentity;
pub use client::DaemonClient;
pub use dto::*;
pub use error::IpcError;
pub use paths::Endpoint;
pub use server::{BoxFuture, CommandHandler, Request, Response, ServeLimits, MAX_LIST_LIMIT};
pub use state::{DaemonState, Event};
#[cfg(windows)]
pub use transport_win::{PeerAuthenticator, PipeFactory, Sid};
