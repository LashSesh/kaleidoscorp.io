#![forbid(unsafe_code)]

//! `ssk-ipc` — shared DTOs, wire protocol, transport, and local authentication
//! between the Kaleidoscorp daemon (`ssk-daemon`) and its clients (`ssk-cli`,
//! and later a Tauri GUI bridge). Defines the request/response contract once
//! so every client speaks the identical protocol — no CLI-shell-improvisation.
//!
//! Layering: this crate depends only on the control-plane crates
//! (`ssk-netadmin`, `ssk-config`, `ssk-types`) plus `tokio`/`ciborium`. It
//! never depends on `ssk-daemon` — `ssk-daemon` depends on this crate.

pub mod auth;
pub mod client;
pub mod dto;
pub mod error;
pub mod framing;
pub mod paths;
pub mod server;
pub mod state;

pub use auth::SessionToken;
pub use dto::*;
pub use error::IpcError;
pub use server::{BoxFuture, CommandHandler, Request, Response};
pub use state::{DaemonState, Event};
