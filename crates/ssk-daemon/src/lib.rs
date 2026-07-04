#![forbid(unsafe_code)]

//! `ssk-daemon` — the Kaleidoscorp product runtime (binary `sskd`). The GUI
//! and CLI are thin clients over this daemon's `ssk-ipc` protocol; all real
//! state, policy evaluation, and (from Phase 3) data-plane execution live
//! here.

pub mod config_load;
pub mod mock_dataplane;
pub mod state;
pub mod supervisor;
