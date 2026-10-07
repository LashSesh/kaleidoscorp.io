#![forbid(unsafe_code)]

//! `ssk-daemon` — the Kaleidoscorp product runtime (binary `sskd`). The GUI
//! and CLI are thin clients over this daemon's `ssk-ipc` protocol; all real
//! state, policy evaluation, and real (`ssk-netcore`-backed) data-plane
//! execution live here.

pub mod cli;
pub mod config_load;
/// The local proxy ingress (design M2_LOCAL_INGRESS_DESIGN.md). Pure modules
/// first; nothing here is wired into `sskd` yet.
pub mod ingress;
// The subscriber, the durable rotated sink, the panic hook and the OS-CSPRNG
// probe used to live here as `diag` and `entropy`. They are now `ssk-diag`,
// linked by `ssk`, `sskd` and `ssk-svc` alike: this crate's copy and `ssk-cli`'s
// inline copy were the duplication that produced the `/dev/urandom` defect in
// two places, and `ssk-svc` would have been the third.
/// The daemon's read-only view of the privileged kill-switch: the seam that
/// replaced `Supervisor`'s three hardcoded `kill_switch: false`. The daemon
/// **asks** the broker; it never observes the OS itself.
pub mod killswitch;
pub mod lock;
pub mod paths;
pub mod routing;
pub mod shutdown;
pub mod state;
pub mod supervisor;
