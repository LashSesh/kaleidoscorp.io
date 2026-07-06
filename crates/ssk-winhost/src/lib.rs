//! # ssk-winhost — the real Windows 11 privileged backends (the "hands")
//!
//! Every other crate in this workspace is pure and `#![forbid(unsafe_code)]`.
//! This is the **one** crate exempt from that: it is where the privileged,
//! OS-specific FFI lives, deliberately isolated so the rest of the system stays
//! provably unsafe-free. It binds real Windows implementations to the three
//! injected seams the pure crates left open:
//!
//! * [`WindowsFirewallEnforcer`] — a real [`ssk_boundary::BoundaryEnforcer`]
//!   that severs and *exactly* restores egress via the Windows Firewall
//!   (`netsh advfirewall`, admin-only, no kernel driver).
//! * [`WindowsConnectionSource`] — a real [`ssk_capture::TrafficSource`] that
//!   enumerates active TCP/UDP flows with owning PID via the IP Helper API
//!   (`GetExtendedTcpTable`/`GetExtendedUdpTable`). Connection/flow level, not
//!   packet level (that is a deeper WinDivert/WFP tier, noted where relevant).
//! * [`WindowsServiceHelper`] — a real [`ssk_service_host::PrivilegedHelper`]
//!   driving the Windows Service Control Manager (install/start/stop/uninstall).
//!
//! ## Honest platform & verification boundary
//!
//! All privileged work is `#[cfg(windows)]`. On a non-Windows target the crate
//! still compiles — the seams return a typed "requires Windows" error or an
//! empty flow list — so the whole workspace builds and every *pure* function
//! here (rule-name derivation, connection-table parsing, service-name
//! derivation, receipt encoding) is unit-tested on any host, including the
//! Linux build box.
//!
//! What is proven here: the code **compiles for `x86_64-pc-windows-msvc`** (the
//! real Windows API signatures) and its pure logic is tested everywhere. What
//! is **not** proven here and must be validated by an operator on a real
//! Windows 11 machine with Administrator rights: that the firewall rule is
//! actually installed/removed, that real flows are enumerated, and that the
//! service actually registers with the SCM. See `RUNBOOK_WINDOWS.md` for the
//! exact validation steps. This crate never claims "runs on a real machine"
//! from a build that cannot exercise the privileged effect.

pub mod connections;
pub mod firewall;
pub mod service;

pub use connections::WindowsConnectionSource;
pub use firewall::WindowsFirewallEnforcer;
pub use service::WindowsServiceHelper;

/// Whether this *build target* actually carries the privileged Windows
/// backends. `false` on non-Windows targets, where the seams are inert stubs.
#[must_use]
pub fn platform_supported() -> bool {
    cfg!(windows)
}

#[cfg(test)]
mod tests {
    #[test]
    fn platform_support_matches_target() {
        assert_eq!(super::platform_supported(), cfg!(windows));
    }
}
