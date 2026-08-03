//! # ssk-winhost — the real Windows 11 privileged backends (the "hands")
//!
//! Every other crate in this workspace is pure and `#![forbid(unsafe_code)]`.
//! This is the **one** crate exempt from that: it is where the privileged,
//! OS-specific FFI lives, deliberately isolated so the rest of the system stays
//! provably unsafe-free. It binds real Windows implementations to the three
//! injected seams the pure crates left open:
//!
//! * [`WindowsEgressEnforcer`] — a real [`ssk_boundary::BoundaryEnforcer`]
//!   (and [`ssk_boundary::BoundaryProbe`]) that severs and *exactly* restores
//!   egress. Its actuator is selected by
//!   [`firewall::EgressMechanism`]: today the interim
//!   `netsh advfirewall` path (admin-only, no kernel driver); the destination
//!   is WFP dynamic session filters. [`WindowsFirewallEnforcer`] is an alias
//!   kept so the mechanism swap is not a rename of every call site.
//! * [`WindowsConnectionSource`] — a real [`ssk_capture::TrafficSource`] that
//!   enumerates active TCP/UDP flows with owning PID via the IP Helper API
//!   (`GetExtendedTcpTable`/`GetExtendedUdpTable`). Connection/flow level, not
//!   packet level (that is a deeper WinDivert/WFP tier, noted where relevant).
//! * [`WindowsServiceHelper`] — a real [`ssk_service_host::PrivilegedHelper`]
//!   driving the Windows Service Control Manager (install/start/stop/uninstall).
//!
//! A fourth seam is Windows-only and arrives from `ssk-ipc` rather than from a
//! pure core crate:
//!
//! * [`pipe`] — the named-pipe security edge. `WindowsPeerAuthenticator`
//!   implements `ssk_ipc::PeerAuthenticator` (`ImpersonateNamedPipeClient` +
//!   `TokenUser`, answering *who is on the far end of this pipe*) and
//!   `WindowsPipeFactory` implements `ssk_ipc::PipeFactory` (SDDL →
//!   `SECURITY_ATTRIBUTES` → `create_with_security_attributes_raw`, so the pipe
//!   carries an explicit DACL instead of the default that grants `Everyone` and
//!   `ANONYMOUS LOGON` read access). `ssk-ipc` stays `#![forbid(unsafe_code)]`
//!   and keeps the *decision*; this crate holds the syscalls. That is what
//!   closes roadmap SEC-3.
//!
//! P3 added three more, all of them the FFI half of a decision
//! `ssk-netd-helper` already owns:
//!
//! * [`observer`] — [`TieredEgressObserver`] implements
//!   [`ssk_netd_helper::EgressObserver`] by composing
//!   [`ssk_boundary::BoundaryProbe`]s, so `os_rule_present` and the
//!   `Recovery::Inconsistent` alarm finally read from something real. It holds
//!   no netsh knowledge of its own. The same module binds
//!   [`ssk_netd_helper::BoundaryRecoverer`] to
//!   [`WindowsEgressEnforcer::recover`], the receipt-less sweep the startup
//!   reconciler needs. **Read that module's header before trusting the alarm:**
//!   the shipped netsh probe can confirm presence and can say "cannot tell", but
//!   it can never conclude *absence*, so the "someone deleted our rule" branch
//!   is unreachable on this mechanism.
//! * [`privileged`] — the SYSTEM-owned control pipe: a synchronous
//!   [`ssk_netd_helper::FrameTransport`] over a named pipe, and the accept loop
//!   that authenticates each peer before a byte is read and hands the
//!   connection to `ssk_netd_helper::PrivilegedServer`. Its client half refuses
//!   any endpoint not owned by `S-1-5-18`, which is the only thing standing
//!   between a client and a squatter on the fixed pipe name.
//! * [`authz_file`] — the `(SID, verb)` allow-list, read from the ACL'd state
//!   directory, degrading to *read-only* rather than deny-all so a severed
//!   machine stays diagnosable.
//!
//! [`pipe`] grew the token-facts probe those need:
//! `WindowsPeerAuthenticator::authenticate_peer` reads the peer's SID and its
//! token's privilege facts in **one** impersonation window, and keeps
//! "holds administrative rights right now" (`CheckTokenMembership`) separate
//! from "the account is an administrator's" (`TokenGroups` including
//! `SE_GROUP_USE_FOR_DENY_ONLY`). Those are different questions with different
//! answers on a UAC-filtered token, and conflating them is what would lock a
//! single-admin machine out of its own kill-switch.
//!
//! Two things here are primitives rather than seams:
//!
//! * [`state_dir`] — the `%ProgramData%\ScorpioSync` state-directory gate. It is
//!   where the P1 store lockdown is actually *executed* on the path the product
//!   takes, and where a directory some other principal already controls becomes
//!   a typed refusal instead of a trusted input.
//! * [`privilege`] — the `TokenElevation` probe that
//!   [`ssk_netd_helper::store::Elevation`] is documented to expect from a
//!   composition root. It lives here because it is FFI and that crate is
//!   `#![forbid(unsafe_code)]`.
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
//!
//! **P3 widened that boundary and the widening is named rather than absorbed.**
//! Roughly half of a LocalSystem broker's behaviour cannot be executed on an
//! unelevated developer machine, so the design puts every *decision* behind an
//! injected seam in a `forbid(unsafe_code)` crate and keeps the un-runnable half
//! to syscalls with no branches in them. Concretely, nothing here has ever run
//! as `LocalSystem`, no service has been installed, no firewall rule has ever
//! been created by this software on any machine, and
//! `%ProgramData%\ScorpioSync` was deliberately never created. Every P3 claim
//! that depends on any of those is an operator leg in
//! `crates/ssk-winhost/scripts/verify-pipe-peer-auth.ps1` (legs P3-1 … P3-8) and
//! is asserted nowhere in code.

pub mod authz_file;
pub mod connections;
pub mod firewall;
pub mod observer;
pub mod pipe;
pub mod privilege;
pub mod service;
pub mod state_dir;

#[cfg(windows)]
pub mod privileged;

pub use authz_file::{authz_path, AuthzLoad, AUTHZ_FILE_NAME, AUTHZ_SCHEME};
pub use connections::WindowsConnectionSource;
pub use firewall::{EgressMechanism, WindowsEgressEnforcer, WindowsFirewallEnforcer};
pub use observer::TieredEgressObserver;
pub use pipe::{
    owner_matches, sddl_for_read_only_fallback_pipe, sddl_for_system_owned_pipe,
    sddl_for_user_owned_pipe, validate_sid_string, PipeSecurityError, LOCAL_SYSTEM_SID,
    MAX_CLIENT_ACES,
};
pub use privilege::{elevation, is_elevated, Elevation};
pub use service::WindowsServiceHelper;
pub use state_dir::{StateDirLayout, StateDirRefusal, StateDirStatus};

/// The three things the daemon's composition root needs to serve on Windows.
///
/// `ssk-daemon` is `#![forbid(unsafe_code)]`, so it cannot obtain its own SID,
/// build a `SECURITY_ATTRIBUTES`, or impersonate a pipe client. All three land
/// here, and all three are `#[cfg(windows)]` because the types they speak in
/// (`tokio::net::windows::named_pipe::NamedPipeServer`) exist only there.
///
/// * [`current_user_sid`] feeds `ssk_ipc::paths::default_endpoint`.
/// * [`WindowsPipeFactory`] and [`WindowsPeerAuthenticator`] are the two
///   required arguments of `ssk_ipc::server::serve_named_pipe`.
#[cfg(windows)]
pub use pipe::{
    client_pipe_owner_sid, current_user_sid, describe_pipe_security, require_pipe_owner,
    require_system_owned_pipe, server_pipe_owner_sid, WindowsPeerAuthenticator, WindowsPipeFactory,
};

/// The P3 privileged host: the SYSTEM-owned control pipe and the accept loop
/// that fronts [`ssk_netd_helper::Broker`].
#[cfg(windows)]
pub use privileged::{
    CsprngLeaseIds, ListenerReport, NamedPipeClientTransport, NamedPipeFrameTransport,
    PrivilegedPipeHost, PrivilegedPipeHostConfig, StopSignal, PRIVILEGED_PIPE_NAME,
};

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
