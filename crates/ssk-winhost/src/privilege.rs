//! The elevation probe — the one thing `ssk-netd-helper` deliberately refused
//! to implement for itself.
//!
//! [`ssk_netd_helper::store::Elevation`] is documented as *"a value supplied by
//! the composition root rather than something this crate probes for itself"*,
//! because the only reliable Windows elevation check is
//! `GetTokenInformation(.., TokenElevation, ..)` — FFI, and that crate is
//! `#![forbid(unsafe_code)]`. This module is the other half of that seam: it
//! performs the FFI here, in the one crate exempt from the forbid, and hands
//! back the same [`Elevation`] type so there is exactly one elevation vocabulary
//! and one `NOT_ELEVATED` machine code in the workspace.
//!
//! ## Why the token, and not `whoami /groups` or SID membership
//!
//! `S-1-5-32-544` (`BUILTIN\Administrators`) is **present** in an unelevated
//! process's filtered token — flagged `SE_GROUP_USE_FOR_DENY_ONLY` — so SID
//! presence is not elevation (roadmap §5.2, established by controlled
//! experiment on this hardware). Parsing `whoami /groups` was rejected for the
//! same reason the English netsh literals were: its attribute column is
//! localized (`"Gruppen, die nur zum Ablehnen verwendet wird"` on the de-DE test
//! box). `TokenElevation` is a boolean the kernel computes; it is neither
//! localized nor inferable from group membership.
//!
//! ## What this does *not* establish
//!
//! `TokenElevation` is true for a full administrator token. It says nothing
//! about which privileges are enabled, and it is not a substitute for the OS's
//! own access check: a privileged call can still fail with `ACCESS_DENIED` after
//! this returns `Some(true)`. It is a **preflight**, used to refuse early and
//! with an accurate message — never to conclude that an operation will succeed.

pub use ssk_netd_helper::store::Elevation;

#[cfg(windows)]
mod sys {
    use std::ffi::c_void;

    /// `TOKEN_QUERY`.
    pub const TOKEN_QUERY: u32 = 0x0008;
    /// `TOKEN_INFORMATION_CLASS::TokenElevation`.
    pub const TOKEN_ELEVATION_CLASS: i32 = 20;

    /// The documented `TOKEN_ELEVATION`: a single `DWORD`.
    #[repr(C)]
    pub struct TokenElevation {
        pub token_is_elevated: u32,
    }

    // Parameter names are the SDK's own, so a reader can match them against the
    // MSDN signature; rustc does not apply `non_snake_case` to foreign items.
    #[link(name = "advapi32")]
    unsafe extern "system" {
        pub fn OpenProcessToken(
            ProcessHandle: *mut c_void,
            DesiredAccess: u32,
            TokenHandle: *mut *mut c_void,
        ) -> i32;
        pub fn GetTokenInformation(
            TokenHandle: *mut c_void,
            TokenInformationClass: i32,
            TokenInformation: *mut c_void,
            TokenInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn GetCurrentProcess() -> *mut c_void;
        pub fn CloseHandle(hObject: *mut c_void) -> i32;
    }
}

/// Whether **this process** runs with a full (elevated) administrator token.
///
/// `None` means the question could not be answered — either the target has no
/// elevation concept implemented here, or a Win32 call failed. Callers must map
/// `None` to [`Elevation::Unknown`] via [`Elevation::from_probe`], which fails
/// closed; see [`elevation`].
#[cfg(windows)]
#[must_use]
pub fn is_elevated() -> Option<bool> {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::ptr;

    let mut token: *mut c_void = ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no close.
    // `token` is a valid out-parameter; on failure it is left null and we bail.
    let opened =
        unsafe { sys::OpenProcessToken(sys::GetCurrentProcess(), sys::TOKEN_QUERY, &mut token) };
    if opened == 0 || token.is_null() {
        return None;
    }

    let mut info = sys::TokenElevation {
        token_is_elevated: 0,
    };
    let mut returned: u32 = 0;
    let len = u32::try_from(size_of::<sys::TokenElevation>()).unwrap_or(u32::MAX);
    // SAFETY: `token` is a live token handle with TOKEN_QUERY; `info` is a
    // correctly sized, correctly aligned `TOKEN_ELEVATION` we own; `len` is its
    // exact size. The handle is closed on every path below.
    let ok = unsafe {
        sys::GetTokenInformation(
            token,
            sys::TOKEN_ELEVATION_CLASS,
            ptr::addr_of_mut!(info).cast::<c_void>(),
            len,
            &mut returned,
        )
    };
    // SAFETY: `token` came from `OpenProcessToken` and is closed exactly once.
    unsafe {
        sys::CloseHandle(token);
    }

    // A short write would leave `token_is_elevated` partly uninitialized as far
    // as the API contract is concerned; refuse to interpret it.
    if ok == 0 || returned as usize != size_of::<sys::TokenElevation>() {
        return None;
    }
    Some(info.token_is_elevated != 0)
}

/// This build target has no elevation probe, so the question is unanswerable
/// here — **not** answered "no". The distinction matters: callers fail closed on
/// `None`, and the non-Windows state-directory path does not gate on elevation
/// at all (there are no Windows ACLs to apply).
#[cfg(not(windows))]
#[must_use]
pub fn is_elevated() -> Option<bool> {
    None
}

/// [`is_elevated`] mapped onto the typed [`Elevation`] vocabulary, failing
/// closed: an unanswerable probe is [`Elevation::Unknown`], which
/// [`Elevation::permits_system_mutation`] refuses exactly like
/// [`Elevation::NotElevated`].
#[must_use]
pub fn elevation() -> Elevation {
    Elevation::from_probe(is_elevated())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unanswerable_probe_never_reads_as_elevated() {
        assert_eq!(Elevation::from_probe(None), Elevation::Unknown);
        assert!(!Elevation::from_probe(None).permits_system_mutation());
    }

    /// On Windows the probe must actually answer. A `None` here would mean the
    /// FFI is broken, and every provisioning call would then fail closed with
    /// `NOT_ELEVATED` regardless of the real token — a silent feature outage.
    #[cfg(windows)]
    #[test]
    fn the_windows_probe_answers() {
        assert!(
            is_elevated().is_some(),
            "GetTokenInformation(TokenElevation) must answer on Windows"
        );
        assert_ne!(elevation(), Elevation::Unknown);
    }

    /// Asserts the *mapping*, not a particular token: whichever state the
    /// process happens to run in, the enum must agree with the probe. It is the
    /// only place that compares the two, so a future inversion of the boolean is
    /// caught in whichever arm is taken.
    ///
    /// Which arm that is depends on how the suite is invoked, and the honest
    /// statement is that only the `Some(false)` arm has ever executed on the
    /// development machine — the test runs unelevated there by policy. The
    /// `Some(true)` arm is written and compiled but unexercised; do not read a
    /// green run of this test as evidence that elevated detection works.
    #[cfg(windows)]
    #[test]
    fn the_enum_agrees_with_the_probe() {
        match is_elevated() {
            Some(true) => assert_eq!(elevation(), Elevation::Elevated),
            Some(false) => assert_eq!(elevation(), Elevation::NotElevated),
            None => panic!("covered by the_windows_probe_answers"),
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_the_probe_declines_to_answer() {
        assert_eq!(is_elevated(), None);
        assert_eq!(elevation(), Elevation::Unknown);
    }
}
