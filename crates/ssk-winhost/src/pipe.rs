//! The Windows named-pipe security edge — the FFI half of the seam `ssk-ipc`
//! declared and deliberately left open.
//!
//! `ssk-ipc` is `#![forbid(unsafe_code)]`. It owns the *decision*
//! ([`ssk_ipc::transport_win::check_peer_same_user`]) and its tests; this
//! module owns the two syscalls that decision cannot make for itself:
//!
//! * [`WindowsPeerAuthenticator`] — `ImpersonateNamedPipeClient` +
//!   `OpenThreadToken` + `GetTokenInformation(TokenUser)` + `RevertToSelf`,
//!   answering *"who is on the far end of this pipe"*.
//! * [`WindowsPipeFactory`] — SDDL → `SECURITY_ATTRIBUTES` →
//!   `ServerOptions::create_with_security_attributes_raw`, so the pipe carries
//!   an explicit DACL instead of the process default.
//! * [`current_user_sid`] — `OpenProcessToken(GetCurrentProcess())` +
//!   `TokenUser`, which both of the above need and which
//!   `ssk_ipc::paths::default_endpoint` requires so the pipe name can be scoped
//!   per user.
//!
//! # What was actually wrong (roadmap SEC-3)
//!
//! `ssk-ipc/src/auth.rs` used to carry `pub const
//! CLIENT_SID_CHECK_IMPLEMENTED: bool = false` — a constant, not code — and the
//! Windows accept loop performed no peer check at all where its Unix twin
//! called `check_peer_same_user`. The pipe was created with a NULL
//! `SECURITY_ATTRIBUTES`, so MSDN's documented default DACL applied. Measured
//! on the development machine, that default is:
//!
//! ```text
//! O:<user> D:(A;;FR;;;WD)(A;;FR;;;AN)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<user>)
//! ```
//!
//! — `Everyone` (`WD`) and `ANONYMOUS LOGON` (`AN`) hold `FILE_GENERIC_READ`,
//! so a *foreign* user's process could open the pipe, consume a server instance
//! and read responses. That exposure is what the explicit DACL removes.
//!
//! # Why `ImpersonateNamedPipeClient` and not `GetNamedPipeClientProcessId`
//!
//! `GetNamedPipeClientProcessId` exists in windows-sys 0.59 and works, but it
//! answers the wrong question. It yields a PID, and PIDs are recycled: the
//! sequence PID → `OpenProcess` → `OpenProcessToken` → `TokenUser` has a TOCTOU
//! window in which the connecting process can exit and its PID be reused by an
//! unrelated one. It also fails outright on protected processes, which would
//! force a fail-closed refusal of legitimate callers. It answers "who owns *a*
//! process with this PID *now*", not "who is on the far end of this pipe".
//! `ImpersonateNamedPipeClient` asks the kernel for the security context
//! captured at connect time, which is the actual question.
//!
//! # The two fail-open traps
//!
//! Both were established by execution, not by reading MSDN, and both are
//! covered by tests in this module:
//!
//! | Client's `CreateFile` SQOS | `ImpersonateNamedPipeClient` | `OpenThreadToken` |
//! |---|---|---|
//! | `SQOS_PRESENT\|SECURITY_IDENTIFICATION` (tokio's default) | TRUE | SID |
//! | `SQOS_PRESENT\|SECURITY_ANONYMOUS` (hostile) | **TRUE** | **fails** |
//! | no SQOS flags at all (hostile) | FALSE (1368) | — |
//!
//! An anonymous client makes `ImpersonateNamedPipeClient` succeed while
//! `OpenThreadToken` fails. Any implementation that reads the impersonate
//! call's success as "authenticated", or that folds the `OpenThreadToken`
//! failure into a "cannot tell, continue", authenticates a peer that explicitly
//! refused to be identified. **Here, every failure is a rejection; there is no
//! "unknown" return.**
//!
//! # Verification boundary
//!
//! Everything in this module that can be exercised by a single unelevated user
//! on one machine is exercised by the tests below, against the real Win32 API
//! and a real pipe: SID retrieval, same-user acceptance end-to-end through
//! `ssk-ipc`'s decision function, rejection of both hostile SQOS shapes, the
//! post-condition that the worker thread is no longer impersonating, the
//! applied DACL *and* mandatory integrity label read back off the live pipe
//! handle, and the anti-squat guard.
//!
//! Two limits on that last one, stated so a green run is not over-read: the
//! DACL read-back proves the ACEs are on the object, not that the OS would
//! refuse a foreign user (nothing here can create one); and the label read-back
//! proves the label is *present*, not that it would block a below-Medium
//! client (spawning one needs token manipulation this box will not do
//! unelevated).
//!
//! What cannot be tested here is **rejection of a genuinely different OS
//! user**: creating a second user account requires elevation, and this
//! workspace's development machine is a single-user box under a hard
//! no-system-changes rule. That is the same limitation the Unix twin discloses
//! (`ssk-ipc/src/auth.rs`), and it is discharged the same way — by a scripted
//! operator check rather than by an `#[ignore]`d test that would read as
//! coverage: **`crates/ssk-winhost/scripts/verify-pipe-peer-auth.ps1`**, to be
//! run on a disposable VM with two user accounts.

/// Rights mask granted to a *client* on a pipe the daemon owns, in the P3
/// shape where the daemon runs as SYSTEM.
///
/// `0x12019b` is `FILE_GENERIC_READ | FILE_GENERIC_WRITE` (`0x12019f`) **minus
/// `FILE_APPEND_DATA` (0x4)**, which on a named pipe *is*
/// `FILE_CREATE_PIPE_INSTANCE`. Measured on Windows 11: a holder of this mask
/// is refused a second pipe instance with `ERROR_ACCESS_DENIED`, while a client
/// requesting `GENERIC_READ | GENERIC_WRITE` — exactly tokio's `ClientOptions`
/// mask — still connects. So it means precisely "connect fully, never squat".
const CLIENT_RIGHTS_NO_INSTANCE_CREATE: &str = "0x12019b";

/// Mandatory integrity label: no-write-up at Medium.
///
/// A process below Medium integrity (sandboxed browser content, some
/// AppContainer'd code) cannot obtain write access, and this protocol requires
/// the client to write. The label is identical in the P2 and P3 descriptors:
/// you cannot set a label above your own integrity, and a `SI` label would lock
/// out the ordinary Medium-integrity clients the product exists to serve.
///
/// Setting a *mandatory label* does not require `SeSecurityPrivilege` (ordinary
/// SACL access does). Via .NET's `PipeSecurity` this fails with
/// `ERROR_PRIVILEGE_NOT_HELD` because that API requests SACL access; via the
/// raw Win32 path used here it converts and creates fine unelevated. Measured.
const MEDIUM_INTEGRITY_SACL: &str = "S:(ML;;NW;;;ME)";

/// Longest SID string this module will accept. The theoretical maximum for
/// `S-1-<48-bit authority>-<15 x 32-bit subauthorities>` is 184 characters;
/// 191 leaves headroom without admitting anything unbounded.
const MAX_SID_STRING_LEN: usize = 191;

/// SID string of `NT AUTHORITY\SYSTEM` — the principal a P3 broker runs as, and
/// therefore the only acceptable owner of the privileged pipe.
///
/// Well-known and locale-independent, which is the entire reason the comparison
/// is on the SID and never on a display name.
pub const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

/// Upper bound on client ACEs in [`sddl_for_system_owned_pipe`].
///
/// The SDDL string is built by interpolation and handed to the kernel; an
/// unbounded allow-list would make it unbounded. 64 is far above any plausible
/// number of principals allowed to command a machine's kill-switch, and refusing
/// above it keeps the descriptor a fixed-size object rather than an
/// attacker-influenced one.
pub const MAX_CLIENT_ACES: usize = 64;

/// A named pipe cannot have more than 254 instances through tokio, whose
/// `ServerOptions::max_instances` *panics* on 255 or more. We refuse with an
/// `io::Error` instead, because a `PipeFactory` that panics takes the accept
/// loop's whole task with it.
#[cfg(windows)]
const MAX_PIPE_INSTANCES: u32 = 254;

/// Something went wrong establishing or expressing a Windows security
/// principal.
///
/// Deliberately has no "unknown" or "could not determine" variant that a caller
/// might read as permissive: every value here is a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipeSecurityError {
    /// A Win32 call failed. Carries the API name and `GetLastError`.
    Win32 {
        /// The API that failed, spelled as in the SDK.
        api: &'static str,
        /// The value `GetLastError` returned immediately afterwards.
        code: u32,
    },
    /// A SID string did not match the `S-1-...` decimal grammar. Refusing is
    /// load-bearing: the SID is interpolated into an SDDL string, and a SID
    /// carrying `)` or `(` could otherwise inject additional ACEs.
    MalformedSid {
        /// The rejected value, truncated to keep the message bounded.
        sid: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// [`sddl_for_system_owned_pipe`] was given no client SIDs at all. A pipe
    /// that no client can open is a bug, not a lockdown: the service would come
    /// up, report healthy, and be unreachable — including by the operator who
    /// needs to release a kill-switch.
    EmptyClientSet,
    /// More client SIDs than [`MAX_CLIENT_ACES`].
    TooManyClients {
        /// How many were supplied.
        count: usize,
        /// The cap.
        max: usize,
    },
    /// A pipe's owner was not the principal the client demanded.
    ///
    /// This is the client half of mutual authentication: a squatter can create
    /// a pipe with any *name*, but cannot make `NT AUTHORITY\SYSTEM` its owner.
    UnexpectedOwner {
        /// The SID the caller required, e.g. [`LOCAL_SYSTEM_SID`].
        expected: String,
        /// The SID actually read off the live handle, truncated.
        actual: String,
    },
}

impl std::fmt::Display for PipeSecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipeSecurityError::Win32 { api, code } => {
                write!(f, "{api} failed with win32 error {code}")
            }
            PipeSecurityError::MalformedSid { sid, reason } => {
                write!(f, "refusing malformed SID {sid:?}: {reason}")
            }
            PipeSecurityError::EmptyClientSet => write!(
                f,
                "refusing to build a pipe descriptor with no client ACE: a pipe no client can \
                 open is unreachable, not locked down"
            ),
            PipeSecurityError::TooManyClients { count, max } => {
                write!(f, "{count} client SIDs exceeds the maximum of {max}")
            }
            PipeSecurityError::UnexpectedOwner { expected, actual } => write!(
                f,
                "refusing a pipe owned by {actual:?}; this endpoint must be owned by {expected:?}"
            ),
        }
    }
}

impl std::error::Error for PipeSecurityError {}

impl PipeSecurityError {
    /// Machine-readable code, matching the vocabulary `ssk-ipc`'s tests already
    /// assert on (`IPC_OWN_SID_FAILED`, `IPC_PEER_SID_FAILED`).
    fn malformed(sid: &str, reason: &'static str) -> Self {
        let mut shown = sid.to_owned();
        shown.truncate(MAX_SID_STRING_LEN);
        PipeSecurityError::MalformedSid { sid: shown, reason }
    }
}

/// Reject anything that is not a plain decimal SID string.
///
/// Accepts `S-1-<authority>[-<subauthority>]*` with 1..=16 numeric components
/// after the `S-1-` prefix, each 1..=20 ASCII digits. That covers everything
/// `ConvertSidToStringSidW` produces for a user or a well-known principal
/// (`S-1-5-18`, `S-1-5-32-544`, `S-1-5-21-…-1001`).
///
/// The hexadecimal authority form (`S-1-0x…`, emitted only for authorities
/// above 2^32, which no user SID uses) is refused rather than parsed: this
/// function exists to bound what can be spliced into an SDDL string, and the
/// safe answer for a form we never expect is "no".
///
/// # Errors
/// [`PipeSecurityError::MalformedSid`] if `sid` is not of that shape.
pub fn validate_sid_string(sid: &str) -> Result<(), PipeSecurityError> {
    if sid.len() > MAX_SID_STRING_LEN {
        return Err(PipeSecurityError::malformed(
            sid,
            "longer than any real SID",
        ));
    }
    let Some(rest) = sid.strip_prefix("S-1-") else {
        return Err(PipeSecurityError::malformed(sid, "missing 'S-1-' prefix"));
    };
    let parts: Vec<&str> = rest.split('-').collect();
    // 1 identifier authority + at most 15 subauthorities.
    if parts.len() > 16 {
        return Err(PipeSecurityError::malformed(
            sid,
            "more than 15 subauthorities",
        ));
    }
    for part in parts {
        if part.is_empty() {
            return Err(PipeSecurityError::malformed(sid, "empty component"));
        }
        if part.len() > 20 {
            return Err(PipeSecurityError::malformed(sid, "component too long"));
        }
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(PipeSecurityError::malformed(
                sid,
                "component is not decimal digits",
            ));
        }
    }
    Ok(())
}

/// SDDL for the **P2** pipe: the daemon runs unprivileged, as the interactive
/// user, and its clients are that same user.
///
/// ```text
/// D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;<owner>)S:(ML;;NW;;;ME)
/// ```
///
/// * `D:P` — protected, so no inherited ACEs. Pipes do not inherit today; `P`
///   states the intent and survives a future move to a securable namespace.
/// * The owner gets `GA` and **this is unavoidable in P2.** The accept loop
///   needs `FILE_CREATE_PIPE_INSTANCE` for instances 2..N, and in P2 the daemon
///   and the client are the same SID, so no ACE can separate them.
///   `OWNER_RIGHTS (S-1-3-4)` does not help — every process of that user is the
///   owner. Same-user squatting therefore closes only in P3, via
///   [`sddl_for_system_owned_pipe`].
/// * `BA` gets `GA`: an elevated administrator can take ownership regardless,
///   so withholding it buys nothing and costs debuggability.
///
/// What this *removes* relative to the pre-P2 default DACL is the measured
/// `(A;;FR;;;WD)(A;;FR;;;AN)` — `Everyone` and `ANONYMOUS LOGON` lose the read
/// access they held.
///
/// # Errors
/// [`PipeSecurityError::MalformedSid`] if `owner_sid` is not a decimal SID.
pub fn sddl_for_user_owned_pipe(owner_sid: &str) -> Result<String, PipeSecurityError> {
    validate_sid_string(owner_sid)?;
    Ok(format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{owner_sid}){MEDIUM_INTEGRITY_SACL}"
    ))
}

/// SDDL for the **P3** pipe: the broker runs as SYSTEM and every human
/// principal is only a client.
///
/// ```text
/// O:SYD:P(A;;GA;;;SY)(A;;0x12019b;;;<sid₁>)…(A;;0x12019b;;;<sidₙ>)(A;;0x12019b;;;BA)S:(ML;;NW;;;ME)
/// ```
///
/// Same shape as [`sddl_for_user_owned_pipe`], tightened principals, identical
/// SACL, plus an **explicit owner**. What each part is for:
///
/// * `O:SY` — the client half of mutual authentication. The P3 broker needs a
///   *fixed, well-known* pipe name (clients cannot derive SYSTEM's state-dir
///   digest), and a fixed name invites squatting.
///   `FILE_FLAG_FIRST_PIPE_INSTANCE` protects the **server** (P2 proved that);
///   nothing protected the **client**. An unprivileged squatter cannot set
///   `S-1-5-18` as an owner, so [`require_pipe_owner`] turns "the name is right"
///   into "the peer is SYSTEM". Measured on this hardware: an unelevated token
///   cannot even set `BA` as an owner.
///
///   Consequence, stated because it is load-bearing rather than incidental:
///   **a process that is not SYSTEM cannot create a pipe from this descriptor.**
///   `CreateNamedPipeW` fails with `ERROR_INVALID_OWNER`. The descriptor still
///   *converts* unelevated (asserted by a test), so only the create is gated.
/// * Only SYSTEM keeps `GA`, i.e. `FILE_CREATE_PIPE_INSTANCE`. **This is the
///   concrete thing P3's DACL denies and P2's could not**: in P2 the accept loop
///   needed the flag for instances 2..N and daemon and client shared a SID, so
///   no ACE could separate them. See `CLIENT_RIGHTS_NO_INSTANCE_CREATE` in this
///   module's source for the derivation of `0x12019b`.
/// * `BA` gets the client mask, and is deliberately **not** the way an ordinary
///   administrator gets in. Measured on this Windows 11 de-DE box: a DACL
///   granting only `SY` and `BA` **refuses** the machine's sole interactive
///   user, who *is* a member of `Administrators`, because `S-1-5-32-544` is
///   flagged `SE_GROUP_USE_FOR_DENY_ONLY` on a UAC-filtered token. It is kept
///   for debuggability and for the elevated recovery path, and it grants an
///   unelevated administrator nothing — so it is neither the way users get in
///   nor a widening. That refusal is asserted by a test in this module.
///
/// `client_sids` is the explicit allow-list, not "whoever is logged on": the
/// grant is a recorded decision with a subject, and the same list drives the
/// per-request [`ssk_netd_helper::PeerAuthorizer`] decision.
///
/// **The DACL is defense in depth; it is not the authorization decision.** It
/// shrinks the pre-auth attack surface. DACL changes are eventually consistent
/// (they take effect on instances created after a reload) while authorization
/// changes are immediate (the authorizer is re-consulted per request), and that
/// ordering is the safe one.
///
/// **Not exercised in its P3 configuration**, which needs a process running as
/// SYSTEM. What *is* exercised here: the exact string shape, the refusals, that
/// the descriptor converts, and that the `SY`+`BA`-only variant locks this very
/// process out.
///
/// # Errors
/// [`PipeSecurityError::MalformedSid`] for any bad SID;
/// [`PipeSecurityError::EmptyClientSet`] if `client_sids` is empty;
/// [`PipeSecurityError::TooManyClients`] above [`MAX_CLIENT_ACES`].
pub fn sddl_for_system_owned_pipe(client_sids: &[&str]) -> Result<String, PipeSecurityError> {
    if client_sids.is_empty() {
        return Err(PipeSecurityError::EmptyClientSet);
    }
    if client_sids.len() > MAX_CLIENT_ACES {
        return Err(PipeSecurityError::TooManyClients {
            count: client_sids.len(),
            max: MAX_CLIENT_ACES,
        });
    }
    let mask = CLIENT_RIGHTS_NO_INSTANCE_CREATE;
    // Validate every SID *before* emitting any of them, so a refusal never
    // depends on how far the loop got.
    for sid in client_sids {
        validate_sid_string(sid)?;
    }
    let mut sddl = String::from("O:SYD:P(A;;GA;;;SY)");
    for sid in client_sids {
        sddl.push_str("(A;;");
        sddl.push_str(mask);
        sddl.push_str(";;;");
        sddl.push_str(sid);
        sddl.push(')');
    }
    sddl.push_str("(A;;");
    sddl.push_str(mask);
    sddl.push_str(";;;BA)");
    sddl.push_str(MEDIUM_INTEGRITY_SACL);
    Ok(sddl)
}

/// The fallback descriptor used when the allow-list cannot be read.
///
/// ```text
/// O:SYD:P(A;;GA;;;SY)(A;;0x12019b;;;IU)(A;;0x12019b;;;BA)S:(ML;;NW;;;ME)
/// ```
///
/// `IU` (`INTERACTIVE`) was measured to admit an ordinary interactive session on
/// this hardware, where `BA` alone does not. The reason this exists at all, and
/// the reason it is not a security hole, is one decision: when the allow-list is
/// unreadable the pipe must still admit *someone* or a severed machine is not
/// even diagnosable — and the broker behind it then runs in
/// [`ssk_netd_helper::TieredSidAuthorizer::read_only`] mode, refusing every
/// mutating verb. Reachability without authority.
///
/// Never describe this as "the degraded gate". The gate is the
/// [`ssk_netd_helper::PeerAuthorizer`]; this only decides who may knock.
#[must_use]
pub fn sddl_for_read_only_fallback_pipe() -> String {
    let mask = CLIENT_RIGHTS_NO_INSTANCE_CREATE;
    format!("O:SYD:P(A;;GA;;;SY)(A;;{mask};;;IU)(A;;{mask};;;BA){MEDIUM_INTEGRITY_SACL}")
}

#[cfg(windows)]
mod sys {
    //! Thin, named re-exports of the Win32 surface this module uses.
    //!
    //! These come from the **generated** `windows-sys` bindings rather than the
    //! hand-written `#[link]` blocks in [`crate::privilege`]. That is a
    //! deliberate divergence from the neighbouring module, not an oversight:
    //! `windows-sys` is already a dependency, and hand-declaring
    //! `GetTokenInformation`'s five-argument signature a second time is a place
    //! for a silent ABI mistake to live. New FFI in this crate should use
    //! `windows-sys`.

    pub use windows_sys::core::PWSTR;
    pub use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_BAD_IMPERSONATION_LEVEL,
        ERROR_CANNOT_IMPERSONATE, ERROR_CANT_OPEN_ANONYMOUS, HANDLE,
    };
    /// Used only by the tests: the anti-squat refusal code, and the
    /// `debug_assert` that pins `RevertToSelf`'s post-condition.
    #[cfg(test)]
    pub use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_NO_TOKEN};
    pub use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_KERNEL_OBJECT,
    };
    /// The P3 token-facts surface. Each was verified to exist in the vendored
    /// windows-sys 0.59.0 source before being named here:
    ///
    /// * `CheckTokenMembership` (`Security/mod.rs:61`, advapi32) — the
    ///   *rights-now* question. Requires an **impersonation** token, which is
    ///   exactly what `OpenThreadToken` yields inside the impersonation window.
    /// * `CreateWellKnownSid` + `WinBuiltinAdministratorsSid`
    ///   (`Security/mod.rs:69`, `:446`) — build `S-1-5-32-544` from the SDK
    ///   rather than parsing a literal, so no string is trusted.
    /// * `EqualSid` (`:77`) — SID comparison by value.
    /// * `TokenGroups` / `TOKEN_GROUPS` / `SID_AND_ATTRIBUTES` (`:374`,
    ///   `:1071`, `:900`) — the *account* question, read **including**
    ///   `SE_GROUP_USE_FOR_DENY_ONLY` entries.
    /// * `TokenIntegrityLevel` / `TOKEN_MANDATORY_LABEL` (`:379`, `:1096`) plus
    ///   `GetSidSubAuthority`/`GetSidSubAuthorityCount` (`:98`, `:99`) — the
    ///   integrity RID.
    ///
    /// `TokenLinkedToken` is present in the bindings and is **deliberately not
    /// named here**: as SYSTEM it yields a full elevated token for a
    /// UAC-filtered admin, so using it to answer "is the caller an admin?" would
    /// manufacture elevation the caller does not have — a UAC bypass authored by
    /// us. See [`WindowsPeerAuthenticator::authenticate_peer`].
    pub use windows_sys::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, EqualSid, GetSidSubAuthority,
        GetSidSubAuthorityCount, TokenGroups, TokenIntegrityLevel, WinBuiltinAdministratorsSid,
        SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL,
    };
    pub use windows_sys::Win32::Security::{
        GetTokenInformation, RevertToSelf, TokenUser, DACL_SECURITY_INFORMATION,
        LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    };
    pub use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
    pub use windows_sys::Win32::System::SystemServices::{
        SE_GROUP_LOGON_ID, SE_GROUP_USE_FOR_DENY_ONLY,
    };
    pub use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
    };
}

/// Compare a pipe's actual owner against the one a client requires.
///
/// Pure, so the decision is testable without a pipe, without SYSTEM, and
/// without a syscall. The comparison is **exact**: `ConvertSidToStringSidW`
/// only ever emits the canonical uppercase form, so a differing spelling
/// arrives from somewhere else and normalizing it is how two spellings of one
/// principal become two identities.
///
/// # Errors
/// [`PipeSecurityError::MalformedSid`] if `expected` is not a decimal SID (a
/// caller cannot be allowed to demand an owner that is really an ACE), or
/// [`PipeSecurityError::UnexpectedOwner`] if they differ.
pub fn owner_matches(expected: &str, actual: &str) -> Result<(), PipeSecurityError> {
    validate_sid_string(expected)?;
    if expected == actual {
        return Ok(());
    }
    let mut shown = actual.to_owned();
    shown.truncate(MAX_SID_STRING_LEN);
    Err(PipeSecurityError::UnexpectedOwner {
        expected: expected.to_owned(),
        actual: shown,
    })
}

#[cfg(windows)]
pub use win::{
    client_pipe_owner_sid, current_user_sid, describe_pipe_security, require_pipe_owner,
    require_system_owned_pipe, server_pipe_owner_sid, WindowsPeerAuthenticator, WindowsPipeFactory,
};

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::io;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;

    use ssk_ipc::transport_win::{PeerAuthenticator, PipeFactory, Sid};
    use ssk_ipc::IpcError;
    use ssk_netd_helper::{AuthenticatedPeer, PeerIdentity, PeerToken};
    use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};

    use super::{
        owner_matches, sddl_for_user_owned_pipe, sys, validate_sid_string, PipeSecurityError,
        LOCAL_SYSTEM_SID, MAX_PIPE_INSTANCES,
    };

    /// `GetLastError`, read immediately after a failed call.
    fn last_error() -> u32 {
        // SAFETY: `GetLastError` reads the calling thread's last-error slot. It
        // takes no arguments, touches no memory we own, and cannot fail.
        unsafe { sys::GetLastError() }
    }

    fn win32(api: &'static str) -> PipeSecurityError {
        PipeSecurityError::Win32 {
            api,
            code: last_error(),
        }
    }

    /// Owns a token `HANDLE` and closes it exactly once, including on unwind.
    struct TokenHandle(sys::HANDLE);

    impl Drop for TokenHandle {
        fn drop(&mut self) {
            // SAFETY: `self.0` came from a successful `OpenProcessToken` or
            // `OpenThreadToken`. Both of this type's construction sites
            // (`current_user_sid` and `peer_sid`) check the return value and
            // the handle for null first, and this type is neither `Clone` nor
            // `Copy`, so the handle is closed exactly once.
            unsafe {
                sys::CloseHandle(self.0);
            }
        }
    }

    /// Reverts the calling thread's impersonation on every exit path,
    /// **including a panic unwind**.
    ///
    /// This is not stylistic. Impersonation is a property of the *thread*, and
    /// `sskd` runs a work-stealing multi-thread tokio runtime: a thread left
    /// impersonating a pipe client would go on to run unrelated tasks under a
    /// foreign identity. The same fact is why `WindowsPeerAuthenticator::
    /// peer_sid` is synchronous and contains no `.await`.
    struct ImpersonationGuard;

    impl Drop for ImpersonationGuard {
        fn drop(&mut self) {
            // SAFETY: `RevertToSelf` takes no arguments and operates only on the
            // calling thread's token slot. This guard is constructed *only*
            // immediately after a successful `ImpersonateNamedPipeClient` on
            // this same thread, so there is always an impersonation to revert.
            let reverted = unsafe { sys::RevertToSelf() };
            if reverted == 0 {
                let code = last_error();
                // There is no safe way to continue. Returning an error would
                // leave this tokio worker impersonating the peer, and tokio
                // will hand it unrelated tasks — privilege confusion in a
                // security product. `RevertToSelf`'s only real failure mode is
                // "not impersonating", which cannot hold here, and it depends
                // on nothing the client controls, so this is not
                // attacker-triggerable. Fail closed, loudly.
                tracing::error!(
                    target: "ssk.winhost.pipe",
                    win32 = code,
                    "RevertToSelf failed; aborting rather than leaving a worker thread impersonating a pipe client"
                );
                std::process::abort();
            }
        }
    }

    /// Read `TOKEN_USER` off `token` and render its SID as a string.
    ///
    /// The two-call size probe and the **8-byte aligned** buffer live in
    /// [`token_information`], which P3 factored out so the four token classes
    /// this module reads share one implementation of that pattern rather than
    /// four.
    fn token_user_sid(token: sys::HANDLE) -> Result<String, PipeSecurityError> {
        let buffer = token_information(
            token,
            sys::TokenUser,
            "GetTokenInformation(TokenUser)",
            size_of::<sys::TOKEN_USER>(),
        )?;
        // SAFETY: on success the kernel wrote a `TOKEN_USER` at the start of
        // `buffer`, followed by the SID it points at (also inside `buffer`).
        // The reference does not outlive `buffer`.
        let user = unsafe { &*buffer.as_ptr().cast::<sys::TOKEN_USER>() };
        // SAFETY: `user.User.Sid` points into `buffer`, which is still alive,
        // and the kernel guarantees it is a well-formed SID.
        unsafe { sid_to_string(user.User.Sid) }
    }

    /// `ConvertSidToStringSidW`, with the `LocalAlloc`'d result freed on every
    /// path.
    ///
    /// # Safety
    /// `sid` must point at a well-formed, live SID.
    unsafe fn sid_to_string(sid: *mut c_void) -> Result<String, PipeSecurityError> {
        let mut out: sys::PWSTR = ptr::null_mut();
        // SAFETY: caller guarantees `sid`; `out` is a valid out-pointer.
        let ok = unsafe { sys::ConvertSidToStringSidW(sid, &mut out) };
        if ok == 0 || out.is_null() {
            return Err(win32("ConvertSidToStringSidW"));
        }
        // SAFETY: on success `out` is a NUL-terminated UTF-16 string allocated
        // with LocalAlloc. `wide_to_string` only reads up to the terminator.
        let text = unsafe { wide_to_string(out) };
        // SAFETY: `out` came from this call's LocalAlloc and is freed once.
        unsafe {
            sys::LocalFree(out.cast::<c_void>());
        }
        Ok(text)
    }

    /// Copy a NUL-terminated UTF-16 string into a `String`.
    ///
    /// # Safety
    /// `ptr` must be non-null and point at a NUL-terminated UTF-16 sequence.
    unsafe fn wide_to_string(ptr: sys::PWSTR) -> String {
        let mut len = 0usize;
        // SAFETY: caller guarantees a NUL terminator, so this walk is bounded.
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: `len` units before the terminator are all initialized and
        // owned by the allocation the caller passed in.
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        String::from_utf16_lossy(slice)
    }

    /// The SID of the user **this process** runs as, e.g.
    /// `"S-1-5-21-…-1001"`.
    ///
    /// Needed in three places: the daemon's own identity for the peer check,
    /// the owner ACE in the pipe's DACL, and `ssk_ipc::paths::default_endpoint`,
    /// which scopes the pipe name by SID so two users sharing an explicit
    /// `SSK_STATE_DIR` still get distinct pipes.
    ///
    /// Fails closed. A caller that cannot obtain a SID must refuse to compute a
    /// pipe name or a DACL rather than fall back to an unscoped name or a NULL
    /// descriptor — the latter is exactly the pre-P2 state.
    ///
    /// # Errors
    /// [`PipeSecurityError::Win32`] if `OpenProcessToken`,
    /// `GetTokenInformation` or `ConvertSidToStringSidW` fails.
    pub fn current_user_sid() -> Result<String, PipeSecurityError> {
        let mut raw: sys::HANDLE = ptr::null_mut();
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no
        // close and is always valid. `raw` is a valid out-pointer; on failure
        // it is left untouched and we bail without closing anything.
        let opened =
            unsafe { sys::OpenProcessToken(sys::GetCurrentProcess(), sys::TOKEN_QUERY, &mut raw) };
        if opened == 0 || raw.is_null() {
            return Err(win32("OpenProcessToken(GetCurrentProcess)"));
        }
        let token = TokenHandle(raw);
        token_user_sid(token.0)
    }

    /// Real [`PeerAuthenticator`]: answers "who is on the far end of this
    /// pipe" by impersonating the client.
    ///
    /// The daemon's own SID is captured once, at construction, for two reasons.
    /// It is immutable — a process's token user cannot change — so re-reading
    /// it per connection buys nothing. And it turns "we cannot determine our
    /// own identity" into a *startup* failure rather than a per-connection one,
    /// which is the right time to refuse.
    #[derive(Debug, Clone)]
    pub struct WindowsPeerAuthenticator {
        own: String,
    }

    impl WindowsPeerAuthenticator {
        /// Capture this process's SID.
        ///
        /// # Errors
        /// [`PipeSecurityError`] if the SID cannot be read or is not a
        /// well-formed decimal SID string.
        pub fn new() -> Result<Self, PipeSecurityError> {
            let own = current_user_sid()?;
            // The SID came from the kernel, so this cannot fail today. It is
            // asserted anyway because `own` is compared against a peer SID that
            // arrives by the same route: if either ever stops being a plain
            // decimal SID, the comparison's meaning changes and we want to know
            // at startup rather than silently.
            validate_sid_string(&own)?;
            Ok(Self { own })
        }

        /// The SID captured at construction.
        #[must_use]
        pub fn own_sid_str(&self) -> &str {
            &self.own
        }
    }

    /// Map a security-layer failure onto the `ssk-ipc` error vocabulary.
    ///
    /// The three security-meaningful win32 codes are annotated here rather than
    /// in the error type, so the FFI helpers can stay a plain
    /// `PipeSecurityError` and the log line still reads without an SDK lookup.
    fn ipc_err(code: &'static str, err: &PipeSecurityError) -> IpcError {
        let mut message = err.to_string();
        if let PipeSecurityError::Win32 {
            code: win32_code, ..
        } = err
        {
            message.push_str(annotate(*win32_code));
        }
        IpcError::new("Permission", code, message)
    }

    /// Impersonate the pipe's client, run `read` against the resulting
    /// **impersonation token**, and revert on every path.
    ///
    /// This is the single impersonation site in the crate. Everything that
    /// wants a fact about the peer goes through it, for three reasons:
    ///
    /// * the two fail-open traps (see this module's header) are handled once,
    ///   so no caller can accidentally treat "impersonate succeeded" as
    ///   "authenticated";
    /// * every fact about a peer is then read from **one** token in **one**
    ///   window, so the SID and the token's privilege facts cannot describe two
    ///   different moments;
    /// * `read` is synchronous and takes no `&mut`, which is what makes the
    ///   "no `.await` while impersonating" rule mechanical rather than a
    ///   convention — there is nowhere to put an await.
    ///
    /// `read` must not spawn, block, or call back into async code: the calling
    /// thread carries a foreign identity for its whole duration.
    fn impersonate_and<R>(
        server: &NamedPipeServer,
        read: impl FnOnce(sys::HANDLE) -> Result<R, PipeSecurityError>,
    ) -> Result<R, PipeSecurityError> {
        let handle = server.as_raw_handle().cast::<c_void>();

        // SAFETY: `handle` is the live pipe handle owned by `server`, which is
        // borrowed for the whole call, so it cannot be closed underneath us.
        // `ImpersonateNamedPipeClient` only reads it and affects only the
        // calling thread's token slot.
        if unsafe { sys::ImpersonateNamedPipeClient(handle) } == 0 {
            // 1368 ERROR_CANNOT_IMPERSONATE is the *no SQOS flags at all* case
            // (measured). Do not "fix" it by moving this check after the first
            // read: such a client fails pre-read and succeeds post-read, so
            // moving the check would admit exactly the peer that refused to
            // identify itself.
            return Err(win32("ImpersonateNamedPipeClient"));
        }
        // Constructed immediately, before anything that can return or panic, so
        // every path below reverts.
        let _revert = ImpersonationGuard;

        let mut raw: sys::HANDLE = ptr::null_mut();
        // SAFETY: `GetCurrentThread` is a pseudo-handle needing no close.
        // `openasself = 0` (FALSE) is required: we want the *impersonation*
        // token now on this thread, not the process token. `raw` is a valid
        // out-pointer; on failure it is left null and nothing is closed.
        let opened =
            unsafe { sys::OpenThreadToken(sys::GetCurrentThread(), sys::TOKEN_QUERY, 0, &mut raw) };
        if opened == 0 || raw.is_null() {
            // THE FAIL-OPEN TRAP. A client that opened the pipe with
            // SECURITY_ANONYMOUS makes ImpersonateNamedPipeClient return TRUE
            // and lands here instead (measured: win32 1347). This is a
            // REJECTION, never an "unknown" the caller might read as success.
            return Err(win32("OpenThreadToken"));
        }
        let token = TokenHandle(raw);
        read(token.0)
    }

    /// A well-known SID materialized by the SDK, owned as an aligned buffer.
    ///
    /// Built with `CreateWellKnownSid` rather than parsed from the literal
    /// `"S-1-5-32-544"`, so no string in this file is trusted to name a
    /// security principal.
    struct WellKnownSid(Vec<u64>);

    impl WellKnownSid {
        /// `BUILTIN\Administrators` (`S-1-5-32-544`).
        fn builtin_administrators() -> Result<Self, PipeSecurityError> {
            // `SECURITY_MAX_SID_SIZE` is 68 bytes; 9 u64 words (72 bytes) is
            // above it and 8-byte aligned, which a SID's `u32` fields do not
            // require but which costs nothing.
            let mut words: Vec<u64> = vec![0; 9];
            let mut size = u32::try_from(words.len() * size_of::<u64>()).unwrap_or(u32::MAX);
            // SAFETY: `words` is a live, exclusively-borrowed buffer of `size`
            // bytes and `size` is a valid in/out pointer. A null `domainsid` is
            // documented as correct for a SID type that needs no domain, which
            // `WinBuiltinAdministratorsSid` does not. On failure nothing is
            // written and we bail.
            let ok = unsafe {
                sys::CreateWellKnownSid(
                    sys::WinBuiltinAdministratorsSid,
                    ptr::null_mut(),
                    words.as_mut_ptr().cast::<c_void>(),
                    &mut size,
                )
            };
            if ok == 0 {
                return Err(win32("CreateWellKnownSid(WinBuiltinAdministratorsSid)"));
            }
            Ok(WellKnownSid(words))
        }

        /// A `PSID` view. The Win32 signatures take `*mut c_void` even where
        /// they only read, which is why this hands out a mutable pointer to
        /// data it owns immutably for the call's duration.
        fn as_psid(&self) -> *mut c_void {
            self.0.as_ptr().cast::<c_void>().cast_mut()
        }
    }

    /// Fill a `Vec<u64>` with a token information class, using the documented
    /// two-call size probe.
    ///
    /// `Vec<u64>` rather than `Vec<u8>` because every one of these structures
    /// contains a pointer, so a byte vector (alignment 1) would be misaligned
    /// for the cast that follows.
    fn token_information(
        token: sys::HANDLE,
        class: i32,
        api: &'static str,
        minimum: usize,
    ) -> Result<Vec<u64>, PipeSecurityError> {
        let mut needed: u32 = 0;
        // SAFETY: `token` is a live token handle opened with TOKEN_QUERY. A
        // null buffer with length 0 is the documented size-probe form; the call
        // is expected to fail with ERROR_INSUFFICIENT_BUFFER and write the
        // required byte count through `needed`, a valid out-pointer.
        unsafe {
            sys::GetTokenInformation(token, class, ptr::null_mut(), 0, &mut needed);
        }
        if (needed as usize) < minimum {
            return Err(PipeSecurityError::Win32 {
                api,
                code: last_error(),
            });
        }
        let words = (needed as usize).div_ceil(size_of::<u64>());
        let mut buffer: Vec<u64> = vec![0; words];
        // SAFETY: `buffer` holds `words * 8 >= needed` bytes, is 8-byte aligned
        // (at least the alignment of every TOKEN_* structure read here, whose
        // largest field is a pointer), and is exclusively borrowed for the call.
        // `needed` is exactly the size the probe above reported.
        let ok = unsafe {
            sys::GetTokenInformation(
                token,
                class,
                buffer.as_mut_ptr().cast::<c_void>(),
                needed,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(win32(api));
        }
        Ok(buffer)
    }

    /// `CheckTokenMembership(token, S-1-5-32-544)` — the *rights right now*
    /// question.
    ///
    /// Measured **false** on this hardware for an unelevated member of
    /// `Administrators`, because the group is flagged
    /// `SE_GROUP_USE_FOR_DENY_ONLY` on a UAC-filtered token. That is the fact
    /// the whole tiering rests on and the reason it is kept separate from
    /// [`token_account_is_admin`].
    fn token_holds_admin_rights(
        token: sys::HANDLE,
        admins: &WellKnownSid,
    ) -> Result<bool, PipeSecurityError> {
        let mut is_member: i32 = 0;
        // SAFETY: `token` is a live **impersonation** token (which this API
        // requires — a primary token would fail), `admins` owns a well-formed
        // SID that outlives the call, and `is_member` is a valid out-pointer.
        let ok = unsafe { sys::CheckTokenMembership(token, admins.as_psid(), &mut is_member) };
        if ok == 0 {
            return Err(win32("CheckTokenMembership(S-1-5-32-544)"));
        }
        Ok(is_member != 0)
    }

    /// Walk `TokenGroups` once, answering both group questions.
    ///
    /// Returns `(account_is_admin, logon_session_sid)`.
    ///
    /// `account_is_admin` counts `S-1-5-32-544` **including** entries flagged
    /// `SE_GROUP_USE_FOR_DENY_ONLY` — deliberately reading a deny-only SID as
    /// presence-of-the-group, which is the opposite of what the kernel's access
    /// check does with it. That is exactly why this value is recorded as a fact
    /// and is never a gate: it answers "is this account an administrator", not
    /// "may this caller do anything".
    fn token_account_is_admin(
        token: sys::HANDLE,
        admins: &WellKnownSid,
    ) -> Result<(bool, Option<String>), PipeSecurityError> {
        let buffer = token_information(
            token,
            sys::TokenGroups,
            "GetTokenInformation(TokenGroups)",
            size_of::<sys::TOKEN_GROUPS>(),
        )?;
        // SAFETY: on success the kernel wrote a `TOKEN_GROUPS` at the start of
        // `buffer`, followed by `GroupCount` `SID_AND_ATTRIBUTES` entries and
        // the SIDs they point at, all inside `buffer`. The reference does not
        // outlive it.
        let groups = unsafe { &*buffer.as_ptr().cast::<sys::TOKEN_GROUPS>() };
        let count = groups.GroupCount as usize;
        // SAFETY: `Groups` is the documented flexible-array head; the kernel
        // guarantees `count` contiguous entries follow it within the buffer it
        // sized for us.
        let entries = unsafe {
            std::slice::from_raw_parts(
                ptr::addr_of!(groups.Groups).cast::<sys::SID_AND_ATTRIBUTES>(),
                count,
            )
        };

        let mut account_is_admin = false;
        let mut logon: Option<String> = None;
        let deny_only = sys::SE_GROUP_USE_FOR_DENY_ONLY as u32;
        let logon_id = sys::SE_GROUP_LOGON_ID as u32;
        for entry in entries {
            if entry.Sid.is_null() {
                continue;
            }
            // SAFETY: the kernel guarantees each `Sid` points at a well-formed
            // SID inside `buffer`, which is still alive. `EqualSid` only reads.
            if unsafe { sys::EqualSid(entry.Sid, admins.as_psid()) } != 0 {
                // The attribute flags are read for the log line below, never to
                // decide: an ACE for `BA` grants a deny-only holder nothing,
                // but the *account* is still an administrator's.
                account_is_admin = true;
                if entry.Attributes & deny_only != 0 {
                    tracing::debug!(
                        target: "ssk.winhost.pipe",
                        "peer's Administrators group is USE_FOR_DENY_ONLY: an administrator account, not administrative rights"
                    );
                }
            }
            if entry.Attributes & logon_id != 0 && logon.is_none() {
                // SAFETY: same guarantee as above.
                match unsafe { sid_to_string(entry.Sid) } {
                    Ok(sid) => logon = Some(sid),
                    Err(e) => tracing::debug!(
                        target: "ssk.winhost.pipe",
                        error = %e,
                        "peer's logon-session SID could not be rendered; it is audited, never decisive, so authentication continues"
                    ),
                }
            }
        }
        Ok((account_is_admin, logon))
    }

    /// The integrity RID from the token's `S-1-16-…` mandatory label.
    fn token_integrity_rid(token: sys::HANDLE) -> Result<u32, PipeSecurityError> {
        let buffer = token_information(
            token,
            sys::TokenIntegrityLevel,
            "GetTokenInformation(TokenIntegrityLevel)",
            size_of::<sys::TOKEN_MANDATORY_LABEL>(),
        )?;
        // SAFETY: on success the kernel wrote a `TOKEN_MANDATORY_LABEL` at the
        // start of `buffer`, with its `Label.Sid` pointing inside it.
        let label = unsafe { &*buffer.as_ptr().cast::<sys::TOKEN_MANDATORY_LABEL>() };
        let sid = label.Label.Sid;
        if sid.is_null() {
            return Err(PipeSecurityError::Win32 {
                api: "GetTokenInformation(TokenIntegrityLevel) returned a null label SID",
                code: 0,
            });
        }
        // SAFETY: `sid` is a well-formed SID owned by `buffer`, which is alive.
        let count_ptr = unsafe { sys::GetSidSubAuthorityCount(sid) };
        if count_ptr.is_null() {
            return Err(win32("GetSidSubAuthorityCount"));
        }
        // SAFETY: non-null out of `GetSidSubAuthorityCount` points at one byte
        // inside the SID.
        let count = unsafe { *count_ptr };
        if count == 0 {
            return Err(PipeSecurityError::Win32 {
                api: "the integrity label SID carries no sub-authority",
                code: 0,
            });
        }
        // SAFETY: `count - 1` is in range by the check above, which is the
        // documented precondition for `GetSidSubAuthority`; the returned
        // pointer is into the same live SID.
        let rid = unsafe { *sys::GetSidSubAuthority(sid, u32::from(count - 1)) };
        Ok(rid)
    }

    impl WindowsPeerAuthenticator {
        /// Everything the P3 broker needs to know about a peer, read in **one**
        /// impersonation window: its SID and its token's privilege facts.
        ///
        /// This is the accept-time check for the *privileged* pipe. It
        /// establishes **who** the peer is; it makes no authorization decision,
        /// because the verb is not known at accept time — that is
        /// [`ssk_netd_helper::PeerAuthorizer`]'s job, per request.
        ///
        /// It deliberately does **not** compare against our own SID. The broker
        /// runs as SYSTEM and no legitimate client shares that SID, so
        /// `check_peer_same_user` here would accept only SYSTEM callers and
        /// reject every real user. Same-user is not merely wrong on this pipe —
        /// it is inverted. `check_peer_same_user` is kept, unchanged, for the
        /// unprivileged `sskd` pipe, which stays same-user.
        ///
        /// Every failure is a refusal. There is no
        /// [`ssk_netd_helper::PeerToken::unprivileged`] fallback here: all-false
        /// would silently downgrade a legitimate administrator out of the
        /// elevation tier — a denial of *recovery* — and any true would
        /// fabricate privilege.
        ///
        /// **`TokenLinkedToken` is not used and must not be.** It succeeds even
        /// from an unelevated process (measured), and from SYSTEM — which holds
        /// `SeTcbPrivilege` — it yields the *full elevated* token behind a
        /// UAC-filtered admin. Using it to answer "is the caller an admin?"
        /// would mean this broker manufactures elevation the caller does not
        /// have.
        ///
        /// # Errors
        /// [`PipeSecurityError`] if impersonation, any token read, or SID
        /// validation fails.
        pub fn authenticate_peer(
            &self,
            server: &NamedPipeServer,
        ) -> Result<AuthenticatedPeer, PipeSecurityError> {
            let admins = WellKnownSid::builtin_administrators()?;
            let (sid, token) = impersonate_and(server, |token| {
                let sid = token_user_sid(token)?;
                validate_sid_string(&sid)?;
                let elevated_admin = token_holds_admin_rights(token, &admins)?;
                let (admin_account_filtered, logon) = token_account_is_admin(token, &admins)?;
                let integrity_rid = token_integrity_rid(token)?;
                Ok((
                    sid,
                    PeerToken {
                        elevated_admin,
                        admin_account_filtered,
                        integrity_rid,
                        logon_session: logon
                            .as_deref()
                            .and_then(|s| PeerIdentity::parse_sid(s).ok()),
                    },
                ))
            })?;
            let identity = PeerIdentity::parse_sid(&sid).map_err(|_| {
                PipeSecurityError::malformed(&sid, "not a canonical SID for an allow-list key")
            })?;
            Ok(AuthenticatedPeer::new(identity, token))
        }
    }

    impl PeerAuthenticator for WindowsPeerAuthenticator {
        fn own_sid(&self) -> Result<Sid, IpcError> {
            Ok(Sid(self.own.clone()))
        }

        fn peer_sid(&self, server: &NamedPipeServer) -> Result<Sid, IpcError> {
            // No `.await` between impersonate and revert — see
            // `ImpersonationGuard`. Everything inside the closure is
            // synchronous.
            let sid = impersonate_and(server, |token| {
                let sid = token_user_sid(token)?;
                validate_sid_string(&sid)?;
                Ok(sid)
            })
            .map_err(|e| ipc_err("IPC_PEER_SID_FAILED", &e))?;
            Ok(Sid(sid))
        }
    }

    /// Read the owner SID off a live kernel handle.
    ///
    /// `0x12019b` — the client mask on the P3 pipe — contains `READ_CONTROL`
    /// (`0x120000` is `READ_CONTROL | SYNCHRONIZE`; `0x19b` is the six
    /// data/EA/attribute bits and excludes `FILE_APPEND_DATA` `0x4`), so **the
    /// same mask that denies instance creation permits this owner check**. The
    /// two design elements compose by arithmetic, and the readback was verified
    /// experimentally on this hardware from a client holding only
    /// `GENERIC_READ | GENERIC_WRITE`.
    fn handle_owner_sid(handle: *mut c_void) -> Result<String, PipeSecurityError> {
        let mut owner: *mut c_void = ptr::null_mut();
        let mut descriptor: sys::PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `handle` is a live kernel handle borrowed for the call.
        // `owner` receives a pointer *into* `descriptor`, which the API
        // allocates and which we take ownership of below; the remaining
        // out-parameters are null because we want none of them, which is the
        // documented way to decline them.
        let status = unsafe {
            sys::GetSecurityInfo(
                handle,
                sys::SE_KERNEL_OBJECT,
                sys::OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 || descriptor.is_null() {
            return Err(PipeSecurityError::Win32 {
                api: "GetSecurityInfo(OWNER_SECURITY_INFORMATION)",
                code: status,
            });
        }
        // Bound immediately so the descriptor is freed on every path below.
        let owned = SecurityDescriptor(descriptor);
        if owner.is_null() {
            return Err(PipeSecurityError::Win32 {
                api: "GetSecurityInfo returned a descriptor with no owner",
                code: 0,
            });
        }
        // SAFETY: `owner` points at a well-formed SID inside `owned`, which is
        // still alive at this point; the string is copied out before the free.
        let sid = unsafe { sid_to_string(owner) };
        drop(owned);
        sid
    }

    /// The owner SID of the pipe a **client** handle is connected to.
    ///
    /// # Errors
    /// [`PipeSecurityError::Win32`] if the descriptor cannot be read.
    pub fn client_pipe_owner_sid(client: &NamedPipeClient) -> Result<String, PipeSecurityError> {
        handle_owner_sid(client.as_raw_handle().cast::<c_void>())
    }

    /// The owner SID of a pipe **server** instance. Test and diagnostic use —
    /// it is what makes the client-side check falsifiable without SYSTEM.
    ///
    /// # Errors
    /// [`PipeSecurityError::Win32`] if the descriptor cannot be read.
    pub fn server_pipe_owner_sid(server: &NamedPipeServer) -> Result<String, PipeSecurityError> {
        handle_owner_sid(server.as_raw_handle().cast::<c_void>())
    }

    /// Refuse to speak to a pipe that is not owned by `expected_sid`.
    ///
    /// **Call this before the first frame is written.** It is the client half of
    /// mutual authentication and it is not optional: the privileged pipe has a
    /// fixed, well-known name, so an unprivileged process can create it at boot
    /// ahead of the SCM. `FILE_FLAG_FIRST_PIPE_INSTANCE` then makes *our* bind
    /// fail closed — a visible denial of service, and the correct failure — but
    /// nothing stops a client from talking to the squatter and being fed a
    /// forged `Ok(Status)` claiming `Engaged` while egress flows. This check is
    /// the only thing that prevents that, because a squatter cannot set
    /// `S-1-5-18` as an owner.
    ///
    /// # Errors
    /// [`PipeSecurityError::UnexpectedOwner`] if the owner differs, or
    /// [`PipeSecurityError::Win32`] if it cannot be read at all — which is also
    /// a refusal, never a "cannot tell, continue".
    pub fn require_pipe_owner(
        client: &NamedPipeClient,
        expected_sid: &str,
    ) -> Result<(), PipeSecurityError> {
        let actual = client_pipe_owner_sid(client)?;
        owner_matches(expected_sid, &actual)
    }

    /// [`require_pipe_owner`] against `NT AUTHORITY\SYSTEM`, which is the only
    /// principal a P3 broker ever runs as.
    ///
    /// # Errors
    /// As [`require_pipe_owner`].
    pub fn require_system_owned_pipe(client: &NamedPipeClient) -> Result<(), PipeSecurityError> {
        require_pipe_owner(client, LOCAL_SYSTEM_SID)
    }

    /// Name the three error codes that carry security meaning, so a log line
    /// is readable without an SDK lookup. Any other code renders bare.
    ///
    /// Note the correction: **1347 is `ERROR_CANT_OPEN_ANONYMOUS`**, not
    /// `ERROR_BAD_IMPERSONATION_LEVEL` (which is 1346). The design document
    /// this module implements measured the number 1347 correctly and labelled
    /// it with the wrong constant name; windows-sys 0.59
    /// (`Win32/Foundation/mod.rs:1140`) settles it. Both are handled, and
    /// neither gates anything — *every* `OpenThreadToken` failure is a
    /// rejection.
    fn annotate(code: u32) -> &'static str {
        if code == sys::ERROR_CANNOT_IMPERSONATE {
            " (ERROR_CANNOT_IMPERSONATE — the client opened the pipe with no security-QoS flags)"
        } else if code == sys::ERROR_CANT_OPEN_ANONYMOUS {
            " (ERROR_CANT_OPEN_ANONYMOUS — the client opened the pipe at SECURITY_ANONYMOUS)"
        } else if code == sys::ERROR_BAD_IMPERSONATION_LEVEL {
            " (ERROR_BAD_IMPERSONATION_LEVEL)"
        } else {
            ""
        }
    }

    /// A `LocalAlloc`'d `SECURITY_DESCRIPTOR`, freed on every path.
    struct SecurityDescriptor(sys::PSECURITY_DESCRIPTOR);

    impl SecurityDescriptor {
        fn from_sddl(sddl: &str) -> Result<Self, PipeSecurityError> {
            let wide: Vec<u16> = std::ffi::OsStr::new(sddl)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let mut descriptor: sys::PSECURITY_DESCRIPTOR = ptr::null_mut();
            // SAFETY: `wide` is a NUL-terminated UTF-16 buffer alive for the
            // call; `descriptor` is a valid out-pointer; passing null for the
            // size out-parameter is documented as "not interested".
            let ok = unsafe {
                sys::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    sys::SDDL_REVISION_1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            };
            if ok == 0 || descriptor.is_null() {
                return Err(win32(
                    "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                ));
            }
            Ok(Self(descriptor))
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: `self.0` was allocated with LocalAlloc — by
            // `ConvertStringSecurityDescriptorToSecurityDescriptorW` in
            // `from_sddl`, or by `GetSecurityInfo` in
            // `describe_pipe_security`; both document LocalFree as the
            // deallocator. It is non-null (checked at every construction site)
            // and this type is not `Clone`, so it is freed exactly once.
            // `CreateNamedPipeW` copies the descriptor into the kernel object,
            // so freeing after creation is correct.
            unsafe {
                sys::LocalFree(self.0.cast::<c_void>());
            }
        }
    }

    /// Real [`PipeFactory`]: creates each pipe instance carrying an explicit
    /// DACL built from SDDL.
    ///
    /// Holds only the SDDL *string*. The descriptor is converted per instance
    /// and freed immediately after `CreateNamedPipeW` returns (the kernel
    /// copies it), so no raw pointer is stored in a `Send + Sync` type and
    /// there is no lifetime to reason about across threads.
    #[derive(Debug, Clone)]
    pub struct WindowsPipeFactory {
        sddl: String,
    }

    impl WindowsPipeFactory {
        /// The P2 factory: a pipe owned by, and reachable only by, the user
        /// this process runs as.
        ///
        /// # Errors
        /// [`PipeSecurityError`] if this process's SID cannot be determined.
        /// **Never falls back to a NULL descriptor** — that is the SEC-3 state.
        pub fn for_current_user() -> Result<Self, PipeSecurityError> {
            let sid = current_user_sid()?;
            Self::from_sddl(sddl_for_user_owned_pipe(&sid)?)
        }

        /// A factory over an explicit SDDL string, for the P3 shape
        /// ([`super::sddl_for_system_owned_pipe`]) and for tests.
        ///
        /// The SDDL is converted once here so an invalid descriptor is a
        /// construction error rather than a per-connection surprise.
        ///
        /// # Errors
        /// [`PipeSecurityError::Win32`] if the SDDL does not convert.
        pub fn from_sddl(sddl: String) -> Result<Self, PipeSecurityError> {
            // Convert-and-discard: proves the string is well formed now,
            // instead of at the first connection attempt.
            drop(SecurityDescriptor::from_sddl(&sddl)?);
            Ok(Self { sddl })
        }

        /// The SDDL every instance from this factory carries.
        #[must_use]
        pub fn sddl(&self) -> &str {
            &self.sddl
        }
    }

    impl PipeFactory for WindowsPipeFactory {
        fn create_instance(
            &self,
            pipe_name: &str,
            first_instance: bool,
            max_instances: u32,
        ) -> io::Result<NamedPipeServer> {
            if max_instances == 0 || max_instances > MAX_PIPE_INSTANCES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "max_instances must be 1..={MAX_PIPE_INSTANCES}, got {max_instances}; \
                         tokio's ServerOptions::max_instances panics at 255 and a panicking \
                         PipeFactory would take the accept loop's task with it"
                    ),
                ));
            }
            let descriptor = SecurityDescriptor::from_sddl(&self.sddl)
                .map_err(|e| io::Error::other(e.to_string()))?;

            let mut attrs = sys::SECURITY_ATTRIBUTES {
                nLength: u32::try_from(size_of::<sys::SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
                lpSecurityDescriptor: descriptor.0,
                // The pipe handle must not leak into child processes.
                bInheritHandle: 0,
            };

            let mut options = ServerOptions::new();
            options
                // Anti-squat guard. True for the first instance only: if
                // another process already owns this name the create fails with
                // ERROR_ACCESS_DENIED and `ssk-ipc` refuses to start.
                .first_pipe_instance(first_instance)
                // Already tokio's default (`ServerOptions::new`), so this is
                // not a fix and must not be reported as one. It is stated
                // explicitly so a future change to that default cannot
                // silently start accepting `\\host\pipe\…` clients.
                .reject_remote_clients(true);
            options.max_instances(max_instances as usize);

            // SAFETY: `attrs` is a fully initialized `SECURITY_ATTRIBUTES`
            // whose `lpSecurityDescriptor` points at a live descriptor owned by
            // `descriptor`, which outlives this call. `CreateNamedPipeW` copies
            // the descriptor into the new kernel object, so dropping
            // `descriptor` afterwards (which `LocalFree`s it) is correct on
            // both the success and the error path.
            let created = unsafe {
                options.create_with_security_attributes_raw(
                    pipe_name,
                    ptr::addr_of_mut!(attrs).cast::<c_void>(),
                )
            };
            drop(descriptor);
            created
        }
    }

    /// Read the DACL (and owner) actually attached to a live pipe handle, as
    /// SDDL.
    ///
    /// Exists so a test can assert the descriptor the kernel holds rather than
    /// the string we intended to pass. Public because that assertion is the
    /// only evidence that [`WindowsPipeFactory`] does anything at all, and an
    /// operator script and P3 will both want it.
    ///
    /// `LABEL_SECURITY_INFORMATION` **is** requested: the mandatory integrity
    /// label is exempt from `SeSecurityPrivilege` (ordinary SACL access is
    /// not), so an unelevated process can read it back. That establishes the
    /// label is *present on the object* — never that it is
    /// *enforcement-verified*, which would need a below-Medium-integrity client
    /// this workspace cannot spawn unelevated.
    ///
    /// # Errors
    /// [`PipeSecurityError::Win32`] if the descriptor cannot be read or
    /// rendered.
    pub fn describe_pipe_security(server: &NamedPipeServer) -> Result<String, PipeSecurityError> {
        let handle = server.as_raw_handle().cast::<c_void>();
        let info = sys::OWNER_SECURITY_INFORMATION
            | sys::DACL_SECURITY_INFORMATION
            | sys::LABEL_SECURITY_INFORMATION;

        let mut descriptor: sys::PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `handle` is the live pipe handle owned by `server`, borrowed
        // for the call. All the SID/ACL out-parameters are null because we only
        // want the self-relative descriptor, which is the documented way to ask
        // for it; `descriptor` is a valid out-pointer.
        let status = unsafe {
            sys::GetSecurityInfo(
                handle,
                sys::SE_KERNEL_OBJECT,
                info,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 || descriptor.is_null() {
            return Err(PipeSecurityError::Win32 {
                api: "GetSecurityInfo",
                code: status,
            });
        }
        let owned = SecurityDescriptor(descriptor);

        let mut out: sys::PWSTR = ptr::null_mut();
        // SAFETY: `owned.0` is the live descriptor just returned; `out` is a
        // valid out-pointer; a null length out-parameter is documented as "not
        // interested".
        let ok = unsafe {
            sys::ConvertSecurityDescriptorToStringSecurityDescriptorW(
                owned.0,
                sys::SDDL_REVISION_1,
                info,
                &mut out,
                ptr::null_mut(),
            )
        };
        if ok == 0 || out.is_null() {
            return Err(win32(
                "ConvertSecurityDescriptorToStringSecurityDescriptorW",
            ));
        }
        // SAFETY: on success `out` is a NUL-terminated UTF-16 LocalAlloc'd
        // string.
        let text = unsafe { wide_to_string(out) };
        // SAFETY: freed exactly once, immediately after the copy.
        unsafe {
            sys::LocalFree(out.cast::<c_void>());
        }
        Ok(text)
    }

    /// Whether the calling thread currently carries an impersonation token.
    ///
    /// The post-condition [`ImpersonationGuard`] must establish:
    /// `OpenThreadToken` on a non-impersonating thread fails with
    /// `ERROR_NO_TOKEN` (1008). Used by the tests to prove the revert actually
    /// happened rather than trusting that `Drop` ran.
    ///
    /// Test-only: it is a measuring instrument, not product API, and compiling
    /// it into the shipped library would be dead code.
    #[cfg(test)]
    pub(super) fn thread_is_impersonating() -> bool {
        let mut raw: sys::HANDLE = ptr::null_mut();
        // SAFETY: pseudo-handle, valid out-pointer; on failure `raw` stays null.
        let opened =
            unsafe { sys::OpenThreadToken(sys::GetCurrentThread(), sys::TOKEN_QUERY, 0, &mut raw) };
        if opened == 0 || raw.is_null() {
            debug_assert_eq!(
                last_error(),
                sys::ERROR_NO_TOKEN,
                "a non-impersonating thread must report ERROR_NO_TOKEN"
            );
            return false;
        }
        drop(TokenHandle(raw));
        true
    }

    /// `ERROR_ACCESS_DENIED` in the `i32` form `io::Error::raw_os_error`
    /// returns, for the test that asserts the anti-squat refusal.
    #[cfg(test)]
    pub(super) const ACCESS_DENIED: i32 = sys::ERROR_ACCESS_DENIED as i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID_A: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";

    #[test]
    fn p2_sddl_has_the_documented_shape() {
        let sddl = sddl_for_user_owned_pipe(SID_A).expect("valid sid");
        assert_eq!(
            sddl,
            format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{SID_A})S:(ML;;NW;;;ME)")
        );
    }

    #[test]
    fn p3_sddl_denies_instance_creation_to_everyone_but_system() {
        let sddl = sddl_for_system_owned_pipe(&[SID_A]).expect("valid sid");
        assert_eq!(
            sddl,
            format!("O:SYD:P(A;;GA;;;SY)(A;;0x12019b;;;{SID_A})(A;;0x12019b;;;BA)S:(ML;;NW;;;ME)")
        );
        // Only SYSTEM keeps GA, i.e. FILE_CREATE_PIPE_INSTANCE.
        assert_eq!(sddl.matches("GA").count(), 1);
        // And the owner is stated explicitly, which is what a client can check.
        assert!(sddl.starts_with("O:SY"), "{sddl}");
    }

    /// The allow-list is N principals, not one. Every ACE must appear, in the
    /// order given, each with the client mask — and `SY`/`BA` must still bracket
    /// them exactly once.
    #[test]
    fn p3_sddl_emits_one_client_ace_per_allow_listed_sid() {
        const SID_B: &str = "S-1-5-21-1111111111-2222222222-3333333333-1002";
        const SID_C: &str = "S-1-5-21-4444444444-5555555555-6666666666-500";
        let sddl = sddl_for_system_owned_pipe(&[SID_A, SID_B, SID_C]).expect("valid sids");
        assert_eq!(
            sddl,
            format!(
                "O:SYD:P(A;;GA;;;SY)(A;;0x12019b;;;{SID_A})(A;;0x12019b;;;{SID_B})\
                 (A;;0x12019b;;;{SID_C})(A;;0x12019b;;;BA)S:(ML;;NW;;;ME)"
            )
        );
        assert_eq!(sddl.matches("(A;;").count(), 5, "{sddl}");
        assert_eq!(sddl.matches("GA").count(), 1, "{sddl}");
    }

    /// A pipe with no client ACE is unreachable, not locked down — including by
    /// the operator who needs to release a kill-switch. Refuse to build it.
    #[test]
    fn p3_sddl_refuses_an_empty_allow_list() {
        assert_eq!(
            sddl_for_system_owned_pipe(&[]),
            Err(PipeSecurityError::EmptyClientSet)
        );
    }

    #[test]
    fn p3_sddl_refuses_more_clients_than_the_cap() {
        let sids: Vec<String> = (0..=MAX_CLIENT_ACES)
            .map(|n| format!("S-1-5-21-1-2-3-{}", 1000 + n))
            .collect();
        let refs: Vec<&str> = sids.iter().map(String::as_str).collect();
        assert_eq!(
            sddl_for_system_owned_pipe(&refs),
            Err(PipeSecurityError::TooManyClients {
                count: MAX_CLIENT_ACES + 1,
                max: MAX_CLIENT_ACES,
            })
        );
        // The cap itself must still be buildable, or the boundary is off by one.
        assert!(sddl_for_system_owned_pipe(&refs[..MAX_CLIENT_ACES]).is_ok());
    }

    /// The SDDL is built by interpolation, so the SID is untrusted input the
    /// moment it comes from anywhere but the kernel. A SID carrying `)` and `(`
    /// would append arbitrary ACEs — e.g. granting `GA` to `WD` (Everyone),
    /// which is strictly worse than the default DACL P2 exists to replace.
    ///
    /// The slice form widens the surface: a hostile SID **anywhere** in the
    /// allow-list must refuse the whole descriptor, and must do so before any
    /// well-formed prefix is emitted.
    #[test]
    fn a_sid_that_would_inject_an_ace_is_refused() {
        let hostile = "S-1-5-21-1)(A;;GA;;;WD";
        assert!(validate_sid_string(hostile).is_err());
        assert!(sddl_for_user_owned_pipe(hostile).is_err());
        assert!(sddl_for_system_owned_pipe(&[hostile]).is_err());
        assert!(sddl_for_system_owned_pipe(&[SID_A, hostile]).is_err());
        assert!(sddl_for_system_owned_pipe(&[hostile, SID_A]).is_err());
    }

    /// The degraded descriptor: reachable, and reachable by `IU` specifically —
    /// because `BA` alone was measured **not** to admit this machine's only
    /// interactive user.
    #[test]
    fn the_read_only_fallback_admits_interactive_and_keeps_the_system_owner() {
        let sddl = sddl_for_read_only_fallback_pipe();
        assert_eq!(
            sddl,
            "O:SYD:P(A;;GA;;;SY)(A;;0x12019b;;;IU)(A;;0x12019b;;;BA)S:(ML;;NW;;;ME)"
        );
        assert!(sddl.contains(";;;IU)"), "{sddl}");
        assert_eq!(sddl.matches("GA").count(), 1, "{sddl}");
    }

    #[test]
    fn an_owner_that_is_not_the_expected_principal_is_refused() {
        assert_eq!(owner_matches(LOCAL_SYSTEM_SID, LOCAL_SYSTEM_SID), Ok(()));
        let err =
            owner_matches(LOCAL_SYSTEM_SID, SID_A).expect_err("a user-owned pipe is not ours");
        assert_eq!(
            err,
            PipeSecurityError::UnexpectedOwner {
                expected: LOCAL_SYSTEM_SID.to_owned(),
                actual: SID_A.to_owned(),
            }
        );
        // `S-1-5-32-544` is the near miss that matters: an elevated squatter is
        // still not SYSTEM.
        assert!(owner_matches(LOCAL_SYSTEM_SID, "S-1-5-32-544").is_err());
        // A caller may not demand an "owner" that is really an ACE fragment.
        assert!(owner_matches("SY", LOCAL_SYSTEM_SID).is_err());
        assert!(owner_matches("S-1-5-18)(A;;GA;;;WD", LOCAL_SYSTEM_SID).is_err());
    }

    #[test]
    fn an_unexpected_owner_message_stays_bounded() {
        let huge = "S-1-5-".to_owned() + &"9".repeat(4096);
        let err = owner_matches(LOCAL_SYSTEM_SID, &huge).expect_err("must refuse");
        assert!(err.to_string().len() < 300, "message must stay bounded");
    }

    #[test]
    fn sid_grammar_accepts_real_sids_and_refuses_the_rest() {
        for good in ["S-1-5-18", "S-1-5-32-544", "S-1-1-0", SID_A, "S-1-16-8192"] {
            validate_sid_string(good).unwrap_or_else(|e| panic!("{good} must be accepted: {e}"));
        }
        for bad in [
            "",
            "S-1-",
            "S-1--5",
            "s-1-5-18",
            "S-2-5-18",
            "S-1-0x206-1",
            "S-1-5-18 ",
            "BA",
            "S-1-5-18;S:(ML;;NW;;;LW)",
            "S-1-5-99999999999999999999999",
        ] {
            assert!(validate_sid_string(bad).is_err(), "{bad:?} must be refused");
        }
        // 16 components after `S-1-` is the ceiling (authority + 15 sub).
        let too_many = format!("S-1-5{}", "-1".repeat(16));
        assert!(validate_sid_string(&too_many).is_err());
    }

    #[test]
    fn refusal_messages_never_echo_an_unbounded_sid() {
        let huge = "S-1-5-".to_owned() + &"9".repeat(4096);
        let err = validate_sid_string(&huge).expect_err("must refuse");
        assert!(err.to_string().len() < 300, "message must stay bounded");
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::win::thread_is_impersonating;
    use super::*;
    use ssk_ipc::transport_win::{check_peer_same_user, PeerAuthenticator, PipeFactory};
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::net::windows::named_pipe::ClientOptions;

    /// `SECURITY_ANONYMOUS`. tokio's `security_qos_flags` always ORs
    /// `SECURITY_SQOS_PRESENT`, so passing 0 yields the hostile
    /// `SQOS_PRESENT | SECURITY_ANONYMOUS` shape exactly.
    const SECURITY_ANONYMOUS: u32 = 0;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// A pipe name unique to this process *and* this test, so the whole file
    /// runs in parallel and leaves nothing behind.
    fn unique_pipe_name(tag: &str) -> String {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(
            r"\\.\pipe\ssk-winhost-test-{}-{tag}-{n}",
            std::process::id()
        )
    }

    fn factory() -> WindowsPipeFactory {
        WindowsPipeFactory::for_current_user().expect("build a P2 factory for the current user")
    }

    #[test]
    fn the_process_sid_is_a_well_formed_sid() {
        let sid = current_user_sid().expect("this process must know its own SID");
        validate_sid_string(&sid).expect("kernel-produced SID must satisfy our grammar");
        assert!(sid.starts_with("S-1-"), "unexpected SID shape: {sid}");
    }

    #[test]
    fn the_authenticator_reports_the_process_sid() {
        let auth = WindowsPeerAuthenticator::new().expect("construct");
        let sid = auth.own_sid().expect("own sid");
        assert_eq!(sid.0, current_user_sid().expect("sid"));
        assert_eq!(auth.own_sid_str(), sid.0);
    }

    /// The end-to-end acceptance proof: a real pipe with the real DACL, a real
    /// client, the real FFI, and `ssk-ipc`'s real decision function.
    #[tokio::test]
    async fn a_same_user_client_is_accepted_end_to_end() {
        let name = unique_pipe_name("accept");
        let pipes = factory();
        let auth = WindowsPeerAuthenticator::new().expect("construct");

        let server = pipes.create_instance(&name, true, 4).expect("create");
        let client = ClientOptions::new().open(&name).expect("client connects");
        server.connect().await.expect("accept");

        let sid = check_peer_same_user(&auth, &server).expect("same-user peer must be accepted");
        assert_eq!(sid.0, auth.own_sid_str());
        assert!(
            !thread_is_impersonating(),
            "impersonation must be reverted before the check returns"
        );
        drop(client);
    }

    /// Impersonation is valid **before any byte is read** — the client below
    /// writes nothing. That is what lets the accept loop authenticate before
    /// the framing layer allocates anything for an unauthenticated peer.
    #[tokio::test]
    async fn the_peer_sid_is_readable_before_the_client_writes_anything() {
        let name = unique_pipe_name("pre-read");
        let auth = WindowsPeerAuthenticator::new().expect("construct");
        let server = factory().create_instance(&name, true, 4).expect("create");
        let client = ClientOptions::new().open(&name).expect("client connects");
        server.connect().await.expect("accept");

        let sid = auth.peer_sid(&server).expect("peer sid pre-read");
        assert_eq!(sid.0, auth.own_sid_str());
        drop(client);
    }

    /// FAIL-OPEN TRAP #1, against the real FFI. `ImpersonateNamedPipeClient`
    /// **succeeds** for a `SECURITY_ANONYMOUS` client; `OpenThreadToken` is
    /// what fails. An implementation that stopped at the first call would
    /// authenticate a peer that refused to be identified.
    #[tokio::test]
    async fn an_anonymous_client_is_rejected() {
        let name = unique_pipe_name("anonymous");
        let auth = WindowsPeerAuthenticator::new().expect("construct");
        let server = factory().create_instance(&name, true, 4).expect("create");
        let client = ClientOptions::new()
            .security_qos_flags(SECURITY_ANONYMOUS)
            .open(&name)
            .expect("anonymous client connects");
        server.connect().await.expect("accept");

        let err = auth
            .peer_sid(&server)
            .expect_err("an anonymous peer must be refused, not treated as unknown");
        assert_eq!(err.code, "IPC_PEER_SID_FAILED");
        assert_eq!(err.class, "Permission");
        assert!(
            err.message.contains("OpenThreadToken"),
            "the anonymous case must fail at OpenThreadToken, not at impersonation: {}",
            err.message
        );
        // Measured on Windows 11 26200 (de-DE): win32 1347. Note the naming
        // correction recorded on `annotate` — 1347 is ERROR_CANT_OPEN_ANONYMOUS,
        // not ERROR_BAD_IMPERSONATION_LEVEL (1346). The rejection does not
        // depend on the code; this pins what was actually observed.
        assert!(
            err.message.contains("win32 error 1347"),
            "expected the measured code: {}",
            err.message
        );
        assert!(
            !thread_is_impersonating(),
            "the guard must revert even on the rejection path"
        );
        // And the decision function must agree.
        let err = check_peer_same_user(&auth, &server).expect_err("decision must refuse too");
        assert_eq!(err.code, "IPC_PEER_SID_FAILED");
        drop(client);
    }

    /// FAIL-OPEN TRAP #2. A client that passes **no** security-QoS flags makes
    /// `ImpersonateNamedPipeClient` itself fail. `std::fs::OpenOptions` sets no
    /// SQOS flags unless asked, so it is exactly that client; tokio's
    /// `ClientOptions` cannot express this shape because it always ORs
    /// `SECURITY_SQOS_PRESENT`.
    #[tokio::test]
    async fn a_client_with_no_security_qos_is_rejected() {
        let name = unique_pipe_name("no-sqos");
        let auth = WindowsPeerAuthenticator::new().expect("construct");
        let server = factory().create_instance(&name, true, 4).expect("create");

        let open_name = name.clone();
        let opener = std::thread::spawn(move || {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&open_name)
        });
        server.connect().await.expect("accept");
        let handle = opener.join().expect("opener thread").expect("client opens");

        let err = auth
            .peer_sid(&server)
            .expect_err("a peer with no SQOS must be refused");
        assert_eq!(err.code, "IPC_PEER_SID_FAILED");
        assert!(
            err.message.contains("ImpersonateNamedPipeClient"),
            "this case must fail at impersonation itself: {}",
            err.message
        );
        // Measured: win32 1368 ERROR_CANNOT_IMPERSONATE.
        assert!(
            err.message.contains("win32 error 1368"),
            "expected the measured code: {}",
            err.message
        );
        assert!(!thread_is_impersonating());
        drop(handle);
    }

    /// The DACL read back off the **live kernel object**, not the string we
    /// meant to pass. This is the only evidence the factory does anything.
    ///
    /// Note the round-trip is not the identity, and the measurement is what
    /// established it: the SDDL we *write* says `GA` (`GENERIC_ALL`), the SDDL
    /// that comes *back* says `FA` (`FILE_ALL_ACCESS`, 0x1F01FF). Generic
    /// rights are resolved through the object type's generic mapping when the
    /// ACE is applied, so no `GA` survives in a kernel object's DACL. Asserting
    /// `GA` here would be asserting the string we sent, not the protection the
    /// kernel actually holds.
    #[tokio::test]
    async fn the_pipe_carries_the_explicit_dacl_and_not_the_default() {
        let name = unique_pipe_name("dacl");
        let sid = current_user_sid().expect("sid").to_uppercase();
        let server = factory().create_instance(&name, true, 4).expect("create");

        let actual = describe_pipe_security(&server).expect("read back the descriptor");
        let upper = actual.to_uppercase();

        // The three ACEs we asked for, in their post-generic-mapping form.
        assert!(
            upper.contains("(A;;FA;;;SY)"),
            "missing SYSTEM ACE: {actual}"
        );
        assert!(
            upper.contains("(A;;FA;;;BA)"),
            "missing admin ACE: {actual}"
        );
        assert!(
            upper.contains(&format!("(A;;FA;;;{sid})")),
            "missing owner ACE: {actual}"
        );
        // Exactly three ACEs — nothing was added, and nothing we asked for was
        // dropped.
        assert_eq!(
            upper.matches("(A;;").count(),
            3,
            "unexpected ACE count: {actual}"
        );
        // `D:P` — protected, no inherited ACEs.
        assert!(upper.contains("D:P"), "DACL must be protected: {actual}");
        // The pipe is owned by this user, which is what makes the owner ACE the
        // daemon's own.
        assert!(
            upper.starts_with(&format!("O:{sid}")),
            "unexpected owner: {actual}"
        );
        // The mandatory integrity label is PRESENT ON THE OBJECT, read back
        // unelevated. This says nothing about whether it would actually block a
        // below-Medium client — see `describe_pipe_security`.
        assert!(
            upper.contains("S:") && upper.contains("(ML;;NW;;;ME)"),
            "the medium-integrity label must be on the object: {actual}"
        );

        // The measured pre-P2 exposure, gone: Everyone and ANONYMOUS LOGON no
        // longer hold FILE_GENERIC_READ.
        assert!(
            !upper.contains(";;;WD)"),
            "Everyone must have no ACE at all: {actual}"
        );
        assert!(
            !upper.contains(";;;AN)"),
            "ANONYMOUS LOGON must have no ACE at all: {actual}"
        );
    }

    /// Control for the test above: a pipe created *without* our factory still
    /// shows the default `WD`/`AN` read ACEs, so the assertion is falsifiable
    /// rather than asserting something the OS would never produce anyway.
    #[tokio::test]
    async fn the_default_dacl_really_does_expose_everyone() {
        use tokio::net::windows::named_pipe::ServerOptions;
        let name = unique_pipe_name("default-dacl");
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .expect("create with the default DACL");
        let actual = describe_pipe_security(&server)
            .expect("read back")
            .to_uppercase();
        assert!(
            actual.contains(";;;WD)"),
            "the pre-P2 default is supposed to grant Everyone; if this ever \
             fails, the DACL assertions above stop proving anything: {actual}"
        );
    }

    /// The anti-squat guard. A second `FILE_FLAG_FIRST_PIPE_INSTANCE` create
    /// of a name that already exists is refused with ERROR_ACCESS_DENIED, which
    /// `ssk-ipc` maps to a typed `IPC_PIPE_NAME_TAKEN` and a refusal to start.
    #[tokio::test]
    async fn first_instance_refuses_a_name_that_is_already_owned() {
        let name = unique_pipe_name("squat");
        let pipes = factory();
        let _first = pipes.create_instance(&name, true, 4).expect("first create");
        let err = pipes
            .create_instance(&name, true, 4)
            .expect_err("a second first-instance create must be refused");
        assert_eq!(err.raw_os_error(), Some(super::win::ACCESS_DENIED));
    }

    /// The P2 DACL must let the accept loop create instances 2..N — that is the
    /// reason the owner gets `GA` rather than the P3 client mask.
    #[tokio::test]
    async fn the_p2_dacl_permits_additional_instances() {
        let name = unique_pipe_name("multi");
        let pipes = factory();
        let _a = pipes.create_instance(&name, true, 4).expect("instance 1");
        let _b = pipes.create_instance(&name, false, 4).expect("instance 2");
        let _c = pipes.create_instance(&name, false, 4).expect("instance 3");
    }

    /// tokio's `ServerOptions::max_instances` *panics* at 255. A panicking
    /// factory would kill the accept loop's task, so the factory refuses first.
    #[tokio::test]
    async fn an_out_of_range_instance_cap_is_an_error_not_a_panic() {
        let pipes = factory();
        for bad in [0u32, 255, 1000, u32::MAX] {
            let err = pipes
                .create_instance(&unique_pipe_name("cap"), true, bad)
                .expect_err("out-of-range cap must be refused");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "cap {bad}");
        }
        // The boundary value must still work.
        let _ok = pipes
            .create_instance(&unique_pipe_name("cap-ok"), true, 254)
            .expect("254 is the documented maximum");
    }

    /// A malformed SDDL must be refused at construction, not at the first
    /// connection.
    #[test]
    fn a_bad_sddl_fails_the_factory_constructor() {
        assert!(WindowsPipeFactory::from_sddl("not an sddl string".to_owned()).is_err());
    }

    /// The P3 descriptor at least *converts* on this machine, so the only
    /// unverified thing about it is the principal assignment.
    #[test]
    fn the_p3_descriptor_converts_unelevated() {
        let sid = current_user_sid().expect("sid");
        let sddl = sddl_for_system_owned_pipe(&[sid.as_str()]).expect("sddl");
        WindowsPipeFactory::from_sddl(sddl).expect(
            "the P3 SDDL, including the mandatory label, must convert without SeSecurityPrivilege",
        );
        WindowsPipeFactory::from_sddl(sddl_for_read_only_fallback_pipe())
            .expect("the degraded fallback descriptor must convert too");
    }

    /// **The single test that would have prevented the wrong design.**
    ///
    /// A DACL granting only `SYSTEM` and `BUILTIN\Administrators` refuses this
    /// very process — which is a member of `Administrators` — because
    /// `S-1-5-32-544` is `SE_GROUP_USE_FOR_DENY_ONLY` on a UAC-filtered token.
    /// So "grant `BA`" is **not** how an administrator user gets in, and any P3
    /// design that admitted users via a `BA` ACE would lock the product's actual
    /// user out of their own kill-switch.
    ///
    /// Measured first through .NET's `PipeSecurity`; re-measured here through
    /// this crate's own factory, against a real pipe, in Rust.
    ///
    /// The `O:SY` owner is deliberately **omitted** from the descriptor under
    /// test: an unelevated process cannot set SYSTEM as an owner, so including
    /// it would make the create fail for a reason unrelated to the DACL and the
    /// test would prove nothing about access. What is isolated here is exactly
    /// the ACE set.
    ///
    /// On an **elevated** runner (GitHub's `windows-latest` is one) the same
    /// process *is* an administrator with rights, so the open succeeds. The test
    /// asserts the measured refusal only when this process is genuinely
    /// unelevated, and asserts the complementary fact otherwise — so it is real
    /// coverage on both kinds of machine rather than a skip.
    #[tokio::test]
    async fn a_system_and_admin_only_dacl_refuses_an_unelevated_administrator() {
        let name = unique_pipe_name("ba-only");
        let pipes =
            WindowsPipeFactory::from_sddl("D:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NW;;;ME)".to_owned())
                .expect("the SY+BA descriptor must convert");
        let _server = pipes.create_instance(&name, true, 4).expect("create");

        let opened = ClientOptions::new().open(&name);
        if crate::privilege::is_elevated() == Some(true) {
            assert!(
                opened.is_ok(),
                "an elevated administrator must be admitted by a BA ACE; if this fails the ACE \
                 itself is wrong: {opened:?}"
            );
            return;
        }
        let err = opened.expect_err(
            "an UNELEVATED member of Administrators must be REFUSED by a BA-only DACL; if this \
             ever starts succeeding, the tiering in `sddl_for_system_owned_pipe` rests on a \
             premise that no longer holds",
        );
        assert_eq!(
            err.raw_os_error(),
            Some(super::win::ACCESS_DENIED),
            "expected ERROR_ACCESS_DENIED: {err}"
        );
    }

    /// The control for the test above: the *same* process, admitted by an ACE
    /// naming its own SID. Without this, "refused" could just mean the pipe was
    /// broken.
    #[tokio::test]
    async fn the_same_process_is_admitted_when_its_own_sid_is_allow_listed() {
        let name = unique_pipe_name("allow-listed");
        let sid = current_user_sid().expect("sid");
        let mask = super::CLIENT_RIGHTS_NO_INSTANCE_CREATE;
        let pipes = WindowsPipeFactory::from_sddl(format!(
            "D:P(A;;GA;;;SY)(A;;{mask};;;{sid})(A;;{mask};;;BA)S:(ML;;NW;;;ME)"
        ))
        .expect("descriptor converts");
        let _server = pipes.create_instance(&name, true, 4).expect("create");
        let _client = ClientOptions::new()
            .open(&name)
            .expect("an explicitly allow-listed SID must be admitted");
    }

    /// The client half of mutual authentication, measured: a client holding
    /// only what a `GENERIC_READ | GENERIC_WRITE` open confers can read the
    /// pipe's owner back off its own handle.
    #[tokio::test]
    async fn a_client_can_read_the_pipe_owner_back_and_refuses_a_foreign_one() {
        let name = unique_pipe_name("owner");
        let sid = current_user_sid().expect("sid");
        let server = factory().create_instance(&name, true, 4).expect("create");
        let client = ClientOptions::new().open(&name).expect("client connects");
        server.connect().await.expect("accept");

        let observed =
            client_pipe_owner_sid(&client).expect("a client must be able to read the owner");
        assert_eq!(
            observed, sid,
            "this pipe is owned by the user that created it"
        );
        // Both directions of the decision, against a live handle.
        require_pipe_owner(&client, &sid).expect("the true owner must be accepted");
        let err = require_system_owned_pipe(&client)
            .expect_err("a user-owned pipe must be refused when SYSTEM is required");
        assert!(
            matches!(err, PipeSecurityError::UnexpectedOwner { .. }),
            "{err}"
        );
        // The server sees the same owner, so the readback is a property of the
        // object and not of which end asked.
        assert_eq!(server_pipe_owner_sid(&server).expect("server side"), sid);
        drop(client);
    }

    /// The token facts, against the real API on the real machine.
    ///
    /// Written to be true on **both** an unelevated developer box and an
    /// elevated CI runner. `elevated_admin` differs between them, so the
    /// invariant is asserted unconditionally and the measured pair is asserted
    /// only under the condition that produced it — stated in the assertion
    /// message rather than hidden in a skip.
    #[tokio::test]
    async fn the_peer_token_facts_are_coherent_and_never_conflate_the_two_admin_questions() {
        let name = unique_pipe_name("token");
        let auth = WindowsPeerAuthenticator::new().expect("construct");
        let server = factory().create_instance(&name, true, 4).expect("create");
        let client = ClientOptions::new().open(&name).expect("client connects");
        server.connect().await.expect("accept");

        let peer = auth
            .authenticate_peer(&server)
            .expect("a same-user client must authenticate");
        assert_eq!(peer.sid.as_str(), auth.own_sid_str());
        assert!(
            peer.token.is_coherent(),
            "no token can hold administrative rights without the account being an administrator: \
             {:?}",
            peer.token
        );
        assert!(
            peer.token.integrity_rid >= ssk_netd_helper::authz::INTEGRITY_RID_MEDIUM,
            "a client that can write to this pipe is at least Medium integrity, got {:#x}",
            peer.token.integrity_rid
        );
        // The implication that holds on every machine, in both directions of
        // deployment: you cannot hold administrative rights on a token the
        // process's own `TokenElevation` probe calls unelevated. The converse is
        // NOT asserted — `TokenIsElevated` is also true for some service
        // accounts that are not in `Administrators` — so asserting equality
        // would be asserting something stronger than Windows guarantees.
        assert!(
            !peer.token.elevated_admin || crate::privilege::is_elevated() == Some(true),
            "elevated_admin={} while the process elevation probe says {:?}",
            peer.token.elevated_admin,
            crate::privilege::is_elevated()
        );
        // The machine report. Deliberately not an assertion: the pair measured
        // on this hardware — `elevated_admin == false` while
        // `admin_account_filtered == true` — is a real, load-bearing fact, and
        // it does **not** reproduce on GitHub's elevated `windows-latest`.
        // Asserting it would make the suite pass or fail on which box ran it;
        // the invariant above is what is actually true everywhere.
        eprintln!(
            "[machine report] elevated_admin={} admin_account_filtered={} integrity_rid={:#x}",
            peer.token.elevated_admin, peer.token.admin_account_filtered, peer.token.integrity_rid
        );
        // THE ANTI-DOWNGRADE ASSERTION. Everything above is also true of
        // `PeerToken::unprivileged()`, so on its own it would not distinguish a
        // real token read from a fabricated all-false default — and a
        // fabricated default is precisely the fail-open this API's doc comment
        // forbids (it would silently deny an administrator the recovery tier).
        //
        // Every Windows token carries an `SE_GROUP_LOGON_ID` group;
        // `PeerToken::unprivileged()` carries `None`. So this is the field that
        // is falsifiable on *any* machine, elevated or not.
        //
        // Verified by mutation: making `authenticate_peer` return
        // `PeerToken::unprivileged()` leaves every other assertion in this file
        // green and turns this one red.
        let logon = peer.token.logon_session.as_ref().expect(
            "a real token read always yields an SE_GROUP_LOGON_ID group; `None` here means the \
             facts were fabricated rather than read",
        );
        assert!(
            logon.as_str().starts_with("S-1-5-5-"),
            "a logon-session SID has the S-1-5-5-<high>-<low> shape: {logon}"
        );
        assert_ne!(
            logon.as_str(),
            peer.sid.as_str(),
            "the logon SID must not be the user SID; matching would mean the wrong group was read"
        );
        // The second anti-downgrade assertion, for the other kind of machine.
        // On an elevated CI runner the process is necessarily an administrator
        // account, so a fabricated all-false token is caught there too.
        if crate::privilege::is_elevated() == Some(true) {
            assert!(
                peer.token.admin_account_filtered,
                "an elevated caller's account is by definition an administrator's; false here \
                 means TokenGroups was never walked"
            );
        }
        drop(client);
    }

    /// The token read happens in the same impersonation window as the SID read,
    /// and that window is closed before the call returns. Both halves matter:
    /// a leaked impersonation would run later tasks as the peer.
    #[tokio::test]
    async fn authenticating_a_peer_leaves_the_thread_un_impersonated() {
        let name = unique_pipe_name("token-revert");
        let auth = WindowsPeerAuthenticator::new().expect("construct");
        let server = factory().create_instance(&name, true, 4).expect("create");
        let client = ClientOptions::new().open(&name).expect("client connects");
        server.connect().await.expect("accept");

        let _peer = auth.authenticate_peer(&server).expect("authenticate");
        assert!(
            !thread_is_impersonating(),
            "impersonation must be reverted before authenticate_peer returns"
        );
        drop(client);
    }

    /// The fail-open traps apply to the token path too: an anonymous client
    /// must be refused outright, never handed a `PeerToken::unprivileged()`.
    /// Downgrading it would silently deny an administrator the recovery tier.
    #[tokio::test]
    async fn an_anonymous_client_cannot_be_authenticated_as_a_peer() {
        let name = unique_pipe_name("token-anon");
        let auth = WindowsPeerAuthenticator::new().expect("construct");
        let server = factory().create_instance(&name, true, 4).expect("create");
        let client = ClientOptions::new()
            .security_qos_flags(SECURITY_ANONYMOUS)
            .open(&name)
            .expect("anonymous client connects");
        server.connect().await.expect("accept");

        let err = auth
            .authenticate_peer(&server)
            .expect_err("an anonymous peer must be refused, not downgraded");
        assert!(
            err.to_string().contains("OpenThreadToken"),
            "the anonymous case must fail at OpenThreadToken: {err}"
        );
        assert!(!thread_is_impersonating());
        drop(client);
    }

    /// The revert post-condition, stated directly: a thread that has never
    /// impersonated has no thread token.
    #[test]
    fn a_fresh_thread_carries_no_impersonation_token() {
        assert!(!thread_is_impersonating());
    }
}
