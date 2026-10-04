//! The Windows named-pipe authentication and creation seam.
//!
//! `ssk-ipc` is `#![forbid(unsafe_code)]` and stays that way. Everything on
//! this page that needs Win32 is a *trait* implemented in `ssk-winhost` — the
//! one crate exempt from the workspace-wide `unsafe_code = "forbid()"` — and
//! injected at the composition root, the same injected-seam shape the codebase
//! already uses for `BoundaryEnforcer` / `TrafficSource` / `PrivilegedHelper`.
//! This crate owns the *decision*; it never owns the syscall.
//!
//! # Why the seam has to be shaped this way
//!
//! `tokio::net::windows::named_pipe::ServerOptions::
//! create_with_security_attributes_raw` takes `&self` and returns
//! `io::Result<NamedPipeServer>`, and calling it is `unsafe`. There is no way
//! to pass a `SECURITY_ATTRIBUTES` pointer *into* this crate and have this
//! crate make the call. So whoever holds the `unsafe` must also hold tokio and
//! must hand back the finished `NamedPipeServer` — hence [`PipeFactory`].
//!
//! The **client** needs no seam at all: `ClientOptions::new()` already defaults
//! to `SECURITY_IDENTIFICATION | SECURITY_SQOS_PRESENT` and `.open()` is safe,
//! and that default is exactly what the server's impersonation check requires
//! (measured). See [`crate::client`].

use tokio::net::windows::named_pipe::NamedPipeServer;

use crate::error::IpcError;

/// A Windows security identifier in string form, e.g.
/// `"S-1-5-21-1111111111-2222222222-3333333333-1001"`.
///
/// Opaque to `ssk-ipc`, which compares but never parses it.
///
/// **The comparison is an ordinary `==` and that is deliberate.** A SID is a
/// public identifier, not a secret — there is nothing for a timing side
/// channel to leak. Do not "harden" this into a constant-time compare: that
/// would imply the SID is a credential, which is precisely the false
/// impression the deleted `SessionToken` used to create.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sid(pub String);

impl std::fmt::Display for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The FFI half of Windows peer authentication.
///
/// Implemented in `ssk-winhost` and injected at the composition root.
pub trait PeerAuthenticator: Send + Sync {
    /// SID of the user this daemon process runs as.
    ///
    /// Must fail closed: an implementation that cannot determine its own SID
    /// returns `Err`, never a placeholder.
    fn own_sid(&self) -> Result<Sid, IpcError>;

    /// SID of the client on the far end of `server`.
    ///
    /// Implementations MUST impersonate the pipe client, read `TokenUser`, and
    /// revert on every path *including unwind*; MUST NOT `.await` while
    /// impersonated (impersonation is per-thread and tokio's multi-thread
    /// runtime is work-stealing, so an `.await` can leave a foreign identity
    /// behind on a worker that then runs unrelated tasks); and MUST map both
    /// `ERROR_CANNOT_IMPERSONATE` (1368) and `ERROR_BAD_IMPERSONATION_LEVEL`
    /// (1347) to `Err` — never to a "cannot tell" a caller might read as
    /// success.
    ///
    /// The second of those is the fail-open trap that measurement found: a
    /// client that opens the pipe with `SECURITY_ANONYMOUS` makes
    /// `ImpersonateNamedPipeClient` return **TRUE** while the subsequent
    /// `OpenThreadToken` fails with 1347. Treating the impersonate call's
    /// success as authentication authenticates a peer that explicitly refused
    /// to be identified.
    fn peer_sid(&self, server: &NamedPipeServer) -> Result<Sid, IpcError>;
}

/// Creates one instance of a named pipe carrying the daemon's DACL.
///
/// Implemented in `ssk-winhost`, which builds the `SECURITY_ATTRIBUTES` from
/// SDDL and calls `create_with_security_attributes_raw`.
pub trait PipeFactory: Send + Sync {
    /// Create a single instance of `pipe_name`.
    ///
    /// `first_instance` maps to `FILE_FLAG_FIRST_PIPE_INSTANCE` and **must** be
    /// true for the first instance: it is the anti-squat guard. (A previous
    /// reading of this code held that the flag was passed unconditionally and
    /// should be removed. It was not passed unconditionally — the accept loop
    /// has always set it only on the first instance — and removing it would let
    /// a squatter's pipe coexist with ours. The multi-instance defect was
    /// entirely the fixed global *name*, now fixed in
    /// [`crate::paths::named_pipe_name`].)
    ///
    /// Returns `io::Result` rather than [`IpcError`] so the caller can
    /// distinguish `ERROR_PIPE_BUSY` (231 — all instances are in use, back off
    /// and retry) from `ERROR_ACCESS_DENIED` (5 — with `first_instance`, a
    /// squatter already owns the name; refuse to start).
    fn create_instance(
        &self,
        pipe_name: &str,
        first_instance: bool,
        max_instances: u32,
    ) -> std::io::Result<NamedPipeServer>;
}

/// The entire Windows authentication boundary — the twin of
/// `auth::unix::check_peer_same_user`.
///
/// Lives here, in the `forbid(unsafe_code)` crate, so the decision is
/// unit-testable against a fake [`PeerAuthenticator`] rather than only against
/// a live foreign-user process (which is not creatable unelevated; see
/// `docs/OPERATOR_VM_VALIDATION.md`).
///
/// Call it *immediately* after `NamedPipeServer::connect()` returns and before
/// any frame is read: impersonation works pre-read (measured, against a client
/// that wrote zero bytes), so an unauthenticated peer never causes a single
/// frame allocation. Do not be tempted to move it after the first read to
/// "fix" an `ERROR_CANNOT_IMPERSONATE` — a client that sent no SQOS flags
/// fails pre-read and *succeeds* post-read, so moving the check would admit
/// exactly the peer that refused to identify itself.
pub fn check_peer_same_user(
    auth: &dyn PeerAuthenticator,
    server: &NamedPipeServer,
) -> Result<Sid, IpcError> {
    // Own SID first: if we cannot establish who *we* are there is nothing to
    // compare against, and the only safe answer is refusal.
    let own = auth.own_sid()?;
    let peer = auth.peer_sid(server)?;
    if peer != own {
        return Err(IpcError::new(
            "Permission",
            "IPC_PEER_REJECTED",
            format!("peer sid {peer} does not match daemon sid {own}"),
        ));
    }
    Ok(peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::windows::named_pipe::ServerOptions;

    /// A `NamedPipeServer` to hand the check. No client ever connects to it —
    /// the fake authenticator does not look at the handle, and creating a
    /// server instance needs no peer.
    fn dummy_server(tag: &str) -> NamedPipeServer {
        let name = format!(r"\\.\pipe\ssk-ipc-test-{tag}-{}", std::process::id());
        ServerOptions::new().create(name).expect("create pipe")
    }

    struct FakeAuth {
        own: Result<Sid, IpcError>,
        peer: Result<Sid, IpcError>,
    }

    impl PeerAuthenticator for FakeAuth {
        fn own_sid(&self) -> Result<Sid, IpcError> {
            self.own.clone()
        }
        fn peer_sid(&self, _server: &NamedPipeServer) -> Result<Sid, IpcError> {
            self.peer.clone()
        }
    }

    const SELF_SID: &str = "S-1-5-21-1-2-3-1001";
    const OTHER_SID: &str = "S-1-5-21-1-2-3-1002";

    #[tokio::test]
    async fn same_sid_is_accepted() {
        let auth = FakeAuth {
            own: Ok(Sid(SELF_SID.to_owned())),
            peer: Ok(Sid(SELF_SID.to_owned())),
        };
        let server = dummy_server("accept");
        let sid = check_peer_same_user(&auth, &server).expect("same sid must be accepted");
        assert_eq!(sid.0, SELF_SID);
    }

    #[tokio::test]
    async fn foreign_sid_is_rejected() {
        let auth = FakeAuth {
            own: Ok(Sid(SELF_SID.to_owned())),
            peer: Ok(Sid(OTHER_SID.to_owned())),
        };
        let server = dummy_server("reject");
        let err = check_peer_same_user(&auth, &server).expect_err("foreign sid must be rejected");
        assert_eq!(err.code, "IPC_PEER_REJECTED");
        assert_eq!(err.class, "Permission");
    }

    /// "Cannot determine the peer" is a rejection, never an unknown. This is
    /// the fail-open trap `ERROR_BAD_IMPERSONATION_LEVEL` sets.
    #[tokio::test]
    async fn unknown_peer_sid_is_rejected() {
        let auth = FakeAuth {
            own: Ok(Sid(SELF_SID.to_owned())),
            peer: Err(IpcError::new(
                "Permission",
                "IPC_PEER_SID_FAILED",
                "OpenThreadToken failed: 1347",
            )),
        };
        let server = dummy_server("unknown-peer");
        let err = check_peer_same_user(&auth, &server).expect_err("unknown peer must be rejected");
        assert_eq!(err.code, "IPC_PEER_SID_FAILED");
    }

    /// Not knowing our *own* SID is equally fatal: there is nothing to compare
    /// against, so there is no safe answer but refusal.
    #[tokio::test]
    async fn unknown_own_sid_is_rejected() {
        let auth = FakeAuth {
            own: Err(IpcError::new(
                "Permission",
                "IPC_OWN_SID_FAILED",
                "OpenProcessToken failed",
            )),
            peer: Ok(Sid(SELF_SID.to_owned())),
        };
        let server = dummy_server("unknown-own");
        let err = check_peer_same_user(&auth, &server).expect_err("unknown own sid must reject");
        assert_eq!(err.code, "IPC_OWN_SID_FAILED");
    }
}
