#![forbid(unsafe_code)]

//! Local-only IPC authentication.
//!
//! # What replaced `SessionToken`
//!
//! This module used to mint a random per-connection `SessionToken`, documented
//! as "required on every mutating request". It was not. It appeared in no
//! `Request` variant, no DTO and no serialized form anywhere in the tree; the
//! only production `CommandHandler` bound it as `_token` and never read it.
//!
//! Transmitting and verifying it would not have helped: the server mints the
//! token, on the connection, and hands it to the very peer it is meant to
//! authenticate. Comparing a value you just gave the peer, over the same
//! connection, whose peer identity you already know from the transport, proves
//! only that the peer can echo — zero bits of authentication, plus the
//! *appearance* of a credential in any future audit.
//!
//! A capability token is meaningful only when minted by an authority the caller
//! cannot reach, over a channel that does not otherwise carry identity. That is
//! the daemon → broker case, where `ssk-netd-helper` already does it properly
//! (a pre-shared `BrokerConfig::session_token` compared with
//! `CapabilityToken::ct_eq`). That layer is real and untouched.
//!
//! So the token is gone and [`PeerIdentity`] takes its place on
//! [`crate::server::CommandHandler`]: the handler now receives what the
//! transport actually *proved*, not a value it invented.

use serde::{Deserialize, Serialize};

/// The verified identity of the peer on the far end of a connection.
///
/// Constructed only by a transport's authentication step — `unix::
/// check_peer_same_user` or `transport_win::check_peer_same_user` — after that
/// step has established the peer is the same OS principal as this daemon.
/// Both variants exist on every platform so cross-platform callers (and their
/// tests) compile everywhere; only one is ever produced at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PeerIdentity {
    /// Unix: the peer's uid, verified equal to this process's uid.
    Uid(u32),
    /// Windows: the peer's SID in string form, verified equal to this
    /// process's SID.
    Sid(String),
}

impl std::fmt::Display for PeerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerIdentity::Uid(uid) => write!(f, "uid:{uid}"),
            PeerIdentity::Sid(sid) => write!(f, "sid:{sid}"),
        }
    }
}

/// Local-only IPC authentication for Unix domain sockets: same-user peer
/// credential check via `SO_PEERCRED`/`LOCAL_PEERCRED` (exposed by tokio's
/// `UnixStream::peer_cred()`, no extra dependency there). Getting *our own*
/// uid to compare against requires a syscall that `std` does not expose
/// safely without `unsafe`; `rustix` is the one new minimal dependency this
/// crate adds, scoped to `cfg(unix)` only, purely to satisfy that need.
#[cfg(unix)]
pub mod unix {
    use super::PeerIdentity;
    use crate::error::IpcError;

    /// Verify that the peer on `stream` is running as the same OS user as
    /// this daemon process. Any other user is rejected — this is the whole
    /// local-only authentication boundary for the Unix transport.
    pub fn check_peer_same_user(stream: &tokio::net::UnixStream) -> Result<PeerIdentity, IpcError> {
        let cred = stream
            .peer_cred()
            .map_err(|e| IpcError::new("Permission", "IPC_PEER_CRED_FAILED", e.to_string()))?;
        let our_uid = rustix::process::getuid().as_raw();
        if cred.uid() != our_uid {
            return Err(IpcError::new(
                "Permission",
                "IPC_PEER_REJECTED",
                format!(
                    "peer uid {} does not match daemon uid {our_uid}",
                    cred.uid()
                ),
            ));
        }
        Ok(PeerIdentity::Uid(our_uid))
    }
}

/// Windows peer authentication. The FFI half lives in `ssk-winhost` (the one
/// crate exempt from `unsafe_code = "forbid"`) and is injected here as a
/// trait object; the *decision* — and its tests — live in this crate. See
/// [`crate::transport_win`].
///
/// The former `windows::CLIENT_SID_CHECK_IMPLEMENTED: bool = false` is gone.
/// A `bool` constant standing in for a security control is exactly the pattern
/// this project's audit trail exists to eliminate: it cannot fail closed, it
/// cannot be exercised by a test, and it read as a decision that had been made.
/// What replaces it is a required constructor argument — `serve_named_pipe`
/// will not compile without a real [`crate::transport_win::PeerAuthenticator`],
/// so "unimplemented" is no longer a state the daemon can be built in.
#[cfg(windows)]
pub use crate::transport_win::{
    check_peer_same_user as check_windows_peer, PeerAuthenticator, Sid,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_identity_displays_its_principal() {
        assert_eq!(PeerIdentity::Uid(1000).to_string(), "uid:1000");
        assert_eq!(
            PeerIdentity::Sid("S-1-5-18".to_owned()).to_string(),
            "sid:S-1-5-18"
        );
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;

    #[tokio::test]
    async fn same_process_peer_is_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.sock");
        let listener = tokio::net::UnixListener::bind(&path).expect("bind");

        let connector = tokio::net::UnixStream::connect(&path);
        let (client, accept_result) = tokio::join!(connector, listener.accept());
        let _client = client.expect("connect");
        let (server_stream, _addr) = accept_result.expect("accept");

        let peer =
            unix::check_peer_same_user(&server_stream).expect("same-user peer must be accepted");
        assert!(matches!(peer, PeerIdentity::Uid(_)));
    }

    /// Verifying rejection of a genuinely *different* OS user isn't feasible
    /// in a standard single-user CI container — there is no second user to
    /// switch to. This is a documented, scripted manual check instead of a
    /// false claim of automated coverage: run
    /// `scripts/manual_peer_cred_test.sh <second-username>` on a machine
    /// with a second real user account.
    #[test]
    #[ignore = "requires a second OS user; run scripts/manual_peer_cred_test.sh instead"]
    fn different_user_is_rejected() {
        unreachable!(
            "not runnable in-process; see scripts/manual_peer_cred_test.sh for the real check"
        );
    }
}
