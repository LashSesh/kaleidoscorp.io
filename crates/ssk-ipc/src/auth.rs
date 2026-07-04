#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Per-session capability token minted at connect and required on every
/// mutating request (`docs/DESKTOP_CLIENT_ARCHITECTURE.md` section F.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionToken(pub [u8; 16]);

impl SessionToken {
    #[must_use]
    pub fn generate() -> Self {
        Self(rand::random())
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
    use crate::error::IpcError;

    /// Verify that the peer on `stream` is running as the same OS user as
    /// this daemon process. Any other user is rejected — this is the whole
    /// local-only authentication boundary for the Unix transport.
    pub fn check_peer_same_user(stream: &tokio::net::UnixStream) -> Result<(), IpcError> {
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
        Ok(())
    }
}

/// Windows local-only authentication is a documented gap for this phase: full
/// named-pipe client-SID verification would need a `windows-sys` dependency
/// that Phase 2 deliberately does not add yet (see
/// `docs/DESKTOP_CLIENT_ARCHITECTURE.md` section H / F.5). Until that ships,
/// the named pipe's default DACL (same desktop session) is the only
/// enforcement on Windows — do not treat this as equivalent to the Unix
/// peer-credential check.
#[cfg(windows)]
pub mod windows {
    /// Placeholder documenting the known gap; intentionally not implemented.
    pub const CLIENT_SID_CHECK_IMPLEMENTED: bool = false;
}

#[cfg(all(test, unix))]
mod tests {
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

        unix::check_peer_same_user(&server_stream).expect("same-user peer must be accepted");
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
