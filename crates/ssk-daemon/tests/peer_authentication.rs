//! Is the peer check actually **on the path a user takes**?
//!
//! Roadmap SEC-3 was not "the SID check is wrong"; it was that
//! `ssk_ipc::auth` carried `CLIENT_SID_CHECK_IMPLEMENTED: bool = false` and the
//! accept loop performed no check at all. P1 then found the same shape twice
//! more: a correct lockdown with **zero production callers**. A seam nobody
//! injects is indistinguishable from no seam.
//!
//! So these tests drive the shipped `sskd` binary. Not `serve_named_pipe`
//! called from a test with hand-built trait objects — `ssk-ipc` and
//! `ssk-winhost` both already cover that, and neither can observe whether
//! `main.rs` injects anything. The daemon here is a separate process started
//! the way an operator starts it, and every trait object it uses is the one its
//! own composition root chose.
//!
//! # What is proven, and what is not
//!
//! * **Proven:** a same-user client is served end to end, and — on Windows — a
//!   client that opens the identical pipe with `SECURITY_ANONYMOUS`
//!   impersonation is hung up on before its request is executed, while the
//!   daemon keeps serving everyone else. The only difference between the two
//!   clients is the impersonation level, so a daemon with no peer check cannot
//!   pass both.
//! * **Not proven, and not fakeable here:** rejection of a genuinely *different
//!   OS user*. Creating a second local account needs elevation, which this
//!   suite never takes. Following the pattern this repo already uses for
//!   privileged legs (`crates/ssk-netd-helper/scripts/verify-store-dacl.ps1`),
//!   that leg lives in
//!   `crates/ssk-winhost/scripts/verify-pipe-peer-auth.ps1` as a scripted
//!   operator check — deliberately **not** an `#[ignore]`d test, which would
//!   read as coverage while asserting nothing.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ssk_ipc::{DaemonClient, Endpoint};

const READY_TIMEOUT: Duration = Duration::from_secs(30);

struct DaemonProcess {
    child: Child,
    state_dir: tempfile::TempDir,
}

impl DaemonProcess {
    fn endpoint(&self) -> Endpoint {
        endpoint_for(self.state_dir.path())
    }

    fn diagnostics(&self) -> String {
        let path = self.state_dir.path().join("sskd.err");
        match std::fs::read_to_string(&path) {
            Ok(text) if !text.trim().is_empty() => text,
            _ => format!("(no stderr captured at {})", path.display()),
        }
    }
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(unix)]
fn endpoint_for(state_dir: &std::path::Path) -> Endpoint {
    Endpoint::UnixSocket(state_dir.join("sskd.sock"))
}

#[cfg(windows)]
fn endpoint_for(state_dir: &std::path::Path) -> Endpoint {
    let sid = ssk_winhost::current_user_sid().expect("read this test process's own SID");
    Endpoint::NamedPipe(ssk_ipc::paths::named_pipe_name(&sid, state_dir))
}

async fn spawn_daemon() -> (DaemonProcess, DaemonClient) {
    let state_dir = tempfile::tempdir().expect("tempdir");
    let stderr = std::fs::File::create(state_dir.path().join("sskd.err")).expect("stderr capture");
    let child = Command::new(env!("CARGO_BIN_EXE_sskd"))
        .env("SSK_STATE_DIR", state_dir.path())
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn sskd");
    let mut proc = DaemonProcess { child, state_dir };
    let endpoint = proc.endpoint();

    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if let Ok(client) = DaemonClient::connect(&endpoint).await {
            return (proc, client);
        }
        if let Some(status) = proc.child.try_wait().expect("try_wait on sskd") {
            panic!(
                "sskd exited with {status} instead of serving {endpoint}:\n{}",
                proc.diagnostics()
            );
        }
        assert!(
            Instant::now() < deadline,
            "sskd never accepted a connection on {endpoint} within {READY_TIMEOUT:?}:\n{}",
            proc.diagnostics()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The positive leg: the daemon's own peer check accepts a same-user client and
/// executes its request.
///
/// On Windows the check runs *before a single frame byte is read*, so a request
/// that is answered at all is a request whose peer was authenticated. On Unix
/// the same is true via `SO_PEERCRED`.
#[tokio::test]
async fn a_same_user_client_is_authenticated_and_served() {
    let (_daemon, mut client) = spawn_daemon().await;

    match client
        .call(ssk_ipc::Request::GetStatus)
        .await
        .expect("a same-user peer must be served")
    {
        ssk_ipc::Response::Status(status) => {
            assert_eq!(status.state, ssk_ipc::DaemonState::Inactive);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

/// The negative leg, and the one that makes the positive leg mean something.
///
/// This client differs from the served one in exactly one respect: it opens the
/// pipe with `SECURITY_ANONYMOUS` impersonation instead of tokio's default
/// `SECURITY_IDENTIFICATION`. Same user, same token, same pipe name, same
/// bytes. `ssk-winhost` measured the consequence against the real FFI:
/// `ImpersonateNamedPipeClient` still returns TRUE, and `OpenThreadToken` then
/// fails with win32 1347 (`ERROR_CANT_OPEN_ANONYMOUS`) — the fail-open trap.
/// A daemon that skipped the peer check, or that treated an undeterminable SID
/// as acceptable, would answer this client.
///
/// The assertion is deliberately about the *wire*: no `Response` ever arrives.
/// `GetStatus` is side-effect-free, so "the handler never ran" is not directly
/// observable from here; "the peer was never answered" is, and it is the
/// property that matters for every request that does have side effects.
///
/// **Mutation-verified.** Swapping `main.rs`'s injected
/// `WindowsPeerAuthenticator` for a permissive one (same signature, returns the
/// daemon's own SID for every peer) makes this test fail with the anonymous
/// client receiving a full `Status` DTO — i.e. reproducing SEC-3 exactly. The
/// positive leg above stays green under that mutation, which is why it alone
/// would not have been evidence of anything.
#[cfg(windows)]
#[tokio::test]
async fn an_anonymous_impersonation_peer_is_refused_by_the_live_daemon() {
    use tokio::net::windows::named_pipe::ClientOptions;

    /// `SECURITY_ANONYMOUS` is 0; tokio ORs in `SECURITY_SQOS_PRESENT` itself.
    /// Spelled as a literal rather than pulled from `windows-sys` because this
    /// crate is `#![forbid(unsafe_code)]` and has no business growing a Win32
    /// dependency for one constant.
    const SECURITY_ANONYMOUS: u32 = 0;

    let (daemon, mut good) = spawn_daemon().await;
    let Endpoint::NamedPipe(name) = daemon.endpoint() else {
        panic!("windows must serve a named pipe");
    };

    /// Every server instance is momentarily in use. Observed here for real:
    /// the accept loop creates the *next* instance only after spawning the
    /// handler for the current one, so the instant after a client connects
    /// there is a `tokio::spawn`-wide window with nothing listening.
    /// `DaemonClient::connect` retries this; a raw `ClientOptions` must too, or
    /// the test measures the window instead of the peer check.
    const ERROR_PIPE_BUSY: i32 = 231;

    let mut hostile = {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match ClientOptions::new()
                .security_qos_flags(SECURITY_ANONYMOUS)
                .open(&name)
            {
                Ok(stream) => break stream,
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    assert!(Instant::now() < deadline, "every pipe instance stayed busy");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(e) => panic!(
                    "the DACL admits this user, so the refusal must come from the peer check, \
                     not the open: {e}"
                ),
            }
        }
    };

    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
        ssk_ipc::framing::write_frame(&mut hostile, &ssk_ipc::Request::GetStatus).await?;
        ssk_ipc::framing::read_frame::<ssk_ipc::Response, _>(
            &mut hostile,
            ssk_ipc::framing::MAX_RESPONSE_FRAME_LEN,
        )
        .await
    })
    .await
    .expect("the daemon must hang up, not stall the connection open");

    match outcome {
        Ok(response) => panic!(
            "an anonymous-impersonation peer was answered with {response:?} — the peer check is \
             not on the served path"
        ),
        Err(err) => assert!(
            !err.code.is_empty(),
            "a refusal must still be a typed IpcError"
        ),
    }

    // The daemon survived the refusal and still serves an authenticated peer:
    // the check is a per-connection decision, not a crash and not a global
    // fail-closed latch a hostile peer could trip on everyone else's behalf.
    match good
        .call(ssk_ipc::Request::GetStatus)
        .await
        .expect("the daemon must keep serving authenticated peers")
    {
        ssk_ipc::Response::Status(status) => {
            assert_eq!(status.state, ssk_ipc::DaemonState::Inactive);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}
