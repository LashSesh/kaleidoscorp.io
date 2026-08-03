//! Spawns the real `sskd` binary as a child process and drives it over the
//! real transport — not an in-process mock. This is the literal Phase 2
//! acceptance criterion: "CLI drives the daemon over IPC."
//!
//! # Why this file is no longer `#![cfg(unix)]`
//!
//! It was gated for a genuine compile reason: the driver was
//! `ssk_ipc::client::UnixClient`, which is `#[cfg(unix)]`, and one unguarded
//! reference to it made `cargo test --workspace` fail to *compile* on Windows.
//! Roadmap P2 removed that reason twice over — [`ssk_ipc::DaemonClient`] is one
//! type on both platforms, and the daemon now binds a per-user, per-state-dir
//! named pipe. So the gate is gone and every assertion below runs on Windows
//! exactly as it does on Unix. Nothing was weakened to get there; the only
//! platform-conditional code is [`endpoint_for`], which names *where* the
//! daemon listens.
//!
//! # Readiness is a connection, not a file
//!
//! The old poll was `<state-dir>/sskd.sock` — a file that exists only on Unix.
//! A named pipe has no equivalent to `Path::exists` that means "accepting", so
//! readiness is established by actually connecting. That is strictly stronger
//! than the file check on both platforms: a socket file appears at `bind`, well
//! before the accept loop runs.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ssk_ipc::{DaemonClient, Endpoint};

/// Generous on purpose: a cold `sskd` on a loaded CI box has to resolve its
/// state dir, take its lock, build a runtime and install a log sink first. The
/// loop below fails fast on an *exited* child, so this bound is only ever paid
/// when the daemon is genuinely alive and slow.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

struct DaemonProcess {
    child: Child,
    state_dir: tempfile::TempDir,
}

impl DaemonProcess {
    fn endpoint(&self) -> Endpoint {
        endpoint_for(self.state_dir.path())
    }

    /// Whatever the child managed to say before dying. Without this a startup
    /// refusal (`STATE_DIR_UNRESOLVABLE`, `IPC_PIPE_NAME_TAKEN`, a lock
    /// contention) is indistinguishable from a hang.
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

/// Where `sskd` listens for this state directory.
///
/// Must stay byte-identical to `ssk_daemon::paths::endpoint` for the same root
/// — that agreement is what makes the daemon reachable at all, and it is pinned
/// directly by `paths::tests::the_daemon_and_a_client_derive_the_same_pipe_name`.
#[cfg(unix)]
fn endpoint_for(state_dir: &std::path::Path) -> Endpoint {
    Endpoint::UnixSocket(state_dir.join("sskd.sock"))
}

/// Where `sskd` listens for this state directory.
///
/// The SID mixed into the digest is *this test process's* SID. That it also
/// works is not incidental: the child daemon runs as the same user, so a
/// mismatch here would mean the client and the daemon disagree about who they
/// are — which is exactly what the peer check would then refuse.
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

#[tokio::test]
async fn cli_drives_the_real_daemon_over_ipc() {
    let (_daemon, mut client) = spawn_daemon().await;

    // get_status
    let status = match client
        .call(ssk_ipc::Request::GetStatus)
        .await
        .expect("call")
    {
        ssk_ipc::Response::Status(s) => s,
        other => panic!("unexpected response: {other:?}"),
    };
    assert_eq!(status.state, ssk_ipc::DaemonState::Inactive);

    // list_profiles
    match client
        .call(ssk_ipc::Request::ListProfiles)
        .await
        .expect("call")
    {
        ssk_ipc::Response::Profiles(profiles) => assert!(!profiles.is_empty()),
        other => panic!("unexpected response: {other:?}"),
    }

    // activate_profile — a real destination the daemon (a genuinely
    // separate process) must really connect to over a real socket for this
    // to reach `Protected`. The listener lives in *this* test process, so
    // `Protected` can only happen if the spawned `sskd` child actually
    // dialed out over the network to reach it — the literal system-level
    // proof that `sskd`'s data plane is real, not a mock.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind real listener");
    let dest_port = listener.local_addr().expect("addr").port();
    let accept = tokio::spawn(async move { listener.accept().await });

    let status = match client
        .call(ssk_ipc::Request::ActivateProfile(
            ssk_ipc::ActivateProfileRequest {
                profile_id: "default".into(),
                dest_host: Some("127.0.0.1".into()),
                dest_port: Some(dest_port),
            },
        ))
        .await
        .expect("call")
    {
        ssk_ipc::Response::Status(s) => s,
        other => panic!("unexpected response: {other:?}"),
    };
    assert_eq!(status.state, ssk_ipc::DaemonState::Protected);
    assert_eq!(status.active_profile.as_deref(), Some("default"));
    assert!(
        status.dns_protected,
        "127.0.0.1 is a literal IP: no DNS lookup should have occurred"
    );
    assert_eq!(
        status.adapters.len(),
        1,
        "must report the one real Direct adapter actually traversed"
    );
    accept
        .await
        .expect("join")
        .expect("the real sskd child process must have really connected to this listener");

    // deactivate
    let status = match client
        .call(ssk_ipc::Request::Deactivate(ssk_ipc::DeactivateRequest {
            release_kill_switch: false,
        }))
        .await
        .expect("call")
    {
        ssk_ipc::Response::Status(s) => s,
        other => panic!("unexpected response: {other:?}"),
    };
    assert_eq!(status.state, ssk_ipc::DaemonState::Inactive);

    // verify_audit_chain — real, persisted, across the real process, and
    // genuinely non-empty: the real activation above must have appended a
    // real entry, not merely verified a vacuous zero-entry chain.
    match client
        .call(ssk_ipc::Request::VerifyAuditChain)
        .await
        .expect("call")
    {
        ssk_ipc::Response::AuditVerify(v) => {
            assert!(v.ok);
            assert!(v.head.is_some(), "audit chain must not be vacuously empty");
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

/// Two daemons with different state directories must coexist.
///
/// On Windows this is the regression test for the fixed global pipe name: a
/// second `sskd` used to die with `ERROR_ACCESS_DENIED` from
/// `first_pipe_instance` because both instances derived
/// `\\.\pipe\kaleidoscorp-sskd`. On Unix it pins the same property for the
/// socket path, which was already per-state-dir.
#[tokio::test]
async fn two_daemons_with_different_state_dirs_coexist() {
    let (first, mut a) = spawn_daemon().await;
    let (second, mut b) = spawn_daemon().await;

    assert_ne!(
        first.endpoint(),
        second.endpoint(),
        "two state directories must not resolve to one endpoint"
    );

    for client in [&mut a, &mut b] {
        match client
            .call(ssk_ipc::Request::GetStatus)
            .await
            .expect("both daemons must answer")
        {
            ssk_ipc::Response::Status(s) => assert_eq!(s.state, ssk_ipc::DaemonState::Inactive),
            other => panic!("unexpected response: {other:?}"),
        }
    }
}
