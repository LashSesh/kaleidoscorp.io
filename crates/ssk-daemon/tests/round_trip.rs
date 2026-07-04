//! Spawns the real `sskd` binary as a child process and drives it over the
//! real Unix socket transport — not an in-process mock. This is the literal
//! Phase 2 acceptance criterion: "CLI drives the daemon over IPC."

use std::process::{Child, Command};
use std::time::Duration;

struct DaemonProcess {
    child: Child,
    state_dir: tempfile::TempDir,
}

impl DaemonProcess {
    fn socket_path(&self) -> std::path::PathBuf {
        self.state_dir.path().join("sskd.sock")
    }
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn spawn_daemon() -> DaemonProcess {
    let state_dir = tempfile::tempdir().expect("tempdir");
    let child = Command::new(env!("CARGO_BIN_EXE_sskd"))
        .env("SSK_STATE_DIR", state_dir.path())
        .spawn()
        .expect("spawn sskd");
    let proc = DaemonProcess { child, state_dir };

    for _ in 0..100 {
        if proc.socket_path().exists() {
            return proc;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("sskd did not create its socket in time");
}

#[tokio::test]
async fn cli_drives_the_real_daemon_over_ipc() {
    let daemon = spawn_daemon().await;
    let mut client = ssk_ipc::client::UnixClient::connect(daemon.socket_path())
        .await
        .expect("connect to real sskd");

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
