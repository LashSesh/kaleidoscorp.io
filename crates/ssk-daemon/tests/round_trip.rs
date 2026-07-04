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

    // activate_profile
    let status = match client
        .call(ssk_ipc::Request::ActivateProfile(
            ssk_ipc::ActivateProfileRequest {
                profile_id: "default".into(),
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

    // verify_audit_chain — real, persisted, across the real process
    match client
        .call(ssk_ipc::Request::VerifyAuditChain)
        .await
        .expect("call")
    {
        ssk_ipc::Response::AuditVerify(v) => assert!(v.ok),
        other => panic!("unexpected response: {other:?}"),
    }
}
