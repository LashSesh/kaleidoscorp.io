//! The state root that `sskd` creates, and the one it refuses (design 6.4.9).
//!
//! The ledger store refuses a state root that group or others can write. A root
//! that an earlier `sskd` made with `create_dir_all` is 0775 under umask 002 (the
//! default for a user with a private group on Debian and Ubuntu), so the daemon
//! would refuse its own directory on the next start. These tests run the real
//! `sskd` under that umask and check that the root it makes is private.
//!
//! Unix only: the mode of a Windows directory is not a Unix mode.

#![cfg(unix)]

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/support/routing_config.rs"
));

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ssk_daemon::ingress::audit::fs::{LedgerFs, StoreError, UnsafeReason};
use ssk_daemon::ingress::audit::fs_unix::UnixLedgerFs;

/// Kills and reaps the daemon when the test ends or panics.
struct Reaper(Child);

impl Drop for Reaper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o7777
}

/// Starts `sskd` under `umask`, with `state` as its state root, and returns once
/// it accepts a connection.
fn start_sskd(umask: &str, state: &Path, config_dir: &Path) -> Reaper {
    let stderr = std::fs::File::create(config_dir.join("sskd.err")).expect("stderr capture");
    let child = Reaper(
        Command::new("sh")
            .arg("-c")
            .arg(format!("umask {umask}; exec \"$0\""))
            .arg(env!("CARGO_BIN_EXE_sskd"))
            .env("SSK_STATE_DIR", state)
            .env("SSK_CONFIG_PATH", write_loopback_config(config_dir))
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn sskd"),
    );
    let socket = state.join("sskd.sock");
    let deadline = Instant::now() + Duration::from_secs(30);
    while UnixStream::connect(&socket).is_err() {
        assert!(
            Instant::now() < deadline,
            "sskd never accepted a connection"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    child
}

/// The control: this machine's `sh` really does apply the umask the test sets,
/// and `create_dir_all` really would have made the root group-writable. Without
/// it the test below could pass on a machine where the umask has no effect.
#[test]
fn umask_002_makes_create_dir_all_group_writable_here() {
    let holder = tempfile::tempdir().expect("tempdir");
    let dir = holder.path().join("made-by-sh");
    let status = Command::new("sh")
        .arg("-c")
        .arg("umask 002; mkdir -p \"$0\"")
        .arg(&dir)
        .status()
        .expect("sh");
    assert!(status.success());
    assert_eq!(mode_of(&dir) & 0o020, 0o020, "{:o}", mode_of(&dir));
}

#[test]
fn daemon_creates_a_missing_state_root_private_under_umask_002() {
    let holder = tempfile::tempdir().expect("tempdir");
    let state = holder.path().join("state").join("kaleidoscorp");
    let _daemon = start_sskd("002", &state, holder.path());

    assert_eq!(mode_of(&state), 0o700, "the root the daemon made");
    // And the ledger store accepts it, which is the point of making it private.
    let store = UnixLedgerFs::new(state.clone())
        .open_store()
        .expect("the store accepts the root the daemon made");
    assert!(store.created());
}

#[test]
fn daemon_leaves_an_existing_state_root_as_it_is() {
    let holder = tempfile::tempdir().expect("tempdir");
    let state = holder.path().join("state");
    std::fs::create_dir(&state).expect("mkdir");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o775)).expect("chmod");
    let _daemon = start_sskd("022", &state, holder.path());
    assert_eq!(mode_of(&state), 0o775, "an existing root is never repaired");
}

#[test]
fn existing_group_writable_state_root_is_refused_with_the_chmod_hint() {
    let holder = tempfile::tempdir().expect("tempdir");
    let state = holder.path().join("state");
    std::fs::create_dir(&state).expect("mkdir");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o775)).expect("chmod");

    let error = UnixLedgerFs::new(state.clone())
        .open_store()
        .err()
        .expect("a group-writable root is refused");
    assert_eq!(
        error,
        StoreError::RootUnsafe(UnsafeReason::GroupOrOtherWritable)
    );
    let hint = error.operator_hint(&state);
    assert!(
        hint.contains(&format!("chmod go-w {}", state.display())),
        "{hint}"
    );
    assert_eq!(mode_of(&state), 0o775, "refused, never repaired");
    assert!(
        !state.join("ingress-audit").exists(),
        "nothing was created in it"
    );

    // The operator runs the command from the hint, and it works.
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).expect("chmod go-w");
    assert!(UnixLedgerFs::new(state).open_store().is_ok());
}
