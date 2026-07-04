//! Spawns the real `sskd` daemon and drives `ssk status` against it — a
//! separate file from `ux_snapshots.rs` so the existing local-command UX
//! contract (`run`/`doctor`) stays untouched by this daemon-backed addition.
//!
//! Requires `sskd` to already be built alongside `ssk` in the same
//! `target/<profile>/` directory. `CARGO_BIN_EXE_<name>` only exposes
//! binaries owned by the *current* crate, so this test cannot force
//! `ssk-daemon`'s `sskd` binary to build via a dependency edge — run this via
//! `cargo test --workspace` (as CI's `build_test` job does: `cargo build
//! --workspace --all-targets` before `cargo test --workspace`), not
//! `cargo test -p ssk-cli` in isolation.

use std::process::{Child, Command};
use std::time::Duration;

struct DaemonProcess {
    child: Child,
    state_dir: tempfile::TempDir,
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_daemon() -> DaemonProcess {
    let state_dir = tempfile::tempdir().expect("tempdir");
    // `sskd` lives in the ssk-daemon crate; its binary path is only exposed
    // via CARGO_BIN_EXE_* to that crate's own tests, so we locate it
    // relative to this crate's own test binary directory instead (both
    // binaries land in the same `target/<profile>/` directory).
    let sskd_path = sskd_binary_path();
    let child = Command::new(sskd_path)
        .env("SSK_STATE_DIR", state_dir.path())
        .spawn()
        .expect("spawn sskd");
    let proc = DaemonProcess { child, state_dir };

    for _ in 0..100 {
        if proc.state_dir.path().join("sskd.sock").exists() {
            return proc;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("sskd did not create its socket in time");
}

fn sskd_binary_path() -> std::path::PathBuf {
    let ssk_path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_ssk"));
    let dir = ssk_path.parent().expect("ssk binary has a parent dir");
    let candidate = dir.join(if cfg!(windows) { "sskd.exe" } else { "sskd" });
    assert!(
        candidate.exists(),
        "expected sskd binary alongside ssk at {}",
        candidate.display()
    );
    candidate
}

#[test]
fn ssk_status_json_reflects_the_real_daemon() {
    let daemon = spawn_daemon();
    let output = Command::new(env!("CARGO_BIN_EXE_ssk"))
        .env("SSK_STATE_DIR", daemon.state_dir.path())
        .args(["--json", "status"])
        .output()
        .expect("ssk status must execute");

    assert!(output.status.success(), "ssk status must exit 0");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"state\""));
    assert!(stdout.contains("Inactive"));
}
