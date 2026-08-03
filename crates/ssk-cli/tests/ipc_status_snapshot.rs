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
//!
//! # Why this file is no longer `#![cfg(unix)]`
//!
//! Roadmap P0 gated it, and said so plainly: the gate silenced a red test that
//! was reporting a real product defect. Two things were broken on Windows —
//! `sskd` bound a named pipe and never created the `<state-dir>/sskd.sock`
//! this file polled for, and `ssk`'s `#[cfg(not(unix))] call_daemon` was a
//! hardcoded `DAEMON_UNIX_ONLY` stub. P2 fixed both: the CLI has a real
//! named-pipe client, and `sskd`'s composition root injects a pipe factory and
//! a peer authenticator. The gate is therefore removed rather than relaxed —
//! no assertion below changed.
//!
//! Readiness is now a real connection to the daemon's endpoint rather than a
//! `Path::exists` on a socket file, because a named pipe has no such file. The
//! probe deliberately does **not** shell out to `ssk`: using the binary under
//! test as its own readiness gate would make the assertions below vacuous.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ssk_ipc::Endpoint;

const READY_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Where `sskd` listens for this state directory — the same derivation `ssk`
/// itself performs, which is the property that makes the CLI reachable.
#[cfg(unix)]
fn endpoint_for(state_dir: &std::path::Path) -> Endpoint {
    Endpoint::UnixSocket(state_dir.join("sskd.sock"))
}

#[cfg(windows)]
fn endpoint_for(state_dir: &std::path::Path) -> Endpoint {
    let sid = ssk_winhost::current_user_sid().expect("read this test process's own SID");
    Endpoint::NamedPipe(ssk_ipc::paths::named_pipe_name(&sid, state_dir))
}

fn spawn_daemon() -> DaemonProcess {
    let state_dir = tempfile::tempdir().expect("tempdir");
    // `sskd` lives in the ssk-daemon crate; its binary path is only exposed
    // via CARGO_BIN_EXE_* to that crate's own tests, so we locate it
    // relative to this crate's own test binary directory instead (both
    // binaries land in the same `target/<profile>/` directory).
    let sskd_path = sskd_binary_path();
    let stderr = std::fs::File::create(state_dir.path().join("sskd.err")).expect("stderr capture");
    let child = Command::new(sskd_path)
        .env("SSK_STATE_DIR", state_dir.path())
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn sskd");
    let mut proc = DaemonProcess { child, state_dir };
    wait_until_serving(&mut proc);
    proc
}

/// Block until the daemon actually accepts a connection on its endpoint.
///
/// Strictly stronger than the old `sskd.sock` existence poll on both platforms:
/// a Unix socket file appears at `bind`, before the accept loop is running.
fn wait_until_serving(proc: &mut DaemonProcess) {
    let endpoint = endpoint_for(proc.state_dir.path());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("readiness runtime");
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if runtime
            .block_on(ssk_ipc::DaemonClient::connect(&endpoint))
            .is_ok()
        {
            return;
        }
        if let Some(status) = proc.child.try_wait().expect("try_wait on sskd") {
            panic!(
                "sskd exited with {status} instead of serving {endpoint}:\n{}",
                daemon_stderr(proc)
            );
        }
        assert!(
            Instant::now() < deadline,
            "sskd never accepted a connection on {endpoint} within {READY_TIMEOUT:?}:\n{}",
            daemon_stderr(proc)
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn daemon_stderr(proc: &DaemonProcess) -> String {
    let path = proc.state_dir.path().join("sskd.err");
    match std::fs::read_to_string(&path) {
        Ok(text) if !text.trim().is_empty() => text,
        _ => format!("(no stderr captured at {})", path.display()),
    }
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

    assert!(
        output.status.success(),
        "ssk status must exit 0: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"state\""));
    assert!(stdout.contains("Inactive"));
}
