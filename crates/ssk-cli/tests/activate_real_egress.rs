//! Drives `ssk activate --dest`/`ssk deactivate` as real subprocesses against
//! a real spawned `sskd`, which must really connect over TCP to a listener
//! living in *this* test process to report `Protected`. This is the
//! system-level, user-reachable proof that SSKΩ-7's real egress capability
//! is reachable through the actual `ssk` binary a user would run — not just
//! exercised in-process against the `Supervisor` directly (see
//! `ssk-daemon/tests/round_trip.rs` for that lower-level proof).
//!
//! Same binary-colocation requirement as `ipc_status_snapshot.rs`: run via
//! `cargo test --workspace`, not `cargo test -p ssk-cli` in isolation.

use std::net::TcpListener;
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
fn ssk_activate_really_connects_and_deactivate_really_tears_down() {
    let daemon = spawn_daemon();

    // A real listener living in *this* process. The only way the following
    // `ssk activate` can report `Protected` is if the separately-spawned
    // `sskd` process really dialed out over a real socket to reach it.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind real listener");
    let port = listener.local_addr().expect("addr").port();
    let accept_thread = std::thread::spawn(move || listener.accept());

    let output = Command::new(env!("CARGO_BIN_EXE_ssk"))
        .env("SSK_STATE_DIR", daemon.state_dir.path())
        .args([
            "--json",
            "activate",
            "--profile",
            "default",
            "--dest",
            &format!("127.0.0.1:{port}"),
        ])
        .output()
        .expect("ssk activate must execute");

    assert!(
        output.status.success(),
        "ssk activate must exit 0 when the destination is really reachable: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Protected"), "stdout was: {stdout}");
    assert!(
        stdout.contains("\"dns_protected\": true") || stdout.contains("\"dns_protected\":true"),
        "127.0.0.1 is a literal IP, so no DNS lookup should have occurred: {stdout}"
    );

    accept_thread
        .join()
        .expect("accept thread must not panic")
        .expect("the real sskd child process must have really connected to this listener");

    // deactivate really tears the session back down.
    let output = Command::new(env!("CARGO_BIN_EXE_ssk"))
        .env("SSK_STATE_DIR", daemon.state_dir.path())
        .args(["--json", "deactivate"])
        .output()
        .expect("ssk deactivate must execute");
    assert!(output.status.success(), "ssk deactivate must exit 0");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Inactive"), "stdout was: {stdout}");
}

#[test]
fn ssk_activate_without_a_reachable_destination_fails_closed() {
    let daemon = spawn_daemon();

    // A real, guaranteed-closed port: bound then dropped immediately.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);

    let output = Command::new(env!("CARGO_BIN_EXE_ssk"))
        .env("SSK_STATE_DIR", daemon.state_dir.path())
        .args([
            "--json",
            "activate",
            "--profile",
            "default",
            "--dest",
            &format!("127.0.0.1:{port}"),
        ])
        .output()
        .expect("ssk activate must execute");

    // Reaching a real destination status (not an IPC-level error) is the
    // correct contract here: the daemon really attempted the connection,
    // really observed the refusal, and truthfully reports `FailClosed` —
    // exactly the same shape as a success, just with a different, honest
    // state, so a caller cannot mistake "no rule matched" for "we tried and
    // it failed".
    assert!(
        output.status.success(),
        "the call itself succeeds; the *state* it reports is FailClosed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(
        stdout.contains("FailClosed"),
        "a real refused connection must report FailClosed, never Protected: {stdout}"
    );
}
