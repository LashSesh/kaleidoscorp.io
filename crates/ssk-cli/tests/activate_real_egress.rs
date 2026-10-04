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
//!
//! # Why this file is no longer `#![cfg(unix)]`
//!
//! Roadmap P0 gated it and recorded the debt: `spawn_daemon` polled for
//! `<state-dir>/sskd.sock`, which `sskd` never created on Windows, and the
//! `ssk` subprocess it drives had no Windows control plane at all
//! (`#[cfg(not(unix))] call_daemon` was a `DAEMON_UNIX_ONLY` stub). P2 closed
//! both halves — a real named-pipe client in `ssk-cli`, and a composition root
//! in `sskd` that injects a pipe factory and a peer authenticator — so the gate
//! is removed rather than relaxed. No assertion below changed.
//!
//! Readiness is now a real connection to the daemon's endpoint instead of a
//! `Path::exists`, because a named pipe has no file to look for.

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/support/routing_config.rs"
));

use std::net::TcpListener;
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
/// itself performs.
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
    let sskd_path = sskd_binary_path();
    let stderr = std::fs::File::create(state_dir.path().join("sskd.err")).expect("stderr capture");
    let child = Command::new(sskd_path)
        .env("SSK_STATE_DIR", state_dir.path())
        .env("SSK_CONFIG_PATH", write_loopback_config(state_dir.path()))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn sskd");
    let mut proc = DaemonProcess { child, state_dir };
    wait_until_serving(&mut proc);
    proc
}

/// Block until the daemon actually accepts a connection on its endpoint.
/// Deliberately not "until `ssk status` succeeds": the binary under test must
/// not be its own readiness gate.
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
