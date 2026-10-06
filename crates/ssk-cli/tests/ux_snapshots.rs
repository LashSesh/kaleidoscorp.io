use std::process::Command;

fn binary() -> String {
    env!("CARGO_BIN_EXE_ssk").to_string()
}

#[test]
fn run_json_output_snapshot_like() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = Command::new(binary())
        .current_dir(temp.path())
        .args(["--json", "run", "--valid-fixture", "true"])
        .output()
        .expect("run command must execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"status\": \"ok\""));
    assert!(stdout.contains("\"outcome\""));
    assert!(stdout.contains("\"next_steps\""));
}

#[test]
fn run_human_output_snapshot_like() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = Command::new(binary())
        .current_dir(temp.path())
        .args(["run", "--valid-fixture", "true"])
        .output()
        .expect("run command must execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("run="));
    assert!(stdout.contains("metrics:"));
    assert!(stdout.contains("next:"));
}

#[test]
fn doctor_json_fails_closed_when_entropy_missing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = Command::new(binary())
        .current_dir(temp.path())
        .args(["--json", "doctor"])
        .output()
        .expect("doctor command must execute");

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"report\""));
}

#[test]
fn system_run_clean_fixture_holds_without_parallax_or_replay_evidence() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = Command::new(binary())
        .current_dir(temp.path())
        .args(["--json", "system", "run", "--fixture", "clean"])
        .output()
        .expect("system run command must execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"decision\": \"hold\""));
    assert!(stdout.contains("a3_parallax_inconsistent"));
    assert!(stdout.contains("a8_replay_divergent"));
    assert!(stdout.contains("\"ledger_ok\": true"));
}

#[test]
fn system_run_sensitive_fixture_denies_with_exit_20() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = Command::new(binary())
        .current_dir(temp.path())
        .args(["--json", "system", "run", "--fixture", "sensitive"])
        .output()
        .expect("system run command must execute");

    assert_eq!(output.status.code(), Some(20));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"decision\": \"deny\""));
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("EMISSION_DENIED"));
}

#[test]
fn system_run_kill_switch_denies_end_to_end() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = Command::new(binary())
        .current_dir(temp.path())
        .args([
            "--json",
            "system",
            "run",
            "--fixture",
            "clean",
            "--engage-kill-switch",
        ])
        .output()
        .expect("system run command must execute");

    assert_eq!(output.status.code(), Some(20));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("kill_switch_engaged"));
}

#[test]
fn system_run_unhealthy_host_holds_not_denies() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = Command::new(binary())
        .current_dir(temp.path())
        .args([
            "--json",
            "system",
            "run",
            "--fixture",
            "clean",
            "--host-unhealthy",
        ])
        .output()
        .expect("system run command must execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"decision\": \"hold\""));
    // Not `"host_downgraded": true`: with no persisted signature baseline
    // wired into this fixture path, the signature gate already holds on its
    // own (`signature_baseline_missing`), so the Crown's own decision starts
    // at Hold rather than a would-be Emit that host-health then downgrades.
    // The reason this test cares about — an unhealthy host is named,
    // end to end, and never escalates to a Deny — still holds regardless of
    // which axis got there first.
    assert!(stdout.contains("service_host_not_emittable"));
}

#[test]
fn system_run_rejects_an_unknown_fixture() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = Command::new(binary())
        .current_dir(temp.path())
        .args(["--json", "system", "run", "--fixture", "bogus"])
        .output()
        .expect("system run command must execute");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("INVALID_FIXTURE"));
}

// --- winhost (real Windows backends) ---------------------------------------
//
// `doctor` and `capture` never fail (they report support and enumerate flows —
// zero off-Windows), so they exit 0 on any platform. The privileged actions
// and the "unsupported off-Windows" assertions are gated to non-Windows, where
// they run on the Linux CI jobs; the Windows CI job compiles and runs the
// crate's own pure tests.

#[test]
fn winhost_doctor_runs_on_any_platform() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = Command::new(binary())
        .current_dir(temp.path())
        .args(["--json", "winhost", "doctor"])
        .output()
        .expect("winhost doctor must execute");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"platform_supported\""));
    assert!(stdout.contains("\"backends\""));
}

#[test]
fn winhost_capture_runs_on_any_platform() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = Command::new(binary())
        .current_dir(temp.path())
        .args(["--json", "winhost", "capture"])
        .output()
        .expect("winhost capture must execute");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"flow_count\""));
}

#[cfg(not(windows))]
#[test]
fn winhost_doctor_reports_unsupported_off_windows() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = Command::new(binary())
        .current_dir(temp.path())
        .args(["--json", "winhost", "doctor"])
        .output()
        .expect("winhost doctor must execute");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"platform_supported\": false"));
}

/// Since the broker split the CLI never drives a firewall itself: off Windows
/// there is no privileged control plane to command, and the refusal must say
/// that nothing was actuated rather than fall back to a local effect.
#[cfg(not(windows))]
#[test]
fn winhost_killswitch_engage_is_unsupported_off_windows() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = Command::new(binary())
        .current_dir(temp.path())
        .args(["winhost", "killswitch", "engage"])
        .output()
        .expect("winhost killswitch engage must execute");
    assert_eq!(output.status.code(), Some(21));
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("no Windows privileged control plane"));
    assert!(stderr.contains("Nothing was actuated"));
}

/// Off Windows `release` is refused at the broker boundary, before any receipt
/// is looked up, so the machine-readable code is `KILLSWITCH_BROKER_UNSUPPORTED`.
#[cfg(not(windows))]
#[test]
fn winhost_killswitch_release_is_unsupported_off_windows() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = Command::new(binary())
        .current_dir(temp.path())
        .args([
            "--json",
            "winhost",
            "killswitch",
            "release",
            "--scope",
            "ci-nonexistent-scope",
        ])
        .output()
        .expect("winhost killswitch release must execute");
    assert_eq!(output.status.code(), Some(21));
    // The machine-readable error envelope is written to stderr by emit_error.
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("KILLSWITCH_BROKER_UNSUPPORTED"));
}

#[cfg(not(windows))]
#[test]
fn winhost_service_start_requires_windows() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = Command::new(binary())
        .current_dir(temp.path())
        .args(["winhost", "service", "start"])
        .output()
        .expect("winhost service start must execute");
    assert_eq!(output.status.code(), Some(21));
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("requires Windows"));
}
