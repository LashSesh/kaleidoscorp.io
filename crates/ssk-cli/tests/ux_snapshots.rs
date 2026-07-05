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
fn system_run_clean_fixture_emits() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = Command::new(binary())
        .current_dir(temp.path())
        .args(["--json", "system", "run", "--fixture", "clean"])
        .output()
        .expect("system run command must execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"decision\": \"emit\""));
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
    assert!(stdout.contains("\"host_downgraded\": true"));
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
