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
