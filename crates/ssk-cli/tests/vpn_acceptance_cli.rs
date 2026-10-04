//! Real recorder subprocesses with explicitly synthetic VM assertions. No VPN,
//! service, driver, ACL provisioning or genuine VM acceptance is performed.
use serde_json::{json, Value};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ssk-vpn-acceptance"))
        .args(args)
        .output()
        .unwrap()
}
fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn initialize(root: &Path, locale: &str) -> (std::path::PathBuf, Value) {
    let mut context: Value = serde_json::from_str(include_str!(
        "../../../docs/examples/openvpn-acceptance-context.json"
    ))
    .unwrap();
    context["locale"] = locale.into();
    context["vm_id"] = "SYNTHETIC-CLI-FIXTURE".into();
    for key in ["disposable_vm", "isolated_network", "test_credentials_only"] {
        context[key] = true.into();
    }
    let source = root.join(format!("{locale}.json"));
    fs::write(&source, serde_json::to_vec(&context).unwrap()).unwrap();
    let binary = root.join("never-execute.exe");
    fs::write(&binary, b"not an executable; fingerprint only").unwrap();
    let bundle = root.join(locale);
    let output = run(&[
        "init",
        "--context",
        path(&source),
        "--cli",
        path(&binary),
        "--service",
        path(&binary),
        "--out",
        path(&bundle),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (bundle, serde_json::from_slice(&output.stdout).unwrap())
}

#[test]
fn acceptance_cli_distinguishes_valid_report_incomplete_gate_and_invalid_evidence() {
    let f = tempfile::tempdir().unwrap();
    let (en, en_report) = initialize(f.path(), "en-US");
    let (de, de_report) = initialize(f.path(), "de-DE");
    assert_eq!(en_report["not_run"], 49);
    assert_eq!(en_report["release_ready"], false);
    let output = run(&[
        "check",
        "--en-us",
        path(&en),
        "--de-de",
        path(&de),
        "--expected-en-head",
        en_report["head_sha256"].as_str().unwrap(),
        "--expected-de-head",
        de_report["head_sha256"].as_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(3));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["coverage_complete"], false);
    let output = run(&["report", "--bundle", path(&en)]);
    assert!(output.status.success());
    fs::write(en.join("run.json"), b"{broken").unwrap();
    let output = run(&["report", "--bundle", path(&en)]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn acceptance_cli_records_blocked_case_and_refuses_unreviewed_sensitive_evidence() {
    let f = tempfile::tempdir().unwrap();
    let (bundle, _) = initialize(f.path(), "en-US");
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let observation = f.path().join("observation.json");
    let mut value = json!({"schema":1,"case_id":"J07","outcome":"blocked","started_unix_ms":time,"ended_unix_ms":time,"observed":"Synthetic fixture: journal restoration is unavailable.","sanitized":true,"evidence":[]});
    fs::write(&observation, serde_json::to_vec(&value).unwrap()).unwrap();
    let output = run(&[
        "record",
        "--bundle",
        path(&bundle),
        "--observation",
        path(&observation),
        "--evidence-dir",
        path(f.path()),
    ]);
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["blocked"], 1);
    value["observed"] = "password=DO_NOT_ECHO_THIS_MATERIAL".into();
    fs::write(&observation, serde_json::to_vec(&value).unwrap()).unwrap();
    let output = run(&[
        "record",
        "--bundle",
        path(&bundle),
        "--observation",
        path(&observation),
        "--evidence-dir",
        path(f.path()),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("DO_NOT_ECHO"));
    assert!(!bundle.join("attempts/000002").exists());
}

#[test]
fn acceptance_cli_has_no_execution_or_force_switch_and_catalog_is_complete() {
    let output = run(&["matrix"]);
    assert!(output.status.success());
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 49);
    for command in ["prepare", "connect", "install", "force"] {
        assert_eq!(run(&[command]).status.code(), Some(2));
    }
}

#[test]
fn kit_verification_requires_a_separately_supplied_hash() {
    let f = tempfile::tempdir().unwrap();
    let output = run(&["kit-verify", "--kit", path(f.path())]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--expected-manifest-sha256"));
    assert!(fs::read_dir(f.path()).unwrap().next().is_none());
}

#[cfg(windows)]
#[test]
fn kit_cli_packages_real_recorder_without_executing_supplied_binary_then_checks_transfer() {
    let f = tempfile::tempdir().unwrap();
    // Only a PE header, not a loadable program. Packaging must not execute it.
    let mut data = vec![0; 128];
    data[..2].copy_from_slice(b"MZ");
    data[60..64].copy_from_slice(&64u32.to_le_bytes());
    data[64..68].copy_from_slice(b"PE\0\0");
    data[68..70].copy_from_slice(&0x8664u16.to_le_bytes());
    data[70..72].copy_from_slice(&1u16.to_le_bytes());
    data[84..86].copy_from_slice(&2u16.to_le_bytes());
    data[86..88].copy_from_slice(&2u16.to_le_bytes());
    data[88..90].copy_from_slice(&0x20bu16.to_le_bytes());
    let source = f.path().join("not-loadable.exe");
    fs::write(&source, data).unwrap();
    let kit = f.path().join("kit");
    let output = run(&[
        "kit-create",
        "--cli",
        path(&source),
        "--service",
        path(&source),
        "--source-revision",
        &"ab".repeat(20),
        "--worktree-dirty",
        "--out",
        path(&kit),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["development_only"], true);
    assert_eq!(report["release_ready"], false);
    assert_eq!(report["worktree_dirty"], true);
    let args = [
        "kit-verify",
        "--kit",
        path(&kit),
        "--expected-manifest-sha256",
        report["manifest_sha256"].as_str().unwrap(),
    ];
    assert!(run(&args).status.success());
    fs::write(kit.join("unexpected.txt"), b"not in manifest").unwrap();
    let output = run(&args);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}
