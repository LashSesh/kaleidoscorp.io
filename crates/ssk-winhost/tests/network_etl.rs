#![cfg(windows)]
//! No kernel tracing. One private in-process fixture writes only its own test
//! provider through the private controller. The reader CLI starts no sessions.
use std::{
    fs,
    os::windows::process::CommandExt,
    path::Path,
    process::{Command, Output},
};

#[path = "fixtures/private_etl.rs"]
mod private_etl;

fn cli(path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ssk-netobserve"))
        .arg("etl")
        .arg(path)
        .creation_flags(0x08000000)
        .output()
        .unwrap()
}

fn cli_check(path: &Path, closure: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ssk-netobserve"))
        .arg("etl-check")
        .arg(path)
        .arg(closure)
        .creation_flags(0x08000000)
        .output()
        .unwrap()
}

#[test]
fn genuine_private_etl_runs_through_the_contained_native_reader() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private fixture.etl");
    private_etl::write(&path);
    let result = cli(&path);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(json["status"], "unavailable", "{json}");
    assert_eq!(
        json["failure"]["kind"], "no_supported_network_events",
        "{json}"
    );
    assert_eq!(json["process_trace_completed"], true, "{json}");
    assert!(json["callbacks_seen"].as_u64().unwrap() > 0);
    assert!(json["ignored_provider_records"].as_u64().unwrap() > 0);
    assert_eq!(json["header"]["events_lost"], 0);
    assert_eq!(json["header"]["buffers_lost"], 0);
    assert_eq!(json["process_identity_verified"], false);
    assert_eq!(json["schema_version"], 2);
    assert_eq!(json["process_provider_records"], 0);
    assert_eq!(json["process_correlation"]["status"], "unavailable");
    assert_eq!(json["process_correlation"]["network_records"], 0);
    assert_eq!(json["loss_completeness_verified"], false);
    assert_eq!(json["enforcement_active"], false);
    assert!(json.get("verdict").is_none());
    // The same real file, truncated: never a successful network observation.
    let data = fs::read(&path).unwrap();
    let corrupt = dir.path().join("truncated.etl");
    fs::write(&corrupt, &data[..100.min(data.len())]).unwrap();
    let result = cli(&corrupt);
    if result.status.success() {
        let json: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(json["status"], "unavailable");
    } else {
        assert_eq!(result.status.code(), Some(2));
    }
}

#[test]
fn malformed_file_returns_native_error_without_exposing_contents() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid.etl");
    fs::write(&path, b"private-marker-must-not-appear").unwrap();
    let result = cli(&path);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(json["status"], "unavailable");
    assert_eq!(json["failure"]["kind"], "open_trace");
    assert_eq!(json["header"], serde_json::Value::Null);
    assert!(!String::from_utf8_lossy(&result.stdout).contains("private-marker"));
}

#[test]
fn direct_worker_invocation_and_extra_switches_are_refused() {
    for args in [
        ["--etl-worker", "missing.etl", ""],
        ["etl", "missing.etl", "--live"],
    ] {
        let count = if args[2].is_empty() { 2 } else { 3 };
        let result = Command::new(env!("CARGO_BIN_EXE_ssk-netobserve"))
            .args(&args[..count])
            .creation_flags(0x08000000)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
    }
}

#[test]
fn empty_and_oversized_inputs_fail_before_native_processing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("size.etl");
    for size in [0, ssk_winhost::network_etw::etl::MAX_FILE_BYTES + 1] {
        fs::File::create(&path).unwrap().set_len(size).unwrap();
        let result = cli(&path);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
    }
}

#[test]
fn native_private_closure_binds_the_file_but_never_proves_network_coverage() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private closure.etl");
    let sidecar = dir.path().join("closure.json");
    let receipt = private_etl::write(&path);
    for phase in ["query_after_start", "stop"] {
        assert_eq!(receipt[phase]["api_status"], 0);
        for counter in ["events_lost", "log_buffers_lost", "realtime_buffers_lost"] {
            assert_eq!(receipt[phase]["properties"][counter], 0, "{receipt}");
        }
    }
    assert!(
        receipt["stop"]["properties"]["buffers_written"]
            .as_u64()
            .unwrap()
            > 0
    );
    fs::write(&sidecar, serde_json::to_vec(&receipt).unwrap()).unwrap();
    let output = cli_check(&path, &sidecar);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["etl"]["schema_version"], 2);
    assert_eq!(report["closure"]["file_binding_matches"], true);
    assert_eq!(report["closure"]["file_sha256"], receipt["file"]["sha256"]);
    assert_eq!(report["closure"]["status"], "unavailable");
    assert_eq!(
        report["closure"]["issues"],
        serde_json::json!(["unsupported_profile_configuration", "etl_unavailable"])
    );
    assert_eq!(report["etl"]["process_trace_completed"], true);
    assert_eq!(report["closure"]["controller_authenticity_verified"], false);
    assert_eq!(report["closure"]["coverage_verified"], false);
    assert_eq!(report["etl"]["enforcement_active"], false);
}

#[test]
fn cli_detects_changed_binding_losses_and_missing_stop_without_promoting_etl() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mutations.etl");
    let sidecar = dir.path().join("closure.json");
    let receipt = private_etl::write(&path);
    for (pointer, replacement, issue) in [
        (
            "/file/sha256",
            serde_json::json!("0".repeat(64)),
            "file_binding_mismatch",
        ),
        (
            "/stop",
            serde_json::Value::Null,
            "stop_unsuccessful_or_missing",
        ),
        (
            "/stop/properties/events_lost",
            serde_json::json!(1),
            "loss_reported",
        ),
        (
            "/stop/properties/session_guid",
            serde_json::json!("b72f10ca-79ef-4ff6-95d9-8b3e7b190422"),
            "session_configuration_mismatch",
        ),
    ] {
        let mut changed = receipt.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        fs::write(&sidecar, serde_json::to_vec(&changed).unwrap()).unwrap();
        let output = cli_check(&path, &sidecar);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["closure"]["status"], "unavailable");
        assert!(
            report["closure"]["issues"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(issue)),
            "{report}"
        );
        assert_eq!(report["etl"]["status"], "unavailable");
    }
}

#[test]
fn closure_inputs_are_bounded_strict_and_checked_before_native_processing() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.etl");
    let sidecar = dir.path().join("closure.json");
    for data in [b"private-marker-invalid-json".to_vec(), vec![b' '; 16385]] {
        fs::write(&sidecar, data).unwrap();
        let output = cli_check(&missing, &sidecar);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-marker"));
    }
    // Both inputs use the read-only sharing policy, including the sidecar.
    fs::write(
        &sidecar,
        include_bytes!("../../../docs/examples/etl-closure.json"),
    )
    .unwrap();
    fs::write(&missing, b"abc").unwrap();
    assert!(cli_check(&missing, &sidecar).status.success());
    let _writer = fs::OpenOptions::new().write(true).open(&sidecar).unwrap();
    assert_eq!(cli_check(&missing, &sidecar).status.code(), Some(2));
    let result = Command::new(env!("CARGO_BIN_EXE_ssk-netobserve"))
        .args(["etl-check", "missing.etl", "closure.json", "--live"])
        .creation_flags(0x08000000)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
}
