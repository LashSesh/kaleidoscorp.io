#![cfg(windows)]
use serde_json::{json, Value};
use std::{
    fs,
    os::windows::process::CommandExt,
    path::Path,
    process::{Command, Output},
};
fn fixture(path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ssk-netcapture"))
        .arg("private-fixture")
        .arg(path)
        .creation_flags(0x08000000)
        .output()
        .unwrap()
}
#[test]
fn private_controller_writes_a_closed_bundle_consumed_by_the_existing_checker() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("capture");
    let output = fixture(&bundle);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "private_fixture_written");
    assert_eq!(report["events_submitted"], 8);
    assert_eq!(report["system_capture_available"], false);
    assert_eq!(report["schema_version"], 2);
    assert_eq!(report["supervision_file"], "supervision.json");
    let supervision: Value =
        serde_json::from_slice(&fs::read(bundle.join("supervision.json")).unwrap()).unwrap();
    assert_eq!(supervision["status"], "worker_completed");
    assert_eq!(supervision["process"]["exit_observed"], true);
    assert_eq!(supervision["process"]["termination_requested"], false);
    assert_eq!(supervision["session_cleanup_verified"], false);
    let controller: Value =
        serde_json::from_slice(&fs::read(bundle.join("controller.json")).unwrap()).unwrap();
    assert_eq!(controller["status"], "private_capture_completed");
    assert_eq!(controller["queries_completed"], 10);
    assert_eq!(controller["stop"]["api_status"], 0);
    assert_eq!(controller["schema_version"], 2);
    assert_eq!(controller["cleanup_status"], "stopped");
    assert_eq!(controller["cleanup_retry"], Value::Null);
    let output = Command::new(env!("CARGO_BIN_EXE_ssk-netobserve"))
        .arg("etl-check")
        .arg(bundle.join("recording.etl"))
        .arg(bundle.join("closure.json"))
        .creation_flags(0x08000000)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["closure"]["file_binding_matches"], true);
    assert_eq!(
        report["closure"]["issues"],
        json!(["unsupported_profile_configuration", "etl_unavailable"])
    );
    assert!(report["etl"]["ignored_provider_records"].as_u64().unwrap() >= 8);
    let original = fs::read(bundle.join("recording.etl")).unwrap();
    assert_eq!(fixture(&bundle).status.code(), Some(2));
    assert_eq!(fs::read(bundle.join("recording.etl")).unwrap(), original);
    assert!(fixture(&dir.path().join("second")).status.success());
}
#[test]
fn system_mode_and_user_selected_network_targets_are_not_cli_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("must-not-exist");
    for verb in ["record", "system", "capture"] {
        let output = Command::new(env!("CARGO_BIN_EXE_ssk-netcapture"))
            .arg(verb)
            .arg(&bundle)
            .creation_flags(0x08000000)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!bundle.exists());
    }
    let output = Command::new(env!("CARGO_BIN_EXE_ssk-netcapture"))
        .args(["traffic", "--host", "example.invalid"])
        .creation_flags(0x08000000)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let output = Command::new(env!("CARGO_BIN_EXE_ssk-netcapture"))
        .arg("plan")
        .creation_flags(0x08000000)
        .output()
        .unwrap();
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["enable_flags"], 0x10010001u32);
    assert_eq!(plan["system_capture_available"], false);
    assert_eq!(plan["prerequisites"].as_array().unwrap().len(), 3);
}
#[test]
fn fixed_loopback_workload_verifies_all_four_cases_and_reports_application_counts() {
    let output = Command::new(env!("CARGO_BIN_EXE_ssk-netcapture"))
        .arg("traffic")
        .creation_flags(0x08000000)
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "completed", "{report}");
    let cases = report["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for (case, name) in cases
        .iter()
        .zip(["tcp_ipv4", "udp_ipv4", "tcp_ipv6", "udp_ipv6"])
    {
        assert_eq!(case["case"], name);
        assert_eq!(case["round_trips_completed"], 8);
        assert_eq!(case["verified_received_application_bytes"], 2048);
        assert_eq!(case["error_kind"], Value::Null);
    }
    assert_eq!(report["etw_coverage_verified"], false);
    assert_eq!(report["enforcement_active"], false);
}

#[test]
fn private_worker_cannot_be_invoked_without_containment_or_with_extra_flags() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("untouched");
    for extra in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ssk-netcapture"));
        command.arg("--private-capture-worker").arg(&target);
        if extra {
            command.arg("--live");
        }
        let output = command.creation_flags(0x08000000).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!target.exists());
    }
}
