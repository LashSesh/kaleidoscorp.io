use std::{io::Write, process::Command};

const EXAMPLE: &[u8] = include_bytes!("../../../docs/examples/etw-network-replay.json");

#[test]
fn etw_cli_rejects_invalid_json_without_echoing_untrusted_keys() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(br#"{"private_input_secret":"must_not_appear"}"#)
        .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_ssk-netobserve"))
        .arg("etw-replay")
        .arg(file.path())
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("invalid ETW replay JSON"));
    assert!(!stderr.contains("private_input_secret"));
}

#[test]
fn etw_cli_rejects_extra_actions_before_reading_the_input() {
    let result = Command::new(env!("CARGO_BIN_EXE_ssk-netobserve"))
        .args(["etw-replay", "missing.json", "--enforce"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
}

#[test]
fn lossy_export_is_reported_without_requiring_windows_metadata() {
    let mut input: serde_json::Value = serde_json::from_slice(EXAMPLE).unwrap();
    input["loss_end"]["consumer_dropped"] = 1.into();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&serde_json::to_vec(&input).unwrap())
        .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_ssk-netobserve"))
        .arg("etw-replay")
        .arg(file.path())
        .output()
        .unwrap();
    assert!(result.status.success());
    let json: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(json["status"], "unavailable");
    assert_eq!(json["reason"]["kind"], "loss_reported");
    assert_eq!(json["decoded_prefix_records"], 0);
    assert_eq!(json["baseline_compatible"], false);
}

#[cfg(windows)]
#[test]
fn actual_cli_tdh_replay_keeps_diagnostic_counts_and_no_authority() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(EXAMPLE).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_ssk-netobserve"))
        .arg("etw-replay")
        .arg(file.path())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(json["status"], "decoded_input");
    assert_eq!(json["tcp"]["reported_send_size_sum"], 1500);
    assert_eq!(json["tcp"]["reported_retransmit_size_sum"], 1000);
    assert_eq!(json["udp"]["reported_receive_size_sum"], 128);
    assert_eq!(json["header_payload_pid_mismatches"], 3);
    assert_eq!(json["process_identity_verified"], false);
    assert_eq!(json["baseline_compatible"], false);
    assert_eq!(json["enforcement_active"], false);
    assert!(json.get("verdict").is_none());
}
