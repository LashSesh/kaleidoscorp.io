use ssk_netanalysis::{
    replay::{analyze, read_and_analyze, ReplayError, ReplayInput, MAX_REPLAY_BYTES},
    UnavailableReason, Verdict,
};
use std::io::Read;
use std::process::Command;

const EXAMPLE: &[u8] = include_bytes!("../../../docs/examples/netanalysis-baseline.json");

#[test]
fn documented_fixture_has_four_explainable_findings_and_no_authority() {
    let report = read_and_analyze(EXAMPLE).unwrap();
    let Verdict::Suspicious { findings } = report.snapshot_verdict() else {
        panic!("fixture must exceed its demonstration thresholds");
    };
    assert_eq!(findings.len(), 4);
    let json = serde_json::to_value(report).unwrap();
    assert_eq!(json["advisory_only"], true);
    assert_eq!(json["identity_verified"], false);
    assert_eq!(json["coverage_verified"], false);
    assert_eq!(json["enforcement_active"], false);
    assert_eq!(json["metrics"]["completed_attempts"], 4);
    assert_eq!(json["metrics"]["failed_attempts"], 3);
}

#[test]
fn replay_loss_is_visible_instead_of_a_partial_positive_result() {
    let mut input: ReplayInput = serde_json::from_slice(EXAMPLE).unwrap();
    input.lost_events = 1;
    assert_eq!(
        analyze(input).unwrap().snapshot_verdict(),
        &Verdict::Unavailable {
            reason: UnavailableReason::EventLoss,
        }
    );
}

#[test]
fn unknown_fields_duplicates_floats_and_trusted_claims_are_rejected() {
    let original: serde_json::Value = serde_json::from_slice(EXAMPLE).unwrap();
    let mut invalid = vec![original.clone(); 7];
    invalid[0]["allow_network"] = true.into();
    invalid[1]["baseline"]["window_ms"] = 1000.1.into();
    invalid[2]["provenance"] = "verified".into();
    invalid[3]["scope"]["trusted"] = true.into();
    invalid[4]["observations"][0]["signal"]["grant"] = true.into();
    invalid[5]["baseline"]["window_ms"] = "NaN".into();
    invalid[6]["observations"][0]["signal"]["failed"] = "false".into();
    for document in invalid {
        let bytes = serde_json::to_vec(&document).unwrap();
        assert!(matches!(
            read_and_analyze(bytes.as_slice()),
            Err(ReplayError::Json)
        ));
    }
    let text = std::str::from_utf8(EXAMPLE).unwrap();
    let duplicate = text.replacen(
        "\"schema_version\": 1",
        "\"schema_version\": 1, \"schema_version\": 1",
        1,
    );
    assert!(matches!(
        read_and_analyze(duplicate.as_bytes()),
        Err(ReplayError::Json)
    ));
    let trailing = [EXAMPLE, b" {}"].concat();
    assert!(matches!(
        read_and_analyze(trailing.as_slice()),
        Err(ReplayError::Json)
    ));
}

#[test]
fn schema_version_and_vector_budgets_are_explicit() {
    let mut input: ReplayInput = serde_json::from_slice(EXAMPLE).unwrap();
    input.schema_version = 2;
    assert!(matches!(analyze(input.clone()), Err(ReplayError::Version)));
    input.schema_version = 1;
    input.observations = vec![input.observations[0].clone(); 4097];
    assert!(matches!(analyze(input), Err(ReplayError::TooManyEvents)));
}

#[test]
fn parser_reads_at_most_the_byte_budget_plus_one() {
    struct Endless {
        read: usize,
    }
    impl Read for Endless {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            buffer.fill(b' ');
            self.read += buffer.len();
            Ok(buffer.len())
        }
    }
    let mut input = Endless { read: 0 };
    assert!(matches!(
        read_and_analyze(&mut input),
        Err(ReplayError::TooLarge)
    ));
    assert_eq!(input.read, MAX_REPLAY_BYTES + 1);
}

#[test]
fn executable_outputs_report_and_rejects_commands_or_malformed_documents() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = directory.path().join("fixture.json");
    std::fs::write(&fixture, EXAMPLE).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ssk-netanalysis-replay"))
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["verdict"]["status"], "suspicious");
    assert_eq!(report["enforcement_active"], false);
    std::fs::write(&fixture, br#"{"DO_NOT_ECHO_THIS": "secret"}"#).unwrap();
    let bad = Command::new(env!("CARGO_BIN_EXE_ssk-netanalysis-replay"))
        .arg(&fixture)
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
    assert!(bad.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&bad.stderr).contains("DO_NOT_ECHO_THIS"));
    let extra = Command::new(env!("CARGO_BIN_EXE_ssk-netanalysis-replay"))
        .args(["--enforce", "--allow"])
        .output()
        .unwrap();
    assert_eq!(extra.status.code(), Some(2));
}
