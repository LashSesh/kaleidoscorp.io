use super::super::{assemble, Header, WorkerReport};
use super::*;
use crate::network_etw::{DecodedEvent, Transport};
use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../../docs/examples/etl-closure.json"
    ))
    .unwrap()
}

fn etl() -> EtlReport {
    let mut worker = WorkerReport {
        header: Some(Header {
            source_windows_build: 0,
            pointer_bytes: 8,
            log_file_mode: SYSTEM_LOGGER | 1,
            clock_type: 1,
            performance_frequency: "10000000".into(),
            session_start_filetime: "100".into(),
            session_end_filetime: "200".into(),
            events_lost: 0,
            buffers_lost: 0,
            buffers_written: 1,
        }),
        process_trace_completed: true,
        callbacks_seen: 1,
        selected_network_records: 1,
        ..Default::default()
    };
    worker.record(
        42,
        150,
        DecodedEvent::Failure {
            transport: Transport::Tcp,
            address_family: 2,
            failure_code: 1,
        },
    );
    worker.finish_correlation();
    assemble(&serde_json::to_vec(&worker).unwrap(), 3).unwrap()
}

fn evaluate(value: Value) -> ClosureInspection {
    let receipt = read(serde_json::to_vec(&value).unwrap().as_slice()).unwrap();
    check(receipt, fingerprint(&b"abc"[..], 3).unwrap(), etl())
}

fn expect_issue(value: Value, issue: Issue) {
    let result = evaluate(value);
    assert_eq!(result.closure.status, "unavailable");
    assert!(
        result.closure.issues.contains(&issue),
        "{:?}",
        result.closure.issues
    );
}

#[test]
fn consistent_synthetic_evidence_never_establishes_authority() {
    let result = evaluate(fixture());
    assert_eq!(result.closure.status, "consistent_unverified");
    assert!(result.closure.issues.is_empty());
    let value = serde_json::to_value(result).unwrap();
    for section in ["closure", "etl"] {
        for (field, value) in value[section].as_object().unwrap() {
            if field.ends_with("_verified")
                || field == "enforcement_active"
                || field == "baseline_compatible"
            {
                assert_eq!(*value, false, "{section}.{field}");
            }
        }
    }
}

#[test]
fn imported_source_label_does_not_grant_trust() {
    let mut value = fixture();
    value["source"] = json!("unverified_controller_export");
    let result = evaluate(value);
    assert_eq!(result.closure.status, "consistent_unverified");
    assert!(!result.closure.controller_authenticity_verified);
}

#[test]
fn rejects_binding_to_different_content_or_length() {
    for (field, replacement) in [("sha256", json!("0".repeat(64))), ("bytes", json!(4))] {
        let mut value = fixture();
        value["file"][field] = replacement;
        expect_issue(value, Issue::FileBindingMismatch);
    }
}

#[test]
fn missing_or_failed_start_is_not_an_existing_session_adoption() {
    for status in [Value::Null, json!(183), json!(5)] {
        let mut value = fixture();
        value["start_status"] = status;
        expect_issue(value, Issue::StartUnsuccessfulOrMissing);
    }
}

#[test]
fn null_false_or_omitted_declarations_remain_unknown() {
    for (field, issue) in [
        ("owns_session_from_start", Issue::SessionOwnershipUndeclared),
        (
            "configuration_unchanged",
            Issue::ConfigurationContinuityUndeclared,
        ),
    ] {
        for replacement in [Value::Null, json!(false)] {
            let mut value = fixture();
            value[field] = replacement;
            let result = evaluate(value);
            assert!(result.closure.issues.contains(&issue));
        }
        let mut value = fixture();
        value.as_object_mut().unwrap().remove(field);
        expect_issue(value, issue);
    }
}

#[test]
fn query_and_stop_require_success_and_complete_properties() {
    for (field, issue) in [
        (
            "query_after_start",
            Issue::InitialQueryUnsuccessfulOrMissing,
        ),
        ("stop", Issue::StopUnsuccessfulOrMissing),
    ] {
        for replacement in [
            Value::Null,
            json!({"api_status": 0, "properties": null}),
            json!({"api_status": 234, "properties": fixture()[field]["properties"]}),
            json!({"api_status": 4201, "properties": null}),
        ] {
            let mut value = fixture();
            value[field] = replacement;
            let result = evaluate(value);
            assert!(result.closure.issues.contains(&issue));
        }
    }
}

#[test]
fn both_snapshots_must_match_the_declared_session_and_flags() {
    for snapshot in ["query_after_start", "stop"] {
        for (field, replacement) in [
            (
                "session_guid",
                json!("b72f10ca-79ef-4ff6-95d9-8b3e7b190422"),
            ),
            ("enable_flags", json!(1)),
            ("log_file_mode", json!(SYSTEM_LOGGER | 2)),
        ] {
            let mut value = fixture();
            value[snapshot]["properties"][field] = replacement;
            expect_issue(value, Issue::SessionConfigurationMismatch);
        }
    }
}

#[test]
fn losses_at_either_boundary_invalidate_even_if_the_other_is_zero() {
    for snapshot in ["query_after_start", "stop"] {
        for counter in ["events_lost", "log_buffers_lost", "realtime_buffers_lost"] {
            let mut value = fixture();
            value[snapshot]["properties"][counter] = json!(1);
            expect_issue(value, Issue::LossReported);
        }
    }
}

#[test]
fn regressing_or_wrapping_counters_are_not_subtracted() {
    for counter in [
        "events_lost",
        "log_buffers_lost",
        "realtime_buffers_lost",
        "buffers_written",
    ] {
        let mut value = fixture();
        value["query_after_start"]["properties"][counter] = json!(u32::MAX);
        expect_issue(value, Issue::CounterRegression);
    }
    let mut value = fixture();
    value["stop"]["properties"]["buffers_written"] = json!(0);
    expect_issue(value, Issue::NoBuffersWritten);
}

#[test]
fn profile_excludes_private_realtime_circular_extra_providers_and_other_clocks() {
    for (field, values) in [
        (
            "log_file_mode",
            vec![1, SYSTEM_LOGGER | 2, SYSTEM_LOGGER | 0x100, 0x20801],
        ),
        ("enable_flags", vec![0, 1, 0x10001, ENABLE_FLAGS | 2]),
        ("clock_type", vec![0, 2, 3]),
    ] {
        for replacement in values {
            let mut value = fixture();
            value["intent"][field] = json!(replacement);
            expect_issue(value, Issue::UnsupportedProfileConfiguration);
        }
    }
    for guid in [
        "9e814aad-3204-11d2-9a82-006008a86939",
        "e8908abc-aa84-11d2-9a93-00805f85d7c6",
    ] {
        let mut value = fixture();
        value["intent"]["session_guid"] = json!(guid);
        expect_issue(value, Issue::UnsupportedProfileConfiguration);
    }
}

#[test]
fn sequential_zero_alias_is_accepted_without_accepting_other_bits() {
    let mut value = fixture();
    value["intent"]["log_file_mode"] = json!(SYSTEM_LOGGER);
    value["stop"]["properties"]["log_file_mode"] = json!(SYSTEM_LOGGER);
    assert_eq!(evaluate(value).closure.status, "consistent_unverified");
}

#[test]
fn header_mismatch_and_etl_failure_cannot_be_overridden_by_a_sidecar() {
    for change in 0..3 {
        let mut report = etl();
        match change {
            0 => report.observation.header.as_mut().unwrap().clock_type = 2,
            1 => report.observation.header = None,
            _ => report.status = "unavailable",
        }
        let value = fixture();
        let result = check(
            read(serde_json::to_vec(&value).unwrap().as_slice()).unwrap(),
            fingerprint(&b"abc"[..], 3).unwrap(),
            report,
        );
        assert_eq!(result.closure.status, "unavailable");
        assert!(result.closure.issues.contains(if change < 2 {
            &Issue::EtlHeaderMismatch
        } else {
            &Issue::EtlUnavailable
        }));
    }
}

#[test]
fn schema_rejects_unknown_authority_duplicate_keys_and_missing_counters() {
    for pointer in ["", "/file", "/intent", "/stop", "/stop/properties"] {
        let mut value = fixture();
        value.pointer_mut(pointer).unwrap()["coverage_verified"] = json!(true);
        assert!(read(serde_json::to_vec(&value).unwrap().as_slice()).is_err());
    }
    let mut value = fixture();
    value["stop"]["properties"]
        .as_object_mut()
        .unwrap()
        .remove("events_lost");
    assert!(read(serde_json::to_vec(&value).unwrap().as_slice()).is_err());
    let text =
        serde_json::to_string(&fixture())
            .unwrap()
            .replacen("{", "{\"schema_version\":1,", 1);
    assert!(read(text.as_bytes()).is_err());
}

#[test]
fn schema_values_are_bounded_canonical_and_not_silently_defaulted() {
    for (pointer, replacement) in [
        ("/schema_version", json!(2)),
        ("/source", json!("verified")),
        ("/profile", json!("custom")),
        ("/file/bytes", json!(0)),
        ("/file/bytes", json!(MAX_FILE_BYTES + 1)),
        ("/file/sha256", json!("A".repeat(64))),
        (
            "/intent/session_guid",
            json!("00000000-0000-0000-0000-000000000000"),
        ),
        ("/intent/session_guid", json!("private-marker")),
        ("/stop/properties/events_lost", json!(4294967296u64)),
    ] {
        let mut value = fixture();
        *value.pointer_mut(pointer).unwrap() = replacement;
        let error = read(serde_json::to_vec(&value).unwrap().as_slice()).unwrap_err();
        assert!(!error.to_string().contains("private-marker"));
    }
    assert!(read(vec![b' '; MAX_RECEIPT_BYTES as usize + 1].as_slice()).is_err());
}

#[test]
fn fingerprint_checks_known_digest_and_refuses_short_or_extra_input() {
    assert_eq!(
        fingerprint(&b"abc"[..], 3).unwrap(),
        fixture()["file"]["sha256"]
    );
    for (input, len) in [
        (&b"ab"[..], 3),
        (&b"abcd"[..], 3),
        (&b"abc"[..], 0),
        (&b"abc"[..], MAX_FILE_BYTES + 1),
    ] {
        assert!(fingerprint(input, len).is_err());
    }
}

#[test]
#[cfg(windows)]
fn native_constants_match_the_versioned_profile() {
    use windows_sys::Win32::System::Diagnostics::Etw::*;
    assert_eq!(SYSTEM_LOGGER, EVENT_TRACE_SYSTEM_LOGGER_MODE);
    assert_eq!(
        ENABLE_FLAGS,
        EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_NETWORK_TCPIP | EVENT_TRACE_FLAG_NO_SYSCONFIG
    );
}
