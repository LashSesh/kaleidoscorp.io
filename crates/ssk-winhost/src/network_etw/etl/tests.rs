use super::*;

fn header() -> Header {
    Header {
        source_windows_build: 0,
        pointer_bytes: 8,
        log_file_mode: 1,
        clock_type: 1,
        performance_frequency: "10000000".into(),
        session_start_filetime: "100".into(),
        session_end_filetime: "200".into(),
        events_lost: 0,
        buffers_lost: 0,
        buffers_written: 1,
    }
}

fn event(kind: EventKind) -> DecodedEvent {
    DecodedEvent::Network {
        transport: Transport::Tcp,
        kind,
        payload_pid: 42,
        reported_size: 100,
        source: super::super::EventEndpoint {
            address: "127.0.0.1".parse().unwrap(),
            port: 1,
        },
        destination: super::super::EventEndpoint {
            address: "127.0.0.1".parse().unwrap(),
            port: 2,
        },
        connection_id: 1,
        sequence_number: 5,
    }
}

#[test]
fn rejects_unfinalized_lossy_and_nonsequential_headers() {
    for (mode, failure) in [
        (2, Failure::UnsupportedFileMode),
        (4, Failure::UnsupportedFileMode),
        (8, Failure::UnsupportedFileMode),
    ] {
        let mut h = header();
        h.log_file_mode = mode;
        assert_eq!(h.failure(), Some(failure));
    }
    let mut h = header();
    h.session_end_filetime = "0".into();
    assert_eq!(h.failure(), Some(Failure::UnfinalizedHeader));
    let mut h = header();
    h.events_lost = 1;
    assert_eq!(h.failure(), Some(Failure::LossReported));
    let mut h = header();
    h.buffers_lost = 1;
    assert_eq!(h.failure(), Some(Failure::LossReported));
}

#[test]
fn invalid_clock_and_pointer_metadata_never_become_zero_loss_success() {
    for (pointer, clock, freq) in [(0, 1, "100"), (8, 0, "100"), (8, 1, "0"), (8, 1, "-1")] {
        let mut h = header();
        h.pointer_bytes = pointer;
        h.clock_type = clock;
        h.performance_frequency = freq.into();
        assert_eq!(h.failure(), Some(Failure::InvalidHeader));
    }
}

#[test]
fn separate_retransmit_copy_and_failure_buckets_and_no_authority() {
    let mut report = WorkerReport {
        header: Some(header()),
        process_trace_completed: true,
        callbacks_seen: 4,
        selected_network_records: 4,
        ..Default::default()
    };
    report.record(7, 100, event(EventKind::Send));
    report.record(7, 101, event(EventKind::Retransmit));
    report.record(42, 102, event(EventKind::TcpCopy));
    report.record(
        7,
        103,
        DecodedEvent::Failure {
            transport: Transport::Udp,
            address_family: 2,
            failure_code: 9,
        },
    );
    report.finish_correlation();
    let result = assemble(&serde_json::to_vec(&report).unwrap(), 1000).unwrap();
    let json = serde_json::to_value(result).unwrap();
    assert_eq!(json["status"], "decoded_file");
    assert_eq!(json["tcp"]["reported_send_size_sum"], 100);
    assert_eq!(json["tcp"]["reported_retransmit_size_sum"], 100);
    assert_eq!(json["tcp"]["reported_tcp_copy_size_sum"], 100);
    assert_eq!(json["udp"]["unattributed_failure_events"], 1);
    assert_eq!(json["header_payload_pid_mismatches"], 2);
    for key in [
        "trace_authenticity_verified",
        "loss_completeness_verified",
        "process_identity_verified",
        "coverage_verified",
        "application_byte_counts_verified",
        "attempt_outcomes_available",
        "baseline_compatible",
        "enforcement_active",
    ] {
        assert_eq!(json[key], false);
    }
}

#[test]
fn timestamp_regression_does_not_increment_prefix_and_first_fault_sticks() {
    let mut report = WorkerReport::default();
    report.record(42, 100, event(EventKind::Send));
    report.record(42, 99, event(EventKind::Receive));
    report.fail(Failure::ProcessTrace { code: 1223 });
    report.record(42, 101, event(EventKind::Send));
    assert_eq!(report.failure, Some(Failure::TimestampRegression));
    assert_eq!(report.decoded_prefix_records, 1);
    assert_eq!(report.tcp.receive_events, 0);
}

#[test]
fn pipe_protocol_rejects_forged_authority_duplicate_fields_and_truncation() {
    let mut report = WorkerReport {
        failure: Some(Failure::NoSupportedNetworkEvents),
        ..Default::default()
    };
    report.finish_correlation();
    let encoded = serde_json::to_vec(&report).unwrap();
    assert!(assemble(&encoded, 100).is_ok());
    let mut json = serde_json::to_value(report).unwrap();
    json["enforcement_active"] = true.into();
    assert!(assemble(&serde_json::to_vec(&json).unwrap(), 100).is_err());
    assert!(assemble(&encoded[..encoded.len() - 1], 100).is_err());
    let mut duplicate = b"{\"header\":null,".to_vec();
    duplicate.extend_from_slice(&encoded[1..]);
    assert!(assemble(&duplicate, 100).is_err());
    assert!(assemble(&vec![b' '; MAX_REPORT_BYTES + 1], 100).is_err());
}

#[test]
fn pipe_protocol_rejects_impossible_counts_and_false_success() {
    let mut report = WorkerReport::default();
    assert!(!report.validate());
    report.failure = Some(Failure::InvalidRecord);
    report.decoded_prefix_records = 1;
    assert!(!report.validate());
    report.decoded_prefix_records = 0;
    report.callbacks_seen = MAX_CALLBACKS + 1;
    assert!(!report.validate());
    report.callbacks_seen = 0;
    report.tcp.reported_send_size_sum = 1;
    assert!(!report.validate());
}

#[test]
fn complete_correlation_survives_ipc_but_cannot_assert_identity_or_forge_counts() {
    use crate::network_etw::process_lifecycle::{Event, Kind};
    let mut report = WorkerReport {
        header: Some(header()),
        process_trace_completed: true,
        callbacks_seen: 3,
        process_provider_records: 2,
        selected_network_records: 1,
        ..Default::default()
    };
    report.process_record(
        999,
        10,
        Event {
            pid: 42,
            key: 123,
            kind: Kind::Start,
        },
    );
    report.record(42, 15, event(EventKind::Send));
    report.process_record(
        999,
        20,
        Event {
            pid: 42,
            key: 123,
            kind: Kind::End,
        },
    );
    report.finish_correlation();
    let encoded = serde_json::to_vec(&report).unwrap();
    let result = serde_json::to_value(assemble(&encoded, 100).unwrap()).unwrap();
    assert_eq!(result["process_correlation"]["start_bounded_records"], 1);
    assert_eq!(result["process_identity_verified"], false);
    assert_eq!(result["header_payload_process_pid_mismatches"], 2);
    assert!(result.get("history").is_none());
    let mut wire: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    wire["process_correlation"]["process_identity_verified"] = true.into();
    assert!(assemble(&serde_json::to_vec(&wire).unwrap(), 100).is_err());
    wire["process_correlation"]
        .as_object_mut()
        .unwrap()
        .remove("process_identity_verified");
    wire["process_correlation"]["start_bounded_records"] = 99.into();
    assert!(assemble(&serde_json::to_vec(&wire).unwrap(), 100).is_err());
}
