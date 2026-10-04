use super::*;

const EXAMPLE: &[u8] = include_bytes!("../../../../../docs/examples/etw-network-replay.json");
fn input() -> ReplayInput {
    serde_json::from_slice(EXAMPLE).unwrap()
}

fn fake_decode(raw: &RawEvent) -> Result<DecodedEvent, DecodeError> {
    let selected = super::super::schema(raw)?;
    if selected.kind == EventKind::Failure {
        return Ok(DecodedEvent::Failure {
            transport: selected.transport,
            address_family: 2,
            failure_code: 5,
        });
    }
    Ok(DecodedEvent::Network {
        transport: selected.transport,
        kind: selected.kind,
        payload_pid: 4321,
        reported_size: u32::from_le_bytes(raw.payload[4..8].try_into().unwrap()),
        source: super::super::EventEndpoint {
            address: "192.0.2.1".parse().unwrap(),
            port: 40000,
        },
        destination: super::super::EventEndpoint {
            address: "192.0.2.5".parse().unwrap(),
            port: 443,
        },
        connection_id: 1,
        sequence_number: 123,
    })
}

fn run(input: ReplayInput) -> ReplayReport {
    audit_with(input, fake_decode, || false).unwrap()
}
fn unavailable(input: ReplayInput, expected: Unavailable) {
    assert_eq!(
        run(input).status(),
        AuditStatus::Unavailable { reason: expected }
    );
}

#[test]
fn missing_loss_statistics_never_mean_zero_loss() {
    for missing_start in [true, false] {
        let mut input = input();
        if missing_start {
            input.loss_start = None;
        } else {
            input.loss_end = None;
        }
        let report = audit_with(input, |_| panic!("must not invoke decoder"), || false).unwrap();
        assert_eq!(
            report.status(),
            AuditStatus::Unavailable {
                reason: Unavailable::MissingLossCounters
            }
        );
        assert_eq!(report.decoded_prefix_records, 0);
    }
}

#[test]
fn each_native_or_consumer_loss_counter_invalidates_the_batch() {
    for at_start in [true, false] {
        for index in 0..4 {
            let mut input = input();
            let mut counters = LossCounters::default();
            match index {
                0 => counters.events_lost = 1,
                1 => counters.log_buffers_lost = 1,
                2 => counters.realtime_buffers_lost = 1,
                _ => counters.consumer_dropped = 1,
            };
            input.loss_end = Some(counters);
            if at_start {
                input.loss_start = Some(counters);
            }
            unavailable(input, Unavailable::LossReported);
        }
    }
}

#[test]
fn decreased_counters_are_not_a_clean_restart_of_the_same_epoch() {
    let mut input = input();
    input.loss_start.as_mut().unwrap().events_lost = 1;
    unavailable(input, Unavailable::LossCounterRegression);
}

#[test]
fn completion_and_record_count_are_required_even_without_reported_loss() {
    let mut missing_end = input();
    missing_end.collection_completed = false;
    unavailable(missing_end, Unavailable::IncompleteCollection);
    let mut short = input();
    short.records.pop();
    unavailable(short, Unavailable::RecordCountMismatch);
    let mut empty = input();
    empty.records.clear();
    empty.expected_records = 0;
    unavailable(empty, Unavailable::EmptyCollection);
}

#[test]
fn ordinals_cannot_duplicate_skip_or_start_after_a_missing_prefix() {
    for (index, ordinal, prefix) in [(0, 1, 0), (1, 0, 1), (2, 3, 2)] {
        let mut input = input();
        input.records[index].ordinal = ordinal;
        let report = run(input);
        assert_eq!(
            report.status(),
            AuditStatus::Unavailable {
                reason: Unavailable::OrdinalDiscontinuity
            }
        );
        assert_eq!(report.decoded_prefix_records, prefix);
    }
}

#[test]
fn backwards_or_outside_timestamps_never_produce_a_decoded_batch() {
    let mut backwards = input();
    backwards.records[1].event.timestamp_ticks = 99;
    unavailable(backwards, Unavailable::TimestampRegression);
    let mut at_end = input();
    at_end.records[0].event.timestamp_ticks = at_end.end_ticks;
    unavailable(at_end, Unavailable::TimestampOutsideRange);
    let mut before_start = input();
    before_start.start_ticks = 101;
    unavailable(before_start, Unavailable::TimestampOutsideRange);
}

#[test]
fn the_first_decode_fault_stops_the_batch_and_keeps_prefix_explicit() {
    let mut calls = 0;
    let report = audit_with(
        input(),
        |event| {
            calls += 1;
            if calls == 2 {
                Err(DecodeError::UnsupportedVersion)
            } else {
                fake_decode(event)
            }
        },
        || false,
    )
    .unwrap();
    assert_eq!(calls, 2);
    assert_eq!(report.decoded_prefix_records, 1);
    assert_eq!(report.tcp().reported_send_size_sum, 1500);
    assert_eq!(
        report.status(),
        AuditStatus::Unavailable {
            reason: Unavailable::Decode {
                reason: DecodeError::UnsupportedVersion
            }
        }
    );
}

#[test]
fn time_budget_prevents_work_and_discards_a_late_decoder_return() {
    let report = audit_with(input(), |_| panic!("must not decode"), || true).unwrap();
    assert_eq!(
        report.status(),
        AuditStatus::Unavailable {
            reason: Unavailable::DecodeBudgetExceeded
        }
    );
    let mut checks = 0;
    let report = audit_with(input(), fake_decode, || {
        checks += 1;
        checks > 1
    })
    .unwrap();
    assert_eq!(
        report.status(),
        AuditStatus::Unavailable {
            reason: Unavailable::DecodeBudgetExceeded
        }
    );
    assert_eq!(report.decoded_prefix_records, 0);
    assert_eq!(report.tcp().reported_send_size_sum, 0);
}

#[test]
fn retransmit_and_unattributed_failure_never_become_new_payload_or_failed_attempts() {
    let report = run(input());
    assert_eq!(report.status(), AuditStatus::DecodedInput);
    assert_eq!(report.tcp().send_events, 1);
    assert_eq!(report.tcp().reported_send_size_sum, 1500);
    assert_eq!(report.tcp().reported_retransmit_size_sum, 1000);
    assert_eq!(report.tcp().unattributed_failure_events, 1);
    assert_eq!(report.udp().reported_receive_size_sum, 128);
    assert_eq!(report.header_payload_pid_mismatches, 3);
    let json = serde_json::to_value(report).unwrap();
    for flag in [
        "trace_authenticity_verified",
        "process_identity_verified",
        "coverage_verified",
        "application_byte_counts_verified",
        "attempt_outcomes_available",
        "baseline_compatible",
        "enforcement_active",
    ] {
        assert_eq!(json[flag], false);
    }
    assert!(json.get("verdict").is_none());
}

#[test]
fn tcp_copy_connect_and_reconnect_are_separate_from_send_receive_sizes() {
    let mut data = input();
    data.records.truncate(1);
    let base = data.records[0].clone();
    data.records = (0..4)
        .map(|i| {
            let mut r = base.clone();
            r.ordinal = i;
            r.event.opcode = [18, 12, 16, 15][i as usize];
            r
        })
        .collect();
    let report = run(data);
    assert_eq!(report.tcp().reported_tcp_copy_size_sum, 1500);
    assert_eq!(report.tcp().connect_events, 1);
    assert_eq!(report.tcp().reconnect_events, 1);
    assert_eq!(report.tcp().accept_events, 1);
    assert_eq!(report.tcp().reported_send_size_sum, 0);
    assert_eq!(report.tcp().reported_receive_size_sum, 0);
}

#[test]
fn maximum_record_and_scalar_values_fit_without_truncation() {
    let mut input = input();
    let mut base = input.records[0].clone();
    base.event.payload[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    input.records = (0..MAX_RECORDS)
        .map(|i| {
            let mut r = base.clone();
            r.ordinal = i as u64;
            r
        })
        .collect();
    input.expected_records = MAX_RECORDS as u32;
    let report = run(input);
    assert_eq!(report.status(), AuditStatus::DecodedInput);
    assert_eq!(
        report.tcp().reported_send_size_sum,
        u64::from(u32::MAX) * MAX_RECORDS as u64
    );
}

#[test]
fn unsupported_envelopes_and_excess_records_are_rejected_before_decoding() {
    let mut invalid = vec![input(); 7];
    invalid[0].schema_version = 2;
    invalid[1].source_epoch = "forged\nlog".into();
    invalid[2].qpc_frequency = 0;
    invalid[3].qpc_frequency = 10_000_000_001;
    invalid[4].end_ticks = 0;
    invalid[5].end_ticks = 60_001;
    invalid[6].end_ticks = u64::MAX;
    for input in invalid {
        assert!(matches!(
            audit_with(input, |_| panic!("must not decode"), || false),
            Err(ReplayError::InvalidEnvelope)
        ));
    }
    let mut too_many = input();
    too_many.records = vec![too_many.records[0].clone(); MAX_RECORDS + 1];
    assert!(matches!(
        audit_with(too_many, fake_decode, || false),
        Err(ReplayError::TooLarge)
    ));
}

#[test]
fn json_cannot_assert_trust_extend_the_schema_or_hide_duplicate_fields() {
    let original: serde_json::Value = serde_json::from_slice(EXAMPLE).unwrap();
    let mut invalid = vec![original.clone(); 6];
    invalid[0]["provenance"] = "verified_os_capture".into();
    invalid[1]["enforce"] = true.into();
    invalid[2]["records"][0]["event"]["trusted_pid"] = true.into();
    invalid[3]["records"][0]["event"]["timestamp_ticks"] = 1.5.into();
    invalid[4]["loss_end"]["events_lost"] = "0".into();
    invalid[5]["records"][0]["event"]["payload"][0] = 256.into();
    for input in invalid {
        assert!(matches!(
            read_and_audit(serde_json::to_vec(&input).unwrap().as_slice()),
            Err(ReplayError::InvalidJson)
        ));
    }
    let duplicated = String::from_utf8(EXAMPLE.to_vec()).unwrap().replacen(
        "\"schema_version\": 1",
        "\"schema_version\": 1, \"schema_version\": 1",
        1,
    );
    assert!(matches!(
        read_and_audit(duplicated.as_bytes()),
        Err(ReplayError::InvalidJson)
    ));
    let trailing = [EXAMPLE, b"{}"].concat();
    assert!(matches!(
        read_and_audit(trailing.as_slice()),
        Err(ReplayError::InvalidJson)
    ));
}

#[test]
fn replay_reads_at_most_the_byte_limit_plus_one_probe_byte() {
    struct Endless(usize);
    impl Read for Endless {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            b.fill(b' ');
            self.0 += b.len();
            Ok(b.len())
        }
    }
    let mut endless = Endless(0);
    assert!(matches!(
        read_and_audit(&mut endless),
        Err(ReplayError::TooLarge)
    ));
    assert_eq!(endless.0, MAX_REPLAY_BYTES + 1);
}

#[cfg(windows)]
#[test]
fn documented_raw_fixture_is_resolved_by_real_windows_tdh() {
    let report = read_and_audit(EXAMPLE).unwrap();
    assert_eq!(report.status(), AuditStatus::DecodedInput);
    assert_eq!(report.decoded_prefix_records, 4);
    assert_eq!(report.tcp().reported_send_size_sum, 1500);
    assert_eq!(report.tcp().reported_retransmit_size_sum, 1000);
    assert_eq!(report.udp().reported_receive_size_sum, 128);
    assert_eq!(report.tcp().unattributed_failure_events, 1);
}
