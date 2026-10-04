use super::*;

fn record(state: &Mutex<WorkerReport>, payload: &mut [u8]) -> EVENT_RECORD {
    let mut record: EVENT_RECORD = unsafe { zeroed() };
    record.UserContext = (state as *const Mutex<WorkerReport>).cast_mut().cast();
    record.EventHeader.ProviderId = GUID::from_u128(0x9a280ac0_c8e0_11d1_84e2_00c04fb998a2);
    record.EventHeader.Flags = 0x140;
    record.EventHeader.EventDescriptor.Version = 2;
    record.EventHeader.EventDescriptor.Opcode = 10;
    record.EventHeader.TimeStamp = 100;
    record.UserData = payload.as_mut_ptr().cast();
    record.UserDataLength = payload.len() as u16;
    record
}

#[test]
fn callback_preserves_original_record_for_native_tdh() {
    let state = Mutex::new(WorkerReport::default());
    let mut payload = [0u8; 128];
    payload[..4].copy_from_slice(&42u32.to_le_bytes());
    payload[4..8].copy_from_slice(&123u32.to_le_bytes());
    let mut record = record(&state, &mut payload);
    unsafe {
        event_callback(&mut record);
    }
    let state = state.into_inner().unwrap();
    assert_eq!(state.failure, None);
    assert_eq!(state.decoded_prefix_records, 1);
    assert_eq!(state.tcp.reported_send_size_sum, 123);
}

#[test]
fn unknown_provider_is_counted_but_unknown_network_schema_stops() {
    let state = Mutex::new(WorkerReport::default());
    let mut payload = [0u8; 8];
    let mut rec = record(&state, &mut payload);
    rec.EventHeader.ProviderId = GUID::from_u128(1);
    unsafe {
        event_callback(&mut rec);
    }
    rec.EventHeader.ProviderId = GUID::from_u128(0x9a280ac0_c8e0_11d1_84e2_00c04fb998a2);
    rec.EventHeader.EventDescriptor.Version = 99;
    unsafe {
        event_callback(&mut rec);
        event_callback(&mut rec);
    }
    let state = state.into_inner().unwrap();
    assert_eq!(state.ignored_provider_records, 1);
    assert_eq!(state.callbacks_seen, 2);
    assert!(matches!(state.failure, Some(Failure::Decode { .. })));
}

#[test]
fn invalid_pointer_and_extended_payload_are_rejected_before_tdh() {
    for extended in [false, true] {
        let state = Mutex::new(WorkerReport::default());
        let mut payload = [0u8; 8];
        let mut rec = record(&state, &mut payload);
        if extended {
            rec.ExtendedDataCount = 1;
        } else {
            rec.UserData = ptr::null_mut();
        }
        unsafe {
            event_callback(&mut rec);
        }
        assert_eq!(
            state.into_inner().unwrap().failure,
            Some(Failure::InvalidRecord)
        );
    }
}

#[test]
fn callback_limits_cancel_buffers_without_inventing_loss_counters() {
    for (callbacks, selected, expected) in [
        (MAX_CALLBACKS, 0, Failure::CallbackLimit),
        (
            MAX_NETWORK_RECORDS,
            MAX_NETWORK_RECORDS,
            Failure::NetworkRecordLimit,
        ),
    ] {
        let state = Mutex::new(WorkerReport {
            callbacks_seen: callbacks,
            selected_network_records: selected,
            ..Default::default()
        });
        let mut payload = [0u8; 8];
        let mut rec = record(&state, &mut payload);
        unsafe {
            event_callback(&mut rec);
        }
        let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { zeroed() };
        logfile.Context = (&state as *const Mutex<WorkerReport>).cast_mut().cast();
        logfile.EventsLost = u32::MAX; // unused Windows member must not be consumed
        assert_eq!(unsafe { buffer_callback(&mut logfile) }, 0);
        assert_eq!(state.into_inner().unwrap().failure, Some(expected));
    }
}

#[test]
fn explicit_lost_event_is_never_ignored_as_an_unrelated_provider() {
    let state = Mutex::new(WorkerReport::default());
    let mut payload = [];
    let mut rec = record(&state, &mut payload);
    rec.EventHeader.ProviderId = GUID::from_u128(0x6a399ae0_4bc6_4de9_870b_3657f8947e7e);
    rec.EventHeader.EventDescriptor.Opcode = 32;
    unsafe {
        event_callback(&mut rec);
    }
    let report = state.into_inner().unwrap();
    assert_eq!(report.failure, Some(Failure::LossReported));
    assert_eq!(report.ignored_provider_records, 0);
}

#[test]
fn native_tdh_resolves_process_versions_opcodes_and_pointer_widths() {
    use crate::network_etw::{process_lifecycle, windows::decode_process_record};
    for version in 2..=4 {
        for width in [4, 8] {
            for opcode in 1..=4 {
                let state = Mutex::new(WorkerReport::default());
                let mut payload = [0u8; 128];
                payload[..width].copy_from_slice(&123u64.to_le_bytes()[..width]);
                payload[width..width + 4].copy_from_slice(&42u32.to_le_bytes());
                let mut rec = record(&state, &mut payload);
                rec.EventHeader.ProviderId = GUID::from_u128(process_lifecycle::PROVIDER_ID);
                rec.EventHeader.Flags = if width == 4 { 0x120 } else { 0x140 };
                rec.EventHeader.ProcessId = 999; // header context is not the child PID
                rec.EventHeader.EventDescriptor.Version = version;
                rec.EventHeader.EventDescriptor.Opcode = opcode;
                let schema = process_lifecycle::schema(
                    version,
                    opcode,
                    rec.EventHeader.Flags,
                    payload.len(),
                    100,
                )
                .unwrap();
                let event = decode_process_record(&rec, schema).unwrap_or_else(|e| {
                    panic!("version={version} width={width} opcode={opcode}: {e}")
                });
                assert_eq!(event.pid, 42);
                assert_eq!(event.key, 123);
            }
        }
    }
}

fn emit_process(state: &Mutex<WorkerReport>, ticks: i64, key: u64, opcode: u8) {
    let mut payload = [0u8; 128];
    payload[..8].copy_from_slice(&key.to_le_bytes());
    payload[8..12].copy_from_slice(&42u32.to_le_bytes());
    let mut rec = record(state, &mut payload);
    rec.EventHeader.ProviderId =
        GUID::from_u128(crate::network_etw::process_lifecycle::PROVIDER_ID);
    rec.EventHeader.EventDescriptor.Version = 4;
    rec.EventHeader.EventDescriptor.Opcode = opcode;
    rec.EventHeader.TimeStamp = ticks;
    rec.EventHeader.ProcessId = 999;
    unsafe {
        event_callback(&mut rec);
    }
}

fn emit_network(state: &Mutex<WorkerReport>, ticks: i64) {
    let mut payload = [0u8; 128];
    payload[..4].copy_from_slice(&42u32.to_le_bytes());
    let mut rec = record(state, &mut payload);
    rec.EventHeader.TimeStamp = ticks;
    unsafe {
        event_callback(&mut rec);
    }
}

#[test]
fn native_callbacks_correlate_reused_pid_only_after_complete_input() {
    let state = Mutex::new(WorkerReport::default());
    emit_process(&state, 10, 1, 1);
    emit_network(&state, 15);
    emit_process(&state, 20, 1, 2);
    emit_process(&state, 30, 2, 1);
    emit_network(&state, 35);
    emit_process(&state, 40, 2, 2);
    let mut report = state.into_inner().unwrap();
    assert_eq!(report.failure, None);
    assert_eq!(report.process_provider_records, 4);
    assert_eq!(report.decoded_process_records, 4);
    assert_eq!(report.header_payload_process_pid_mismatches, 4);
    // Synthetic callback test only; it does not attest a real completed capture.
    report.process_trace_completed = true;
    report.finish_correlation();
    let json = serde_json::to_value(report.process_correlation).unwrap();
    assert_eq!(json["start_bounded_records"], 2);
    assert_eq!(json["pid_lifetime_transitions"], 1);
    assert!(json.get("key").is_none());
    assert!(json.get("command_line").is_none());
}

#[test]
fn late_native_loss_marker_invalidates_an_already_closed_process_interval() {
    let state = Mutex::new(WorkerReport::default());
    emit_process(&state, 10, 1, 1);
    emit_network(&state, 15);
    emit_process(&state, 20, 1, 2);
    let mut payload = [];
    let mut rec = record(&state, &mut payload);
    rec.EventHeader.ProviderId = GUID::from_u128(0x6a399ae0_4bc6_4de9_870b_3657f8947e7e);
    rec.EventHeader.TimeStamp = 30;
    unsafe {
        event_callback(&mut rec);
    }
    let mut report = state.into_inner().unwrap();
    report.process_trace_completed = true;
    report.finish_correlation();
    let json = serde_json::to_value(report.process_correlation).unwrap();
    assert_eq!(json["status"], "unavailable");
    assert_eq!(json["start_bounded_records"], 0);
    assert_eq!(json["invalidated_records"], 1);
}

#[test]
fn auxiliary_process_events_cannot_supply_starts_or_stops_and_unknown_versions_fail() {
    let state = Mutex::new(WorkerReport::default());
    for opcode in [11, 32, 33, 39] {
        emit_process(&state, 10, 1, opcode);
    }
    let mut payload = [0u8; 128];
    let mut rec = record(&state, &mut payload);
    rec.EventHeader.ProviderId =
        GUID::from_u128(crate::network_etw::process_lifecycle::PROVIDER_ID);
    rec.EventHeader.EventDescriptor.Version = 255;
    rec.EventHeader.EventDescriptor.Opcode = 1;
    unsafe {
        event_callback(&mut rec);
    }
    let report = state.into_inner().unwrap();
    assert_eq!(report.auxiliary_process_records, 4);
    assert_eq!(report.decoded_process_records, 0);
    assert!(matches!(
        report.failure,
        Some(Failure::ProcessDecode { .. })
    ));
}

#[test]
fn oversized_process_payload_and_process_record_limit_fail_before_tdh() {
    let state = Mutex::new(WorkerReport::default());
    let mut payload = [0u8; 8193];
    let mut rec = record(&state, &mut payload);
    rec.EventHeader.ProviderId =
        GUID::from_u128(crate::network_etw::process_lifecycle::PROVIDER_ID);
    rec.EventHeader.EventDescriptor.Opcode = 1;
    unsafe {
        event_callback(&mut rec);
    }
    assert!(matches!(
        state.into_inner().unwrap().failure,
        Some(Failure::ProcessDecode { .. })
    ));
    let state = Mutex::new(WorkerReport {
        process_provider_records: history::MAX_PROCESS_RECORDS,
        ..Default::default()
    });
    emit_process(&state, 10, 1, 1);
    assert_eq!(
        state.into_inner().unwrap().failure,
        Some(Failure::ProcessHistory {
            reason: history::Fault::ProcessRecordLimit
        })
    );
}

#[test]
fn concurrent_mixed_width_process_and_network_properties_keep_their_event_context() {
    std::thread::scope(|scope| {
        for worker in 0..4 {
            scope.spawn(move || {
                for iteration in 0..16 {
                    let width = if (worker + iteration) % 2 == 0 { 4 } else { 8 };
                    let state = Mutex::new(WorkerReport::default());
                    let mut payload = [0u8; 128];
                    payload[..width].copy_from_slice(&123u64.to_le_bytes()[..width]);
                    payload[width..width + 4].copy_from_slice(&42u32.to_le_bytes());
                    let mut rec = record(&state, &mut payload);
                    rec.EventHeader.ProviderId =
                        GUID::from_u128(crate::network_etw::process_lifecycle::PROVIDER_ID);
                    rec.EventHeader.EventDescriptor.Version = 4;
                    rec.EventHeader.EventDescriptor.Opcode = 1;
                    rec.EventHeader.Flags = if width == 4 { 0x120 } else { 0x140 };
                    unsafe {
                        event_callback(&mut rec);
                    }
                    payload.fill(0);
                    payload[..4].copy_from_slice(&42u32.to_le_bytes());
                    let mut rec = record(&state, &mut payload);
                    rec.EventHeader.Flags = if width == 4 { 0x120 } else { 0x140 };
                    rec.EventHeader.TimeStamp = 101;
                    unsafe {
                        event_callback(&mut rec);
                    }
                    let report = state.into_inner().unwrap();
                    assert_eq!(report.failure, None);
                    assert_eq!(report.decoded_process_records, 1);
                    assert_eq!(report.decoded_prefix_records, 1);
                }
            });
        }
    });
}
