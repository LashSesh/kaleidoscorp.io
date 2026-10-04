use super::*;
use std::{
    mem::zeroed,
    os::windows::ffi::OsStrExt,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
    sync::Mutex,
};
use windows_sys::{
    core::GUID,
    Win32::{Foundation::GetLastError, System::Diagnostics::Etw::*},
};

struct Trace(PROCESSTRACE_HANDLE);
impl Drop for Trace {
    fn drop(&mut self) {
        // SAFETY: uniquely owned successful OpenTrace result; no processing runs
        // once read() returns. Destruction never touches an ETW controller.
        unsafe {
            CloseTrace(self.0);
        }
    }
}

pub(super) fn read(path: &Path) -> WorkerReport {
    let mut name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let state = Mutex::new(WorkerReport::default());
    // SAFETY: POD; all callback/context/name pointers assigned before OpenTrace.
    let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { zeroed() };
    logfile.LogFileName = name.as_mut_ptr();
    logfile.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    logfile.Anonymous2.EventRecordCallback = Some(event_callback);
    logfile.BufferCallback = Some(buffer_callback);
    logfile.Context = (&state as *const Mutex<WorkerReport>).cast_mut().cast();
    // File mode only: LoggerName stays NULL, REAL_TIME is never selected.
    let raw = unsafe { OpenTraceW(&mut logfile) };
    if raw.Value == usize::MAX as u64 {
        let mut report = state.into_inner().unwrap_or_else(|e| e.into_inner());
        report.fail(Failure::OpenTrace {
            code: unsafe { GetLastError() },
        });
        report.finish_correlation();
        return report;
    }
    let trace = Trace(raw);
    let header = &logfile.LogfileHeader;
    // OpenTrace has normalized TRACE_LOGFILE_HEADER; never reinterpret the
    // first event payload as this pointer-width-dependent structure.
    let info = unsafe { header.Anonymous2.Anonymous };
    let header = Header {
        source_windows_build: header.ProviderVersion,
        pointer_bytes: info.PointerSize,
        log_file_mode: header.LogFileMode,
        clock_type: header.ReservedFlags,
        performance_frequency: header.PerfFreq.to_string(),
        session_start_filetime: header.StartTime.to_string(),
        session_end_filetime: header.EndTime.to_string(),
        events_lost: info.EventsLost,
        buffers_lost: header.BuffersLost,
        buffers_written: header.BuffersWritten,
    };
    let failure = header.failure();
    {
        let mut report = state.lock().unwrap_or_else(|e| e.into_inner());
        report.header = Some(header);
        if let Some(failure) = failure {
            report.fail(failure);
        }
    }
    if state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .failure
        .is_none()
    {
        // SAFETY: single live file consumer and live callback context. This can
        // block indefinitely; only the supervised child is permitted to call it.
        let code = unsafe { ProcessTrace(&trace.0, 1, ptr::null(), ptr::null()) };
        let mut report = state.lock().unwrap_or_else(|e| e.into_inner());
        report.process_trace_completed = code == 0;
        if code != 0 {
            report.fail(Failure::ProcessTrace { code });
        }
        if report.decoded_prefix_records == 0 {
            report.fail(Failure::NoSupportedNetworkEvents);
        }
    }
    // Explicit close lets failure remain visible. Forget only after closing.
    let close = unsafe { CloseTrace(trace.0) };
    std::mem::forget(trace);
    let mut report = state.into_inner().unwrap_or_else(|e| e.into_inner());
    if close != 0 {
        report.fail(Failure::CloseTrace { code: close });
    }
    report.finish_correlation();
    report
}

unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
    // Windows supplies callback-lifetime record/context pointers, never pointers
    // from the serialized ETL payload. No references escape the callback.
    if record.is_null() {
        return;
    }
    let record = unsafe { &*record };
    if record.UserContext.is_null() {
        return;
    }
    let state = unsafe { &*record.UserContext.cast::<Mutex<WorkerReport>>() };
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut report = state.lock().unwrap_or_else(|e| e.into_inner());
        if report.failure.is_some() {
            return;
        }
        if report.callbacks_seen >= MAX_CALLBACKS {
            report.fail(Failure::CallbackLimit);
            return;
        }
        report.callbacks_seen += 1;
        let guid = record.EventHeader.ProviderId;
        // Classic kernel LostEvent task GUID, also used by Microsoft's
        // TraceEvent parser. A loss marker must not vanish among other providers.
        if same_guid(
            guid,
            GUID::from_u128(0x6a399ae0_4bc6_4de9_870b_3657f8947e7e),
        ) {
            report.fail(Failure::LossReported);
            return;
        }
        if same_guid(
            guid,
            GUID::from_u128(super::super::process_lifecycle::PROVIDER_ID),
        ) {
            consume_process(&mut report, record);
            return;
        }
        let provider = if same_guid(
            guid,
            GUID::from_u128(0x9a280ac0_c8e0_11d1_84e2_00c04fb998a2),
        ) {
            super::super::TCP_PROVIDER
        } else if same_guid(
            guid,
            GUID::from_u128(0xbf3a50c5_a9c9_4988_a005_2df0b7c80f80),
        ) {
            super::super::UDP_PROVIDER
        } else {
            report.ignored_provider_records += 1;
            return;
        };
        if report.selected_network_records >= MAX_NETWORK_RECORDS {
            report.fail(Failure::NetworkRecordLimit);
            return;
        }
        report.selected_network_records += 1;
        if record.ExtendedDataCount != 0
            || record.UserData.is_null()
            || record.UserDataLength == 0
            || usize::from(record.UserDataLength) > super::super::MAX_PAYLOAD_BYTES
            || record.EventHeader.TimeStamp < 0
        {
            report.fail(Failure::InvalidRecord);
            return;
        }
        // Only the schema selector uses an owned bounded copy. TDH receives the
        // ORIGINAL EVENT_RECORD with its native descriptor/header/buffer context.
        let raw = super::super::RawEvent {
            provider_guid: provider.into(),
            version: record.EventHeader.EventDescriptor.Version,
            opcode: record.EventHeader.EventDescriptor.Opcode,
            flags: record.EventHeader.Flags,
            header_pid: record.EventHeader.ProcessId,
            timestamp_ticks: record.EventHeader.TimeStamp as u64,
            payload: unsafe {
                std::slice::from_raw_parts(
                    record.UserData.cast::<u8>(),
                    usize::from(record.UserDataLength),
                )
            }
            .to_vec(),
        };
        let decoded = super::super::schema(&raw)
            .and_then(|schema| super::super::windows::decode_record(record, schema));
        match decoded {
            Ok(event) => report.record(raw.header_pid, raw.timestamp_ticks, event),
            Err(error) => report.fail(Failure::Decode {
                detail: error.to_string(),
            }),
        }
    }));
    if outcome.is_err() {
        state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .fail(Failure::CallbackPanic);
    }
}

fn consume_process(report: &mut WorkerReport, record: &EVENT_RECORD) {
    use super::super::process_lifecycle;
    if report.process_provider_records >= history::MAX_PROCESS_RECORDS {
        report.fail(Failure::ProcessHistory {
            reason: history::Fault::ProcessRecordLimit,
        });
        return;
    }
    report.process_provider_records += 1;
    let descriptor = record.EventHeader.EventDescriptor;
    // Explicitly non-lifecycle events: terminate request is not actual exit;
    // performance counters and delayed Defunct must not manufacture a lifetime.
    if (2..=4).contains(&descriptor.Version) && [11, 32, 33, 39].contains(&descriptor.Opcode) {
        report.auxiliary_process_records += 1;
        return;
    }
    if record.UserData.is_null() || record.ExtendedDataCount != 0 {
        report.fail(Failure::InvalidRecord);
        return;
    }
    let decoded = process_lifecycle::schema(
        descriptor.Version,
        descriptor.Opcode,
        record.EventHeader.Flags,
        usize::from(record.UserDataLength),
        record.EventHeader.TimeStamp,
    )
    .and_then(|schema| super::super::windows::decode_process_record(record, schema));
    match decoded {
        Ok(event) => report.process_record(
            record.EventHeader.ProcessId,
            record.EventHeader.TimeStamp as u64,
            event,
        ),
        Err(error) => report.fail(Failure::ProcessDecode {
            detail: error.to_string(),
        }),
    }
}

unsafe extern "system" fn buffer_callback(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    if logfile.is_null() {
        return 0;
    }
    let logfile = unsafe { &*logfile };
    if logfile.Context.is_null() {
        return 0;
    }
    let state = unsafe { &*logfile.Context.cast::<Mutex<WorkerReport>>() };
    // Only primitive operations under a poison-recovering lock; no native calls
    // or user code. EventsLost on EVENT_TRACE_LOGFILE is UNUSED by Windows.
    let mut report = state.lock().unwrap_or_else(|e| e.into_inner());
    report.buffer_callbacks = report.buffer_callbacks.saturating_add(1);
    u32::from(report.failure.is_none())
}

fn same_guid(a: GUID, b: GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

#[cfg(test)]
mod tests;
