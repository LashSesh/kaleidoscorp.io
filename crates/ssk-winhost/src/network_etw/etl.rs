//! Read-only ETL diagnostics. Native parsing runs in a bounded child process.
//! Imported trace metadata never establishes authenticity or coverage.
use super::replay::Totals;
#[cfg(any(windows, test))]
use super::{DecodedEvent, EventKind, Transport};
use serde::{Deserialize, Serialize};
use std::{io, path::Path};

pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(any(windows, test))]
const MAX_CALLBACKS: u32 = 100_000;
#[cfg(any(windows, test))]
const MAX_NETWORK_RECORDS: u32 = 10_000;
#[cfg(any(windows, test))]
const MAX_REPORT_BYTES: usize = 16 * 1024;

pub(super) mod closure;
mod history;
pub use closure::ClosureInspection;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Failure {
    OpenTrace { code: u32 },
    ProcessTrace { code: u32 },
    CloseTrace { code: u32 },
    UnfinalizedHeader,
    InvalidHeader,
    UnsupportedFileMode,
    LossReported,
    CallbackLimit,
    NetworkRecordLimit,
    InvalidRecord,
    Decode { detail: String },
    ProcessDecode { detail: String },
    ProcessHistory { reason: history::Fault },
    TimestampRegression,
    CallbackPanic,
    NoSupportedNetworkEvents,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Header {
    source_windows_build: u32,
    pointer_bytes: u32,
    log_file_mode: u32,
    clock_type: u32,
    performance_frequency: String,
    session_start_filetime: String,
    session_end_filetime: String,
    events_lost: u32,
    buffers_lost: u32,
    buffers_written: u32,
}

#[cfg(any(windows, test))]
impl Header {
    fn failure(&self) -> Option<Failure> {
        let start = self.session_start_filetime.parse::<i64>().unwrap_or(0);
        let end = self.session_end_filetime.parse::<i64>().unwrap_or(0);
        if end == 0 {
            return Some(Failure::UnfinalizedHeader);
        }
        if start <= 0
            || end < start
            || ![4, 8].contains(&self.pointer_bytes)
            || ![1, 2, 3].contains(&self.clock_type)
            || (self.clock_type == 1 && self.performance_frequency.parse::<i64>().unwrap_or(0) <= 0)
        {
            return Some(Failure::InvalidHeader);
        }
        // Reject circular, append and multi-file modes. Even a sequential file
        // is NOT evidence that the controller enabled all required providers.
        if ![0, 1].contains(&(self.log_file_mode & 0xf)) {
            return Some(Failure::UnsupportedFileMode);
        }
        if self.events_lost != 0 || self.buffers_lost != 0 {
            return Some(Failure::LossReported);
        }
        None
    }
}

/// Private IPC schema: the worker cannot supply the authority flags below.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerReport {
    header: Option<Header>,
    failure: Option<Failure>,
    process_trace_completed: bool,
    callbacks_seen: u32,
    ignored_provider_records: u32,
    selected_network_records: u32,
    process_provider_records: u32,
    auxiliary_process_records: u32,
    decoded_process_records: u32,
    header_payload_process_pid_mismatches: u32,
    decoded_prefix_records: u32,
    header_payload_pid_mismatches: u32,
    buffer_callbacks: u32,
    first_network_timestamp_raw: Option<String>,
    last_network_timestamp_raw: Option<String>,
    tcp: Totals,
    udp: Totals,
    process_correlation: history::Summary,
    #[cfg(any(windows, test))]
    #[serde(skip)]
    history: history::Tracker,
}

#[cfg(any(windows, test))]
impl WorkerReport {
    fn fail(&mut self, failure: Failure) {
        self.failure.get_or_insert(failure);
    }

    fn process_record(
        &mut self,
        header_pid: u32,
        ticks: u64,
        event: super::process_lifecycle::Event,
    ) {
        if self.failure.is_some() {
            return;
        }
        self.decoded_process_records += 1;
        self.header_payload_process_pid_mismatches += u32::from(header_pid != event.pid);
        if let Err(reason) = self.history.process(event, ticks) {
            self.fail(Failure::ProcessHistory { reason });
        }
    }

    fn finish_correlation(&mut self) {
        self.process_correlation = std::mem::take(&mut self.history)
            .finish(self.process_trace_completed && self.failure.is_none());
    }

    fn record(&mut self, header_pid: u32, timestamp: u64, event: DecodedEvent) {
        if self.failure.is_some() {
            return;
        }
        if self
            .last_network_timestamp_raw
            .as_ref()
            .is_some_and(|last| timestamp < last.parse::<u64>().unwrap_or(u64::MAX))
        {
            self.fail(Failure::TimestampRegression);
            return;
        }
        let pid = match &event {
            DecodedEvent::Network { payload_pid, .. } => Some(*payload_pid),
            DecodedEvent::Failure { .. } => None,
        };
        if let Err(reason) = self.history.network(pid, timestamp) {
            self.fail(Failure::ProcessHistory { reason });
            return;
        }
        self.first_network_timestamp_raw
            .get_or_insert_with(|| timestamp.to_string());
        self.last_network_timestamp_raw = Some(timestamp.to_string());
        self.decoded_prefix_records += 1;
        let (transport, kind, size) = match event {
            DecodedEvent::Failure { transport, .. } => (transport, EventKind::Failure, 0),
            DecodedEvent::Network {
                transport,
                kind,
                reported_size,
                payload_pid,
                ..
            } => {
                self.header_payload_pid_mismatches += u32::from(header_pid != payload_pid);
                (transport, kind, u64::from(reported_size))
            }
        };
        let totals = if transport == Transport::Tcp {
            &mut self.tcp
        } else {
            &mut self.udp
        };
        match kind {
            EventKind::Send => {
                totals.send_events += 1;
                totals.reported_send_size_sum += size;
            }
            EventKind::Receive => {
                totals.receive_events += 1;
                totals.reported_receive_size_sum += size;
            }
            EventKind::Connect => totals.connect_events += 1,
            EventKind::Accept => totals.accept_events += 1,
            EventKind::Disconnect => totals.disconnect_events += 1,
            EventKind::Reconnect => totals.reconnect_events += 1,
            EventKind::Retransmit => {
                totals.retransmit_events += 1;
                totals.reported_retransmit_size_sum += size;
            }
            EventKind::TcpCopy => {
                totals.tcp_copy_events += 1;
                totals.reported_tcp_copy_size_sum += size;
            }
            EventKind::Failure => totals.unattributed_failure_events += 1,
        }
    }

    fn validate(&self) -> bool {
        let sum = |t: &Totals| {
            [
                t.send_events,
                t.receive_events,
                t.connect_events,
                t.accept_events,
                t.disconnect_events,
                t.reconnect_events,
                t.retransmit_events,
                t.tcp_copy_events,
                t.unattributed_failure_events,
            ]
            .into_iter()
            .map(u64::from)
            .sum::<u64>()
        };
        let sizes = |t: &Totals| {
            [
                (t.reported_send_size_sum, t.send_events),
                (t.reported_receive_size_sum, t.receive_events),
                (t.reported_retransmit_size_sum, t.retransmit_events),
                (t.reported_tcp_copy_size_sum, t.tcp_copy_events),
            ]
            .into_iter()
            .all(|(s, n)| s <= u64::from(n) * u64::from(u32::MAX))
        };
        let timestamps = match (
            &self.first_network_timestamp_raw,
            &self.last_network_timestamp_raw,
        ) {
            (None, None) => self.decoded_prefix_records == 0,
            (Some(first), Some(last)) => match (first.parse::<u64>(), last.parse::<u64>()) {
                (Ok(first), Ok(last)) => {
                    self.decoded_prefix_records > 0 && first <= last && last <= i64::MAX as u64
                }
                _ => false,
            },
            _ => false,
        };
        self.callbacks_seen <= MAX_CALLBACKS
            && timestamps
            && self.selected_network_records <= MAX_NETWORK_RECORDS
            && self.decoded_prefix_records <= self.selected_network_records
            && self.header_payload_pid_mismatches <= self.decoded_prefix_records
            && self.process_provider_records <= history::MAX_PROCESS_RECORDS
            && u64::from(self.decoded_process_records) + u64::from(self.auxiliary_process_records)
                <= u64::from(self.process_provider_records)
            && self.header_payload_process_pid_mismatches <= self.decoded_process_records
            && self.process_correlation.valid(
                self.decoded_prefix_records,
                self.process_trace_completed && self.failure.is_none(),
                self.decoded_process_records,
            )
            && u64::from(self.ignored_provider_records)
                + u64::from(self.selected_network_records)
                + u64::from(self.process_provider_records)
                <= u64::from(self.callbacks_seen)
            && sum(&self.tcp) + sum(&self.udp) == u64::from(self.decoded_prefix_records)
            && sizes(&self.tcp)
            && sizes(&self.udp)
            && (self.failure.is_some()
                || (self.process_trace_completed
                    && self.header.as_ref().is_some_and(|h| h.failure().is_none())
                    && self.decoded_prefix_records > 0))
    }
}

#[derive(Debug, Serialize)]
pub struct EtlReport {
    schema_version: u32,
    source: &'static str,
    status: &'static str,
    source_file_bytes: u64,
    #[serde(flatten)]
    observation: WorkerReport,
    trace_authenticity_verified: bool,
    loss_completeness_verified: bool,
    process_identity_verified: bool,
    coverage_verified: bool,
    application_byte_counts_verified: bool,
    attempt_outcomes_available: bool,
    baseline_compatible: bool,
    enforcement_active: bool,
}

/// Launch the current ssk-netobserve executable as a contained file reader.
/// Other executables must not call this entry point (worker protocol is CLI-local).
pub fn inspect(path: &Path) -> io::Result<EtlReport> {
    #[cfg(windows)]
    {
        process::inspect(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ETL reading requires Windows",
        ))
    }
}

/// Compare a bounded, untrusted controller closure with a pinned ETL file.
/// This is a read-only consistency check, not capture or authentication.
/// Like `inspect`, this entry point requires the ssk-netobserve worker protocol
/// in the current executable; it is not a general-purpose host API.
pub fn inspect_with_closure(path: &Path, receipt: &Path) -> io::Result<ClosureInspection> {
    #[cfg(windows)]
    {
        process::inspect_with_closure(path, receipt)
    }
    #[cfg(not(windows))]
    {
        let _ = (path, receipt);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ETL reading requires Windows",
        ))
    }
}

#[cfg(any(windows, test))]
fn assemble(bytes: &[u8], file_bytes: u64) -> io::Result<EtlReport> {
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let observation: WorkerReport =
        serde_json::from_slice(bytes).map_err(|_| io::ErrorKind::InvalidData)?;
    if !observation.validate() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(EtlReport {
        schema_version: 2,
        source: "unverified_etl_file",
        status: if observation.failure.is_some() {
            "unavailable"
        } else {
            "decoded_file"
        },
        source_file_bytes: file_bytes,
        observation,
        trace_authenticity_verified: false,
        loss_completeness_verified: false,
        process_identity_verified: false,
        coverage_verified: false,
        application_byte_counts_verified: false,
        attempt_outcomes_available: false,
        baseline_compatible: false,
        enforcement_active: false,
    })
}

/// Internal command dispatch for ssk-netobserve. Not a general in-process ETL API.
#[doc(hidden)]
pub fn worker(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        process::require_containment()?;
        let (path, _pin) = process::pin_file(path)?;
        let report = windows::read(&path);
        serde_json::to_writer(std::io::stdout().lock(), &report)?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[cfg(windows)]
mod process;
#[cfg(test)]
mod tests;
#[cfg(windows)]
mod windows;
