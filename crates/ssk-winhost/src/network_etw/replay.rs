//! Bounded diagnostic exports, not ETL files or verified live capture.
use super::{decode, DecodeError, DecodedEvent, EventKind, RawEvent, Transport};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    time::{Duration, Instant},
};

pub const MAX_REPLAY_BYTES: usize = 1_048_576;
pub const MAX_RECORDS: usize = 512;
const MAX_DECODE_TIME: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    SyntheticFixture,
    UnverifiedExport,
}

/// These must eventually come from controller/session statistics, NOT the
/// unused EVENT_TRACE_LOGFILE.EventsLost member. All values remain assertions.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LossCounters {
    pub events_lost: u64,
    pub log_buffers_lost: u64,
    pub realtime_buffers_lost: u64,
    pub consumer_dropped: u64,
}

impl LossCounters {
    fn values(self) -> [u64; 4] {
        [
            self.events_lost,
            self.log_buffers_lost,
            self.realtime_buffers_lost,
            self.consumer_dropped,
        ]
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRecord {
    pub ordinal: u64,
    pub event: RawEvent,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayInput {
    pub schema_version: u32,
    pub provenance: Provenance,
    pub source_epoch: String,
    /// A declared QPC clock frequency; never inferred from wall time or seqnum.
    pub qpc_frequency: u64,
    pub start_ticks: u64,
    pub end_ticks: u64,
    pub expected_records: u32,
    pub collection_completed: bool,
    pub loss_start: Option<LossCounters>,
    pub loss_end: Option<LossCounters>,
    pub records: Vec<ReplayRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Unavailable {
    MissingLossCounters,
    LossCounterRegression,
    LossReported,
    IncompleteCollection,
    RecordCountMismatch,
    EmptyCollection,
    OrdinalDiscontinuity,
    TimestampOutsideRange,
    TimestampRegression,
    DecodeBudgetExceeded,
    Decode { reason: DecodeError },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuditStatus {
    DecodedInput,
    Unavailable { reason: Unavailable },
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Totals {
    pub send_events: u32,
    pub receive_events: u32,
    pub connect_events: u32,
    pub accept_events: u32,
    pub disconnect_events: u32,
    pub reconnect_events: u32,
    pub retransmit_events: u32,
    pub tcp_copy_events: u32,
    pub unattributed_failure_events: u32,
    // Distinct buckets prevent retransmit/copy/connect sizes being treated as
    // new application payload. Counts describe only this decoded prefix.
    pub reported_send_size_sum: u64,
    pub reported_receive_size_sum: u64,
    pub reported_retransmit_size_sum: u64,
    pub reported_tcp_copy_size_sum: u64,
}

#[derive(Debug, Serialize)]
pub struct ReplayReport {
    schema_version: u32,
    decoder: &'static str,
    provenance: Provenance,
    source_epoch: String,
    qpc_frequency: u64,
    start_ticks: String,
    end_ticks: String,
    loss_start: Option<LossCounters>,
    loss_end: Option<LossCounters>,
    input_records: usize,
    decoded_prefix_records: u32,
    header_payload_pid_mismatches: u32,
    #[serde(flatten)]
    status: AuditStatus,
    tcp: Totals,
    udp: Totals,
    trace_authenticity_verified: bool,
    process_identity_verified: bool,
    coverage_verified: bool,
    application_byte_counts_verified: bool,
    attempt_outcomes_available: bool,
    baseline_compatible: bool,
    enforcement_active: bool,
}

impl ReplayReport {
    pub fn status(&self) -> AuditStatus {
        self.status
    }
    pub fn tcp(&self) -> &Totals {
        &self.tcp
    }
    pub fn udp(&self) -> &Totals {
        &self.udp
    }
}

#[derive(Debug)]
pub enum ReplayError {
    Read(std::io::Error),
    TooLarge,
    InvalidJson,
    InvalidEnvelope,
}
impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(e) => write!(f, "ETW replay read failed: {e}"),
            Self::TooLarge => f.write_str("ETW replay exceeds input limits"),
            Self::InvalidJson => f.write_str("invalid ETW replay JSON or schema fields"),
            Self::InvalidEnvelope => f.write_str("invalid ETW replay envelope"),
        }
    }
}
impl std::error::Error for ReplayError {}

pub fn read_and_audit(reader: impl Read) -> Result<ReplayReport, ReplayError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_REPLAY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(ReplayError::Read)?;
    if bytes.len() > MAX_REPLAY_BYTES {
        return Err(ReplayError::TooLarge);
    }
    let input: ReplayInput =
        serde_json::from_slice(&bytes).map_err(|_| ReplayError::InvalidJson)?;
    audit(input)
}

pub fn audit(input: ReplayInput) -> Result<ReplayReport, ReplayError> {
    let started = Instant::now();
    audit_with(input, decode, || started.elapsed() >= MAX_DECODE_TIME)
}

fn audit_with(
    input: ReplayInput,
    mut decoder: impl FnMut(&RawEvent) -> Result<DecodedEvent, DecodeError>,
    mut expired: impl FnMut() -> bool,
) -> Result<ReplayReport, ReplayError> {
    if input.records.len() > MAX_RECORDS || input.expected_records as usize > MAX_RECORDS {
        return Err(ReplayError::TooLarge);
    }
    if input.schema_version != 1
        || input.source_epoch.is_empty()
        || input.source_epoch.len() > 64
        || !input
            .source_epoch
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
        || !(1..=10_000_000_000).contains(&input.qpc_frequency)
        || input.end_ticks <= input.start_ticks
        || input.end_ticks > i64::MAX as u64
        || u128::from(input.end_ticks - input.start_ticks) > u128::from(input.qpc_frequency) * 60
    {
        return Err(ReplayError::InvalidEnvelope);
    }
    // Conservative contract: any nonzero loss in the declared source epoch
    // invalidates the batch. Missing counters must never default to zero.
    let fault = match (input.loss_start, input.loss_end) {
        (Some(start), Some(end))
            if start.values().iter().zip(end.values()).any(|(a, b)| b < *a) =>
        {
            Some(Unavailable::LossCounterRegression)
        }
        (Some(start), Some(end))
            if start
                .values()
                .iter()
                .chain(end.values().iter())
                .any(|n| *n != 0) =>
        {
            Some(Unavailable::LossReported)
        }
        (None, _) | (_, None) => Some(Unavailable::MissingLossCounters),
        _ if !input.collection_completed => Some(Unavailable::IncompleteCollection),
        _ if input.records.len() != input.expected_records as usize => {
            Some(Unavailable::RecordCountMismatch)
        }
        _ if input.records.is_empty() => Some(Unavailable::EmptyCollection),
        _ => None,
    };
    let mut report = ReplayReport {
        schema_version: 1,
        decoder: "kernel-network-v2-tdh-properties-v1",
        provenance: input.provenance,
        source_epoch: input.source_epoch,
        qpc_frequency: input.qpc_frequency,
        start_ticks: input.start_ticks.to_string(),
        end_ticks: input.end_ticks.to_string(),
        loss_start: input.loss_start,
        loss_end: input.loss_end,
        input_records: input.records.len(),
        decoded_prefix_records: 0,
        header_payload_pid_mismatches: 0,
        status: fault.map_or(AuditStatus::DecodedInput, |reason| {
            AuditStatus::Unavailable { reason }
        }),
        tcp: Totals::default(),
        udp: Totals::default(),
        trace_authenticity_verified: false,
        process_identity_verified: false,
        coverage_verified: false,
        application_byte_counts_verified: false,
        attempt_outcomes_available: false,
        baseline_compatible: false,
        enforcement_active: false,
    };
    // Do not query TDH for a batch already known to be incomplete/lossy.
    if fault.is_some() {
        return Ok(report);
    }
    let mut last_ticks = input.start_ticks;
    for (ordinal, record) in input.records.iter().enumerate() {
        let failure = if expired() {
            Some(Unavailable::DecodeBudgetExceeded)
        } else if record.ordinal != ordinal as u64 {
            Some(Unavailable::OrdinalDiscontinuity)
        } else if record.event.timestamp_ticks < input.start_ticks
            || record.event.timestamp_ticks >= input.end_ticks
        {
            Some(Unavailable::TimestampOutsideRange)
        } else if record.event.timestamp_ticks < last_ticks {
            Some(Unavailable::TimestampRegression)
        } else {
            None
        };
        if let Some(reason) = failure {
            report.status = AuditStatus::Unavailable { reason };
            break;
        }
        let decoded = decoder(&record.event);
        if expired() {
            report.status = AuditStatus::Unavailable {
                reason: Unavailable::DecodeBudgetExceeded,
            };
            break;
        }
        let decoded = match decoded {
            Ok(event) => event,
            Err(reason) => {
                report.status = AuditStatus::Unavailable {
                    reason: Unavailable::Decode { reason },
                };
                break;
            }
        };
        last_ticks = record.event.timestamp_ticks;
        report.decoded_prefix_records += 1;
        match decoded {
            DecodedEvent::Failure { transport, .. } => {
                let totals = if transport == Transport::Tcp {
                    &mut report.tcp
                } else {
                    &mut report.udp
                };
                totals.unattributed_failure_events += 1;
            }
            DecodedEvent::Network {
                transport,
                kind,
                payload_pid,
                reported_size,
                ..
            } => {
                if record.event.header_pid != payload_pid {
                    report.header_payload_pid_mismatches += 1;
                }
                let totals = if transport == Transport::Tcp {
                    &mut report.tcp
                } else {
                    &mut report.udp
                };
                let size = u64::from(reported_size);
                // <=512 records * u32::MAX fits u64; no unbounded accumulator.
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
                    EventKind::Failure => unreachable!("failure has its own decoded variant"),
                }
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests;
