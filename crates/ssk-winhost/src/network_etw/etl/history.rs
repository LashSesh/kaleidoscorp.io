//! Bounded, file-local correlation, finalized only after the entire file closes.
//! Every result is conditional on unverified input; nothing here grants authority.
#[cfg(any(windows, test))]
use crate::network_etw::process_lifecycle::{Event, Kind};
use serde::{Deserialize, Serialize};
#[cfg(any(windows, test))]
use std::collections::BTreeMap;

#[cfg(any(windows, test))]
pub(super) const MAX_PROCESS_RECORDS: u32 = 10_000;
#[cfg(any(windows, test))]
const MAX_LIFETIMES: u32 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Fault {
    SourceUnavailable,
    TimestampRegression,
    ConflictingLifecycle,
    InvalidIdentity,
    ProcessRecordLimit,
    LifetimeLimit,
    NetworkRecordLimit,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum State {
    #[default]
    NotEvaluated,
    EvaluatedUnverifiedInput,
    Unavailable,
}

/// Counts are diagnostic; raw object addresses and per-process data never leave
/// the worker. The authority fields live in the parent-owned report instead.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Summary {
    status: State,
    reason: Option<Fault>,
    network_records: u32,
    start_bounded_records: u32,
    rundown_bounded_records: u32,
    missing_history_records: u32,
    unclosed_window_records: u32,
    outside_observed_window_records: u32,
    ambiguous_boundary_records: u32,
    no_payload_pid_records: u32,
    invalidated_records: u32,
    observed_process_lifetimes: u32,
    pid_lifetime_transitions: u32,
    orphan_end_events: u32,
    idle_process_events: u32,
}

#[cfg(any(windows, test))]
impl Summary {
    pub(super) fn valid(&self, decoded: u32, source_complete: bool, process_records: u32) -> bool {
        let classified: u64 = [
            self.start_bounded_records,
            self.rundown_bounded_records,
            self.missing_history_records,
            self.unclosed_window_records,
            self.outside_observed_window_records,
            self.ambiguous_boundary_records,
            self.no_payload_pid_records,
            self.invalidated_records,
        ]
        .into_iter()
        .map(u64::from)
        .sum();
        self.network_records == decoded
            && classified == u64::from(decoded)
            && self.observed_process_lifetimes <= MAX_LIFETIMES
            && self.observed_process_lifetimes <= process_records
            && self.pid_lifetime_transitions <= self.observed_process_lifetimes
            && self.orphan_end_events <= process_records
            && self.idle_process_events <= process_records
            && u64::from(self.observed_process_lifetimes)
                + u64::from(self.orphan_end_events)
                + u64::from(self.idle_process_events)
                <= u64::from(process_records)
            && (self.observed_process_lifetimes == 0
                || self.pid_lifetime_transitions < self.observed_process_lifetimes)
            && (self.start_bounded_records == 0 && self.rundown_bounded_records == 0
                || self.observed_process_lifetimes > 0)
            && match self.status {
                State::NotEvaluated => false,
                State::EvaluatedUnverifiedInput => {
                    source_complete && self.invalidated_records == 0 && self.reason.is_none()
                }
                State::Unavailable => {
                    !source_complete && self.invalidated_records == decoded && self.reason.is_some()
                }
            }
    }
}

#[derive(Debug)]
#[cfg(any(windows, test))]
struct Lifetime {
    key: u64,
    lower: u64,
    witness: Option<u64>,
    end: Option<u64>,
    started: bool,
}
#[derive(Debug, Default)]
#[cfg(any(windows, test))]
struct PidHistory {
    lifetimes: Vec<Lifetime>,
    active: Option<usize>,
}
#[derive(Debug)]
#[cfg(any(windows, test))]
struct NetworkPoint {
    pid: Option<u32>,
    ticks: u64,
}

#[derive(Debug, Default)]
#[cfg(any(windows, test))]
pub(super) struct Tracker {
    pids: BTreeMap<u32, PidHistory>,
    network: Vec<NetworkPoint>,
    last_ticks: Option<u64>,
    fault: Option<Fault>,
    process_records: u32,
    lifetimes: u32,
    reuse: u32,
    orphan_ends: u32,
    idle: u32,
}

#[cfg(any(windows, test))]
impl Tracker {
    fn fail(&mut self, fault: Fault) -> Fault {
        *self.fault.get_or_insert(fault)
    }

    fn clock(&mut self, ticks: u64) -> Result<(), Fault> {
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        if ticks > i64::MAX as u64 || self.last_ticks.is_some_and(|last| ticks < last) {
            return Err(self.fail(Fault::TimestampRegression));
        }
        self.last_ticks = Some(ticks);
        Ok(())
    }

    pub(super) fn network(&mut self, pid: Option<u32>, ticks: u64) -> Result<(), Fault> {
        self.clock(ticks)?;
        if pid.is_some_and(|p| p == 0 || p == u32::MAX) {
            return Err(self.fail(Fault::InvalidIdentity));
        }
        if self.network.len() >= super::MAX_NETWORK_RECORDS as usize {
            return Err(self.fail(Fault::NetworkRecordLimit));
        }
        self.network.push(NetworkPoint { pid, ticks });
        Ok(())
    }

    pub(super) fn process(&mut self, event: Event, ticks: u64) -> Result<(), Fault> {
        self.clock(ticks)?;
        if self.process_records >= MAX_PROCESS_RECORDS {
            return Err(self.fail(Fault::ProcessRecordLimit));
        }
        self.process_records += 1;
        if event.pid == u32::MAX || (event.pid != 0 && event.key == 0) {
            return Err(self.fail(Fault::InvalidIdentity));
        }
        if event.pid == 0 {
            self.idle += 1;
            return Ok(());
        }
        let active = self.pids.get(&event.pid).and_then(|h| h.active);
        if let Some(index) = active {
            let lifetime = &mut self
                .pids
                .get_mut(&event.pid)
                .expect("active PID exists")
                .lifetimes[index];
            if lifetime.key != event.key || event.kind == Kind::Start {
                return Err(self.fail(Fault::ConflictingLifecycle));
            }
            lifetime.witness = Some(ticks);
            if event.kind == Kind::End {
                lifetime.end = Some(ticks);
                self.pids
                    .get_mut(&event.pid)
                    .expect("active PID exists")
                    .active = None;
            }
            return Ok(());
        }
        if event.kind == Kind::End {
            self.orphan_ends += 1;
            // End without a lower witness never backfills earlier network data.
            return Ok(());
        }
        if self.lifetimes >= MAX_LIFETIMES {
            return Err(self.fail(Fault::LifetimeLimit));
        }
        let history = self.pids.entry(event.pid).or_default();
        if !history.lifetimes.is_empty() {
            self.reuse += 1;
        }
        history.active = Some(history.lifetimes.len());
        history.lifetimes.push(Lifetime {
            key: event.key,
            lower: ticks,
            witness: None,
            end: None,
            started: event.kind == Kind::Start,
        });
        self.lifetimes += 1;
        Ok(())
    }

    pub(super) fn finish(self, source_complete: bool) -> Summary {
        let mut summary = Summary {
            network_records: self.network.len() as u32,
            observed_process_lifetimes: self.lifetimes,
            pid_lifetime_transitions: self.reuse,
            orphan_end_events: self.orphan_ends,
            idle_process_events: self.idle,
            ..Default::default()
        };
        if let Some(reason) = self
            .fault
            .or((!source_complete).then_some(Fault::SourceUnavailable))
        {
            summary.status = State::Unavailable;
            summary.reason = Some(reason);
            summary.invalidated_records = summary.network_records;
            return summary;
        }
        summary.status = State::EvaluatedUnverifiedInput;
        for point in self.network {
            let Some(pid) = point.pid else {
                summary.no_payload_pid_records += 1;
                continue;
            };
            let Some(history) = self.pids.get(&pid) else {
                summary.missing_history_records += 1;
                continue;
            };
            // Lifetimes were appended in observed timestamp order, never sorted.
            // Equal start/end ticks remain ambiguous regardless of callback order.
            let position = history
                .lifetimes
                .partition_point(|l| l.lower <= point.ticks);
            if position == 0 {
                summary.outside_observed_window_records += 1;
                continue;
            }
            let lifetime = &history.lifetimes[position - 1];
            if lifetime.lower == point.ticks || lifetime.witness == Some(point.ticks) {
                summary.ambiguous_boundary_records += 1;
            } else if lifetime.witness.is_some_and(|upper| point.ticks < upper) {
                if lifetime.started {
                    summary.start_bounded_records += 1;
                } else {
                    summary.rundown_bounded_records += 1;
                }
            } else if lifetime.end.is_none() {
                summary.unclosed_window_records += 1;
            } else {
                summary.outside_observed_window_records += 1;
            }
        }
        summary
    }
}

#[cfg(test)]
mod tests;
