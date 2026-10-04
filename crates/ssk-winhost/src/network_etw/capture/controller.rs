//! Cooperative session controller; native API calls are synchronous. This guard
//! covers Rust unwinding, not process termination. Only private capture uses it.
use super::super::session::{Properties, Snapshot, PRIVATE_MODE};
use serde::Serialize;

pub(super) const EVENT_COUNT: u32 = 8;
pub(super) const BUDGET_MS: u64 = 1000;

pub(super) trait Backend {
    type Handle;
    fn start(&mut self) -> Result<Self::Handle, u32>;
    fn enable(&mut self, handle: &Self::Handle) -> Result<(), u32>;
    fn query(&mut self, handle: &Self::Handle) -> Snapshot;
    fn emit(&mut self, ordinal: u32) -> Result<(), u32>;
    fn stop(&mut self, handle: &Self::Handle) -> Snapshot;
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Fault {
    Deadline,
    ClockRegression,
    Query { code: u32 },
    Enable { code: u32 },
    MissingStatistics,
    SessionMismatch,
    LossReported,
    CounterRegression,
    Emit { code: u32 },
    Stop { code: u32 },
    SessionAlreadyAbsent,
    NoBuffersWritten,
}

#[derive(Debug, Serialize)]
pub(super) struct Report {
    pub schema_version: u32,
    pub status: &'static str,
    pub failure: Option<Fault>,
    pub start_status: u32,
    pub query_after_start: Snapshot,
    pub cleanup_query: Snapshot,
    pub stop: Option<Snapshot>,
    pub cleanup_status: CleanupStatus,
    pub cleanup_retry: Option<CleanupAttempt>,
    pub queries_completed: u32,
    pub events_submitted: u32,
    pub elapsed_ms: u64,
    pub native_calls_preemptible: bool,
    pub system_capture_available: bool,
}

struct Owned<B: Backend> {
    backend: B,
    handle: Option<B::Handle>,
    guid: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CleanupStatus {
    Stopped,
    StoppedWithoutStatistics,
    AlreadyAbsent,
    OwnershipMismatch,
    Unconfirmed,
}

#[derive(Debug, Serialize)]
pub(super) struct CleanupAttempt {
    pub identity_query: Snapshot,
    pub stop: Option<Snapshot>,
    pub status: CleanupStatus,
}

impl<B: Backend> Owned<B> {
    fn cleanup(&mut self) -> CleanupAttempt {
        let identity_query = self
            .backend
            .query(self.handle.as_ref().expect("owned session"));
        let mut attempt = CleanupAttempt {
            identity_query,
            stop: None,
            status: CleanupStatus::Unconfirmed,
        };
        if attempt.identity_query.api_status == 4201 {
            self.handle = None;
            attempt.status = CleanupStatus::AlreadyAbsent;
            return attempt;
        }
        if attempt.identity_query.api_status != 0 {
            return attempt;
        }
        let Some(properties) = &attempt.identity_query.properties else {
            return attempt;
        };
        if properties.session_guid != self.guid {
            // Never act on a different incarnation, including from Drop.
            self.handle = None;
            attempt.status = CleanupStatus::OwnershipMismatch;
            return attempt;
        }
        let result = self
            .backend
            .stop(self.handle.as_ref().expect("owned session"));
        // MORE_DATA stopped the session but did not produce usable statistics.
        // INSTANCE_NOT_FOUND also relinquishes this handle; never adopt by name.
        attempt.status = match result.api_status {
            0 => CleanupStatus::Stopped,
            234 => CleanupStatus::StoppedWithoutStatistics,
            4201 => CleanupStatus::AlreadyAbsent,
            _ => CleanupStatus::Unconfirmed,
        };
        if attempt.status != CleanupStatus::Unconfirmed {
            self.handle = None;
        }
        attempt.stop = Some(result);
        attempt
    }
}

impl<B: Backend> Drop for Owned<B> {
    fn drop(&mut self) {
        if self.handle.is_some() {
            // One best-effort retry after a failed STOP or Rust unwind. Its
            // success cannot rewrite an already failed report into success.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.cleanup()));
        }
    }
}

fn observe(snapshot: &Snapshot, guid: &str, previous: Option<&Properties>) -> Option<Fault> {
    if snapshot.api_status != 0 {
        return Some(Fault::Query {
            code: snapshot.api_status,
        });
    }
    let Some(p) = &snapshot.properties else {
        return Some(Fault::MissingStatistics);
    };
    if p.session_guid != guid || p.log_file_mode != PRIVATE_MODE || p.enable_flags != 0 {
        return Some(Fault::SessionMismatch);
    }
    if p.events_lost != 0 || p.log_buffers_lost != 0 || p.realtime_buffers_lost != 0 {
        return Some(Fault::LossReported);
    }
    if previous.is_some_and(|a| p.buffers_written < a.buffers_written) {
        return Some(Fault::CounterRegression);
    }
    None
}

fn tick(elapsed: u64, previous: &mut u64) -> Option<Fault> {
    let fault = if elapsed < *previous {
        Some(Fault::ClockRegression)
    } else if elapsed >= BUDGET_MS {
        Some(Fault::Deadline)
    } else {
        None
    };
    *previous = elapsed;
    fault
}

pub(super) fn run<B: Backend>(
    mut backend: B,
    guid: &str,
    elapsed: impl Fn() -> u64,
) -> Result<Report, u32> {
    let mut last_tick = elapsed();
    // No native start if the caller's budget is already exhausted.
    if last_tick >= BUDGET_MS {
        return Err(1460);
    }
    let handle = backend.start()?;
    let mut owned = Owned {
        backend,
        handle: Some(handle),
        guid: guid.to_owned(),
    };
    let enable = owned.backend.enable(owned.handle.as_ref().unwrap());
    let initial = owned.backend.query(owned.handle.as_ref().unwrap());
    let mut failure = enable
        .err()
        .map(|code| Fault::Enable { code })
        .or_else(|| observe(&initial, guid, None));
    let mut previous = initial.properties.clone();
    let mut submitted = 0;
    let mut queries = 1;
    for ordinal in 0..EVENT_COUNT {
        if failure.is_none() {
            failure = tick(elapsed(), &mut last_tick);
        }
        if failure.is_some() {
            break;
        }
        if let Err(code) = owned.backend.emit(ordinal) {
            failure = Some(Fault::Emit { code });
            break;
        }
        submitted += 1;
        let snapshot = owned.backend.query(owned.handle.as_ref().unwrap());
        queries += 1;
        failure = observe(&snapshot, guid, previous.as_ref());
        previous = snapshot.properties;
    }
    if failure.is_none() {
        failure = tick(elapsed(), &mut last_tick);
    }
    let cleanup = owned.cleanup();
    queries += 1;
    let stop_fault = if cleanup.identity_query.api_status == 4201 {
        Some(Fault::SessionAlreadyAbsent)
    } else {
        observe(&cleanup.identity_query, guid, previous.as_ref()).or_else(|| {
            cleanup.stop.as_ref().and_then(|stop| {
                if stop.api_status != 0 {
                    Some(Fault::Stop {
                        code: stop.api_status,
                    })
                } else {
                    observe(stop, guid, cleanup.identity_query.properties.as_ref())
                }
            })
        })
    };
    if failure.is_none() {
        failure = stop_fault;
    }
    if failure.is_none()
        && cleanup
            .stop
            .as_ref()
            .and_then(|s| s.properties.as_ref())
            .is_some_and(|p| p.buffers_written == 0)
    {
        failure = Some(Fault::NoBuffersWritten);
    }
    // Record the bounded normal retry. Drop remains a fallback for unwinding,
    // not an invisible third attempt after a returned failure.
    let cleanup_retry = if owned.handle.is_some() {
        queries += 1;
        let retry = owned.cleanup();
        owned.handle = None;
        Some(retry)
    } else {
        None
    };
    let finished = elapsed();
    if failure.is_none() {
        failure = tick(finished, &mut last_tick);
    }
    Ok(Report {
        schema_version: 2,
        status: if failure.is_none() {
            "private_capture_completed"
        } else {
            "unavailable"
        },
        failure,
        start_status: 0,
        query_after_start: initial,
        cleanup_query: cleanup.identity_query,
        stop: cleanup.stop,
        cleanup_status: cleanup.status,
        cleanup_retry,
        queries_completed: queries,
        events_submitted: submitted,
        elapsed_ms: finished,
        native_calls_preemptible: false,
        system_capture_available: false,
    })
}

#[cfg(test)]
mod tests;
