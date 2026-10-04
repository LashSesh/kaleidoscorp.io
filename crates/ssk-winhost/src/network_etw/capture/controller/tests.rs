use super::*;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
};
const GUID: &str = "a72f10ca-79ef-4ff6-95d9-8b3e7b190422";
fn snapshot() -> Snapshot {
    Snapshot {
        api_status: 0,
        properties: Some(Properties {
            session_guid: GUID.into(),
            log_file_mode: PRIVATE_MODE,
            enable_flags: 0,
            events_lost: 0,
            log_buffers_lost: 0,
            realtime_buffers_lost: 0,
            buffers_written: 1,
        }),
    }
}
#[derive(Default)]
struct Fake {
    calls: Rc<RefCell<Vec<&'static str>>>,
    start_error: Option<u32>,
    enable_error: Option<u32>,
    emit_error: Option<u32>,
    panic_on_emit: bool,
    snapshots: VecDeque<Snapshot>,
    stop_result: Option<Snapshot>,
}
impl Backend for Fake {
    type Handle = u64;
    fn start(&mut self) -> Result<u64, u32> {
        self.calls.borrow_mut().push("start");
        self.start_error.map_or(Ok(42), Err)
    }
    fn enable(&mut self, handle: &u64) -> Result<(), u32> {
        assert_eq!(*handle, 42);
        self.calls.borrow_mut().push("enable");
        self.enable_error.map_or(Ok(()), Err)
    }
    fn query(&mut self, handle: &u64) -> Snapshot {
        assert_eq!(*handle, 42);
        self.calls.borrow_mut().push("query");
        self.snapshots.pop_front().unwrap_or_else(snapshot)
    }
    fn emit(&mut self, ordinal: u32) -> Result<(), u32> {
        assert!(ordinal < EVENT_COUNT);
        self.calls.borrow_mut().push("emit");
        assert!(!self.panic_on_emit, "injected unwind");
        self.emit_error.map_or(Ok(()), Err)
    }
    fn stop(&mut self, handle: &u64) -> Snapshot {
        assert_eq!(*handle, 42);
        self.calls.borrow_mut().push("stop");
        self.stop_result.clone().unwrap_or_else(snapshot)
    }
}
fn clock() -> impl Fn() -> u64 {
    let tick = Cell::new(0);
    move || {
        let value = tick.get();
        tick.set(value + 1);
        value
    }
}
#[test]
fn owned_success_enables_then_queries_and_stops_exactly_once() {
    let backend = Fake::default();
    let calls = backend.calls.clone();
    let report = run(backend, GUID, clock()).unwrap();
    assert!(report.failure.is_none());
    assert_eq!(report.events_submitted, EVENT_COUNT);
    assert_eq!(report.queries_completed, EVENT_COUNT + 2);
    assert_eq!(&calls.borrow()[..3], ["start", "enable", "query"]);
    assert_eq!(calls.borrow().iter().filter(|c| **c == "stop").count(), 1);
    assert!(!report.system_capture_available);
    assert!(!report.native_calls_preemptible);
}
#[test]
fn collisions_and_failed_starts_never_query_adopt_or_stop_a_session() {
    for code in [183, 5, 1450] {
        let backend = Fake {
            start_error: Some(code),
            ..Default::default()
        };
        let calls = backend.calls.clone();
        assert_eq!(run(backend, GUID, clock()).unwrap_err(), code);
        assert_eq!(*calls.borrow(), ["start"]);
    }
}
#[test]
fn enable_failure_is_inside_the_owned_cleanup_scope() {
    let backend = Fake {
        enable_error: Some(5),
        ..Default::default()
    };
    let calls = backend.calls.clone();
    let report = run(backend, GUID, clock()).unwrap();
    assert_eq!(report.failure, Some(Fault::Enable { code: 5 }));
    assert_eq!(report.events_submitted, 0);
    assert_eq!(
        *calls.borrow(),
        ["start", "enable", "query", "query", "stop"]
    );
}
#[test]
fn missing_and_failed_initial_statistics_stop_without_emitting() {
    for (s, fault) in [
        (
            Snapshot {
                api_status: 5,
                properties: None,
            },
            Fault::Query { code: 5 },
        ),
        (
            Snapshot {
                api_status: 0,
                properties: None,
            },
            Fault::MissingStatistics,
        ),
    ] {
        let report = run(
            Fake {
                snapshots: [s].into(),
                ..Default::default()
            },
            GUID,
            clock(),
        )
        .unwrap();
        assert_eq!(report.failure, Some(fault));
        assert_eq!(report.events_submitted, 0);
        assert_eq!(report.stop.as_ref().unwrap().api_status, 0);
    }
}
#[test]
fn losses_at_start_during_capture_and_stop_invalidate_the_result() {
    for stage in 0..3 {
        let mut lossy = snapshot();
        lossy.properties.as_mut().unwrap().events_lost = 1;
        let backend = match stage {
            0 => Fake {
                snapshots: [lossy].into(),
                ..Default::default()
            },
            1 => Fake {
                snapshots: [snapshot(), lossy].into(),
                ..Default::default()
            },
            _ => Fake {
                stop_result: Some(lossy),
                ..Default::default()
            },
        };
        let report = run(backend, GUID, clock()).unwrap();
        assert_eq!(report.failure, Some(Fault::LossReported));
        assert_eq!(report.events_submitted, [0, 1, EVENT_COUNT][stage]);
        assert_eq!(report.status, "unavailable");
    }
}
#[test]
fn configuration_changes_are_not_accepted_as_continuous_capture() {
    for field in 0..3 {
        let mut changed = snapshot();
        let p = changed.properties.as_mut().unwrap();
        match field {
            0 => p.session_guid = "different".into(),
            1 => p.enable_flags = 1,
            _ => p.log_file_mode = 1,
        }
        let report = run(
            Fake {
                snapshots: [snapshot(), changed].into(),
                ..Default::default()
            },
            GUID,
            clock(),
        )
        .unwrap();
        assert_eq!(report.failure, Some(Fault::SessionMismatch));
        assert_eq!(report.events_submitted, 1);
    }
}
#[test]
fn buffer_count_regression_and_empty_stop_are_failures() {
    let mut initial = snapshot();
    initial.properties.as_mut().unwrap().buffers_written = 2;
    let report = run(
        Fake {
            snapshots: [initial, snapshot()].into(),
            ..Default::default()
        },
        GUID,
        clock(),
    )
    .unwrap();
    assert_eq!(report.failure, Some(Fault::CounterRegression));
    let mut stopped = snapshot();
    stopped.properties.as_mut().unwrap().buffers_written = 0;
    let backend = Fake {
        stop_result: Some(stopped.clone()),
        snapshots: vec![stopped; 10].into(),
        ..Default::default()
    };
    assert_eq!(
        run(backend, GUID, clock()).unwrap().failure,
        Some(Fault::NoBuffersWritten)
    );
}
#[test]
fn more_data_and_already_gone_relinquish_handle_but_do_not_report_success() {
    for code in [234, 4201] {
        let backend = Fake {
            stop_result: Some(Snapshot {
                api_status: code,
                properties: None,
            }),
            ..Default::default()
        };
        let calls = backend.calls.clone();
        assert_eq!(
            run(backend, GUID, clock()).unwrap().failure,
            Some(Fault::Stop { code })
        );
        assert_eq!(calls.borrow().iter().filter(|c| **c == "stop").count(), 1);
    }
}
#[test]
fn uncertain_stop_retries_once_without_erasing_the_failure() {
    let backend = Fake {
        stop_result: Some(Snapshot {
            api_status: 5,
            properties: None,
        }),
        ..Default::default()
    };
    let calls = backend.calls.clone();
    assert_eq!(
        run(backend, GUID, clock()).unwrap().failure,
        Some(Fault::Stop { code: 5 })
    );
    assert_eq!(calls.borrow().iter().filter(|c| **c == "stop").count(), 2);
}
#[test]
fn emit_failure_remains_primary_when_cleanup_also_fails() {
    let backend = Fake {
        emit_error: Some(87),
        stop_result: Some(Snapshot {
            api_status: 5,
            properties: None,
        }),
        ..Default::default()
    };
    let report = run(backend, GUID, clock()).unwrap();
    assert_eq!(report.failure, Some(Fault::Emit { code: 87 }));
    assert_eq!(report.events_submitted, 0);
    assert_eq!(report.stop.as_ref().unwrap().api_status, 5);
}
#[test]
fn rust_unwind_still_stops_the_owned_session() {
    let backend = Fake {
        panic_on_emit: true,
        ..Default::default()
    };
    let calls = backend.calls.clone();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(backend, GUID, clock())))
            .is_err()
    );
    assert_eq!(calls.borrow().iter().filter(|c| **c == "stop").count(), 1);
}
#[test]
fn expired_budget_before_start_has_no_side_effect() {
    let backend = Fake::default();
    let calls = backend.calls.clone();
    assert_eq!(run(backend, GUID, || BUDGET_MS).unwrap_err(), 1460);
    assert!(calls.borrow().is_empty());
}
#[test]
fn deadline_after_start_stops_and_suppresses_events() {
    let count = Cell::new(0);
    let report = run(Fake::default(), GUID, || {
        let n = count.get();
        count.set(n + 1);
        n * BUDGET_MS
    })
    .unwrap();
    assert_eq!(report.failure, Some(Fault::Deadline));
    assert_eq!(report.events_submitted, 0);
    assert_eq!(report.stop.as_ref().unwrap().api_status, 0);
}
#[test]
fn time_must_be_monotonic_including_after_stop() {
    let count = Cell::new(0);
    let report = run(Fake::default(), GUID, || {
        let n = count.get();
        count.set(n + 1);
        if n == 0 {
            10
        } else {
            9
        }
    })
    .unwrap();
    assert_eq!(report.failure, Some(Fault::ClockRegression));
    let count = Cell::new(0);
    let report = run(Fake::default(), GUID, || {
        let n = count.get();
        count.set(n + 1);
        if n > EVENT_COUNT as u64 + 1 {
            BUDGET_MS
        } else {
            n
        }
    })
    .unwrap();
    assert_eq!(report.failure, Some(Fault::Deadline));
    assert_eq!(report.events_submitted, EVENT_COUNT);
}

#[test]
fn a_foreign_incarnation_at_cleanup_is_never_stopped_or_retried() {
    let mut changed = snapshot();
    changed.properties.as_mut().unwrap().session_guid = "foreign".into();
    let backend = Fake {
        snapshots: vec![snapshot(); 9].into_iter().chain([changed]).collect(),
        ..Default::default()
    };
    let calls = backend.calls.clone();
    let report = run(backend, GUID, clock()).unwrap();
    assert_eq!(report.failure, Some(Fault::SessionMismatch));
    assert_eq!(report.cleanup_status, CleanupStatus::OwnershipMismatch);
    assert!(report.stop.is_none());
    assert!(report.cleanup_retry.is_none());
    assert!(!calls.borrow().contains(&"stop"));
}

#[test]
fn unknown_cleanup_identity_does_not_authorize_a_stop() {
    for unknown in [
        Snapshot {
            api_status: 5,
            properties: None,
        },
        Snapshot {
            api_status: 0,
            properties: None,
        },
    ] {
        let backend = Fake {
            snapshots: vec![snapshot(); 9]
                .into_iter()
                .chain([unknown.clone(), unknown])
                .collect(),
            ..Default::default()
        };
        let calls = backend.calls.clone();
        let report = run(backend, GUID, clock()).unwrap();
        assert!(report.failure.is_some());
        assert!(report.stop.is_none());
        assert_eq!(
            report.cleanup_retry.unwrap().status,
            CleanupStatus::Unconfirmed
        );
        assert!(!calls.borrow().contains(&"stop"));
    }
}

#[test]
fn a_session_already_absent_during_cleanup_has_no_fabricated_stop_result() {
    let backend = Fake {
        snapshots: vec![snapshot(); 9]
            .into_iter()
            .chain([Snapshot {
                api_status: 4201,
                properties: None,
            }])
            .collect(),
        ..Default::default()
    };
    let calls = backend.calls.clone();
    let report = run(backend, GUID, clock()).unwrap();
    assert_eq!(report.failure, Some(Fault::SessionAlreadyAbsent));
    assert_eq!(report.cleanup_status, CleanupStatus::AlreadyAbsent);
    assert!(report.stop.is_none());
    assert!(!calls.borrow().contains(&"stop"));
}
