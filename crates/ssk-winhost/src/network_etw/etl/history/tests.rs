use super::*;
fn process(tracker: &mut Tracker, pid: u32, key: u64, kind: Kind, ticks: u64) {
    tracker.process(Event { pid, key, kind }, ticks).unwrap();
}
fn network(tracker: &mut Tracker, pid: u32, ticks: u64) {
    tracker.network(Some(pid), ticks).unwrap();
}

#[test]
fn real_start_and_end_bound_observations_but_file_end_does_not() {
    let mut t = Tracker::default();
    process(&mut t, 42, 1, Kind::Start, 10);
    network(&mut t, 42, 15);
    let s = t.finish(true);
    assert_eq!(s.unclosed_window_records, 1);
    assert_eq!(s.start_bounded_records, 0);
    let mut t = Tracker::default();
    process(&mut t, 42, 1, Kind::Start, 10);
    network(&mut t, 42, 15);
    process(&mut t, 42, 1, Kind::End, 20);
    let s = t.finish(true);
    assert_eq!(s.start_bounded_records, 1);
    assert!(s.valid(1, true, 2));
}

#[test]
fn rundown_only_bounds_forward_observation_and_never_manufactures_start() {
    let mut t = Tracker::default();
    network(&mut t, 42, 5);
    process(&mut t, 42, 1, Kind::RundownStart, 10);
    network(&mut t, 42, 15);
    process(&mut t, 42, 1, Kind::RundownEnd, 20);
    network(&mut t, 42, 25);
    let s = t.finish(true);
    assert_eq!(s.rundown_bounded_records, 1);
    assert_eq!(s.start_bounded_records, 0);
    assert_eq!(s.outside_observed_window_records, 1);
    assert_eq!(s.unclosed_window_records, 1);
}

#[test]
fn end_rundown_is_an_alive_witness_not_process_termination() {
    let mut t = Tracker::default();
    process(&mut t, 42, 1, Kind::Start, 10);
    process(&mut t, 42, 1, Kind::RundownEnd, 20);
    network(&mut t, 42, 25);
    process(&mut t, 42, 1, Kind::End, 30);
    assert_eq!(t.finish(true).start_bounded_records, 1);
}

#[test]
fn end_without_start_never_backfills_and_headerless_failures_have_no_pid() {
    let mut t = Tracker::default();
    network(&mut t, 42, 10);
    t.network(None, 11).unwrap();
    process(&mut t, 42, 1, Kind::End, 20);
    let s = t.finish(true);
    assert_eq!(s.missing_history_records, 1);
    assert_eq!(s.no_payload_pid_records, 1);
    assert_eq!(s.orphan_end_events, 1);
}

#[test]
fn reused_pid_and_reused_object_address_still_create_distinct_lifetimes() {
    for second_key in [1, 2] {
        let mut t = Tracker::default();
        process(&mut t, 42, 1, Kind::Start, 10);
        network(&mut t, 42, 15);
        process(&mut t, 42, 1, Kind::End, 20);
        network(&mut t, 42, 25);
        process(&mut t, 42, second_key, Kind::Start, 30);
        network(&mut t, 42, 35);
        process(&mut t, 42, second_key, Kind::End, 40);
        let s = t.finish(true);
        assert_eq!(s.start_bounded_records, 2);
        assert_eq!(s.pid_lifetime_transitions, 1);
        assert_eq!(s.observed_process_lifetimes, 2);
        assert_eq!(s.outside_observed_window_records, 1);
    }
}

#[test]
fn same_time_start_stop_and_reuse_boundaries_are_ambiguous_in_both_callback_orders() {
    for before in [true, false] {
        let mut t = Tracker::default();
        if before {
            network(&mut t, 42, 10);
        }
        process(&mut t, 42, 1, Kind::Start, 10);
        if !before {
            network(&mut t, 42, 10);
        }
        network(&mut t, 42, 20);
        process(&mut t, 42, 1, Kind::End, 20);
        process(&mut t, 42, 2, Kind::Start, 20);
        network(&mut t, 42, 20);
        process(&mut t, 42, 2, Kind::End, 30);
        let s = t.finish(true);
        assert_eq!(s.ambiguous_boundary_records, 3);
        assert_eq!(s.start_bounded_records, 0);
    }
}

#[test]
fn interleaved_pids_do_not_share_bounds_or_keys() {
    let mut t = Tracker::default();
    process(&mut t, 42, 1, Kind::Start, 10);
    process(&mut t, 43, 2, Kind::Start, 11);
    network(&mut t, 42, 12);
    network(&mut t, 43, 13);
    process(&mut t, 42, 1, Kind::End, 20);
    let s = t.finish(true);
    assert_eq!(s.start_bounded_records, 1);
    assert_eq!(s.unclosed_window_records, 1);
}

#[test]
fn conflicting_start_end_or_rundown_invalidates_all_earlier_matches() {
    for kind in [Kind::Start, Kind::End, Kind::RundownStart, Kind::RundownEnd] {
        let mut t = Tracker::default();
        process(&mut t, 42, 1, Kind::Start, 10);
        network(&mut t, 42, 15);
        assert_eq!(
            t.process(
                Event {
                    pid: 42,
                    key: 2,
                    kind
                },
                20
            ),
            Err(Fault::ConflictingLifecycle)
        );
        let s = t.finish(true);
        assert_eq!(s.invalidated_records, 1);
        assert_eq!(s.start_bounded_records, 0);
    }
}

#[test]
fn duplicate_start_is_a_conflict_even_with_identical_object_key() {
    let mut t = Tracker::default();
    process(&mut t, 42, 1, Kind::Start, 10);
    assert_eq!(
        t.process(
            Event {
                pid: 42,
                key: 1,
                kind: Kind::Start
            },
            11
        ),
        Err(Fault::ConflictingLifecycle)
    );
}

#[test]
fn late_loss_or_source_failure_discards_all_correlation_results() {
    let mut t = Tracker::default();
    process(&mut t, 42, 1, Kind::Start, 10);
    network(&mut t, 42, 15);
    process(&mut t, 42, 1, Kind::End, 20);
    let s = t.finish(false);
    assert_eq!(s.invalidated_records, 1);
    assert_eq!(s.start_bounded_records, 0);
    assert_eq!(s.status, State::Unavailable);
    assert_eq!(s.reason, Some(Fault::SourceUnavailable));
}

#[test]
fn process_and_network_time_regression_is_sticky() {
    let mut t = Tracker::default();
    process(&mut t, 42, 1, Kind::Start, 10);
    network(&mut t, 42, 15);
    assert_eq!(
        t.process(
            Event {
                pid: 42,
                key: 1,
                kind: Kind::End
            },
            14
        ),
        Err(Fault::TimestampRegression)
    );
    assert_eq!(t.network(Some(42), 16), Err(Fault::TimestampRegression));
    assert_eq!(t.finish(true).invalidated_records, 1);
}

#[test]
fn idle_process_is_counted_and_never_correlated_to_network() {
    let mut t = Tracker::default();
    process(&mut t, 0, 0, Kind::RundownStart, 10);
    let s = t.finish(true);
    assert_eq!(s.idle_process_events, 1);
    assert_eq!(s.observed_process_lifetimes, 0);
    let mut t = Tracker::default();
    assert_eq!(t.network(Some(0), 11), Err(Fault::InvalidIdentity));
}

#[test]
fn bounded_histories_do_not_evict_old_evidence_and_reassign_pids() {
    let mut t = Tracker::default();
    for i in 0..MAX_LIFETIMES {
        process(&mut t, i + 1, u64::from(i + 1), Kind::Start, u64::from(i));
    }
    assert_eq!(
        t.process(
            Event {
                pid: MAX_LIFETIMES + 1,
                key: 1,
                kind: Kind::Start
            },
            u64::from(MAX_LIFETIMES)
        ),
        Err(Fault::LifetimeLimit)
    );
    assert_eq!(t.lifetimes, MAX_LIFETIMES);
    let mut t = Tracker::default();
    for i in 0..MAX_PROCESS_RECORDS {
        process(&mut t, 42, 1, Kind::End, u64::from(i));
    }
    assert_eq!(
        t.process(
            Event {
                pid: 42,
                key: 1,
                kind: Kind::End
            },
            u64::from(MAX_PROCESS_RECORDS)
        ),
        Err(Fault::ProcessRecordLimit)
    );
}

#[test]
fn network_limit_stops_growth_and_never_returns_partial_matches() {
    let mut t = Tracker::default();
    for i in 0..super::super::MAX_NETWORK_RECORDS {
        network(&mut t, 42, u64::from(i));
    }
    assert_eq!(
        t.network(Some(42), u64::from(super::super::MAX_NETWORK_RECORDS)),
        Err(Fault::NetworkRecordLimit)
    );
    let s = t.finish(true);
    assert_eq!(s.invalidated_records, super::super::MAX_NETWORK_RECORDS);
}
