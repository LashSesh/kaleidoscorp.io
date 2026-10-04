use ssk_netanalysis::{
    Assessment, Baseline, BaselineConfig, ConfigError, Finding, Observation, Provenance, Scope,
    Signal, Transport, UnavailableReason as U, Verdict, WindowAnalyzer,
};

fn config() -> BaselineConfig {
    BaselineConfig {
        window_ms: 1000,
        valid_for_ms: 1000,
        max_events: 32,
        min_events: 1,
        max_attempts_per_second: 2,
        min_attempts_for_failure_rate: 4,
        max_failed_basis_points: 5000,
        max_sent_bytes_per_second: 1000,
        min_sent_bytes_for_imbalance: 100,
        max_sent_to_received_ratio: 4,
    }
}

fn scope() -> Scope {
    Scope {
        source_epoch: "fixture-epoch-1".into(),
        subject: "application:process-incarnation-1".into(),
        endpoint: "192.0.2.1:443".parse().unwrap(),
        transport: Transport::Tcp,
    }
}

fn analyzer(c: BaselineConfig) -> WindowAnalyzer {
    WindowAnalyzer::new(
        Baseline::new(c).unwrap(),
        scope(),
        Provenance::SyntheticReplay,
        0,
        1,
    )
    .unwrap()
}

fn event(sequence: u64, at_ms: u64, signal: Signal) -> Observation {
    Observation {
        scope: scope(),
        sequence,
        at_ms,
        signal,
    }
}

fn attempt(sequence: u64, failed: bool) -> Observation {
    event(sequence, sequence, Signal::ConnectionAttempt { failed })
}

fn transfer(sequence: u64, sent_bytes: u64, received_bytes: u64) -> Observation {
    event(
        sequence,
        sequence,
        Signal::Transfer {
            sent_bytes,
            received_bytes,
        },
    )
}

fn unavailable(a: &Assessment, reason: U) {
    assert_eq!(a.snapshot_verdict(), &Verdict::Unavailable { reason });
}

fn findings(a: &Assessment) -> Vec<Finding> {
    match a.snapshot_verdict() {
        Verdict::Suspicious { findings } => findings.clone(),
        other => panic!("expected suspicious, got {other:?}"),
    }
}

#[test]
fn an_empty_window_is_unknown_even_after_its_deadline() {
    unavailable(&analyzer(config()).assess(1000), U::InsufficientSamples);
}

#[test]
fn complete_zero_byte_observation_has_finite_explicit_counters() {
    let mut a = analyzer(config());
    a.observe(&transfer(1, 0, 0)).unwrap();
    let report = a.assess(1000);
    assert_eq!(report.snapshot_verdict(), &Verdict::NoAnomalyObserved);
    let json = serde_json::to_value(&report).unwrap();
    for flag in [
        "identity_verified",
        "coverage_verified",
        "enforcement_active",
    ] {
        assert_eq!(json[flag], false);
    }
    assert_eq!(json["advisory_only"], true);
    assert_eq!(json["provenance"], "synthetic_replay");
    assert_eq!(json["metrics"]["sent_bytes"], 0);
}

#[test]
fn exact_thresholds_do_not_trigger_but_exceeding_them_does() {
    let mut a = analyzer(config());
    a.observe(&attempt(1, false)).unwrap();
    a.observe(&attempt(2, false)).unwrap();
    a.observe(&transfer(3, 1000, 250)).unwrap();
    assert_eq!(
        a.assess(1000).snapshot_verdict(),
        &Verdict::NoAnomalyObserved
    );
    a.observe(&attempt(4, false)).unwrap();
    a.observe(&transfer(5, 1, 0)).unwrap();
    assert_eq!(
        findings(&a.assess(1000)),
        vec![
            Finding::AttemptRateExceeded,
            Finding::SentRateExceeded,
            Finding::SentReceivedImbalance,
        ]
    );
}

#[test]
fn failure_ratio_uses_a_minimum_sample_count_and_basis_points() {
    let mut c = config();
    c.max_attempts_per_second = 100;
    let mut a = analyzer(c.clone());
    for sequence in 1..4 {
        a.observe(&attempt(sequence, true)).unwrap();
    }
    assert_eq!(
        a.assess(1000).snapshot_verdict(),
        &Verdict::NoAnomalyObserved
    );
    a.observe(&attempt(4, false)).unwrap();
    assert_eq!(
        findings(&a.assess(1000)),
        vec![Finding::FailureRatioExceeded]
    );
    let mut b = analyzer(c);
    for sequence in 1..=4 {
        b.observe(&attempt(sequence, sequence <= 2)).unwrap();
    }
    assert_eq!(
        b.assess(1000).snapshot_verdict(),
        &Verdict::NoAnomalyObserved
    );
}

#[test]
fn rates_use_the_actual_duration_without_integer_rounding() {
    let mut c = config();
    c.window_ms = 1500;
    let mut a = analyzer(c);
    for sequence in 1..=3 {
        a.observe(&attempt(sequence, false)).unwrap();
    }
    a.observe(&transfer(4, 1500, 1500)).unwrap();
    assert_eq!(
        a.assess(1500).snapshot_verdict(),
        &Verdict::NoAnomalyObserved
    );
    a.observe(&transfer(5, 1, 0)).unwrap();
    assert_eq!(findings(&a.assess(1500)), vec![Finding::SentRateExceeded]);
}

#[test]
fn zero_received_bytes_require_the_minimum_sent_volume() {
    let mut a = analyzer(config());
    a.observe(&transfer(1, 99, 0)).unwrap();
    assert_eq!(
        a.assess(1000).snapshot_verdict(),
        &Verdict::NoAnomalyObserved
    );
    a.observe(&transfer(2, 1, 0)).unwrap();
    assert_eq!(
        findings(&a.assess(1000)),
        vec![Finding::SentReceivedImbalance]
    );
}

#[test]
fn incomplete_and_expired_windows_are_never_clean_evidence() {
    let mut a = analyzer(config());
    a.observe(&attempt(1, false)).unwrap();
    unavailable(&a.assess(999), U::IncompleteWindow);
    assert_eq!(
        a.assess(1000).snapshot_verdict(),
        &Verdict::NoAnomalyObserved
    );
    assert_eq!(
        a.assess(1999).snapshot_verdict(),
        &Verdict::NoAnomalyObserved
    );
    unavailable(&a.assess(2000), U::Expired);
    unavailable(&a.assess(0), U::ClockRegression);
}

#[test]
fn snapshots_require_matching_scope_baseline_and_freshness() {
    let mut a = analyzer(config());
    a.observe(&attempt(1, false)).unwrap();
    let report = a.assess(1000);
    let id = report.baseline_id();
    assert_eq!(
        report.verdict_for(&scope(), id, 1999),
        Verdict::NoAnomalyObserved
    );
    for (time, reason) in [(999, U::ClockRegression), (2000, U::Expired)] {
        assert_eq!(
            report.verdict_for(&scope(), id, time),
            Verdict::Unavailable { reason }
        );
    }
    assert_eq!(
        report.verdict_for(&scope(), "another-model", 1000),
        Verdict::Unavailable {
            reason: U::BaselineMismatch
        }
    );
    let mut other = scope();
    other.source_epoch = "fixture-epoch-2".into();
    assert_eq!(
        report.verdict_for(&other, id, 1000),
        Verdict::Unavailable {
            reason: U::ScopeMismatch
        }
    );
}

#[test]
fn incomplete_snapshots_do_not_become_valid_by_waiting() {
    let mut a = analyzer(config());
    a.observe(&attempt(1, false)).unwrap();
    let report = a.assess(500);
    assert_eq!(
        report.verdict_for(&scope(), report.baseline_id(), 1000),
        Verdict::Unavailable {
            reason: U::IncompleteWindow
        }
    );
}

#[test]
fn duplicates_gaps_and_reordering_poison_the_window() {
    for bad in [1, 3, 0] {
        let mut a = analyzer(config());
        a.observe(&attempt(1, false)).unwrap();
        assert_eq!(
            a.observe(&attempt(bad, false)),
            Err(U::SequenceDiscontinuity)
        );
        assert_eq!(a.observe(&attempt(2, false)), Err(U::SequenceDiscontinuity));
        unavailable(&a.assess(1000), U::SequenceDiscontinuity);
        assert_eq!(a.assess(1000).metrics().accepted_events, 1);
    }
}

#[test]
fn any_scope_change_is_rejected_and_cannot_be_repaired() {
    let original = scope();
    let mut variants = vec![original.clone(); 5];
    variants[0].source_epoch = "new-producer".into();
    variants[1].subject = "other-process".into();
    variants[2].endpoint = "192.0.2.2:443".parse().unwrap();
    variants[3].endpoint.set_port(80);
    variants[4].transport = Transport::Udp;
    for wrong in variants {
        let mut a = analyzer(config());
        let mut e = attempt(1, false);
        e.scope = wrong;
        assert_eq!(a.observe(&e), Err(U::ScopeMismatch));
        assert_eq!(a.observe(&attempt(1, false)), Err(U::ScopeMismatch));
    }
}

#[test]
fn a_loss_report_overrides_previously_computed_findings() {
    let mut a = analyzer(config());
    a.observe(&transfer(1, 10_000, 0)).unwrap();
    assert!(!findings(&a.assess(1000)).is_empty());
    a.report_event_loss(0);
    assert!(!findings(&a.assess(1000)).is_empty());
    a.report_event_loss(1);
    assert_eq!(a.observe(&attempt(2, false)), Err(U::EventLoss));
    unavailable(&a.assess(1000), U::EventLoss);
}

#[test]
fn the_first_fault_remains_visible() {
    let mut a = analyzer(config());
    assert_eq!(a.observe(&attempt(3, false)), Err(U::SequenceDiscontinuity));
    a.report_event_loss(10);
    unavailable(&a.assess(1000), U::SequenceDiscontinuity);
}

#[test]
fn window_is_half_open_and_time_is_monotonic() {
    let mut a = analyzer(config());
    let mut e = attempt(1, false);
    e.at_ms = 0;
    a.observe(&e).unwrap();
    e.sequence = 2;
    e.at_ms = 999;
    a.observe(&e).unwrap();
    e.sequence = 3;
    e.at_ms = 1000;
    assert_eq!(a.observe(&e), Err(U::OutsideWindow));
    let mut b = analyzer(config());
    b.observe(&event(1, 100, Signal::ConnectionAttempt { failed: false }))
        .unwrap();
    assert_eq!(
        b.observe(&event(2, 99, Signal::ConnectionAttempt { failed: false })),
        Err(U::ClockRegression)
    );
    unavailable(&b.assess(1000), U::ClockRegression);
}

#[test]
fn budget_exhaustion_is_not_a_clean_truncated_sample() {
    let mut c = config();
    c.max_events = 2;
    c.min_attempts_for_failure_rate = 2;
    let mut a = analyzer(c);
    for sequence in 1..=2 {
        a.observe(&attempt(sequence, false)).unwrap();
    }
    assert_eq!(a.observe(&attempt(3, true)), Err(U::EventLimit));
    unavailable(&a.assess(1000), U::EventLimit);
    assert_eq!(a.assess(1000).metrics().accepted_events, 2);
}

#[test]
fn byte_overflow_is_atomic_and_permanent() {
    let mut a = analyzer(config());
    a.observe(&transfer(1, 1, u64::MAX)).unwrap();
    let before = a.assess(1000).metrics();
    assert_eq!(a.observe(&transfer(2, 10, 1)), Err(U::CounterOverflow));
    assert_eq!(a.assess(1000).metrics(), before);
    unavailable(&a.assess(1000), U::CounterOverflow);
    assert_eq!(a.observe(&transfer(2, 0, 0)), Err(U::CounterOverflow));
}

#[test]
fn large_counters_are_compared_without_overflow() {
    let mut c = config();
    c.max_sent_bytes_per_second = u64::MAX;
    c.max_sent_to_received_ratio = u32::MAX;
    let mut a = analyzer(c);
    a.observe(&transfer(1, u64::MAX, u64::MAX)).unwrap();
    assert_eq!(
        a.assess(1000).snapshot_verdict(),
        &Verdict::NoAnomalyObserved
    );
}

#[test]
fn sequence_wrap_is_unavailable() {
    let mut a = WindowAnalyzer::new(
        Baseline::new(config()).unwrap(),
        scope(),
        Provenance::SyntheticReplay,
        0,
        u64::MAX,
    )
    .unwrap();
    assert_eq!(a.observe(&attempt(u64::MAX, false)), Err(U::OutsideWindow));
    let mut b = WindowAnalyzer::new(
        Baseline::new(config()).unwrap(),
        scope(),
        Provenance::SyntheticReplay,
        0,
        u64::MAX,
    )
    .unwrap();
    assert_eq!(
        b.observe(&event(
            u64::MAX,
            1,
            Signal::ConnectionAttempt { failed: false }
        )),
        Err(U::CounterOverflow)
    );
}

#[test]
fn every_parameter_participates_in_baseline_identity() {
    let c = config();
    let original = Baseline::new(c.clone()).unwrap();
    assert_eq!(original.id(), Baseline::new(c.clone()).unwrap().id());
    let mut variants = vec![c; 10];
    variants[0].window_ms += 1;
    variants[1].valid_for_ms += 1;
    variants[2].max_events += 1;
    variants[3].min_events += 1;
    variants[4].max_attempts_per_second += 1;
    variants[5].min_attempts_for_failure_rate += 1;
    variants[6].max_failed_basis_points += 1;
    variants[7].max_sent_bytes_per_second += 1;
    variants[8].min_sent_bytes_for_imbalance += 1;
    variants[9].max_sent_to_received_ratio += 1;
    for changed in variants {
        assert_ne!(original.id(), Baseline::new(changed).unwrap().id());
    }
}

#[test]
fn invalid_configuration_is_rejected_before_observation() {
    let mut cases = vec![config(); 11];
    cases[0].window_ms = 999;
    cases[1].window_ms = 60_001;
    cases[2].valid_for_ms = 0;
    cases[3].max_events = 4097;
    cases[4].min_events = 0;
    cases[5].min_events = 33;
    cases[6].max_attempts_per_second = 0;
    cases[7].min_attempts_for_failure_rate = 33;
    cases[8].max_failed_basis_points = 10_001;
    cases[9].max_sent_bytes_per_second = 0;
    cases[10].max_sent_to_received_ratio = 0;
    for invalid in cases {
        assert!(Baseline::new(invalid).is_err());
    }
    assert!(matches!(
        WindowAnalyzer::new(
            Baseline::new(config()).unwrap(),
            scope(),
            Provenance::SyntheticReplay,
            u64::MAX - 1500,
            1
        ),
        Err(ConfigError::TimeOverflow)
    ));
}

#[test]
fn invalid_scope_is_rejected_before_retention() {
    let mut cases = vec![scope(); 4];
    cases[0].source_epoch = "".into();
    cases[1].subject = "a".repeat(129);
    cases[2].subject = "untrusted\nlog".into();
    cases[3].endpoint.set_port(0);
    for invalid in cases {
        assert!(matches!(
            WindowAnalyzer::new(
                Baseline::new(config()).unwrap(),
                invalid,
                Provenance::SyntheticReplay,
                0,
                1
            ),
            Err(ConfigError::InvalidScope)
        ));
    }
}

#[test]
fn replay_is_deterministic_and_configuration_affects_outcomes() {
    let mut strict = config();
    strict.max_attempts_per_second = 1;
    let mut relaxed = strict.clone();
    relaxed.max_attempts_per_second = 2;
    let mut reports = Vec::new();
    for c in [strict.clone(), strict, relaxed] {
        let mut a = analyzer(c);
        for sequence in 1..=2 {
            a.observe(&attempt(sequence, false)).unwrap();
        }
        reports.push(a.assess(1000));
    }
    assert_eq!(
        serde_json::to_vec(&reports[0]).unwrap(),
        serde_json::to_vec(&reports[1]).unwrap()
    );
    assert_eq!(findings(&reports[0]), vec![Finding::AttemptRateExceeded]);
    assert_eq!(reports[2].snapshot_verdict(), &Verdict::NoAnomalyObserved);
}
