use super::recovery::{
    diagnose_with, reconcile_with as reconcile_restore_with, restore_with, RestoreRequest,
};

impl Fixture {
    fn restore(
        &self,
        journal: &mut Journal,
        committed: &str,
        observed: &str,
    ) -> Result<RecoveryReport> {
        restore_with(
            &self.store(),
            &Probe::default(),
            journal,
            "S-1-5-18",
            RestoreRequest {
                expected_committed: committed,
                expected_observed: observed,
                source: None,
            },
            replace_selector,
        )
    }
    fn reconcile_restore(&self, journal: &mut Journal) -> Result<RecoveryReport> {
        reconcile_restore_with(&self.store(), &Probe::default(), journal, "S-1-5-18")
    }
}
fn repair_fixture() -> (Fixture, Journal, String) {
    let f = Fixture::new();
    let mut journal = f.journal();
    let id = f.stage(&journal, "committed.example", "S-1-5-19");
    f.activate(&mut journal, &id, "none").unwrap();
    (f, journal, id)
}
fn evidence_files(f: &Fixture) -> Vec<PathBuf> {
    fs::read_dir(&f.path)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("configuration-evidence-")
        })
        .collect()
}

#[test]
fn diagnosis_reports_damage_without_changing_files_or_exposing_contents() {
    let (f, journal, id) = repair_fixture();
    let before = fs::read(f.path.join("openvpn-control.journal")).unwrap();
    let bad = b"private_key SECRET_BROKEN_CONTENT committed.example";
    fs::write(f.path.join(ACTIVE), bad).unwrap();
    let entries = fs::read_dir(&f.path).unwrap().count();
    let diagnosis = diagnose_with(&f.store(), &Probe::default(), &journal);
    assert_eq!(diagnosis.active.state, ArtifactState::InvalidDocument);
    assert_eq!(diagnosis.active.sha256, Some(hex(&sha(bad))));
    assert_eq!(diagnosis.expected_configuration_sha256, Some(id));
    assert_eq!(diagnosis.next_step, Advice::RestoreRetained);
    let json = serde_json::to_string(&diagnosis).unwrap();
    assert!(!json.contains("SECRET_BROKEN_CONTENT"));
    assert!(!json.contains("committed.example"));
    assert_eq!(
        fs::read(f.path.join("openvpn-control.journal")).unwrap(),
        before
    );
    assert_eq!(fs::read_dir(&f.path).unwrap().count(), entries);
    assert_eq!(fs::read(f.path.join(ACTIVE)).unwrap(), bad);
}

#[test]
fn restore_preserves_damaged_bytes_and_committed_permissions() {
    let (f, mut journal, id) = repair_fixture();
    let bad = b"\0broken credential bytes";
    fs::write(f.path.join(ACTIVE), bad).unwrap();
    let report = f.restore(&mut journal, &id, &hex(&sha(bad))).unwrap();
    assert_eq!(report.outcome, "restored");
    assert_eq!(report.diagnosis.next_step, Advice::ConfigurationIntact);
    let evidence = f.path.join(format!(
        "configuration-evidence-{}.json",
        report.operation_id.unwrap()
    ));
    assert_eq!(fs::read(evidence).unwrap(), bad);
    let snapshot = f.snapshot(&journal).unwrap();
    assert!(snapshot
        .policy
        .permits(&peer("S-1-5-19"), "company-managed", Verb::Prepare));
    assert!(!snapshot
        .policy
        .permits(&peer("S-1-5-18"), "company-managed", Verb::Prepare));
    assert_eq!(journal.configuration_digest(), Some(digest(&id).unwrap()));
    assert!(!journal.has_pending_maintenance());
    let audit = fs::read(f.path.join("openvpn-control.journal")).unwrap();
    assert!(!audit.windows(bad.len()).any(|w| w == bad));
}

#[test]
fn missing_active_configuration_is_restored_and_intact_retry_is_a_noop() {
    let (f, mut journal, id) = repair_fixture();
    fs::remove_file(f.path.join(ACTIVE)).unwrap();
    assert_eq!(
        diagnose_with(&f.store(), &Probe::default(), &journal)
            .active
            .state,
        ArtifactState::Missing
    );
    f.restore(&mut journal, &id, "missing").unwrap();
    assert!(evidence_files(&f).is_empty());
    let before = journal.inspection().records;
    assert_eq!(
        f.restore(&mut journal, &id, &id).unwrap().outcome,
        "already-intact"
    );
    assert_eq!(journal.inspection().records, before);
}

#[test]
fn stale_observation_or_committed_digest_cannot_replace_changed_files() {
    let (f, mut journal, id) = repair_fixture();
    fs::write(f.path.join(ACTIVE), b"first").unwrap();
    let observed = hex(&sha(b"first"));
    fs::write(f.path.join(ACTIVE), b"second").unwrap();
    assert!(matches!(
        f.restore(&mut journal, &id, &observed),
        Err(DeploymentError::StaleSelection)
    ));
    assert!(matches!(
        f.restore(&mut journal, &"01".repeat(32), &hex(&sha(b"second"))),
        Err(DeploymentError::StaleSelection)
    ));
    assert_eq!(fs::read(f.path.join(ACTIVE)).unwrap(), b"second");
    assert!(evidence_files(&f).is_empty());
}

#[test]
fn a_confidential_external_copy_must_match_the_current_commit_not_an_older_version() {
    let (f, mut journal, id) = repair_fixture();
    let retained = f.path.join(format!("configuration-{id}.json"));
    let backup = f.temp.path().join("backup.json");
    fs::copy(&retained, &backup).unwrap();
    let (wrong, _) = f.source("obsolete.example", "S-1-5-18");
    fs::remove_file(retained).unwrap();
    fs::remove_file(f.path.join(ACTIVE)).unwrap();
    assert_eq!(
        diagnose_with(&f.store(), &Probe::default(), &journal).next_step,
        Advice::ObtainVerifiedCopy
    );
    assert!(matches!(
        restore_with(
            &f.store(),
            &Probe::default(),
            &mut journal,
            "S-1-5-18",
            RestoreRequest {
                expected_committed: &id,
                expected_observed: "missing",
                source: Some(&wrong)
            },
            replace_selector
        ),
        Err(DeploymentError::DigestMismatch)
    ));
    assert!(!f.path.join(ACTIVE).exists());
    restore_with(
        &f.store(),
        &Probe::default(),
        &mut journal,
        "S-1-5-18",
        RestoreRequest {
            expected_committed: &id,
            expected_observed: "missing",
            source: Some(&backup),
        },
        replace_selector,
    )
    .unwrap();
    assert!(f.snapshot(&journal).is_ok());
    assert_eq!(
        fs::read(&backup).unwrap(),
        fs::read(f.path.join(ACTIVE)).unwrap()
    );
}

#[test]
fn oversized_hardlinked_or_nonconfidential_active_files_are_not_repaired() {
    let (f, mut journal, id) = repair_fixture();
    fs::write(
        f.path.join(ACTIVE),
        vec![b'x'; configuration::MAX_BYTES + 1],
    )
    .unwrap();
    let diagnosis = diagnose_with(&f.store(), &Probe::default(), &journal);
    assert_eq!(diagnosis.active.state, ArtifactState::TooLarge);
    assert_eq!(diagnosis.next_step, Advice::PreserveForInvestigation);
    assert!(f.restore(&mut journal, &id, "missing").is_err());
    fs::write(f.path.join(ACTIVE), b"broken").unwrap();
    let linked = f.temp.path().join("linked.json");
    fs::hard_link(f.path.join(ACTIVE), &linked).unwrap();
    assert_eq!(
        diagnose_with(&f.store(), &Probe::default(), &journal)
            .active
            .state,
        ArtifactState::Unsafe
    );
    assert!(f.restore(&mut journal, &id, &hex(&sha(b"broken"))).is_err());
    fs::remove_file(linked).unwrap();
    let probe = Probe {
        deny: Some(ACTIVE.into()),
    };
    assert_eq!(
        diagnose_with(&f.store(), &probe, &journal).active.state,
        ArtifactState::Unsafe
    );
    assert!(restore_with(
        &f.store(),
        &probe,
        &mut journal,
        "S-1-5-18",
        RestoreRequest {
            expected_committed: &id,
            expected_observed: &hex(&sha(b"broken")),
            source: None
        },
        replace_selector
    )
    .is_err());
    assert!(evidence_files(&f).is_empty());
    assert_eq!(fs::read(f.path.join(ACTIVE)).unwrap(), b"broken");
}

#[test]
fn failed_evidence_confidentiality_check_writes_no_secret_and_never_changes_selection() {
    let (f, mut journal, id) = repair_fixture();
    let bad = b"damaged-secret";
    fs::write(f.path.join(ACTIVE), bad).unwrap();
    let before = journal.inspection().records;
    let probe = Probe {
        deny: Some("configuration-evidence-*".into()),
    };
    assert!(restore_with(
        &f.store(),
        &probe,
        &mut journal,
        "S-1-5-18",
        RestoreRequest {
            expected_committed: &id,
            expected_observed: &hex(&sha(bad)),
            source: None
        },
        replace_selector
    )
    .is_err());
    let files = evidence_files(&f);
    assert_eq!(files.len(), 1);
    assert_eq!(fs::metadata(&files[0]).unwrap().len(), 0);
    assert_eq!(fs::read(f.path.join(ACTIVE)).unwrap(), bad);
    assert_eq!(journal.inspection().records, before);
}

#[test]
fn restore_keeps_unresolved_process_identity_and_exit_state() {
    let (f, mut journal, id) = repair_fixture();
    let status = Status {
        revision: 3,
        phase: Phase::RecoveryRequired,
        profile: Some("company-managed".into()),
        exit_confirmed: Some(false),
        process_identity: Some(ssk_netd_helper::vpn::ProcessIdentity {
            pid: 42,
            created_at: 987,
            launch_id: [2; 16],
        }),
        ..Status::default()
    };
    journal
        .append(Event {
            kind: Kind::Observation,
            actor: "service".into(),
            command: None,
            status: status.clone(),
            deployment: None,
        })
        .unwrap();
    fs::remove_file(f.path.join(ACTIVE)).unwrap();
    let restored = f.restore(&mut journal, &id, "missing").unwrap();
    assert!(restored.diagnosis.process_recovery_required);
    let expected = Status {
        revision: 5,
        ..status
    };
    assert_eq!(journal.last(), Some(&expected));
    assert!(f.snapshot(&journal).is_ok());
}

#[test]
fn restore_interruptions_are_reconciled_as_unchanged_or_restored_without_automatic_moves() {
    for after_move in [false, true] {
        let (f, mut journal, id) = repair_fixture();
        fs::write(f.path.join(ACTIVE), b"broken").unwrap();
        assert!(restore_with(
            &f.store(),
            &Probe::default(),
            &mut journal,
            "S-1-5-18",
            RestoreRequest {
                expected_committed: &id,
                expected_observed: &hex(&sha(b"broken")),
                source: None
            },
            |from, to| {
                if after_move {
                    replace_selector(from, to)?;
                }
                Err(io::ErrorKind::Interrupted.into())
            }
        )
        .is_err());
        assert!(journal.pending_repair().is_some());
        assert!(matches!(
            f.snapshot(&journal),
            Err(DeploymentError::RecoveryRequired)
        ));
        assert!(matches!(
            f.restore(&mut journal, &id, "missing"),
            Err(DeploymentError::RecoveryRequired)
        ));
        assert!(f.reconcile(&mut journal).is_err());
        drop(journal);
        let mut journal = f.journal();
        let before = fs::read(f.path.join(ACTIVE)).unwrap();
        let result = f.reconcile_restore(&mut journal).unwrap();
        assert_eq!(
            result.outcome,
            if after_move { "restored" } else { "unchanged" }
        );
        assert_eq!(fs::read(f.path.join(ACTIVE)).unwrap(), before);
        assert!(!journal.has_pending_maintenance());
        if !after_move {
            assert!(f.snapshot(&journal).is_err());
        }
    }
}

#[test]
fn reconciliation_requires_preserved_evidence_and_refuses_unexpected_active_bytes() {
    let (f, mut journal, id) = repair_fixture();
    fs::write(f.path.join(ACTIVE), b"broken").unwrap();
    assert!(restore_with(
        &f.store(),
        &Probe::default(),
        &mut journal,
        "S-1-5-18",
        RestoreRequest {
            expected_committed: &id,
            expected_observed: &hex(&sha(b"broken")),
            source: None
        },
        |from, to| {
            replace_selector(from, to)?;
            Err(io::ErrorKind::Interrupted.into())
        }
    )
    .is_err());
    let evidence = evidence_files(&f).pop().unwrap();
    fs::write(&evidence, b"altered-evidence").unwrap();
    assert!(f.reconcile_restore(&mut journal).is_err());
    fs::remove_file(&evidence).unwrap();
    assert!(f.reconcile_restore(&mut journal).is_err());
    fs::write(&evidence, b"broken").unwrap();
    let selected = fs::read(f.path.join(ACTIVE)).unwrap();
    fs::write(f.path.join(ACTIVE), b"unrelated").unwrap();
    assert!(f.reconcile_restore(&mut journal).is_err());
    assert!(journal.pending_repair().is_some());
    fs::write(f.path.join(ACTIVE), selected).unwrap();
    f.reconcile_restore(&mut journal).unwrap();
}

#[test]
fn failed_restore_audit_preserves_disk_outcome_and_pending_intent() {
    for after_move in [false, true] {
        let f = Fixture::new();
        let fail = Arc::new(AtomicBool::new(false));
        let mut journal = Journal::open(Box::new(FaultStore {
            inner: f.disk(),
            fail: fail.clone(),
        }))
        .unwrap();
        let id = f.stage(&journal, "committed.example", "S-1-5-19");
        f.activate(&mut journal, &id, "none").unwrap();
        fs::remove_file(f.path.join(ACTIVE)).unwrap();
        fail.store(!after_move, Ordering::SeqCst);
        assert!(restore_with(
            &f.store(),
            &Probe::default(),
            &mut journal,
            "S-1-5-18",
            RestoreRequest {
                expected_committed: &id,
                expected_observed: "missing",
                source: None
            },
            |from, to| {
                replace_selector(from, to)?;
                fail.store(true, Ordering::SeqCst);
                Ok(())
            }
        )
        .is_err());
        assert_eq!(f.path.join(ACTIVE).exists(), after_move);
        drop(journal);
        let mut journal = f.journal();
        assert_eq!(journal.pending_repair().is_some(), after_move);
        assert_eq!(journal.configuration_digest(), Some(digest(&id).unwrap()));
        if after_move {
            f.reconcile_restore(&mut journal).unwrap();
        }
    }
}
