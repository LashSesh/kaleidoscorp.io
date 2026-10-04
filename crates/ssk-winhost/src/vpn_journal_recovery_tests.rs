use super::*;
use crate::service::{acl, AceEntry, PathSecurity, ProbeError};
use ssk_netd_helper::vpn::{
    journal::{Event, Kind},
    Phase, Status,
};

#[derive(Default)]
struct Probe {
    deny_suffix: Option<String>,
}
impl PathSecurityProbe for Probe {
    fn inspect(&self, path: &Path) -> Result<PathSecurity, ProbeError> {
        let mut aces = vec![AceEntry::allow(acl::SID_LOCAL_SYSTEM, acl::GENERIC_ALL)];
        if self
            .deny_suffix
            .as_ref()
            .is_some_and(|s| path.to_string_lossy().ends_with(s))
        {
            aces.push(AceEntry::allow("S-1-1-0", 1));
        }
        Ok(PathSecurity {
            owner_sid: acl::SID_LOCAL_SYSTEM.into(),
            aces: Some(aces),
            is_reparse_point: false,
        })
    }
}
struct Fixture {
    temp: tempfile::TempDir,
    root: PathBuf,
    archive: PathBuf,
    archive_sha: String,
    head: String,
    count: u64,
    observed: String,
    originals: Vec<Vec<u8>>,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("profiles");
        fs::create_dir(&root).unwrap();
        let mut f = Self {
            archive: temp.path().join("source.sskj"),
            temp,
            root,
            archive_sha: String::new(),
            head: String::new(),
            count: 6,
            observed: String::new(),
            originals: Vec::new(),
        };
        let mut j = Journal::open(Box::new(f.store(true).unwrap())).unwrap();
        for revision in 1..=6 {
            j.append(Event {
                kind: Kind::Observation,
                actor: "service".into(),
                command: None,
                deployment: None,
                status: Status {
                    revision,
                    phase: Phase::Preparing,
                    profile: Some("corp".into()),
                    exit_confirmed: Some(false),
                    ..Status::default()
                },
            })
            .unwrap();
        }
        let i = j.inspection();
        f.head = i.head.to_hex();
        drop(j);
        f.originals = (0..2)
            .map(|i| fs::read(f.root.join(name(i))).unwrap())
            .collect();
        let report = super::super::backup_with(
            &mut f.store(false).unwrap(),
            &f.archive,
            &Anchor::parse(&f.head, f.count).unwrap(),
            &Probe::default(),
        )
        .unwrap();
        f.archive_sha = report.archive_sha256;
        fs::write(f.root.join(name(1)), b"damaged original PRIVATE_MARKER").unwrap();
        f.refresh();
        f
    }
    fn profiles(&self) -> ProfileStore {
        ProfileStore::open_layout(
            StateDirLayout::new(&self.root, 1).unwrap(),
            &Probe::default(),
        )
        .unwrap()
    }
    fn store(&self, create: bool) -> io::Result<SegmentedJournal> {
        SegmentedJournal::open_with(
            self.profiles(),
            create,
            Limits {
                records: 4,
                ..Limits::default()
            },
            Box::new(Probe::default()),
        )
    }
    fn request(&self) -> RecoveryRequest<'_> {
        RecoveryRequest {
            archive: &self.archive,
            expected_archive_sha256: &self.archive_sha,
            expected_head: &self.head,
            expected_records: self.count,
            expected_observed: &self.observed,
        }
    }
    fn refresh(&mut self) {
        self.observed = diagnose_with(&self.profiles(), &Probe::default())
            .unwrap()
            .observed_sha256;
    }
    fn run(
        &self,
        plan: Option<&str>,
        checkpoint: &mut dyn FnMut(&str) -> io::Result<()>,
    ) -> io::Result<RecoveryReport> {
        run_with(
            &self.profiles(),
            &Probe::default(),
            &self.request(),
            plan,
            checkpoint,
        )
    }
    fn stage(&self) -> io::Result<RecoveryReport> {
        self.run(None, &mut |_| Ok(()))
    }
    fn plan(&self) -> String {
        diagnose_with(&self.profiles(), &Probe::default())
            .unwrap()
            .recovery_plan_sha256
            .unwrap()
    }
    fn resume(&self) -> io::Result<RecoveryReport> {
        self.run(Some(&self.plan()), &mut |_| Ok(()))
    }
    fn assert_blocked(&self) {
        assert!(self.store(true).is_err());
        assert!(self.store(false).is_err());
    }
}

#[test]
fn recovery_diagnosis_handles_damaged_missing_and_gapped_originals_without_mutation() {
    let mut f = Fixture::new();
    let diagnosis = diagnose_with(&f.profiles(), &Probe::default()).unwrap();
    assert_eq!(diagnosis.segments.len(), 2);
    assert!(!diagnosis.service_blocked_by_recovery);
    assert!(!serde_json::to_string(&diagnosis)
        .unwrap()
        .contains("PRIVATE_MARKER"));
    fs::remove_file(f.root.join(name(0))).unwrap();
    f.refresh();
    assert_ne!(f.observed, diagnosis.observed_sha256);
    assert_eq!(fs::read_dir(&f.root).unwrap().count(), 1);
    fs::remove_file(f.root.join(name(1))).unwrap();
    f.refresh();
    assert_eq!(
        diagnose_with(&f.profiles(), &Probe::default())
            .unwrap()
            .segments
            .len(),
        0
    );
    assert_eq!(fs::read_dir(&f.root).unwrap().count(), 0);
}

#[test]
fn recovery_stages_exact_candidate_and_original_evidence_without_activating_or_resetting_status() {
    let f = Fixture::new();
    let damaged = fs::read(f.root.join(name(1))).unwrap();
    let report = f.stage().unwrap();
    assert_eq!(report.attempt, 1);
    assert!(report.service_blocked && !report.activation_performed);
    assert_eq!(
        report.inspection.last_status.as_ref().unwrap().phase,
        Phase::Preparing
    );
    assert_eq!(
        report.inspection.last_status.unwrap().exit_confirmed,
        Some(false)
    );
    assert!(!report.inspection.accepts_intent);
    for index in 0..2 {
        assert_eq!(
            fs::read(report.candidate_directory.join(name(index))).unwrap(),
            f.originals[index]
        );
    }
    assert_eq!(
        fs::read(report.evidence_directory.join(name(1))).unwrap(),
        damaged
    );
    assert_eq!(fs::read(f.root.join(name(1))).unwrap(), damaged);
    f.assert_blocked();
    assert_eq!(f.resume().unwrap().attempt, 1);
    f.assert_blocked();
    assert!(f.stage().is_err());
}

#[test]
fn recovery_missing_origin_never_becomes_a_fresh_service_history() {
    let mut f = Fixture::new();
    fs::remove_file(f.root.join(name(0))).unwrap();
    f.refresh();
    let report = f.stage().unwrap();
    f.assert_blocked();
    assert!(!f.root.join(name(0)).exists());
    assert!(report.candidate_directory.join(name(0)).exists());
    assert!(!report.evidence_directory.join(name(0)).exists());
}

#[test]
fn recovery_rejects_stale_or_untrusted_inputs_before_claiming_the_marker() {
    for field in 0..5 {
        let mut f = Fixture::new();
        match field {
            0 => f.observed = "ab".repeat(32),
            1 => f.archive_sha = "ab".repeat(32),
            2 => f.head = "ab".repeat(32),
            3 => f.count = 7,
            _ => {
                f.count = 0;
                f.head = "00".repeat(32);
            }
        }
        assert!(f.stage().is_err());
        assert!(!f.root.join(MARKER).exists());
        assert_eq!(fs::read_dir(&f.root).unwrap().count(), 2);
    }
}

#[test]
fn recovery_resumes_each_synced_boundary_preserving_failed_attempts_and_uncertain_completion() {
    for point in [
        "marker-synced",
        "evidence-file-synced",
        "candidate-file-synced",
        "complete-synced",
    ] {
        let f = Fixture::new();
        assert!(f
            .run(None, &mut |seen| if seen == point {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                Ok(())
            })
            .is_err());
        f.assert_blocked();
        let report = f.resume().unwrap();
        assert_eq!(
            report.attempt,
            if point == "evidence-file-synced" || point == "candidate-file-synced" {
                2
            } else {
                1
            }
        );
        f.assert_blocked();
        assert_eq!(
            fs::read(f.root.join(name(1))).unwrap(),
            b"damaged original PRIVATE_MARKER"
        );
    }
}

#[test]
fn recovery_never_overwrites_a_partial_candidate_in_a_previous_attempt() {
    let f = Fixture::new();
    assert!(f
        .run(None, &mut |s| if s == "candidate-file-synced" {
            Err(io::ErrorKind::Interrupted.into())
        } else {
            Ok(())
        })
        .is_err());
    let plan: Plan = serde_json::from_slice(&fs::read(f.root.join(MARKER)).unwrap()).unwrap();
    let old = f.root.join(format!(
        "journal-recovery-{}/attempt-0001/candidate/{}",
        plan.id,
        name(0)
    ));
    fs::write(&old, b"torn copy preserved").unwrap();
    let report = f.resume().unwrap();
    assert_eq!(report.attempt, 2);
    assert_eq!(fs::read(old).unwrap(), b"torn copy preserved");
}

#[test]
fn recovery_refuses_modified_completed_candidate_evidence_or_receipt_without_new_attempt() {
    for field in 0..3 {
        let f = Fixture::new();
        let report = f.stage().unwrap();
        let path = match field {
            0 => report.candidate_directory.join(name(0)),
            1 => report.evidence_directory.join(name(1)),
            _ => report
                .candidate_directory
                .parent()
                .unwrap()
                .join("complete.json"),
        };
        fs::write(&path, b"corruption").unwrap();
        assert!(f.resume().is_err());
        f.assert_blocked();
        assert!(!report
            .candidate_directory
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("attempt-0002")
            .exists());
        assert_eq!(fs::read(path).unwrap(), b"corruption");
    }
}

#[test]
fn recovery_requires_pinned_plan_and_originals_to_stay_identical() {
    let f = Fixture::new();
    f.stage().unwrap();
    assert!(f.run(Some(&"ab".repeat(32)), &mut |_| Ok(())).is_err());
    fs::write(f.root.join(name(1)), b"changed after diagnosis").unwrap();
    assert!(f.resume().is_err());
    f.assert_blocked();
}

#[test]
fn recovery_empty_torn_or_unsafe_marker_fences_even_an_empty_store() {
    for bytes in [b"".as_slice(), b"{torn"] {
        let f = Fixture::new();
        fs::remove_file(f.root.join(name(0))).unwrap();
        fs::remove_file(f.root.join(name(1))).unwrap();
        fs::write(f.root.join(MARKER), bytes).unwrap();
        f.assert_blocked();
        assert!(!f.root.join(name(0)).exists());
    }
    let f = Fixture::new();
    let probe = Probe {
        deny_suffix: Some(MARKER.into()),
    };
    assert!(run_with(&f.profiles(), &probe, &f.request(), None, &mut |_| Ok(())).is_err());
    assert_eq!(fs::metadata(f.root.join(MARKER)).unwrap().len(), 0);
    f.assert_blocked();
}

#[test]
fn recovery_checks_candidate_permissions_before_writing_any_journal_bytes() {
    let f = Fixture::new();
    let probe = Probe {
        deny_suffix: Some(format!("candidate\\{}", name(0))),
    };
    assert!(run_with(&f.profiles(), &probe, &f.request(), None, &mut |_| Ok(())).is_err());
    let plan: Plan = serde_json::from_slice(&fs::read(f.root.join(MARKER)).unwrap()).unwrap();
    let file = f.root.join(format!(
        "journal-recovery-{}/attempt-0001/candidate/{}",
        plan.id,
        name(0)
    ));
    assert_eq!(fs::metadata(file).unwrap().len(), 0);
    f.assert_blocked();
}

#[test]
fn recovery_attempt_bound_preserves_all_failed_copies_and_remains_blocked() {
    let f = Fixture::new();
    let fault = |s: &str| {
        if s == "candidate-file-synced" {
            Err(io::ErrorKind::Interrupted.into())
        } else {
            Ok(())
        }
    };
    assert!(f.run(None, &mut |s| fault(s)).is_err());
    for _ in 1..MAX_ATTEMPTS {
        assert!(f.run(Some(&f.plan()), &mut |s| fault(s)).is_err());
    }
    assert!(f.resume().is_err());
    f.assert_blocked();
    let plan: Plan = serde_json::from_slice(&fs::read(f.root.join(MARKER)).unwrap()).unwrap();
    assert_eq!(
        fs::read_dir(f.root.join(format!("journal-recovery-{}", plan.id)))
            .unwrap()
            .count(),
        MAX_ATTEMPTS
    );
}

#[test]
fn recovery_writer_exclusion_and_malformed_original_namespace_fail_before_fencing() {
    let f = Fixture::new();
    let _locked = f.store(false).unwrap();
    assert!(f.stage().is_err());
    assert!(!f.root.join(MARKER).exists());
    let f = Fixture::new();
    fs::write(f.root.join("openvpn-control-1.journal"), b"preserve").unwrap();
    assert!(f.stage().is_err());
    assert!(!f.root.join(MARKER).exists());
    let f = Fixture::new();
    fs::hard_link(f.root.join(name(1)), f.temp.path().join("alias")).unwrap();
    assert!(f.stage().is_err());
    assert!(!f.root.join(MARKER).exists());
}

#[test]
fn recovery_verifies_copied_bytes_before_writing_a_completion_receipt() {
    let f = Fixture::new();
    let mut attempt = None;
    assert!(f
        .run(None, &mut |point| {
            if point == "copies-synced" {
                let folder = fs::read_dir(&f.root)?
                    .filter_map(Result::ok)
                    .find(|e| {
                        e.file_name()
                            .to_string_lossy()
                            .starts_with("journal-recovery-")
                    })
                    .unwrap()
                    .path();
                let path = folder.join("attempt-0001");
                fs::write(
                    path.join("candidate").join(name(0)),
                    b"simulated corrupt copy",
                )?;
                attempt = Some(path);
            }
            Ok(())
        })
        .is_err());
    let attempt = attempt.unwrap();
    assert!(!attempt.join("complete.json").exists());
    assert_eq!(f.resume().unwrap().attempt, 2);
    assert_eq!(
        fs::read(attempt.join("candidate").join(name(0))).unwrap(),
        b"simulated corrupt copy"
    );
    f.assert_blocked();
}
