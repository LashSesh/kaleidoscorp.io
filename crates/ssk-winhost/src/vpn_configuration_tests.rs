use super::*;
use crate::{
    service::{acl, AceEntry, PathSecurity, ProbeError},
    state_dir::StateDirLayout,
    vpn_journal::SegmentedJournal,
};
use ssk_netd_helper::{
    vpn::{
        journal::{Event, Kind, Record, Store},
        Phase, Status, Verb,
    },
    AuthenticatedPeer, PeerIdentity, PeerToken,
};
use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

#[derive(Default)]
struct Probe {
    deny: Option<String>,
}
impl PathSecurityProbe for Probe {
    fn inspect(&self, path: &Path) -> std::result::Result<PathSecurity, ProbeError> {
        let mut aces = vec![AceEntry::allow(acl::SID_LOCAL_SYSTEM, acl::GENERIC_ALL)];
        if self.deny.as_deref().is_some_and(|d| {
            path.file_name().is_some_and(|n| {
                n == d
                    || d.strip_suffix('*')
                        .is_some_and(|prefix| n.to_string_lossy().starts_with(prefix))
            })
        }) {
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
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("profiles");
        fs::create_dir(&path).unwrap();
        Self { temp, path }
    }
    fn store(&self) -> ProfileStore {
        ProfileStore::open_layout(
            StateDirLayout::new(&self.path, 1).unwrap(),
            &Probe::default(),
        )
        .unwrap()
    }
    fn disk(&self) -> SegmentedJournal {
        SegmentedJournal::open_fixture(self.store(), Box::<Probe>::default()).unwrap()
    }
    fn journal(&self) -> Journal {
        Journal::open(Box::new(self.disk())).unwrap()
    }
    fn source(&self, name: &str, sid: &str) -> (PathBuf, String) {
        let profile = include_str!("../../ssk-vpnctl/tests/fixtures/profile.json")
            .replace("vpn.example.test", name);
        let bytes = format!(
            r#"{{"schema":1,"policy":{{"schema":1,"grants":[{{"sid":"{sid}","profile":"company-managed","verbs":["status","prepare","stop","recover"]}}]}},"profiles":[{profile}]}}"#
        );
        let path = self.temp.path().join(format!("{name}.json"));
        fs::write(&path, bytes.as_bytes()).unwrap();
        (path, hex(&sha(bytes.as_bytes())))
    }
    fn stage(&self, journal: &Journal, name: &str, sid: &str) -> String {
        let (path, id) = self.source(name, sid);
        stage_with(&self.store(), &Probe::default(), journal, &path, &id).unwrap();
        id
    }
    fn activate(&self, journal: &mut Journal, id: &str, previous: &str) -> Result<Report> {
        activate_with(
            &self.store(),
            &Probe::default(),
            journal,
            "S-1-5-18",
            id,
            previous,
            replace_selector,
        )
    }
    fn snapshot(&self, journal: &Journal) -> Result<Snapshot> {
        load_for_service(&self.store(), journal, &Probe::default())
    }
    fn reconcile(&self, journal: &mut Journal) -> Result<Report> {
        reconcile_with(&self.store(), &Probe::default(), journal, "S-1-5-18")
    }
    fn legacy(&self) {
        fs::write(
            self.path.join("vpn-company-managed.json"),
            include_bytes!("../../ssk-vpnctl/tests/fixtures/profile.json"),
        )
        .unwrap();
        fs::write(self.path.join("openvpn-control.json"), br#"{"schema":1,"grants":[{"sid":"S-1-5-18","profile":"company-managed","verbs":["prepare"]}]}"#).unwrap();
    }
}
fn peer(sid: &str) -> AuthenticatedPeer {
    AuthenticatedPeer {
        sid: PeerIdentity::parse_sid(sid).unwrap(),
        token: PeerToken::unprivileged(),
    }
}

#[test]
fn whole_snapshot_update_revokes_old_grants_and_changes_profile_together() {
    let f = Fixture::new();
    let mut journal = f.journal();
    let old = f.stage(&journal, "old.example", "S-1-5-18");
    assert!(!f.path.join(ACTIVE).exists());
    f.activate(&mut journal, &old, "none").unwrap();
    let new = f.stage(&journal, "new.example", "S-1-5-19");
    assert!(matches!(
        f.activate(&mut journal, &new, "none"),
        Err(DeploymentError::StaleSelection)
    ));
    f.activate(&mut journal, &new, &old).unwrap();
    let snapshot = f.snapshot(&journal).unwrap();
    assert!(!snapshot
        .policy
        .permits(&peer("S-1-5-18"), "company-managed", Verb::Prepare));
    assert!(snapshot
        .policy
        .permits(&peer("S-1-5-19"), "company-managed", Verb::Prepare));
    let bytes = snapshot
        .profiles
        .get(&ProfileId::new("company-managed").unwrap())
        .unwrap()
        .to_document()
        .unwrap();
    assert!(std::str::from_utf8(&bytes).unwrap().contains("new.example"));
    assert_eq!(journal.configuration_digest(), Some(digest(&new).unwrap()));
    drop(snapshot);
    f.activate(&mut journal, &old, &new).unwrap();
    let count = journal.inspection().records;
    assert_eq!(
        f.activate(&mut journal, &old, &old).unwrap().action,
        "already-selected"
    );
    assert_eq!(journal.inspection().records, count);
    assert!(f.path.join(format!("configuration-{new}.json")).exists());
}

#[test]
fn committed_configuration_cannot_fall_back_to_legacy_after_deletion_or_replacement() {
    let f = Fixture::new();
    f.legacy();
    let mut journal = f.journal();
    drop(f.snapshot(&journal).unwrap());
    let id = f.stage(&journal, "managed.example", "S-1-5-19");
    f.activate(&mut journal, &id, "none").unwrap();
    fs::remove_file(f.path.join(ACTIVE)).unwrap();
    assert!(matches!(
        f.snapshot(&journal),
        Err(DeploymentError::UnknownSelection)
    ));
    drop(journal);
    let journal = f.journal();
    assert!(f.snapshot(&journal).is_err());
    fs::write(f.path.join(ACTIVE), b"{}").unwrap();
    assert!(f.snapshot(&journal).is_err());
}

#[test]
fn source_and_destination_confidentiality_are_checked_before_secret_copy() {
    let f = Fixture::new();
    let journal = f.journal();
    let (path, id) = f.source("private.example", "S-1-5-18");
    let deny_source = Probe {
        deny: Some("private.example.json".into()),
    };
    assert!(stage_with(&f.store(), &deny_source, &journal, &path, &id).is_err());
    let target = format!("configuration-{id}.json");
    assert!(!f.path.join(&target).exists());
    let deny_target = Probe {
        deny: Some(target.clone()),
    };
    assert!(stage_with(&f.store(), &deny_target, &journal, &path, &id).is_err());
    assert_eq!(fs::metadata(f.path.join(&target)).unwrap().len(), 0);
    assert!(stage_with(&f.store(), &Probe::default(), &journal, &path, &id).is_err());
    assert_eq!(fs::metadata(f.path.join(target)).unwrap().len(), 0);
}

#[test]
fn staging_rejects_wrong_approval_hardlinks_malformed_and_oversized_documents() {
    let f = Fixture::new();
    let journal = f.journal();
    let (path, id) = f.source("private.example", "S-1-5-18");
    assert!(matches!(
        stage_with(
            &f.store(),
            &Probe::default(),
            &journal,
            &path,
            &"0".repeat(64)
        ),
        Err(DeploymentError::DigestMismatch)
    ));
    let link = f.temp.path().join("linked.json");
    fs::hard_link(&path, &link).unwrap();
    assert!(stage_with(&f.store(), &Probe::default(), &journal, &path, &id).is_err());
    fs::remove_file(link).unwrap();
    fs::write(&path, b"{}").unwrap();
    assert!(stage_with(
        &f.store(),
        &Probe::default(),
        &journal,
        &path,
        &hex(&sha(b"{}"))
    )
    .is_err());
    fs::write(&path, vec![b' '; configuration::MAX_BYTES + 1]).unwrap();
    assert!(stage_with(&f.store(), &Probe::default(), &journal, &path, &id).is_err());
    assert!(!f.path.join(format!("configuration-{id}.json")).exists());
}

#[test]
fn service_snapshot_locks_selector_and_does_not_reread_legacy_profile_changes() {
    let f = Fixture::new();
    f.legacy();
    let mut journal = f.journal();
    let snapshot = f.snapshot(&journal).unwrap();
    fs::write(
        f.path.join("vpn-company-managed.json"),
        b"invalid-after-snapshot",
    )
    .unwrap();
    assert!(snapshot
        .profiles
        .get(&ProfileId::new("company-managed").unwrap())
        .is_some());
    drop(snapshot);
    let id = f.stage(&journal, "managed.example", "S-1-5-18");
    f.activate(&mut journal, &id, "none").unwrap();
    let _snapshot = f.snapshot(&journal).unwrap();
    assert!(fs::write(f.path.join(ACTIVE), b"modified").is_err());
    assert!(fs::remove_file(f.path.join(ACTIVE)).is_err());
    assert!(SegmentedJournal::open_fixture(f.store(), Box::<Probe>::default()).is_err());
}

#[test]
fn failed_move_leaves_old_snapshot_and_pending_transaction_blocks_boot() {
    let f = Fixture::new();
    let mut journal = f.journal();
    let old = f.stage(&journal, "old.example", "S-1-5-18");
    f.activate(&mut journal, &old, "none").unwrap();
    let new = f.stage(&journal, "new.example", "S-1-5-19");
    assert!(activate_with(
        &f.store(),
        &Probe::default(),
        &mut journal,
        "S-1-5-18",
        &new,
        &old,
        |_, _| Err(io::ErrorKind::Interrupted.into())
    )
    .is_err());
    assert!(matches!(
        f.snapshot(&journal),
        Err(DeploymentError::RecoveryRequired)
    ));
    drop(journal);
    let mut journal = f.journal();
    assert_eq!(
        f.reconcile(&mut journal).unwrap().configuration_sha256,
        Some(old)
    );
    assert!(f.snapshot(&journal).is_ok());
}

#[test]
fn post_move_interruption_reconciles_new_grants_without_restoring_old_ones() {
    let f = Fixture::new();
    let mut journal = f.journal();
    let id = f.stage(&journal, "managed.example", "S-1-5-19");
    assert!(activate_with(
        &f.store(),
        &Probe::default(),
        &mut journal,
        "S-1-5-18",
        &id,
        "none",
        |from, to| {
            replace_selector(from, to)?;
            Err(io::ErrorKind::Interrupted.into())
        }
    )
    .is_err());
    assert!(f.snapshot(&journal).is_err());
    drop(journal);
    let mut journal = f.journal();
    assert_eq!(
        f.reconcile(&mut journal).unwrap().configuration_sha256,
        Some(id)
    );
    assert!(!f.snapshot(&journal).unwrap().policy.permits(
        &peer("S-1-5-18"),
        "company-managed",
        Verb::Prepare
    ));
}

#[test]
fn unknown_selection_and_cross_domain_completion_never_clear_pending_intent() {
    let f = Fixture::new();
    let mut journal = f.journal();
    let id = f.stage(&journal, "managed.example", "S-1-5-18");
    assert!(activate_with(
        &f.store(),
        &Probe::default(),
        &mut journal,
        "S-1-5-18",
        &id,
        "none",
        |_, _| Err(io::ErrorKind::Interrupted.into())
    )
    .is_err());
    fs::write(f.path.join(ACTIVE), b"foreign").unwrap();
    assert!(f.reconcile(&mut journal).is_err());
    assert!(journal.pending_deployment().is_some());
    fs::remove_file(f.path.join(ACTIVE)).unwrap();
    assert!(f
        .reconcile(&mut journal)
        .unwrap()
        .configuration_sha256
        .is_none());
    journal
        .deployment(
            "S-1-5-18",
            DeploymentEvent::Begin(DeploymentChange {
                target: DeploymentTarget::Package,
                id: [7; 16],
                previous: None,
                candidate: [9; 32],
            }),
        )
        .unwrap();
    assert!(f.reconcile(&mut journal).is_err());
    assert!(journal.pending_deployment().is_some());
}

#[test]
fn reports_and_journal_metadata_never_contain_credentials_or_endpoints() {
    let f = Fixture::new();
    let mut journal = f.journal();
    let id = f.stage(&journal, "confidential.example", "S-1-5-18");
    let report = f.activate(&mut journal, &id, "none").unwrap();
    let report = serde_json::to_string(&report).unwrap();
    let metadata = serde_json::to_string(&journal.inspection()).unwrap();
    for text in [report, metadata] {
        for secret in [
            "confidential.example",
            "192.0.2.10",
            "private_key",
            "RklYVFVSR",
            "tls_crypt",
        ] {
            assert!(!text.contains(secret));
        }
    }
    let audit = fs::read(f.path.join("openvpn-control.journal")).unwrap();
    for secret in [
        "confidential.example",
        "192.0.2.10",
        "RklYVFVSR",
        "private_key",
    ] {
        assert!(!audit.windows(secret.len()).any(|w| w == secret.as_bytes()));
    }
}

#[test]
fn missing_legacy_profile_preserves_recovery_grants_but_cannot_prepare() {
    let f = Fixture::new();
    f.legacy();
    fs::write(f.path.join("openvpn-control.json"), br#"{"schema":1,"grants":[{"sid":"S-1-5-18","profile":"company-managed","verbs":["recover","status","prepare"]}]}"#).unwrap();
    fs::remove_file(f.path.join("vpn-company-managed.json")).unwrap();
    let mut journal = f.journal();
    journal
        .append(Event {
            kind: Kind::Observation,
            actor: "service".into(),
            command: None,
            deployment: None,
            status: Status {
                revision: 1,
                phase: Phase::RecoveryRequired,
                exit_confirmed: Some(false),
                ..Status::default()
            },
        })
        .unwrap();
    let snapshot = f.snapshot(&journal).unwrap();
    assert!(snapshot
        .policy
        .permits(&peer("S-1-5-18"), "company-managed", Verb::Recover));
    assert!(snapshot
        .profiles
        .get(&ProfileId::new("company-managed").unwrap())
        .is_none());
}

#[test]
fn selecting_empty_configuration_revokes_all_rights_without_legacy_fallback() {
    let f = Fixture::new();
    f.legacy();
    let mut journal = f.journal();
    let source = f.temp.path().join("revoke.json");
    let bytes = br#"{"schema":1,"policy":{"schema":1,"grants":[]},"profiles":[]}"#;
    let id = hex(&sha(bytes));
    fs::write(&source, bytes).unwrap();
    stage_with(&f.store(), &Probe::default(), &journal, &source, &id).unwrap();
    f.activate(&mut journal, &id, "none").unwrap();
    let snapshot = f.snapshot(&journal).unwrap();
    assert!(snapshot.policy.client_sids().is_empty());
    assert!(snapshot.profiles.ids().is_empty());
}

#[test]
fn unresolved_process_history_prevents_configuration_staging() {
    let f = Fixture::new();
    let mut journal = f.journal();
    journal
        .append(Event {
            kind: Kind::Observation,
            actor: "service".into(),
            command: None,
            deployment: None,
            status: Status {
                revision: 1,
                phase: Phase::RecoveryRequired,
                exit_confirmed: Some(false),
                ..Status::default()
            },
        })
        .unwrap();
    let (source, id) = f.source("private.example", "S-1-5-18");
    assert!(matches!(
        stage_with(&f.store(), &Probe::default(), &journal, &source, &id),
        Err(DeploymentError::BusyHistory)
    ));
    assert!(!f.path.join(format!("configuration-{id}.json")).exists());
}

struct FaultStore {
    inner: SegmentedJournal,
    fail: Arc<AtomicBool>,
}
impl Store for FaultStore {
    fn load(&mut self) -> io::Result<Vec<Record>> {
        self.inner.load()
    }
    fn replay(&mut self, visit: &mut dyn FnMut(Record) -> io::Result<()>) -> io::Result<()> {
        self.inner.replay(visit)
    }
    fn append(&mut self, record: &Record) -> io::Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            Err(io::ErrorKind::StorageFull.into())
        } else {
            self.inner.append(record)
        }
    }
}
#[test]
fn audit_failure_before_and_after_change_never_acknowledges_unaudited_grants() {
    for after_move in [false, true] {
        let f = Fixture::new();
        let fail = Arc::new(AtomicBool::new(!after_move));
        let mut journal = Journal::open(Box::new(FaultStore {
            inner: f.disk(),
            fail: fail.clone(),
        }))
        .unwrap();
        let id = f.stage(&journal, "managed.example", "S-1-5-18");
        assert!(activate_with(
            &f.store(),
            &Probe::default(),
            &mut journal,
            "S-1-5-18",
            &id,
            "none",
            |from, to| {
                replace_selector(from, to)?;
                fail.store(true, Ordering::SeqCst);
                Ok(())
            }
        )
        .is_err());
        assert_eq!(f.path.join(ACTIVE).exists(), after_move);
        assert_eq!(journal.configuration_digest(), None);
        drop(journal);
        let mut journal = f.journal();
        assert_eq!(journal.pending_deployment().is_some(), after_move);
        if after_move {
            f.reconcile(&mut journal).unwrap();
        }
    }
}

include!("vpn_configuration_recovery_tests.rs");

#[path = "vpn_configuration_backup_tests.rs"]
mod backup_tests;
