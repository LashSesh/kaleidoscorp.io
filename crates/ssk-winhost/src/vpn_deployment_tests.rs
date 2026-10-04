use super::*;
use crate::{
    service::{acl, AceEntry, PathSecurity, ProbeError},
    state_dir::StateDirLayout,
};
use ssk_netd_helper::vpn::{
    journal::{Event, Kind, Record, Store},
    Phase, Status,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Clone, Default)]
struct Probe {
    deny: Option<String>,
}
impl PathSecurityProbe for Probe {
    fn inspect(&self, path: &Path) -> std::result::Result<PathSecurity, ProbeError> {
        let mut aces = vec![AceEntry::allow(acl::SID_LOCAL_SYSTEM, acl::GENERIC_ALL)];
        if path
            .file_name()
            .is_some_and(|n| self.deny.as_deref().is_some_and(|d| n == d))
        {
            aces.push(AceEntry::allow("S-1-1-0", acl::GENERIC_ALL));
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
    profiles: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let profiles = temp.path().join("profiles");
        fs::create_dir(&profiles).unwrap();
        Self { temp, profiles }
    }
    fn store(&self) -> ProfileStore {
        ProfileStore::open_layout(
            StateDirLayout::new(&self.profiles, 1).unwrap(),
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
    fn source(&self, version: &str) -> (PathBuf, String) {
        let path = self.temp.path().join(version);
        fs::create_dir(&path).unwrap();
        fs::write(path.join("openvpn.exe"), version).unwrap();
        fs::write(path.join("provider.dll"), b"library").unwrap();
        let bytes = serde_json::to_vec(&serde_json::json!({"schema":1,"protocol":"openvpn-2.6",
            "directory":path,"files":[{"name":"provider.dll","sha256":hex(&sha(b"library"))},
            {"name":"openvpn.exe","sha256":hex(&sha(version.as_bytes()))}]}))
        .unwrap();
        let manifest = self.temp.path().join(format!("{version}.json"));
        fs::write(&manifest, &bytes).unwrap();
        (manifest, hex(&sha(&bytes)))
    }
    fn stage(&self, journal: &Journal, version: &str) -> (String, String) {
        let (path, id) = self.source(version);
        let report = stage_with(&self.store(), &Probe::default(), journal, &path, &id).unwrap();
        (id, report.selection.unwrap().manifest_sha256)
    }
    fn select(&self, journal: &mut Journal, id: &str, expected: &str) -> Result<Report> {
        activate_with(
            &self.store(),
            &Probe::default(),
            journal,
            "S-1-5-18",
            id,
            expected,
            replace_selector,
        )
    }
    fn reconcile(&self, journal: &mut Journal) -> Result<Report> {
        reconcile_with(&self.store(), &Probe::default(), journal, "S-1-5-18")
    }
}

#[test]
fn stage_select_update_and_explicit_rollback_keep_both_bundles() {
    let f = Fixture::new();
    let mut journal = f.journal();
    let (v1, hash1) = f.stage(&journal, "v1");
    assert!(!f.profiles.join(ACTIVE).exists());
    assert_eq!(
        f.select(&mut journal, &v1, "none").unwrap().action,
        "selected"
    );
    let old = fs::read(f.profiles.join(ACTIVE)).unwrap();
    let (v2, hash2) = f.stage(&journal, "v2");
    assert!(matches!(
        f.select(&mut journal, &v2, "none"),
        Err(DeploymentError::StaleSelection)
    ));
    f.select(&mut journal, &v2, &hash1).unwrap();
    assert_eq!(
        fs::read(f.profiles.join(format!("manifest-{hash1}.json"))).unwrap(),
        old
    );
    assert_eq!(
        fs::read(f.profiles.join(format!("package-{v1}/openvpn.exe"))).unwrap(),
        b"v1"
    );
    f.select(&mut journal, &v1, &hash2).unwrap();
    assert_eq!(fs::read(f.profiles.join(ACTIVE)).unwrap(), old);
    let count = journal.inspection().records;
    assert_eq!(
        f.select(&mut journal, &v1, &hash1).unwrap().action,
        "already-selected"
    );
    assert_eq!(journal.inspection().records, count);
    drop(journal);
    assert!(f.journal().pending_deployment().is_none());
}

#[test]
fn stage_refuses_wrong_approval_changed_sources_and_existing_partial_directory() {
    let f = Fixture::new();
    let journal = f.journal();
    let (manifest, id) = f.source("v1");
    assert!(matches!(
        stage_with(
            &f.store(),
            &Probe::default(),
            &journal,
            &manifest,
            &"0".repeat(64)
        ),
        Err(DeploymentError::DigestMismatch)
    ));
    fs::write(f.temp.path().join("v1/openvpn.exe"), b"changed").unwrap();
    assert!(stage_with(&f.store(), &Probe::default(), &journal, &manifest, &id).is_err());
    fs::write(f.temp.path().join("v1/openvpn.exe"), b"v1").unwrap();
    let destination = f.profiles.join(format!("package-{id}"));
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("sentinel"), b"keep").unwrap();
    assert!(stage_with(&f.store(), &Probe::default(), &journal, &manifest, &id).is_err());
    assert_eq!(fs::read(destination.join("sentinel")).unwrap(), b"keep");
    assert!(!f.profiles.join(format!("package-{id}.json")).exists());
}

#[test]
fn source_manifest_hardlinks_and_unlisted_files_are_refused() {
    let f = Fixture::new();
    let journal = f.journal();
    let (manifest, id) = f.source("v1");
    let link = f.temp.path().join("linked.json");
    fs::hard_link(&manifest, &link).unwrap();
    assert!(stage_with(&f.store(), &Probe::default(), &journal, &manifest, &id).is_err());
    fs::remove_file(link).unwrap();
    fs::write(f.temp.path().join("v1/extra.dll"), b"extra").unwrap();
    assert!(stage_with(&f.store(), &Probe::default(), &journal, &manifest, &id).is_err());
    assert!(!f.profiles.join(format!("package-{id}")).exists());
}

#[test]
fn unsafe_inherited_file_acl_is_refused_before_copying_bytes() {
    let f = Fixture::new();
    let journal = f.journal();
    let (manifest, id) = f.source("v1");
    let probe = Probe {
        deny: Some("openvpn.exe".into()),
    };
    assert!(stage_with(&f.store(), &probe, &journal, &manifest, &id).is_err());
    assert_eq!(
        fs::metadata(f.profiles.join(format!("package-{id}/openvpn.exe")))
            .unwrap()
            .len(),
        0
    );
    assert!(!f.profiles.join(format!("package-{id}.json")).exists());
}

#[test]
fn failed_selector_move_keeps_old_selection_and_requires_reconciliation() {
    let f = Fixture::new();
    let mut journal = f.journal();
    let (v1, hash1) = f.stage(&journal, "v1");
    f.select(&mut journal, &v1, "none").unwrap();
    let old = fs::read(f.profiles.join(ACTIVE)).unwrap();
    let (v2, _) = f.stage(&journal, "v2");
    assert!(activate_with(
        &f.store(),
        &Probe::default(),
        &mut journal,
        "S-1-5-18",
        &v2,
        &hash1,
        |_, _| Err(io::ErrorKind::PermissionDenied.into())
    )
    .is_err());
    assert_eq!(fs::read(f.profiles.join(ACTIVE)).unwrap(), old);
    assert!(matches!(
        f.select(&mut journal, &v2, &hash1),
        Err(DeploymentError::RecoveryRequired)
    ));
    drop(journal);
    let mut journal = f.journal();
    assert!(journal.pending_deployment().is_some());
    f.reconcile(&mut journal).unwrap();
    assert!(journal.pending_deployment().is_none());
    f.select(&mut journal, &v2, &hash1).unwrap();
}

#[test]
fn crash_after_move_is_reconciled_from_verified_candidate() {
    let f = Fixture::new();
    let mut journal = f.journal();
    let (id, hash) = f.stage(&journal, "v1");
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
    drop(journal);
    let mut journal = f.journal();
    assert!(journal.pending_deployment().is_some());
    let report = f.reconcile(&mut journal).unwrap();
    assert_eq!(report.selection.unwrap().manifest_sha256, hash);
    assert!(journal.pending_deployment().is_none());
}

#[test]
fn reconciliation_refuses_foreign_selection_and_damaged_candidate() {
    let f = Fixture::new();
    let mut journal = f.journal();
    let (id, _) = f.stage(&journal, "v1");
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
    let original = fs::read(f.profiles.join(ACTIVE)).unwrap();
    fs::write(f.profiles.join(ACTIVE), b"foreign").unwrap();
    assert!(matches!(
        f.reconcile(&mut journal),
        Err(DeploymentError::UnknownSelection)
    ));
    fs::write(f.profiles.join(ACTIVE), original).unwrap();
    fs::write(
        f.profiles.join(format!("package-{id}/openvpn.exe")),
        b"modified",
    )
    .unwrap();
    assert!(f.reconcile(&mut journal).is_err());
    assert!(journal.pending_deployment().is_some());
}

#[test]
fn interrupted_first_install_can_confirm_unchanged_absence() {
    let f = Fixture::new();
    let mut journal = f.journal();
    let (id, _) = f.stage(&journal, "v1");
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
    assert!(f.reconcile(&mut journal).unwrap().selection.is_none());
    assert!(!f.profiles.join(ACTIVE).exists());
}

#[test]
fn offline_lock_and_unfinished_process_history_block_updates() {
    let f = Fixture::new();
    let mut journal = f.journal();
    assert!(SegmentedJournal::open_fixture(f.store(), Box::<Probe>::default()).is_err());
    journal
        .append(Event {
            kind: Kind::Observation,
            actor: "service".into(),
            command: None,
            status: Status {
                revision: 1,
                phase: Phase::PreparedHeld,
                exit_confirmed: Some(false),
                ..Status::default()
            },
            deployment: None,
        })
        .unwrap();
    let (manifest, id) = f.source("v1");
    assert!(matches!(
        stage_with(&f.store(), &Probe::default(), &journal, &manifest, &id),
        Err(DeploymentError::BusyHistory)
    ));
    assert!(!f.profiles.join(format!("package-{id}")).exists());
}

struct FailingStore {
    inner: SegmentedJournal,
    fail: Arc<AtomicBool>,
}
impl Store for FailingStore {
    fn load(&mut self) -> io::Result<Vec<Record>> {
        self.inner.load()
    }
    fn replay(&mut self, visit: &mut dyn FnMut(Record) -> io::Result<()>) -> io::Result<()> {
        self.inner.replay(visit)
    }
    fn append(&mut self, record: &Record) -> io::Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::StorageFull.into());
        }
        self.inner.append(record)
    }
}
#[test]
fn audit_failure_before_intent_never_changes_selection() {
    let f = Fixture::new();
    let fail = Arc::new(AtomicBool::new(true));
    let mut journal = Journal::open(Box::new(FailingStore {
        inner: f.disk(),
        fail,
    }))
    .unwrap();
    let (id, _) = f.stage(&journal, "v1");
    assert!(f.select(&mut journal, &id, "none").is_err());
    assert!(!f.profiles.join(ACTIVE).exists());
    assert!(journal.pending_deployment().is_none());
}
#[test]
fn audit_failure_after_selection_preserves_pending_transaction_on_disk() {
    let f = Fixture::new();
    let fail = Arc::new(AtomicBool::new(false));
    let mut journal = Journal::open(Box::new(FailingStore {
        inner: f.disk(),
        fail: fail.clone(),
    }))
    .unwrap();
    let (id, hash) = f.stage(&journal, "v1");
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
    drop(journal);
    let mut journal = f.journal();
    assert!(journal.pending_deployment().is_some());
    assert_eq!(
        f.reconcile(&mut journal)
            .unwrap()
            .selection
            .unwrap()
            .manifest_sha256,
        hash
    );
}
