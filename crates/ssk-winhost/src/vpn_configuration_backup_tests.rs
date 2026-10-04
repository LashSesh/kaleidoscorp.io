use super::*;
use crate::vpn_configuration::backup::{backup_with, key_create_with, load, verify_with};

fn paths(f: &Fixture) -> (PathBuf, PathBuf) {
    let keys = f.temp.path().join("keys");
    let backups = f.temp.path().join("backups");
    fs::create_dir_all(&keys).unwrap();
    fs::create_dir_all(&backups).unwrap();
    (keys.join("recovery.key"), backups.join("snapshot.sskb"))
}
fn create_backup(f: &Fixture, journal: &Journal, id: &str) -> (PathBuf, PathBuf) {
    let (key, archive) = paths(f);
    key_create_with(&key, &Probe::default()).unwrap();
    backup_with(&f.store(), &Probe::default(), journal, &archive, &key, id).unwrap();
    (key, archive)
}
fn restore_archive(
    f: &Fixture,
    journal: &mut Journal,
    id: &str,
    observed: &str,
    archive: &Path,
    key: &Path,
) -> Result<RecoveryReport> {
    recovery::restore_using(
        &f.store(),
        &Probe::default(),
        journal,
        "S-1-5-18",
        RestoreRequest {
            expected_committed: id,
            expected_observed: observed,
            source: None,
        },
        replace_selector,
        |expected| load(&Probe::default(), archive, key, expected),
    )
}

#[test]
fn backup_key_generation_is_fresh_confidential_and_never_overwrites() {
    let f = Fixture::new();
    let (key, _) = paths(&f);
    let report = key_create_with(&key, &Probe::default()).unwrap();
    let first = fs::read(&key).unwrap();
    assert_eq!(first.len(), 40);
    assert_eq!(&first[..8], b"SSKKEY01");
    assert!(first[8..].iter().any(|b| *b != 0));
    assert!(key_create_with(&key, &Probe::default()).is_err());
    assert_eq!(fs::read(&key).unwrap(), first);
    let second_path = key.with_file_name("second.key");
    key_create_with(&second_path, &Probe::default()).unwrap();
    assert_ne!(fs::read(second_path).unwrap(), first);
    let report = serde_json::to_string(&report).unwrap();
    assert!(!report.contains(&hex(&first[8..])));
    assert!(report.contains("key-created"));
}

#[test]
fn backup_round_trip_verifies_disk_and_restores_without_plaintext_import() {
    let (f, mut journal, id) = repair_fixture();
    let original = fs::read(f.path.join(ACTIVE)).unwrap();
    let before = fs::read(f.path.join("openvpn-control.journal")).unwrap();
    let (key, archive) = create_backup(&f, &journal, &id);
    let encrypted = fs::read(&archive).unwrap();
    assert!(!encrypted.windows(15).any(|w| w == b"private_key_pem"));
    assert!(!encrypted.windows(17).any(|w| w == b"committed.example"));
    fs::remove_file(f.path.join(ACTIVE)).unwrap();
    fs::remove_file(f.path.join(format!("configuration-{id}.json"))).unwrap();
    let verified = verify_with(&Probe::default(), &journal, &archive, &key, &id).unwrap();
    assert_eq!(verified.archive_sha256, Some(hex(&sha(&encrypted))));
    assert_eq!(verified.archive_bytes, Some(encrypted.len()));
    assert_eq!(verified.configuration_sha256, Some(id.clone()));
    let output = serde_json::to_string(&verified).unwrap();
    assert!(!output.contains("committed.example"));
    assert_eq!(
        fs::read(f.path.join("openvpn-control.journal")).unwrap(),
        before
    );
    assert_eq!(
        restore_archive(&f, &mut journal, &id, "missing", &archive, &key)
            .unwrap()
            .outcome,
        "restored"
    );
    assert_eq!(fs::read(f.path.join(ACTIVE)).unwrap(), original);
    assert_eq!(fs::read(&archive).unwrap(), encrypted);
    assert_eq!(fs::read_dir(&f.path).unwrap().count(), 2); // active + journal only
}

#[test]
fn backup_sources_and_new_files_require_confidentiality_before_any_bytes() {
    let (f, journal, id) = repair_fixture();
    let (key, archive) = paths(&f);
    let deny_parent = Probe {
        deny: Some("keys".into()),
    };
    assert!(key_create_with(&key, &deny_parent).is_err());
    assert!(!key.exists());
    let denied_key = key.with_file_name("denied.key");
    let deny_file = Probe {
        deny: Some("denied.key".into()),
    };
    assert!(key_create_with(&denied_key, &deny_file).is_err());
    assert_eq!(fs::metadata(denied_key).unwrap().len(), 0);
    key_create_with(&key, &Probe::default()).unwrap();
    let denied_source = Probe {
        deny: Some("recovery.key".into()),
    };
    assert!(backup_with(&f.store(), &denied_source, &journal, &archive, &key, &id).is_err());
    assert!(!archive.exists());
    let denied_parent = Probe {
        deny: Some("backups".into()),
    };
    assert!(backup_with(&f.store(), &denied_parent, &journal, &archive, &key, &id).is_err());
    assert!(!archive.exists());
    let denied_output = Probe {
        deny: Some("snapshot.sskb".into()),
    };
    assert!(backup_with(&f.store(), &denied_output, &journal, &archive, &key, &id).is_err());
    assert_eq!(fs::metadata(&archive).unwrap().len(), 0);
    assert!(backup_with(&f.store(), &Probe::default(), &journal, &archive, &key, &id).is_err());
}

#[test]
fn backup_refuses_wrong_commit_damaged_source_and_existing_archive() {
    let (f, journal, id) = repair_fixture();
    let (key, archive) = create_backup(&f, &journal, &id);
    let bytes = fs::read(&archive).unwrap();
    assert!(backup_with(&f.store(), &Probe::default(), &journal, &archive, &key, &id).is_err());
    assert_eq!(fs::read(&archive).unwrap(), bytes);
    let fresh = archive.with_file_name("new.sskb");
    assert!(backup_with(
        &f.store(),
        &Probe::default(),
        &journal,
        &fresh,
        &key,
        &"ab".repeat(32)
    )
    .is_err());
    fs::write(f.path.join(ACTIVE), b"broken").unwrap();
    assert!(backup_with(&f.store(), &Probe::default(), &journal, &fresh, &key, &id).is_err());
    assert!(!fresh.exists());
}

#[test]
fn backup_wrong_keys_and_modified_archives_cause_no_restore_effect() {
    let (f, mut journal, id) = repair_fixture();
    let (key, archive) = create_backup(&f, &journal, &id);
    let other_key = key.with_file_name("other.key");
    key_create_with(&other_key, &Probe::default()).unwrap();
    fs::write(f.path.join(ACTIVE), b"damaged").unwrap();
    let observed = hex(&sha(b"damaged"));
    let count = journal.inspection().records;
    assert!(restore_archive(&f, &mut journal, &id, &observed, &archive, &other_key).is_err());
    let mut bytes = fs::read(&archive).unwrap();
    bytes[70] ^= 1;
    fs::write(&archive, bytes).unwrap();
    assert!(verify_with(&Probe::default(), &journal, &archive, &key, &id).is_err());
    assert!(restore_archive(&f, &mut journal, &id, &observed, &archive, &key).is_err());
    assert_eq!(journal.inspection().records, count);
    assert_eq!(fs::read(f.path.join(ACTIVE)).unwrap(), b"damaged");
    assert!(evidence_files(&f).is_empty());
}

#[test]
fn backup_old_grants_cannot_return_after_new_configuration_commit() {
    let (f, mut journal, old) = repair_fixture();
    let (key, archive) = create_backup(&f, &journal, &old);
    let new = f.stage(&journal, "replacement.example", "S-1-5-18");
    f.activate(&mut journal, &new, &old).unwrap();
    fs::remove_file(f.path.join(ACTIVE)).unwrap();
    assert!(verify_with(&Probe::default(), &journal, &archive, &key, &old).is_err());
    assert!(verify_with(&Probe::default(), &journal, &archive, &key, &new).is_err());
    assert!(restore_archive(&f, &mut journal, &old, "missing", &archive, &key).is_err());
    assert!(restore_archive(&f, &mut journal, &new, "missing", &archive, &key).is_err());
    assert!(!f.path.join(ACTIVE).exists());
    assert_eq!(journal.configuration_digest(), Some(digest(&new).unwrap()));
}

#[test]
fn backup_reading_refuses_linked_oversized_and_nonconfidential_artifacts() {
    let (f, journal, id) = repair_fixture();
    let (key, archive) = create_backup(&f, &journal, &id);
    for path in [&key, &archive] {
        let linked = path.with_extension("linked");
        fs::hard_link(path, &linked).unwrap();
        assert!(verify_with(&Probe::default(), &journal, &archive, &key, &id).is_err());
        fs::remove_file(linked).unwrap();
        let probe = Probe {
            deny: Some(path.file_name().unwrap().to_str().unwrap().into()),
        };
        assert!(verify_with(&probe, &journal, &archive, &key, &id).is_err());
    }
    let saved_key = fs::read(&key).unwrap();
    fs::write(&key, vec![0; 41]).unwrap();
    assert!(verify_with(&Probe::default(), &journal, &archive, &key, &id).is_err());
    fs::write(&key, saved_key).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&archive)
        .unwrap()
        .set_len((configuration::MAX_BYTES + 81) as u64)
        .unwrap();
    assert!(verify_with(&Probe::default(), &journal, &archive, &key, &id).is_err());
}

#[test]
fn backup_restoration_preserves_pending_process_and_reconciles_interruption() {
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
    let (key, archive) = create_backup(&f, &journal, &id);
    assert_eq!(journal.last(), Some(&status));
    fs::write(f.path.join(ACTIVE), b"damaged").unwrap();
    assert!(recovery::restore_using(
        &f.store(),
        &Probe::default(),
        &mut journal,
        "S-1-5-18",
        RestoreRequest {
            expected_committed: &id,
            expected_observed: &hex(&sha(b"damaged")),
            source: None
        },
        |from, to| {
            replace_selector(from, to)?;
            Err(io::ErrorKind::Interrupted.into())
        },
        |expected| load(&Probe::default(), &archive, &key, expected)
    )
    .is_err());
    assert!(journal.pending_repair().is_some());
    assert!(verify_with(&Probe::default(), &journal, &archive, &key, &id).is_err());
    drop(journal);
    let mut journal = f.journal();
    f.reconcile_restore(&mut journal).unwrap();
    assert_eq!(
        journal.last(),
        Some(&Status {
            revision: 5,
            ..status
        })
    );
    assert_eq!(
        fs::read(evidence_files(&f).pop().unwrap()).unwrap(),
        b"damaged"
    );
}

#[test]
fn backup_paths_require_existing_local_protected_directories() {
    let f = Fixture::new();
    assert!(key_create_with(Path::new("relative.key"), &Probe::default()).is_err());
    assert!(key_create_with(&f.temp.path().join("missing/key"), &Probe::default()).is_err());
    assert!(!f.temp.path().join("missing").exists());
    let named_directory = f.temp.path().join("directory.key");
    fs::create_dir(&named_directory).unwrap();
    assert!(key_create_with(&named_directory, &Probe::default()).is_err());
}

#[test]
fn backup_refuses_unhealthy_audit_without_touching_output() {
    let (f, mut journal, id) = repair_fixture();
    let (key, archive) = paths(&f);
    key_create_with(&key, &Probe::default()).unwrap();
    let status = Status {
        revision: 3,
        audit_healthy: false,
        ..Status::default()
    };
    journal
        .append(Event {
            kind: Kind::Observation,
            actor: "service".into(),
            command: None,
            status,
            deployment: None,
        })
        .unwrap();
    assert!(backup_with(&f.store(), &Probe::default(), &journal, &archive, &key, &id).is_err());
    assert!(!archive.exists());
    assert_eq!(journal.inspection().records, 3);
}
