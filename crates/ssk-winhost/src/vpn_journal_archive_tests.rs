use super::*;
use crate::service::{acl, AceEntry, PathSecurity, ProbeError};
use ssk_netd_helper::vpn::{
    journal::{DeploymentChange, DeploymentEvent, DeploymentTarget, Event, Kind, RepairChange},
    Phase, Status,
};
use std::{fs, path::PathBuf};

#[derive(Default)]
struct Probe {
    deny: Option<PathBuf>,
}
impl PathSecurityProbe for Probe {
    fn inspect(&self, path: &Path) -> Result<PathSecurity, ProbeError> {
        let mut aces = vec![AceEntry::allow(acl::SID_LOCAL_SYSTEM, acl::GENERIC_ALL)];
        if self.deny.as_deref() == Some(path) {
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
    profiles: PathBuf,
    archive: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let profiles = temp.path().join("profiles");
        fs::create_dir(&profiles).unwrap();
        let backups = temp.path().join("backups");
        fs::create_dir(&backups).unwrap();
        Self {
            temp,
            profiles,
            archive: backups.join("history.sskj"),
        }
    }
    fn store(&self, create: bool) -> io::Result<SegmentedJournal> {
        let profiles = ProfileStore::open_layout(
            StateDirLayout::new(&self.profiles, 1).unwrap(),
            &Probe::default(),
        )
        .unwrap();
        SegmentedJournal::open_with(
            profiles,
            create,
            Limits {
                records: 4,
                ..Limits::default()
            },
            Box::new(Probe::default()),
        )
    }
    fn file(&self, index: usize) -> PathBuf {
        self.profiles.join(if index == 0 {
            "openvpn-control.journal".into()
        } else {
            format!("openvpn-control-{index:06}.journal")
        })
    }
    fn seed(&self, count: u64) -> Inspection {
        let mut journal = Journal::open(Box::new(self.store(true).unwrap())).unwrap();
        for revision in 1..=count {
            journal.append(event(revision)).unwrap();
        }
        journal.inspection()
    }
    fn backup(&self, inspection: &Inspection) -> io::Result<ArchiveReport> {
        backup_with(
            &mut self.store(false)?,
            &self.archive,
            &anchor(inspection),
            &Probe::default(),
        )
    }
    fn verify(&self, sha: &str, inspection: &Inspection) -> io::Result<ArchiveReport> {
        verify_with(&self.archive, sha, &anchor(inspection), &Probe::default())
    }
}
fn event(revision: u64) -> Event {
    Event {
        kind: Kind::Observation,
        actor: "service".into(),
        command: None,
        status: Status {
            revision,
            ..Status::default()
        },
        deployment: None,
    }
}
fn anchor(i: &Inspection) -> Anchor {
    Anchor {
        head: i.head,
        records: i.records,
    }
}
fn sha(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn payloads(bytes: &[u8]) -> Vec<Vec<u8>> {
    let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let mut offset = 12;
    let mut out = Vec::new();
    for _ in 0..count {
        let size = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) as usize;
        offset += 8;
        out.push(bytes[offset..offset + size].to_vec());
        offset += size;
    }
    assert_eq!(offset, bytes.len());
    out
}
fn envelope(segments: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&(segments.len() as u32).to_le_bytes());
    for segment in segments {
        bytes.extend_from_slice(&(segment.len() as u64).to_le_bytes());
        bytes.extend_from_slice(segment);
    }
    bytes
}

#[test]
fn archive_roundtrip_preserves_every_segment_and_excludes_other_profile_files() {
    let f = Fixture::new();
    let original = f.seed(10);
    fs::write(f.profiles.join("private-key.pem"), b"DO_NOT_EXPORT").unwrap();
    let before = (0..3)
        .map(|n| fs::read(f.file(n)).unwrap())
        .collect::<Vec<_>>();
    let report = f.backup(&original).unwrap();
    let bytes = fs::read(&f.archive).unwrap();
    assert_eq!(payloads(&bytes), before);
    assert_eq!(sha(&bytes), report.archive_sha256);
    assert_eq!(report.archive_bytes, bytes.len() as u64);
    assert!(!bytes.windows(13).any(|b| b == b"DO_NOT_EXPORT"));
    let verified = f.verify(&report.archive_sha256, &original).unwrap();
    assert_eq!(verified.inspection.last_status, original.last_status);
    assert_eq!(verified.inspection.storage.unwrap().segments, 3);
    assert!(!verified.inspection.accepts_intent && !verified.restoration_performed);
    for (n, expected) in before.iter().enumerate() {
        assert_eq!(&fs::read(f.file(n)).unwrap(), expected);
    }
}

#[test]
fn archive_verification_survives_unavailable_live_store_without_recreating_it() {
    let f = Fixture::new();
    let original = f.seed(6);
    let report = f.backup(&original).unwrap();
    fs::rename(
        &f.profiles,
        f.temp.path().join("preserved-unavailable-store"),
    )
    .unwrap();
    assert!(f.verify(&report.archive_sha256, &original).is_ok());
    assert!(!f.profiles.exists());
}

#[test]
fn archive_rejects_stale_head_and_count_before_claiming_destination() {
    let f = Fixture::new();
    let original = f.seed(6);
    let mut wrong = original.clone();
    wrong.records -= 1;
    assert!(f.backup(&wrong).is_err());
    assert!(!f.archive.exists());
    wrong = original;
    wrong.head = ssk_types::Digest([9; 32]);
    assert!(f.backup(&wrong).is_err());
    assert!(!f.archive.exists());
    for (head, count) in [
        ("00".repeat(32), 1),
        ("ab".repeat(32), 0),
        ("AB".repeat(32), 1),
        ("ab".repeat(32), (MAX_RECORDS * MAX_SEGMENTS + 1) as u64),
    ] {
        assert!(Anchor::parse(&head, count).is_err());
    }
}

#[test]
fn archive_refuses_corrupt_live_history_before_copy_and_keeps_original_bytes() {
    let f = Fixture::new();
    let original = f.seed(6);
    OpenOptions::new()
        .append(true)
        .open(f.file(1))
        .unwrap()
        .write_all(&[1, 0])
        .unwrap();
    let damaged = fs::read(f.file(1)).unwrap();
    assert!(f.backup(&original).is_err());
    assert!(!f.archive.exists());
    assert_eq!(fs::read(f.file(1)).unwrap(), damaged);
}

#[test]
fn archive_is_offline_and_source_locks_survive_copying() {
    let f = Fixture::new();
    let original = f.seed(6);
    let mut locked = f.store(false).unwrap();
    assert!(f.backup(&original).is_err());
    assert!(!f.archive.exists());
    backup_with(
        &mut locked,
        &f.archive,
        &anchor(&original),
        &Probe::default(),
    )
    .unwrap();
    for n in 0..2 {
        assert!(OpenOptions::new().write(true).open(f.file(n)).is_err());
        assert!(fs::remove_file(f.file(n)).is_err());
    }
    assert!(f.store(false).is_err());
}

#[test]
fn archive_preserves_empty_final_segment_and_empty_origin_without_inventing_records() {
    for count in [0, 4] {
        let f = Fixture::new();
        let original = f.seed(count);
        if count != 0 {
            fs::write(f.file(1), []).unwrap();
        }
        let report = f.backup(&original).unwrap();
        assert_eq!(report.inspection.records, count as usize);
        assert!(payloads(&fs::read(&f.archive).unwrap())
            .last()
            .unwrap()
            .is_empty());
        assert!(f.verify(&report.archive_sha256, &original).is_ok());
    }
}

#[test]
fn archive_retains_pending_deployment_configuration_repair_and_unresolved_process() {
    for scenario in 0..3 {
        let f = Fixture::new();
        f.seed(1);
        let mut journal = Journal::open(Box::new(f.store(false).unwrap())).unwrap();
        let change = DeploymentChange {
            target: DeploymentTarget::Configuration,
            id: [1; 16],
            previous: None,
            candidate: [2; 32],
        };
        journal
            .deployment("S-1-5-18", DeploymentEvent::Begin(change.clone()))
            .unwrap();
        if scenario > 0 {
            journal
                .deployment("S-1-5-18", DeploymentEvent::Committed(change))
                .unwrap();
            let mut dirty = event(4);
            dirty.status.phase = Phase::Preparing;
            dirty.status.profile = Some("corp".into());
            dirty.status.exit_confirmed = Some(false);
            journal.append(dirty).unwrap();
            if scenario == 2 {
                journal
                    .deployment(
                        "S-1-5-18",
                        DeploymentEvent::RestoreBegin(RepairChange {
                            id: [3; 16],
                            configuration: [2; 32],
                            observed: None,
                        }),
                    )
                    .unwrap();
            }
        }
        let original = journal.inspection();
        drop(journal);
        let report = f.backup(&original).unwrap();
        let replayed = report.inspection;
        assert_eq!(replayed.last_status, original.last_status);
        assert_eq!(replayed.pending_deployment, original.pending_deployment);
        assert_eq!(replayed.pending_repair, original.pending_repair);
        assert_eq!(replayed.configuration_digest, original.configuration_digest);
    }
}

#[test]
fn archive_external_head_detects_removed_whole_tail_even_after_rehashing() {
    let f = Fixture::new();
    let original = f.seed(10);
    let report = f.backup(&original).unwrap();
    let mut segments = payloads(&fs::read(&f.archive).unwrap());
    segments.pop();
    let older = envelope(&segments);
    fs::write(&f.archive, &older).unwrap();
    assert!(f.verify(&report.archive_sha256, &original).is_err());
    assert!(f.verify(&sha(&older), &original).is_err());
    // The shortened history is internally valid: only independently retained
    // expectations distinguish it from an operator-approved earlier snapshot.
    let replay = Journal::open(Box::new(ArchiveReader {
        file: File::open(&f.archive).unwrap(),
        storage: None,
    }))
    .unwrap();
    assert_eq!(replay.inspection().records, 8);
}

#[test]
fn archive_rejects_corrupt_reordered_truncated_and_extra_payload_despite_matching_sha() {
    for scenario in 0..6 {
        let f = Fixture::new();
        let original = f.seed(10);
        f.backup(&original).unwrap();
        let mut bytes = fs::read(&f.archive).unwrap();
        match scenario {
            0 => {
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
            }
            1 => {
                bytes.pop();
            }
            2 => bytes.push(0),
            3 => {
                let mut segments = payloads(&bytes);
                segments.swap(1, 2);
                bytes = envelope(&segments);
            }
            4 => {
                let mut segments = payloads(&bytes);
                segments[1].clear();
                bytes = envelope(&segments);
            }
            5 => bytes[0] ^= 1,
            _ => unreachable!(),
        }
        fs::write(&f.archive, &bytes).unwrap();
        assert!(
            f.verify(&sha(&bytes), &original).is_err(),
            "scenario {scenario}"
        );
        assert_eq!(fs::read(&f.archive).unwrap(), bytes);
    }
}

#[test]
fn archive_bounds_reject_forged_counts_lengths_oversized_files_and_partial_headers() {
    let f = Fixture::new();
    let original = f.seed(1);
    let report = f.backup(&original).unwrap();
    for count in [0u32, MAX_SEGMENTS as u32 + 1, u32::MAX] {
        let mut bytes = vec![0; 20];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..12].copy_from_slice(&count.to_le_bytes());
        fs::write(&f.archive, &bytes).unwrap();
        assert!(f.verify(&sha(&bytes), &original).is_err());
    }
    let mut bytes = vec![0; 20];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
    bytes[12..20].copy_from_slice(&(MAX_JOURNAL_BYTES as u64 + 1).to_le_bytes());
    fs::write(&f.archive, &bytes).unwrap();
    assert!(f.verify(&sha(&bytes), &original).is_err());
    for length in [0, 19, MAX_ARCHIVE + 1] {
        OpenOptions::new()
            .write(true)
            .open(&f.archive)
            .unwrap()
            .set_len(length)
            .unwrap();
        assert!(f.verify(&report.archive_sha256, &original).is_err());
    }
}

#[test]
fn archive_never_overwrites_existing_or_partial_outputs_or_creates_missing_parents() {
    let f = Fixture::new();
    let original = f.seed(1);
    for bytes in [b"".as_slice(), b"preserve incomplete archive"] {
        fs::write(&f.archive, bytes).unwrap();
        assert!(f.backup(&original).is_err());
        assert_eq!(fs::read(&f.archive).unwrap(), bytes);
    }
    let missing = f.temp.path().join("missing/history.sskj");
    assert!(backup_with(
        &mut f.store(false).unwrap(),
        &missing,
        &anchor(&original),
        &Probe::default()
    )
    .is_err());
    assert!(!missing.parent().unwrap().exists());
}

#[test]
fn archive_refuses_live_namespace_and_descendants_including_case_aliases() {
    let f = Fixture::new();
    let original = f.seed(1);
    let nested = f.profiles.join("backups");
    fs::create_dir(&nested).unwrap();
    for destination in [
        f.file(1),
        nested.join("history.sskj"),
        f.profiles.with_file_name("PROFILES").join("new.sskj"),
    ] {
        assert!(backup_with(
            &mut f.store(false).unwrap(),
            &destination,
            &anchor(&original),
            &Probe::default()
        )
        .is_err());
        assert!(!destination.exists());
    }
    assert_eq!(
        Journal::open(Box::new(f.store(false).unwrap()))
            .unwrap()
            .inspection()
            .head,
        original.head
    );
}

#[test]
fn archive_acl_is_checked_before_writing_and_reading_and_hardlinks_are_refused() {
    let f = Fixture::new();
    let original = f.seed(1);
    let probe = Probe {
        deny: Some(f.archive.clone()),
    };
    assert!(backup_with(
        &mut f.store(false).unwrap(),
        &f.archive,
        &anchor(&original),
        &probe
    )
    .is_err());
    assert_eq!(fs::metadata(&f.archive).unwrap().len(), 0);
    fs::remove_file(&f.archive).unwrap();
    let report = f.backup(&original).unwrap();
    let before = fs::read(&f.archive).unwrap();
    assert!(verify_with(
        &f.archive,
        &report.archive_sha256,
        &anchor(&original),
        &probe
    )
    .is_err());
    fs::hard_link(&f.archive, f.temp.path().join("alias.sskj")).unwrap();
    assert!(f.verify(&report.archive_sha256, &original).is_err());
    assert_eq!(fs::read(&f.archive).unwrap(), before);
}

#[test]
fn archive_preserves_legacy_schema_one_bytes_and_requires_fence_for_multiple_segments() {
    let f = Fixture::new();
    let e = event(1);
    let record = Record {
        schema: 1,
        sequence: 1,
        previous: ssk_types::Digest::GENESIS,
        hash: ssk_types::digest_of(
            &(1u32, 1u64, ssk_types::Digest::GENESIS, &e),
            ssk_types::HashAlg::Blake3,
        )
        .unwrap(),
        event: e,
    };
    let mut origin = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(f.file(0))
        .unwrap();
    append_frame(&mut origin, &encode(&record).unwrap()).unwrap();
    drop(origin);
    let before = fs::read(f.file(0)).unwrap();
    let original = Journal::open(Box::new(f.store(false).unwrap()))
        .unwrap()
        .inspection();
    let report = f.backup(&original).unwrap();
    assert_eq!(
        payloads(&fs::read(&f.archive).unwrap()),
        vec![before.clone()]
    );
    assert!(f.verify(&report.archive_sha256, &original).is_ok());
    let unfenced = envelope(&[before, vec![]]);
    fs::write(&f.archive, &unfenced).unwrap();
    assert!(f.verify(&sha(&unfenced), &original).is_err());
}

#[test]
fn archive_refuses_unsafe_parent_before_claim_and_concurrent_archive_writer() {
    let f = Fixture::new();
    let original = f.seed(1);
    let probe = Probe {
        deny: Some(f.archive.parent().unwrap().to_path_buf()),
    };
    assert!(backup_with(
        &mut f.store(false).unwrap(),
        &f.archive,
        &anchor(&original),
        &probe
    )
    .is_err());
    assert!(!f.archive.exists());
    let report = f.backup(&original).unwrap();
    let _writer = OpenOptions::new().write(true).open(&f.archive).unwrap();
    assert!(f.verify(&report.archive_sha256, &original).is_err());
}
