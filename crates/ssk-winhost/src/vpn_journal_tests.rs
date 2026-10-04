use super::*;
use crate::{
    service::{acl, AceEntry, PathSecurity, ProbeError},
    state_dir::StateDirLayout,
};
use ssk_netd_helper::vpn::{
    journal::{Event, Kind, EMERGENCY_RECORDS},
    Phase, Status,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

#[derive(Default)]
struct Probe {
    deny_next: Arc<AtomicBool>,
}
impl PathSecurityProbe for Probe {
    fn inspect(&self, path: &Path) -> Result<PathSecurity, ProbeError> {
        let mut aces = vec![AceEntry::allow(acl::SID_LOCAL_SYSTEM, acl::GENERIC_ALL)];
        if self.deny_next.load(Ordering::Acquire)
            && path
                .file_name()
                .is_some_and(|n| n == "openvpn-control-000001.journal")
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
    path: PathBuf,
    deny: Arc<AtomicBool>,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("profiles");
        fs::create_dir(&path).unwrap();
        Self {
            temp,
            path,
            deny: Arc::new(AtomicBool::new(false)),
        }
    }
    fn probe(&self) -> Probe {
        Probe {
            deny_next: self.deny.clone(),
        }
    }
    fn store(&self, create: bool, limits: Limits) -> io::Result<SegmentedJournal> {
        let profiles =
            ProfileStore::open_layout(StateDirLayout::new(&self.path, 1).unwrap(), &self.probe())
                .unwrap();
        SegmentedJournal::open_with(profiles, create, limits, Box::new(self.probe()))
    }
    fn journal(&self, limits: Limits) -> Journal {
        Journal::open(Box::new(self.store(true, limits).unwrap())).unwrap()
    }
    fn file(&self, index: usize) -> PathBuf {
        self.path.join(if index == 0 {
            "openvpn-control.journal".to_owned()
        } else {
            format!("openvpn-control-{index:06}.journal")
        })
    }
}
fn limits() -> Limits {
    Limits {
        records: 4,
        segments: 4,
        ..Limits::default()
    }
}
fn event(revision: u64) -> Event {
    Event {
        deployment: None,
        kind: Kind::Observation,
        actor: "service".into(),
        command: None,
        status: Status {
            revision,
            ..Status::default()
        },
    }
}
fn append(journal: &mut Journal, from: u64, to: u64) {
    for n in from..=to {
        journal.append(event(n)).unwrap();
    }
}
fn records(path: &Path) -> Vec<Record> {
    FileJournal {
        file: File::open(path).unwrap(),
    }
    .load()
    .unwrap()
}

#[test]
fn journal_rolls_without_changing_history_and_replays_across_all_segments() {
    let f = Fixture::new();
    let mut journal = f.journal(limits());
    append(&mut journal, 1, 4);
    let first = fs::read(f.file(0)).unwrap();
    append(&mut journal, 5, 10);
    let report = journal.inspection();
    assert_eq!(report.records, 10);
    assert_eq!(report.storage.as_ref().unwrap().segments, 3);
    assert_eq!(fs::read(f.file(0)).unwrap(), first);
    assert_eq!(records(&f.file(1))[0].sequence, 5);
    assert_eq!(records(&f.file(1))[0].previous, records(&f.file(0))[3].hash);
    assert!(
        f.store(false, limits()).is_err(),
        "origin lock prevents a second service or inspector"
    );
    for n in 0..3 {
        assert!(fs::OpenOptions::new().write(true).open(f.file(n)).is_err());
        assert!(fs::remove_file(f.file(n)).is_err());
    }
    drop(journal);
    let mut reopened = f.journal(limits());
    assert_eq!(reopened.inspection().head, report.head);
    assert_eq!(reopened.last().unwrap().revision, 10);
    reopened.append(event(11)).unwrap();
    assert_eq!(reopened.inspection().records, 11);
}

#[test]
fn byte_limit_rollover_and_total_segment_limit_fail_without_erasing_records() {
    let f = Fixture::new();
    let mut record = Record {
        schema: 2,
        sequence: 1,
        previous: ssk_types::Digest::GENESIS,
        event: event(1),
        hash: ssk_types::Digest::GENESIS,
    };
    let bytes = encode(&record).unwrap().len() + 4;
    // All sequence/revision values below 24 use the same CBOR width.
    let cap = Limits {
        records: 20,
        bytes: bytes * 2,
        segments: 2,
    };
    let mut journal = f.journal(cap);
    append(&mut journal, 1, 4);
    let before = [fs::read(f.file(0)).unwrap(), fs::read(f.file(1)).unwrap()];
    assert_eq!(journal.inspection().storage.unwrap().segments, 2);
    assert_eq!(
        journal.append(event(5)).unwrap_err().kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(journal.inspection().records, 4);
    assert_eq!(fs::read(f.file(0)).unwrap(), before[0]);
    assert_eq!(fs::read(f.file(1)).unwrap(), before[1]);
    assert!(!f.file(2).exists());
    record.event.actor = "x".repeat(MAX_RECORD_BYTES);
    assert!(encode(&record).is_err());
}

#[test]
fn empty_final_segment_is_a_resumable_crash_point_but_empty_middle_is_not() {
    let f = Fixture::new();
    let mut journal = f.journal(limits());
    append(&mut journal, 1, 4);
    drop(journal);
    fs::write(f.file(1), []).unwrap();
    let mut resumed = f.journal(limits());
    resumed.append(event(5)).unwrap();
    drop(resumed);
    assert_eq!(records(&f.file(1))[0].sequence, 5);
    fs::write(f.file(1), []).unwrap();
    fs::write(f.file(2), []).unwrap();
    assert!(Journal::open(Box::new(f.store(false, limits()).unwrap())).is_err());
}

#[test]
fn torn_tail_corrupt_hash_and_cross_segment_reordering_are_refused() {
    for fault in 0..3 {
        let f = Fixture::new();
        let mut journal = f.journal(limits());
        append(&mut journal, 1, 6);
        drop(journal);
        match fault {
            0 => {
                fs::OpenOptions::new()
                    .append(true)
                    .open(f.file(1))
                    .unwrap()
                    .write_all(&[4, 0])
                    .unwrap();
            }
            1 => {
                let mut data = fs::read(f.file(1)).unwrap();
                let end = data.len() - 1;
                data[end] ^= 1;
                fs::write(f.file(1), data).unwrap();
            }
            _ => {
                let a = fs::read(f.file(0)).unwrap();
                let b = fs::read(f.file(1)).unwrap();
                fs::write(f.file(0), b).unwrap();
                fs::write(f.file(1), a).unwrap();
            }
        }
        let before = fs::read(f.file(1)).unwrap();
        assert!(Journal::open(Box::new(f.store(false, limits()).unwrap())).is_err());
        assert_eq!(fs::read(f.file(1)).unwrap(), before);
    }
}

#[test]
fn missing_origin_gap_and_noncanonical_segment_names_never_create_a_new_history() {
    for name in [
        "openvpn-control-000001.journal",
        "openvpn-control-000002.journal",
        "openvpn-control-1.journal",
        "openvpn-control-000064.journal",
        "OpenVPN-Control-000001.journal",
    ] {
        let f = Fixture::new();
        fs::write(f.path.join(name), b"preserve").unwrap();
        assert!(f.store(true, Limits::default()).is_err(), "{name}");
        assert!(!f.file(0).exists());
        assert_eq!(fs::read(f.path.join(name)).unwrap(), b"preserve");
    }
    let f = Fixture::new();
    let mut j = f.journal(limits());
    append(&mut j, 1, 9);
    drop(j);
    fs::remove_file(f.file(1)).unwrap();
    assert!(f.store(false, limits()).is_err());
}

#[test]
fn journal_offline_inspection_preserves_bytes_and_never_creates_missing_storage() {
    let f = Fixture::new();
    assert!(f.store(false, limits()).is_err());
    assert_eq!(fs::read_dir(&f.path).unwrap().count(), 0);
    let mut j = f.journal(limits());
    append(&mut j, 1, 6);
    drop(j);
    let before = [fs::read(f.file(0)).unwrap(), fs::read(f.file(1)).unwrap()];
    let inspected = Journal::open(Box::new(f.store(false, limits()).unwrap())).unwrap();
    assert_eq!(inspected.inspection().records, 6);
    assert_eq!(
        inspected.inspection().storage.unwrap().total_bytes,
        (before[0].len() + before[1].len()) as u64
    );
    drop(inspected);
    assert_eq!(fs::read(f.file(0)).unwrap(), before[0]);
    assert_eq!(fs::read(f.file(1)).unwrap(), before[1]);
}

#[test]
fn capacity_reserves_intent_plus_emergency_records_for_both_count_and_bytes() {
    let f = Fixture::new();
    let cap = Limits {
        records: 20,
        segments: 1,
        ..Limits::default()
    };
    let mut j = f.journal(cap);
    append(&mut j, 1, 11);
    assert!(j.accepts_intent()); // nine remaining, including the intent
    j.append(event(12)).unwrap();
    assert!(!j.accepts_intent()); // eight reserved
    let f = Fixture::new();
    let mut j = f.journal(Limits::default());
    j.append(event(1)).unwrap();
    let size = fs::metadata(f.file(0)).unwrap().len() as usize;
    drop(j);
    let cap = Limits {
        records: 100,
        segments: 1,
        bytes: size + EMERGENCY_RECORDS * (MAX_RECORD_BYTES + 4),
    };
    let j = f.journal(cap);
    assert_eq!(
        j.inspection().storage.unwrap().guaranteed_record_slots,
        EMERGENCY_RECORDS
    );
    assert!(
        !j.accepts_intent(),
        "byte bound also retains all emergency slots"
    );
}

fn legacy_origin(f: &Fixture) {
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
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(f.file(0))
        .unwrap();
    append_frame(&mut file, &encode(&record).unwrap()).unwrap();
}

#[test]
fn legacy_upgrade_keeps_old_bytes_and_fences_old_readers_before_first_rollover() {
    let f = Fixture::new();
    legacy_origin(&f);
    let before = fs::read(f.file(0)).unwrap();
    let cap = Limits {
        records: 2,
        ..limits()
    };
    let mut j = f.journal(cap);
    append(&mut j, 2, 3);
    drop(j);
    assert!(fs::read(f.file(0)).unwrap().starts_with(&before));
    assert_eq!(
        records(&f.file(0))
            .iter()
            .map(|r| r.schema)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(records(&f.file(1))[0].sequence, 3);
    assert_eq!(f.journal(cap).last().unwrap().revision, 3);
}

#[test]
fn full_legacy_origin_cannot_roll_over_without_an_old_reader_fence() {
    let f = Fixture::new();
    legacy_origin(&f);
    let before = fs::read(f.file(0)).unwrap();
    let mut j = f.journal(Limits {
        records: 1,
        ..limits()
    });
    assert!(!j.accepts_intent());
    assert_eq!(
        j.append(event(2)).unwrap_err().kind(),
        io::ErrorKind::StorageFull
    );
    assert!(!f.file(1).exists());
    assert_eq!(fs::read(f.file(0)).unwrap(), before);
    drop(j);
    fs::write(f.file(1), []).unwrap();
    assert!(Journal::open(Box::new(f.store(false, limits()).unwrap())).is_err());
}

#[test]
fn segment_collisions_and_failed_acl_checks_never_overwrite_or_write_untrusted_files() {
    let f = Fixture::new();
    let mut j = f.journal(limits());
    append(&mut j, 1, 4);
    fs::write(f.file(1), b"collision").unwrap();
    assert!(j.append(event(5)).is_err());
    assert_eq!(fs::read(f.file(1)).unwrap(), b"collision");
    let f = Fixture::new();
    let mut j = f.journal(limits());
    append(&mut j, 1, 4);
    f.deny.store(true, Ordering::Release);
    assert!(j.append(event(5)).is_err());
    assert_eq!(
        fs::metadata(f.file(1)).unwrap().len(),
        0,
        "ACL check precedes any record bytes"
    );
    assert_eq!(j.inspection().records, 4);
    drop(j);
    f.deny.store(false, Ordering::Release);
    let mut resumed = f.journal(limits());
    resumed.append(event(5)).unwrap();
    assert_eq!(resumed.inspection().records, 5);
}

#[test]
fn existing_hardlinked_or_nonconfidential_segment_is_refused_before_replay() {
    for hardlink in [false, true] {
        let f = Fixture::new();
        let mut j = f.journal(limits());
        append(&mut j, 1, 5);
        drop(j);
        if hardlink {
            fs::hard_link(f.file(1), f.temp.path().join("alias")).unwrap();
        } else {
            f.deny.store(true, Ordering::Release);
        }
        let before = fs::read(f.file(1)).unwrap();
        assert!(f.store(false, limits()).is_err());
        assert_eq!(fs::read(f.file(1)).unwrap(), before);
    }
}

#[test]
fn unconfirmed_status_is_preserved_across_rollover_and_service_restart() {
    use ssk_netd_helper::{vpn, CapabilityToken};
    struct NoLaunch;
    impl vpn::Backend for NoLaunch {
        fn prepare(
            &mut self,
            _: &ssk_vpnctl::ProfileId,
            _: &AtomicBool,
            _: &mut dyn FnMut(vpn::ProcessIdentity) -> bool,
        ) -> Result<Box<dyn vpn::LiveSession>, vpn::PrepareError> {
            panic!("must not launch")
        }
    }
    let f = Fixture::new();
    let mut j = f.journal(limits());
    append(&mut j, 1, 4);
    let mut dirty = event(5);
    dirty.status.phase = Phase::Preparing;
    dirty.status.profile = Some("corp".into());
    dirty.status.exit_confirmed = Some(false);
    j.append(dirty).unwrap();
    drop(j);
    let mut service = vpn::Service::start(
        vpn::Policy::parse(br#"{"schema":1,"grants":[]}"#).unwrap(),
        CapabilityToken([7; 16]),
        Box::new(f.store(false, limits()).unwrap()),
        NoLaunch,
    )
    .unwrap();
    assert_eq!(service.shutdown().phase, Phase::RecoveryRequired);
}
