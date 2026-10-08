//! [`LedgerIo`] over a [`LedgerStore`]: the writer's disk, in the order the design
//! gives for creating and pruning segments (6.4.8, D2 and D5).

use std::io;

use super::fs::{ActiveSegment, ActiveStat, LedgerIo, LedgerStore, PruneOutcome, StoreError};

/// The store error as an `io::Error` whose kind keeps the class `io_code` reduces
/// it to (a store error never carries a path, so nothing is lost by this).
fn io_error(error: StoreError) -> io::Error {
    let kind = match error {
        StoreError::Io("AUDIT_DISK_FULL") => io::ErrorKind::StorageFull,
        StoreError::Io("AUDIT_PERMISSION_DENIED") => io::ErrorKind::PermissionDenied,
        StoreError::Io("AUDIT_NOT_FOUND") => io::ErrorKind::NotFound,
        StoreError::Io("AUDIT_ALREADY_EXISTS") => io::ErrorKind::AlreadyExists,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error.code())
}

/// The active segment and the directory it is in.
pub struct StoreIo {
    store: Box<dyn LedgerStore>,
    active: Box<dyn ActiveSegment>,
}

impl StoreIo {
    #[must_use]
    pub fn new(store: Box<dyn LedgerStore>, active: Box<dyn ActiveSegment>) -> Self {
        Self { store, active }
    }
}

impl LedgerIo for StoreIo {
    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.active.append(bytes)
    }

    fn sync_data(&mut self) -> io::Result<()> {
        self.active.sync_data()
    }

    fn active_stat(&self) -> io::Result<ActiveStat> {
        self.active.stat()
    }

    fn truncate_active(&mut self, len: u64) -> io::Result<()> {
        self.active.truncate(len)
    }

    fn rotate(&mut self, next_first_seq: u64, first_record: &[u8]) -> io::Result<()> {
        // R2: the name is new, or this fails (`O_EXCL`): an existing name is never reused.
        let mut next = self
            .store
            .create_segment(next_first_seq)
            .map_err(io_error)?;
        // R3, R4: the first record, and the size it gives the file, durable.
        next.append(first_record)?;
        next.sync_all()?;
        // R5: the name durable, so that the segment cannot vanish after a record in
        // it was acknowledged.
        self.store.sync_dir()?;
        // R6: only now is it the segment that is appended to.
        self.active = next;
        Ok(())
    }

    fn prune(&mut self, victims: &[u64]) -> io::Result<PruneOutcome> {
        let mut outcome = PruneOutcome::default();
        for (done, victim) in victims.iter().enumerate() {
            let gone = match self.store.remove_segment(*victim) {
                Ok(()) => true,
                // Gone already (an earlier round got as far as the unlink): fine.
                Err(error) => error.kind() == io::ErrorKind::NotFound,
            };
            if !gone {
                // Oldest first, and no further: removing a newer segment while an
                // older one stays would leave a hole in the chain, which no
                // verifier could tell from damage. This one and every newer
                // victim are kept and retried.
                let left = victims.len().saturating_sub(done);
                outcome.deferred = u32::try_from(left).unwrap_or(u32::MAX);
                break;
            }
            outcome.removed.push(*victim);
            // Each unlink is made durable before the next is issued. One directory
            // fsync at the end would let a crash persist the removal of a newer
            // segment and not that of an older one, and the ledger would come back
            // with a hole that no verifier can tell from damage. Done one at a time,
            // what a crash can bring back is a suffix of the victims: the oldest
            // segments that remain, a valid anchored prefix that is pruned again.
            if self.store.sync_dir().is_err() {
                // Not known to be durable, so nothing newer is unlinked after it;
                // the newer victims wait for the next round.
                let left = victims.len().saturating_sub(done).saturating_sub(1);
                outcome.deferred = u32::try_from(left).unwrap_or(u32::MAX);
                break;
            }
        }
        Ok(outcome)
    }

    fn make_durable(&mut self) -> io::Result<()> {
        self.active.sync_all()?;
        self.store.sync_dir()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use crate::ingress::audit::fs::{SegmentReader, Segments};
    use crate::ingress::types::lock_unpoisoned;

    type Log = Arc<Mutex<Vec<String>>>;

    struct Seg {
        name: String,
        log: Log,
    }

    impl Seg {
        fn note(&self, op: &str) {
            lock_unpoisoned(&self.log).push(format!("{}:{op}", self.name));
        }
    }

    impl ActiveSegment for Seg {
        fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.note(&format!("append {}", bytes.len()));
            Ok(())
        }
        fn sync_data(&mut self) -> io::Result<()> {
            self.note("sync_data");
            Ok(())
        }
        fn sync_all(&mut self) -> io::Result<()> {
            self.note("sync_all");
            Ok(())
        }
        fn stat(&self) -> io::Result<ActiveStat> {
            self.note("stat");
            Ok(ActiveStat { len: 7, nlink: 1 })
        }
        fn truncate(&mut self, len: u64) -> io::Result<()> {
            self.note(&format!("truncate {len}"));
            Ok(())
        }
    }

    struct Store {
        log: Log,
        fail_create: Option<StoreError>,
        fail_sync_dir: bool,
        /// Removing these fails with a permission error.
        stuck: Vec<u64>,
        /// Removing these reports that they are gone already.
        gone: Vec<u64>,
    }

    impl LedgerStore for Store {
        fn created(&self) -> bool {
            false
        }
        fn segments(&self) -> Result<Segments, StoreError> {
            Ok(Segments::default())
        }
        fn open_reader(&self, _: u64) -> Result<SegmentReader, StoreError> {
            Err(StoreError::Unsupported)
        }
        fn open_active(&self, _: u64) -> Result<Box<dyn ActiveSegment>, StoreError> {
            Err(StoreError::Unsupported)
        }
        fn create_segment(&self, first_seq: u64) -> Result<Box<dyn ActiveSegment>, StoreError> {
            lock_unpoisoned(&self.log).push(format!("create {first_seq}"));
            if let Some(error) = self.fail_create {
                return Err(error);
            }
            Ok(Box::new(Seg {
                name: format!("seg{first_seq}"),
                log: Arc::clone(&self.log),
            }))
        }
        fn remove_segment(&self, first_seq: u64) -> io::Result<()> {
            lock_unpoisoned(&self.log).push(format!("remove {first_seq}"));
            if self.stuck.contains(&first_seq) {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else if self.gone.contains(&first_seq) {
                Err(io::Error::from(io::ErrorKind::NotFound))
            } else {
                Ok(())
            }
        }
        fn sync_dir(&self) -> io::Result<()> {
            lock_unpoisoned(&self.log).push("sync_dir".to_owned());
            if self.fail_sync_dir {
                Err(io::Error::from(io::ErrorKind::Other))
            } else {
                Ok(())
            }
        }
    }

    fn io_over(store: Store) -> (StoreIo, Log) {
        let log = Arc::clone(&store.log);
        let old = Seg {
            name: "old".to_owned(),
            log: Arc::clone(&log),
        };
        (StoreIo::new(Box::new(store), Box::new(old)), log)
    }

    fn store() -> Store {
        Store {
            log: Arc::new(Mutex::new(Vec::new())),
            fail_create: None,
            fail_sync_dir: false,
            stuck: Vec::new(),
            gone: Vec::new(),
        }
    }

    fn take(log: &Log) -> Vec<String> {
        std::mem::take(&mut *lock_unpoisoned(log))
    }

    #[test]
    fn the_active_segment_is_what_the_four_operations_act_on() {
        let (mut io, log) = io_over(store());
        io.append(b"abc").expect("append");
        io.sync_data().expect("sync");
        assert_eq!(
            io.active_stat().expect("stat"),
            ActiveStat { len: 7, nlink: 1 }
        );
        io.truncate_active(9).expect("truncate");
        assert_eq!(
            take(&log),
            [
                "old:append 3",
                "old:sync_data",
                "old:stat",
                "old:truncate 9"
            ]
        );
    }

    #[test]
    fn a_rotation_creates_writes_syncs_names_and_only_then_switches() {
        let (mut io, log) = io_over(store());
        io.rotate(5, b"continue\n").expect("rotates");
        // R2 create, R3 write, R4 sync_all, R5 directory; the old segment was not touched.
        assert_eq!(
            take(&log),
            ["create 5", "seg5:append 9", "seg5:sync_all", "sync_dir"]
        );
        // R6: from now on the new segment is the one that is appended to.
        io.append(b"x").expect("append");
        assert_eq!(take(&log), ["seg5:append 1"]);
    }

    #[test]
    fn a_rotation_that_fails_before_the_directory_is_durable_leaves_the_old_segment_active() {
        let mut failing = store();
        failing.fail_sync_dir = true;
        let (mut io, log) = io_over(failing);
        assert!(io.rotate(5, b"continue\n").is_err());
        take(&log);
        io.append(b"x").expect("append");
        assert_eq!(take(&log), ["old:append 1"], "R6 comes after R5");

        // A name that exists is never reused: the error says so, and nothing was written.
        let mut exists = store();
        exists.fail_create = Some(StoreError::Io("AUDIT_ALREADY_EXISTS"));
        let (mut io, log) = io_over(exists);
        let error = io.rotate(5, b"continue\n").expect_err("refused");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(take(&log), ["create 5"]);
        io.append(b"x").expect("append");
        assert_eq!(take(&log), ["old:append 1"]);

        // The classes of a failure survive the trip through `io::Error`.
        for (code, kind) in [
            ("AUDIT_DISK_FULL", io::ErrorKind::StorageFull),
            ("AUDIT_PERMISSION_DENIED", io::ErrorKind::PermissionDenied),
            ("AUDIT_NOT_FOUND", io::ErrorKind::NotFound),
            ("AUDIT_IO", io::ErrorKind::Other),
        ] {
            let error = io_error(StoreError::Io(code));
            assert_eq!(error.kind(), kind, "{code}");
            // The message is the store's own code: nothing else to leak or to lose.
            assert_eq!(error.to_string(), code);
        }
        assert_eq!(
            io_error(StoreError::FileUnsafe(
                crate::ingress::audit::fs::UnsafeReason::HardLinked
            ))
            .kind(),
            io::ErrorKind::Other
        );
    }

    #[test]
    fn a_prune_removes_oldest_first_and_makes_each_removal_durable_before_the_next() {
        let (mut io, log) = io_over(store());
        let outcome = io.prune(&[1, 11, 21]).expect("prunes");
        assert_eq!(
            outcome,
            PruneOutcome {
                removed: vec![1, 11, 21],
                deferred: 0
            }
        );
        assert_eq!(
            take(&log),
            [
                "remove 1",
                "sync_dir",
                "remove 11",
                "sync_dir",
                "remove 21",
                "sync_dir"
            ]
        );
        // Nothing to remove, nothing to make durable.
        let outcome = io.prune(&[]).expect("prunes");
        assert_eq!(outcome, PruneOutcome::default());
        assert!(take(&log).is_empty());
    }

    #[test]
    fn a_segment_that_is_gone_already_counts_as_removed() {
        let mut gone = store();
        gone.gone = vec![11];
        let (mut io, _) = io_over(gone);
        assert_eq!(
            io.prune(&[1, 11, 21]).expect("prunes"),
            PruneOutcome {
                removed: vec![1, 11, 21],
                deferred: 0
            }
        );
    }

    #[test]
    fn a_segment_that_cannot_be_removed_keeps_every_newer_one_so_the_chain_has_no_hole() {
        let mut stuck = store();
        stuck.stuck = vec![11];
        let (mut io, log) = io_over(stuck);
        let outcome = io.prune(&[1, 11, 21, 31]).expect("prunes");
        // 1 went; 11 failed; 21 and 31 are kept although they could have gone, because
        // a ledger from which 21 and 31 were removed while 11 stays has a hole.
        assert_eq!(
            outcome,
            PruneOutcome {
                removed: vec![1],
                deferred: 3
            }
        );
        assert_eq!(take(&log), ["remove 1", "sync_dir", "remove 11"]);
        // And when the first cannot go, nothing is made durable.
        let mut first = store();
        first.stuck = vec![1];
        let (mut io, log) = io_over(first);
        assert_eq!(
            io.prune(&[1, 11]).expect("prunes"),
            PruneOutcome {
                removed: Vec::new(),
                deferred: 2
            }
        );
        assert_eq!(take(&log), ["remove 1"]);
    }

    #[test]
    fn a_directory_that_cannot_be_made_durable_stops_the_prune_after_the_unlink_it_made() {
        let mut failing = store();
        failing.fail_sync_dir = true;
        let (mut io, log) = io_over(failing);
        // The unlink of 1 happened and is not known to be durable: 11 and 21 are not
        // unlinked behind it, because a crash could persist theirs and not that one.
        // It is not an error, and the segment that is gone is counted as gone.
        assert_eq!(
            io.prune(&[1, 11, 21]).expect("prunes"),
            PruneOutcome {
                removed: vec![1],
                deferred: 2
            }
        );
        assert_eq!(take(&log), ["remove 1", "sync_dir"]);
        // The last victim: nothing is left to wait.
        let mut failing = store();
        failing.fail_sync_dir = true;
        let (mut io, _) = io_over(failing);
        assert_eq!(
            io.prune(&[1]).expect("prunes"),
            PruneOutcome {
                removed: vec![1],
                deferred: 0
            }
        );
    }

    #[test]
    fn making_a_segment_durable_syncs_the_file_and_then_its_name() {
        let (mut io, log) = io_over(store());
        io.make_durable().expect("durable");
        assert_eq!(take(&log), ["old:sync_all", "sync_dir"]);
        let mut failing = store();
        failing.fail_sync_dir = true;
        let (mut io, _) = io_over(failing);
        assert!(io.make_durable().is_err());
    }
}
