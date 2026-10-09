//! Test doubles of the ledger's disk (design 23.6), shared by the tests of the
//! writer and of everything built on it. `FakeIo` is a disk in memory that can be
//! told to fail the nth append or sync, to block inside a sync, an append, a
//! rotation or a prune, and to say what was written; `FakeView` lets
//! `verify_dir` read it.

use std::io;
use std::sync::{Arc, Condvar, Mutex};

use super::fs::{ActiveStat, LedgerIo, StoreError};
use super::record::{Chain, FlowAuditRecord};
use crate::ingress::types::lock_unpoisoned;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Call {
    Stat,
    Append(usize),
    Sync,
    Truncate(u64),
    Rotate(u64, usize),
    Prune(Vec<u64>),
    MakeDurable,
}

pub(crate) struct Disk {
    /// The active segment.
    pub(crate) file: Vec<u8>,
    /// The first sequence number the active segment is named for.
    pub(crate) active_first: u64,
    /// Segments that were rotated away from, oldest first.
    pub(crate) closed: Vec<(u64, Vec<u8>)>,
    /// Segments whose removal fails (they are kept and counted as deferred).
    pub(crate) stuck: Vec<u64>,
    pub(crate) fail_rotate: bool,
    pub(crate) fail_make_durable: bool,
    pub(crate) prune_errors: bool,
    pub(crate) calls: Vec<Call>,
    pub(crate) appends: usize,
    pub(crate) syncs: usize,
    /// The nth append (1-based) writes half of its bytes and fails.
    pub(crate) fail_append_at: Option<usize>,
    /// The nth sync (1-based) fails.
    pub(crate) fail_sync_at: Option<usize>,
    pub(crate) block_sync: bool,
    pub(crate) in_sync: bool,
    pub(crate) block_append: bool,
    pub(crate) in_append: bool,
    pub(crate) block_rotate: bool,
    pub(crate) in_rotate: bool,
    pub(crate) block_prune: bool,
    pub(crate) in_prune: bool,
    pub(crate) unlinked: bool,
    pub(crate) stat_fails: bool,
    pub(crate) panic_on_append: bool,
}

pub(crate) struct DiskCell {
    pub(crate) disk: Mutex<Disk>,
    pub(crate) changed: Condvar,
}

#[derive(Clone)]
pub(crate) struct FakeIo(pub(crate) Arc<DiskCell>);

impl Default for Disk {
    fn default() -> Self {
        Self {
            file: Vec::new(),
            active_first: 1,
            closed: Vec::new(),
            stuck: Vec::new(),
            fail_rotate: false,
            fail_make_durable: false,
            prune_errors: false,
            calls: Vec::new(),
            appends: 0,
            syncs: 0,
            fail_append_at: None,
            fail_sync_at: None,
            block_sync: false,
            in_sync: false,
            block_append: false,
            in_append: false,
            block_rotate: false,
            in_rotate: false,
            block_prune: false,
            in_prune: false,
            unlinked: false,
            stat_fails: false,
            panic_on_append: false,
        }
    }
}

impl FakeIo {
    pub(crate) fn new() -> Self {
        Self(Arc::new(DiskCell {
            disk: Mutex::new(Disk::default()),
            changed: Condvar::new(),
        }))
    }

    /// Every segment, oldest first, as (first sequence number, bytes).
    pub(crate) fn segments(&self) -> Vec<(u64, Vec<u8>)> {
        self.with(|d| {
            let mut all = d.closed.clone();
            all.push((d.active_first, d.file.clone()));
            all
        })
    }

    pub(crate) fn with<T>(&self, f: impl FnOnce(&mut Disk) -> T) -> T {
        f(&mut lock_unpoisoned(&self.0.disk))
    }

    pub(crate) fn block(&self) {
        self.with(|d| d.block_sync = true);
    }

    pub(crate) fn release(&self) {
        self.with(|d| {
            d.block_sync = false;
            d.block_append = false;
            d.block_rotate = false;
            d.block_prune = false;
        });
        self.0.changed.notify_all();
    }

    pub(crate) fn calls(&self) -> Vec<Call> {
        self.with(|d| d.calls.clone())
    }

    pub(crate) fn len(&self) -> usize {
        self.with(|d| d.file.len())
    }

    pub(crate) fn text(&self) -> String {
        let all: Vec<u8> = self
            .segments()
            .into_iter()
            .flat_map(|(_, bytes)| bytes)
            .collect();
        String::from_utf8_lossy(&all).into_owned()
    }

    /// Every record on the "disk", oldest first, each verified against the
    /// chain: from genesis when segment 1 is still there, else from the anchor
    /// of the oldest segment.
    pub(crate) fn records(&self) -> Vec<FlowAuditRecord> {
        let mut chain: Option<Chain> = None;
        let mut out = Vec::new();
        for (first_seq, bytes) in self.segments() {
            for line in bytes.split(|byte| *byte == b'\n') {
                if line.is_empty() {
                    continue;
                }
                let chain = chain.get_or_insert_with(|| {
                    if first_seq == 1 {
                        Chain::genesis()
                    } else {
                        let (head, prev_seq) = crate::ingress::audit::verify::peek_anchor(line)
                            .expect("the oldest segment starts with its anchor");
                        Chain::resume(head, prev_seq)
                    }
                });
                out.push(chain.accept(line).expect("every line chains"));
            }
        }
        out
    }

    /// A read-only view for `verify_dir`.
    pub(crate) fn view(&self) -> FakeView {
        FakeView(self.clone())
    }
}

impl LedgerIo for FakeIo {
    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut disk = lock_unpoisoned(&self.0.disk);
        disk.in_append = true;
        self.0.changed.notify_all();
        while disk.block_append {
            disk = self
                .0
                .changed
                .wait(disk)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        disk.in_append = false;
        disk.calls.push(Call::Append(bytes.len()));
        disk.appends += 1;
        if disk.panic_on_append {
            drop(disk);
            panic!("the disk double was told to panic");
        }
        if disk.fail_append_at == Some(disk.appends) {
            let half = bytes.len() / 2;
            disk.file
                .extend_from_slice(bytes.get(..half).unwrap_or_default());
            return Err(io::Error::from(io::ErrorKind::StorageFull));
        }
        disk.file.extend_from_slice(bytes);
        Ok(())
    }

    fn sync_data(&mut self) -> io::Result<()> {
        let mut disk = lock_unpoisoned(&self.0.disk);
        disk.calls.push(Call::Sync);
        disk.syncs += 1;
        disk.in_sync = true;
        self.0.changed.notify_all();
        while disk.block_sync {
            disk = self
                .0
                .changed
                .wait(disk)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        disk.in_sync = false;
        if disk.fail_sync_at == Some(disk.syncs) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(())
    }

    fn active_stat(&self) -> io::Result<ActiveStat> {
        let mut disk = lock_unpoisoned(&self.0.disk);
        disk.calls.push(Call::Stat);
        if disk.stat_fails {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        Ok(ActiveStat {
            len: u64::try_from(disk.file.len()).expect("fits"),
            nlink: if disk.unlinked { 0 } else { 1 },
        })
    }

    fn truncate_active(&mut self, len: u64) -> io::Result<()> {
        let mut disk = lock_unpoisoned(&self.0.disk);
        disk.calls.push(Call::Truncate(len));
        disk.file.truncate(usize::try_from(len).expect("fits"));
        Ok(())
    }

    fn rotate(&mut self, next_first_seq: u64, first_record: &[u8]) -> io::Result<()> {
        let mut disk = lock_unpoisoned(&self.0.disk);
        disk.in_rotate = true;
        self.0.changed.notify_all();
        while disk.block_rotate {
            disk = self
                .0
                .changed
                .wait(disk)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        disk.in_rotate = false;
        disk.calls
            .push(Call::Rotate(next_first_seq, first_record.len()));
        if disk.fail_rotate {
            return Err(io::Error::from(io::ErrorKind::StorageFull));
        }
        let old = std::mem::replace(&mut disk.file, first_record.to_vec());
        let old_first = std::mem::replace(&mut disk.active_first, next_first_seq);
        disk.closed.push((old_first, old));
        Ok(())
    }

    fn prune(&mut self, victims: &[u64]) -> io::Result<crate::ingress::audit::fs::PruneOutcome> {
        let mut disk = lock_unpoisoned(&self.0.disk);
        disk.in_prune = true;
        self.0.changed.notify_all();
        while disk.block_prune {
            disk = self
                .0
                .changed
                .wait(disk)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        disk.in_prune = false;
        disk.calls.push(Call::Prune(victims.to_vec()));
        if disk.prune_errors {
            return Err(io::Error::other("the directory cannot be listed"));
        }
        let mut outcome = crate::ingress::audit::fs::PruneOutcome::default();
        for (done, victim) in victims.iter().enumerate() {
            if disk.stuck.contains(victim) {
                // Oldest first, and no further (see `StoreIo::prune`).
                outcome.deferred = u32::try_from(victims.len() - done).expect("fits");
                break;
            }
            disk.closed.retain(|(first, _)| first != victim);
            outcome.removed.push(*victim);
        }
        Ok(outcome)
    }

    fn make_durable(&mut self) -> io::Result<()> {
        let mut disk = lock_unpoisoned(&self.0.disk);
        disk.calls.push(Call::MakeDurable);
        if disk.fail_make_durable {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(())
    }
}

/// The disk double as a store that `verify_dir` can read.
pub(crate) struct FakeView(pub(crate) FakeIo);

impl crate::ingress::audit::fs::LedgerStore for FakeView {
    fn created(&self) -> bool {
        false
    }

    fn segments(&self) -> Result<crate::ingress::audit::fs::Segments, StoreError> {
        Ok(crate::ingress::audit::fs::Segments {
            first_seqs: self
                .0
                .segments()
                .into_iter()
                .map(|(first, _)| first)
                .collect(),
            ignored: 0,
        })
    }

    fn open_reader(
        &self,
        first_seq: u64,
    ) -> Result<crate::ingress::audit::fs::SegmentReader, StoreError> {
        let bytes = self
            .0
            .segments()
            .into_iter()
            .find(|(first, _)| *first == first_seq)
            .map(|(_, bytes)| bytes)
            .ok_or(StoreError::Io("AUDIT_NOT_FOUND"))?;
        Ok(crate::ingress::audit::fs::SegmentReader {
            len: u64::try_from(bytes.len()).expect("fits"),
            reader: Box::new(std::io::Cursor::new(bytes)),
        })
    }

    fn open_active(
        &self,
        _: u64,
    ) -> Result<Box<dyn crate::ingress::audit::fs::ActiveSegment>, StoreError> {
        Err(StoreError::Unsupported)
    }

    fn create_segment(
        &self,
        _: u64,
    ) -> Result<Box<dyn crate::ingress::audit::fs::ActiveSegment>, StoreError> {
        Err(StoreError::Unsupported)
    }

    fn remove_segment(&self, _: u64) -> io::Result<()> {
        Err(io::Error::other("read-only"))
    }

    fn sync_dir(&self) -> io::Result<()> {
        Ok(())
    }
}
