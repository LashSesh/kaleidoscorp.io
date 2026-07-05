#![forbid(unsafe_code)]

//! # ssk-audit-store — a durable, crash-safe, append-only audit sink
//!
//! Every hash-chained ledger elsewhere in this workspace (`ssk-crown`'s
//! emission ledger, `ssk-boundary`'s kill-switch audit, `ssk-service-host`'s
//! lifecycle ledger, `ssk-tfa`'s execution ledger, `ssk-profile-manifold`,
//! `ssk-funnel-dag`'s trace, `ssk-imdf`'s atlas) is a bare in-memory `Vec`: pure,
//! deterministic, and replay-stable, but destroyed on process restart or crash.
//!
//! This crate is the **injected durability seam** those pure crates can
//! optionally persist through without giving up their own purity: an
//! [`AuditSink`] trait a supervisor holds as `Option<Box<dyn AuditSink>>`,
//! appending to it *in addition to* its own `Vec` — never *instead of* it. The
//! pure crate stays deterministic and testable with no sink at all (`None`,
//! the default); a caller who wants durability supplies a real one.
//!
//! [`FileAuditStore`] is the real, general-purpose implementation:
//!
//! * **Append-only, one frame per record**, not a whole-file rewrite. Each
//!   `append` opens the file in OS append mode, writes one length-prefixed
//!   frame, and calls `sync_all` (fsync) before returning — a genuine
//!   durability barrier, not a page-cache promise a crash can silently lose.
//! * **Bounded recovery, not corruption.** [`FileAuditStore::load`] scans
//!   frames from the start; the first frame that fails to parse (a torn
//!   write from a crash mid-append) stops the scan there. Everything before
//!   it is returned as valid, and [`LoadReport::truncated_tail_bytes`] reports
//!   exactly how many trailing bytes were dropped — never silently absorbed,
//!   so a caller with a residue register can record the loss rather than
//!   pretend it didn't happen.

use ssk_types::Digest;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Errors the audit store can return.
#[derive(Debug, thiserror::Error)]
pub enum AuditStoreError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// One durably-appended record: the `(seq, prev_hash, entry_hash)` triple
/// every hash-chained ledger in this workspace already computes, plus an
/// opaque body the caller controls the shape of (typically a canonical
/// serialization of its own entry type, so `load()` + the caller's own
/// deserialization reconstructs the exact entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecord {
    pub seq: u64,
    pub prev_hash: Digest,
    pub entry_hash: Digest,
    pub body: Vec<u8>,
}

/// The result of loading a store: the records recovered, and how much (if
/// any) of a torn tail was dropped to recover them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoadReport {
    pub records: Vec<StoredRecord>,
    /// Bytes dropped from a torn tail (0 on a clean load). Non-zero means a
    /// crash interrupted the last append; everything before it is intact.
    pub truncated_tail_bytes: usize,
}

/// The injected durability seam. `Send + Sync` so a supervisor can hold it
/// behind an `Arc` (shareable across clones without duplicating the
/// underlying file handle/path).
pub trait AuditSink: Send + Sync {
    /// Durably persist one record. Must not return `Ok` until the record is
    /// guaranteed to survive a crash (i.e. after an `fsync`-equivalent).
    ///
    /// # Errors
    /// [`AuditStoreError`] on any I/O failure.
    fn append(&self, record: &StoredRecord) -> Result<(), AuditStoreError>;

    /// Load every record durably persisted so far, in append order.
    ///
    /// # Errors
    /// [`AuditStoreError`] on an I/O failure. A torn tail from a crash
    /// mid-append is NOT an error — it is recovered up to the last complete
    /// record; see [`LoadReport::truncated_tail_bytes`].
    fn load(&self) -> Result<LoadReport, AuditStoreError>;
}

/// Frame header: `[seq: 8][prev_hash: 32][entry_hash: 32]`, preceded by a
/// 4-byte little-endian total-frame-length prefix (header + body).
const HEADER_LEN: usize = 8 + 32 + 32;
const LEN_PREFIX: usize = 4;

/// A real, crash-safe, append-only file store.
pub struct FileAuditStore {
    path: PathBuf,
}

impl FileAuditStore {
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl AuditSink for FileAuditStore {
    fn append(&self, record: &StoredRecord) -> Result<(), AuditStoreError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let frame_len = HEADER_LEN + record.body.len();
        file.write_all(&u32::try_from(frame_len).unwrap_or(u32::MAX).to_le_bytes())?;
        file.write_all(&record.seq.to_le_bytes())?;
        file.write_all(&record.prev_hash.0)?;
        file.write_all(&record.entry_hash.0)?;
        file.write_all(&record.body)?;
        file.sync_all()?;
        Ok(())
    }

    fn load(&self) -> Result<LoadReport, AuditStoreError> {
        if !self.path.exists() {
            return Ok(LoadReport::default());
        }
        let mut file = File::open(&self.path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;

        let mut records = Vec::new();
        let mut offset = 0usize;
        while offset + LEN_PREFIX <= bytes.len() {
            let frame_len =
                u32::from_le_bytes(bytes[offset..offset + LEN_PREFIX].try_into().unwrap()) as usize;
            let frame_start = offset + LEN_PREFIX;
            if frame_len < HEADER_LEN || frame_start + frame_len > bytes.len() {
                // A torn frame: either the length prefix itself is bogus, or
                // the frame it announces extends past what was actually
                // written. Stop here -- this is the crash boundary.
                break;
            }
            let frame = &bytes[frame_start..frame_start + frame_len];
            let seq = u64::from_le_bytes(frame[0..8].try_into().unwrap());
            let mut prev_hash = [0u8; 32];
            prev_hash.copy_from_slice(&frame[8..40]);
            let mut entry_hash = [0u8; 32];
            entry_hash.copy_from_slice(&frame[40..72]);
            let body = frame[72..].to_vec();
            records.push(StoredRecord {
                seq,
                prev_hash: Digest(prev_hash),
                entry_hash: Digest(entry_hash),
                body,
            });
            offset = frame_start + frame_len;
        }

        Ok(LoadReport {
            records,
            truncated_tail_bytes: bytes.len() - offset,
        })
    }
}

/// An in-memory sink, mainly for tests that want the `AuditSink` seam
/// exercised without touching a filesystem.
#[derive(Default)]
pub struct MemoryAuditSink {
    records: std::sync::Mutex<Vec<StoredRecord>>,
}

impl MemoryAuditSink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl AuditSink for MemoryAuditSink {
    fn append(&self, record: &StoredRecord) -> Result<(), AuditStoreError> {
        self.records.lock().unwrap().push(record.clone());
        Ok(())
    }

    fn load(&self) -> Result<LoadReport, AuditStoreError> {
        Ok(LoadReport {
            records: self.records.lock().unwrap().clone(),
            truncated_tail_bytes: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(seq: u64, prev: u8, entry: u8, body: &[u8]) -> StoredRecord {
        StoredRecord {
            seq,
            prev_hash: Digest([prev; 32]),
            entry_hash: Digest([entry; 32]),
            body: body.to_vec(),
        }
    }

    #[test]
    fn round_trips_and_preserves_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileAuditStore::new(dir.path().join("ledger.bin"));
        store.append(&record(0, 0, 1, b"first")).unwrap();
        store.append(&record(1, 1, 2, b"second")).unwrap();
        store.append(&record(2, 2, 3, b"third")).unwrap();

        let report = store.load().unwrap();
        assert_eq!(report.truncated_tail_bytes, 0);
        assert_eq!(report.records.len(), 3);
        assert_eq!(report.records[0], record(0, 0, 1, b"first"));
        assert_eq!(report.records[1], record(1, 1, 2, b"second"));
        assert_eq!(report.records[2], record(2, 2, 3, b"third"));
    }

    #[test]
    fn survives_reopen_across_separate_store_instances() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ledger.bin");
        {
            let store = FileAuditStore::new(&path);
            store.append(&record(0, 0, 1, b"a")).unwrap();
        }
        {
            let store = FileAuditStore::new(&path);
            store.append(&record(1, 1, 2, b"b")).unwrap();
        }
        let reopened = FileAuditStore::new(&path);
        let report = reopened.load().unwrap();
        assert_eq!(report.records.len(), 2);
        assert_eq!(report.records[1].body, b"b");
    }

    #[test]
    fn empty_or_missing_file_loads_as_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileAuditStore::new(dir.path().join("does-not-exist.bin"));
        let report = store.load().unwrap();
        assert!(report.records.is_empty());
        assert_eq!(report.truncated_tail_bytes, 0);
    }

    // A crash mid-write truncates the file's tail. load() must recover every
    // complete record before the crash boundary and report exactly how many
    // trailing bytes were dropped -- never silently absorb the loss, and
    // never let a torn final frame corrupt the whole read.
    #[test]
    fn recovers_a_torn_tail_without_losing_prior_records() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ledger.bin");
        let store = FileAuditStore::new(&path);
        store.append(&record(0, 0, 1, b"good-one")).unwrap();
        store.append(&record(1, 1, 2, b"good-two")).unwrap();
        store.append(&record(2, 2, 3, b"would-be-third")).unwrap();

        let full_len = std::fs::metadata(&path).unwrap().len();
        let two_complete_frames_len = 2 * (LEN_PREFIX + HEADER_LEN) as u64
            + "good-one".len() as u64
            + "good-two".len() as u64;
        // Truncate mid-way through the last frame, simulating a crash during
        // its write.
        let torn_len = full_len - 5;
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(torn_len).unwrap();
        drop(file);

        let report = store.load().unwrap();
        assert_eq!(
            report.records.len(),
            2,
            "the two complete records must survive"
        );
        assert_eq!(report.records[0].body, b"good-one");
        assert_eq!(report.records[1].body, b"good-two");
        assert_eq!(
            report.truncated_tail_bytes,
            (torn_len - two_complete_frames_len) as usize,
            "the leftover torn third frame must be reported, not silently absorbed"
        );
        assert!(report.truncated_tail_bytes > 0);
    }

    #[test]
    fn memory_sink_round_trips() {
        let sink = MemoryAuditSink::new();
        sink.append(&record(0, 0, 1, b"x")).unwrap();
        sink.append(&record(1, 1, 2, b"y")).unwrap();
        let report = sink.load().unwrap();
        assert_eq!(report.records.len(), 2);
        assert_eq!(report.truncated_tail_bytes, 0);
    }
}
