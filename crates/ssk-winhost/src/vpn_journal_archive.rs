//! Offline byte-preserving journal snapshots and external-anchor verification.
//! This format carries confidential history, not configuration secrets. No
//! extraction, live-store replacement, truncation, pruning or status mutation.
use super::*;
use crate::{
    state_dir::StateDirLayout,
    vpn_deployment::{elevated, hex},
    vpn_installation::{digest, strict_path},
    vpn_profiles::deny_write_delete_sharing,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::{fs::OpenOptions, path::Path};

#[path = "vpn_journal_recovery.rs"]
mod recovery;
pub use recovery::{
    diagnose, recovery_resume, recovery_stage, Diagnosis, RecoveryReport, RecoveryRequest,
};

// Fixed segments in canonical order. No caller-controlled archive paths or names.
// 8-byte magic + u32 count, followed by (u64 length, exact segment bytes)*count.
const MAGIC: &[u8; 8] = b"SSKJNL01";
const MAX_ARCHIVE: u64 = 12 + MAX_SEGMENTS as u64 * (8 + MAX_JOURNAL_BYTES as u64);

#[derive(Serialize)]
pub struct ArchiveReport {
    pub action: &'static str,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub inspection: Inspection,
    pub restoration_performed: bool,
}
struct Anchor {
    head: ssk_types::Digest,
    records: usize,
}
impl Anchor {
    fn parse(head: &str, records: u64) -> io::Result<Self> {
        let head = ssk_types::Digest(digest(head).map_err(|_| io::ErrorKind::InvalidInput)?);
        if records > (MAX_RECORDS * MAX_SEGMENTS) as u64
            || (records == 0) != (head == ssk_types::Digest::GENESIS)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            head,
            records: records as usize,
        })
    }
    fn check(&self, inspection: &Inspection) -> io::Result<()> {
        if inspection.head != self.head || inspection.records != self.records {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal differs from expected head or record count",
            ));
        }
        Ok(())
    }
}

// Both production segments and archives replay through the same frame decoder
// and the existing Journal state machine, including deployment/repair metadata.
fn segment(
    reader: &mut dyn Read,
    index: usize,
    total: usize,
    visit: &mut dyn FnMut(Record) -> io::Result<()>,
) -> io::Result<(usize, u64)> {
    let mut schema2 = false;
    let result = read_frames(reader, Limits::default(), &mut |record| {
        schema2 |= record.schema == 2;
        visit(record)
    })?;
    if (result.0 == 0 && index + 1 != total) || (index == 0 && total > 1 && !schema2) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(result)
}
struct SnapshotReader(Vec<File>);
impl Store for SnapshotReader {
    fn load(&mut self) -> io::Result<Vec<Record>> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn append(&mut self, _: &Record) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn has_capacity(&self, _: usize) -> bool {
        false
    }
    fn record_limit(&self) -> usize {
        MAX_RECORDS * MAX_SEGMENTS
    }
    fn replay(&mut self, visit: &mut dyn FnMut(Record) -> io::Result<()>) -> io::Result<()> {
        let count = self.0.len();
        for (index, file) in self.0.iter_mut().enumerate() {
            if file.metadata()?.len() > MAX_JOURNAL_BYTES as u64 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            file.seek(SeekFrom::Start(0))?;
            segment(file, index, count, visit)?;
        }
        Ok(())
    }
}
struct ArchiveReader {
    file: File,
    storage: Option<StorageInfo>,
}
impl Store for ArchiveReader {
    fn load(&mut self) -> io::Result<Vec<Record>> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn append(&mut self, _: &Record) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn has_capacity(&self, _: usize) -> bool {
        false
    }
    fn record_limit(&self) -> usize {
        MAX_RECORDS * MAX_SEGMENTS
    }
    fn storage_info(&self) -> Option<StorageInfo> {
        self.storage.clone()
    }
    fn replay(&mut self, visit: &mut dyn FnMut(Record) -> io::Result<()>) -> io::Result<()> {
        self.storage = None;
        let length = self.file.metadata()?.len();
        if !(20..=MAX_ARCHIVE).contains(&length) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.file.seek(SeekFrom::Start(0))?;
        let mut header = [0; 12];
        self.file.read_exact(&mut header)?;
        let count = u32::from_le_bytes(header[8..].try_into().unwrap()) as usize;
        if &header[..8] != MAGIC || !(1..=MAX_SEGMENTS).contains(&count) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut storage = StorageInfo {
            segments: count,
            max_segments: MAX_SEGMENTS,
            active_records: 0,
            active_bytes: 0,
            total_bytes: 0,
            max_total_bytes: (MAX_SEGMENTS * MAX_JOURNAL_BYTES) as u64,
            guaranteed_record_slots: 0,
        };
        for index in 0..count {
            let mut size = [0; 8];
            self.file.read_exact(&mut size)?;
            let size = u64::from_le_bytes(size);
            if size > MAX_JOURNAL_BYTES as u64 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let mut reader = (&mut self.file).take(size);
            let (records, bytes) = segment(&mut reader, index, count, visit)?;
            if reader.limit() != 0 || bytes != size {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            storage.total_bytes += size;
            storage.active_records = records;
            storage.active_bytes = bytes;
        }
        if self.file.read(&mut [0; 1])? != 0
            || length != 12 + 8 * count as u64 + storage.total_bytes
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.storage = Some(storage);
        Ok(())
    }
}

fn artifact_store(path: &Path, probe: &dyn PathSecurityProbe) -> io::Result<ProfileStore> {
    strict_path(path).map_err(|_| io::ErrorKind::InvalidInput)?;
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let layout = StateDirLayout::new(parent, 1).map_err(|_| io::ErrorKind::InvalidInput)?;
    ProfileStore::open_layout(layout, probe).map_err(store_error)
}
fn fingerprint(file: &mut File) -> io::Result<[u8; 32]> {
    let length = file.metadata()?.len();
    if !(20..=MAX_ARCHIVE).contains(&length) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    file.seek(SeekFrom::Start(0))?;
    let mut read = 0u64;
    let mut hash = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        read += n as u64;
        if read > length {
            return Err(io::ErrorKind::InvalidData.into());
        }
        hash.update(&buf[..n]);
    }
    if read != length {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(hash.finalize().into())
}
fn verify_file(
    mut file: File,
    expected_sha: [u8; 32],
    anchor: &Anchor,
    action: &'static str,
) -> io::Result<ArchiveReport> {
    if fingerprint(&mut file)? != expected_sha {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "archive differs from expected SHA-256",
        ));
    }
    let archive_bytes = file.metadata()?.len();
    let journal = Journal::open(Box::new(ArchiveReader {
        file,
        storage: None,
    }))?;
    let inspection = journal.inspection();
    anchor.check(&inspection)?;
    Ok(ArchiveReport {
        action,
        archive_sha256: hex(&expected_sha),
        archive_bytes,
        inspection,
        restoration_performed: false,
    })
}
fn write_hashed(file: &mut File, hash: &mut Sha256, bytes: &[u8]) -> io::Result<()> {
    file.write_all(bytes)?;
    hash.update(bytes);
    Ok(())
}
fn backup_with(
    store: &mut SegmentedJournal,
    destination: &Path,
    anchor: &Anchor,
    probe: &dyn PathSecurityProbe,
) -> io::Result<ArchiveReport> {
    let files = store
        .segments
        .iter()
        .map(|s| s.file.try_clone())
        .collect::<io::Result<Vec<_>>>()?;
    let journal = Journal::open(Box::new(SnapshotReader(files)))?;
    anchor.check(&journal.inspection())?;
    // Keep both source locks and the full verified replay alive during creation.
    // Existing outputs are never overwritten, including incomplete prior copies.
    let artifacts = artifact_store(destination, probe)?;
    // Never place an archive in the live store, where its name could become a
    // future journal segment or another active product artifact. Canonicalize
    // existing parents after ACL/reparse checks, then compare Windows casing.
    let parent = std::fs::canonicalize(artifacts.directory())?
        .to_string_lossy()
        .to_lowercase();
    let live = std::fs::canonicalize(store.profiles.directory())?
        .to_string_lossy()
        .to_lowercase();
    if parent == live || parent.starts_with(&(live + "\\")) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "archive destination must be outside the live profile store",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    use std::os::windows::fs::OpenOptionsExt;
    options.share_mode(0);
    let mut out = options.open(destination)?;
    artifacts
        .check_file(&out, destination, probe)
        .map_err(store_error)?;
    let mut hash = Sha256::new();
    write_hashed(&mut out, &mut hash, MAGIC)?;
    write_hashed(
        &mut out,
        &mut hash,
        &(store.segments.len() as u32).to_le_bytes(),
    )?;
    let mut buf = [0; 65536];
    for source in &mut store.segments {
        let length = source.file.metadata()?.len();
        if length > MAX_JOURNAL_BYTES as u64 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        source.file.seek(SeekFrom::Start(0))?;
        write_hashed(&mut out, &mut hash, &length.to_le_bytes())?;
        let mut copied = 0u64;
        loop {
            let n = source.file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            copied += n as u64;
            if copied > length {
                return Err(io::ErrorKind::InvalidData.into());
            }
            write_hashed(&mut out, &mut hash, &buf[..n])?;
        }
        if copied != length {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
    }
    out.sync_all()?;
    // Verify exact bytes AND replay the complete archive through a duplicated
    // handle while the original exclusive output handle remains held.
    let report = verify_file(
        out.try_clone()?,
        hash.finalize().into(),
        anchor,
        "journal-backed-up",
    )?;
    artifacts.verify(probe).map_err(store_error)?;
    artifacts
        .check_file(&out, destination, probe)
        .map_err(store_error)?;
    Ok(report)
}
fn verify_with(
    archive: &Path,
    expected_sha: &str,
    anchor: &Anchor,
    probe: &dyn PathSecurityProbe,
) -> io::Result<ArchiveReport> {
    let expected = digest(expected_sha).map_err(|_| io::ErrorKind::InvalidInput)?;
    let artifacts = artifact_store(archive, probe)?;
    let mut options = OpenOptions::new();
    options.read(true);
    deny_write_delete_sharing(&mut options);
    let file = options.open(archive)?;
    artifacts
        .check_file(&file, archive, probe)
        .map_err(store_error)?;
    verify_file(file, expected, anchor, "journal-backup-verified")
}

/// Snapshot existing fixed journals while holding the service's writer locks.
/// Expected head/count come from a separately retained offline inspection.
pub fn backup(
    destination: &Path,
    expected_head: &str,
    expected_records: u64,
) -> io::Result<ArchiveReport> {
    elevated().map_err(|_| io::ErrorKind::PermissionDenied)?;
    let anchor = Anchor::parse(expected_head, expected_records)?;
    let mut store = SegmentedJournal::open(ProfileStore::open().map_err(store_error)?, false)?;
    backup_with(&mut store, destination, &anchor, &Win32PathSecurityProbe)
}
/// Verify independently of a live store, even when that store is unavailable.
/// Caller-supplied anchors must come from independent trusted custody.
pub fn backup_verify(
    archive: &Path,
    expected_sha256: &str,
    expected_head: &str,
    expected_records: u64,
) -> io::Result<ArchiveReport> {
    elevated().map_err(|_| io::ErrorKind::PermissionDenied)?;
    verify_with(
        archive,
        expected_sha256,
        &Anchor::parse(expected_head, expected_records)?,
        &Win32PathSecurityProbe,
    )
}

#[cfg(test)]
#[path = "vpn_journal_archive_tests.rs"]
mod tests;
