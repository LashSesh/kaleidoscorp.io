//! Bounded, append-only VPN journal segments. The original file stays locked
//! for the store lifetime; closed segments are retained, never renamed/reset.
use crate::{
    service::{PathSecurityProbe, Win32PathSecurityProbe},
    vpn_profiles::{ProfileStore, ProfileStoreError},
};
use ssk_netd_helper::vpn::journal::{
    Inspection, Journal, Record, StorageInfo, Store, MAX_JOURNAL_BYTES, MAX_RECORDS,
    MAX_RECORD_BYTES, MAX_SEGMENTS,
};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};

#[path = "vpn_journal_archive.rs"]
mod archive;
pub use archive::{
    backup, backup_verify, diagnose, recovery_resume, recovery_stage, ArchiveReport, Diagnosis,
    RecoveryReport, RecoveryRequest,
};

#[derive(Clone, Copy)]
struct Limits {
    records: usize,
    bytes: usize,
    segments: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            records: MAX_RECORDS,
            bytes: MAX_JOURNAL_BYTES,
            segments: MAX_SEGMENTS,
        }
    }
}
struct Segment {
    file: File,
    records: usize,
    bytes: u64,
}
pub(crate) struct SegmentedJournal {
    profiles: ProfileStore,
    segments: Vec<Segment>,
    limits: Limits,
    ready: bool,
    upgrade_fence: bool,
    // Private fixture seam only; production always uses the real probe.
    probe: Box<dyn PathSecurityProbe + Send>,
}

fn store_error(error: ProfileStoreError) -> io::Error {
    let kind = match error {
        ProfileStoreError::NotFound => io::ErrorKind::NotFound,
        ProfileStoreError::AlreadyExists => io::ErrorKind::AlreadyExists,
        ProfileStoreError::Io(kind) => kind,
        _ => io::ErrorKind::PermissionDenied,
    };
    io::Error::new(kind, error.to_string())
}
impl SegmentedJournal {
    pub(crate) fn open(profiles: ProfileStore, create: bool) -> io::Result<Self> {
        Self::open_with(
            profiles,
            create,
            Limits::default(),
            Box::new(Win32PathSecurityProbe),
        )
    }
    fn open_with(
        profiles: ProfileStore,
        create: bool,
        limits: Limits,
        probe: Box<dyn PathSecurityProbe + Send>,
    ) -> io::Result<Self> {
        if limits.records == 0
            || limits.records > MAX_RECORDS
            || limits.bytes == 0
            || limits.bytes > MAX_JOURNAL_BYTES
            || limits.segments == 0
            || limits.segments > MAX_SEGMENTS
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let indices = profiles.journal_indices(&*probe).map_err(store_error)?;
        if indices.is_empty() && !create {
            return Err(io::ErrorKind::NotFound.into());
        }
        let origin = profiles
            .journal_segment(0, indices.is_empty(), &*probe)
            .map_err(store_error)?;
        // Another service could have completed a rotation during the first scan.
        // Scan again only AFTER acquiring the permanent origin writer lock.
        let indices = profiles.journal_indices(&*probe).map_err(store_error)?;
        if indices.is_empty() || indices.len() > limits.segments {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut segments = vec![Segment {
            file: origin,
            records: 0,
            bytes: 0,
        }];
        for index in indices.into_iter().skip(1) {
            let file = profiles
                .journal_segment(index, false, &*probe)
                .map_err(store_error)?;
            segments.push(Segment {
                file,
                records: 0,
                bytes: 0,
            });
        }
        Ok(Self {
            profiles,
            segments,
            limits,
            ready: false,
            upgrade_fence: false,
            probe,
        })
    }
    #[cfg(test)]
    pub(crate) fn open_fixture(
        profiles: ProfileStore,
        probe: Box<dyn PathSecurityProbe + Send>,
    ) -> io::Result<Self> {
        Self::open_with(profiles, true, Limits::default(), probe)
    }
    fn slots(&self) -> usize {
        let active = self.segments.last().expect("origin is always present");
        let frame = MAX_RECORD_BYTES + 4;
        let current = self
            .limits
            .records
            .saturating_sub(active.records)
            .min(self.limits.bytes.saturating_sub(active.bytes as usize) / frame);
        let future = self.limits.segments.saturating_sub(self.segments.len())
            * self.limits.records.min(self.limits.bytes / frame);
        current + if self.upgrade_fence { future } else { 0 }
    }
}
impl Store for SegmentedJournal {
    fn load(&mut self) -> io::Result<Vec<Record>> {
        // Intentional: callers must use streaming replay for this bounded store.
        Err(io::ErrorKind::Unsupported.into())
    }
    fn replay(&mut self, visit: &mut dyn FnMut(Record) -> io::Result<()>) -> io::Result<()> {
        self.ready = false;
        self.upgrade_fence = false;
        let length = self.segments.len();
        for (index, segment) in self.segments.iter_mut().enumerate() {
            let mut fence = false;
            let (records, bytes) = read_records(&mut segment.file, self.limits, &mut |record| {
                fence |= record.schema == 2;
                visit(record)
            })?;
            if records == 0 && index + 1 != length {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if index == 0 {
                self.upgrade_fence = fence;
            }
            segment.records = records;
            segment.bytes = bytes;
        }
        if length > 1 && !self.upgrade_fence {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.ready = true;
        Ok(())
    }
    fn append(&mut self, record: &Record) -> io::Result<()> {
        if !self.ready || record.schema != 2 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let bytes = encode(record)?;
        let frame = bytes.len() + 4;
        if frame > self.limits.bytes {
            return Err(io::ErrorKind::StorageFull.into());
        }
        let active = self.segments.last().expect("origin is always present");
        if active.records >= self.limits.records
            || active.bytes + frame as u64 > self.limits.bytes as u64
        {
            if self.segments.len() >= self.limits.segments {
                return Err(io::ErrorKind::StorageFull.into());
            }
            if !self.upgrade_fence {
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "legacy journal has no room for its first schema-2 record; migration required",
                ));
            }
            let file = self
                .profiles
                .journal_segment(self.segments.len(), true, &*self.probe)
                .map_err(store_error)?;
            self.segments.push(Segment {
                file,
                records: 0,
                bytes: 0,
            });
            // An empty final segment is a valid crash point, not a new history.
            self.segments.last().unwrap().file.sync_all()?;
        }
        let active = self.segments.last_mut().unwrap();
        append_frame(&mut active.file, &bytes)?;
        active.records += 1;
        active.bytes += frame as u64;
        if self.segments.len() == 1 {
            self.upgrade_fence = true;
        }
        Ok(())
    }
    fn record_limit(&self) -> usize {
        self.limits.records * self.limits.segments
    }
    fn has_capacity(&self, records: usize) -> bool {
        self.ready && self.slots() >= records
    }
    fn storage_info(&self) -> Option<StorageInfo> {
        let active = self.segments.last().unwrap();
        Some(StorageInfo {
            segments: self.segments.len(),
            max_segments: self.limits.segments,
            active_records: active.records,
            active_bytes: active.bytes,
            total_bytes: self.segments.iter().map(|s| s.bytes).sum(),
            max_total_bytes: (self.limits.bytes * self.limits.segments) as u64,
            guaranteed_record_slots: self.slots(),
        })
    }
}

/// Offline integrity/capacity inspection. Opens existing fixed files only and
/// takes the same lifetime lock as the service. No boot event or other mutation.
pub fn inspect() -> io::Result<Inspection> {
    let profiles = ProfileStore::open().map_err(store_error)?;
    let store = SegmentedJournal::open(profiles, false)?;
    Ok(Journal::open(Box::new(store))?.inspection())
}

fn encode(record: &Record) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(record, &mut bytes).map_err(|_| io::ErrorKind::InvalidData)?;
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(bytes)
}
fn append_frame(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    file.write_all(&(bytes.len() as u32).to_le_bytes())?;
    file.write_all(bytes)?;
    file.sync_all()
}
fn read_records(
    file: &mut File,
    limits: Limits,
    visit: &mut dyn FnMut(Record) -> io::Result<()>,
) -> io::Result<(usize, u64)> {
    if file.metadata()?.len() > limits.bytes as u64 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    file.seek(SeekFrom::Start(0))?;
    read_frames(file, limits, visit)
}

fn read_frames(
    file: &mut dyn Read,
    limits: Limits,
    visit: &mut dyn FnMut(Record) -> io::Result<()>,
) -> io::Result<(usize, u64)> {
    let mut records = 0usize;
    let mut consumed = 0usize;
    loop {
        let mut header = [0u8; 4];
        if file.read(&mut header[..1])? == 0 {
            break;
        }
        file.read_exact(&mut header[1..])?;
        let length = u32::from_le_bytes(header) as usize;
        consumed = consumed
            .checked_add(4 + length)
            .ok_or(io::ErrorKind::InvalidData)?;
        if length == 0
            || length > MAX_RECORD_BYTES
            || consumed > limits.bytes
            || records >= limits.records
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut bytes = vec![0u8; length];
        file.read_exact(&mut bytes)?;
        visit(
            ssk_netd_helper::framing::decode_strict(&bytes)
                .map_err(|_| io::ErrorKind::InvalidData)?,
        )?;
        records += 1;
    }
    Ok((records, consumed as u64))
}

/// Single-file adapter for existing fixture tests. Production uses SegmentedJournal.
#[cfg(test)]
pub(crate) struct FileJournal {
    pub(crate) file: File,
}
#[cfg(test)]
impl Store for FileJournal {
    fn load(&mut self) -> io::Result<Vec<Record>> {
        let mut records = Vec::new();
        read_records(&mut self.file, Limits::default(), &mut |r| {
            records.push(r);
            Ok(())
        })?;
        Ok(records)
    }
    fn append(&mut self, record: &Record) -> io::Result<()> {
        let bytes = encode(record)?;
        if self.file.metadata()?.len() + 4 + bytes.len() as u64 > MAX_JOURNAL_BYTES as u64 {
            return Err(io::ErrorKind::StorageFull.into());
        }
        append_frame(&mut self.file, &bytes)
    }
}

#[cfg(test)]
#[path = "vpn_journal_tests.rs"]
mod tests;
