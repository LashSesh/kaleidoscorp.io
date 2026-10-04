//! Recover exact journal bytes into quarantine, preserving originals and failed
//! attempts. The durable reserved marker fences all normal journal opens. No
//! activation, removal of the fence, live-file replacement or PID operation.
use super::*;
use serde::Deserialize;
use std::os::windows::fs::OpenOptionsExt;
use std::{collections::BTreeSet, fs, path::PathBuf};

const MARKER: &str = "openvpn-control-recovery.journal";
const MAX_PLAN: usize = 32768;
const MAX_ATTEMPTS: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentEvidence {
    pub index: usize,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Serialize)]
pub struct Diagnosis {
    pub observed_sha256: String,
    pub segments: Vec<SegmentEvidence>,
    pub recovery_plan_sha256: Option<String>,
    pub service_blocked_by_recovery: bool,
}
pub struct RecoveryRequest<'a> {
    pub archive: &'a Path,
    pub expected_archive_sha256: &'a str,
    pub expected_head: &'a str,
    pub expected_records: u64,
    pub expected_observed: &'a str,
}
#[derive(Serialize)]
pub struct RecoveryReport {
    pub recovery_id: String,
    pub plan_sha256: String,
    pub attempt: usize,
    pub candidate_directory: PathBuf,
    pub evidence_directory: PathBuf,
    pub inspection: Inspection,
    pub service_blocked: bool,
    pub activation_performed: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: u32,
    id: String,
    archive_sha256: String,
    head: String,
    records: u64,
    observed_sha256: String,
    original: Vec<SegmentEvidence>,
}
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    schema: u32,
    plan_sha256: String,
    attempt: usize,
}
struct Snapshot {
    files: Vec<File>,
    entries: Vec<SegmentEvidence>,
}
struct VerifiedCopies {
    inspection: Inspection,
    _evidence: Snapshot,
    _candidate: Snapshot,
    _journal: Journal,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn json(value: &impl Serialize) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid("recovery encoding failed"))
}
fn hash(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn name(index: usize) -> String {
    if index == 0 {
        "openvpn-control.journal".into()
    } else {
        format!("openvpn-control-{index:06}.journal")
    }
}
fn indices(
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    exact: bool,
) -> io::Result<Vec<usize>> {
    store.verify(probe).map_err(store_error)?;
    let mut indices = Vec::new();
    for (count, entry) in fs::read_dir(store.directory())?.enumerate() {
        if count >= 4096 {
            return Err(invalid("recovery directory bound exceeded"));
        }
        let filename = entry?.file_name();
        let text = filename
            .to_str()
            .ok_or_else(|| invalid("invalid recovery filename"))?;
        if text == "openvpn-control.journal" {
            indices.push(0);
        } else if text == MARKER && !exact {
            continue;
        } else if text.to_ascii_lowercase().starts_with("openvpn-control")
            && text.to_ascii_lowercase().ends_with(".journal")
        {
            let value = text
                .strip_prefix("openvpn-control-")
                .and_then(|s| s.strip_suffix(".journal"))
                .ok_or_else(|| invalid("noncanonical journal filename"))?;
            let index: usize = value
                .parse()
                .map_err(|_| invalid("noncanonical journal index"))?;
            if index == 0 || index >= MAX_SEGMENTS || text != name(index) {
                return Err(invalid("noncanonical journal index"));
            }
            indices.push(index);
        } else if exact {
            return Err(invalid("unexpected recovery artifact"));
        }
    }
    indices.sort_unstable();
    if indices.len() > MAX_SEGMENTS {
        return Err(invalid("too many recovery segments"));
    }
    Ok(indices)
}
fn file_hash(file: &mut File) -> io::Result<String> {
    let length = file.metadata()?.len();
    if length > MAX_JOURNAL_BYTES as u64 {
        return Err(invalid("damaged segment exceeds recovery bound"));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut total = 0;
    let mut hash = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > length {
            return Err(invalid("segment changed while reading"));
        }
        hash.update(&buf[..n]);
    }
    if total != length {
        return Err(invalid("segment changed while reading"));
    }
    Ok(hex(&hash.finalize()))
}
impl Snapshot {
    fn open(store: &ProfileStore, probe: &dyn PathSecurityProbe, exact: bool) -> io::Result<Self> {
        let mut files = Vec::new();
        let mut entries = Vec::new();
        for index in indices(store, probe, exact)? {
            // The original writer-exclusion locks work even for corrupt bodies
            // and missing/gapped segments. No missing file is ever created.
            let mut file = store
                .journal_segment(index, false, probe)
                .map_err(store_error)?;
            let sha256 = file_hash(&mut file)?;
            entries.push(SegmentEvidence {
                index,
                bytes: file.metadata()?.len(),
                sha256,
            });
            files.push(file);
        }
        Ok(Self { files, entries })
    }
    fn digest(&self) -> io::Result<String> {
        Ok(hash(&json(&self.entries)?))
    }
    fn check_inventory(
        &mut self,
        store: &ProfileStore,
        probe: &dyn PathSecurityProbe,
    ) -> io::Result<()> {
        if indices(store, probe, false)? != self.entries.iter().map(|s| s.index).collect::<Vec<_>>()
        {
            return Err(invalid("live journal inventory changed"));
        }
        for (file, entry) in self.files.iter_mut().zip(&self.entries) {
            store
                .check_file(file, &store.directory().join(name(entry.index)), probe)
                .map_err(store_error)?;
            if file_hash(file)? != entry.sha256 {
                return Err(invalid("live journal bytes changed"));
            }
        }
        Ok(())
    }
    fn archive_hash(&mut self) -> io::Result<String> {
        if self.entries.is_empty()
            || self
                .entries
                .iter()
                .map(|s| s.index)
                .ne(0..self.entries.len())
        {
            return Err(invalid("candidate journal gaps"));
        }
        let mut hasher = Sha256::new();
        hasher.update(MAGIC);
        hasher.update((self.files.len() as u32).to_le_bytes());
        let mut buf = [0; 65536];
        for (file, entry) in self.files.iter_mut().zip(&self.entries) {
            hasher.update(entry.bytes.to_le_bytes());
            file.seek(SeekFrom::Start(0))?;
            let mut total = 0;
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                if total > entry.bytes {
                    return Err(invalid("candidate size changed"));
                }
                hasher.update(&buf[..n]);
            }
            if total != entry.bytes {
                return Err(invalid("candidate size changed"));
            }
        }
        Ok(hex(&hasher.finalize()))
    }
}
fn open_metadata(
    store: &ProfileStore,
    filename: &str,
    probe: &dyn PathSecurityProbe,
    exclusive: bool,
) -> io::Result<File> {
    store.verify(probe).map_err(store_error)?;
    let path = store.directory().join(filename);
    let mut options = OpenOptions::new();
    options.read(true).share_mode(if exclusive { 0 } else { 1 });
    let file = options.open(&path)?;
    store.check_file(&file, &path, probe).map_err(store_error)?;
    Ok(file)
}
fn read_metadata(file: &mut File) -> io::Result<Vec<u8>> {
    if file.metadata()?.len() > MAX_PLAN as u64 {
        return Err(invalid("recovery metadata too large"));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(MAX_PLAN as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PLAN {
        return Err(invalid("recovery metadata too large"));
    }
    Ok(bytes)
}
fn create_file(
    store: &ProfileStore,
    filename: &str,
    probe: &dyn PathSecurityProbe,
) -> io::Result<File> {
    store.verify(probe).map_err(store_error)?;
    let path = store.directory().join(filename);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(&path)?;
    store.check_file(&file, &path, probe).map_err(store_error)?;
    Ok(file)
}
fn child(
    store: &ProfileStore,
    filename: &str,
    probe: &dyn PathSecurityProbe,
    create: bool,
) -> io::Result<ProfileStore> {
    store.verify(probe).map_err(store_error)?;
    let path = store.directory().join(filename);
    if create {
        fs::create_dir(&path)?;
    }
    store.child_store(&path, probe).map_err(store_error)
}
fn copy(source: &mut dyn Read, bytes: u64, target: &mut File) -> io::Result<()> {
    let mut remaining = bytes;
    let mut buf = [0; 65536];
    while remaining > 0 {
        let n = remaining.min(buf.len() as u64) as usize;
        source.read_exact(&mut buf[..n])?;
        target.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    target.sync_all()
}
fn diagnose_with(store: &ProfileStore, probe: &dyn PathSecurityProbe) -> io::Result<Diagnosis> {
    let snapshot = Snapshot::open(store, probe, false)?;
    let marker = match open_metadata(store, MARKER, probe, false) {
        Ok(mut file) => Some(hash(&read_metadata(&mut file)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    Ok(Diagnosis {
        observed_sha256: snapshot.digest()?,
        segments: snapshot.entries,
        service_blocked_by_recovery: marker.is_some(),
        recovery_plan_sha256: marker,
    })
}
fn completed(
    attempt_store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    plan: &Plan,
    expected: &Completion,
) -> io::Result<Inspection> {
    let names = fs::read_dir(attempt_store.directory())?
        .take(4)
        .map(|e| e.map(|e| e.file_name()))
        .collect::<io::Result<BTreeSet<_>>>()?;
    if names
        != ["candidate", "evidence", "complete.json"]
            .map(std::ffi::OsString::from)
            .into_iter()
            .collect()
    {
        return Err(invalid("unexpected completed-attempt contents"));
    }
    let mut record = open_metadata(attempt_store, "complete.json", probe, false)?;
    let receipt: Completion = serde_json::from_slice(&read_metadata(&mut record)?)
        .map_err(|_| invalid("invalid completion receipt"))?;
    if &receipt != expected {
        return Err(invalid("completion belongs to another recovery plan"));
    }
    Ok(verify_copies(attempt_store, probe, plan)?.inspection)
}
fn verify_copies(
    attempt_store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    plan: &Plan,
) -> io::Result<VerifiedCopies> {
    let evidence_store = child(attempt_store, "evidence", probe, false)?;
    let evidence = Snapshot::open(&evidence_store, probe, true)?;
    if evidence.entries != plan.original || evidence.digest()? != plan.observed_sha256 {
        return Err(invalid("preserved original evidence changed"));
    }
    let candidate_store = child(attempt_store, "candidate", probe, false)?;
    let mut candidate = Snapshot::open(&candidate_store, probe, true)?;
    if candidate.archive_hash()? != plan.archive_sha256 {
        return Err(invalid("candidate differs from trusted archive"));
    }
    let files = candidate
        .files
        .iter()
        .map(File::try_clone)
        .collect::<io::Result<Vec<_>>>()?;
    let journal = Journal::open(Box::new(SnapshotReader(files)))?;
    let inspection = journal.inspection();
    Anchor::parse(&plan.head, plan.records)?.check(&inspection)?;
    Ok(VerifiedCopies {
        inspection,
        _evidence: evidence,
        _candidate: candidate,
        _journal: journal,
    })
}
fn run_with(
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    request: &RecoveryRequest<'_>,
    expected_plan: Option<&str>,
    checkpoint: &mut dyn FnMut(&str) -> io::Result<()>,
) -> io::Result<RecoveryReport> {
    let anchor = Anchor::parse(request.expected_head, request.expected_records)?;
    if anchor.records == 0 {
        return Err(invalid("empty history cannot be a recovery candidate"));
    }
    let archive_sha =
        digest(request.expected_archive_sha256).map_err(|_| io::ErrorKind::InvalidInput)?;
    digest(request.expected_observed).map_err(|_| io::ErrorKind::InvalidInput)?;
    let artifacts = artifact_store(request.archive, probe)?;
    let mut options = OpenOptions::new();
    options.read(true);
    deny_write_delete_sharing(&mut options);
    let mut archive = options.open(request.archive)?;
    artifacts
        .check_file(&archive, request.archive, probe)
        .map_err(store_error)?;
    verify_file(
        archive.try_clone()?,
        archive_sha,
        &anchor,
        "recovery-source-verified",
    )?;
    let mut original = Snapshot::open(store, probe, false)?;
    if original.digest()? != request.expected_observed {
        return Err(invalid("observed journal differs from diagnosis"));
    }
    let (plan, bytes, _marker) = if let Some(expected) = expected_plan {
        digest(expected).map_err(|_| io::ErrorKind::InvalidInput)?;
        let mut file = open_metadata(store, MARKER, probe, true)?;
        let bytes = read_metadata(&mut file)?;
        if hash(&bytes) != expected {
            return Err(invalid("recovery plan differs from pinned hash"));
        }
        let plan: Plan =
            serde_json::from_slice(&bytes).map_err(|_| invalid("invalid recovery plan"))?;
        if plan.schema != 1
            || plan.id.len() != 32
            || !plan
                .id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || plan.id.bytes().all(|b| b == b'0')
            || plan.archive_sha256 != request.expected_archive_sha256
            || plan.head != request.expected_head
            || plan.records != request.expected_records
            || plan.observed_sha256 != request.expected_observed
            || plan.original != original.entries
        {
            return Err(invalid("recovery plan does not match trusted inputs"));
        }
        (plan, bytes, file)
    } else {
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| io::ErrorKind::Other)?;
        if id == [0; 16] {
            return Err(io::ErrorKind::Other.into());
        }
        let plan = Plan {
            schema: 1,
            id: hex(&id),
            archive_sha256: request.expected_archive_sha256.into(),
            head: request.expected_head.into(),
            records: request.expected_records,
            observed_sha256: request.expected_observed.into(),
            original: original.entries.clone(),
        };
        let bytes = json(&plan)?;
        if bytes.len() > MAX_PLAN {
            return Err(invalid("recovery plan too large"));
        }
        let mut file = create_file(store, MARKER, probe)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        (plan, bytes, file)
    };
    checkpoint("marker-synced")?;
    original.check_inventory(store, probe)?;
    let plan_sha = hash(&bytes);
    let folder = format!("journal-recovery-{}", plan.id);
    let root = match child(store, &folder, probe, true) {
        Ok(root) => root,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists && expected_plan.is_some() => {
            child(store, &folder, probe, false)?
        }
        Err(error) => return Err(error),
    };
    let mut attempts = fs::read_dir(root.directory())?
        .take(MAX_ATTEMPTS + 1)
        .map(|e| e.map(|e| e.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    attempts.sort();
    if attempts.len() > MAX_ATTEMPTS
        || attempts
            .iter()
            .enumerate()
            .any(|(i, n)| n != &std::ffi::OsString::from(format!("attempt-{:04}", i + 1)))
    {
        return Err(invalid("unexpected recovery attempts"));
    }
    for index in 1..=attempts.len() {
        let attempt = child(&root, &format!("attempt-{index:04}"), probe, false)?;
        match fs::symlink_metadata(attempt.directory().join("complete.json")) {
            Ok(_) => {
                if index != attempts.len() {
                    return Err(invalid("unexpected attempt after completion"));
                }
                let receipt = Completion {
                    schema: 1,
                    plan_sha256: plan_sha.clone(),
                    attempt: index,
                };
                let inspection = completed(&attempt, probe, &plan, &receipt)?;
                original.check_inventory(store, probe)?;
                return Ok(report(&plan, plan_sha, index, &attempt, inspection));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let index = attempts.len() + 1;
    if index > MAX_ATTEMPTS {
        return Err(invalid(
            "recovery attempt limit reached; preserve all evidence",
        ));
    }
    let attempt = child(&root, &format!("attempt-{index:04}"), probe, true)?;
    let evidence = child(&attempt, "evidence", probe, true)?;
    let candidate = child(&attempt, "candidate", probe, true)?;
    for (source, entry) in original.files.iter_mut().zip(&original.entries) {
        source.seek(SeekFrom::Start(0))?;
        let mut target = create_file(&evidence, &name(entry.index), probe)?;
        copy(source, entry.bytes, &mut target)?;
        checkpoint("evidence-file-synced")?;
    }
    archive.seek(SeekFrom::Start(0))?;
    let mut header = [0; 12];
    archive.read_exact(&mut header)?;
    let count = u32::from_le_bytes(header[8..].try_into().unwrap()) as usize;
    if &header[..8] != MAGIC || !(1..=MAX_SEGMENTS).contains(&count) {
        return Err(invalid("archive header changed"));
    }
    for index in 0..count {
        let mut size = [0; 8];
        archive.read_exact(&mut size)?;
        let size = u64::from_le_bytes(size);
        if size > MAX_JOURNAL_BYTES as u64 {
            return Err(invalid("archive segment size changed"));
        }
        let mut target = create_file(&candidate, &name(index), probe)?;
        copy(&mut archive, size, &mut target)?;
        checkpoint("candidate-file-synced")?;
    }
    if archive.read(&mut [0; 1])? != 0 {
        return Err(invalid("archive trailing bytes"));
    }
    original.check_inventory(store, probe)?;
    checkpoint("copies-synced")?;
    let verified = verify_copies(&attempt, probe, &plan)?;
    let receipt = Completion {
        schema: 1,
        plan_sha256: plan_sha.clone(),
        attempt: index,
    };
    let mut file = create_file(&attempt, "complete.json", probe)?;
    file.write_all(&json(&receipt)?)?;
    file.sync_all()?;
    let readback: Completion = serde_json::from_slice(&read_metadata(&mut file)?)
        .map_err(|_| invalid("invalid completion readback"))?;
    if readback != receipt {
        return Err(invalid("completion readback mismatch"));
    }
    drop(file);
    checkpoint("complete-synced")?;
    Ok(report(
        &plan,
        plan_sha,
        index,
        &attempt,
        verified.inspection,
    ))
}
fn report(
    plan: &Plan,
    plan_sha256: String,
    attempt: usize,
    store: &ProfileStore,
    inspection: Inspection,
) -> RecoveryReport {
    RecoveryReport {
        recovery_id: plan.id.clone(),
        plan_sha256,
        attempt,
        candidate_directory: store.directory().join("candidate"),
        evidence_directory: store.directory().join("evidence"),
        inspection,
        service_blocked: true,
        activation_performed: false,
    }
}
pub fn diagnose() -> io::Result<Diagnosis> {
    elevated().map_err(|_| io::ErrorKind::PermissionDenied)?;
    diagnose_with(
        &ProfileStore::open().map_err(store_error)?,
        &Win32PathSecurityProbe,
    )
}
pub fn recovery_stage(request: RecoveryRequest<'_>) -> io::Result<RecoveryReport> {
    elevated().map_err(|_| io::ErrorKind::PermissionDenied)?;
    run_with(
        &ProfileStore::open().map_err(store_error)?,
        &Win32PathSecurityProbe,
        &request,
        None,
        &mut |_| Ok(()),
    )
}
pub fn recovery_resume(
    request: RecoveryRequest<'_>,
    expected_plan_sha256: &str,
) -> io::Result<RecoveryReport> {
    elevated().map_err(|_| io::ErrorKind::PermissionDenied)?;
    run_with(
        &ProfileStore::open().map_err(store_error)?,
        &Win32PathSecurityProbe,
        &request,
        Some(expected_plan_sha256),
        &mut |_| Ok(()),
    )
}

#[cfg(test)]
#[path = "vpn_journal_recovery_tests.rs"]
mod tests;
