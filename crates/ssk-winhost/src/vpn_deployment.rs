//! Offline, elevated deployment of independently pinned flat OpenVPN bundles.
//! Never downloads, executes, releases HOLD, installs a driver or controls SCM.
use crate::{
    service::{PathSecurityProbe, Win32PathSecurityProbe},
    vpn_installation::{
        digest, strict_path, Installation, InstallationError, Manifest, MAX_MANIFEST,
    },
    vpn_journal::SegmentedJournal,
    vpn_profiles::{
        deny_write_delete_sharing, reparse, single_link, ProfileStore, ProfileStoreError,
    },
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use ssk_netd_helper::vpn::journal::{clean_status, DeploymentChange, DeploymentEvent, Journal};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

const ACTIVE: &str = "openvpn-installation.json";

#[derive(Debug)]
pub enum DeploymentError {
    Configuration(&'static str),
    ElevationRequired,
    InvalidInput,
    DigestMismatch,
    StaleSelection,
    RecoveryRequired,
    BusyHistory,
    AuditCapacity,
    UnknownSelection,
    BackupFormat,
    BackupAuthentication,
    Store(ProfileStoreError),
    Installation(InstallationError),
    Io(io::ErrorKind),
}
impl std::fmt::Display for DeploymentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpenVPN deployment: {self:?}")
    }
}
impl std::error::Error for DeploymentError {}
impl From<io::Error> for DeploymentError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}
impl From<ProfileStoreError> for DeploymentError {
    fn from(e: ProfileStoreError) -> Self {
        Self::Store(e)
    }
}
impl From<InstallationError> for DeploymentError {
    fn from(e: InstallationError) -> Self {
        Self::Installation(e)
    }
}
type Result<T> = std::result::Result<T, DeploymentError>;

#[derive(Debug, Serialize)]
pub struct Selection {
    pub manifest_sha256: String,
    pub directory: PathBuf,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub action: &'static str,
    pub package_id: Option<String>,
    pub selection: Option<Selection>,
    pub pending_deployment: Option<DeploymentChange>,
    pub pending_repair: Option<ssk_netd_helper::vpn::journal::RepairChange>,
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub(crate) fn elevated() -> Result<()> {
    if crate::elevation() != crate::Elevation::Elevated {
        return Err(DeploymentError::ElevationRequired);
    }
    Ok(())
}
pub(crate) fn journal(create: bool) -> Result<Journal> {
    Ok(Journal::open(Box::new(SegmentedJournal::open(
        ProfileStore::open()?,
        create,
    )?))?)
}
pub(crate) fn ready(journal: &Journal) -> Result<()> {
    if journal.has_pending_maintenance() {
        return Err(DeploymentError::RecoveryRequired);
    }
    if journal.last().is_some_and(|s| !clean_status(s)) {
        return Err(DeploymentError::BusyHistory);
    }
    Ok(())
}

/// Explicit provisioning uses the same create-or-verify ACL policy as profiles.
pub fn provision() -> Result<Report> {
    elevated()?;
    let profiles = ProfileStore::provision(crate::elevation())?;
    let journal = journal(true)?;
    report(
        "provisioned",
        None,
        &profiles,
        &Win32PathSecurityProbe,
        &journal,
    )
}
pub fn inspect() -> Result<Report> {
    elevated()?;
    let journal = journal(false)?;
    report(
        "inspected",
        None,
        &ProfileStore::open()?,
        &Win32PathSecurityProbe,
        &journal,
    )
}
pub fn stage(manifest: &Path, approved_sha256: &str) -> Result<Report> {
    elevated()?;
    let journal = journal(false)?;
    stage_with(
        &ProfileStore::open()?,
        &Win32PathSecurityProbe,
        &journal,
        manifest,
        approved_sha256,
    )
}
pub fn activate(package_id: &str, expected_active: &str) -> Result<Report> {
    elevated()?;
    let mut journal = journal(false)?;
    let actor = crate::current_user_sid().map_err(|_| DeploymentError::ElevationRequired)?;
    activate_with(
        &ProfileStore::open()?,
        &Win32PathSecurityProbe,
        &mut journal,
        &actor,
        package_id,
        expected_active,
        replace_selector,
    )
}
pub fn reconcile() -> Result<Report> {
    elevated()?;
    let mut journal = journal(false)?;
    let actor = crate::current_user_sid().map_err(|_| DeploymentError::ElevationRequired)?;
    reconcile_with(
        &ProfileStore::open()?,
        &Win32PathSecurityProbe,
        &mut journal,
        &actor,
    )
}

struct Document {
    _file: File,
    bytes: Vec<u8>,
}
fn read_document(
    store: &ProfileStore,
    path: &Path,
    probe: &dyn PathSecurityProbe,
) -> Result<Document> {
    store.verify(probe)?;
    let mut options = OpenOptions::new();
    options.read(true);
    deny_write_delete_sharing(&mut options);
    let mut file = options.open(path)?;
    store.check_file(&file, path, probe)?;
    let bytes = bounded_document(&mut file)?;
    Ok(Document { _file: file, bytes })
}
fn bounded_document(file: &mut File) -> Result<Vec<u8>> {
    if file.metadata()?.len() > MAX_MANIFEST as u64 {
        return Err(DeploymentError::InvalidInput);
    }
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_MANIFEST {
        return Err(DeploymentError::InvalidInput);
    }
    Ok(bytes)
}
fn active(store: &ProfileStore, probe: &dyn PathSecurityProbe) -> Result<Option<Document>> {
    match read_document(store, &store.directory().join(ACTIVE), probe) {
        Ok(document) => Ok(Some(document)),
        Err(DeploymentError::Io(io::ErrorKind::NotFound)) => Ok(None),
        Err(e) => Err(e),
    }
}
pub(crate) fn create_document(
    store: &ProfileStore,
    path: &Path,
    bytes: &[u8],
    probe: &dyn PathSecurityProbe,
) -> Result<()> {
    store.verify(probe)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    deny_write_delete_sharing(&mut options);
    let mut file = options.open(path)?;
    store.check_file(&file, path, probe)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn preserve(store: &ProfileStore, bytes: &[u8], probe: &dyn PathSecurityProbe) -> Result<()> {
    let path = store
        .directory()
        .join(format!("manifest-{}.json", hex(&sha(bytes))));
    match create_document(store, &path, bytes, probe) {
        Ok(()) => Ok(()),
        Err(DeploymentError::Io(io::ErrorKind::AlreadyExists)) => {
            if read_document(store, &path, probe)?.bytes == bytes {
                Ok(())
            } else {
                Err(DeploymentError::DigestMismatch)
            }
        }
        Err(e) => Err(e),
    }
}
fn report(
    action: &'static str,
    package_id: Option<String>,
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    journal: &Journal,
) -> Result<Report> {
    let selection = active(store, probe)?
        .map(|doc| {
            let installation = Installation::open_with(&doc.bytes, probe)?;
            Ok::<_, DeploymentError>(Selection {
                manifest_sha256: hex(&sha(&doc.bytes)),
                directory: installation.directory().to_owned(),
            })
        })
        .transpose()?;
    Ok(Report {
        action,
        package_id,
        selection,
        pending_deployment: journal.pending_deployment().cloned(),
        pending_repair: journal.pending_repair().cloned(),
    })
}

fn stage_with(
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    journal: &Journal,
    manifest: &Path,
    approved_sha256: &str,
) -> Result<Report> {
    ready(journal)?;
    let approved = digest(approved_sha256)?;
    strict_path(manifest)?;
    for path in manifest.ancestors() {
        if reparse(path)? {
            return Err(DeploymentError::InvalidInput);
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    deny_write_delete_sharing(&mut options);
    let mut source_manifest = options.open(manifest)?;
    if !source_manifest.metadata()?.is_file() || !single_link(&source_manifest)? {
        return Err(DeploymentError::InvalidInput);
    }
    let bytes = bounded_document(&mut source_manifest)?;
    if sha(&bytes) != approved {
        return Err(DeploymentError::DigestMismatch);
    }
    let mut source = Installation::source(&bytes, probe)?;
    let (_, entries) = Installation::manifest(&bytes)?;
    let directory = store.directory().join(format!("package-{approved_sha256}"));
    strict_path(&directory.join("openvpn.exe"))?;
    store.verify(probe)?;
    // Claim once under the protected parent. Never adopt an incomplete package.
    fs::create_dir(&directory)?;
    let target = store.child_store(&directory, probe)?;
    for ((name, _), input) in entries.iter().zip(source.locked_files()) {
        target.verify(probe)?;
        let path = directory.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        deny_write_delete_sharing(&mut options);
        let mut output = options.open(&path)?;
        target.check_file(&output, &path, probe)?;
        input.seek(SeekFrom::Start(0))?;
        let length = input.metadata()?.len();
        if length > 64 * 1024 * 1024 {
            return Err(DeploymentError::InvalidInput);
        }
        if io::copy(&mut input.take(length + 1), &mut output)? != length {
            return Err(DeploymentError::InvalidInput);
        }
        output.sync_all()?;
    }
    let mut document: Manifest =
        serde_json::from_slice(&bytes).map_err(|_| DeploymentError::InvalidInput)?;
    document.directory = directory;
    let receipt = serde_json::to_vec(&document).map_err(|_| DeploymentError::InvalidInput)?;
    let _verified = Installation::open_with(&receipt, probe)?;
    create_document(
        store,
        &store
            .directory()
            .join(format!("package-{approved_sha256}.json")),
        &receipt,
        probe,
    )?;
    Ok(Report {
        action: "staged",
        package_id: Some(approved_sha256.into()),
        selection: Some(Selection {
            manifest_sha256: hex(&sha(&receipt)),
            directory: document.directory,
        }),
        pending_deployment: None,
        pending_repair: None,
    })
}

fn activate_with(
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    journal: &mut Journal,
    actor: &str,
    package_id: &str,
    expected_active: &str,
    replace: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> Result<Report> {
    ready(journal)?;
    digest(package_id)?;
    let expected = if expected_active == "none" {
        None
    } else {
        Some(digest(expected_active)?)
    };
    let candidate = read_document(
        store,
        &store.directory().join(format!("package-{package_id}.json")),
        probe,
    )?;
    let bundle = Installation::open_with(&candidate.bytes, probe)?;
    if bundle.directory() != store.directory().join(format!("package-{package_id}")) {
        return Err(DeploymentError::InvalidInput);
    }
    let previous = active(store, probe)?;
    if previous.as_ref().map(|d| sha(&d.bytes)) != expected {
        return Err(DeploymentError::StaleSelection);
    }
    // Validate and pin the previous images throughout selection, preserving rollback.
    let _previous_bundle = previous
        .as_ref()
        .map(|d| Installation::open_with(&d.bytes, probe))
        .transpose()?;
    if expected == Some(sha(&candidate.bytes)) {
        return report(
            "already-selected",
            Some(package_id.into()),
            store,
            probe,
            journal,
        );
    }
    if !journal.accepts_intent() {
        return Err(DeploymentError::AuditCapacity);
    }
    if let Some(doc) = &previous {
        preserve(store, &doc.bytes, probe)?;
    }
    preserve(store, &candidate.bytes, probe)?;
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| DeploymentError::Io(io::ErrorKind::Other))?;
    if id == [0; 16] {
        return Err(DeploymentError::InvalidInput);
    }
    let change = DeploymentChange {
        target: ssk_netd_helper::vpn::journal::DeploymentTarget::Package,
        id,
        previous: expected,
        candidate: sha(&candidate.bytes),
    };
    let temporary = store
        .directory()
        .join(format!("installation-{}.pending.json", hex(&id)));
    create_document(store, &temporary, &candidate.bytes, probe)?;
    journal.deployment(actor, DeploymentEvent::Begin(change.clone()))?;
    drop(previous); // Windows replacement needs the selector's delete-denying handle closed.
    store.verify(probe)?;
    replace(&temporary, &store.directory().join(ACTIVE))?;
    let selected = active(store, probe)?.ok_or(DeploymentError::UnknownSelection)?;
    if sha(&selected.bytes) != change.candidate {
        return Err(DeploymentError::UnknownSelection);
    }
    let _verified = Installation::open_with(&selected.bytes, probe)?;
    journal.deployment(actor, DeploymentEvent::Committed(change))?;
    report("selected", Some(package_id.into()), store, probe, journal)
}

fn reconcile_with(
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    journal: &mut Journal,
    actor: &str,
) -> Result<Report> {
    let change = journal
        .pending_deployment()
        .cloned()
        .ok_or(DeploymentError::InvalidInput)?;
    let selected = active(store, probe)?;
    let actual = selected.as_ref().map(|d| sha(&d.bytes));
    if change.target != ssk_netd_helper::vpn::journal::DeploymentTarget::Package {
        return Err(DeploymentError::InvalidInput);
    }
    let event = if actual == Some(change.candidate) {
        DeploymentEvent::Committed(change)
    } else if actual == change.previous {
        DeploymentEvent::Unchanged(change)
    } else {
        return Err(DeploymentError::UnknownSelection);
    };
    // A known digest alone never blesses a missing, unsafe or modified bundle.
    let _bundle = selected
        .as_ref()
        .map(|d| Installation::open_with(&d.bytes, probe))
        .transpose()?;
    journal.deployment(actor, event)?;
    report("reconciled", None, store, probe, journal)
}

pub(crate) fn replace_selector(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    if from.parent() != to.parent() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    // Same-directory move only, never COPY_ALLOWED or DELAY_UNTIL_REBOOT.
    if unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "vpn_deployment_tests.rs"]
mod tests;
