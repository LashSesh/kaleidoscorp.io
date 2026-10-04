//! Bounded authenticated archives. Keys are separate confidential files; no
//! password arguments, machine-bound encryption, plaintext export or auto-prune.
use super::*;
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Tag, XChaCha20Poly1305, XNonce,
};

const KEY_MAGIC: &[u8; 8] = b"SSKKEY01";
const MAGIC: &[u8; 8] = b"SSKVPN01";
const KEY_BYTES: usize = 40;
const HEADER: usize = 64; // magic/version + committed SHA-256 + random 192-bit nonce
const TAG: usize = 16;
const MAX_ARCHIVE: usize = HEADER + configuration::MAX_BYTES + TAG;

#[derive(Serialize)]
pub struct BackupReport {
    pub action: &'static str,
    pub configuration_sha256: Option<String>,
    pub archive_sha256: Option<String>,
    pub archive_bytes: Option<usize>,
}

// Require an existing confidential administrative parent with protected ancestry.
// Never provision or repair an arbitrary caller-supplied directory's permissions.
fn artifact_store(path: &Path, probe: &dyn PathSecurityProbe) -> Result<ProfileStore> {
    strict_path(path)?;
    let parent = path.parent().ok_or(DeploymentError::InvalidInput)?;
    let layout = crate::state_dir::StateDirLayout::new(parent, 1)
        .map_err(|_| DeploymentError::InvalidInput)?;
    Ok(ProfileStore::open_layout(layout, probe)?)
}
fn key(path: &Path, probe: &dyn PathSecurityProbe) -> Result<SecretDocument> {
    let store = artifact_store(path, probe)?;
    let key = read(&store, path, probe, KEY_BYTES)?;
    if key.bytes.len() != KEY_BYTES || &key.bytes[..8] != KEY_MAGIC {
        return Err(DeploymentError::BackupFormat);
    }
    Ok(key)
}
fn cipher(key: &[u8]) -> Result<XChaCha20Poly1305> {
    if key.len() != KEY_BYTES || &key[..8] != KEY_MAGIC {
        return Err(DeploymentError::BackupFormat);
    }
    XChaCha20Poly1305::new_from_slice(&key[8..]).map_err(|_| DeploymentError::BackupFormat)
}
fn seal(plain: &[u8], expected: [u8; 32], key: &[u8]) -> Result<Vec<u8>> {
    if plain.len() > configuration::MAX_BYTES || sha(plain) != expected {
        return Err(DeploymentError::DigestMismatch);
    }
    configuration::parse(plain).map_err(DeploymentError::Configuration)?;
    let mut header = [0u8; HEADER];
    header[..8].copy_from_slice(MAGIC);
    header[8..40].copy_from_slice(&expected);
    getrandom::fill(&mut header[40..]).map_err(|_| DeploymentError::Io(io::ErrorKind::Other))?;
    // Detached encryption avoids reallocating a buffer while it contains secrets.
    let mut body = Zeroizing::new(plain.to_vec());
    let tag = cipher(key)?
        .encrypt_in_place_detached(XNonce::from_slice(&header[40..]), &header, &mut body)
        .map_err(|_| DeploymentError::BackupAuthentication)?;
    let mut archive = Vec::with_capacity(HEADER + body.len() + TAG);
    archive.extend_from_slice(&header);
    archive.extend_from_slice(&body);
    archive.extend_from_slice(&tag);
    Ok(archive)
}
fn open(archive: &[u8], expected: [u8; 32], key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if !(HEADER + TAG..=MAX_ARCHIVE).contains(&archive.len()) || &archive[..8] != MAGIC {
        return Err(DeploymentError::BackupFormat);
    }
    if archive[8..40] != expected {
        return Err(DeploymentError::DigestMismatch);
    }
    let tag_at = archive.len() - TAG;
    let mut plain = Zeroizing::new(archive[HEADER..tag_at].to_vec());
    cipher(key)?
        .decrypt_in_place_detached(
            XNonce::from_slice(&archive[40..HEADER]),
            &archive[..HEADER],
            &mut plain,
            Tag::from_slice(&archive[tag_at..]),
        )
        .map_err(|_| DeploymentError::BackupAuthentication)?;
    if sha(&plain) != expected {
        return Err(DeploymentError::DigestMismatch);
    }
    configuration::parse(&plain).map_err(DeploymentError::Configuration)?;
    Ok(plain)
}
fn report(action: &'static str, expected: [u8; 32], archive: &[u8]) -> BackupReport {
    BackupReport {
        action,
        configuration_sha256: Some(hex(&expected)),
        archive_sha256: Some(hex(&sha(archive))),
        archive_bytes: Some(archive.len()),
    }
}
fn committed(journal: &Journal, expected: &str) -> Result<[u8; 32]> {
    if journal.has_pending_maintenance() {
        return Err(DeploymentError::RecoveryRequired);
    }
    if journal.last().is_some_and(|s| !s.audit_healthy) {
        return Err(DeploymentError::AuditCapacity);
    }
    let expected = digest(expected)?;
    if journal.configuration_digest() != Some(expected) {
        return Err(DeploymentError::StaleSelection);
    }
    Ok(expected)
}

pub fn backup_key_create(destination: &Path) -> Result<BackupReport> {
    elevated()?;
    key_create_with(destination, &Win32PathSecurityProbe)
}
pub(super) fn key_create_with(
    destination: &Path,
    probe: &dyn PathSecurityProbe,
) -> Result<BackupReport> {
    let store = artifact_store(destination, probe)?;
    let mut bytes = Zeroizing::new([0u8; KEY_BYTES]);
    bytes[..8].copy_from_slice(KEY_MAGIC);
    getrandom::fill(&mut bytes[8..]).map_err(|_| DeploymentError::Io(io::ErrorKind::Other))?;
    create_document(&store, destination, &bytes[..], probe)?;
    let stored = key(destination, probe)?;
    if stored.bytes.as_slice() != &bytes[..] {
        return Err(DeploymentError::DigestMismatch);
    }
    Ok(BackupReport {
        action: "key-created",
        configuration_sha256: None,
        archive_sha256: None,
        archive_bytes: None,
    })
}
pub fn backup(destination: &Path, key_file: &Path, expected: &str) -> Result<BackupReport> {
    elevated()?;
    let journal = journal(false)?;
    backup_with(
        &ProfileStore::open()?,
        &Win32PathSecurityProbe,
        &journal,
        destination,
        key_file,
        expected,
    )
}
pub(super) fn backup_with(
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    journal: &Journal,
    destination: &Path,
    key_file: &Path,
    expected: &str,
) -> Result<BackupReport> {
    let expected = committed(journal, expected)?;
    let doc = active(store, probe)?.ok_or(DeploymentError::UnknownSelection)?;
    let key = key(key_file, probe)?;
    let bytes = seal(&doc.bytes, expected, &key.bytes)?;
    let target = artifact_store(destination, probe)?;
    create_document(&target, destination, &bytes, probe)?;
    let stored = read(&target, destination, probe, MAX_ARCHIVE)?;
    if stored.bytes.as_slice() != bytes {
        return Err(DeploymentError::DigestMismatch);
    }
    open(&stored.bytes, expected, &key.bytes)?;
    Ok(report("backed-up", expected, &stored.bytes))
}
pub fn backup_verify(archive: &Path, key_file: &Path, expected: &str) -> Result<BackupReport> {
    elevated()?;
    let journal = journal(false)?;
    verify_with(
        &Win32PathSecurityProbe,
        &journal,
        archive,
        key_file,
        expected,
    )
}
pub(super) fn verify_with(
    probe: &dyn PathSecurityProbe,
    journal: &Journal,
    archive: &Path,
    key_file: &Path,
    expected: &str,
) -> Result<BackupReport> {
    let expected = committed(journal, expected)?;
    let store = artifact_store(archive, probe)?;
    let key = key(key_file, probe)?;
    let doc = read(&store, archive, probe, MAX_ARCHIVE)?;
    open(&doc.bytes, expected, &key.bytes)?;
    Ok(report("verified", expected, &doc.bytes))
}
pub(super) fn load(
    probe: &dyn PathSecurityProbe,
    archive: &Path,
    key_file: &Path,
    expected: [u8; 32],
) -> Result<SecretDocument> {
    let store = artifact_store(archive, probe)?;
    let key = key(key_file, probe)?;
    let doc = read(&store, archive, probe, MAX_ARCHIVE)?;
    Ok(SecretDocument {
        bytes: open(&doc.bytes, expected, &key.bytes)?,
        _file: doc._file,
    })
}
pub fn restore_backup(
    expected_committed: &str,
    expected_observed: &str,
    archive: &Path,
    key_file: &Path,
) -> Result<RecoveryReport> {
    elevated()?;
    let mut journal = journal(false)?;
    recovery::restore_using(
        &ProfileStore::open()?,
        &Win32PathSecurityProbe,
        &mut journal,
        &actor()?,
        recovery::RestoreRequest {
            expected_committed,
            expected_observed,
            source: None,
        },
        replace_selector,
        |expected| load(&Win32PathSecurityProbe, archive, key_file, expected),
    )
}

#[cfg(test)]
#[path = "vpn_configuration_backup_codec_tests.rs"]
mod tests;
