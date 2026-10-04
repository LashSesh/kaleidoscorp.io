//! Offline, whole-snapshot profile and grant deployment. Secret bytes never
//! enter reports/journals; active policy and profiles are pinned for a service run.
use crate::{
    service::{PathSecurityProbe, Win32PathSecurityProbe},
    vpn_deployment::{
        create_document, elevated, hex, journal, ready, replace_selector, sha, DeploymentError,
    },
    vpn_installation::{digest, strict_path},
    vpn_profiles::{deny_write_delete_sharing, reparse, ProfileStore},
};
use serde::Serialize;
use ssk_netd_helper::vpn::{
    configuration::{self, ProfileSet},
    journal::{DeploymentChange, DeploymentEvent, DeploymentTarget, Journal},
    Policy,
};
use ssk_vpnctl::ProfileId;
use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    path::Path,
};
use zeroize::Zeroizing;

const ACTIVE: &str = "openvpn-configuration.json";
type Result<T> = std::result::Result<T, DeploymentError>;

#[path = "vpn_configuration_backup.rs"]
mod backup;
pub use backup::{backup, backup_key_create, backup_verify, restore_backup, BackupReport};

#[path = "vpn_configuration_recovery.rs"]
mod recovery;
pub use recovery::{
    diagnose, reconcile_restore, restore, Advice, ArtifactAssessment, ArtifactState, Diagnosis,
    RecoveryReport,
};

pub(crate) struct SecretDocument {
    _file: File,
    bytes: Zeroizing<Vec<u8>>,
}
pub(crate) struct Snapshot {
    pub policy: Policy,
    pub profiles: ProfileSet,
    pub document: Option<SecretDocument>,
}

#[derive(Serialize)]
pub struct Report {
    pub action: &'static str,
    pub configuration_sha256: Option<String>,
    pub profile_ids: Vec<String>,
    pub principal_sids: Vec<String>,
    pub pending_deployment: Option<DeploymentChange>,
    pub pending_repair: Option<ssk_netd_helper::vpn::journal::RepairChange>,
}

fn read(
    store: &ProfileStore,
    path: &Path,
    probe: &dyn PathSecurityProbe,
    max: usize,
) -> Result<SecretDocument> {
    store.verify(probe)?;
    let mut options = OpenOptions::new();
    options.read(true);
    deny_write_delete_sharing(&mut options);
    let mut file = options.open(path)?;
    store.check_file(&file, path, probe)?;
    if file.metadata()?.len() > max as u64 {
        return Err(DeploymentError::InvalidInput);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(max + 1));
    (&mut file).take(max as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(DeploymentError::InvalidInput);
    }
    Ok(SecretDocument { _file: file, bytes })
}
fn active(store: &ProfileStore, probe: &dyn PathSecurityProbe) -> Result<Option<SecretDocument>> {
    match read(
        store,
        &store.directory().join(ACTIVE),
        probe,
        configuration::MAX_BYTES,
    ) {
        Ok(doc) => Ok(Some(doc)),
        Err(DeploymentError::Io(io::ErrorKind::NotFound)) => Ok(None),
        Err(e) => Err(e),
    }
}
fn parse(doc: &SecretDocument) -> Result<(Policy, ProfileSet)> {
    configuration::parse(&doc.bytes).map_err(DeploymentError::Configuration)
}
fn summarize(
    action: &'static str,
    doc: Option<&SecretDocument>,
    journal: &Journal,
) -> Result<Report> {
    let (profile_ids, principal_sids) = match doc {
        Some(doc) => {
            let (policy, profiles) = parse(doc)?;
            (profiles.ids(), policy.client_sids().into_iter().collect())
        }
        None => (vec![], vec![]),
    };
    Ok(Report {
        action,
        configuration_sha256: doc.map(|d| hex(&sha(&d.bytes))),
        profile_ids,
        principal_sids,
        pending_deployment: journal.pending_deployment().cloned(),
        pending_repair: journal.pending_repair().cloned(),
    })
}
fn actor() -> Result<String> {
    crate::current_user_sid().map_err(|_| DeploymentError::ElevationRequired)
}
pub fn stage(source: &Path, approved_sha256: &str) -> Result<Report> {
    elevated()?;
    let journal = journal(false)?;
    stage_with(
        &ProfileStore::open()?,
        &Win32PathSecurityProbe,
        &journal,
        source,
        approved_sha256,
    )
}
pub fn inspect() -> Result<Report> {
    elevated()?;
    let journal = journal(false)?;
    inspect_with(&ProfileStore::open()?, &Win32PathSecurityProbe, &journal)
}
pub fn activate(configuration_id: &str, expected_active: &str) -> Result<Report> {
    elevated()?;
    let mut journal = journal(false)?;
    activate_with(
        &ProfileStore::open()?,
        &Win32PathSecurityProbe,
        &mut journal,
        &actor()?,
        configuration_id,
        expected_active,
        replace_selector,
    )
}
pub fn reconcile() -> Result<Report> {
    elevated()?;
    let mut journal = journal(false)?;
    reconcile_with(
        &ProfileStore::open()?,
        &Win32PathSecurityProbe,
        &mut journal,
        &actor()?,
    )
}

fn stage_with(
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    journal: &Journal,
    source: &Path,
    approved_sha256: &str,
) -> Result<Report> {
    ready(journal)?;
    let expected = digest(approved_sha256)?;
    strict_path(source)?;
    for path in source.ancestors() {
        if reparse(path)? {
            return Err(DeploymentError::InvalidInput);
        }
    }
    // Unlike executable sources, configuration input is secret: require a
    // confidential administrative owner/DACL before reading any bytes.
    let source = read(store, source, probe, configuration::MAX_BYTES)?;
    if sha(&source.bytes) != expected {
        return Err(DeploymentError::DigestMismatch);
    }
    parse(&source)?;
    let path = store
        .directory()
        .join(format!("configuration-{approved_sha256}.json"));
    create_document(store, &path, &source.bytes, probe)?;
    let stored = read(store, &path, probe, configuration::MAX_BYTES)?;
    if sha(&stored.bytes) != expected {
        return Err(DeploymentError::DigestMismatch);
    }
    summarize("staged", Some(&stored), journal)
}

fn inspect_with(
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    journal: &Journal,
) -> Result<Report> {
    let doc = active(store, probe)?;
    let actual = doc.as_ref().map(|d| sha(&d.bytes));
    let known = if let Some(change) = journal
        .pending_deployment()
        .filter(|c| c.target == DeploymentTarget::Configuration)
    {
        actual == change.previous || actual == Some(change.candidate)
    } else {
        actual == journal.configuration_digest()
    };
    if !known {
        return Err(DeploymentError::UnknownSelection);
    }
    summarize("inspected", doc.as_ref(), journal)
}

fn preserve(
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    doc: &SecretDocument,
) -> Result<()> {
    let path = store
        .directory()
        .join(format!("configuration-{}.json", hex(&sha(&doc.bytes))));
    match create_document(store, &path, &doc.bytes, probe) {
        Ok(()) => Ok(()),
        Err(DeploymentError::Io(io::ErrorKind::AlreadyExists)) => {
            let saved = read(store, &path, probe, configuration::MAX_BYTES)?;
            if saved.bytes == doc.bytes {
                Ok(())
            } else {
                Err(DeploymentError::DigestMismatch)
            }
        }
        Err(e) => Err(e),
    }
}
fn activate_with(
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    journal: &mut Journal,
    actor: &str,
    configuration_id: &str,
    expected_active: &str,
    replace: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> Result<Report> {
    ready(journal)?;
    let candidate_digest = digest(configuration_id)?;
    let expected = if expected_active == "none" {
        None
    } else {
        Some(digest(expected_active)?)
    };
    let candidate = read(
        store,
        &store
            .directory()
            .join(format!("configuration-{configuration_id}.json")),
        probe,
        configuration::MAX_BYTES,
    )?;
    if sha(&candidate.bytes) != candidate_digest {
        return Err(DeploymentError::DigestMismatch);
    }
    parse(&candidate)?;
    let previous = active(store, probe)?;
    let actual = previous.as_ref().map(|d| sha(&d.bytes));
    if actual != journal.configuration_digest() {
        return Err(DeploymentError::UnknownSelection);
    }
    if actual != expected {
        return Err(DeploymentError::StaleSelection);
    }
    if let Some(doc) = &previous {
        parse(doc)?;
    }
    if actual == Some(candidate_digest) {
        return summarize("already-selected", previous.as_ref(), journal);
    }
    if !journal.accepts_intent() {
        return Err(DeploymentError::AuditCapacity);
    }
    if let Some(doc) = &previous {
        preserve(store, probe, doc)?;
    }
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| DeploymentError::Io(io::ErrorKind::Other))?;
    if id == [0; 16] {
        return Err(DeploymentError::InvalidInput);
    }
    let change = DeploymentChange {
        target: DeploymentTarget::Configuration,
        id,
        previous: expected,
        candidate: candidate_digest,
    };
    let temporary = store
        .directory()
        .join(format!("configuration-change-{}.pending.json", hex(&id)));
    create_document(store, &temporary, &candidate.bytes, probe)?;
    journal.deployment(actor, DeploymentEvent::Begin(change.clone()))?;
    drop(previous);
    store.verify(probe)?;
    replace(&temporary, &store.directory().join(ACTIVE))?;
    let selected = active(store, probe)?.ok_or(DeploymentError::UnknownSelection)?;
    if sha(&selected.bytes) != candidate_digest {
        return Err(DeploymentError::UnknownSelection);
    }
    parse(&selected)?;
    journal.deployment(actor, DeploymentEvent::Committed(change))?;
    summarize("selected", Some(&selected), journal)
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
    if change.target != DeploymentTarget::Configuration {
        return Err(DeploymentError::InvalidInput);
    }
    let selected = active(store, probe)?;
    let actual = selected.as_ref().map(|d| sha(&d.bytes));
    let event = if actual == Some(change.candidate) {
        DeploymentEvent::Committed(change)
    } else if actual == change.previous {
        DeploymentEvent::Unchanged(change)
    } else {
        return Err(DeploymentError::UnknownSelection);
    };
    if let Some(doc) = &selected {
        parse(doc)?;
    }
    journal.deployment(actor, event)?;
    summarize("reconciled", selected.as_ref(), journal)
}

/// Called only after acquiring the lifetime journal lock, before constructing
/// the pipe's allowed-SID set or the worker. No fallback after a managed commit.
pub(crate) fn load_for_service(
    store: &ProfileStore,
    journal: &Journal,
    probe: &dyn PathSecurityProbe,
) -> Result<Snapshot> {
    if journal.has_pending_maintenance() {
        return Err(DeploymentError::RecoveryRequired);
    }
    if let Some(doc) = active(store, probe)? {
        if journal.configuration_digest() != Some(sha(&doc.bytes)) {
            return Err(DeploymentError::UnknownSelection);
        }
        let (policy, profiles) = parse(&doc)?;
        return Ok(Snapshot {
            policy,
            profiles,
            document: Some(doc),
        });
    }
    if journal.configuration_digest().is_some() {
        return Err(DeploymentError::UnknownSelection);
    }
    // Compatibility only before the first managed configuration commit. Load all
    // referenced profiles into one in-memory snapshot under the journal lock.
    let policy_doc = read(
        store,
        &store.directory().join("openvpn-control.json"),
        probe,
        Policy::MAX_BYTES,
    )?;
    let policy = Policy::parse(&policy_doc.bytes).map_err(DeploymentError::Configuration)?;
    let ids = policy.profile_ids();
    if ids.len() > configuration::MAX_PROFILES {
        return Err(DeploymentError::Configuration("too many VPN profiles"));
    }
    let mut profiles = Vec::new();
    for id in ids {
        let id = ProfileId::new(&id).map_err(|_| DeploymentError::InvalidInput)?;
        match store.load_with(&id, probe) {
            Ok(profile) => profiles.push(profile),
            Err(reason) => {
                // Preserve the old recovery/status path even when a legacy
                // profile is missing or damaged. Preparation for it refuses;
                // no file is reopened later under the old policy snapshot.
                tracing::warn!(target: "ssk.vpn", profile = id.as_str(), reason = ?reason, "Legacy VPN profile unavailable for preparation");
            }
        }
    }
    store.verify(probe)?;
    let profiles = ProfileSet::from_profiles(profiles).map_err(DeploymentError::Configuration)?;
    Ok(Snapshot {
        policy,
        profiles,
        document: Some(policy_doc),
    })
}

#[cfg(test)]
#[path = "vpn_configuration_tests.rs"]
mod tests;
