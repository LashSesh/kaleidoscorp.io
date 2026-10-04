//! Exact committed-state repair, never rollback or journal reset. All preserved
//! evidence and temporary configuration bytes remain confidential artifacts.
use super::*;
use ssk_netd_helper::vpn::journal::{clean_status, Inspection, RepairChange};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactState {
    Missing,
    Valid,
    InvalidDocument,
    Unsafe,
    TooLarge,
    Unreadable,
}
#[derive(Debug, Serialize)]
pub struct ArtifactAssessment {
    pub state: ArtifactState,
    pub sha256: Option<String>,
    pub matches_committed: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Advice {
    ConfigurationIntact,
    NoManagedConfiguration,
    ReconcileDeployment,
    ReconcileRestore,
    AuditBlocked,
    PreserveForInvestigation,
    RestoreRetained,
    ObtainVerifiedCopy,
}
#[derive(Serialize)]
pub struct Diagnosis {
    pub expected_configuration_sha256: Option<String>,
    pub active: ArtifactAssessment,
    pub retained: Option<ArtifactAssessment>,
    pub process_recovery_required: bool,
    pub next_step: Advice,
    pub journal: Inspection,
}
#[derive(Serialize)]
pub struct RecoveryReport {
    pub outcome: &'static str,
    pub operation_id: Option<String>,
    pub diagnosis: Diagnosis,
}

pub fn diagnose() -> Result<RecoveryReport> {
    elevated()?;
    let journal = journal(false)?;
    Ok(report(
        "diagnosed",
        None,
        &ProfileStore::open()?,
        &Win32PathSecurityProbe,
        &journal,
    ))
}
pub fn restore(
    expected_committed: &str,
    expected_observed: &str,
    source: Option<&Path>,
) -> Result<RecoveryReport> {
    elevated()?;
    let mut journal = journal(false)?;
    restore_with(
        &ProfileStore::open()?,
        &Win32PathSecurityProbe,
        &mut journal,
        &actor()?,
        RestoreRequest {
            expected_committed,
            expected_observed,
            source,
        },
        replace_selector,
    )
}
pub fn reconcile_restore() -> Result<RecoveryReport> {
    elevated()?;
    let mut journal = journal(false)?;
    reconcile_with(
        &ProfileStore::open()?,
        &Win32PathSecurityProbe,
        &mut journal,
        &actor()?,
    )
}

fn assess(
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    path: &Path,
    expected: Option<[u8; 32]>,
) -> ArtifactAssessment {
    match read(store, path, probe, configuration::MAX_BYTES) {
        Ok(doc) => {
            let hash = sha(&doc.bytes);
            ArtifactAssessment {
                state: if parse(&doc).is_ok() {
                    ArtifactState::Valid
                } else {
                    ArtifactState::InvalidDocument
                },
                sha256: Some(hex(&hash)),
                matches_committed: expected == Some(hash),
            }
        }
        Err(e) => {
            use crate::vpn_profiles::ProfileStoreError;
            let state = match e {
                DeploymentError::Io(io::ErrorKind::NotFound) => ArtifactState::Missing,
                DeploymentError::InvalidInput => ArtifactState::TooLarge,
                DeploymentError::Store(
                    ProfileStoreError::UnsafeDirectory | ProfileStoreError::UnsafeFile,
                ) => ArtifactState::Unsafe,
                _ => ArtifactState::Unreadable,
            };
            ArtifactAssessment {
                state,
                sha256: None,
                matches_committed: false,
            }
        }
    }
}
pub(super) fn diagnose_with(
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    journal: &Journal,
) -> Diagnosis {
    let expected = journal.configuration_digest();
    let active = assess(store, probe, &store.directory().join(ACTIVE), expected);
    let retained = expected.map(|hash| {
        assess(
            store,
            probe,
            &store
                .directory()
                .join(format!("configuration-{}.json", hex(&hash))),
            expected,
        )
    });
    let next_step = if journal.pending_repair().is_some() {
        Advice::ReconcileRestore
    } else if journal.pending_deployment().is_some() {
        Advice::ReconcileDeployment
    } else if expected.is_none() {
        Advice::NoManagedConfiguration
    } else if active.state == ArtifactState::Valid && active.matches_committed {
        Advice::ConfigurationIntact
    } else if journal.last().is_some_and(|s| !s.audit_healthy) || !journal.accepts_intent() {
        Advice::AuditBlocked
    } else if !matches!(
        active.state,
        ArtifactState::Missing | ArtifactState::Valid | ArtifactState::InvalidDocument
    ) {
        Advice::PreserveForInvestigation
    } else if retained
        .as_ref()
        .is_some_and(|a| a.state == ArtifactState::Valid && a.matches_committed)
    {
        Advice::RestoreRetained
    } else {
        Advice::ObtainVerifiedCopy
    };
    Diagnosis {
        expected_configuration_sha256: expected.map(|d| hex(&d)),
        active,
        retained,
        process_recovery_required: journal.last().is_some_and(|s| !clean_status(s)),
        next_step,
        journal: journal.inspection(),
    }
}
fn report(
    outcome: &'static str,
    id: Option<[u8; 16]>,
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    journal: &Journal,
) -> RecoveryReport {
    RecoveryReport {
        outcome,
        operation_id: id.map(|id| hex(&id)),
        diagnosis: diagnose_with(store, probe, journal),
    }
}

pub(super) struct RestoreRequest<'a> {
    pub expected_committed: &'a str,
    pub expected_observed: &'a str,
    pub source: Option<&'a Path>,
}
fn evidence_path(store: &ProfileStore, id: &[u8; 16]) -> std::path::PathBuf {
    store
        .directory()
        .join(format!("configuration-evidence-{}.json", hex(id)))
}
fn evidence(
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    change: &RepairChange,
) -> Result<Option<SecretDocument>> {
    if let Some(expected) = change.observed {
        let doc = read(
            store,
            &evidence_path(store, &change.id),
            probe,
            configuration::MAX_BYTES,
        )?;
        if sha(&doc.bytes) != expected {
            return Err(DeploymentError::DigestMismatch);
        }
        return Ok(Some(doc));
    }
    Ok(None)
}
pub(super) fn restore_with(
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    journal: &mut Journal,
    actor: &str,
    request: RestoreRequest<'_>,
    replace: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> Result<RecoveryReport> {
    let source = request.source;
    restore_using(
        store,
        probe,
        journal,
        actor,
        request,
        replace,
        |committed| {
            let retained = store
                .directory()
                .join(format!("configuration-{}.json", hex(&committed)));
            let source = source.unwrap_or(&retained);
            strict_path(source)?;
            for path in source.ancestors() {
                if reparse(path)? {
                    return Err(DeploymentError::InvalidInput);
                }
            }
            read(store, source, probe, configuration::MAX_BYTES)
        },
    )
}

// Both plaintext and encrypted inputs pass the same expectation, evidence,
// durable-intent and replacement gates. No decrypted import file is needed.
pub(super) fn restore_using(
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    journal: &mut Journal,
    actor: &str,
    request: RestoreRequest<'_>,
    replace: impl FnOnce(&Path, &Path) -> io::Result<()>,
    load: impl FnOnce([u8; 32]) -> Result<SecretDocument>,
) -> Result<RecoveryReport> {
    if journal.has_pending_maintenance() {
        return Err(DeploymentError::RecoveryRequired);
    }
    if journal.last().is_some_and(|s| !s.audit_healthy) {
        return Err(DeploymentError::AuditCapacity);
    }
    let committed = digest(request.expected_committed)?;
    if journal.configuration_digest() != Some(committed) {
        return Err(DeploymentError::StaleSelection);
    }
    let expected_observed = if request.expected_observed == "missing" {
        None
    } else {
        Some(digest(request.expected_observed)?)
    };
    // Unsafe, unreadable, linked and oversized active files are never silently
    // removed or re-ACL'd. Only securely readable bytes or absence can be repaired.
    let previous = active(store, probe)?;
    let observed = previous.as_ref().map(|d| sha(&d.bytes));
    if observed != expected_observed {
        return Err(DeploymentError::StaleSelection);
    }
    if observed == Some(committed) {
        parse(previous.as_ref().unwrap())?;
        return Ok(report("already-intact", None, store, probe, journal));
    }
    if !journal.accepts_intent() {
        return Err(DeploymentError::AuditCapacity);
    }
    let candidate = load(committed)?;
    if sha(&candidate.bytes) != committed {
        return Err(DeploymentError::DigestMismatch);
    }
    parse(&candidate)?;
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| DeploymentError::Io(io::ErrorKind::Other))?;
    if id == [0; 16] {
        return Err(DeploymentError::InvalidInput);
    }
    let change = RepairChange {
        id,
        configuration: committed,
        observed,
    };
    if let Some(doc) = &previous {
        create_document(store, &evidence_path(store, &id), &doc.bytes, probe)?;
    }
    // Preserve and verify damaged bytes before recording intent and replacement.
    let _evidence = evidence(store, probe, &change)?;
    let temporary = store
        .directory()
        .join(format!("configuration-restore-{}.pending.json", hex(&id)));
    create_document(store, &temporary, &candidate.bytes, probe)?;
    journal.deployment(actor, DeploymentEvent::RestoreBegin(change.clone()))?;
    drop(previous);
    store.verify(probe)?;
    replace(&temporary, &store.directory().join(ACTIVE))?;
    let selected = active(store, probe)?.ok_or(DeploymentError::UnknownSelection)?;
    if sha(&selected.bytes) != committed {
        return Err(DeploymentError::UnknownSelection);
    }
    parse(&selected)?;
    journal.deployment(actor, DeploymentEvent::RestoreCompleted(change))?;
    Ok(report("restored", Some(id), store, probe, journal))
}
pub(super) fn reconcile_with(
    store: &ProfileStore,
    probe: &dyn PathSecurityProbe,
    journal: &mut Journal,
    actor: &str,
) -> Result<RecoveryReport> {
    let change = journal
        .pending_repair()
        .cloned()
        .ok_or(DeploymentError::InvalidInput)?;
    let _evidence = evidence(store, probe, &change)?;
    let selected = active(store, probe)?;
    let actual = selected.as_ref().map(|d| sha(&d.bytes));
    let (outcome, event) = if actual == Some(change.configuration) {
        parse(selected.as_ref().unwrap())?;
        (
            "restored",
            DeploymentEvent::RestoreCompleted(change.clone()),
        )
    } else if actual == change.observed {
        (
            "unchanged",
            DeploymentEvent::RestoreUnchanged(change.clone()),
        )
    } else {
        return Err(DeploymentError::UnknownSelection);
    };
    journal.deployment(actor, event)?;
    Ok(report(outcome, Some(change.id), store, probe, journal))
}
