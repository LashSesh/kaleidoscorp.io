//! Bounded, hash-chained intent/result journal. The platform store must sync
//! append before returning and exclusively own its protected file while open.
use super::{Command, Phase, Status};
use serde::{Deserialize, Serialize};
use ssk_types::{digest_of, Digest, HashAlg};
use std::io;

/// Per-file bounds, including the original unsegmented journal.
pub const MAX_RECORDS: usize = 20_000;
pub const MAX_SEGMENTS: usize = 64;
pub const MAX_TOTAL_RECORDS: usize = MAX_RECORDS * MAX_SEGMENTS;
pub const EMERGENCY_RECORDS: usize = 8;
pub const MAX_RECORD_BYTES: usize = 4096;
pub const MAX_JOURNAL_BYTES: usize = 16 * 1024 * 1024;

pub trait Store: Send {
    fn load(&mut self) -> io::Result<Vec<Record>>;
    fn append(&mut self, record: &Record) -> io::Result<()>;
    /// Streaming replay keeps segmented stores from allocating the whole history.
    fn replay(&mut self, visit: &mut dyn FnMut(Record) -> io::Result<()>) -> io::Result<()> {
        for record in self.load()? {
            visit(record)?;
        }
        Ok(())
    }
    fn record_limit(&self) -> usize {
        MAX_RECORDS
    }
    /// Conservative capacity for worst-size records, excluding filesystem free
    /// space. I/O failures still latch the broker audit fault.
    fn has_capacity(&self, _records: usize) -> bool {
        true
    }
    fn storage_info(&self) -> Option<StorageInfo> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageInfo {
    pub segments: usize,
    pub max_segments: usize,
    pub active_records: usize,
    pub active_bytes: u64,
    pub total_bytes: u64,
    pub max_total_bytes: u64,
    pub guaranteed_record_slots: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Inspection {
    pub records: usize,
    pub head: Digest,
    pub last_status: Option<Status>,
    pub storage: Option<StorageInfo>,
    pub accepts_intent: bool,
    pub pending_deployment: Option<DeploymentChange>,
    pub pending_repair: Option<RepairChange>,
    pub configuration_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentTarget {
    #[default]
    Package,
    Configuration,
}
impl DeploymentTarget {
    fn is_package(&self) -> bool {
        *self == Self::Package
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentChange {
    #[serde(default, skip_serializing_if = "DeploymentTarget::is_package")]
    pub target: DeploymentTarget,
    pub id: [u8; 16],
    pub previous: Option<[u8; 32]>,
    pub candidate: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentEvent {
    Begin(DeploymentChange),
    Committed(DeploymentChange),
    Unchanged(DeploymentChange),
    RestoreBegin(RepairChange),
    RestoreCompleted(RepairChange),
    RestoreUnchanged(RepairChange),
}

/// Repair restores exactly the already committed configuration. The observed
/// bytes (or absence) are evidence, never a new authorized predecessor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairChange {
    pub id: [u8; 16],
    pub configuration: [u8; 32],
    pub observed: Option<[u8; 32]>,
}
fn transition(
    pending: &mut Option<DeploymentChange>,
    repair: &mut Option<RepairChange>,
    configuration_digest: &mut Option<[u8; 32]>,
    last: Option<&Status>,
    event: &Event,
) -> io::Result<()> {
    if event.kind == Kind::Deployment {
        let mut expected = last.cloned().unwrap_or_default();
        expected.revision = expected
            .revision
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        if event.command.is_some()
            || event.status != expected
            || crate::PeerIdentity::parse_sid(&event.actor).is_err()
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    match (&event.kind, &event.deployment) {
        (Kind::Deployment, Some(DeploymentEvent::Begin(change))) => {
            if pending.is_some()
                || repair.is_some()
                || change.id == [0; 16]
                || change.candidate == [0; 32]
                || change.previous == Some(change.candidate)
                || !clean_status(&event.status)
                || (change.target == DeploymentTarget::Configuration
                    && change.previous != *configuration_digest)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            *pending = Some(change.clone());
        }
        (
            Kind::Deployment,
            Some(DeploymentEvent::Committed(change) | DeploymentEvent::Unchanged(change)),
        ) => {
            if repair.is_some() || pending.as_ref() != Some(change) || !clean_status(&event.status)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            *pending = None;
            if change.target == DeploymentTarget::Configuration {
                *configuration_digest =
                    if matches!(event.deployment, Some(DeploymentEvent::Committed(_))) {
                        Some(change.candidate)
                    } else {
                        change.previous
                    };
            }
        }
        (Kind::Deployment, Some(DeploymentEvent::RestoreBegin(change))) => {
            if pending.is_some()
                || repair.is_some()
                || change.id == [0; 16]
                || change.configuration == [0; 32]
                || Some(change.configuration) != *configuration_digest
                || change.observed == Some(change.configuration)
                || !event.status.audit_healthy
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            *repair = Some(change.clone());
        }
        (
            Kind::Deployment,
            Some(
                DeploymentEvent::RestoreCompleted(change)
                | DeploymentEvent::RestoreUnchanged(change),
            ),
        ) => {
            if pending.is_some()
                || repair.as_ref() != Some(change)
                || Some(change.configuration) != *configuration_digest
                || !event.status.audit_healthy
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            // In particular: never reset process identity, recovery state or
            // the committed permission digest when repairing a missing file.
            *repair = None;
        }
        (Kind::Deployment, None) | (_, Some(_)) => return Err(io::ErrorKind::InvalidData.into()),
        (_, None) if pending.is_some() || repair.is_some() => {
            return Err(io::ErrorKind::InvalidData.into())
        }
        _ => {}
    }
    Ok(())
}
pub fn clean_status(status: &Status) -> bool {
    matches!(status.phase, Phase::Idle | Phase::Shutdown | Phase::Failed)
        && status.exit_confirmed != Some(false)
        && status.audit_healthy
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Boot,
    Intent,
    ProcessCreated,
    Result,
    Observation,
    Shutdown,
    Deployment,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub kind: Kind,
    /// OS-authenticated SID for client intent; service for internal transitions.
    pub actor: String,
    pub command: Option<Command>,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<DeploymentEvent>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema: u32,
    pub sequence: u64,
    pub previous: Digest,
    pub event: Event,
    pub hash: Digest,
}
fn hash(schema: u32, sequence: u64, previous: Digest, event: &Event) -> Digest {
    digest_of(&(schema, sequence, previous, event), HashAlg::Blake3)
        .expect("fixed VPN journal types are serializable")
}
pub struct Journal {
    store: Box<dyn Store>,
    count: usize,
    head: Digest,
    last: Option<Status>,
    pending_deployment: Option<DeploymentChange>,
    pending_repair: Option<RepairChange>,
    configuration_digest: Option<[u8; 32]>,
}
impl Journal {
    pub fn open(mut store: Box<dyn Store>) -> io::Result<Self> {
        let limit = store.record_limit().min(MAX_TOTAL_RECORDS);
        let mut head = Digest::GENESIS;
        let mut revision = 0u64;
        let mut count = 0usize;
        let mut last = None;
        let mut pending_deployment = None;
        let mut pending_repair = None;
        let mut configuration_digest = None;
        store.replay(&mut |record| {
            if count >= limit
                || !matches!(record.schema, 1 | 2)
                || record.sequence != count as u64 + 1
                || record.previous != head
                || record.hash != hash(record.schema, record.sequence, head, &record.event)
                || revision.checked_add(1) != Some(record.event.status.revision)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            transition(
                &mut pending_deployment,
                &mut pending_repair,
                &mut configuration_digest,
                last.as_ref(),
                &record.event,
            )?;
            revision = record.event.status.revision;
            head = record.hash;
            last = Some(record.event.status);
            count += 1;
            Ok(())
        })?;
        Ok(Self {
            count,
            head,
            last,
            pending_deployment,
            pending_repair,
            configuration_digest,
            store,
        })
    }
    pub fn inspection(&self) -> Inspection {
        Inspection {
            records: self.count,
            head: self.head,
            last_status: self.last.clone(),
            storage: self.store.storage_info(),
            accepts_intent: self.accepts_intent(),
            pending_deployment: self.pending_deployment.clone(),
            pending_repair: self.pending_repair.clone(),
            configuration_digest: self.configuration_digest,
        }
    }
    pub fn pending_deployment(&self) -> Option<&DeploymentChange> {
        self.pending_deployment.as_ref()
    }
    pub fn configuration_digest(&self) -> Option<[u8; 32]> {
        self.configuration_digest
    }
    pub fn pending_repair(&self) -> Option<&RepairChange> {
        self.pending_repair.as_ref()
    }
    pub fn has_pending_maintenance(&self) -> bool {
        self.pending_deployment.is_some() || self.pending_repair.is_some()
    }
    pub fn deployment(&mut self, actor: &str, deployment: DeploymentEvent) -> io::Result<()> {
        let mut status = self.last.clone().unwrap_or_default();
        status.revision = status
            .revision
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        self.append(Event {
            kind: Kind::Deployment,
            actor: actor.into(),
            command: None,
            status,
            deployment: Some(deployment),
        })
    }
    pub fn last(&self) -> Option<&Status> {
        self.last.as_ref()
    }
    /// Reserve room for result, emergency termination and shutdown observations.
    pub fn accepts_intent(&self) -> bool {
        self.count
            < self
                .store
                .record_limit()
                .min(MAX_TOTAL_RECORDS)
                .saturating_sub(EMERGENCY_RECORDS)
            && self.store.has_capacity(EMERGENCY_RECORDS + 1)
    }
    pub fn append(&mut self, event: Event) -> io::Result<()> {
        if self.count >= self.store.record_limit().min(MAX_TOTAL_RECORDS) {
            return Err(io::ErrorKind::StorageFull.into());
        }
        let mut pending = self.pending_deployment.clone();
        let mut repair = self.pending_repair.clone();
        let mut configuration_digest = self.configuration_digest;
        if self.last.as_ref().map_or(0, |s| s.revision).checked_add(1)
            != Some(event.status.revision)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        transition(
            &mut pending,
            &mut repair,
            &mut configuration_digest,
            self.last.as_ref(),
            &event,
        )?;
        let record = Record {
            // A v1-only reader must refuse the original file after the first
            // new append, rather than silently ignoring later segment files.
            schema: 2,
            sequence: self.count as u64 + 1,
            previous: self.head,
            hash: hash(2, self.count as u64 + 1, self.head, &event),
            event,
        };
        self.store.append(&record)?;
        self.pending_deployment = pending;
        self.pending_repair = repair;
        self.configuration_digest = configuration_digest;
        self.count += 1;
        self.head = record.hash;
        self.last = Some(record.event.status);
        Ok(())
    }
}
