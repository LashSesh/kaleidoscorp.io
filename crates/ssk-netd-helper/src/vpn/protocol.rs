use crate::protocol::{CapabilityToken, IdempotencyKey, Nonce};
use serde::{Deserialize, Serialize};

/// Explicit opt-in; legacy kill-switch connections continue to speak v1.
pub const PROTOCOL_VERSION: u16 = 3;
pub const MAX_FRAME: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verb {
    Status,
    Prepare,
    Stop,
    Recover,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub verb: Verb,
    /// Validated again at the authority boundary. Never a filesystem path.
    pub profile: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub session_token: CapabilityToken,
    pub nonce: Nonce,
    pub idempotency_key: IdempotencyKey,
    pub expected_revision: u64,
    pub command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Idle,
    Preparing,
    PreparedHeld,
    Stopping,
    Failed,
    RecoveryRequired,
    Recovering,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Preparation,
    Management,
    ExitUnconfirmed,
    Audit,
    Worker,
    Cancelled,
    Recovery,
}

/// Identity captured from an owned, suspended process handle before execution.
/// Windows creation time is a FILETIME (100 ns ticks since 1601); PID alone is
/// never sufficient. The random launch ID names exactly two private run files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub created_at: u64,
    pub launch_id: [u8; 16],
}
impl ProcessIdentity {
    pub fn valid(&self) -> bool {
        self.pid != 0 && self.created_at != 0 && self.launch_id != [0; 16]
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryEvidence {
    ProcessExited,
    PidAbsent,
    PidReused,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryFailure {
    MissingIdentity,
    ProcessAlive,
    ProcessQuery,
    Cleanup,
    Cancelled,
}

/// Historical control status, never a traffic admission permit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub revision: u64,
    pub profile: Option<String>,
    pub phase: Phase,
    pub operation: Option<IdempotencyKey>,
    pub failure: Option<Failure>,
    /// None means no child was created for this operation (or recovery unknown).
    pub exit_confirmed: Option<bool>,
    pub audit_healthy: bool,
    // Omitting absent additions preserves hashes of existing schema-1 records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_identity: Option<ProcessIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_evidence: Option<RecoveryEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_failure: Option<RecoveryFailure>,
}
impl Default for Status {
    fn default() -> Self {
        Self {
            revision: 0,
            profile: None,
            phase: Phase::Idle,
            operation: None,
            failure: None,
            exit_confirmed: None,
            audit_healthy: true,
            process_identity: None,
            recovery_evidence: None,
            recovery_failure: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reject {
    Unavailable,
    Malformed,
    Unauthorized,
    BadToken,
    ReplayedNonce,
    IdempotencyConflict,
    StaleRevision { actual: u64 },
    Busy,
    RecoveryRequired,
    EvidenceUnavailable,
    AuditUnavailable,
    SessionLimit,
    ShuttingDown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Status(Status),
    /// Intent is durable; the asynchronous OS effect is NOT yet complete.
    Accepted(Status),
    /// Original accepted intent; query Status for the current outcome.
    Duplicate(Status),
    Rejected(Reject),
}

pub fn decode(bytes: &[u8]) -> Result<Request, Reject> {
    if bytes.len() > MAX_FRAME {
        return Err(Reject::Malformed);
    }
    crate::framing::decode_strict(bytes).map_err(|_| Reject::Malformed)
}
