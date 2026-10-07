//! Vocabulary, state types, seams and leaf types of the local ingress
//! (design 6.1, 6.3, 6.9.5, 10.2, 10.7).
//!
//! Everything here is a leaf: `audit`, `limits`, `engine`, `shared` and `host`
//! import from this file and never from each other, so a type that two of them
//! need lives here. Nothing in this file does I/O.

use std::net::SocketAddrV4;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use ssk_config::ingress::{DirectAddressFamilies, IngressHardening, IngressProtocol};
use ssk_netcore::BoxFuture;

pub use ssk_config::fingerprint::{ConfigFingerprint, RuleRow, RuleTable};
pub use ssk_config::ingress::{DestinationLogging, IngressAuditConfig, IngressLimits};

// ---------------------------------------------------------------------------
// 10.7 / 6.1.1: what may be claimed, and the words that may never appear
// ---------------------------------------------------------------------------

/// The one sentence that says what the proxy covers. It is what `status`,
/// `ssk ingress status` and the GUI show next to every state, so it is a
/// constant: nobody can reword it into a stronger claim at a call site.
pub const INGRESS_COVERAGE_NOTICE: &str = "Covers only applications that are configured to use this proxy. Everything else is not covered. Names an application resolves itself are not covered. Names this proxy resolves for direct routes are resolved by the operating system.";

/// The part of the notice that every armed headline repeats (10.2).
pub const COVERAGE_SENTENCE: &str = "Everything else is not covered.";

/// Case-insensitive substrings that no string the ingress PRODUCES may contain:
/// notice, state and coverage words, warning texts, headlines, retry hints,
/// errors, and the GUI's own sentences. Each entry is lower case because the
/// scan lower-cases the text. OS-supplied data and user-chosen ids are exempt
/// (10.7); they are rendered in fields that say what they are.
pub const FORBIDDEN_WORDS: &[&str] = &[
    "protected",
    "protection",
    "secure",
    "system-wide",
    "system wide",
    "all traffic",
    "vpn",
    "geschützt",
    "geschuetzt",
    "schutz",
    "sicher",
    "systemweit",
    "systemübergreifend",
    "gesamter datenverkehr",
    "gesamten datenverkehr",
    "aller datenverkehr",
    "alle verbindungen",
    "tunnel",
    "anonym",
    "verschlüsselt",
];

/// The first forbidden word `text` contains, if any (case-insensitive).
#[must_use]
pub fn contains_forbidden_word(text: &str) -> Option<&'static str> {
    let lowered = text.to_lowercase();
    FORBIDDEN_WORDS
        .iter()
        .find(|word| lowered.contains(**word))
        .copied()
}

// ---------------------------------------------------------------------------
// 6.1.1 / 6.1.2: state, coverage, gate
// ---------------------------------------------------------------------------

/// The closed set of state words a client may see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IngressState {
    Disabled,
    Starting,
    Unavailable,
    Disarmed,
    Armed,
    Tripped,
    Stopping,
}

impl IngressState {
    pub const ALL: [Self; 7] = [
        Self::Disabled,
        Self::Starting,
        Self::Unavailable,
        Self::Disarmed,
        Self::Armed,
        Self::Tripped,
        Self::Stopping,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Starting => "starting",
            Self::Unavailable => "unavailable",
            Self::Disarmed => "disarmed",
            Self::Armed => "armed",
            Self::Tripped => "tripped",
            Self::Stopping => "stopping",
        }
    }
}

/// What the ingress covers. There is deliberately no "all": the strongest
/// claim is "applications that use this proxy" (10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Coverage {
    None,
    ProxyClientsOnly,
}

impl Coverage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ProxyClientsOnly => "proxy_clients_only",
        }
    }
}

/// Why the gate is `Tripped`. Closed: a trip is an event with a cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TripReason {
    AuditWriteFailed,
    AuditStalled,
    FlowPanicBudget,
    ControlPanic,
    AcceptFatal,
    ListenerDied,
}

impl TripReason {
    pub const ALL: [Self; 6] = [
        Self::AuditWriteFailed,
        Self::AuditStalled,
        Self::FlowPanicBudget,
        Self::ControlPanic,
        Self::AcceptFatal,
        Self::ListenerDied,
    ];

    /// The word the `Tripped` record and `last_transition.reason_code` carry.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuditWriteFailed => "audit_write_failed",
            Self::AuditStalled => "audit_stalled",
            Self::FlowPanicBudget => "flow_panic_budget",
            Self::ControlPanic => "control_panic",
            Self::AcceptFatal => "accept_fatal",
            Self::ListenerDied => "listener_died",
        }
    }
}

/// Why a start (or a recover) left the ingress unavailable. The first three
/// are properties of the process or the configuration and need a restart; the
/// rest can be retried by arming again, the audit ones once the operator fixed
/// or moved the store aside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnavailableCode {
    ConfigInvalid,
    HardeningUnavailable,
    FdLimitTooLow,
    AuditCorrupt,
    AuditUnsupportedFormat,
    AuditRootUnsafe,
    AuditDirUnsafe,
    AuditFileUnsafe,
    AuditKeyUnavailable,
    AuditFailed,
    BindFailed,
    RecoveryFailed,
}

impl UnavailableCode {
    pub const ALL: [Self; 12] = [
        Self::ConfigInvalid,
        Self::HardeningUnavailable,
        Self::FdLimitTooLow,
        Self::AuditCorrupt,
        Self::AuditUnsupportedFormat,
        Self::AuditRootUnsafe,
        Self::AuditDirUnsafe,
        Self::AuditFileUnsafe,
        Self::AuditKeyUnavailable,
        Self::AuditFailed,
        Self::BindFailed,
        Self::RecoveryFailed,
    ];

    /// The machine code (11.14); also the code an error answer carries.
    #[must_use]
    pub const fn as_code(self) -> &'static str {
        match self {
            Self::ConfigInvalid => "CONFIG_INVALID",
            Self::HardeningUnavailable => "INGRESS_HARDENING_UNAVAILABLE",
            Self::FdLimitTooLow => "INGRESS_FD_LIMIT_TOO_LOW",
            Self::AuditCorrupt => "INGRESS_AUDIT_CORRUPT",
            Self::AuditUnsupportedFormat => "INGRESS_AUDIT_UNSUPPORTED_FORMAT",
            Self::AuditRootUnsafe => "INGRESS_AUDIT_ROOT_UNSAFE",
            Self::AuditDirUnsafe => "INGRESS_AUDIT_DIR_UNSAFE",
            Self::AuditFileUnsafe => "INGRESS_AUDIT_FILE_UNSAFE",
            Self::AuditKeyUnavailable => "INGRESS_AUDIT_KEY_UNAVAILABLE",
            Self::AuditFailed => "INGRESS_AUDIT_FAILED",
            Self::BindFailed => "INGRESS_BIND_FAILED",
            Self::RecoveryFailed => "INGRESS_RECOVERY_FAILED",
        }
    }

    /// `false` for a property of the process: only a restart changes it.
    #[must_use]
    pub const fn recoverable(self) -> bool {
        !matches!(
            self,
            Self::ConfigInvalid | Self::HardeningUnavailable | Self::FdLimitTooLow
        )
    }

    /// What the gate becomes when a trip happens while it is still `Starting`:
    /// a failed ledger stays a ledger failure, every other cause is a failed
    /// recovery of the start.
    #[must_use]
    pub const fn from_trip(reason: TripReason) -> Self {
        match reason {
            TripReason::AuditWriteFailed | TripReason::AuditStalled => Self::AuditFailed,
            TripReason::FlowPanicBudget
            | TripReason::ControlPanic
            | TripReason::AcceptFatal
            | TripReason::ListenerDied => Self::RecoveryFailed,
        }
    }

    /// The next step for a code that arming again cannot fix.
    const fn restart_step(self) -> &'static str {
        match self {
            Self::ConfigInvalid => "fix the configuration, then restart sskd",
            Self::HardeningUnavailable => {
                "a required control is not available here; provide it or set hardening to best_effort, then restart sskd"
            }
            Self::FdLimitTooLow => {
                "raise the descriptor limit or lower limits.max_connections, then restart sskd"
            }
            // Recoverable codes never reach this arm (`retry_hint` checks).
            _ => "arm again to retry",
        }
    }
}

/// The gate's mode (6.1.2). `Closing` is terminal: no write may change it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateMode {
    Disabled,
    Starting,
    Unavailable(UnavailableCode),
    Disarmed,
    Armed { profile: Arc<str> },
    Tripped(TripReason),
    Closing,
}

impl GateMode {
    #[must_use]
    pub const fn state(&self) -> IngressState {
        match self {
            Self::Disabled => IngressState::Disabled,
            Self::Starting => IngressState::Starting,
            Self::Unavailable(_) => IngressState::Unavailable,
            Self::Disarmed => IngressState::Disarmed,
            Self::Armed { .. } => IngressState::Armed,
            Self::Tripped(_) => IngressState::Tripped,
            Self::Closing => IngressState::Stopping,
        }
    }

    /// What this mode covers WHEN the accept task and the ledger writer are
    /// alive. `Armed` is the only mode that covers anything; the status
    /// snapshot demotes it to `tripped` with coverage `none` the moment either
    /// is gone (10.1), so a caller must not report this value without that
    /// liveness check.
    #[must_use]
    pub const fn coverage_if_healthy(&self) -> Coverage {
        match self {
            Self::Armed { .. } => Coverage::ProxyClientsOnly,
            _ => Coverage::None,
        }
    }

    #[must_use]
    pub fn armed_profile(&self) -> Option<&str> {
        match self {
            Self::Armed { profile } => Some(profile),
            _ => None,
        }
    }

    /// The `retry_hint` of the table in 6.1.2.
    #[must_use]
    pub const fn retry_hint(&self) -> Option<&'static str> {
        match self {
            Self::Starting => Some("starting; read status again"),
            Self::Unavailable(code) if code.recoverable() => Some("arm again to retry"),
            Self::Unavailable(code) => Some(code.restart_step()),
            Self::Tripped(_) => Some("re-arm to recover"),
            Self::Disabled | Self::Disarmed | Self::Armed { .. } | Self::Closing => None,
        }
    }
}

/// One published gate value. Every transition bumps `epoch`; a flow records the
/// `(epoch, profile)` it was admitted under and is cancelled by any change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gate {
    pub epoch: u64,
    pub mode: GateMode,
}

/// Why a disarm happened. The last two are written only by the compensation of
/// an arm whose durable `Armed` record could not be followed by the gate write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisarmCause {
    Operator,
    Deactivate,
    Shutdown,
    ArmSuperseded,
    ArmNotApplied,
    ArmAbandoned,
}

impl DisarmCause {
    pub const ALL: [Self; 6] = [
        Self::Operator,
        Self::Deactivate,
        Self::Shutdown,
        Self::ArmSuperseded,
        Self::ArmNotApplied,
        Self::ArmAbandoned,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Deactivate => "deactivate",
            Self::Shutdown => "shutdown",
            Self::ArmSuperseded => "arm_superseded",
            Self::ArmNotApplied => "arm_not_applied",
            Self::ArmAbandoned => "arm_abandoned",
        }
    }
}

/// The caller's self-declared label (11.4). Never verified; the `Armed` record
/// says "this principal asked, and claimed to be this client".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientLabel {
    Cli,
    Desktop,
    Unknown,
}

impl ClientLabel {
    /// `"cli"` and `"desktop"` are mapped, everything else is `Unknown`. The
    /// raw text is dropped here and never stored or logged above DEBUG.
    #[must_use]
    pub fn from_declared(label: Option<&str>) -> Self {
        match label {
            Some("cli") => Self::Cli,
            Some("desktop") => Self::Desktop,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Desktop => "desktop",
            Self::Unknown => "unknown",
        }
    }
}

/// Who arms. `peer` is `uid:<n>` or `sid:<sid>` as formatted by the IPC layer
/// from its verified `PeerIdentity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Actor {
    Operator {
        peer: Option<Arc<str>>,
        client: ClientLabel,
    },
    ConfigAutostart,
}

impl Actor {
    /// `Armed.cause`.
    #[must_use]
    pub const fn cause(&self) -> &'static str {
        match self {
            Self::Operator { .. } => "operator",
            Self::ConfigAutostart => "config_autostart",
        }
    }

    /// `Armed.client`.
    #[must_use]
    pub const fn client(&self) -> &'static str {
        match self {
            Self::Operator { client, .. } => client.as_str(),
            Self::ConfigAutostart => "config",
        }
    }

    /// `Armed.requested_by`.
    #[must_use]
    pub fn requested_by(&self) -> &str {
        match self {
            Self::Operator { peer, .. } => peer.as_deref().unwrap_or("unknown"),
            Self::ConfigAutostart => "config",
        }
    }
}

// ---------------------------------------------------------------------------
// 10.2: the headline is a pure function of what the daemon sends
// ---------------------------------------------------------------------------

/// What the platform could really establish about the listener (6.6). A control
/// that is `false` is not "unknown": it is absent, and `hardening: required`
/// refuses to serve without the ones it needs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Controls {
    pub exclusive_bind: bool,
    pub peer_check: bool,
    pub private_audit_store: bool,
}

/// The sentence a client shows for a status (10.2). Pure, so the CLI, the doctor
/// and the GUI cannot disagree; the GUI renders its own German sentences from
/// the same inputs.
///
/// "active" appears only in the armed headline, because that is the only state
/// in which the listener evaluates connections under a profile. The disarmed
/// headline says "activated" and never "active", and the notes about a missing
/// peer check avoid the word as well; `headline_claims_activity_only_when_armed`
/// pins both.
///
/// An `Armed` state without a profile is an inconsistent input; it is rendered
/// as "not covered" rather than as activity.
#[must_use]
pub fn headline(
    state: IngressState,
    controls: Controls,
    armed_profile: Option<&str>,
    code: Option<&str>,
) -> String {
    let peer_note = !controls.peer_check;
    match state {
        IngressState::Disabled => "Local proxy: off".to_owned(),
        IngressState::Starting => "Local proxy starting".to_owned(),
        IngressState::Stopping => "Local proxy stopping".to_owned(),
        IngressState::Unavailable => match code {
            Some(c) if c == UnavailableCode::ConfigInvalid.as_code() => {
                "Local proxy unavailable: configuration invalid".to_owned()
            }
            Some(c) => format!("Proxy unavailable: {c}"),
            None => "Proxy unavailable".to_owned(),
        },
        IngressState::Disarmed => {
            let mut text = String::from("Proxy ready, not activated: connections are refused.");
            if peer_note {
                text.push_str(
                    " If activated, other local accounts could use it: there is no peer check.",
                );
            }
            text
        }
        IngressState::Armed => match armed_profile {
            Some(profile) => {
                let mut text = format!(
                    "Proxy active for applications that use it (profile {profile}). {COVERAGE_SENTENCE}"
                );
                if peer_note {
                    text.push_str(" Other local accounts may also use it: there is no peer check.");
                }
                text
            }
            None => "Local proxy: state unknown, treat as not covered".to_owned(),
        },
        IngressState::Tripped => match code {
            Some(c) => format!("Proxy stopped: {c}. Re-arm to recover."),
            None => "Proxy stopped. Re-arm to recover.".to_owned(),
        },
    }
}

// ---------------------------------------------------------------------------
// 6.1.4: Tuning
// ---------------------------------------------------------------------------

/// Internal numbers. NOT configuration: tests shrink them through
/// `IngressDeps.tuning`, and changing a default is a design change that
/// `tuning_defaults_match_the_design_table` makes visible.
///
/// The bind schedule is platform policy (6.9.4) and the resolver, dial and
/// observation constants belong to `ssk-netcore` and `path.rs`; neither is
/// repeated here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tuning {
    // accept
    pub accept_backoff_start: Duration,
    pub accept_backoff_max: Duration,
    pub accept_fatal: u32,
    pub capacity_wait: Duration,
    pub capacity_wait_room: usize,
    // pre-admission and peer
    pub peer_burst: u32,
    pub peer_refill_per_s: u32,
    pub pre_admission_slots: usize,
    pub handshake_evict_after: Duration,
    pub peer_timeout: Duration,
    pub peer_queue: usize,
    pub peer_min_snapshot_interval: Duration,
    // denials
    pub denial_window: Duration,
    pub denial_keys: usize,
    pub denial_burst: u32,
    pub denial_refill_per_s: u32,
    pub summary_tick: Duration,
    // budget
    pub panic_budget: u32,
    // audit
    pub audit_queue: usize,
    pub group_commit: usize,
    pub audit_queue_wait: Duration,
    pub audit_sync_wait: Duration,
    pub audit_stall_trip: Duration,
    pub summary_floor: Duration,
    pub closed_deadline: Duration,
    // control
    pub control_lock_wait: Duration,
    pub disarm_bookkeeping_wait: Duration,
    pub recover_verify_deadline: Duration,
    pub doctor_verify_deadline: Duration,
    pub audit_read_verify_deadline: Duration,
    pub session_shutdown_bound: Duration,
    pub set_ingress_burst: u32,
    /// One token every this long (arm only, 11.4).
    pub set_ingress_refill: Duration,
    // bind
    /// Waits before each retry when a recover has to bind again; the first
    /// attempt is immediate.
    pub bind_retry_recover: Vec<Duration>,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            accept_backoff_start: Duration::from_millis(50),
            accept_backoff_max: Duration::from_secs(1),
            accept_fatal: 100,
            capacity_wait: Duration::from_millis(250),
            capacity_wait_room: 8,
            peer_burst: 256,
            peer_refill_per_s: 1024,
            pre_admission_slots: 64,
            handshake_evict_after: Duration::from_secs(1),
            peer_timeout: Duration::from_millis(500),
            peer_queue: 256,
            peer_min_snapshot_interval: Duration::from_millis(20),
            denial_window: Duration::from_secs(60),
            denial_keys: 128,
            denial_burst: 20,
            denial_refill_per_s: 1,
            summary_tick: Duration::from_secs(10),
            panic_budget: 3,
            audit_queue: 256,
            group_commit: 64,
            audit_queue_wait: Duration::from_secs(2),
            audit_sync_wait: Duration::from_secs(5),
            audit_stall_trip: Duration::from_secs(30),
            summary_floor: Duration::from_secs(300),
            closed_deadline: Duration::from_secs(1),
            control_lock_wait: Duration::from_secs(10),
            disarm_bookkeeping_wait: Duration::from_secs(2),
            recover_verify_deadline: Duration::from_secs(60),
            doctor_verify_deadline: Duration::from_secs(10),
            audit_read_verify_deadline: Duration::from_secs(30),
            session_shutdown_bound: Duration::from_secs(1),
            set_ingress_burst: 5,
            set_ingress_refill: Duration::from_secs(2),
            bind_retry_recover: vec![
                Duration::ZERO,
                Duration::from_millis(250),
                Duration::from_millis(500),
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// 6.9.5: seams
// ---------------------------------------------------------------------------

/// Time as the ingress sees it. Limiters take `now` as an argument, so only the
/// code that has to ask for the time holds one of these.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
    /// Milliseconds since the Unix epoch. Untrusted: the wall clock can be set
    /// backwards, which is why the ledger's `seq` and not `ts_ms` is authority.
    fn wall_ms(&self) -> u64;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
            .unwrap_or(0)
    }
}

/// The seam of the bind-retry and limiter tests: production sleeps, a test
/// records the request and completes at once.
pub trait Sleeper: Send + Sync {
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TokioSleeper;

impl Sleeper for TokioSleeper {
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// The validated ingress section plus what the host needs from routing, owned
/// so that the host never sees the whole `AppConfig`. Built once by `C-F1`.
#[derive(Debug, Clone)]
pub struct IngressCfgView {
    pub enabled: bool,
    pub listen: SocketAddrV4,
    pub protocols: Vec<IngressProtocol>,
    pub hardening: IngressHardening,
    pub arm_on_start: bool,
    pub default_profile: Arc<str>,
    pub profile_ids: Vec<Arc<str>>,
    pub families: DirectAddressFamilies,
    pub destination_logging: DestinationLogging,
    pub limits: IngressLimits,
    pub audit: IngressAuditConfig,
    /// The running configuration's digests: `Started`, status, and the
    /// `expect_routing_digest` check of 11.4.
    pub fingerprint: ConfigFingerprint,
}

/// Who connected, as the audit layer records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStamp {
    pub peer: Arc<str>,
    pub verified: bool,
}

// ---------------------------------------------------------------------------
// Proof that a result is durable
// ---------------------------------------------------------------------------

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// What the SOCKS5 success reply (`socks5::write_success`) demands: a value that
/// exists only once the `Result` record of the flow is durable in the ledger.
/// Sealed, so no code outside this crate can mint one; inside the crate the
/// only implementor is the audit ledger's `ResultReceipt` (`C-A6`), and a
/// source-scan test there lists the impls.
pub trait ResultProof: sealed::Sealed {}

// ---------------------------------------------------------------------------
// Poison-tolerant locks
// ---------------------------------------------------------------------------

// A flow task that panics while it holds one of these locks poisons it. Three
// such panics trip the ingress (6.1.3); until then every other task must keep
// working, and `lock().unwrap()` would turn the first panic into a second one
// on every later acquisition. All guarded state in the ingress is plain data
// whose every intermediate value is acceptable, so the poison flag is ignored.

/// Locks `mutex`, ignoring poison.
pub fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Read-locks `lock`, ignoring poison.
pub fn read_unpoisoned<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

/// Write-locks `lock`, ignoring poison.
pub fn write_unpoisoned<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// 6.4.3: audit leaf types
// ---------------------------------------------------------------------------

/// The spelling class of a destination host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKind {
    Name,
    Ipv4,
    Ipv6,
}

/// How a client-supplied destination appears in a record. `Denied` records are
/// always `Plain`: a refusal is evidence, and nothing was dialled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum DestRef {
    Plain {
        host: String,
        port: u16,
    },
    Hashed {
        /// 16 hex characters: which key sealed the token.
        kid: String,
        kind: HostKind,
        /// 32 hex characters.
        token: String,
        port: u16,
    },
}

/// How a resolved address appears in a record; the same two modes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum AddrRef {
    Plain {
        ip: String,
        port: u16,
    },
    Hashed {
        kid: String,
        kind: HostKind,
        token: String,
        port: u16,
    },
}

/// Planned at `Pending` time: a name on a proxied route is `ProxyResolved`, a
/// name on `Direct` is `LocalPinned` (resolved once by `sskd`, filtered, dialled
/// pinned).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    Literal,
    ProxyResolved,
    LocalPinned,
}

/// `Connected`: the upstream tunnel is established. `Failed`: a dial was
/// started and failed. `NotDialed`: no dial was started. `Aborted`: a dial was
/// started and the flow ended before the real outcome was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultOutcome {
    Connected,
    Failed,
    NotDialed,
    Aborted,
}

/// What a chain verification found still open: flows with a `Pending` and no
/// `Result`, tunnels with a connected `Result` and no `Closed`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unresolved {
    pub pending: u64,
    pub open_tunnels: u64,
}

/// A fact observed about the host, quoted as such (10.5, rule R-O).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub kind: String,
    pub value: String,
}

/// `Observation.kind`: the source address the OS gave the dial socket.
pub const OBSERVATION_EGRESS_LOCAL: &str = "egress_local";
/// `Observation.kind`: the cached route-interface alias.
pub const OBSERVATION_OS_ROUTE_IF: &str = "os_route_if";
/// What an unprintable or over-long value is stored as.
pub const OBSERVATION_INVALID: &str = "(invalid)";
/// The longest value stored as given.
pub const OBSERVATION_VALUE_MAX: usize = 64;

impl Observation {
    /// Rule R-O: `kind` must be one of the two closed kinds (anything else is
    /// not recorded at all), and `value` must be printable ASCII (0x20 to 0x7e)
    /// of at most [`OBSERVATION_VALUE_MAX`] characters, else it is stored as
    /// [`OBSERVATION_INVALID`]. The value is quoted OS data and may be hostile
    /// (an adapter alias is chosen by whoever installed the adapter).
    #[must_use]
    pub fn new(kind: &str, value: &str) -> Option<Self> {
        let kind = match kind {
            OBSERVATION_EGRESS_LOCAL => OBSERVATION_EGRESS_LOCAL,
            OBSERVATION_OS_ROUTE_IF => OBSERVATION_OS_ROUTE_IF,
            _ => return None,
        };
        let printable = value.len() <= OBSERVATION_VALUE_MAX
            && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte));
        let value = if printable {
            value
        } else {
            OBSERVATION_INVALID
        };
        Some(Self {
            kind: kind.to_owned(),
            value: value.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "zz-profile";

    fn all_controls() -> Vec<Controls> {
        let mut out = Vec::new();
        for bits in 0u8..8 {
            out.push(Controls {
                exclusive_bind: bits & 1 != 0,
                peer_check: bits & 2 != 0,
                private_audit_store: bits & 4 != 0,
            });
        }
        out
    }

    fn whole_words(text: &str) -> Vec<String> {
        text.split(|c: char| !c.is_alphabetic())
            .filter(|word| !word.is_empty())
            .map(str::to_lowercase)
            .collect()
    }

    fn all_codes() -> Vec<Option<&'static str>> {
        let mut codes: Vec<Option<&'static str>> = vec![None];
        codes.extend(UnavailableCode::ALL.iter().map(|c| Some(c.as_code())));
        codes.extend(TripReason::ALL.iter().map(|r| Some(r.as_str())));
        codes
    }

    // -- vocabulary ---------------------------------------------------------

    #[test]
    fn the_notice_makes_no_forbidden_claim_and_contains_the_coverage_sentence() {
        assert_eq!(contains_forbidden_word(INGRESS_COVERAGE_NOTICE), None);
        assert!(INGRESS_COVERAGE_NOTICE.contains(COVERAGE_SENTENCE));
    }

    #[test]
    fn forbidden_words_are_lower_case_and_the_scan_is_case_insensitive() {
        assert_eq!(FORBIDDEN_WORDS.len(), 20);
        for word in FORBIDDEN_WORDS {
            assert_eq!(
                *word,
                word.to_lowercase(),
                "an upper-case needle never matches"
            );
            assert_eq!(contains_forbidden_word(word), Some(*word));
            assert_eq!(
                contains_forbidden_word(&format!("x {} y", word.to_uppercase())),
                Some(*word),
                "{word}"
            );
        }
        assert!(contains_forbidden_word("Some VPN protected secure tunnel").is_some());
        assert_eq!(contains_forbidden_word("Geschützt"), Some("geschützt"));
        assert_eq!(contains_forbidden_word("proxy ready"), None);
        assert_eq!(contains_forbidden_word(""), None);
    }

    #[test]
    fn state_and_coverage_words_are_the_closed_sets_of_the_design() {
        let states: Vec<_> = IngressState::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            states,
            [
                "disabled",
                "starting",
                "unavailable",
                "disarmed",
                "armed",
                "tripped",
                "stopping"
            ]
        );
        assert_eq!(Coverage::None.as_str(), "none");
        assert_eq!(Coverage::ProxyClientsOnly.as_str(), "proxy_clients_only");
        for word in states {
            assert_eq!(contains_forbidden_word(word), None);
        }
    }

    // -- gate ---------------------------------------------------------------

    #[test]
    fn gate_mode_maps_to_state_coverage_and_hint_as_the_table_says() {
        use GateMode as M;
        let armed = M::Armed {
            profile: Arc::from("p"),
        };
        let rows: Vec<(M, IngressState, Coverage, Option<&str>)> = vec![
            (M::Disabled, IngressState::Disabled, Coverage::None, None),
            (
                M::Starting,
                IngressState::Starting,
                Coverage::None,
                Some("starting; read status again"),
            ),
            (
                M::Unavailable(UnavailableCode::BindFailed),
                IngressState::Unavailable,
                Coverage::None,
                Some("arm again to retry"),
            ),
            (M::Disarmed, IngressState::Disarmed, Coverage::None, None),
            (
                armed.clone(),
                IngressState::Armed,
                Coverage::ProxyClientsOnly,
                None,
            ),
            (
                M::Tripped(TripReason::AcceptFatal),
                IngressState::Tripped,
                Coverage::None,
                Some("re-arm to recover"),
            ),
            (M::Closing, IngressState::Stopping, Coverage::None, None),
        ];
        for (mode, state, coverage, hint) in rows {
            assert_eq!(mode.state(), state, "{mode:?}");
            assert_eq!(mode.coverage_if_healthy(), coverage, "{mode:?}");
            assert_eq!(mode.retry_hint(), hint, "{mode:?}");
        }
        assert_eq!(armed.armed_profile(), Some("p"));
        assert_eq!(GateMode::Disarmed.armed_profile(), None);
        assert_eq!(
            GateMode::Tripped(TripReason::ListenerDied).armed_profile(),
            None
        );
    }

    #[test]
    fn only_an_armed_gate_ever_claims_coverage() {
        let mut modes = vec![
            GateMode::Disabled,
            GateMode::Starting,
            GateMode::Disarmed,
            GateMode::Closing,
        ];
        modes.extend(UnavailableCode::ALL.map(GateMode::Unavailable));
        modes.extend(TripReason::ALL.map(GateMode::Tripped));
        for mode in modes {
            assert_eq!(mode.coverage_if_healthy(), Coverage::None, "{mode:?}");
        }
    }

    #[test]
    fn unavailable_codes_have_the_documented_machine_codes_and_recoverability() {
        let table = [
            (UnavailableCode::ConfigInvalid, "CONFIG_INVALID", false),
            (
                UnavailableCode::HardeningUnavailable,
                "INGRESS_HARDENING_UNAVAILABLE",
                false,
            ),
            (
                UnavailableCode::FdLimitTooLow,
                "INGRESS_FD_LIMIT_TOO_LOW",
                false,
            ),
            (UnavailableCode::AuditCorrupt, "INGRESS_AUDIT_CORRUPT", true),
            (
                UnavailableCode::AuditUnsupportedFormat,
                "INGRESS_AUDIT_UNSUPPORTED_FORMAT",
                true,
            ),
            (
                UnavailableCode::AuditRootUnsafe,
                "INGRESS_AUDIT_ROOT_UNSAFE",
                true,
            ),
            (
                UnavailableCode::AuditDirUnsafe,
                "INGRESS_AUDIT_DIR_UNSAFE",
                true,
            ),
            (
                UnavailableCode::AuditFileUnsafe,
                "INGRESS_AUDIT_FILE_UNSAFE",
                true,
            ),
            (
                UnavailableCode::AuditKeyUnavailable,
                "INGRESS_AUDIT_KEY_UNAVAILABLE",
                true,
            ),
            (UnavailableCode::AuditFailed, "INGRESS_AUDIT_FAILED", true),
            (UnavailableCode::BindFailed, "INGRESS_BIND_FAILED", true),
            (
                UnavailableCode::RecoveryFailed,
                "INGRESS_RECOVERY_FAILED",
                true,
            ),
        ];
        assert_eq!(table.len(), UnavailableCode::ALL.len());
        for (code, text, recoverable) in table {
            assert_eq!(code.as_code(), text);
            assert_eq!(code.recoverable(), recoverable, "{text}");
            assert!(UnavailableCode::ALL.contains(&code));
        }
        let mut seen: Vec<_> = UnavailableCode::ALL.iter().map(|c| c.as_code()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), UnavailableCode::ALL.len(), "codes are unique");
    }

    #[test]
    fn a_process_property_names_its_own_next_step_and_everything_else_says_arm_again() {
        for code in UnavailableCode::ALL {
            let hint = GateMode::Unavailable(code).retry_hint().expect("a hint");
            if code.recoverable() {
                assert_eq!(hint, "arm again to retry", "{code:?}");
            } else {
                assert!(hint.contains("restart sskd"), "{code:?}: {hint}");
                assert_ne!(hint, "arm again to retry");
            }
            assert_eq!(contains_forbidden_word(hint), None, "{hint}");
        }
        for hint in [
            "starting; read status again",
            "re-arm to recover",
            "arm again to retry",
        ] {
            assert_eq!(contains_forbidden_word(hint), None);
        }
    }

    #[test]
    fn a_trip_while_starting_keeps_a_ledger_failure_a_ledger_failure() {
        for reason in TripReason::ALL {
            let expected = match reason {
                TripReason::AuditWriteFailed | TripReason::AuditStalled => {
                    UnavailableCode::AuditFailed
                }
                _ => UnavailableCode::RecoveryFailed,
            };
            assert_eq!(UnavailableCode::from_trip(reason), expected, "{reason:?}");
            assert!(UnavailableCode::from_trip(reason).recoverable());
        }
    }

    #[test]
    fn trip_and_disarm_words_are_closed_unique_and_free_of_forbidden_words() {
        let trips: Vec<_> = TripReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            trips,
            [
                "audit_write_failed",
                "audit_stalled",
                "flow_panic_budget",
                "control_panic",
                "accept_fatal",
                "listener_died"
            ]
        );
        let disarms: Vec<_> = DisarmCause::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            disarms,
            [
                "operator",
                "deactivate",
                "shutdown",
                "arm_superseded",
                "arm_not_applied",
                "arm_abandoned"
            ]
        );
        for word in trips.iter().chain(disarms.iter()) {
            assert_eq!(contains_forbidden_word(word), None, "{word}");
        }
    }

    #[test]
    fn the_client_label_maps_two_names_and_drops_everything_else() {
        assert_eq!(ClientLabel::from_declared(Some("cli")), ClientLabel::Cli);
        assert_eq!(
            ClientLabel::from_declared(Some("desktop")),
            ClientLabel::Desktop
        );
        for other in [
            None,
            Some(""),
            Some("CLI"),
            Some("Desktop"),
            Some("cli "),
            Some("ssk-desktop"),
            Some("cli\nforged: record"),
        ] {
            assert_eq!(ClientLabel::from_declared(other), ClientLabel::Unknown);
        }
        assert_eq!(ClientLabel::Unknown.as_str(), "unknown");
    }

    #[test]
    fn actor_fields_are_the_armed_record_vocabulary() {
        let operator = Actor::Operator {
            peer: Some(Arc::from("uid:1000")),
            client: ClientLabel::Desktop,
        };
        assert_eq!(
            (operator.cause(), operator.client(), operator.requested_by()),
            ("operator", "desktop", "uid:1000")
        );
        let anonymous = Actor::Operator {
            peer: None,
            client: ClientLabel::Unknown,
        };
        assert_eq!(
            (
                anonymous.cause(),
                anonymous.client(),
                anonymous.requested_by()
            ),
            ("operator", "unknown", "unknown")
        );
        let config = Actor::ConfigAutostart;
        assert_eq!(
            (config.cause(), config.client(), config.requested_by()),
            ("config_autostart", "config", "config")
        );
    }

    // -- headline -----------------------------------------------------------

    #[test]
    fn headline_claims_activity_only_when_armed() {
        let armed_profiles = [None, Some(PROFILE)];
        for state in IngressState::ALL {
            for controls in all_controls() {
                for profile in armed_profiles {
                    for code in all_codes() {
                        let text = headline(state, controls, profile, code);
                        let words = whole_words(&text);
                        let says_active = words.iter().any(|w| w == "active" || w == "aktiv");
                        let ctx = format!("{state:?} {controls:?} {profile:?} {code:?}: {text}");

                        let really_armed = state == IngressState::Armed && profile.is_some();
                        assert_eq!(says_active, really_armed, "{ctx}");
                        assert_eq!(text.contains(PROFILE), really_armed, "{ctx}");
                        assert_eq!(text.contains(COVERAGE_SENTENCE), really_armed, "{ctx}");

                        // Never the word, in any of its spellings, and never a
                        // claim made by a third-party word.
                        assert!(!text.to_lowercase().contains("protected"), "{ctx}");
                        assert_eq!(contains_forbidden_word(&text), None, "{ctx}");

                        if state != IngressState::Armed {
                            assert!(!text.to_lowercase().contains("serving"), "{ctx}");
                            assert!(!text.contains("for applications that use it"), "{ctx}");
                        }
                        // The peer-check note appears exactly where it must.
                        let notes_peer = text.contains("no peer check");
                        let may_note =
                            matches!(state, IngressState::Disarmed | IngressState::Armed)
                                && (state != IngressState::Armed || profile.is_some());
                        assert_eq!(notes_peer, may_note && !controls.peer_check, "{ctx}");
                    }
                }
            }
        }
    }

    #[test]
    fn headline_rows_are_the_texts_of_the_design() {
        let on = Controls {
            exclusive_bind: true,
            peer_check: true,
            private_audit_store: true,
        };
        let off = Controls::default();
        let h = |state, controls, profile, code| headline(state, controls, profile, code);
        assert_eq!(
            h(IngressState::Disabled, on, None, None),
            "Local proxy: off"
        );
        assert_eq!(
            h(IngressState::Starting, on, None, None),
            "Local proxy starting"
        );
        assert_eq!(
            h(IngressState::Unavailable, on, None, Some("CONFIG_INVALID")),
            "Local proxy unavailable: configuration invalid"
        );
        assert_eq!(
            h(
                IngressState::Unavailable,
                on,
                None,
                Some("INGRESS_BIND_FAILED")
            ),
            "Proxy unavailable: INGRESS_BIND_FAILED"
        );
        assert_eq!(
            h(IngressState::Disarmed, on, None, None),
            "Proxy ready, not activated: connections are refused."
        );
        assert_eq!(
            h(IngressState::Disarmed, off, None, None),
            "Proxy ready, not activated: connections are refused. If activated, other local accounts could use it: there is no peer check."
        );
        assert_eq!(
            h(IngressState::Armed, on, Some("work"), None),
            "Proxy active for applications that use it (profile work). Everything else is not covered."
        );
        assert_eq!(
            h(IngressState::Armed, off, Some("work"), None),
            "Proxy active for applications that use it (profile work). Everything else is not covered. Other local accounts may also use it: there is no peer check."
        );
        assert_eq!(
            h(IngressState::Tripped, on, None, Some("audit_write_failed")),
            "Proxy stopped: audit_write_failed. Re-arm to recover."
        );
        assert_eq!(
            h(IngressState::Stopping, on, None, None),
            "Local proxy stopping"
        );
    }

    #[test]
    fn an_armed_state_without_a_profile_is_not_rendered_as_activity() {
        let text = headline(IngressState::Armed, Controls::default(), None, None);
        assert_eq!(text, "Local proxy: state unknown, treat as not covered");
    }

    #[test]
    fn the_headline_ignores_inputs_that_do_not_belong_to_its_state() {
        // A profile handed to a disarmed state, or a code handed to an armed
        // one, must not leak into the sentence.
        let controls = Controls {
            peer_check: true,
            ..Controls::default()
        };
        let disarmed = headline(IngressState::Disarmed, controls, Some(PROFILE), Some("X"));
        assert!(
            !disarmed.contains(PROFILE) && !disarmed.contains('X'),
            "{disarmed}"
        );
        let armed = headline(
            IngressState::Armed,
            controls,
            Some(PROFILE),
            Some("INGRESS_X"),
        );
        assert!(!armed.contains("INGRESS_X"), "{armed}");
    }

    // -- tuning -------------------------------------------------------------

    #[test]
    fn tuning_defaults_match_the_design_table() {
        let t = Tuning::default();
        let ms = Duration::from_millis;
        let s = Duration::from_secs;
        assert_eq!(
            (t.accept_backoff_start, t.accept_backoff_max, t.accept_fatal),
            (ms(50), s(1), 100)
        );
        assert_eq!((t.capacity_wait, t.capacity_wait_room), (ms(250), 8));
        assert_eq!(
            (t.peer_burst, t.peer_refill_per_s, t.pre_admission_slots),
            (256, 1024, 64)
        );
        assert_eq!(
            (
                t.handshake_evict_after,
                t.peer_timeout,
                t.peer_queue,
                t.peer_min_snapshot_interval
            ),
            (s(1), ms(500), 256, ms(20))
        );
        assert_eq!(
            (
                t.denial_window,
                t.denial_keys,
                t.denial_burst,
                t.denial_refill_per_s,
                t.summary_tick
            ),
            (s(60), 128, 20, 1, s(10))
        );
        assert_eq!(t.panic_budget, 3);
        assert_eq!(
            (t.audit_queue, t.group_commit, t.audit_queue_wait),
            (256, 64, s(2))
        );
        assert_eq!(
            (
                t.audit_sync_wait,
                t.audit_stall_trip,
                t.summary_floor,
                t.closed_deadline
            ),
            (s(5), s(30), s(300), s(1))
        );
        assert_eq!(
            (
                t.control_lock_wait,
                t.disarm_bookkeeping_wait,
                t.recover_verify_deadline,
                t.doctor_verify_deadline,
                t.audit_read_verify_deadline,
                t.session_shutdown_bound
            ),
            (s(10), s(2), s(60), s(10), s(30), s(1))
        );
        assert_eq!((t.set_ingress_burst, t.set_ingress_refill), (5, s(2)));
        assert_eq!(t.bind_retry_recover, vec![Duration::ZERO, ms(250), ms(500)]);
    }

    #[test]
    fn the_audit_stall_trip_is_longer_than_the_sync_wait() {
        // A single slow fsync must time out the flow (5 s) long before the
        // detector trips the whole ingress (30 s).
        let t = Tuning::default();
        assert!(t.audit_stall_trip > t.audit_sync_wait);
        assert!(t.audit_sync_wait > t.audit_queue_wait);
    }

    // -- clock and sleeper --------------------------------------------------

    #[test]
    fn the_system_clock_is_monotonic_and_its_wall_clock_is_plausible() {
        let clock = SystemClock;
        let (a, b) = (clock.now(), clock.now());
        assert!(b >= a);
        // After 2020-09-13 and not absurdly far in the future.
        let wall = clock.wall_ms();
        assert!(wall > 1_600_000_000_000, "{wall}");
        assert!(wall < 32_503_680_000_000, "{wall}");
    }

    #[tokio::test]
    async fn the_tokio_sleeper_really_waits() {
        let started = Instant::now();
        TokioSleeper.sleep(Duration::from_millis(30)).await;
        assert!(started.elapsed() >= Duration::from_millis(25));
    }

    #[test]
    fn clock_and_sleeper_are_object_safe() {
        let _clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let _sleeper: Arc<dyn Sleeper> = Arc::new(TokioSleeper);
    }

    // -- locks --------------------------------------------------------------

    #[test]
    fn a_poisoned_lock_is_still_usable() {
        let mutex = Arc::new(Mutex::new(1_u32));
        let rw = Arc::new(RwLock::new(10_u32));
        let (m, r) = (Arc::clone(&mutex), Arc::clone(&rw));
        let _ = std::thread::spawn(move || {
            let _guard = m.lock().expect("fresh lock");
            let _write = r.write().expect("fresh lock");
            panic!("poison both locks");
        })
        .join();
        assert!(mutex.is_poisoned() && rw.is_poisoned());

        *lock_unpoisoned(&mutex) += 1;
        assert_eq!(*lock_unpoisoned(&mutex), 2);
        *write_unpoisoned(&rw) += 1;
        assert_eq!(*read_unpoisoned(&rw), 11);
    }

    // -- audit leaf types ---------------------------------------------------

    #[test]
    fn leaf_enums_serialise_as_the_ledger_vocabulary() {
        let json = |value: &dyn erased::Json| value.json();
        assert_eq!(json(&HostKind::Name), r#""name""#);
        assert_eq!(json(&HostKind::Ipv4), r#""ipv4""#);
        assert_eq!(json(&HostKind::Ipv6), r#""ipv6""#);
        assert_eq!(json(&Resolution::Literal), r#""literal""#);
        assert_eq!(json(&Resolution::ProxyResolved), r#""proxy_resolved""#);
        assert_eq!(json(&Resolution::LocalPinned), r#""local_pinned""#);
        assert_eq!(json(&ResultOutcome::Connected), r#""connected""#);
        assert_eq!(json(&ResultOutcome::Failed), r#""failed""#);
        assert_eq!(json(&ResultOutcome::NotDialed), r#""not_dialed""#);
        assert_eq!(json(&ResultOutcome::Aborted), r#""aborted""#);
        assert_eq!(
            json(&Unresolved {
                pending: 2,
                open_tunnels: 1
            }),
            r#"{"pending":2,"open_tunnels":1}"#
        );
    }

    /// Lets the table above take heterogeneous values without a macro.
    mod erased {
        pub trait Json {
            fn json(&self) -> String;
        }
        impl<T: serde::Serialize> Json for T {
            fn json(&self) -> String {
                serde_json::to_string(self).expect("serialise a leaf type")
            }
        }
    }

    #[test]
    fn dest_and_addr_refs_have_a_pinned_wire_shape_and_round_trip() {
        let plain = DestRef::Plain {
            host: "example.com".into(),
            port: 443,
        };
        let hashed = DestRef::Hashed {
            kid: "0123456789abcdef".into(),
            kind: HostKind::Name,
            token: "00112233445566778899aabbccddeeff".into(),
            port: 443,
        };
        assert_eq!(
            serde_json::to_string(&plain).expect("plain"),
            r#"{"mode":"plain","host":"example.com","port":443}"#
        );
        assert_eq!(
            serde_json::to_string(&hashed).expect("hashed"),
            r#"{"mode":"hashed","kid":"0123456789abcdef","kind":"name","token":"00112233445566778899aabbccddeeff","port":443}"#
        );
        for value in [plain, hashed] {
            let text = serde_json::to_string(&value).expect("serialise");
            assert_eq!(
                serde_json::from_str::<DestRef>(&text).expect("parse"),
                value
            );
        }
        let addr = AddrRef::Plain {
            ip: "93.184.216.34".into(),
            port: 80,
        };
        assert_eq!(
            serde_json::to_string(&addr).expect("addr"),
            r#"{"mode":"plain","ip":"93.184.216.34","port":80}"#
        );
        let text = serde_json::to_string(&addr).expect("serialise");
        assert_eq!(serde_json::from_str::<AddrRef>(&text).expect("parse"), addr);
    }

    #[test]
    fn a_plain_ref_cannot_be_read_as_hashed_and_back() {
        // An attacker (or a bug) that edits `mode` must not turn one form into
        // the other: the verifier would otherwise accept a hashed record whose
        // token is a host name.
        let forged = r#"{"mode":"hashed","host":"example.com","port":443}"#;
        assert!(serde_json::from_str::<DestRef>(forged).is_err());
        let unknown = r#"{"mode":"omitted","port":443}"#;
        assert!(serde_json::from_str::<DestRef>(unknown).is_err());
    }

    #[test]
    fn observation_new_enforces_rule_r_o() {
        let ok = Observation::new("os_route_if", "Ethernet 2").expect("a closed kind");
        assert_eq!(ok.kind, "os_route_if");
        assert_eq!(ok.value, "Ethernet 2");
        assert_eq!(
            Observation::new("egress_local", "192.0.2.7")
                .expect("a closed kind")
                .kind,
            "egress_local"
        );

        // An unknown kind is not recorded at all.
        for kind in [
            "",
            "route",
            "OS_ROUTE_IF",
            "os_route_if ",
            "egress",
            "default_route",
        ] {
            assert_eq!(Observation::new(kind, "x"), None, "{kind:?}");
        }

        // Anything that is not printable ASCII becomes the marker text.
        for value in [
            "line\nbreak",
            "tab\there",
            "nul\0",
            "\u{7f}",
            "caf\u{e9}",
            "\u{202e}rtl",
            "\u{2028}",
            &"a".repeat(65),
        ] {
            let obs = Observation::new("os_route_if", value).expect("a closed kind");
            assert_eq!(obs.value, OBSERVATION_INVALID, "{value:?}");
        }

        // The boundaries: 64 printable characters are kept, 0x20 and 0x7e are
        // printable, 0x1f and 0x7f are not.
        let longest = "a".repeat(OBSERVATION_VALUE_MAX);
        assert_eq!(
            Observation::new("os_route_if", &longest)
                .expect("a closed kind")
                .value,
            longest
        );
        assert_eq!(
            Observation::new("os_route_if", " ~")
                .expect("a closed kind")
                .value,
            " ~"
        );
        assert_eq!(
            Observation::new("os_route_if", "\u{1f}")
                .expect("a closed kind")
                .value,
            OBSERVATION_INVALID
        );
    }

    #[test]
    fn the_marker_and_the_kinds_are_free_of_forbidden_words() {
        for text in [
            OBSERVATION_INVALID,
            OBSERVATION_EGRESS_LOCAL,
            OBSERVATION_OS_ROUTE_IF,
        ] {
            assert_eq!(contains_forbidden_word(text), None, "{text}");
        }
    }

    #[test]
    fn peer_stamp_and_controls_are_plain_values() {
        let stamp = PeerStamp {
            peer: Arc::from("uid:1000"),
            verified: true,
        };
        assert_eq!(stamp.clone(), stamp);
        // The default describes a platform that proved nothing.
        assert_eq!(
            Controls::default(),
            Controls {
                exclusive_bind: false,
                peer_check: false,
                private_audit_store: false
            }
        );
    }
}
