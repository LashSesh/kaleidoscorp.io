//! The control plane of the local ingress (design 6.9, 10.3 to 10.5).
//!
//! [`IngressShared`] owns the gate and everything a status read needs; the host
//! (sockets and tasks) and the supervisor hold an `Arc` of it. Neither the host
//! nor this file imports the supervisor, its `Inner` or the state machine.
//!
//! * **One lifecycle value.** The gate (`watch<Gate>`: an epoch and a mode) is the
//!   only lifecycle state. Every change is a compare-and-set on the epoch
//!   ([`IngressShared::cas`]) whose closure takes no lock and does no I/O, so it can
//!   run under the watch cell's write lock; every transition bumps the epoch, and
//!   a flow, an arm or a recover that captured the old epoch loses.
//! * **Four operations** ([`arm`](IngressShared::arm), [`disarm`](IngressShared::disarm),
//!   [`trip`](IngressShared::trip), [`recover`](IngressShared::recover)) plus
//!   [`close`](IngressShared::close). `arm` and `recover` serialise on a FIFO
//!   `control` lock and run as spawned tasks, so a requester that goes away does not
//!   abandon an arm half way. `disarm` and `trip` take no lock before their effect:
//!   they cannot be delayed by an arm that waits for its fsync.
//! * **The ledger is reached through a slot.** A re-arm after a trip needs a new
//!   audit writer; [`LedgerSlot`] is the indirection that lets the host install it
//!   without a restart (6.9).
//! * **Status is read, not computed under a lock.** [`IngressShared::snapshot`]
//!   reads the gate, short std mutexes and atomics; it never waits for `control`,
//!   never awaits and never does file I/O.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use ssk_config::ingress::{DirectAddressFamilies, IngressHardening};
use ssk_ipc::{
    ConfigDigestsDto, DenialSummaryDto, Event, FlowInspectionDto, FlowSummaryDto, IngressAuditDto,
    IngressControlsDto, IngressCountersDto, IngressEgressDto, IngressLimitsDto,
    IngressObservationsDto, IngressStatusDto, IngressWarningDto, IpcError, LastTransitionDto,
    RejectedTargetDto,
};
use ssk_netcore::BoxFuture;
use tokio::sync::{broadcast, watch, Mutex as AsyncMutex, OwnedMutexGuard};
use tokio::task::JoinHandle;

use super::audit::input::{ArmedEvent, DisarmedEvent, TrippedEvent};
use super::audit::writer::{
    ArmReceipt, AuditError, AuditStatus, FlowAuditWriter, Waits, WriterState,
};
use super::peer::no_controls;
use super::types::{
    lock_unpoisoned, read_unpoisoned, write_unpoisoned, Actor, Controls, DisarmCause, Gate,
    GateMode, IngressCfgView, Observation, TripReason, Tuning, UnavailableCode,
    INGRESS_COVERAGE_NOTICE,
};

// ---------------------------------------------------------------------------
// Words
// ---------------------------------------------------------------------------

/// What the observations are, in words that claim nothing about anyone else's
/// software (10.5).
pub const OBSERVATION_LABEL: &str = "Facts read from the operating system and from this daemon's own sockets. They describe what was seen, not what any other software is doing.";

pub const WARNING_PEER_CHECK_INACTIVE: &str = "PEER_CHECK_INACTIVE";
pub const WARNING_EXCLUSIVE_BIND_INACTIVE: &str = "EXCLUSIVE_BIND_INACTIVE";
pub const WARNING_AUDIT_STORE_NOT_PRIVATE: &str = "AUDIT_STORE_NOT_PRIVATE";
pub const WARNING_OS_ROUTE_CHANGED: &str = "OS_ROUTE_CHANGED";
pub const WARNING_DIRECT_MAY_USE_IPV6: &str = "DIRECT_MAY_USE_IPV6";
pub const WARNING_OBSERVATION_UNAVAILABLE: &str = "OBSERVATION_UNAVAILABLE";
pub const WARNING_AUDIT_WINDOW_SHORT: &str = "AUDIT_WINDOW_SHORT";

/// The text of a warning is fixed per code (10.5) and contains no word of
/// `FORBIDDEN_WORDS`.
#[must_use]
pub fn warning_text(code: &str) -> Option<&'static str> {
    Some(match code {
        WARNING_PEER_CHECK_INACTIVE => {
            "No peer check is active: any local account that can reach this port can use the proxy."
        }
        WARNING_EXCLUSIVE_BIND_INACTIVE => {
            "The port is not bound exclusively: another local process might be able to share or take it."
        }
        WARNING_AUDIT_STORE_NOT_PRIVATE => {
            "The destination log is not verified as private: other local accounts might be able to read it."
        }
        WARNING_OS_ROUTE_CHANGED => {
            "The network interface that the operating system selects for the probe address changed recently. See the observations. This says nothing about other destinations."
        }
        WARNING_DIRECT_MAY_USE_IPV6 => {
            "Direct connections may use IPv6. Whether other network software covers that path is not known to this daemon."
        }
        WARNING_OBSERVATION_UNAVAILABLE => {
            "The operating system's routing lookup is not available here; no route observation is shown."
        }
        WARNING_AUDIT_WINDOW_SHORT => {
            "Older audit records have already been removed by size retention: the retained window is shorter than 24 hours."
        }
        _ => return None,
    })
}

const AUDIT_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;
const OS_ROUTE_CHANGED_WINDOW_MS: u64 = 10 * 60 * 1000;

// ---------------------------------------------------------------------------
// Errors the control plane answers with (11.14)
// ---------------------------------------------------------------------------

pub const INGRESS_DISABLED: &str = "INGRESS_DISABLED";
pub const INGRESS_STARTING: &str = "INGRESS_STARTING";
pub const INGRESS_BUSY: &str = "INGRESS_BUSY";
pub const INGRESS_SUPERSEDED: &str = "INGRESS_SUPERSEDED";
pub const INGRESS_TRIPPED: &str = "INGRESS_TRIPPED";
pub const INGRESS_STOPPING: &str = "INGRESS_STOPPING";
pub const INGRESS_CONTROL_FAILED: &str = "INGRESS_CONTROL_FAILED";
pub const INGRESS_RECOVERY_FAILED: &str = "INGRESS_RECOVERY_FAILED";
pub const INGRESS_AUDIT_FAILED: &str = "INGRESS_AUDIT_FAILED";
pub const INGRESS_AUDIT_STALLED: &str = "INGRESS_AUDIT_STALLED";
pub const INGRESS_ARGUMENT: &str = "INGRESS_ARGUMENT";
pub const INGRESS_ARMED: &str = "INGRESS_ARMED";
pub const INGRESS_DISARMED: &str = "INGRESS_DISARMED";
pub const INGRESS_RECOVERED: &str = "INGRESS_RECOVERED";
pub const FLOW_NOT_FOUND: &str = "FLOW_NOT_FOUND";
pub const FLOW_NOT_RETAINED: &str = "FLOW_NOT_RETAINED";

fn err_disabled() -> IpcError {
    IpcError::new(
        "Config",
        INGRESS_DISABLED,
        "the local proxy is off in this daemon; nothing was changed",
    )
    .with_next_step(
        "`ssk status` reports the proxy under `ingress`; `disabled` means no listener exists.",
    )
}

fn err_starting() -> IpcError {
    IpcError::new(
        "Runtime",
        INGRESS_STARTING,
        "the local proxy is still starting; nothing was changed",
    )
    .retriable()
    .with_next_step("Read `ssk status` and retry once `ingress.state` is no longer `starting`.")
}

fn err_busy() -> IpcError {
    IpcError::new(
        "Runtime",
        INGRESS_BUSY,
        "another change to the local proxy is in progress; nothing was changed",
    )
    .retriable()
    .with_next_step("Retry in a moment.")
}

fn err_superseded() -> IpcError {
    IpcError::new(
        "Runtime",
        INGRESS_SUPERSEDED,
        "a disarm or another change won while this arm was in progress; nothing is armed",
    )
    .with_next_step("Read `ssk status`, then arm again if that is still wanted.")
}

fn err_tripped() -> IpcError {
    IpcError::new(
        "Runtime",
        INGRESS_TRIPPED,
        "the local proxy stopped while this arm was in progress; nothing is armed",
    )
    .with_next_step("Arm again to recover.")
}

fn err_stopping() -> IpcError {
    IpcError::new(
        "Runtime",
        INGRESS_STOPPING,
        "the local proxy is shutting down; nothing was changed",
    )
}

fn err_control_failed() -> IpcError {
    IpcError::new(
        "Runtime",
        INGRESS_CONTROL_FAILED,
        "a control task of the local proxy failed; the proxy has stopped",
    )
    .with_next_step("Arm again to recover; if it happens again, run `ssk doctor`.")
}

fn err_argument(message: &str) -> IpcError {
    IpcError::new("Usage", INGRESS_ARGUMENT, message)
}

fn err_audit(error: AuditError, stalled: bool) -> IpcError {
    if stalled {
        return IpcError::new(
            "Runtime",
            INGRESS_AUDIT_STALLED,
            "the flow ledger's disk is not answering; nothing was armed",
        )
        .with_next_step("Restart sskd once the disk is healthy.");
    }
    IpcError::new(
        "Runtime",
        INGRESS_AUDIT_FAILED,
        format!(
            "the flow ledger could not record the arm ({}); nothing was armed",
            error.code()
        ),
    )
    .with_next_step("Run `ssk doctor` and read the ingress audit checks.")
}

fn err_unavailable(code: UnavailableCode) -> IpcError {
    let class = if code.recoverable() {
        "Runtime"
    } else {
        "Config"
    };
    IpcError::new(
        class,
        code.as_code(),
        "the local proxy is unavailable; nothing was changed",
    )
    .with_next_step(code.restart_step())
}

fn err_recovery_failed(code: UnavailableCode, cause: &str) -> IpcError {
    IpcError::new(
        "Runtime",
        INGRESS_RECOVERY_FAILED,
        format!(
            "the local proxy could not recover ({}): {cause}",
            code.as_code()
        ),
    )
    .with_next_step("Fix what the message names, then arm again.")
}

/// What a lost compare-and-set means for the caller, from the mode that won.
fn err_after_loss(mode: &GateMode) -> IpcError {
    match mode {
        GateMode::Tripped(_) | GateMode::Unavailable(_) => err_tripped(),
        GateMode::Closing => err_stopping(),
        GateMode::Starting => err_starting(),
        GateMode::Disabled => err_disabled(),
        GateMode::Disarmed | GateMode::Armed { .. } => err_superseded(),
    }
}

// ---------------------------------------------------------------------------
// The ledger, as the control plane sees it
// ---------------------------------------------------------------------------

/// The current audit writer and the boot it belongs to.
#[derive(Clone)]
pub struct Installed {
    pub writer: Arc<FlowAuditWriter>,
    /// `b<seq of the Started record>`: the flow-id prefix.
    pub boot: Arc<str>,
}

/// Where the current writer lives. The host installs the first one at start and a
/// fresh one at every recover; everything else reads it through [`current`].
///
/// [`current`]: LedgerSlot::current
#[derive(Default)]
pub struct LedgerSlot {
    current: RwLock<Option<Installed>>,
}

impl LedgerSlot {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Two `Arc` clones under a read lock; never held across an await.
    #[must_use]
    pub fn current(&self) -> Option<Installed> {
        read_unpoisoned(&self.current).clone()
    }

    /// Host only. Returns the writer that was replaced.
    pub fn install(&self, new: Installed) -> Option<Installed> {
        write_unpoisoned(&self.current).replace(new)
    }
}

/// What the control plane needs from the ledger. Implemented by [`LedgerSlot`]
/// (which delegates to the current writer) and by test doubles.
pub trait ControlLedger: Send + Sync {
    /// Durable: the gate may open only after this returns.
    fn append_armed(
        &self,
        record: ArmedEvent,
        waits: Waits,
    ) -> BoxFuture<'_, Result<ArmReceipt, AuditError>>;
    /// Durable, best effort. `true` when the record was written.
    fn append_disarmed(&self, record: DisarmedEvent, bounded: Duration) -> BoxFuture<'_, bool>;
    /// Synchronous, never blocks. `false` when the record could not be queued.
    fn try_enqueue_tripped(&self, record: TrippedEvent) -> bool;
    /// How long the disk part of the batch that is running now has been running;
    /// `None` when none is. A stalled writer is told apart from a failed one by it.
    fn io_in_progress_for(&self) -> Option<Duration>;
}

impl ControlLedger for LedgerSlot {
    fn append_armed(
        &self,
        record: ArmedEvent,
        waits: Waits,
    ) -> BoxFuture<'_, Result<ArmReceipt, AuditError>> {
        Box::pin(async move {
            // With no writer: refuse, never "write nothing and carry on".
            match self.current() {
                Some(installed) => installed.writer.append_armed(record, waits).await,
                None => Err(AuditError::Closing),
            }
        })
    }

    fn append_disarmed(&self, record: DisarmedEvent, bounded: Duration) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            match self.current() {
                Some(installed) => installed.writer.append_disarmed(record, bounded).await,
                None => false,
            }
        })
    }

    fn try_enqueue_tripped(&self, record: TrippedEvent) -> bool {
        self.current()
            .is_some_and(|installed| installed.writer.try_enqueue_tripped(record))
    }

    fn io_in_progress_for(&self) -> Option<Duration> {
        self.current()
            .and_then(|installed| installed.writer.io_in_progress_for())
    }
}

/// Why the host could not recover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoverError {
    /// A verification of the previous recover is still running.
    Busy,
    /// The previous writer could not be joined: never open a second one on the
    /// same segment.
    Stalled,
    /// The most specific reason, and the cause as text.
    Unavailable(UnavailableCode, String),
}

/// What `recover` asks of the host. All or nothing: the new writer is installed in
/// the [`LedgerSlot`] as the last step, immediately before the gate write, so a
/// failure at any earlier step installs nothing.
pub trait HostControl: Send + Sync {
    fn recover(&self) -> BoxFuture<'_, Result<(), RecoverError>>;
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/// Counts since this boot (10.4). Atomics only: a counter wraps, it never panics.
#[derive(Debug, Default)]
pub struct Counters {
    pub accepted: AtomicU64,
    pub refused_disarmed: AtomicU64,
    pub refused_peer_budget: AtomicU64,
    pub refused_peer: AtomicU64,
    pub refused_rate: AtomicU64,
    pub refused_capacity: AtomicU64,
    pub malformed: AtomicU64,
    pub rejected_malformed: AtomicU64,
    pub rejected_numeric_alias: AtomicU64,
    pub rejected_localhost: AtomicU64,
    pub denied: AtomicU64,
    pub denied_suppressed: AtomicU64,
    pub admitted: AtomicU64,
    pub connect_failed: AtomicU64,
    active_flows: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub panics: AtomicU64,
    pub accept_errors: AtomicU64,
    pub audit_close_lost: AtomicU64,
    pub audit_busy: AtomicU64,
    pub audit_timeouts: AtomicU64,
    pub disarm_record_lost: AtomicU64,
    pub trips: AtomicU64,
    pub evicted_handshake: AtomicU64,
    pub resolver_busy: AtomicU64,
    pub resolver_zombies: AtomicU64,
}

impl Counters {
    pub fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    /// A flow was admitted and holds a tunnel.
    pub fn flow_started(&self) {
        Self::bump(&self.active_flows);
    }

    /// The flow ended; never below zero.
    pub fn flow_ended(&self) {
        let _ = self
            .active_flows
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
    }

    #[must_use]
    pub fn active_flows(&self) -> u64 {
        self.active_flows.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn dto(&self) -> IngressCountersDto {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        IngressCountersDto {
            accepted: get(&self.accepted),
            refused_disarmed: get(&self.refused_disarmed),
            refused_peer_budget: get(&self.refused_peer_budget),
            refused_peer: get(&self.refused_peer),
            refused_rate: get(&self.refused_rate),
            refused_capacity: get(&self.refused_capacity),
            malformed: get(&self.malformed),
            rejected_target: RejectedTargetDto {
                malformed: get(&self.rejected_malformed),
                numeric_alias: get(&self.rejected_numeric_alias),
                localhost: get(&self.rejected_localhost),
            },
            denied: get(&self.denied),
            denied_suppressed: get(&self.denied_suppressed),
            admitted: get(&self.admitted),
            connect_failed: get(&self.connect_failed),
            active_flows: get(&self.active_flows),
            bytes_up: get(&self.bytes_up),
            bytes_down: get(&self.bytes_down),
            panics: get(&self.panics),
            accept_errors: get(&self.accept_errors),
            audit_close_lost: get(&self.audit_close_lost),
            audit_busy: get(&self.audit_busy),
            audit_timeouts: get(&self.audit_timeouts),
            disarm_record_lost: get(&self.disarm_record_lost),
            trips: get(&self.trips),
            evicted_handshake: get(&self.evicted_handshake),
            resolver_busy: get(&self.resolver_busy),
            resolver_zombies: get(&self.resolver_zombies),
        }
    }
}

// ---------------------------------------------------------------------------
// The registry of recent flows
// ---------------------------------------------------------------------------

/// How many flows are kept for `ListRecentFlows` and `InspectFlow`.
pub const FLOW_REGISTRY_CAPACITY: usize = 256;

/// One flow as the registry keeps it.
#[derive(Debug, Clone)]
pub struct FlowEntry {
    pub summary: FlowSummaryDto,
    /// What `InspectFlow` shows; absent for a flow that never got that far.
    pub inspection: Option<FlowInspectionDto>,
}

/// A ring of the newest flows, behind a short std mutex. Nothing awaits while
/// holding it.
#[derive(Debug, Default)]
pub struct FlowRegistry {
    inner: Mutex<RegistryInner>,
}

#[derive(Debug, Default)]
struct RegistryInner {
    ring: VecDeque<FlowEntry>,
    /// The highest `<n>` of a flow id `ingress:b<boot>:<n>` ever recorded, per boot
    /// prefix: an id at or below it was issued even when it has left the ring.
    issued: Option<(String, u64)>,
}

/// `ingress:b<boot>:<n>` split into the boot prefix (`b<boot>`) and `n`.
fn parse_flow_id(flow_id: &str) -> Option<(&str, u64)> {
    let rest = flow_id.strip_prefix("ingress:")?;
    let (boot, n) = rest.split_once(':')?;
    let digits = boot.strip_prefix('b')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((boot, n.parse().ok()?))
}

impl FlowRegistry {
    /// Inserts a flow, or replaces the one with the same id; the oldest leaves when
    /// the ring is full.
    pub fn record(&self, entry: FlowEntry) {
        let mut inner = lock_unpoisoned(&self.inner);
        if let Some((boot, n)) = parse_flow_id(&entry.summary.flow_id) {
            match &mut inner.issued {
                Some((current, highest)) if current == boot => *highest = (*highest).max(n),
                other => *other = Some((boot.to_owned(), n)),
            }
        }
        if let Some(existing) = inner
            .ring
            .iter_mut()
            .rev()
            .find(|e| e.summary.flow_id == entry.summary.flow_id)
        {
            *existing = entry;
            return;
        }
        if inner.ring.len() >= FLOW_REGISTRY_CAPACITY {
            inner.ring.pop_front();
        }
        inner.ring.push_back(entry);
    }

    /// Changes a flow that is still in the ring; `false` when it has left.
    pub fn update(&self, flow_id: &str, change: impl FnOnce(&mut FlowEntry)) -> bool {
        let mut inner = lock_unpoisoned(&self.inner);
        match inner
            .ring
            .iter_mut()
            .rev()
            .find(|e| e.summary.flow_id == flow_id)
        {
            Some(entry) => {
                change(entry);
                true
            }
            None => false,
        }
    }

    /// Newest first, at most `limit`.
    #[must_use]
    pub fn recent(&self, limit: usize) -> Vec<FlowSummaryDto> {
        lock_unpoisoned(&self.inner)
            .ring
            .iter()
            .rev()
            .take(limit)
            .map(|e| e.summary.clone())
            .collect()
    }

    /// `FLOW_NOT_RETAINED` for an id this daemon issued (of this boot, below the
    /// highest number seen, or of another boot) that is no longer in memory;
    /// `FLOW_NOT_FOUND` for an id that was never issued.
    ///
    /// # Errors
    /// The two codes above.
    pub fn inspect(&self, flow_id: &str) -> Result<FlowInspectionDto, IpcError> {
        let inner = lock_unpoisoned(&self.inner);
        if let Some(entry) = inner
            .ring
            .iter()
            .rev()
            .find(|e| e.summary.flow_id == flow_id)
        {
            return entry.inspection.clone().ok_or_else(err_flow_not_retained);
        }
        let issued = match parse_flow_id(flow_id) {
            Some((boot, n)) => match &inner.issued {
                Some((current, highest)) if current == boot => n <= *highest,
                // Another boot: this daemon cannot say it was never issued.
                _ => true,
            },
            None => false,
        };
        if issued {
            Err(err_flow_not_retained())
        } else {
            Err(IpcError::new(
                "Runtime",
                FLOW_NOT_FOUND,
                "no flow with this id was issued by this daemon",
            ))
        }
    }
}

fn err_flow_not_retained() -> IpcError {
    IpcError::new(
        "Runtime",
        FLOW_NOT_RETAINED,
        "this flow is not kept in memory; see the ingress audit",
    )
    .with_next_step("`ssk ingress audit` reads the ledger.")
}

// ---------------------------------------------------------------------------
// What the host publishes
// ---------------------------------------------------------------------------

/// The limits after the descriptor budget (7.3) has been applied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EffectiveLimits {
    pub max_connections: u32,
    /// The descriptor limit cut the configured value.
    pub clamped_by_fd_limit: bool,
    pub fd_soft_limit: Option<u64>,
    pub fd_needed: u64,
}

/// Facts that only the host knows, published through
/// [`IngressShared::update_host_facts`].
#[derive(Debug, Clone)]
pub struct HostFacts {
    /// Only while a listener is bound.
    pub listen: Option<SocketAddr>,
    /// Only while starting: `verifying_ledger` or `binding (attempt n of N)`.
    pub phase: Option<String>,
    pub controls: Controls,
    /// `None` until the budget has been applied.
    pub limits: Option<EffectiveLimits>,
    /// The accept task is running.
    pub accept_alive: bool,
    pub observations: IngressObservationsDto,
}

impl Default for HostFacts {
    fn default() -> Self {
        Self {
            listen: None,
            phase: None,
            controls: no_controls(),
            limits: None,
            accept_alive: false,
            observations: IngressObservationsDto {
                label: OBSERVATION_LABEL.to_owned(),
                ..IngressObservationsDto::default()
            },
        }
    }
}

#[derive(Debug, Default)]
struct StatusInner {
    last_error: Option<IpcError>,
    last_denial: Option<DenialSummaryDto>,
    last_transition: Option<LastTransitionDto>,
    host: HostFacts,
    /// What the `Armed` record carries as observations.
    armed_observations: Vec<Observation>,
}

// ---------------------------------------------------------------------------
// The shared state
// ---------------------------------------------------------------------------

struct ControlState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArmOutcome {
    pub epoch: u64,
    /// `false` for an arm of the profile that is already armed.
    pub changed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisarmOutcome {
    pub was_armed: bool,
    pub epoch: u64,
}

pub struct IngressShared {
    gate: watch::Sender<Gate>,
    /// FIFO; arm, recover and the bookkeeping half of disarm. It serialises
    /// operations and guards no data.
    control: Arc<AsyncMutex<ControlState>>,
    events: broadcast::Sender<Event>,
    status: Mutex<StatusInner>,
    counters: Counters,
    flows: FlowRegistry,
    /// The slot the host installs writers in.
    slot: Arc<LedgerSlot>,
    /// What arm, disarm and trip write to: the slot, or a double.
    ledger: Arc<dyn ControlLedger>,
    host: OnceLock<Arc<dyn HostControl>>,
    cfg: IngressCfgView,
    tuning: Tuning,
    /// A disarm during `Starting` cancels the autostart.
    autostart_cancelled: AtomicBool,
}

impl IngressShared {
    /// The gate starts `Disabled` when the section is off, otherwise `Starting`
    /// (the host publishes the outcome of its start with [`start_transition`]).
    ///
    /// [`start_transition`]: IngressShared::start_transition
    #[must_use]
    pub fn new(cfg: IngressCfgView, tuning: Tuning, events: broadcast::Sender<Event>) -> Arc<Self> {
        let slot = Arc::new(LedgerSlot::new());
        let ledger: Arc<dyn ControlLedger> = slot.clone();
        Self::with_ledger(cfg, tuning, events, slot, ledger)
    }

    /// With the control ledger of one's choosing (the tests' double).
    #[must_use]
    pub(crate) fn with_ledger(
        cfg: IngressCfgView,
        tuning: Tuning,
        events: broadcast::Sender<Event>,
        slot: Arc<LedgerSlot>,
        ledger: Arc<dyn ControlLedger>,
    ) -> Arc<Self> {
        let mode = if cfg.enabled {
            GateMode::Starting
        } else {
            GateMode::Disabled
        };
        let (gate, _) = watch::channel(Gate { epoch: 0, mode });
        Arc::new(Self {
            gate,
            control: Arc::new(AsyncMutex::new(ControlState)),
            events,
            status: Mutex::new(StatusInner::default()),
            counters: Counters::default(),
            flows: FlowRegistry::default(),
            slot,
            ledger,
            host: OnceLock::new(),
            cfg,
            tuning,
            autostart_cancelled: AtomicBool::new(false),
        })
    }

    // -- accessors ---------------------------------------------------------------------------

    #[must_use]
    pub fn gate(&self) -> watch::Receiver<Gate> {
        self.gate.subscribe()
    }

    fn gate_now(&self) -> Gate {
        self.gate.borrow().clone()
    }

    #[must_use]
    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    #[must_use]
    pub fn flows(&self) -> &FlowRegistry {
        &self.flows
    }

    #[must_use]
    pub fn ledger_slot(&self) -> &Arc<LedgerSlot> {
        &self.slot
    }

    #[must_use]
    pub fn cfg(&self) -> &IngressCfgView {
        &self.cfg
    }

    #[must_use]
    pub fn tuning(&self) -> &Tuning {
        &self.tuning
    }

    /// Host only: what `recover` calls. Set once.
    pub fn set_host(&self, host: Arc<dyn HostControl>) {
        let _ = self.host.set(host);
    }

    /// A disarm arrived while the ingress was starting: the autostart must not arm.
    #[must_use]
    pub fn autostart_cancelled(&self) -> bool {
        self.autostart_cancelled.load(Ordering::Acquire)
    }

    pub fn update_host_facts(&self, change: impl FnOnce(&mut HostFacts)) {
        change(&mut lock_unpoisoned(&self.status).host);
    }

    pub fn set_last_error(&self, error: Option<IpcError>) {
        lock_unpoisoned(&self.status).last_error = error;
    }

    pub fn set_last_denial(&self, denial: DenialSummaryDto) {
        lock_unpoisoned(&self.status).last_denial = Some(denial);
    }

    /// The observations the next `Armed` record carries.
    pub fn set_armed_observations(&self, observations: Vec<Observation>) {
        lock_unpoisoned(&self.status).armed_observations = observations;
    }

    // -- the write primitive -----------------------------------------------------------------

    /// The only way the gate changes (6.9.1). `expect_epoch` makes it a
    /// compare-and-set; `change` sees the current mode and returns the new one or
    /// `None` for "no write". The closure runs under the watch cell's write lock:
    /// it takes no lock and does no I/O. `Closing` is terminal. Returns the gate as
    /// written.
    pub(crate) fn cas<F>(&self, expect_epoch: Option<u64>, change: F) -> Option<Gate>
    where
        F: FnOnce(&GateMode) -> Option<GateMode>,
    {
        let mut applied = None;
        self.gate.send_if_modified(|gate| {
            if matches!(gate.mode, GateMode::Closing) {
                return false;
            }
            if expect_epoch.is_some_and(|epoch| epoch != gate.epoch) {
                return false;
            }
            let Some(mode) = change(&gate.mode) else {
                return false;
            };
            match gate.epoch.checked_add(1) {
                Some(next) => {
                    gate.epoch = next;
                    gate.mode = mode;
                }
                // 2^64 transitions: unreachable, but never a wrap.
                None => gate.mode = GateMode::Closing,
            }
            applied = Some(gate.clone());
            true
        });
        applied
    }

    /// The host's start task publishes its outcome (transition 1 of 6.1.2) with the
    /// epoch it read at its start; a shutdown or a trip that arrived meanwhile makes
    /// it lose.
    pub fn start_transition(&self, expected_epoch: u64, mode: GateMode) -> Option<Gate> {
        let kind = match &mode {
            GateMode::Unavailable(_) => "unavailable",
            _ => "started",
        };
        let reason = match &mode {
            GateMode::Unavailable(code) => code.as_code().to_owned(),
            _ => String::new(),
        };
        let applied = self.cas(Some(expected_epoch), |_| Some(mode));
        if let Some(gate) = &applied {
            self.note_transition(gate.epoch, kind, &reason, None);
        }
        applied
    }

    fn note_transition(&self, epoch: u64, kind: &str, reason: &str, actor: Option<&str>) {
        lock_unpoisoned(&self.status).last_transition = Some(LastTransitionDto {
            epoch,
            kind: kind.to_owned(),
            reason_code: reason.to_owned(),
            actor: actor.map(str::to_owned),
        });
    }

    fn emit(&self, code: &str, message: String) {
        // No receiver is not an error.
        let _ = self.events.send(Event::Warning {
            code: code.to_owned(),
            message,
        });
    }

    async fn lock_control(&self) -> Result<OwnedMutexGuard<ControlState>, IpcError> {
        tokio::time::timeout(
            self.tuning.control_lock_wait,
            Arc::clone(&self.control).lock_owned(),
        )
        .await
        .map_err(|_| err_busy())
    }

    /// Runs a control task to its end and maps a panic to a trip.
    async fn join_control<T>(&self, task: JoinHandle<Result<T, IpcError>>) -> Result<T, IpcError> {
        match task.await {
            Ok(result) => result,
            Err(error) => {
                if error.is_panic() {
                    self.trip(TripReason::ControlPanic);
                }
                Err(err_control_failed())
            }
        }
    }

    // -- arm -------------------------------------------------------------------------------------

    /// Arms `profile` (6.9.2). The caller has validated the id. The work runs in a
    /// spawned task, so a requester that goes away does not abandon it.
    ///
    /// # Errors
    /// `INGRESS_*` (11.14); nothing is armed.
    pub async fn arm(
        self: &Arc<Self>,
        profile: &str,
        actor: Actor,
    ) -> Result<ArmOutcome, IpcError> {
        let shared = Arc::clone(self);
        let profile: Arc<str> = Arc::from(profile);
        let task = tokio::spawn(async move { shared.arm_task(profile, actor).await });
        self.join_control(task).await
    }

    /// The 11.4 shortcut: the gate reads `Armed{profile}` AND nothing else is in
    /// control. Holds the lock only for the check.
    #[must_use]
    pub fn arm_would_be_noop(&self, profile: &str) -> bool {
        let armed = self.gate.borrow().mode.armed_profile() == Some(profile);
        armed && self.control.try_lock().is_ok()
    }

    async fn arm_task(
        self: Arc<Self>,
        profile: Arc<str>,
        actor: Actor,
    ) -> Result<ArmOutcome, IpcError> {
        let guard = self.lock_control().await?;
        let gate = self.gate_now();
        match &gate.mode {
            GateMode::Disabled => return Err(err_disabled()),
            GateMode::Starting => return Err(err_starting()),
            GateMode::Closing => return Err(err_stopping()),
            GateMode::Armed { profile: armed } if **armed == *profile => {
                return Ok(ArmOutcome {
                    epoch: gate.epoch,
                    changed: false,
                });
            }
            GateMode::Tripped(_) | GateMode::Unavailable(_) => {
                self.recover_locked(&guard).await?;
            }
            GateMode::Disarmed | GateMode::Armed { .. } => {}
        }
        self.arm_locked(&guard, &profile, &actor).await
    }

    async fn arm_locked(
        &self,
        _guard: &OwnedMutexGuard<ControlState>,
        profile: &Arc<str>,
        actor: &Actor,
    ) -> Result<ArmOutcome, IpcError> {
        let Some(facts) = self.cfg.armed.get(&**profile) else {
            return Err(err_argument("the profile is not configured"));
        };
        // Read after any recover. A mode that is not armable now (a trip or a
        // shutdown arrived since) ends the arm here, before anything is written.
        let from = self.gate_now();
        match &from.mode {
            GateMode::Disarmed | GateMode::Armed { .. } => {}
            other => return Err(err_after_loss(other)),
        }
        let Some(next_epoch) = from.epoch.checked_add(1) else {
            self.close();
            return Err(err_stopping());
        };
        let observations = lock_unpoisoned(&self.status).armed_observations.clone();
        let event = ArmedEvent {
            actor: actor.clone(),
            profile: profile.to_string(),
            epoch: next_epoch,
            profile_digest: facts.profile_digest.clone(),
            rules: facts.rules.clone(),
            observations,
        };
        let waits = Waits {
            queue_wait: self.tuning.audit_queue_wait,
            sync_wait: self.tuning.audit_sync_wait,
        };
        let receipt = match self.ledger.append_armed(event, waits).await {
            Ok(receipt) => receipt,
            Err(error) => return Err(err_audit(error, self.writer_stalled())),
        };
        let armed = GateMode::Armed {
            profile: Arc::clone(profile),
        };
        match self.cas(Some(from.epoch), move |_| Some(armed)) {
            Some(gate) => {
                receipt.applied();
                self.note_transition(gate.epoch, "armed", "", Some(actor.requested_by()));
                self.set_last_error(None);
                self.emit(
                    INGRESS_ARMED,
                    format!("the local proxy was armed for profile `{profile}`"),
                );
                Ok(ArmOutcome {
                    epoch: gate.epoch,
                    changed: true,
                })
            }
            None => {
                // A trip, a disarm or a shutdown won: the durable `Armed` is
                // closed by a `Disarmed{arm_superseded}` on the compensation channel.
                receipt.superseded();
                Err(err_after_loss(&self.gate_now().mode))
            }
        }
    }

    /// The writer's disk part has been running longer than the stall bound.
    fn writer_stalled(&self) -> bool {
        self.ledger
            .io_in_progress_for()
            .is_some_and(|running| running >= self.tuning.audit_stall_trip)
    }

    // -- disarm -----------------------------------------------------------------------------------

    /// Disarms (6.9.2). The effect is first, lock-free and cannot fail; the record
    /// follows. It bumps the epoch even when the gate is already disarmed, tripped
    /// or unavailable: an arm that waits for its fsync captured the old epoch.
    pub async fn disarm(self: &Arc<Self>, cause: DisarmCause) -> DisarmOutcome {
        let mut was_armed = false;
        let applied = self.cas(None, |mode| match mode {
            GateMode::Armed { .. } => {
                was_armed = true;
                Some(GateMode::Disarmed)
            }
            GateMode::Disarmed | GateMode::Tripped(_) | GateMode::Unavailable(_) => {
                Some(mode.clone())
            }
            // No arm or recover can be in flight, and a bump would make the start
            // task's own compare-and-set fail.
            GateMode::Starting | GateMode::Disabled | GateMode::Closing => None,
        });
        let Some(gate) = applied else {
            let gate = self.gate_now();
            if matches!(gate.mode, GateMode::Starting) {
                self.autostart_cancelled.store(true, Ordering::Release);
            }
            return DisarmOutcome {
                was_armed: false,
                epoch: gate.epoch,
            };
        };
        self.note_transition(gate.epoch, "disarmed", cause.as_str(), None);
        if was_armed {
            // The record is bookkeeping: it runs to its end even if the requester
            // goes away, and it never changes the answer.
            let shared = Arc::clone(self);
            let epoch = gate.epoch;
            let task = tokio::spawn(async move { shared.disarm_record(cause, epoch).await });
            if let Err(error) = task.await {
                if error.is_panic() {
                    self.trip(TripReason::ControlPanic);
                }
            }
            self.emit(
                INGRESS_DISARMED,
                format!("the local proxy was disarmed ({})", cause.as_str()),
            );
        }
        DisarmOutcome {
            was_armed,
            epoch: gate.epoch,
        }
    }

    async fn disarm_record(&self, cause: DisarmCause, epoch: u64) {
        let lock = tokio::time::timeout(
            self.tuning.disarm_bookkeeping_wait,
            Arc::clone(&self.control).lock_owned(),
        )
        .await;
        let written = match lock {
            Ok(_guard) => {
                self.ledger
                    .append_disarmed(DisarmedEvent { cause, epoch }, self.tuning.closed_deadline)
                    .await
            }
            Err(_) => false,
        };
        if !written {
            Counters::bump(&self.counters.disarm_record_lost);
        }
    }

    // -- trip ---------------------------------------------------------------------------------------

    /// A fault latches the gate (6.1.3). Synchronous and callable from any thread,
    /// including the audit writer's: it never awaits and never takes `control`.
    pub fn trip(&self, why: TripReason) {
        let applied = self.cas(None, |mode| match mode {
            GateMode::Armed { .. } | GateMode::Disarmed => Some(GateMode::Tripped(why)),
            GateMode::Starting => Some(GateMode::Unavailable(UnavailableCode::from_trip(why))),
            GateMode::Tripped(_)
            | GateMode::Unavailable(_)
            | GateMode::Disabled
            | GateMode::Closing => None,
        });
        let Some(gate) = applied else {
            return;
        };
        Counters::bump(&self.counters.trips);
        self.note_transition(gate.epoch, "tripped", why.as_str(), None);
        lock_unpoisoned(&self.status).last_error = Some(
            IpcError::new(
                "Runtime",
                INGRESS_TRIPPED,
                format!("the local proxy stopped: {}", why.as_str()),
            )
            .with_next_step("Arm again to recover."),
        );
        self.emit(
            INGRESS_TRIPPED,
            format!("the local proxy stopped: {}", why.as_str()),
        );
        // Where the writer itself failed, the record cannot be written.
        if why != TripReason::AuditWriteFailed {
            let _ = self.ledger.try_enqueue_tripped(TrippedEvent {
                reason: why,
                epoch: gate.epoch,
            });
        }
    }

    // -- recover ------------------------------------------------------------------------------------

    /// Brings a tripped or recoverably unavailable ingress back to `Disarmed`
    /// (6.9.2), single-flight and all or nothing.
    ///
    /// # Errors
    /// `INGRESS_*`; the gate is as it was, or `Unavailable` with the most specific
    /// code.
    pub async fn recover(self: &Arc<Self>) -> Result<(), IpcError> {
        let shared = Arc::clone(self);
        let task = tokio::spawn(async move {
            let guard = shared.lock_control().await?;
            shared.recover_locked(&guard).await
        });
        self.join_control(task).await
    }

    /// The guard is the witness that `control` is held.
    async fn recover_locked(&self, _guard: &OwnedMutexGuard<ControlState>) -> Result<(), IpcError> {
        let gate = self.gate_now();
        match &gate.mode {
            GateMode::Tripped(_) => {}
            GateMode::Unavailable(code) if code.recoverable() => {}
            GateMode::Unavailable(code) => return Err(err_unavailable(*code)),
            GateMode::Closing => return Err(err_stopping()),
            GateMode::Starting => return Err(err_starting()),
            GateMode::Disabled => return Err(err_disabled()),
            // Nothing to recover.
            GateMode::Disarmed | GateMode::Armed { .. } => return Ok(()),
        }
        let e0 = gate.epoch;
        let Some(host) = self.host.get().cloned() else {
            return Err(err_recovery_failed(
                UnavailableCode::RecoveryFailed,
                "no host to recover with",
            ));
        };
        match host.recover().await {
            Ok(()) => match self.cas(Some(e0), |_| Some(GateMode::Disarmed)) {
                Some(gate) => {
                    self.note_transition(gate.epoch, "recovered", "", None);
                    self.set_last_error(None);
                    self.emit(
                        INGRESS_RECOVERED,
                        "the local proxy recovered and is disarmed".to_owned(),
                    );
                    Ok(())
                }
                None => Err(err_after_loss(&self.gate_now().mode)),
            },
            Err(RecoverError::Busy) => Err(err_busy()),
            Err(RecoverError::Stalled) => Err(err_audit(AuditError::Timeout, true)),
            Err(RecoverError::Unavailable(code, cause)) => {
                if let Some(gate) = self.cas(Some(e0), |_| Some(GateMode::Unavailable(code))) {
                    self.note_transition(gate.epoch, "unavailable", code.as_code(), None);
                }
                let error = err_recovery_failed(code, &cause);
                self.set_last_error(Some(error.clone()));
                Err(error)
            }
        }
    }

    // -- close --------------------------------------------------------------------------------------

    /// Terminal: nothing changes the gate after this.
    pub fn close(&self) {
        if let Some(gate) = self.cas(None, |_| Some(GateMode::Closing)) {
            self.note_transition(gate.epoch, "stopping", "", None);
        }
    }

    // -- flows ---------------------------------------------------------------------------------------

    #[must_use]
    pub fn recent_flows(&self, limit: usize) -> Vec<FlowSummaryDto> {
        self.flows.recent(limit)
    }

    /// # Errors
    /// `FLOW_NOT_RETAINED` or `FLOW_NOT_FOUND`.
    pub fn inspect(&self, flow_id: &str) -> Result<FlowInspectionDto, IpcError> {
        self.flows.inspect(flow_id)
    }

    // -- status -----------------------------------------------------------------------------------------

    /// The ingress block of the status (10.4). No await, no tokio lock, no file I/O;
    /// it never waits for `control`.
    #[must_use]
    pub fn snapshot(&self) -> IngressStatusDto {
        let gate = self.gate_now();
        let (host, last_error, last_denial, last_transition) = {
            let status = lock_unpoisoned(&self.status);
            (
                status.host.clone(),
                status.last_error.clone(),
                status.last_denial.clone(),
                status.last_transition.clone(),
            )
        };
        let installed = self.slot.current();
        let audit_status = installed.as_ref().map(|i| i.writer.status());
        let stalled = self.writer_stalled();
        let writer_ok = audit_status
            .as_ref()
            .is_some_and(|status| status.state == WriterState::Ok);

        let hardening_ok = match self.cfg.hardening {
            IngressHardening::Required => {
                host.controls.exclusive_bind
                    && host.controls.peer_check
                    && host.controls.private_audit_store
            }
            IngressHardening::BestEffort => true,
        };
        // `armed` is computed, never stored (10.1).
        let healthy = host.accept_alive && writer_ok && hardening_ok;
        let armed_profile = gate.mode.armed_profile().map(str::to_owned);
        let demoted = armed_profile.is_some() && !healthy;
        let (state, coverage, retry_hint) = if demoted {
            ("tripped", "none", Some("re-arm to recover".to_owned()))
        } else {
            (
                gate.mode.state().as_str(),
                gate.mode.coverage_if_healthy().as_str(),
                gate.mode.retry_hint().map(str::to_owned),
            )
        };

        let listen = host.listen.map(|addr| addr.to_string());
        let bound = listen.is_some();
        let limits = host.limits.unwrap_or(EffectiveLimits {
            max_connections: self.cfg.limits.max_connections,
            ..EffectiveLimits::default()
        });
        let warnings = self.warnings(&host, bound, audit_status.as_ref());

        IngressStatusDto {
            state: state.to_owned(),
            coverage: coverage.to_owned(),
            system_wide: false,
            notice: INGRESS_COVERAGE_NOTICE.to_owned(),
            listen,
            configured_listen: self.cfg.enabled.then(|| self.cfg.listen.to_string()),
            protocols: self
                .cfg
                .protocols
                .iter()
                .map(|p| p.name().to_owned())
                .collect(),
            armed_profile: if demoted { None } else { armed_profile },
            arm_profile: self
                .cfg
                .enabled
                .then(|| self.cfg.default_profile.to_string()),
            controls: IngressControlsDto {
                exclusive_bind: host.controls.exclusive_bind,
                peer_check: host.controls.peer_check,
                private_audit_store: host.controls.private_audit_store,
                hardening: match self.cfg.hardening {
                    IngressHardening::Required => "required",
                    IngressHardening::BestEffort => "best_effort",
                }
                .to_owned(),
            },
            counters: self.counters.dto(),
            audit: self.audit_dto(&gate.mode, audit_status.as_ref(), stalled),
            last_error,
            last_denial,
            retry_hint,
            epoch: gate.epoch,
            trips: self.counters.trips.load(Ordering::Relaxed),
            last_transition,
            phase: host.phase.clone(),
            limits: IngressLimitsDto {
                max_connections: self.cfg.limits.max_connections,
                max_connections_effective: limits.max_connections,
                accept_rate_per_s: self.cfg.limits.accept_rate_per_s,
                clamped_by: limits.clamped_by_fd_limit.then(|| "fd_limit".to_owned()),
                fd_soft_limit: limits.fd_soft_limit,
                fd_needed: limits.fd_needed,
            },
            config: ConfigDigestsDto {
                config: self.cfg.fingerprint.config.clone(),
                routing: self.cfg.fingerprint.routing.clone(),
                ingress: self.cfg.fingerprint.ingress.clone(),
            },
            egress: IngressEgressDto {
                binds_interface: false,
                binds_source_address: false,
                direct_resolver: "operating_system".to_owned(),
                direct_address_families: match self.cfg.families {
                    DirectAddressFamilies::Ipv4Only => "ipv4_only",
                    DirectAddressFamilies::Any => "any",
                }
                .to_owned(),
            },
            observations: host.observations,
            warnings,
        }
    }

    fn audit_dto(
        &self,
        mode: &GateMode,
        status: Option<&AuditStatus>,
        stalled: bool,
    ) -> IngressAuditDto {
        let logging = match self.cfg.destination_logging {
            ssk_config::ingress::DestinationLogging::Plain => "plain",
            ssk_config::ingress::DestinationLogging::Hashed => "hashed",
        };
        let dir_sync = if cfg!(unix) { "fsync" } else { "unavailable" };
        let Some(status) = status else {
            let state = match mode {
                GateMode::Starting => "starting",
                GateMode::Unavailable(UnavailableCode::AuditCorrupt) => "corrupt",
                GateMode::Closing => "closing",
                _ => "unavailable",
            };
            return IngressAuditDto {
                state: state.to_owned(),
                destination_logging: logging.to_owned(),
                dir_sync: dir_sync.to_owned(),
                ..IngressAuditDto::default()
            };
        };
        let state = match status.state {
            WriterState::Ok if stalled => "stalled",
            WriterState::Ok => "ok",
            WriterState::Closing => "closing",
            WriterState::Down => "tripped",
        };
        IngressAuditDto {
            state: state.to_owned(),
            entries: status.entries,
            head: Some(status.head.clone()),
            segments: status.segments,
            bytes: status.bytes,
            oldest_ts_ms: status.oldest_ts_ms,
            pruned_entries: status.pruned_entries,
            prune_deferred: status.prune_deferred,
            destination_logging: logging.to_owned(),
            dest_key_id: status.dest_key_id.clone(),
            refusal_quota_used_percent: status.refusal_quota_used_percent,
            denials_over_quota: status.denials_over_quota,
            busy: status.busy,
            timeouts: status.timeouts,
            sync_last_ms: status.sync_last_ms,
            sync_max_ms: status.sync_max_ms,
            dir_sync: dir_sync.to_owned(),
        }
    }

    /// The warnings of 10.5 that this module can derive (`KILL_SWITCH_ENGAGED` is
    /// the supervisor's). The clock for the window is the wall clock and is
    /// advisory.
    fn warnings(
        &self,
        host: &HostFacts,
        bound: bool,
        audit: Option<&AuditStatus>,
    ) -> Vec<IngressWarningDto> {
        let mut codes: Vec<&'static str> = Vec::new();
        if bound {
            if !host.controls.peer_check {
                codes.push(WARNING_PEER_CHECK_INACTIVE);
            }
            if !host.controls.exclusive_bind {
                codes.push(WARNING_EXCLUSIVE_BIND_INACTIVE);
            }
            if !host.controls.private_audit_store {
                codes.push(WARNING_AUDIT_STORE_NOT_PRIVATE);
            }
        }
        let obs = &host.observations;
        if route_changed_recently(&obs.route_v4) || route_changed_recently(&obs.route_v6) {
            codes.push(WARNING_OS_ROUTE_CHANGED);
        }
        if self.cfg.families == DirectAddressFamilies::Any && obs.route_v6.status == "observed" {
            codes.push(WARNING_DIRECT_MAY_USE_IPV6);
        }
        if matches!(obs.route_v4.status.as_str(), "unsupported" | "failed") {
            codes.push(WARNING_OBSERVATION_UNAVAILABLE);
        }
        if audit.is_some_and(|a| audit_window_short(a.pruned_entries, a.oldest_ts_ms, wall_ms())) {
            codes.push(WARNING_AUDIT_WINDOW_SHORT);
        }
        codes
            .into_iter()
            .filter_map(|code| {
                warning_text(code).map(|text| IngressWarningDto {
                    code: code.to_owned(),
                    text: text.to_owned(),
                })
            })
            .collect()
    }
}

/// The probe's route changed, and less than ten minutes ago (10.5).
fn route_changed_recently(route: &ssk_ipc::ObservedRouteDto) -> bool {
    route.previous.is_some()
        && route
            .unchanged_for_ms
            .is_some_and(|ms| ms < OS_ROUTE_CHANGED_WINDOW_MS)
}

/// Records were removed by size retention and the oldest one that remains is less
/// than a day old (advisory: the clock is untrusted).
fn audit_window_short(pruned_entries: u64, oldest_ts_ms: Option<u64>, now_ms: u64) -> bool {
    pruned_entries > 0
        && oldest_ts_ms.is_some_and(|oldest| now_ms.saturating_sub(oldest) < AUDIT_WINDOW_MS)
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::atomic::AtomicUsize;

    use tokio::sync::Notify;

    use crate::ingress::audit::dest::DestSealer;
    use crate::ingress::audit::fs_unix::UnixLedgerFs;
    use crate::ingress::audit::open::open_dir;
    use crate::ingress::audit::record::FlowAuditEvent;
    use crate::ingress::audit::writer::{system_clock, AuditOpenCfg, SUMMARY_FLOOR};
    use crate::ingress::types::{ClientLabel, TripReason};
    use crate::lock::LockProof;

    const SHORT: Duration = Duration::from_secs(10);

    fn operator() -> Actor {
        Actor::Operator {
            peer: Some(Arc::from("uid:1000")),
            client: ClientLabel::Cli,
        }
    }

    /// The ledger of the control plane with barriers: `append_armed` can be held
    /// inside the call, so that a disarm, a trip or a close can win the race on
    /// purpose. Everything else is the real writer.
    struct GatedLedger {
        inner: Arc<LedgerSlot>,
        hold_arm: AtomicBool,
        panic_arm: AtomicBool,
        arm_entered: Notify,
        arm_release: Notify,
        delay: Mutex<Duration>,
        /// What the arm was asked to wait for, and a failure to answer it with.
        last_waits: Mutex<Option<Waits>>,
        fail_arm: Mutex<Option<AuditError>>,
        /// An override of how long the writer's disk part has been running.
        stalled_for: Mutex<Option<Duration>>,
        armed_calls: AtomicUsize,
        disarmed: Mutex<Vec<(DisarmCause, u64)>>,
        tripped: Mutex<Vec<TrippedEvent>>,
    }

    impl GatedLedger {
        fn new(inner: Arc<LedgerSlot>) -> Arc<Self> {
            Arc::new(Self {
                inner,
                hold_arm: AtomicBool::new(false),
                panic_arm: AtomicBool::new(false),
                arm_entered: Notify::new(),
                arm_release: Notify::new(),
                delay: Mutex::new(Duration::ZERO),
                last_waits: Mutex::new(None),
                fail_arm: Mutex::new(None),
                stalled_for: Mutex::new(None),
                armed_calls: AtomicUsize::new(0),
                disarmed: Mutex::new(Vec::new()),
                tripped: Mutex::new(Vec::new()),
            })
        }
    }

    impl ControlLedger for GatedLedger {
        fn append_armed(
            &self,
            record: ArmedEvent,
            waits: Waits,
        ) -> BoxFuture<'_, Result<ArmReceipt, AuditError>> {
            Box::pin(async move {
                self.armed_calls.fetch_add(1, Ordering::SeqCst);
                if self.panic_arm.load(Ordering::SeqCst) {
                    panic!("the ledger double was told to panic");
                }
                if self.hold_arm.load(Ordering::SeqCst) {
                    self.arm_entered.notify_one();
                    self.arm_release.notified().await;
                }
                *lock_unpoisoned(&self.last_waits) = Some(waits);
                let delay = *lock_unpoisoned(&self.delay);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                if let Some(error) = *lock_unpoisoned(&self.fail_arm) {
                    return Err(error);
                }
                self.inner.append_armed(record, waits).await
            })
        }

        fn append_disarmed(&self, record: DisarmedEvent, bounded: Duration) -> BoxFuture<'_, bool> {
            Box::pin(async move {
                lock_unpoisoned(&self.disarmed).push((record.cause, record.epoch));
                self.inner.append_disarmed(record, bounded).await
            })
        }

        fn try_enqueue_tripped(&self, record: TrippedEvent) -> bool {
            lock_unpoisoned(&self.tripped).push(record);
            self.inner.try_enqueue_tripped(record)
        }

        fn io_in_progress_for(&self) -> Option<Duration> {
            (*lock_unpoisoned(&self.stalled_for)).or_else(|| self.inner.io_in_progress_for())
        }
    }

    /// A host that answers `recover` as told, and can be held inside the call.
    struct FakeHost {
        result: Mutex<Result<(), RecoverError>>,
        hold: AtomicBool,
        entered: Notify,
        release: Notify,
        calls: AtomicUsize,
    }

    impl FakeHost {
        fn new(result: Result<(), RecoverError>) -> Arc<Self> {
            Arc::new(Self {
                result: Mutex::new(result),
                hold: AtomicBool::new(false),
                entered: Notify::new(),
                release: Notify::new(),
                calls: AtomicUsize::new(0),
            })
        }
    }

    impl HostControl for FakeHost {
        fn recover(&self) -> BoxFuture<'_, Result<(), RecoverError>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if self.hold.load(Ordering::SeqCst) {
                    self.entered.notify_one();
                    self.release.notified().await;
                }
                lock_unpoisoned(&self.result).clone()
            })
        }
    }

    struct Rig {
        dir: tempfile::TempDir,
        shared: Arc<IngressShared>,
        ledger: Arc<GatedLedger>,
        events: broadcast::Receiver<Event>,
    }

    impl Rig {
        fn writer(&self) -> Arc<FlowAuditWriter> {
            self.shared.slot.current().expect("a writer").writer
        }

        /// Everything the ledger holds, oldest first. Waits for what was queued.
        async fn records(&self) -> Vec<FlowAuditEvent> {
            self.writer().flush(SHORT).await.expect("flushed");
            ledger_events(self.dir.path())
        }

        fn mode(&self) -> GateMode {
            self.shared.gate_now().mode
        }
    }

    fn ledger_events(root: &Path) -> Vec<FlowAuditEvent> {
        let dir = root.join("ingress-audit");
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .expect("list")
            .map(|e| e.expect("entry").file_name())
            .collect();
        names.sort();
        let mut out = Vec::new();
        for name in names {
            let bytes = std::fs::read(dir.join(name)).expect("read");
            for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                let record: crate::ingress::audit::record::FlowAuditRecord =
                    serde_json::from_slice(line.get(65..).expect("a line")).expect("a record");
                out.push(record.event);
            }
        }
        out
    }

    fn kinds(events: &[FlowAuditEvent]) -> Vec<&'static str> {
        events.iter().map(FlowAuditEvent::kind).collect()
    }

    fn open_cfg() -> AuditOpenCfg {
        AuditOpenCfg {
            segment_bytes: 1 << 20,
            retain_segments: 4,
            denied_share_percent: 20,
            summary_share_percent: 5,
            destination_logging: ssk_config::ingress::DestinationLogging::Plain,
            fingerprint: IngressCfgView::for_tests().fingerprint,
            daemon_version: "0.0.0-test".to_owned(),
            queue_cap: 256,
            summary_floor: SUMMARY_FLOOR,
            clock: system_clock(),
        }
    }

    fn cfg_with_two_profiles() -> IngressCfgView {
        let mut cfg = IngressCfgView::for_tests();
        let mut facts = cfg.armed.get("main").expect("main").clone();
        // The second profile has facts of its own, rules included, so that a record
        // that carries the wrong ones is noticed.
        facts.profile_digest = "d".repeat(64);
        facts.rules = ssk_config::fingerprint::RuleTable {
            total: 1,
            truncated: false,
            rules: vec![ssk_config::fingerprint::RuleRow {
                id: "rule-1".to_owned(),
                priority: 10,
                action: "direct".to_owned(),
                attestation: false,
                exact_destination: false,
                suffix: true,
                port: Some(443),
            }],
        };
        let mut armed: BTreeMap<Arc<str>, _> = (*cfg.armed).clone();
        armed.insert(Arc::from("alt"), facts);
        cfg.armed = Arc::new(armed);
        cfg.profile_ids.push(Arc::from("alt"));
        cfg
    }

    fn fast_tuning() -> Tuning {
        Tuning {
            control_lock_wait: Duration::from_millis(400),
            disarm_bookkeeping_wait: Duration::from_millis(400),
            ..Tuning::default()
        }
    }

    fn healthy_host(shared: &IngressShared) {
        shared.update_host_facts(|facts| {
            facts.accept_alive = true;
            facts.controls = Controls {
                exclusive_bind: true,
                peer_check: true,
                private_audit_store: true,
            };
            facts.listen = Some("127.0.0.1:10800".parse().expect("addr"));
        });
    }

    /// A control plane over a real writer in a temporary directory, gate `Disarmed`.
    async fn rig_with(cfg: IngressCfgView, tuning: Tuning) -> Rig {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        let slot = Arc::new(LedgerSlot::new());
        let ledger = GatedLedger::new(Arc::clone(&slot));
        let (tx, events) = broadcast::channel(64);
        let shared = IngressShared::with_ledger(cfg, tuning, tx, Arc::clone(&slot), ledger.clone());
        let on_trip: crate::ingress::audit::writer::TripFn = {
            let shared = Arc::clone(&shared);
            Arc::new(move |reason| shared.trip(reason))
        };
        let fs = UnixLedgerFs::new(dir.path().to_path_buf());
        let writer = open_dir(
            LockProof::for_tests(),
            &fs,
            &open_cfg(),
            DestSealer::Plain,
            None,
            on_trip,
        )
        .expect("opens");
        slot.install(Installed {
            writer: Arc::new(writer),
            boot: Arc::from("b1"),
        });
        healthy_host(&shared);
        let started = shared.start_transition(0, GateMode::Disarmed);
        assert!(started.is_some());
        Rig {
            dir,
            shared,
            ledger,
            events,
        }
    }

    async fn rig() -> Rig {
        rig_with(cfg_with_two_profiles(), fast_tuning()).await
    }

    async fn arm_task(
        rig: &Rig,
        profile: &'static str,
    ) -> JoinHandle<Result<ArmOutcome, IpcError>> {
        let shared = Arc::clone(&rig.shared);
        tokio::spawn(async move { shared.arm(profile, operator()).await })
    }

    fn code(result: Result<ArmOutcome, IpcError>) -> String {
        result.expect_err("refused").code
    }

    // -- the happy path and its records ------------------------------------------------------------

    #[tokio::test]
    async fn arm_writes_armed_before_the_gate_opens_and_a_second_arm_of_the_same_profile_is_a_noop()
    {
        let mut rig = rig().await;
        let outcome = rig.shared.arm("main", operator()).await.expect("armed");
        assert!(outcome.changed);
        assert_eq!(
            rig.mode(),
            GateMode::Armed {
                profile: Arc::from("main")
            }
        );
        assert_eq!(rig.shared.gate_now().epoch, outcome.epoch);
        let events = rig.records().await;
        assert_eq!(kinds(&events), ["started", "armed"]);
        match &events[1] {
            FlowAuditEvent::Armed {
                profile,
                cause,
                client,
                requested_by,
                epoch,
                ..
            } => {
                assert_eq!(profile, "main");
                assert_eq!((cause.as_str(), client.as_str()), ("operator", "cli"));
                assert_eq!(requested_by, "uid:1000");
                assert_eq!(
                    *epoch, outcome.epoch,
                    "the record names the epoch the gate took"
                );
            }
            other => panic!("not Armed: {other:?}"),
        }
        // Arming it again changes nothing: no epoch, no record, no event.
        let again = rig.shared.arm("main", operator()).await.expect("armed");
        assert_eq!(
            again,
            ArmOutcome {
                epoch: outcome.epoch,
                changed: false
            }
        );
        assert_eq!(kinds(&rig.records().await), ["started", "armed"]);
        assert_eq!(rig.ledger.armed_calls.load(Ordering::SeqCst), 1);
        // The event of the first arm, and no second one.
        match rig.events.try_recv().expect("an event") {
            Event::Warning { code, .. } => assert_eq!(code, INGRESS_ARMED),
            other => panic!("{other:?}"),
        }
        assert!(rig.events.try_recv().is_err());
    }

    #[tokio::test]
    async fn arming_another_profile_re_arms_and_records_it() {
        let rig = rig().await;
        rig.shared.arm("main", operator()).await.expect("armed");
        let outcome = rig.shared.arm("alt", operator()).await.expect("armed");
        assert!(outcome.changed);
        assert_eq!(
            rig.mode(),
            GateMode::Armed {
                profile: Arc::from("alt")
            }
        );
        assert_eq!(kinds(&rig.records().await), ["started", "armed", "armed"]);
    }

    #[tokio::test]
    async fn an_unknown_profile_is_an_argument_error_and_writes_nothing() {
        let rig = rig().await;
        let error = rig
            .shared
            .arm("nope", operator())
            .await
            .expect_err("refused");
        assert_eq!(error.code, INGRESS_ARGUMENT);
        assert_eq!(rig.ledger.armed_calls.load(Ordering::SeqCst), 0);
        assert_eq!(rig.mode(), GateMode::Disarmed);
    }

    #[tokio::test]
    async fn disarm_bumps_the_epoch_even_when_already_disarmed_and_records_only_an_armed_gate() {
        let mut rig = rig().await;
        let e0 = rig.shared.gate_now().epoch;
        let first = rig.shared.disarm(DisarmCause::Operator).await;
        assert_eq!(
            first,
            DisarmOutcome {
                was_armed: false,
                epoch: e0 + 1
            }
        );
        let second = rig.shared.disarm(DisarmCause::Operator).await;
        assert_eq!(second.epoch, e0 + 2);
        assert!(rig.ledger.disarmed.lock().expect("lock").is_empty());
        assert!(
            rig.events.try_recv().is_err(),
            "nothing was armed: no event"
        );

        rig.shared.arm("main", operator()).await.expect("armed");
        let _ = rig.events.try_recv();
        let armed = rig.shared.gate_now().epoch;
        let outcome = rig.shared.disarm(DisarmCause::Operator).await;
        assert_eq!(
            outcome,
            DisarmOutcome {
                was_armed: true,
                epoch: armed + 1
            }
        );
        assert_eq!(rig.mode(), GateMode::Disarmed);
        assert_eq!(
            *rig.ledger.disarmed.lock().expect("lock"),
            [(DisarmCause::Operator, armed + 1)]
        );
        assert_eq!(
            kinds(&rig.records().await),
            ["started", "armed", "disarmed"]
        );
        match rig.events.try_recv().expect("an event") {
            Event::Warning { code, .. } => assert_eq!(code, INGRESS_DISARMED),
            other => panic!("{other:?}"),
        }
    }

    // -- the races ------------------------------------------------------------------------------------

    #[tokio::test]
    async fn arm_in_flight_loses_to_disarm() {
        let rig = rig().await;
        rig.ledger.hold_arm.store(true, Ordering::SeqCst);
        let arm = arm_task(&rig, "main").await;
        rig.ledger.arm_entered.notified().await;
        // The gate still reads Disarmed while the arm waits for its fsync; the
        // disarm must not be answered from that read. It answers at once.
        let before = rig.shared.gate_now().epoch;
        let disarm = rig.shared.disarm(DisarmCause::Operator).await;
        assert!(!disarm.was_armed);
        assert_eq!(disarm.epoch, before + 1);
        rig.ledger.arm_release.notify_one();
        let result = arm.await.expect("joined");
        assert_eq!(code(result), INGRESS_SUPERSEDED);
        assert_eq!(rig.mode(), GateMode::Disarmed);
        let events = rig.records().await;
        assert_eq!(kinds(&events), ["started", "armed", "disarmed"]);
        match &events[2] {
            FlowAuditEvent::Disarmed { cause, .. } => assert_eq!(cause, "arm_superseded"),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn arm_in_flight_loses_to_trip_and_reports_tripped() {
        let rig = rig().await;
        rig.ledger.hold_arm.store(true, Ordering::SeqCst);
        let arm = arm_task(&rig, "main").await;
        rig.ledger.arm_entered.notified().await;
        rig.shared.trip(TripReason::AcceptFatal);
        rig.ledger.arm_release.notify_one();
        assert_eq!(code(arm.await.expect("joined")), INGRESS_TRIPPED);
        assert_eq!(rig.mode(), GateMode::Tripped(TripReason::AcceptFatal));
        let events = rig.records().await;
        assert_eq!(kinds(&events), ["started", "tripped", "armed", "disarmed"]);
    }

    #[tokio::test]
    async fn arm_in_flight_loses_to_close_and_reports_stopping() {
        let rig = rig().await;
        rig.ledger.hold_arm.store(true, Ordering::SeqCst);
        let arm = arm_task(&rig, "main").await;
        rig.ledger.arm_entered.notified().await;
        rig.shared.close();
        rig.ledger.arm_release.notify_one();
        assert_eq!(code(arm.await.expect("joined")), INGRESS_STOPPING);
        assert_eq!(rig.mode(), GateMode::Closing);
    }

    #[tokio::test]
    async fn closing_is_terminal() {
        let rig = rig().await;
        rig.shared.close();
        let epoch = rig.shared.gate_now().epoch;
        rig.shared.trip(TripReason::AcceptFatal);
        let outcome = rig.shared.disarm(DisarmCause::Operator).await;
        assert_eq!(outcome.epoch, epoch);
        assert_eq!(
            code(rig.shared.arm("main", operator()).await),
            INGRESS_STOPPING
        );
        assert!(rig.shared.recover().await.is_err());
        assert_eq!(rig.mode(), GateMode::Closing);
        assert_eq!(rig.shared.gate_now().epoch, epoch);
        // And closing it again is not a transition.
        rig.shared.close();
        assert_eq!(rig.shared.gate_now().epoch, epoch);
        let transition = rig.shared.snapshot().last_transition.expect("one");
        assert_eq!(
            (transition.kind.as_str(), transition.epoch),
            ("stopping", epoch)
        );
        assert_eq!(rig.shared.snapshot().state, "stopping");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn trip_never_waits_for_the_control_lock() {
        let rig = rig().await;
        rig.ledger.hold_arm.store(true, Ordering::SeqCst);
        let arm = arm_task(&rig, "main").await;
        rig.ledger.arm_entered.notified().await;
        // The control lock is held by the blocked arm. A trip from a plain thread
        // is applied at once.
        let shared = Arc::clone(&rig.shared);
        let tripper = std::thread::spawn(move || {
            let began = std::time::Instant::now();
            shared.trip(TripReason::AuditWriteFailed);
            began.elapsed()
        });
        let took = tripper.join().expect("joined");
        assert!(took < Duration::from_millis(50), "{took:?}");
        assert_eq!(rig.mode(), GateMode::Tripped(TripReason::AuditWriteFailed));
        rig.ledger.arm_release.notify_one();
        assert_eq!(code(arm.await.expect("joined")), INGRESS_TRIPPED);
    }

    #[tokio::test]
    async fn status_snapshot_never_waits_for_the_control_lock() {
        let rig = rig().await;
        rig.ledger.hold_arm.store(true, Ordering::SeqCst);
        let arm = arm_task(&rig, "main").await;
        rig.ledger.arm_entered.notified().await;
        // A plain call, on the one thread that would be needed to release the arm.
        let status = rig.shared.snapshot();
        assert_eq!(status.state, "disarmed");
        rig.ledger.arm_release.notify_one();
        arm.await.expect("joined").expect("armed");
        assert_eq!(rig.shared.snapshot().state, "armed");
    }

    #[tokio::test]
    async fn an_arm_that_cannot_get_the_control_lock_is_busy_and_has_no_effect() {
        let rig = rig().await;
        rig.ledger.hold_arm.store(true, Ordering::SeqCst);
        let first = arm_task(&rig, "main").await;
        rig.ledger.arm_entered.notified().await;
        let calls = rig.ledger.armed_calls.load(Ordering::SeqCst);
        let second = rig.shared.arm("alt", operator()).await;
        assert_eq!(code(second), INGRESS_BUSY);
        assert!(!rig.shared.arm_would_be_noop("main"), "the lock is held");
        assert_eq!(rig.ledger.armed_calls.load(Ordering::SeqCst), calls);
        rig.ledger.arm_release.notify_one();
        first.await.expect("joined").expect("armed");
    }

    #[tokio::test]
    async fn control_tasks_survive_requester_drop() {
        let rig = rig().await;
        rig.ledger.hold_arm.store(true, Ordering::SeqCst);
        let shared = Arc::clone(&rig.shared);
        let requester = tokio::spawn(async move { shared.arm("main", operator()).await });
        rig.ledger.arm_entered.notified().await;
        requester.abort();
        assert!(requester.await.is_err());
        rig.ledger.arm_release.notify_one();
        // The task finished the arm on its own.
        let mut gate = rig.shared.gate();
        tokio::time::timeout(
            SHORT,
            gate.wait_for(|g| matches!(g.mode, GateMode::Armed { .. })),
        )
        .await
        .expect("armed in time")
        .expect("open");
        assert_eq!(kinds(&rig.records().await), ["started", "armed"]);
    }

    #[tokio::test]
    async fn control_task_panic_trips_control_panic_and_answers_ingress_control_failed() {
        let rig = rig().await;
        rig.shared.set_host(FakeHost::new(Ok(())));
        rig.ledger.panic_arm.store(true, Ordering::SeqCst);
        let result = rig.shared.arm("main", operator()).await;
        assert_eq!(code(result), INGRESS_CONTROL_FAILED);
        assert_eq!(rig.mode(), GateMode::Tripped(TripReason::ControlPanic));
        // The lock is not left held by the dead task; arming recovers first.
        rig.ledger.panic_arm.store(false, Ordering::SeqCst);
        let again = rig.shared.arm("main", operator()).await;
        assert!(again.is_ok(), "{again:?}");
    }

    #[tokio::test]
    async fn epoch_exhaustion_closes_the_gate() {
        let rig = rig().await;
        rig.shared.gate.send_modify(|g| g.epoch = u64::MAX);
        let outcome = rig.shared.disarm(DisarmCause::Operator).await;
        assert!(!outcome.was_armed);
        assert_eq!(rig.mode(), GateMode::Closing);
        assert_eq!(
            code(rig.shared.arm("main", operator()).await),
            INGRESS_STOPPING
        );
    }

    #[tokio::test]
    async fn the_epoch_changes_on_every_transition() {
        let rig = rig().await;
        let mut seen = vec![rig.shared.gate_now().epoch];
        rig.shared.arm("main", operator()).await.expect("armed");
        seen.push(rig.shared.gate_now().epoch);
        rig.shared.arm("alt", operator()).await.expect("armed");
        seen.push(rig.shared.gate_now().epoch);
        rig.shared.disarm(DisarmCause::Operator).await;
        seen.push(rig.shared.gate_now().epoch);
        rig.shared.disarm(DisarmCause::Operator).await;
        seen.push(rig.shared.gate_now().epoch);
        rig.shared.trip(TripReason::ListenerDied);
        seen.push(rig.shared.gate_now().epoch);
        let mut sorted = seen.clone();
        sorted.dedup();
        assert_eq!(sorted, seen, "strictly increasing: {seen:?}");
        assert!(seen.windows(2).all(|w| w[1] == w[0] + 1), "{seen:?}");
    }

    // -- start ------------------------------------------------------------------------------------------

    fn starting_shared() -> (Arc<IngressShared>, Arc<GatedLedger>) {
        let slot = Arc::new(LedgerSlot::new());
        let ledger = GatedLedger::new(Arc::clone(&slot));
        let (tx, _) = broadcast::channel(8);
        let shared = IngressShared::with_ledger(
            IngressCfgView::for_tests(),
            fast_tuning(),
            tx,
            slot,
            ledger.clone(),
        );
        (shared, ledger)
    }

    #[tokio::test]
    async fn arm_during_starting_answers_ingress_starting_and_writes_nothing() {
        let (shared, ledger) = starting_shared();
        assert_eq!(code(shared.arm("main", operator()).await), INGRESS_STARTING);
        assert_eq!(ledger.armed_calls.load(Ordering::SeqCst), 0);
        assert_eq!(shared.gate_now().epoch, 0);
    }

    #[tokio::test]
    async fn disarm_during_starting_cancels_arm_on_start_and_does_not_abort_the_start() {
        let (shared, _) = starting_shared();
        assert!(!shared.autostart_cancelled());
        let outcome = shared.disarm(DisarmCause::Operator).await;
        assert!(!outcome.was_armed);
        assert_eq!(
            outcome.epoch, 0,
            "no write: the start task's own epoch is intact"
        );
        assert!(shared.autostart_cancelled());
        // The start task publishes with the epoch it read.
        let published = shared.start_transition(0, GateMode::Disarmed);
        assert_eq!(published.map(|g| g.epoch), Some(1));
    }

    #[tokio::test]
    async fn the_state_of_the_gate_is_answered_before_the_argument_is_looked_at() {
        // Starting, disabled, closing: a profile that does not exist gets the answer
        // about the state, which is what the caller can do something about.
        let (shared, _) = starting_shared();
        assert_eq!(code(shared.arm("nope", operator()).await), INGRESS_STARTING);
        shared.close();
        assert_eq!(code(shared.arm("nope", operator()).await), INGRESS_STOPPING);
        let mut cfg = IngressCfgView::for_tests();
        cfg.enabled = false;
        let (tx, _) = broadcast::channel(8);
        let disabled = IngressShared::new(cfg, fast_tuning(), tx);
        assert_eq!(
            code(disabled.arm("nope", operator()).await),
            INGRESS_DISABLED
        );
        // An armable gate does look at it.
        let rig = rig().await;
        assert_eq!(
            code(rig.shared.arm("nope", operator()).await),
            INGRESS_ARGUMENT
        );
    }

    #[tokio::test]
    async fn a_disabled_ingress_refuses_everything_that_would_change_it() {
        let mut cfg = IngressCfgView::for_tests();
        cfg.enabled = false;
        let slot = Arc::new(LedgerSlot::new());
        let (tx, _) = broadcast::channel(8);
        let shared = IngressShared::new(cfg, fast_tuning(), tx);
        let _ = slot;
        assert_eq!(code(shared.arm("main", operator()).await), INGRESS_DISABLED);
        assert!(shared.recover().await.is_err());
        let outcome = shared.disarm(DisarmCause::Operator).await;
        assert_eq!(outcome.epoch, 0);
        shared.trip(TripReason::AcceptFatal);
        assert_eq!(shared.gate_now().epoch, 0);
        let status = shared.snapshot();
        assert_eq!(status.state, "disabled");
        assert_eq!(status.coverage, "none");
    }

    #[tokio::test]
    async fn a_start_that_lost_to_a_trip_does_not_overwrite_it() {
        let (shared, _) = starting_shared();
        shared.trip(TripReason::AuditWriteFailed);
        assert_eq!(
            shared.gate_now().mode,
            GateMode::Unavailable(UnavailableCode::AuditFailed)
        );
        assert!(shared.start_transition(0, GateMode::Disarmed).is_none());
        assert_eq!(
            shared.gate_now().mode,
            GateMode::Unavailable(UnavailableCode::AuditFailed)
        );
    }

    // -- trip ----------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn trip_follows_the_table_and_counts_only_what_it_wrote() {
        let rig = rig().await;
        rig.shared.arm("main", operator()).await.expect("armed");
        rig.shared.trip(TripReason::FlowPanicBudget);
        assert_eq!(rig.mode(), GateMode::Tripped(TripReason::FlowPanicBudget));
        let epoch = rig.shared.gate_now().epoch;
        // A tripped gate is not tripped again: no write, no count, no record.
        rig.shared.trip(TripReason::AcceptFatal);
        assert_eq!(rig.shared.gate_now().epoch, epoch);
        assert_eq!(rig.shared.counters().trips.load(Ordering::Relaxed), 1);
        let status = rig.shared.snapshot();
        assert_eq!(
            (status.state.as_str(), status.coverage.as_str()),
            ("tripped", "none")
        );
        assert_eq!(status.trips, 1);
        assert_eq!(status.retry_hint.as_deref(), Some("re-arm to recover"));
        assert_eq!(status.last_error.expect("an error").code, INGRESS_TRIPPED);
        let transition = status.last_transition.expect("a transition");
        assert_eq!(
            (transition.kind.as_str(), transition.reason_code.as_str()),
            ("tripped", "flow_panic_budget")
        );
        assert_eq!(
            *lock_unpoisoned(&rig.ledger.tripped),
            [TrippedEvent {
                reason: TripReason::FlowPanicBudget,
                epoch
            }]
        );
    }

    #[tokio::test]
    async fn a_trip_caused_by_the_writer_is_not_recorded_by_the_writer() {
        let rig = rig().await;
        rig.shared.trip(TripReason::AuditWriteFailed);
        assert!(lock_unpoisoned(&rig.ledger.tripped).is_empty());
        assert_eq!(rig.mode(), GateMode::Tripped(TripReason::AuditWriteFailed));
    }

    // -- recover --------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn arm_from_tripped_recovers_first_and_then_arms() {
        let mut rig = rig().await;
        let host = FakeHost::new(Ok(()));
        rig.shared.set_host(host.clone());
        rig.shared.trip(TripReason::ListenerDied);
        while rig.events.try_recv().is_ok() {}
        let outcome = rig.shared.arm("main", operator()).await.expect("armed");
        assert!(outcome.changed);
        assert_eq!(
            rig.mode(),
            GateMode::Armed {
                profile: Arc::from("main")
            }
        );
        assert_eq!(host.calls.load(Ordering::SeqCst), 1);
        let codes: Vec<String> = std::iter::from_fn(|| rig.events.try_recv().ok())
            .filter_map(|e| match e {
                Event::Warning { code, .. } => Some(code),
                _ => None,
            })
            .collect();
        assert_eq!(codes, [INGRESS_RECOVERED, INGRESS_ARMED]);
        assert_eq!(rig.shared.snapshot().last_error.map(|e| e.code), None);
    }

    #[tokio::test]
    async fn recover_is_all_or_nothing_and_a_failure_names_the_most_specific_code() {
        let rig = rig().await;
        let host = FakeHost::new(Err(RecoverError::Unavailable(
            UnavailableCode::AuditCorrupt,
            "segment 3 line 2".to_owned(),
        )));
        rig.shared.set_host(host.clone());
        rig.shared.trip(TripReason::AuditWriteFailed);
        let error = rig.shared.recover().await.expect_err("fails");
        assert_eq!(error.code, INGRESS_RECOVERY_FAILED);
        assert!(
            error.message.contains("segment 3 line 2"),
            "{}",
            error.message
        );
        assert_eq!(
            rig.mode(),
            GateMode::Unavailable(UnavailableCode::AuditCorrupt)
        );
        let status = rig.shared.snapshot();
        assert_eq!(status.state, "unavailable");
        assert_eq!(
            status.last_error.map(|e| e.code),
            Some(INGRESS_RECOVERY_FAILED.to_owned())
        );
        // A recoverable code can be tried again; a process property cannot.
        *lock_unpoisoned(&host.result) = Ok(());
        rig.shared.recover().await.expect("recovered");
        assert_eq!(rig.mode(), GateMode::Disarmed);
        rig.shared.update_host_facts(|_| {});
        rig.shared
            .gate
            .send_modify(|g| g.mode = GateMode::Unavailable(UnavailableCode::HardeningUnavailable));
        let error = rig.shared.recover().await.expect_err("not recoverable");
        assert_eq!(error.code, "INGRESS_HARDENING_UNAVAILABLE");
        assert_eq!(
            host.calls.load(Ordering::SeqCst),
            2,
            "the host was not asked again"
        );
    }

    #[tokio::test]
    async fn a_busy_or_stalled_recover_changes_nothing() {
        let rig = rig().await;
        let host = FakeHost::new(Err(RecoverError::Busy));
        rig.shared.set_host(host.clone());
        rig.shared.trip(TripReason::AuditWriteFailed);
        let epoch = rig.shared.gate_now().epoch;
        assert_eq!(
            rig.shared.recover().await.expect_err("busy").code,
            INGRESS_BUSY
        );
        *lock_unpoisoned(&host.result) = Err(RecoverError::Stalled);
        assert_eq!(
            rig.shared.recover().await.expect_err("stalled").code,
            INGRESS_AUDIT_STALLED
        );
        assert_eq!(rig.shared.gate_now().epoch, epoch);
        assert_eq!(rig.mode(), GateMode::Tripped(TripReason::AuditWriteFailed));
    }

    #[tokio::test]
    async fn recover_losing_to_disarm_leaves_the_state_unchanged() {
        let rig = rig().await;
        let host = FakeHost::new(Ok(()));
        host.hold.store(true, Ordering::SeqCst);
        rig.shared.set_host(host.clone());
        rig.shared.trip(TripReason::ListenerDied);
        let shared = Arc::clone(&rig.shared);
        let recovering = tokio::spawn(async move { shared.recover().await });
        host.entered.notified().await;
        let disarm = rig.shared.disarm(DisarmCause::Operator).await;
        assert!(!disarm.was_armed);
        host.release.notify_one();
        let error = recovering.await.expect("joined").expect_err("lost");
        assert_eq!(error.code, INGRESS_TRIPPED);
        assert_eq!(rig.mode(), GateMode::Tripped(TripReason::ListenerDied));
    }

    #[tokio::test]
    async fn recover_is_single_flight_through_the_control_lock() {
        let rig = rig().await;
        let host = FakeHost::new(Ok(()));
        host.hold.store(true, Ordering::SeqCst);
        rig.shared.set_host(host.clone());
        rig.shared.trip(TripReason::ListenerDied);
        let shared = Arc::clone(&rig.shared);
        let first = tokio::spawn(async move { shared.recover().await });
        host.entered.notified().await;
        let second = rig.shared.recover().await;
        assert_eq!(second.expect_err("busy").code, INGRESS_BUSY);
        assert_eq!(host.calls.load(Ordering::SeqCst), 1);
        host.release.notify_one();
        first.await.expect("joined").expect("recovered");
    }

    #[tokio::test]
    async fn recovery_clears_tripped_without_a_restart_and_a_second_trip_can_be_recovered_too() {
        let rig = rig().await;
        rig.shared.set_host(FakeHost::new(Ok(())));
        for _ in 0..2 {
            rig.shared.trip(TripReason::AcceptFatal);
            assert_eq!(rig.mode(), GateMode::Tripped(TripReason::AcceptFatal));
            rig.shared.recover().await.expect("recovered");
            assert_eq!(rig.mode(), GateMode::Disarmed);
        }
        assert_eq!(rig.shared.snapshot().trips, 2);
    }

    // -- what the Armed record and the transitions carry ----------------------------------------------------

    #[tokio::test]
    async fn the_armed_record_carries_the_profile_s_facts_the_observations_and_the_waits() {
        let tuning = Tuning {
            audit_queue_wait: Duration::from_millis(1_234),
            audit_sync_wait: Duration::from_millis(5_678),
            ..fast_tuning()
        };
        let rig = rig_with(cfg_with_two_profiles(), tuning).await;
        let observation = Observation::new("egress_local", "192.0.2.9").expect("valid");
        rig.shared.set_armed_observations(vec![observation.clone()]);
        let facts = rig.shared.cfg().armed.get("alt").expect("alt").clone();
        assert!(!facts.rules.rules.is_empty());
        rig.shared.arm("alt", operator()).await.expect("armed");
        assert_eq!(
            *lock_unpoisoned(&rig.ledger.last_waits),
            Some(Waits {
                queue_wait: Duration::from_millis(1_234),
                sync_wait: Duration::from_millis(5_678)
            })
        );
        let events = rig.records().await;
        match &events[1] {
            FlowAuditEvent::Armed {
                profile_digest,
                rules,
                observations,
                ..
            } => {
                assert_eq!(*profile_digest, facts.profile_digest);
                assert_eq!(*rules, facts.rules);
                assert_eq!(*observations, vec![observation]);
            }
            other => panic!("{other:?}"),
        }
        // Who asked, and when, is what the status says about the last transition.
        let status = rig.shared.snapshot();
        let transition = status.last_transition.expect("a transition");
        assert_eq!(transition.kind, "armed");
        assert_eq!(transition.epoch, status.epoch);
        assert_eq!(transition.actor.as_deref(), Some("uid:1000"));
    }

    #[tokio::test]
    async fn a_failed_arm_says_why_and_a_stalled_disk_says_so() {
        let rig = rig().await;
        *lock_unpoisoned(&rig.ledger.fail_arm) = Some(AuditError::Io("AUDIT_DISK_FULL"));
        let error = rig.shared.arm("main", operator()).await.expect_err("fails");
        assert_eq!(error.code, INGRESS_AUDIT_FAILED);
        assert!(
            error.message.contains("AUDIT_DISK_FULL"),
            "{}",
            error.message
        );
        assert_eq!(rig.mode(), GateMode::Disarmed, "nothing was armed");
        // The disk part has run for exactly the bound: stalled.
        *lock_unpoisoned(&rig.ledger.stalled_for) = Some(rig.shared.tuning().audit_stall_trip);
        let error = rig.shared.arm("main", operator()).await.expect_err("fails");
        assert_eq!(error.code, INGRESS_AUDIT_STALLED);
        let status = rig.shared.snapshot();
        assert_eq!(status.audit.state, "stalled");
        // A moment under the bound is not.
        *lock_unpoisoned(&rig.ledger.stalled_for) =
            Some(rig.shared.tuning().audit_stall_trip - Duration::from_millis(1));
        let error = rig.shared.arm("main", operator()).await.expect_err("fails");
        assert_eq!(error.code, INGRESS_AUDIT_FAILED);
        assert_eq!(rig.shared.snapshot().audit.state, "ok");
    }

    #[tokio::test]
    async fn arm_does_not_open_a_gate_that_a_trip_closed_before_it_read_it() {
        let rig = rig().await;
        rig.shared.trip(TripReason::ListenerDied);
        let guard = rig.shared.lock_control().await.expect("lock");
        let profile: Arc<str> = Arc::from("main");
        let error = rig
            .shared
            .arm_locked(&guard, &profile, &operator())
            .await
            .expect_err("refused");
        assert_eq!(error.code, INGRESS_TRIPPED);
        assert_eq!(rig.ledger.armed_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_arm_of_the_armed_profile_is_a_noop_only_while_nothing_else_is_in_control() {
        let rig = rig().await;
        rig.shared.arm("main", operator()).await.expect("armed");
        assert!(rig.shared.arm_would_be_noop("main"));
        assert!(!rig.shared.arm_would_be_noop("alt"), "another profile");
        rig.ledger.hold_arm.store(true, Ordering::SeqCst);
        let other = arm_task(&rig, "alt").await;
        rig.ledger.arm_entered.notified().await;
        assert!(
            !rig.shared.arm_would_be_noop("main"),
            "an arm of another profile is in flight"
        );
        rig.ledger.arm_release.notify_one();
        other.await.expect("joined").expect("armed");
        assert!(rig.shared.arm_would_be_noop("alt"));
    }

    #[tokio::test]
    async fn a_disarm_record_that_cannot_get_the_control_lock_is_counted_and_not_written() {
        let rig = rig().await;
        rig.shared.arm("main", operator()).await.expect("armed");
        // Another arm holds the control lock, inside its fsync.
        rig.ledger.hold_arm.store(true, Ordering::SeqCst);
        let other = arm_task(&rig, "alt").await;
        rig.ledger.arm_entered.notified().await;
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            rig.shared.disarm(DisarmCause::Operator),
        )
        .await
        .expect("the record gives up after the bookkeeping wait, not after a minute");
        // The effect did not wait; the record gave up after the bookkeeping wait.
        assert!(outcome.was_armed);
        assert_eq!(rig.mode(), GateMode::Disarmed);
        assert_eq!(
            rig.shared
                .counters()
                .disarm_record_lost
                .load(Ordering::Relaxed),
            1
        );
        assert!(lock_unpoisoned(&rig.ledger.disarmed).is_empty());
        assert_eq!(rig.shared.snapshot().counters.disarm_record_lost, 1);
        rig.ledger.arm_release.notify_one();
        assert_eq!(code(other.await.expect("joined")), INGRESS_SUPERSEDED);
    }

    #[tokio::test]
    async fn the_transitions_are_published_with_their_kind_and_reason() {
        let mut rig = rig().await;
        let host = FakeHost::new(Ok(()));
        rig.shared.set_host(host);
        rig.shared.arm("main", operator()).await.expect("armed");
        rig.shared.disarm(DisarmCause::Deactivate).await;
        let t = rig.shared.snapshot().last_transition.expect("one");
        assert_eq!(
            (t.kind.as_str(), t.reason_code.as_str(), t.epoch),
            ("disarmed", "deactivate", rig.shared.gate_now().epoch)
        );
        rig.shared.trip(TripReason::AcceptFatal);
        let t = rig.shared.snapshot().last_transition.expect("one");
        assert_eq!(
            (t.kind.as_str(), t.reason_code.as_str()),
            ("tripped", "accept_fatal")
        );
        while rig.events.try_recv().is_ok() {}
        rig.shared.recover().await.expect("recovered");
        let t = rig.shared.snapshot().last_transition.expect("one");
        assert_eq!(t.kind, "recovered");
        assert_eq!(rig.shared.snapshot().last_error.map(|e| e.code), None);
        match rig.events.try_recv().expect("an event") {
            Event::Warning { code, .. } => assert_eq!(code, INGRESS_RECOVERED),
            other => panic!("{other:?}"),
        }
        // A trip is also an event.
        rig.shared.trip(TripReason::ListenerDied);
        match rig.events.try_recv().expect("an event") {
            Event::Warning { code, .. } => assert_eq!(code, INGRESS_TRIPPED),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn the_start_publishes_its_outcome_with_a_kind_and_the_code() {
        let (shared, _) = starting_shared();
        let gate = shared
            .start_transition(0, GateMode::Unavailable(UnavailableCode::BindFailed))
            .expect("published");
        let t = shared.snapshot().last_transition.expect("one");
        assert_eq!(
            (t.kind.as_str(), t.reason_code.as_str(), t.epoch),
            ("unavailable", "INGRESS_BIND_FAILED", gate.epoch)
        );
        let (shared, _) = starting_shared();
        shared
            .start_transition(0, GateMode::Disarmed)
            .expect("published");
        let t = shared.snapshot().last_transition.expect("one");
        assert_eq!((t.kind.as_str(), t.reason_code.as_str()), ("started", ""));
    }

    #[tokio::test]
    async fn a_writer_that_failed_is_reported_tripped_and_the_gate_is_tripped_with_it() {
        let rig = rig().await;
        // Someone cut the segment behind the writer's back: its next batch is a fault.
        let dir = rig.dir.path().join("ingress-audit");
        let segment = std::fs::read_dir(&dir)
            .expect("list")
            .next()
            .expect("a segment")
            .expect("entry")
            .path();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&segment)
            .expect("open")
            .set_len(3)
            .expect("truncate");
        let error = rig.shared.arm("main", operator()).await.expect_err("fails");
        assert_eq!(error.code, INGRESS_AUDIT_FAILED);
        assert_eq!(rig.mode(), GateMode::Tripped(TripReason::AuditWriteFailed));
        let status = rig.shared.snapshot();
        assert_eq!(status.state, "tripped");
        assert_eq!(status.audit.state, "tripped");
        // The writer cannot record its own failure.
        assert!(lock_unpoisoned(&rig.ledger.tripped).is_empty());
    }

    // -- pure pieces of the snapshot -----------------------------------------------------------------------------

    #[test]
    fn the_audit_block_maps_every_field_of_the_writer_status() {
        let (shared, _) = starting_shared();
        let status = AuditStatus {
            state: WriterState::Ok,
            entries: 11,
            head: "a".repeat(64),
            bytes: 22,
            queue_depth: 33,
            busy: 44,
            timeouts: 55,
            queue_full: 66,
            unknown_codes: 77,
            compensations_lost: 88,
            sync_last_ms: 99,
            sync_max_ms: 111,
            segments: 5,
            pruned_entries: 222,
            prune_deferred: 3,
            rotations: 9,
            denials_over_quota: 333,
            capacity_refusals: 8,
            destination_logging: ssk_config::ingress::DestinationLogging::Hashed,
            dest_key_id: Some("kid".to_owned()),
            oldest_ts_ms: Some(444),
            refusal_quota_used_percent: 55,
        };
        let dto = shared.audit_dto(&GateMode::Disarmed, Some(&status), false);
        assert_eq!(dto.state, "ok");
        assert_eq!((dto.entries, dto.bytes, dto.segments), (11, 22, 5));
        assert_eq!(dto.head.as_deref(), Some("a".repeat(64).as_str()));
        assert_eq!((dto.busy, dto.timeouts), (44, 55));
        assert_eq!((dto.sync_last_ms, dto.sync_max_ms), (99, 111));
        assert_eq!((dto.pruned_entries, dto.prune_deferred), (222, 3));
        assert_eq!(dto.denials_over_quota, 333);
        assert_eq!(dto.oldest_ts_ms, Some(444));
        assert_eq!(dto.refusal_quota_used_percent, 55);
        assert_eq!(dto.dest_key_id.as_deref(), Some("kid"));
        // The destination mode is the configuration's, not the writer's.
        assert_eq!(dto.destination_logging, "plain");
        let down = AuditStatus {
            state: WriterState::Down,
            ..status.clone()
        };
        assert_eq!(
            shared
                .audit_dto(&GateMode::Disarmed, Some(&down), false)
                .state,
            "tripped"
        );
        let stalled = shared.audit_dto(&GateMode::Disarmed, Some(&status), true);
        assert_eq!(stalled.state, "stalled");
        let down_and_stalled = shared.audit_dto(&GateMode::Disarmed, Some(&down), true);
        assert_eq!(
            down_and_stalled.state, "tripped",
            "a dead writer is not a stalled one"
        );
        let closing = AuditStatus {
            state: WriterState::Closing,
            ..status
        };
        assert_eq!(
            shared
                .audit_dto(&GateMode::Closing, Some(&closing), true)
                .state,
            "closing"
        );
    }

    #[test]
    fn the_window_warning_is_a_day_exclusive_and_needs_pruned_records() {
        let day = 24 * 60 * 60 * 1000;
        let now = 10 * day;
        assert!(audit_window_short(1, Some(now - day + 1), now));
        assert!(
            !audit_window_short(1, Some(now - day), now),
            "a day old is not short"
        );
        assert!(!audit_window_short(1, Some(now - day - 1), now));
        assert!(!audit_window_short(0, Some(now), now), "nothing was pruned");
        assert!(!audit_window_short(1, None, now), "no time known");
        // A clock that is behind the record does not wrap.
        assert!(audit_window_short(1, Some(now + 5), now));
    }

    #[test]
    fn a_route_change_is_recent_for_less_than_ten_minutes_and_only_if_there_was_a_previous_one() {
        let ten_minutes = 600_000;
        assert!(route_changed_recently(&route(
            "observed",
            Some(ten_minutes - 1),
            true
        )));
        assert!(!route_changed_recently(&route(
            "observed",
            Some(ten_minutes),
            true
        )));
        assert!(!route_changed_recently(&route("observed", Some(1), false)));
        assert!(!route_changed_recently(&route("observed", None, true)));
    }

    #[tokio::test]
    async fn the_address_family_and_unsupported_warnings_depend_on_what_was_asked_and_seen() {
        let rig = rig().await;
        // IPv4 only (the default): an observed IPv6 route is nothing to warn about.
        rig.shared.update_host_facts(|f| {
            f.observations.route_v6 = route("observed", None, false);
            f.observations.route_v4 = route("unsupported", None, false);
        });
        let codes: Vec<String> = rig
            .shared
            .snapshot()
            .warnings
            .into_iter()
            .map(|w| w.code)
            .collect();
        assert_eq!(codes, [WARNING_OBSERVATION_UNAVAILABLE]);
        rig.shared
            .update_host_facts(|f| f.observations.route_v4 = route("failed", None, false));
        assert_eq!(rig.shared.snapshot().warnings.len(), 1);
        rig.shared
            .update_host_facts(|f| f.observations.route_v4 = route("no_route", None, false));
        assert!(rig.shared.snapshot().warnings.is_empty());
    }

    #[test]
    fn the_registry_remembers_the_highest_number_of_a_boot_after_it_has_left_the_ring() {
        let registry = FlowRegistry::default();
        registry.record(entry("ingress:b7:5"));
        registry.record(entry("ingress:b7:3"));
        // Not recorded, below the highest: issued.
        assert_eq!(
            registry.inspect("ingress:b7:4").expect_err("gone").code,
            FLOW_NOT_RETAINED
        );
        // The highest itself, once it has left the ring.
        for n in 0..FLOW_REGISTRY_CAPACITY {
            registry.record(entry(&format!("other-{n}")));
        }
        assert_eq!(
            registry.inspect("ingress:b7:5").expect_err("gone").code,
            FLOW_NOT_RETAINED
        );
        assert_eq!(
            registry.inspect("ingress:b7:6").expect_err("never").code,
            FLOW_NOT_FOUND
        );
        // A flow recorded without its inspection data is kept in the list only.
        registry.record(entry("ingress:b7:6"));
        assert_eq!(
            registry.inspect("ingress:b7:6").expect_err("none").code,
            FLOW_NOT_RETAINED
        );
    }

    // -- the model: arms, disarms and trips in any order, and the ledger agrees -----------------------

    /// A tiny seeded generator: no dependency, the same schedule every run.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }
    }

    /// What the ledger says the gate is, by its last record of the three kinds.
    fn ledger_says_armed(events: &[FlowAuditEvent]) -> Option<String> {
        let mut armed = None;
        for event in events {
            match event {
                FlowAuditEvent::Armed { profile, .. } => armed = Some(profile.clone()),
                FlowAuditEvent::Disarmed { .. } | FlowAuditEvent::Tripped { .. } => armed = None,
                _ => {}
            }
        }
        armed
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_operations_serialise_and_the_ledger_agrees_with_the_gate() {
        for seed in 0..40_u64 {
            let rig = rig().await;
            rig.shared.set_host(FakeHost::new(Ok(())));
            let mut rng = Lcg(seed + 1);
            let mut handles = Vec::new();
            for _ in 0..8 {
                let shared = Arc::clone(&rig.shared);
                let delay = Duration::from_micros(rng.next() % 2_000);
                let op = rng.next() % 5;
                handles.push(tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    match op {
                        0 => drop(shared.arm("main", operator()).await),
                        1 => drop(shared.arm("alt", operator()).await),
                        2 => drop(shared.disarm(DisarmCause::Operator).await),
                        3 => shared.trip(TripReason::ListenerDied),
                        _ => drop(shared.recover().await),
                    }
                }));
            }
            *lock_unpoisoned(&rig.ledger.delay) = Duration::from_micros(rng.next() % 1_500);
            for handle in handles {
                handle.await.expect("no task panicked");
            }
            let events = rig.records().await;
            let from_ledger = ledger_says_armed(&events);
            let from_gate = rig.mode().armed_profile().map(str::to_owned);
            assert_eq!(from_ledger, from_gate, "seed {seed}: {:?}", kinds(&events));
            // The gate is armed only if the writer also says so (no second source of truth).
            let status = rig.shared.snapshot();
            assert_eq!(status.armed_profile, from_gate, "seed {seed}");
        }
    }

    // -- the registry -----------------------------------------------------------------------------------------

    fn entry(flow_id: &str) -> FlowEntry {
        FlowEntry {
            summary: FlowSummaryDto {
                flow_id: flow_id.to_owned(),
                ..FlowSummaryDto::default()
            },
            inspection: None,
        }
    }

    #[test]
    fn the_registry_ring_evicts_the_oldest_and_inspect_says_not_retained() {
        let registry = FlowRegistry::default();
        for n in 1..=(FLOW_REGISTRY_CAPACITY + 2) {
            registry.record(entry(&format!("ingress:b7:{n}")));
        }
        let recent = registry.recent(1_000);
        assert_eq!(recent.len(), FLOW_REGISTRY_CAPACITY);
        assert_eq!(
            recent.first().map(|f| f.flow_id.as_str()),
            Some(format!("ingress:b7:{}", FLOW_REGISTRY_CAPACITY + 2).as_str()),
            "newest first"
        );
        assert_eq!(registry.recent(3).len(), 3);
        // Evicted: issued, no longer kept.
        assert_eq!(
            registry.inspect("ingress:b7:1").expect_err("gone").code,
            FLOW_NOT_RETAINED
        );
        // Another boot: this daemon cannot say it was never issued.
        assert_eq!(
            registry.inspect("ingress:b3:1").expect_err("gone").code,
            FLOW_NOT_RETAINED
        );
        // Never issued: a number above the highest of this boot, and nonsense.
        assert_eq!(
            registry
                .inspect("ingress:b7:99999")
                .expect_err("never")
                .code,
            FLOW_NOT_FOUND
        );
        for nonsense in [
            "",
            "x",
            "ingress:b7:",
            "ingress:7:1",
            "ingress:b:1",
            "ingress:b7:1x",
        ] {
            assert_eq!(
                registry.inspect(nonsense).expect_err("never").code,
                FLOW_NOT_FOUND,
                "{nonsense:?}"
            );
        }
    }

    #[test]
    fn recording_a_flow_again_replaces_it_and_update_changes_it_in_place() {
        let registry = FlowRegistry::default();
        registry.record(entry("ingress:b1:1"));
        let mut changed = entry("ingress:b1:1");
        changed.summary.outcome = "closed".to_owned();
        registry.record(changed);
        assert_eq!(registry.recent(10).len(), 1);
        assert_eq!(registry.recent(10)[0].outcome, "closed");
        assert!(registry.update("ingress:b1:1", |e| e.summary.bytes_up = 5));
        assert_eq!(registry.recent(10)[0].bytes_up, 5);
        assert!(!registry.update("ingress:b1:2", |_| {}));
    }

    #[test]
    fn every_counter_reaches_its_own_field_of_the_status() {
        let counters = Counters::default();
        let set = |counter: &AtomicU64, n: u64| Counters::add(counter, n);
        set(&counters.accepted, 1);
        set(&counters.refused_disarmed, 2);
        set(&counters.refused_peer_budget, 3);
        set(&counters.refused_peer, 4);
        set(&counters.refused_rate, 5);
        set(&counters.refused_capacity, 6);
        set(&counters.malformed, 7);
        set(&counters.rejected_malformed, 8);
        set(&counters.rejected_numeric_alias, 9);
        set(&counters.rejected_localhost, 10);
        set(&counters.denied, 11);
        set(&counters.denied_suppressed, 12);
        set(&counters.admitted, 13);
        set(&counters.connect_failed, 14);
        set(&counters.bytes_up, 16);
        set(&counters.bytes_down, 17);
        set(&counters.panics, 18);
        set(&counters.accept_errors, 19);
        set(&counters.audit_close_lost, 20);
        set(&counters.audit_busy, 21);
        set(&counters.audit_timeouts, 22);
        set(&counters.disarm_record_lost, 23);
        set(&counters.trips, 24);
        set(&counters.evicted_handshake, 25);
        set(&counters.resolver_busy, 26);
        set(&counters.resolver_zombies, 27);
        for _ in 0..15 {
            counters.flow_started();
        }
        let dto = counters.dto();
        assert_eq!(
            [
                dto.accepted,
                dto.refused_disarmed,
                dto.refused_peer_budget,
                dto.refused_peer,
                dto.refused_rate,
                dto.refused_capacity,
                dto.malformed,
                dto.rejected_target.malformed,
                dto.rejected_target.numeric_alias,
                dto.rejected_target.localhost,
                dto.denied,
                dto.denied_suppressed,
                dto.admitted,
                dto.connect_failed,
                dto.active_flows,
                dto.bytes_up,
                dto.bytes_down,
                dto.panics,
                dto.accept_errors,
                dto.audit_close_lost,
                dto.audit_busy,
                dto.audit_timeouts,
                dto.disarm_record_lost,
                dto.trips,
                dto.evicted_handshake,
                dto.resolver_busy,
                dto.resolver_zombies,
            ],
            std::array::from_fn::<u64, 27, _>(|n| u64::try_from(n).expect("fits") + 1)
        );
    }

    // -- the snapshot ---------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn an_armed_gate_is_reported_armed_only_while_the_listener_and_the_writer_are_alive() {
        let rig = rig().await;
        rig.shared.arm("main", operator()).await.expect("armed");
        let status = rig.shared.snapshot();
        assert_eq!(
            (status.state.as_str(), status.coverage.as_str()),
            ("armed", "proxy_clients_only")
        );
        assert_eq!(status.armed_profile.as_deref(), Some("main"));
        assert!(!status.system_wide);
        assert_eq!(status.notice, INGRESS_COVERAGE_NOTICE);
        // The accept task is gone: demoted, never "armed".
        rig.shared.update_host_facts(|f| f.accept_alive = false);
        let status = rig.shared.snapshot();
        assert_eq!(
            (status.state.as_str(), status.coverage.as_str()),
            ("tripped", "none")
        );
        assert_eq!(status.armed_profile, None);
        assert_eq!(status.retry_hint.as_deref(), Some("re-arm to recover"));
        // The writer is gone.
        rig.shared.update_host_facts(|f| f.accept_alive = true);
        assert_eq!(rig.shared.snapshot().state, "armed");
        rig.writer().close(SHORT).await;
        let status = rig.shared.snapshot();
        assert_eq!(status.state, "tripped");
        assert_eq!(status.audit.state, "closing");
    }

    #[tokio::test]
    async fn hardening_required_with_a_control_missing_is_not_reported_armed() {
        let rig = rig().await;
        rig.shared.arm("main", operator()).await.expect("armed");
        rig.shared
            .update_host_facts(|f| f.controls.peer_check = false);
        assert_eq!(rig.shared.snapshot().state, "tripped");
    }

    #[tokio::test]
    async fn best_effort_reports_armed_without_the_controls_and_warns_about_each() {
        let mut cfg = cfg_with_two_profiles();
        cfg.hardening = IngressHardening::BestEffort;
        let rig = rig_with(cfg, fast_tuning()).await;
        rig.shared.update_host_facts(|f| f.controls = no_controls());
        rig.shared.arm("main", operator()).await.expect("armed");
        let status = rig.shared.snapshot();
        assert_eq!(status.state, "armed");
        assert_eq!(status.controls.hardening, "best_effort");
        let codes: Vec<&str> = status.warnings.iter().map(|w| w.code.as_str()).collect();
        assert_eq!(
            codes,
            [
                WARNING_PEER_CHECK_INACTIVE,
                WARNING_EXCLUSIVE_BIND_INACTIVE,
                WARNING_AUDIT_STORE_NOT_PRIVATE
            ]
        );
        // Unbound: nothing to warn about.
        rig.shared.update_host_facts(|f| f.listen = None);
        assert!(rig.shared.snapshot().warnings.is_empty());
    }

    #[tokio::test]
    async fn the_snapshot_carries_the_configuration_the_counters_and_the_ledger() {
        let rig = rig().await;
        Counters::add(&rig.shared.counters().accepted, 3);
        rig.shared.counters().flow_started();
        rig.shared.counters().flow_started();
        rig.shared.counters().flow_ended();
        rig.shared.counters().flow_ended();
        rig.shared.counters().flow_ended();
        Counters::bump(&rig.shared.counters().rejected_localhost);
        rig.shared.update_host_facts(|f| {
            f.limits = Some(EffectiveLimits {
                max_connections: 100,
                clamped_by_fd_limit: true,
                fd_soft_limit: Some(256),
                fd_needed: 300,
            });
            f.phase = Some("binding (attempt 2 of 6)".to_owned());
        });
        let status = rig.shared.snapshot();
        assert_eq!(status.epoch, rig.shared.gate_now().epoch);
        assert_eq!(status.counters.accepted, 3);
        assert_eq!(status.counters.active_flows, 0, "never below zero");
        assert_eq!(status.counters.rejected_target.localhost, 1);
        assert_eq!(status.listen.as_deref(), Some("127.0.0.1:10800"));
        assert_eq!(status.configured_listen.as_deref(), Some("127.0.0.1:10800"));
        assert_eq!(status.protocols, ["socks5"]);
        assert_eq!(status.arm_profile.as_deref(), Some("main"));
        assert_eq!(status.phase.as_deref(), Some("binding (attempt 2 of 6)"));
        assert_eq!(status.limits.max_connections_effective, 100);
        assert_eq!(status.limits.clamped_by.as_deref(), Some("fd_limit"));
        assert_eq!(status.limits.fd_soft_limit, Some(256));
        assert_eq!(status.limits.fd_needed, 300);
        let fingerprint = &rig.shared.cfg().fingerprint;
        assert_eq!(status.config.routing, fingerprint.routing);
        assert_eq!(status.config.config, fingerprint.config);
        assert_eq!(status.config.ingress, fingerprint.ingress);
        assert_eq!(status.egress.direct_resolver, "operating_system");
        assert_eq!(status.egress.direct_address_families, "ipv4_only");
        assert!(!status.egress.binds_interface && !status.egress.binds_source_address);
        assert_eq!(status.audit.state, "ok");
        assert_eq!(status.audit.entries, 1, "Started");
        assert_eq!(status.audit.destination_logging, "plain");
        assert_eq!(status.audit.dir_sync, "fsync");
        assert!(status.audit.head.is_some());
        assert_eq!(status.observations.label, OBSERVATION_LABEL);
    }

    #[tokio::test]
    async fn the_audit_block_says_why_there_is_no_writer() {
        let (shared, _) = starting_shared();
        // Before the host has said anything, the limits are the configured ones.
        let limits = shared.snapshot().limits;
        assert_eq!(limits.max_connections, limits.max_connections_effective);
        assert!(limits.max_connections > 0);
        assert_eq!(shared.snapshot().audit.state, "starting");
        shared.gate.send_modify(|g| {
            g.mode = GateMode::Unavailable(UnavailableCode::AuditCorrupt);
        });
        assert_eq!(shared.snapshot().audit.state, "corrupt");
        shared.gate.send_modify(|g| g.mode = GateMode::Closing);
        assert_eq!(shared.snapshot().audit.state, "closing");
        shared
            .gate
            .send_modify(|g| g.mode = GateMode::Unavailable(UnavailableCode::BindFailed));
        assert_eq!(shared.snapshot().audit.state, "unavailable");
        let status = shared.snapshot();
        assert_eq!(status.retry_hint.as_deref(), Some("arm again to retry"));
    }

    #[test]
    fn counters_do_not_leave_zero_when_more_flows_end_than_started() {
        let counters = Counters::default();
        counters.flow_ended();
        counters.flow_ended();
        assert_eq!(counters.active_flows(), 0);
        counters.flow_started();
        assert_eq!(counters.active_flows(), 1);
    }

    // -- the observations and the warnings -------------------------------------------------------------------------

    fn route(
        status: &str,
        unchanged_for_ms: Option<u64>,
        previous: bool,
    ) -> ssk_ipc::ObservedRouteDto {
        ssk_ipc::ObservedRouteDto {
            status: status.to_owned(),
            unchanged_for_ms,
            previous: previous.then(ssk_ipc::PreviousRouteDto::default),
            ..ssk_ipc::ObservedRouteDto::default()
        }
    }

    #[tokio::test]
    async fn warnings_follow_the_observations_and_never_use_a_forbidden_word() {
        let mut cfg = cfg_with_two_profiles();
        cfg.families = DirectAddressFamilies::Any;
        let rig = rig_with(cfg, fast_tuning()).await;
        // A recent change of the route for the probe, IPv6 observed, IPv4 lookup failed.
        rig.shared.update_host_facts(|f| {
            f.observations.route_v4 = route("failed", Some(1_000), true);
            f.observations.route_v6 = route("observed", Some(599_999), true);
        });
        let codes: Vec<String> = rig
            .shared
            .snapshot()
            .warnings
            .iter()
            .map(|w| w.code.clone())
            .collect();
        assert_eq!(
            codes,
            [
                WARNING_OS_ROUTE_CHANGED,
                WARNING_DIRECT_MAY_USE_IPV6,
                WARNING_OBSERVATION_UNAVAILABLE
            ]
        );
        // The ten minutes are exclusive; a route that never changed does not warn.
        rig.shared.update_host_facts(|f| {
            f.observations.route_v4 = route("observed", Some(600_000), true);
            f.observations.route_v6 = route("not_sampled", None, false);
        });
        assert!(rig.shared.snapshot().warnings.is_empty());
        // Every text is fixed per code and free of the words that may not be said.
        for code in [
            WARNING_PEER_CHECK_INACTIVE,
            WARNING_EXCLUSIVE_BIND_INACTIVE,
            WARNING_AUDIT_STORE_NOT_PRIVATE,
            WARNING_OS_ROUTE_CHANGED,
            WARNING_DIRECT_MAY_USE_IPV6,
            WARNING_OBSERVATION_UNAVAILABLE,
            WARNING_AUDIT_WINDOW_SHORT,
        ] {
            let text = warning_text(code).expect("a text");
            assert_eq!(
                crate::ingress::types::contains_forbidden_word(text),
                None,
                "{code}"
            );
        }
        assert_eq!(warning_text("UNKNOWN"), None);
        assert_eq!(
            crate::ingress::types::contains_forbidden_word(OBSERVATION_LABEL),
            None
        );
    }

    #[tokio::test]
    async fn the_window_warning_needs_pruned_records_and_a_young_oldest_one() {
        // Retention 2 of 1,000-byte segments, so that records are pruned at once.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        let slot = Arc::new(LedgerSlot::new());
        let (tx, _) = broadcast::channel(8);
        let shared = IngressShared::new(IngressCfgView::for_tests(), fast_tuning(), tx);
        let mut cfg = open_cfg();
        cfg.segment_bytes = 1_000;
        cfg.retain_segments = 2;
        cfg.denied_share_percent = 100;
        let fs = UnixLedgerFs::new(dir.path().to_path_buf());
        let writer = Arc::new(
            open_dir(
                LockProof::for_tests(),
                &fs,
                &cfg,
                DestSealer::Plain,
                None,
                Arc::new(|_| {}),
            )
            .expect("opens"),
        );
        let _ = slot;
        shared.ledger_slot().install(Installed {
            writer: Arc::clone(&writer),
            boot: Arc::from("b1"),
        });
        assert!(
            !shared
                .snapshot()
                .warnings
                .iter()
                .any(|w| w.code == WARNING_AUDIT_WINDOW_SHORT),
            "nothing pruned yet"
        );
        for n in 0..12_u64 {
            writer
                .append_disarmed(
                    DisarmedEvent {
                        cause: DisarmCause::Operator,
                        epoch: n,
                    },
                    SHORT,
                )
                .await;
        }
        let status = shared.snapshot();
        assert!(status.audit.pruned_entries > 0, "{:?}", status.audit);
        assert!(
            status
                .warnings
                .iter()
                .any(|w| w.code == WARNING_AUDIT_WINDOW_SHORT),
            "records were pruned and the oldest is minutes old"
        );
    }
}
