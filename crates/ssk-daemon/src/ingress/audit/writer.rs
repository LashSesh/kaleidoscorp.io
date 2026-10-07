//! The writer of the flow ledger (design 6.4.4 to 6.4.6): one thread, one file,
//! group commit, and receipts that are the only way to learn that a record is
//! durable.
//!
//! * **A reply exists only after the sync that covers its record.** The writer
//!   thread appends a batch of at most [`BATCH_MAX`] lines with one `append` and
//!   one `sync_data`, and only then answers the jobs in it.
//! * **A receipt is a proof, and it cleans up after itself.** [`PendingReceipt`]
//!   says a `Pending` is durable; [`ResultReceipt`] says a `Connected` result is,
//!   and is the only value that authorises a success reply or a byte
//!   ([`ResultProof`]); [`ArmReceipt`] says an `Armed` record is. Dropped
//!   unresolved, each queues the record that closes its story, over an unbounded
//!   channel with a synchronous send (a `Drop` cannot await, and a spawned
//!   clean-up task is not guaranteed to run during shutdown). A flow whose task
//!   panics or is aborted therefore leaves a closed story without any cooperation
//!   from the dying task.
//! * **A caller and the writer never both own a job.** Every job has a state
//!   (queued, claimed, done, cancelled, abandoned) and exactly one side wins each
//!   compare-and-swap, so there is no window in which a record is written, nobody
//!   holds its receipt and nobody compensates.
//! * **A write fault trips.** Any failure of the append, the sync or the check
//!   that nobody touched the file ends the thread, answers every job with the
//!   fault and calls `on_trip` once; a thread that dies by panic does the same
//!   from a guard, so a dead writer can never leave the gate open.
//!
//! Rotation, retention and the refusal quota are `C-A7`; this module appends to
//! the active segment it is given.

use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

use ssk_netadmin::admission::AdmissionToken;
use ssk_netadmin::audit::summarise_route;

use super::dest::{host_kind_of, DestSealer};
use super::fs::{io_code, LedgerIo};
use super::input::{
    closed, ArmedEvent, CloseReason, ClosedEvent, ConnectedEvent, DeniedEvent, DisarmedEvent,
    FailedEvent, PendingInput, SummaryEvent, TrippedEvent, DENIED_REASON_CODES, RESULT_ERROR_CODES,
    RESULT_REFUSALS,
};
use super::record::{
    encode_line, EncodeError, FlowAuditEvent, FlowAuditRecord, GENESIS, LEDGER_FORMAT,
};
use crate::ingress::pump::ByteCounts;
use crate::ingress::target::TargetKind;
use crate::ingress::types::{
    lock_unpoisoned, sealed, AddrRef, ConfigFingerprint, DestinationLogging, DisarmCause,
    ResultOutcome, ResultProof, TripReason, Unresolved,
};

/// Lines per append and sync at most. Group commit is opportunistic: a lone job
/// costs one sync and nothing waits for company.
pub const BATCH_MAX: usize = 64;

/// The most addresses a `Result` lists as attempted (the format's own limit).
pub const MAX_ATTEMPTED: usize = 8;

/// Jobs that can be queued at once (compensation jobs are not counted).
pub const DEFAULT_QUEUE_CAP: usize = 256;

const QUEUED: u8 = 0;
const CLAIMED: u8 = 1;
const DONE: u8 = 2;
const CANCELLED: u8 = 3;
const ABANDONED: u8 = 4;

// ---------------------------------------------------------------------------
// Errors, waits, status
// ---------------------------------------------------------------------------

/// Why an append did not give a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    /// The depth of normal jobs is at the cap. Nothing was queued.
    QueueFull,
    /// Not claimed in time; cancelled, so the record will never be written.
    Busy,
    /// Claimed and not answered in time; abandoned. The record may become durable
    /// later, and its receipt then compensates.
    Timeout,
    /// The ledger is at its hard cap because pruning keeps failing (`C-A7`).
    Capacity,
    /// `close()` has started.
    Closing,
    /// The record is over the size limit; a bug, never cut.
    RecordTooLarge,
    /// A field holds a value that may not be written.
    Invalid(&'static str),
    /// The writer thread is gone.
    WriterDown,
    /// The sequence number space is used up.
    SeqExhausted,
    /// The append, the sync or the file check failed: a write fault.
    Io(&'static str),
}

impl AuditError {
    /// `true` for the faults that trip the gate.
    #[must_use]
    pub const fn trips(self) -> bool {
        matches!(self, Self::Io(_) | Self::SeqExhausted | Self::WriterDown)
    }

    /// A static label for logs and counters.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::QueueFull => "AUDIT_QUEUE_FULL",
            Self::Busy => "AUDIT_BUSY",
            Self::Timeout => "AUDIT_TIMEOUT",
            Self::Capacity => "AUDIT_CAPACITY",
            Self::Closing => "AUDIT_CLOSING",
            Self::RecordTooLarge => "AUDIT_RECORD_TOO_LARGE",
            Self::Invalid(_) => "AUDIT_INVALID_RECORD",
            Self::WriterDown => "AUDIT_WRITER_DOWN",
            Self::SeqExhausted => "AUDIT_SEQ_EXHAUSTED",
            Self::Io(code) => code,
        }
    }
}

/// Why a writer could not be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOpenError {
    /// The first records could not be written, or the thread not started.
    Io(&'static str),
    /// The sealer's mode is not the configured one.
    ModeMismatch,
    /// The ledger has no sequence number left.
    SeqExhausted,
}

/// The two waits of every append (design 6.4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Waits {
    /// How long to wait for the first answer. When it ends and the writer has not
    /// claimed the job, the job is cancelled (`Busy`).
    pub queue_wait: Duration,
    /// How much longer to wait for a job that was claimed. The worst case is the
    /// sum of the two, as in the design; a job claimed at once and slow to sync
    /// is waited for `queue_wait + sync_wait` from the submission, not
    /// `sync_wait` from the claim.
    pub sync_wait: Duration,
}

impl Waits {
    /// 2 s and 5 s: the worst audit wait on the connect path is 7 s before the
    /// dial and 7 s after it.
    pub const DEFAULT: Self = Self {
        queue_wait: Duration::from_secs(2),
        sync_wait: Duration::from_secs(5),
    };

    /// The same bound for both waits.
    #[must_use]
    pub const fn both(each: Duration) -> Self {
        Self {
            queue_wait: each,
            sync_wait: each,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterState {
    Ok,
    Closing,
    /// The thread ended after a fault, or by panic.
    Down,
}

/// What status shows. Read from atomics: no file is opened and no tokio lock is
/// taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditStatus {
    pub state: WriterState,
    pub entries: u64,
    pub head: String,
    pub bytes: u64,
    pub queue_depth: usize,
    pub busy: u64,
    pub timeouts: u64,
    pub queue_full: u64,
    pub unknown_codes: u64,
    pub compensations_lost: u64,
    pub sync_last_ms: u64,
    pub sync_max_ms: u64,
    pub destination_logging: DestinationLogging,
    pub dest_key_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Opening
// ---------------------------------------------------------------------------

/// What the open found in the ledger. `C-A7`'s `open_dir` fills it from a
/// verified chain; a fresh ledger is [`Replayed::fresh`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replayed {
    /// The hash the next line follows: `genesis` for a fresh ledger.
    pub head: String,
    /// The last sequence number written, `None` for a fresh ledger.
    pub last_seq: Option<u64>,
    /// The length of the active segment, which the writer checks against `fstat`
    /// before every batch.
    pub active_len: u64,
    pub entries: u64,
    pub bytes: u64,
    pub unresolved: Unresolved,
    /// Bytes of a torn tail that were cut off; a `Recovered` record is written
    /// when this is not zero.
    pub truncated_tail_bytes: u64,
    /// The reason of the trip that preceded this open, if one did.
    pub after_trip: Option<String>,
}

impl Replayed {
    #[must_use]
    pub fn fresh() -> Self {
        Self {
            head: GENESIS.to_owned(),
            last_seq: None,
            active_len: 0,
            entries: 0,
            bytes: 0,
            unresolved: Unresolved::default(),
            truncated_tail_bytes: 0,
            after_trip: None,
        }
    }
}

pub type TripFn = Arc<dyn Fn(TripReason) + Send + Sync>;
pub type ClockFn = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Settings of the writer. Sizes are in bytes so that tests can use tiny
/// segments.
#[derive(Clone)]
pub struct AuditOpenCfg {
    pub segment_bytes: u64,
    pub retain_segments: u32,
    pub denied_share_percent: u8,
    pub summary_share_percent: u8,
    pub destination_logging: DestinationLogging,
    pub fingerprint: ConfigFingerprint,
    pub daemon_version: String,
    /// Depth of normal jobs; [`DEFAULT_QUEUE_CAP`] in production.
    pub queue_cap: usize,
    /// Wall clock in milliseconds since the epoch; the record's `ts_ms`.
    pub clock: ClockFn,
}

/// The wall clock. A clock before the epoch reads as 0.
#[must_use]
pub fn system_clock() -> ClockFn {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    })
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Written by the writer thread, read by anyone.
struct Shared {
    entries: AtomicU64,
    bytes: AtomicU64,
    head: Mutex<String>,
    /// Milliseconds since `base` plus one while the disk part of a batch is
    /// running, 0 otherwise.
    io_started: AtomicU64,
    sync_last_ms: AtomicU64,
    sync_max_ms: AtomicU64,
    queued: AtomicUsize,
    down: AtomicBool,
    busy: AtomicU64,
    timeouts: AtomicU64,
    queue_full: AtomicU64,
    unknown_codes: AtomicU64,
    compensations_lost: AtomicU64,
}

impl Shared {
    fn new(replayed: &Replayed) -> Self {
        Self {
            entries: AtomicU64::new(replayed.entries),
            bytes: AtomicU64::new(replayed.bytes),
            head: Mutex::new(replayed.head.clone()),
            io_started: AtomicU64::new(0),
            sync_last_ms: AtomicU64::new(0),
            sync_max_ms: AtomicU64::new(0),
            queued: AtomicUsize::new(0),
            down: AtomicBool::new(false),
            busy: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            queue_full: AtomicU64::new(0),
            unknown_codes: AtomicU64::new(0),
            compensations_lost: AtomicU64::new(0),
        }
    }
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// What the writer tells a job it wrote.
struct Written {
    seq: u64,
    hash: String,
}

type Deliver = Box<dyn FnOnce(Result<Written, AuditError>) + Send>;

struct Normal {
    flow_id: String,
    event: FlowAuditEvent,
    state: Arc<AtomicU8>,
    deliver: Deliver,
}

struct Comp {
    flow_id: String,
    event: FlowAuditEvent,
}

enum Job {
    Normal(Normal),
    /// A record that closes a story. Not counted against the queue, not
    /// cancellable, accepted while closing.
    Comp(Comp),
    /// Answers `true` once everything queued before it is durable.
    Flush(oneshot::Sender<bool>),
    Shutdown,
}

/// A job's answer, or the lack of one, as a value that can be handed back.
trait Delivered: Send + 'static {
    /// The caller is gone: the value is about to be dropped by the writer.
    fn abandoned(&mut self);
}

fn deliver_fn<R: Delivered>(
    state: Arc<AtomicU8>,
    tx: oneshot::Sender<Result<R, AuditError>>,
    make: impl FnOnce(Written) -> R + Send + 'static,
) -> Deliver {
    Box::new(move |outcome| match outcome {
        Ok(written) => {
            let mut value = make(written);
            if state
                .compare_exchange(CLAIMED, DONE, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                if let Err(Ok(mut back)) = tx.send(Ok(value)) {
                    // The receiver went away after the claim: the story of this
                    // value is closed by its own `Drop`, on this thread.
                    back.abandoned();
                }
            } else {
                // The caller abandoned the job after the claim.
                value.abandoned();
            }
        }
        Err(error) => {
            if state
                .compare_exchange(CLAIMED, DONE, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let _ = tx.send(Err(error));
            }
        }
    })
}

/// What a caller wants done if its future is dropped while its job is still queued:
/// the job is then cancelled and will never be written, so whatever the caller had
/// already promised on the strength of it has to be undone. Runs inside a `Drop`,
/// so it only touches atomics and the unbounded side channel.
type OnCancel = Box<dyn FnOnce() + Send>;

/// Cancels or abandons a job when its caller is dropped before it has an answer.
struct ClaimGuard {
    state: Arc<AtomicU8>,
    armed: bool,
    on_cancel: Option<OnCancel>,
}

impl Drop for ClaimGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let swap = |from, to| {
            self.state
                .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        };
        if swap(QUEUED, CANCELLED) {
            // Never written. Undo the promise made on its behalf.
            if let Some(on_cancel) = self.on_cancel.take() {
                on_cancel();
            }
        } else {
            // Claimed: the record will land, and its receipt (dropped by the
            // writer, the caller being gone) closes its own story.
            let _ = swap(CLAIMED, ABANDONED);
        }
    }
}

// ---------------------------------------------------------------------------
// The shared core: what the writer handle and every receipt hold
// ---------------------------------------------------------------------------

struct Inner {
    tx: mpsc::UnboundedSender<Job>,
    shared: Arc<Shared>,
    queue_cap: usize,
    closing: AtomicBool,
    sealer: DestSealer,
    boot_seq: u64,
    flow_counter: AtomicU64,
    thread: Mutex<Option<JoinHandle<()>>>,
    base: Instant,
}

impl Inner {
    /// Queues a record that closes a story. `false` when the writer is gone (the
    /// record is lost and counted).
    fn send_comp(&self, flow_id: String, event: FlowAuditEvent) -> bool {
        // A writer that has failed will not write it, whether or not its channel
        // has been closed yet: say so instead of pretending.
        let sent = !self.shared.down.load(Ordering::Acquire)
            && self.tx.send(Job::Comp(Comp { flow_id, event })).is_ok();
        if !sent {
            bump(&self.shared.compensations_lost);
        }
        sent
    }

    async fn submit<R: Delivered>(
        self: &Arc<Self>,
        flow_id: String,
        event: FlowAuditEvent,
        waits: Waits,
        make: impl FnOnce(Written, Arc<Self>) -> R + Send + 'static,
    ) -> Result<R, AuditError> {
        self.submit_with(flow_id, event, waits, None, make).await
    }

    /// [`Inner::submit`] with `on_cancel`: run if this future is dropped while the
    /// job is still queued (and so never written).
    async fn submit_with<R: Delivered>(
        self: &Arc<Self>,
        flow_id: String,
        event: FlowAuditEvent,
        waits: Waits,
        on_cancel: Option<OnCancel>,
        make: impl FnOnce(Written, Arc<Self>) -> R + Send + 'static,
    ) -> Result<R, AuditError> {
        if self.closing.load(Ordering::Acquire) {
            return Err(AuditError::Closing);
        }
        if self.shared.down.load(Ordering::Acquire) {
            return Err(AuditError::WriterDown);
        }
        let depth = self.shared.queued.fetch_add(1, Ordering::AcqRel);
        if depth >= self.queue_cap {
            self.shared.queued.fetch_sub(1, Ordering::AcqRel);
            bump(&self.shared.queue_full);
            return Err(AuditError::QueueFull);
        }
        let state = Arc::new(AtomicU8::new(QUEUED));
        let (tx, mut rx) = oneshot::channel();
        let core = Arc::clone(self);
        let deliver = deliver_fn(Arc::clone(&state), tx, move |written| make(written, core));
        let job = Job::Normal(Normal {
            flow_id,
            event,
            state: Arc::clone(&state),
            deliver,
        });
        if self.tx.send(job).is_err() {
            self.shared.queued.fetch_sub(1, Ordering::AcqRel);
            return Err(AuditError::WriterDown);
        }
        let mut guard = ClaimGuard {
            state: Arc::clone(&state),
            armed: true,
            on_cancel,
        };
        let swap = |from, to| {
            state
                .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        };
        let reply = match timeout(waits.queue_wait, &mut rx).await {
            Ok(reply) => reply,
            Err(_) => {
                if swap(QUEUED, CANCELLED) {
                    guard.armed = false;
                    bump(&self.shared.busy);
                    return Err(AuditError::Busy);
                }
                match timeout(waits.sync_wait, &mut rx).await {
                    Ok(reply) => reply,
                    Err(_) => {
                        if swap(CLAIMED, ABANDONED) {
                            guard.armed = false;
                            bump(&self.shared.timeouts);
                            return Err(AuditError::Timeout);
                        }
                        // The writer won: its answer is on the way.
                        (&mut rx).await
                    }
                }
            }
        };
        guard.armed = false;
        reply.unwrap_or(Err(AuditError::WriterDown))
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

/// Any durable record that authorises nothing. Its fields are private: nothing
/// outside this module can make one (`tests/ui_receipts.rs` pins the error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    seq: u64,
    entry_hash: String,
}

impl Receipt {
    fn new(written: Written) -> Self {
        Self {
            seq: written.seq,
            entry_hash: written.hash,
        }
    }

    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    #[must_use]
    pub fn entry_hash(&self) -> &str {
        &self.entry_hash
    }
}

impl Delivered for Receipt {
    fn abandoned(&mut self) {}
}

/// What a `Denied` append came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeniedOutcome {
    Recorded(Receipt),
    /// The refusal quota of `C-A7` was used up: the flow still answers `02`, and
    /// the refusal is counted.
    OverQuota,
}

impl Delivered for DeniedOutcome {
    fn abandoned(&mut self) {}
}

/// `blake3(kind || host || port || route summary)`: the destination and route the
/// ledger says were authorised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Binding([u8; 32]);

fn binding_of(kind: TargetKind, host: &str, port: u16, route: &str) -> Binding {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ssk.ingress.binding.v1\0");
    // Only the host needs a terminator: the kind words are prefix-free and the port
    // has a fixed width, so nothing else can run into its neighbour.
    hasher.update(kind.as_str().as_bytes());
    hasher.update(host.as_bytes());
    hasher.update(&[0]);
    hasher.update(&port.to_be_bytes());
    hasher.update(route.as_bytes());
    Binding(*hasher.finalize().as_bytes())
}

/// A durable `Pending`: the proxy authorised the destination and a dial may
/// start. Not `Clone`. Dropped before a result was submitted, it writes the
/// `Result` that closes the story.
///
/// Its fields are private: nothing outside this module can make one, so a dial
/// cannot be started without the record that says it may. Not `Clone`
/// (`tests/ui_receipts.rs` pins both).
pub struct PendingReceipt {
    core: Arc<Inner>,
    flow_id: String,
    seq: u64,
    entry_hash: String,
    kind: TargetKind,
    binding: Binding,
    /// Shared with the guard of a result that is being submitted, which has to be
    /// able to undo the submission if its future is dropped while still queued.
    flags: Arc<PendingFlags>,
    abandoned: bool,
}

/// What a `PendingReceipt` knows about its own story.
#[derive(Default)]
struct PendingFlags {
    dial_started: AtomicBool,
    /// Set when a result is SUBMITTED, not when it is durable: a result that timed
    /// out may still land, and a second one for the same `Pending` would break the
    /// one-result rule.
    result_submitted: AtomicBool,
    result_failed: AtomicBool,
    explicit_code: Mutex<Option<&'static str>>,
}

impl PendingFlags {
    fn begin_result(&self) -> Result<(), AuditError> {
        if self.result_submitted.swap(true, Ordering::AcqRel) {
            return Err(AuditError::Invalid("result already submitted"));
        }
        Ok(())
    }

    /// The result was not recorded and will not be: the drop compensates.
    fn result_not_recorded(&self, code: Option<&'static str>) {
        self.result_failed.store(true, Ordering::Release);
        if let Some(code) = code {
            *lock_unpoisoned(&self.explicit_code) = Some(code);
        }
        self.result_submitted.store(false, Ordering::Release);
    }
}

impl PendingReceipt {
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    #[must_use]
    pub fn entry_hash(&self) -> &str {
        &self.entry_hash
    }

    #[must_use]
    pub fn flow_id(&self) -> &str {
        &self.flow_id
    }

    /// `true` when `token` is the destination and route this record authorised.
    /// The dial calls it with the token it is about to consume and refuses
    /// otherwise: the ledger can never say X while the dial does Y.
    #[must_use]
    pub fn matches(&self, token: &AdmissionToken) -> bool {
        let (host, port) = token.target();
        binding_of(self.kind, host, port, &summarise_route(token.route())) == self.binding
    }

    /// Called by the dial immediately before the first connect. From now on a
    /// drop without a result means `Aborted`, not `NotDialed`.
    pub fn mark_dial_started(&self) {
        self.flags.dial_started.store(true, Ordering::Release);
    }
}

impl Delivered for PendingReceipt {
    fn abandoned(&mut self) {
        self.abandoned = true;
    }
}

impl Drop for PendingReceipt {
    fn drop(&mut self) {
        if self.flags.result_submitted.load(Ordering::Acquire) {
            return;
        }
        let (outcome, code) = if self.flags.dial_started.load(Ordering::Acquire) {
            let code = if self.flags.result_failed.load(Ordering::Acquire) {
                "RESULT_NOT_RECORDED"
            } else {
                "DIAL_NOT_COMPLETED"
            };
            (ResultOutcome::Aborted, code)
        } else {
            let explicit = *lock_unpoisoned(&self.flags.explicit_code);
            let code = explicit.unwrap_or(if self.abandoned {
                "AUDIT_ABANDONED"
            } else {
                "FLOW_DROPPED"
            });
            (ResultOutcome::NotDialed, code)
        };
        self.core.send_comp(
            self.flow_id.clone(),
            FlowAuditEvent::Result {
                outcome,
                error_code: Some(code.to_owned()),
                refusal: None,
                chain_kinds: Vec::new(),
                dialed: None,
                attempted: Vec::new(),
                answers: None,
                observations: Vec::new(),
            },
        );
    }
}

/// A durable `Connected` result: the upstream tunnel is established and the
/// client may be told so. The only value that authorises a success reply or a
/// byte.
///
/// Nobody outside this crate can make one, copy one, or make a second kind of
/// proof: the fields are private, it is not `Clone`, and `ResultProof` is sealed by
/// a marker that cannot be named from outside (`tests/ui_receipts.rs` pins each).
pub struct ResultReceipt {
    core: Arc<Inner>,
    flow_id: String,
    seq: u64,
    entry_hash: String,
    counts: Arc<ByteCounts>,
    started: Instant,
    resolved: bool,
    abandoned: bool,
    /// The bytes of a `Closed` that could not be written, for the drop.
    final_bytes: Option<(u64, u64)>,
}

impl sealed::Sealed for ResultReceipt {}
impl ResultProof for ResultReceipt {}

impl ResultReceipt {
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    #[must_use]
    pub fn entry_hash(&self) -> &str {
        &self.entry_hash
    }

    fn closed_event(&self, bytes_up: u64, bytes_down: u64, reason: CloseReason) -> FlowAuditEvent {
        FlowAuditEvent::Closed {
            bytes_up,
            bytes_down,
            duration_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            reason: reason.as_str().to_owned(),
        }
    }

    /// The tunnel ended: writes `Closed` and consumes the receipt. A loss is
    /// counted and never trips (the bytes were really counted, so the drop still
    /// writes them if this could not).
    pub async fn closed(mut self, ev: ClosedEvent, bounded: Duration) {
        let event = self.closed_event(ev.bytes_up, ev.bytes_down, ev.reason);
        // If this future is dropped while the `Closed` is still queued (a flow task
        // aborted at shutdown, a client that disconnected inside a `select!`) the
        // job is cancelled and never written, and the receipt below has already
        // been marked resolved: the callback writes the `Closed` instead, with the
        // real byte counts and the honest reason. If the job was already claimed it
        // will land by itself and nothing more is needed.
        let fallback = self.closed_event(ev.bytes_up, ev.bytes_down, CloseReason::AuditAbandoned);
        let on_cancel: OnCancel = {
            let core = Arc::clone(&self.core);
            let flow_id = self.flow_id.clone();
            Box::new(move || {
                core.send_comp(flow_id, fallback);
            })
        };
        self.resolved = true;
        let result = self
            .core
            .submit_with(
                self.flow_id.clone(),
                event,
                Waits::both(bounded),
                Some(on_cancel),
                |written, _| Receipt::new(written),
            )
            .await;
        match result {
            Ok(_) | Err(AuditError::Timeout) => {}
            Err(_) => {
                // Never written, and never will be: the drop writes it, with the
                // real byte counts and the honest reason.
                self.resolved = false;
                self.final_bytes = Some((ev.bytes_up, ev.bytes_down));
                self.abandoned = true;
            }
        }
    }
}

impl Delivered for ResultReceipt {
    fn abandoned(&mut self) {
        self.abandoned = true;
    }
}

impl Drop for ResultReceipt {
    fn drop(&mut self) {
        if self.resolved {
            return;
        }
        let (up, down) = self
            .final_bytes
            .unwrap_or_else(|| (self.counts.up(), self.counts.down()));
        let reason = if self.abandoned {
            CloseReason::AuditAbandoned
        } else {
            CloseReason::Aborted
        };
        self.core
            .send_comp(self.flow_id.clone(), self.closed_event(up, down, reason));
    }
}

/// A durable `Armed`. Resolved by [`ArmReceipt::applied`], [`ArmReceipt::superseded`]
/// or [`ArmReceipt::not_applied`]; dropped unresolved it writes
/// `Disarmed{arm_abandoned}`, so a durable `Armed` is never left without the
/// record that says what became of it.
pub struct ArmReceipt {
    core: Arc<Inner>,
    epoch: u64,
    seq: u64,
    entry_hash: String,
    resolved: bool,
}

impl ArmReceipt {
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    #[must_use]
    pub fn entry_hash(&self) -> &str {
        &self.entry_hash
    }

    /// The gate was opened for this record.
    pub fn applied(mut self) {
        self.resolved = true;
    }

    /// The gate moved on before it was opened for this record.
    pub fn superseded(mut self) {
        self.close(DisarmCause::ArmSuperseded);
    }

    /// The gate write that should have followed this record did not happen.
    pub fn not_applied(mut self) {
        self.close(DisarmCause::ArmNotApplied);
    }

    fn close(&mut self, cause: DisarmCause) {
        self.resolved = true;
        self.core.send_comp(
            String::new(),
            FlowAuditEvent::Disarmed {
                cause: cause.as_str().to_owned(),
                epoch: self.epoch,
            },
        );
    }
}

impl Delivered for ArmReceipt {
    // The caller is gone and will not apply it: the drop writes
    // `Disarmed{arm_abandoned}`, which is what an unresolved receipt always does.
    fn abandoned(&mut self) {}
}

impl Drop for ArmReceipt {
    fn drop(&mut self) {
        if !self.resolved {
            self.close(DisarmCause::ArmAbandoned);
        }
    }
}

// ---------------------------------------------------------------------------
// The thread
// ---------------------------------------------------------------------------

/// A record on its way to the file, and the way to answer for it.
struct Item {
    flow_id: String,
    event: FlowAuditEvent,
    deliver: Option<Deliver>,
}

struct Core {
    io: Box<dyn LedgerIo>,
    head: String,
    /// `None` once the last representable sequence number has been written.
    next_seq: Option<u64>,
    expected_len: u64,
    shared: Arc<Shared>,
    clock: ClockFn,
    on_trip: TripFn,
    base: Instant,
}

fn encode_error(error: &EncodeError) -> AuditError {
    match error {
        EncodeError::RecordTooLarge => AuditError::RecordTooLarge,
        EncodeError::InvalidField(what) => AuditError::Invalid(what),
        EncodeError::Serialize => AuditError::Invalid("serialize"),
    }
}

/// Marks the writer down and calls `on_trip`, once. The callback runs on the
/// calling thread and must not block.
fn trip_once(shared: &Shared, on_trip: &TripFn) {
    if !shared.down.swap(true, Ordering::AcqRel) {
        let on_trip = Arc::clone(on_trip);
        let _ = catch_unwind(AssertUnwindSafe(|| on_trip(TripReason::AuditWriteFailed)));
    }
}

/// Trips when the batch in progress is abandoned by a panic. Declared after the
/// values that hold the callers' reply channels, so that it drops before them:
/// unwinding closes those channels (which tells the callers), and the trip has to
/// come first.
struct PanicTrip {
    shared: Arc<Shared>,
    on_trip: TripFn,
}

impl Drop for PanicTrip {
    fn drop(&mut self) {
        if std::thread::panicking() {
            trip_once(&self.shared, &self.on_trip);
        }
    }
}

/// The answers a batch owes: the callers of the records that were written, and of
/// those that were refused for want of a sequence number.
type Written2 = (Option<Deliver>, Written);

impl Core {
    fn trip(&self) {
        trip_once(&self.shared, &self.on_trip);
    }

    /// Answers a caller, or counts a compensation that nobody was waiting for.
    fn answer(&self, deliver: Option<Deliver>, outcome: Result<Written, AuditError>) {
        match deliver {
            Some(deliver) => deliver(outcome),
            None => {
                if outcome.is_err() {
                    bump(&self.shared.compensations_lost);
                }
            }
        }
    }

    /// A write fault: trips first, then answers, so that whoever sees the error
    /// also sees a tripped gate.
    fn fail_batch(&self, written: Vec<Written2>, refused: Vec<Option<Deliver>>, error: AuditError) {
        self.trip();
        for (deliver, _) in written {
            self.answer(deliver, Err(error));
        }
        for deliver in refused {
            self.answer(deliver, Err(AuditError::SeqExhausted));
        }
    }

    /// Writes `items` as one batch: encode, check the file, append, sync, answer.
    /// `false` when the writer must stop.
    fn commit(&mut self, mut items: VecDeque<Item>) -> bool {
        let mut head = self.head.clone();
        let mut next = self.next_seq;
        let mut bytes: Vec<u8> = Vec::new();
        let mut written: Vec<Written2> = Vec::new();
        let mut refused: Vec<Option<Deliver>> = Vec::new();
        // After everything that holds a reply channel (see `PanicTrip`).
        let _panic_trip = PanicTrip {
            shared: Arc::clone(&self.shared),
            on_trip: Arc::clone(&self.on_trip),
        };
        while !items.is_empty() {
            // Read before the item is taken: the clock is somebody else's code.
            let ts_ms = (self.clock)();
            let Some(item) = items.pop_front() else {
                break;
            };
            let Some(seq) = next else {
                refused.push(item.deliver);
                continue;
            };
            let Item {
                flow_id,
                event,
                deliver,
            } = item;
            let record = FlowAuditRecord {
                seq,
                ts_ms,
                flow_id,
                event,
            };
            match encode_line(&head, &record) {
                Ok(line) => {
                    bytes.extend_from_slice(&line.bytes);
                    head = line.hash.clone();
                    next = seq.checked_add(1);
                    written.push((
                        deliver,
                        Written {
                            seq,
                            hash: line.hash,
                        },
                    ));
                }
                Err(error) => self.answer(deliver, Err(encode_error(&error))),
            }
        }
        let exhausted = !refused.is_empty();
        if written.is_empty() {
            if exhausted {
                self.fail_batch(Vec::new(), refused, AuditError::SeqExhausted);
                return false;
            }
            return true;
        }

        let took = {
            let _mark = IoMark::start(Arc::clone(&self.shared), self.base);
            self.write_batch(&bytes)
        };
        let took = match took {
            Ok(took) => took,
            Err(error) => {
                self.fail_batch(written, refused, error);
                return false;
            }
        };

        // Durable. Move the state first, then answer, so that a caller that sees
        // its receipt also sees the status that includes it.
        let added = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let count = u64::try_from(written.len()).unwrap_or(u64::MAX);
        self.expected_len = self.expected_len.saturating_add(added);
        self.head = head;
        self.next_seq = next;
        self.shared.entries.fetch_add(count, Ordering::AcqRel);
        self.shared.bytes.fetch_add(added, Ordering::AcqRel);
        *lock_unpoisoned(&self.shared.head) = self.head.clone();
        self.shared.sync_last_ms.store(took, Ordering::Release);
        self.shared.sync_max_ms.fetch_max(took, Ordering::AcqRel);
        for (deliver, written) in written {
            self.answer(deliver, Ok(written));
        }
        if exhausted {
            // The numbers ran out inside this batch: what fitted is durable and
            // answered; the rest are refused, after the trip.
            self.fail_batch(Vec::new(), refused, AuditError::SeqExhausted);
            return false;
        }
        true
    }

    /// The disk part of a batch: check the file, append, sync. On a failure the file
    /// is cut back to what it held, and the error says why. Returns the time the
    /// sync took, in milliseconds.
    fn write_batch(&mut self, bytes: &[u8]) -> Result<u64, AuditError> {
        // Nobody may have touched the file since the last batch: an unlinked
        // segment or an appended byte means the chain on disk is not the chain in
        // memory.
        match self.io.active_stat() {
            Ok(stat) if stat.nlink != 0 && stat.len == self.expected_len => {}
            Ok(_) => return Err(AuditError::Io("AUDIT_EXTERNAL_MODIFICATION")),
            Err(error) => return Err(AuditError::Io(io_code(&error))),
        }
        let before = self.expected_len;
        if let Err(error) = self.io.append(bytes) {
            let _ = self.io.truncate_active(before);
            return Err(AuditError::Io(io_code(&error)));
        }
        let began = Instant::now();
        if let Err(error) = self.io.sync_data() {
            let _ = self.io.truncate_active(before);
            return Err(AuditError::Io(io_code(&error)));
        }
        Ok(u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}

/// While alive, the disk part of a batch is marked as running, for the host's
/// stall watchdog: a stuck `append` or `fstat` stalls the ledger as surely as a
/// stuck `sync_data`.
struct IoMark {
    shared: Arc<Shared>,
}

impl IoMark {
    fn start(shared: Arc<Shared>, base: Instant) -> Self {
        let now = u64::try_from(base.elapsed().as_millis()).unwrap_or(u64::MAX);
        shared
            .io_started
            .store(now.saturating_add(1), Ordering::Release);
        Self { shared }
    }
}

impl Drop for IoMark {
    fn drop(&mut self) {
        self.shared.io_started.store(0, Ordering::Release);
    }
}

/// Calls `on_trip` when the thread leaves by any road but a clean close.
struct ExitGuard {
    shared: Arc<Shared>,
    on_trip: TripFn,
    clean: bool,
}

impl Drop for ExitGuard {
    fn drop(&mut self) {
        if !self.clean {
            trip_once(&self.shared, &self.on_trip);
        }
    }
}

fn thread_main(mut core: Core, mut rx: mpsc::UnboundedReceiver<Job>) {
    let mut exit = ExitGuard {
        shared: Arc::clone(&core.shared),
        on_trip: Arc::clone(&core.on_trip),
        clean: false,
    };
    let mut stopping = false;
    loop {
        let first = if stopping {
            match rx.try_recv() {
                Ok(job) => job,
                Err(_) => {
                    // Nothing is queued. Close the channel so that nothing can
                    // slip in after this look (a later `send` fails and is
                    // counted); whatever got in before the close is seen by the
                    // second look.
                    rx.close();
                    match rx.try_recv() {
                        Ok(job) => job,
                        Err(_) => {
                            exit.clean = true;
                            return;
                        }
                    }
                }
            }
        } else {
            match rx.blocking_recv() {
                Some(job) => job,
                None => {
                    // Every sender is gone: nothing can be asked of this writer.
                    exit.clean = true;
                    return;
                }
            }
        };
        let mut jobs = vec![first];
        while jobs.len() < BATCH_MAX {
            match rx.try_recv() {
                Ok(job) => jobs.push(job),
                Err(_) => break,
            }
        }
        let mut items = Vec::new();
        let mut flushes = Vec::new();
        for job in jobs {
            match job {
                Job::Normal(normal) => {
                    core.shared.queued.fetch_sub(1, Ordering::AcqRel);
                    let claimed = normal
                        .state
                        .compare_exchange(QUEUED, CLAIMED, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok();
                    if claimed {
                        items.push(Item {
                            flow_id: normal.flow_id,
                            event: normal.event,
                            deliver: Some(normal.deliver),
                        });
                    }
                }
                Job::Comp(comp) => items.push(Item {
                    flow_id: comp.flow_id,
                    event: comp.event,
                    deliver: None,
                }),
                Job::Flush(tx) => flushes.push(tx),
                Job::Shutdown => stopping = true,
            }
        }
        let alive = core.commit(VecDeque::from(items));
        for flush in flushes {
            let _ = flush.send(alive);
        }
        if !alive {
            // The writer is finished. Everything still queued is dropped here, which
            // answers its caller `WriterDown` at once (the reply channel closes)
            // instead of leaving it to a timeout.
            rx.close();
            while let Ok(job) = rx.try_recv() {
                match job {
                    Job::Normal(_) => {
                        core.shared.queued.fetch_sub(1, Ordering::AcqRel);
                    }
                    Job::Comp(_) => bump(&core.shared.compensations_lost),
                    Job::Flush(tx) => {
                        let _ = tx.send(false);
                    }
                    Job::Shutdown => {}
                }
            }
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// The handle
// ---------------------------------------------------------------------------

/// The flow ledger's writer.
pub struct FlowAuditWriter {
    core: Arc<Inner>,
}

impl FlowAuditWriter {
    /// Opens a writer over `io`: writes `Recovered` (when the open cut a torn tail
    /// or followed a trip) and `Started`, synchronously, and starts the thread.
    /// Blocking; production runs it inside `spawn_blocking`.
    ///
    /// # Errors
    /// [`AuditOpenError`].
    // Crate-internal on purpose: a writer over a disk of one's own choosing can
    // issue receipts. `open_dir` (`C-A7`) is the entry point; this is its body and
    // the seam of the tests.
    #[allow(dead_code)]
    pub(crate) fn open_with(
        io: impl LedgerIo,
        replayed: Replayed,
        cfg: &AuditOpenCfg,
        sealer: DestSealer,
        on_trip: TripFn,
    ) -> Result<Self, AuditOpenError> {
        if sealer.mode() != cfg.destination_logging {
            return Err(AuditOpenError::ModeMismatch);
        }
        let next_seq = match replayed.last_seq {
            None => Some(1),
            Some(last) => last.checked_add(1),
        };
        if next_seq.is_none() {
            return Err(AuditOpenError::SeqExhausted);
        }
        let shared = Arc::new(Shared::new(&replayed));
        let base = Instant::now();
        let mut core = Core {
            io: Box::new(io),
            head: replayed.head.clone(),
            next_seq,
            expected_len: replayed.active_len,
            shared: Arc::clone(&shared),
            clock: Arc::clone(&cfg.clock),
            // A failure while opening is the opener's to report, not a trip.
            on_trip: Arc::new(|_| {}),
            base,
        };

        let outcome: Arc<Mutex<Option<Result<Written, AuditError>>>> = Arc::new(Mutex::new(None));
        let mut items = Vec::new();
        if replayed.truncated_tail_bytes != 0 || replayed.after_trip.is_some() {
            items.push(Item {
                flow_id: String::new(),
                event: FlowAuditEvent::Recovered {
                    truncated_tail_bytes: replayed.truncated_tail_bytes,
                    unresolved: replayed.unresolved,
                    after_trip: replayed.after_trip.clone(),
                },
                deliver: None,
            });
        }
        let slot = Arc::clone(&outcome);
        items.push(Item {
            flow_id: String::new(),
            event: FlowAuditEvent::Started {
                daemon_version: cfg.daemon_version.clone(),
                ledger_format: LEDGER_FORMAT,
                config: cfg.fingerprint.clone(),
                destination_logging: sealer.mode(),
                dest_key_id: sealer.kid().map(str::to_owned),
                unresolved_before: replayed.unresolved,
            },
            deliver: Some(Box::new(move |result| {
                *lock_unpoisoned(&slot) = Some(result);
            })),
        });
        if !core.commit(VecDeque::from(items)) {
            let code = match lock_unpoisoned(&outcome).take() {
                Some(Err(AuditError::Io(code))) => code,
                Some(Err(AuditError::SeqExhausted)) => return Err(AuditOpenError::SeqExhausted),
                _ => "AUDIT_IO",
            };
            return Err(AuditOpenError::Io(code));
        }
        let boot_seq = match lock_unpoisoned(&outcome).take() {
            Some(Ok(written)) => written.seq,
            Some(Err(error)) => return Err(AuditOpenError::Io(error.code())),
            None => return Err(AuditOpenError::Io("AUDIT_IO")),
        };
        core.on_trip = Arc::clone(&on_trip);

        let (tx, rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            tx,
            shared,
            queue_cap: cfg.queue_cap,
            closing: AtomicBool::new(false),
            sealer,
            boot_seq,
            flow_counter: AtomicU64::new(0),
            thread: Mutex::new(None),
            base,
        });
        let handle = std::thread::Builder::new()
            .name("ssk-ingress-audit".to_owned())
            .spawn(move || thread_main(core, rx))
            .map_err(|_| AuditOpenError::Io("AUDIT_THREAD"))?;
        *lock_unpoisoned(&inner.thread) = Some(handle);
        Ok(Self { core: inner })
    }

    /// A flow id that is unique across restarts: `ingress:b<seq of this boot's
    /// Started>:<n>`.
    #[must_use]
    pub fn next_flow_id(&self) -> String {
        let n = self
            .core
            .flow_counter
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        format!("ingress:b{}:{n}", self.core.boot_seq)
    }

    /// The sequence number of this boot's `Started` record.
    #[must_use]
    pub fn boot_seq(&self) -> u64 {
        self.core.boot_seq
    }

    #[must_use]
    pub fn sealer(&self) -> &DestSealer {
        &self.core.sealer
    }

    /// `Pending`: durable before the dial.
    ///
    /// # Errors
    /// [`AuditError`]; no receipt exists then, and nothing was dialled.
    pub async fn append_pending(
        &self,
        input: PendingInput<'_>,
        waits: Waits,
    ) -> Result<PendingReceipt, AuditError> {
        let (host, port) = input.token.target();
        let route = summarise_route(input.token.route());
        let dest = self
            .core
            .sealer
            .dest_for(host_kind_of(input.target_kind), host, port)
            .map_err(|_| AuditError::Invalid("destination"))?;
        let binding = binding_of(input.target_kind, host, port, &route);
        let event = FlowAuditEvent::Pending {
            peer: input.peer.to_owned(),
            peer_verified: input.peer_verified,
            dest,
            target_provenance: input.provenance.as_str().to_owned(),
            target_kind: input.target_kind.as_str().to_owned(),
            resolution: input.resolution,
            profile: input.profile.to_owned(),
            matched_rule: input.matched_rule.map(str::to_owned),
            route,
            planned_adapters: input.planned_adapters.to_vec(),
        };
        let flow_id = input.flow_id.to_owned();
        let kind = input.target_kind;
        let id = flow_id.clone();
        self.core
            .submit(flow_id, event, waits, move |written, core| PendingReceipt {
                core,
                flow_id: id,
                seq: written.seq,
                entry_hash: written.hash,
                kind,
                binding,
                flags: Arc::new(PendingFlags::default()),
                abandoned: false,
            })
            .await
    }

    /// The addresses a dial started a connect for, in start order, sealed. At most
    /// [`MAX_ATTEMPTED`]: the list is evidence of what was tried, and a record that
    /// the format would refuse must not make a finished dial unrecordable.
    fn seal_addresses(
        &self,
        addresses: &[std::net::SocketAddr],
    ) -> Result<Vec<AddrRef>, AuditError> {
        addresses
            .iter()
            .take(MAX_ATTEMPTED)
            .map(|address| self.core.sealer.addr(*address))
            .collect::<Result<_, _>>()
            .map_err(|_| AuditError::Invalid("address"))
    }

    fn note_unknown(&self, unknown: bool) {
        if unknown {
            bump(&self.core.shared.unknown_codes);
        }
    }

    /// `Result{Connected}`: durable before the success reply and before any byte.
    ///
    /// # Errors
    /// [`AuditError`]. After an error other than `Timeout` the result was not
    /// recorded and the `Pending`'s drop writes one; after `Timeout` it may become
    /// durable later and the receipt it then yields writes the `Closed`.
    pub async fn append_connected(
        &self,
        pending: &PendingReceipt,
        event: ConnectedEvent,
        counts: Arc<ByteCounts>,
        waits: Waits,
    ) -> Result<ResultReceipt, AuditError> {
        pending.flags.begin_result()?;
        let record = (|| -> Result<FlowAuditEvent, AuditError> {
            Ok(FlowAuditEvent::Result {
                outcome: ResultOutcome::Connected,
                error_code: None,
                refusal: None,
                chain_kinds: event
                    .chain_kinds
                    .iter()
                    .map(|kind| (*kind).to_owned())
                    .collect(),
                dialed: match event.dialed {
                    Some(address) => Some(
                        self.core
                            .sealer
                            .addr(address)
                            .map_err(|_| AuditError::Invalid("address"))?,
                    ),
                    None => None,
                },
                attempted: self.seal_addresses(&event.attempted)?,
                answers: event.answers,
                observations: event.observations.clone(),
            })
        })();
        let record = match record {
            Ok(record) => record,
            Err(error) => {
                pending.flags.result_not_recorded(None);
                return Err(error);
            }
        };
        let flow_id = pending.flow_id.clone();
        let id = flow_id.clone();
        let result = self
            .core
            .submit_with(
                flow_id,
                record,
                waits,
                Some(Self::undo_submission(&pending.flags, None)),
                move |written, core| ResultReceipt {
                    core,
                    flow_id: id,
                    seq: written.seq,
                    entry_hash: written.hash,
                    counts,
                    started: Instant::now(),
                    resolved: false,
                    abandoned: false,
                    final_bytes: None,
                },
            )
            .await;
        Self::settle(&pending.flags, &result, None);
        result
    }

    /// What a dropped result future does when its job was still queued (and so is
    /// never written): the `Pending` goes back to having no result, and its own
    /// drop writes the honest one.
    fn undo_submission(flags: &Arc<PendingFlags>, code: Option<&'static str>) -> OnCancel {
        let flags = Arc::clone(flags);
        Box::new(move || flags.result_not_recorded(code))
    }

    /// After a result append came back with an error: unless it was a `Timeout`
    /// (the record may still land, and a second one would break the one-result
    /// rule) the result was not recorded and the `Pending` goes back to having none.
    fn settle<T>(flags: &PendingFlags, result: &Result<T, AuditError>, code: Option<&'static str>) {
        if let Err(error) = result {
            if *error != AuditError::Timeout {
                flags.result_not_recorded(code);
            }
        }
    }

    /// `Result{Failed}`: a dial was started and failed.
    ///
    /// # Errors
    /// [`AuditError`], with the same consequences as [`Self::append_connected`].
    pub async fn append_failed(
        &self,
        pending: &PendingReceipt,
        event: FailedEvent,
        waits: Waits,
    ) -> Result<Receipt, AuditError> {
        pending.flags.begin_result()?;
        let (error_code, unknown_code) = closed(event.error_code, &RESULT_ERROR_CODES);
        let (refusal, unknown_refusal) = match event.refusal {
            Some(label) => {
                let (label, unknown) = closed(label, &RESULT_REFUSALS);
                (Some(label.to_owned()), unknown)
            }
            None => (None, false),
        };
        self.note_unknown(unknown_code || unknown_refusal);
        let attempted = match self.seal_addresses(&event.attempted) {
            Ok(attempted) => attempted,
            Err(error) => {
                pending.flags.result_not_recorded(None);
                return Err(error);
            }
        };
        let record = FlowAuditEvent::Result {
            outcome: ResultOutcome::Failed,
            error_code: Some(error_code.to_owned()),
            refusal,
            chain_kinds: Vec::new(),
            dialed: None,
            attempted,
            answers: event.answers,
            observations: event.observations,
        };
        self.plain_result(pending, record, waits).await
    }

    /// `Result{NotDialed}`: no dial was started.
    ///
    /// # Errors
    /// [`AuditError`]; the `code` is then the one the drop writes.
    pub async fn append_not_dialed(
        &self,
        pending: &PendingReceipt,
        code: &'static str,
        bounded: Duration,
    ) -> Result<Receipt, AuditError> {
        pending.flags.begin_result()?;
        let (code, unknown) = closed(code, &RESULT_ERROR_CODES);
        self.note_unknown(unknown);
        let record = FlowAuditEvent::Result {
            outcome: ResultOutcome::NotDialed,
            error_code: Some(code.to_owned()),
            refusal: None,
            chain_kinds: Vec::new(),
            dialed: None,
            attempted: Vec::new(),
            answers: None,
            observations: Vec::new(),
        };
        let result = self
            .core
            .submit_with(
                pending.flow_id.clone(),
                record,
                Waits::both(bounded),
                Some(Self::undo_submission(&pending.flags, Some(code))),
                |written, _| Receipt::new(written),
            )
            .await;
        Self::settle(&pending.flags, &result, Some(code));
        result
    }

    async fn plain_result(
        &self,
        pending: &PendingReceipt,
        record: FlowAuditEvent,
        waits: Waits,
    ) -> Result<Receipt, AuditError> {
        let result = self
            .core
            .submit_with(
                pending.flow_id.clone(),
                record,
                waits,
                Some(Self::undo_submission(&pending.flags, None)),
                |written, _| Receipt::new(written),
            )
            .await;
        Self::settle(&pending.flags, &result, None);
        result
    }

    /// `Denied`: a refusal, always written with the destination in clear.
    ///
    /// # Errors
    /// [`AuditError`]; the flow still answers `02`.
    pub async fn append_denied(
        &self,
        event: DeniedEvent<'_>,
        waits: Waits,
    ) -> Result<DeniedOutcome, AuditError> {
        let (reason_code, unknown) = closed(event.reason_code, &DENIED_REASON_CODES);
        self.note_unknown(unknown);
        let record = FlowAuditEvent::Denied {
            peer: event.peer.to_owned(),
            peer_verified: event.peer_verified,
            dest: self.core.sealer.denied(event.target),
            target_provenance: event.target.provenance().as_str().to_owned(),
            target_kind: event.target.kind().as_str().to_owned(),
            profile: event.profile.to_owned(),
            matched_rule: event.matched_rule.map(str::to_owned),
            reason_code: reason_code.to_owned(),
            route: event.route,
            coalesced: event.coalesced,
        };
        self.core
            .submit(String::new(), record, waits, |written, _| {
                DeniedOutcome::Recorded(Receipt::new(written))
            })
            .await
    }

    /// `Armed`: durable before the gate opens.
    ///
    /// # Errors
    /// [`AuditError`]; the gate must stay closed.
    pub async fn append_armed(
        &self,
        event: ArmedEvent,
        waits: Waits,
    ) -> Result<ArmReceipt, AuditError> {
        let epoch = event.epoch;
        let record = FlowAuditEvent::Armed {
            profile: event.profile,
            cause: event.actor.cause().to_owned(),
            client: event.actor.client().to_owned(),
            requested_by: event.actor.requested_by().to_owned(),
            epoch,
            profile_digest: event.profile_digest,
            rules: event.rules,
            observations: event.observations,
        };
        self.core
            .submit(String::new(), record, waits, move |written, core| {
                ArmReceipt {
                    core,
                    epoch,
                    seq: written.seq,
                    entry_hash: written.hash,
                    resolved: false,
                }
            })
            .await
    }

    /// `Disarmed`. Never fails the caller: a record that could not be written is
    /// counted.
    pub async fn append_disarmed(&self, event: DisarmedEvent, bounded: Duration) {
        let record = FlowAuditEvent::Disarmed {
            cause: event.cause.as_str().to_owned(),
            epoch: event.epoch,
        };
        let result = self
            .core
            .submit(String::new(), record, Waits::both(bounded), |written, _| {
                Receipt::new(written)
            })
            .await;
        // Never fails the caller, never silent: a `Disarmed` that was not written is
        // counted with the other records that close a story.
        if result.is_err_and(|error| error != AuditError::Timeout) {
            bump(&self.core.shared.compensations_lost);
        }
    }

    /// `Tripped`: synchronous, never blocks, rides the compensation channel. For
    /// the gate's `trip()`, which cannot await. `false` when the writer is gone
    /// (a trip caused by an audit failure cannot be recorded in the audit).
    #[must_use]
    pub fn try_enqueue_tripped(&self, event: TrippedEvent) -> bool {
        self.core.send_comp(
            String::new(),
            FlowAuditEvent::Tripped {
                reason: event.reason.as_str().to_owned(),
                epoch: event.epoch,
            },
        )
    }

    /// `Summary`: the same road as `Tripped`.
    #[must_use]
    pub fn queue_summary(&self, event: SummaryEvent) -> bool {
        self.core.send_comp(
            String::new(),
            FlowAuditEvent::Summary {
                window_ms: event.window_ms,
                pre_admission_rejects: event.pre_admission_rejects,
                denials_suppressed: event.denials_suppressed,
                denials_over_quota: event.denials_over_quota,
                denials_repeated: event.denials_repeated,
                other_keys: event.other_keys,
            },
        )
    }

    /// A barrier: returns once everything queued before it is durable.
    ///
    /// # Errors
    /// `Timeout` after `deadline`; `WriterDown` if the writer ended first.
    pub async fn flush(&self, deadline: Duration) -> Result<(), AuditError> {
        let (tx, rx) = oneshot::channel();
        if self.core.tx.send(Job::Flush(tx)).is_err() {
            return Err(AuditError::WriterDown);
        }
        match timeout(deadline, rx).await {
            Ok(Ok(true)) => Ok(()),
            Ok(_) => Err(AuditError::WriterDown),
            Err(_) => Err(AuditError::Timeout),
        }
    }

    /// How long the disk part of the batch that is running now (the check of the
    /// file, the append, the sync) has been running, if one is: for the host's
    /// stall watchdog.
    #[must_use]
    pub fn io_in_progress_for(&self) -> Option<Duration> {
        let started = self.core.shared.io_started.load(Ordering::Acquire);
        let started = started.checked_sub(1)?;
        Some(Duration::from_millis(
            self.core.now_ms().saturating_sub(started),
        ))
    }

    /// From atomics only: no file is read and no tokio lock is taken.
    #[must_use]
    pub fn status(&self) -> AuditStatus {
        let shared = &self.core.shared;
        let state = if shared.down.load(Ordering::Acquire) {
            WriterState::Down
        } else if self.core.closing.load(Ordering::Acquire) {
            WriterState::Closing
        } else {
            WriterState::Ok
        };
        AuditStatus {
            state,
            entries: shared.entries.load(Ordering::Acquire),
            head: lock_unpoisoned(&shared.head).clone(),
            bytes: shared.bytes.load(Ordering::Acquire),
            queue_depth: shared.queued.load(Ordering::Acquire),
            busy: shared.busy.load(Ordering::Relaxed),
            timeouts: shared.timeouts.load(Ordering::Relaxed),
            queue_full: shared.queue_full.load(Ordering::Relaxed),
            unknown_codes: shared.unknown_codes.load(Ordering::Relaxed),
            compensations_lost: shared.compensations_lost.load(Ordering::Relaxed),
            sync_last_ms: shared.sync_last_ms.load(Ordering::Relaxed),
            sync_max_ms: shared.sync_max_ms.load(Ordering::Relaxed),
            destination_logging: self.core.sealer.mode(),
            dest_key_id: self.core.sealer.kid().map(str::to_owned),
        }
    }

    /// Stops accepting normal appends, lets the writer drain what was queued
    /// (compensation records included), and waits for the thread for at most
    /// `deadline`. After the deadline the join is abandoned: the process is
    /// exiting and holds the daemon lock until it ends. Idempotent.
    pub async fn close(&self, deadline: Duration) {
        self.core.closing.store(true, Ordering::Release);
        let handle = lock_unpoisoned(&self.core.thread).take();
        let Some(handle) = handle else {
            return;
        };
        let _ = self.core.tx.send(Job::Shutdown);
        let join = tokio::task::spawn_blocking(move || {
            let _ = handle.join();
        });
        let _ = timeout(deadline, join).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::Condvar;

    use ssk_netadmin::{
        FlowDescriptor, FlowRecord, PolicyAction, PolicyDecision, ProtocolKind, RiskLevel,
        RouteOrchestrator,
    };

    use crate::ingress::audit::dest::DestKey;
    use crate::ingress::audit::fs::ActiveStat;
    use crate::ingress::audit::record::Chain;
    use crate::ingress::target::{canonicalize, Provenance, RawTarget};
    use crate::ingress::types::{
        Actor, ClientLabel, HostKind, IngressCfgView, Resolution, RuleTable,
    };

    // -- the disk double ------------------------------------------------------

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Stat,
        Append(usize),
        Sync,
        Truncate(u64),
    }

    #[derive(Default)]
    struct Disk {
        file: Vec<u8>,
        calls: Vec<Call>,
        appends: usize,
        syncs: usize,
        /// The nth append (1-based) writes half of its bytes and fails.
        fail_append_at: Option<usize>,
        /// The nth sync (1-based) fails.
        fail_sync_at: Option<usize>,
        block_sync: bool,
        in_sync: bool,
        block_append: bool,
        in_append: bool,
        unlinked: bool,
        stat_fails: bool,
        panic_on_append: bool,
    }

    struct DiskCell {
        disk: Mutex<Disk>,
        changed: Condvar,
    }

    #[derive(Clone)]
    struct FakeIo(Arc<DiskCell>);

    impl FakeIo {
        fn new() -> Self {
            Self(Arc::new(DiskCell {
                disk: Mutex::new(Disk::default()),
                changed: Condvar::new(),
            }))
        }

        fn with<T>(&self, f: impl FnOnce(&mut Disk) -> T) -> T {
            f(&mut lock_unpoisoned(&self.0.disk))
        }

        fn block(&self) {
            self.with(|d| d.block_sync = true);
        }

        fn release(&self) {
            self.with(|d| {
                d.block_sync = false;
                d.block_append = false;
            });
            self.0.changed.notify_all();
        }

        fn calls(&self) -> Vec<Call> {
            self.with(|d| d.calls.clone())
        }

        fn len(&self) -> usize {
            self.with(|d| d.file.len())
        }

        fn text(&self) -> String {
            self.with(|d| String::from_utf8_lossy(&d.file).into_owned())
        }

        /// Every record on the "disk", each verified against the chain from genesis.
        fn records(&self) -> Vec<FlowAuditRecord> {
            let bytes = self.with(|d| d.file.clone());
            let mut chain = Chain::genesis();
            let mut out = Vec::new();
            for line in bytes.split(|byte| *byte == b'\n') {
                if line.is_empty() {
                    continue;
                }
                out.push(chain.accept(line).expect("every line chains"));
            }
            out
        }
    }

    impl LedgerIo for FakeIo {
        fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
            let mut disk = lock_unpoisoned(&self.0.disk);
            disk.in_append = true;
            self.0.changed.notify_all();
            while disk.block_append {
                disk = self
                    .0
                    .changed
                    .wait(disk)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            disk.in_append = false;
            disk.calls.push(Call::Append(bytes.len()));
            disk.appends += 1;
            if disk.panic_on_append {
                drop(disk);
                panic!("the disk double was told to panic");
            }
            if disk.fail_append_at == Some(disk.appends) {
                let half = bytes.len() / 2;
                disk.file
                    .extend_from_slice(bytes.get(..half).unwrap_or_default());
                return Err(io::Error::from(io::ErrorKind::StorageFull));
            }
            disk.file.extend_from_slice(bytes);
            Ok(())
        }

        fn sync_data(&mut self) -> io::Result<()> {
            let mut disk = lock_unpoisoned(&self.0.disk);
            disk.calls.push(Call::Sync);
            disk.syncs += 1;
            disk.in_sync = true;
            self.0.changed.notify_all();
            while disk.block_sync {
                disk = self
                    .0
                    .changed
                    .wait(disk)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            disk.in_sync = false;
            if disk.fail_sync_at == Some(disk.syncs) {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            Ok(())
        }

        fn active_stat(&self) -> io::Result<ActiveStat> {
            let mut disk = lock_unpoisoned(&self.0.disk);
            disk.calls.push(Call::Stat);
            if disk.stat_fails {
                return Err(io::Error::from(io::ErrorKind::Other));
            }
            Ok(ActiveStat {
                len: u64::try_from(disk.file.len()).expect("fits"),
                nlink: if disk.unlinked { 0 } else { 1 },
            })
        }

        fn truncate_active(&mut self, len: u64) -> io::Result<()> {
            let mut disk = lock_unpoisoned(&self.0.disk);
            disk.calls.push(Call::Truncate(len));
            disk.file.truncate(usize::try_from(len).expect("fits"));
            Ok(())
        }

        fn rotate(&mut self, _next_first_seq: u64, _first_record: &[u8]) -> io::Result<()> {
            Err(io::Error::other("rotation is C-A7"))
        }

        fn prune(&mut self, _keep: u32) -> io::Result<super::super::fs::PruneOutcome> {
            Err(io::Error::other("pruning is C-A7"))
        }
    }

    // -- helpers ----------------------------------------------------------------

    type Trips = Arc<Mutex<Vec<TripReason>>>;

    fn cfg(mode: DestinationLogging, queue_cap: usize) -> AuditOpenCfg {
        let view = IngressCfgView::for_tests();
        let ticks = Arc::new(AtomicU64::new(0));
        AuditOpenCfg {
            segment_bytes: 1 << 20,
            retain_segments: 4,
            denied_share_percent: 20,
            summary_share_percent: 5,
            destination_logging: mode,
            fingerprint: view.fingerprint,
            daemon_version: "0.0.0-test".to_owned(),
            queue_cap,
            clock: Arc::new(move || 1_700_000_000_000 + ticks.fetch_add(1, Ordering::Relaxed)),
        }
    }

    fn trips() -> (Trips, TripFn) {
        let seen: Trips = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        (
            seen,
            Arc::new(move |reason| lock_unpoisoned(&sink).push(reason)),
        )
    }

    fn open_plain(io: &FakeIo) -> (Arc<FlowAuditWriter>, Trips) {
        open_with_sealer(io, DestSealer::Plain, DestinationLogging::Plain, 8)
    }

    fn open_with_sealer(
        io: &FakeIo,
        sealer: DestSealer,
        mode: DestinationLogging,
        queue_cap: usize,
    ) -> (Arc<FlowAuditWriter>, Trips) {
        let (seen, on_trip) = trips();
        let writer = FlowAuditWriter::open_with(
            io.clone(),
            Replayed::fresh(),
            &cfg(mode, queue_cap),
            sealer,
            on_trip,
        )
        .expect("opens");
        (Arc::new(writer), seen)
    }

    fn token(host: &str, port: u16) -> AdmissionToken {
        let flow = FlowRecord::new(
            "flow",
            0,
            FlowDescriptor::new("app", host, port, ProtocolKind::Tcp, RiskLevel::Low),
        );
        let decision = PolicyDecision {
            flow_id: flow.flow_id.clone(),
            matched_rule: None,
            action: PolicyAction::Allow,
            rationale: String::new(),
        };
        RouteOrchestrator::default()
            .admit(&flow, &decision)
            .expect("admitted")
    }

    const LONG: Waits = Waits {
        queue_wait: Duration::from_secs(20),
        sync_wait: Duration::from_secs(20),
    };

    async fn pend_kind(
        writer: &FlowAuditWriter,
        host: &str,
        port: u16,
        kind: TargetKind,
        waits: Waits,
    ) -> Result<PendingReceipt, AuditError> {
        let token = token(host, port);
        let flow = writer.next_flow_id();
        let adapters = vec!["direct".to_owned()];
        writer
            .append_pending(
                PendingInput {
                    token: &token,
                    flow_id: &flow,
                    profile: "main",
                    matched_rule: Some("rule-1"),
                    peer: "uid:1000",
                    peer_verified: true,
                    target_kind: kind,
                    provenance: Provenance::ClientSuppliedName,
                    resolution: Resolution::LocalPinned,
                    planned_adapters: &adapters,
                },
                waits,
            )
            .await
    }

    async fn pend(
        writer: &FlowAuditWriter,
        host: &str,
        port: u16,
        waits: Waits,
    ) -> Result<PendingReceipt, AuditError> {
        pend_kind(writer, host, port, TargetKind::Name, waits).await
    }

    fn sa(text: &str) -> std::net::SocketAddr {
        text.parse().expect("socket address")
    }

    async fn eventually(what: &str, cond: impl Fn() -> bool) {
        for _ in 0..2000 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("never happened: {what}");
    }

    fn events(io: &FakeIo) -> Vec<(u64, &'static str)> {
        io.records()
            .iter()
            .map(|r| (r.seq, r.event.kind()))
            .collect()
    }

    fn results(io: &FakeIo) -> Vec<(ResultOutcome, Option<String>)> {
        let found: Vec<(ResultOutcome, Option<String>)> = io
            .records()
            .into_iter()
            .filter_map(|r| match r.event {
                FlowAuditEvent::Result {
                    outcome,
                    error_code,
                    ..
                } => Some((outcome, error_code)),
                _ => None,
            })
            .collect();
        // Every code a receipt writes by itself is one of the closed list.
        for (_, code) in &found {
            if let Some(code) = code {
                assert!(
                    !closed(code, &RESULT_ERROR_CODES).1,
                    "{code} is not in the closed list"
                );
            }
        }
        found
    }

    // -- opening ----------------------------------------------------------------

    #[tokio::test]
    async fn open_writes_started_first_with_the_mode_and_the_key_id() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let records = io.records();
        assert_eq!(records.len(), 1);
        let first = records.first().expect("one record");
        assert_eq!((first.seq, first.flow_id.as_str()), (1, ""));
        match &first.event {
            FlowAuditEvent::Started {
                daemon_version,
                ledger_format,
                destination_logging,
                dest_key_id,
                unresolved_before,
                ..
            } => {
                assert_eq!(daemon_version, "0.0.0-test");
                assert_eq!(*ledger_format, 1);
                assert_eq!(*destination_logging, DestinationLogging::Plain);
                assert_eq!(*dest_key_id, None);
                assert_eq!(*unresolved_before, Unresolved::default());
            }
            other => panic!("not Started: {other:?}"),
        }
        assert_eq!(writer.boot_seq(), 1);
        assert_eq!(writer.next_flow_id(), "ingress:b1:1");
        assert_eq!(writer.next_flow_id(), "ingress:b1:2");
        assert_eq!(io.calls(), [Call::Stat, Call::Append(io.len()), Call::Sync]);

        let hashed = FakeIo::new();
        let key = Arc::new(DestKey::from_bytes([7; 32]));
        let kid = key.kid().to_owned();
        let (_writer, _) = open_with_sealer(
            &hashed,
            DestSealer::Hashed(key),
            DestinationLogging::Hashed,
            8,
        );
        match &hashed.records().first().expect("started").event {
            FlowAuditEvent::Started {
                destination_logging,
                dest_key_id,
                ..
            } => {
                assert_eq!(*destination_logging, DestinationLogging::Hashed);
                assert_eq!(dest_key_id.as_deref(), Some(kid.as_str()));
            }
            other => panic!("not Started: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_second_boot_continues_the_chain_and_the_flow_ids_say_which_boot() {
        let io = FakeIo::new();
        let (first, _) = open_plain(&io);
        let receipt = pend(&first, "example.com", 443, LONG)
            .await
            .expect("pending");
        assert_eq!(receipt.flow_id(), "ingress:b1:1");
        let status = first.status();
        receipt.mark_dial_started();
        drop(receipt);
        first.close(Duration::from_secs(10)).await;
        let last = io.records().last().map(|r| r.seq).expect("records");
        let replayed = Replayed {
            head: first.status().head,
            last_seq: Some(last),
            active_len: u64::try_from(io.len()).expect("fits"),
            entries: last,
            bytes: u64::try_from(io.len()).expect("fits"),
            unresolved: Unresolved {
                pending: 1,
                open_tunnels: 0,
            },
            truncated_tail_bytes: 12,
            after_trip: Some("audit_write_failed".to_owned()),
        };
        assert_eq!(status.entries, 2);
        let (on_trip_seen, on_trip) = trips();
        let second = FlowAuditWriter::open_with(
            io.clone(),
            replayed,
            &cfg(DestinationLogging::Plain, 8),
            DestSealer::Plain,
            on_trip,
        )
        .expect("reopens");
        assert!(lock_unpoisoned(&on_trip_seen).is_empty());
        // Recovered comes first, then Started, and the chain never breaks.
        let kinds = events(&io);
        let tail: Vec<&str> = kinds.iter().rev().take(2).rev().map(|(_, k)| *k).collect();
        assert_eq!(tail, ["recovered", "started"]);
        let recovered_at = kinds
            .iter()
            .rposition(|(_, k)| *k == "recovered")
            .expect("recovered");
        match &io.records().get(recovered_at).expect("record").event {
            FlowAuditEvent::Recovered {
                truncated_tail_bytes,
                unresolved,
                after_trip,
            } => {
                assert_eq!(*truncated_tail_bytes, 12);
                assert_eq!(unresolved.pending, 1);
                assert_eq!(after_trip.as_deref(), Some("audit_write_failed"));
            }
            other => panic!("not Recovered: {other:?}"),
        }
        let boot = second.boot_seq();
        assert_eq!(second.next_flow_id(), format!("ingress:b{boot}:1"));
        assert_ne!(second.next_flow_id(), "ingress:b1:2");
        let seqs: Vec<u64> = events(&io).iter().map(|(s, _)| *s).collect();
        assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1), "{seqs:?}");
    }

    #[tokio::test]
    async fn the_sealer_must_match_the_configured_mode() {
        let io = FakeIo::new();
        let (_seen, on_trip) = trips();
        let result = FlowAuditWriter::open_with(
            io.clone(),
            Replayed::fresh(),
            &cfg(DestinationLogging::Hashed, 8),
            DestSealer::Plain,
            on_trip,
        );
        assert_eq!(result.err(), Some(AuditOpenError::ModeMismatch));
        assert_eq!(io.len(), 0, "nothing was written");
    }

    #[tokio::test]
    async fn a_ledger_with_no_sequence_number_left_is_not_opened() {
        let io = FakeIo::new();
        let (_seen, on_trip) = trips();
        let replayed = Replayed {
            last_seq: Some(u64::MAX),
            ..Replayed::fresh()
        };
        let result = FlowAuditWriter::open_with(
            io.clone(),
            replayed,
            &cfg(DestinationLogging::Plain, 8),
            DestSealer::Plain,
            on_trip,
        );
        assert_eq!(result.err(), Some(AuditOpenError::SeqExhausted));
    }

    #[tokio::test]
    async fn a_failure_while_opening_is_the_openers_and_trips_nothing() {
        let io = FakeIo::new();
        io.with(|d| d.fail_sync_at = Some(1));
        let (seen, on_trip) = trips();
        let result = FlowAuditWriter::open_with(
            io.clone(),
            Replayed::fresh(),
            &cfg(DestinationLogging::Plain, 8),
            DestSealer::Plain,
            on_trip,
        );
        assert_eq!(
            result.err(),
            Some(AuditOpenError::Io("AUDIT_PERMISSION_DENIED"))
        );
        assert!(lock_unpoisoned(&seen).is_empty(), "no trip while opening");
        assert_eq!(io.len(), 0, "the torn first line was cut again");
    }

    // -- durability ----------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn a_receipt_exists_only_after_the_sync_that_covers_its_record() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        io.block();
        let task = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { pend(&writer, "example.com", 443, LONG).await })
        };
        eventually("the writer is inside the sync", || io.with(|d| d.in_sync)).await;
        // The bytes are in the file, and the caller still has nothing.
        assert!(io.text().contains("\"event\":\"pending\""));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!task.is_finished(), "no receipt before the sync returned");
        io.release();
        let receipt = task.await.expect("joined").expect("receipt");
        assert_eq!(receipt.seq(), 2);
        let calls = io.calls();
        assert!(
            matches!(
                calls.as_slice(),
                [.., Call::Stat, Call::Append(_), Call::Sync]
            ),
            "{calls:?}"
        );
        receipt.mark_dial_started();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn jobs_that_wait_together_share_one_append_and_one_sync() {
        let io = FakeIo::new();
        let (writer, _) = open_with_sealer(&io, DestSealer::Plain, DestinationLogging::Plain, 16);
        io.block();
        let first = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { pend(&writer, "a.example", 443, LONG).await })
        };
        eventually("the first job is in its sync", || io.with(|d| d.in_sync)).await;
        let mut rest = Vec::new();
        for n in 0..5 {
            let writer = Arc::clone(&writer);
            rest.push(tokio::spawn(async move {
                pend(&writer, &format!("h{n}.example"), 443, LONG).await
            }));
        }
        eventually("five jobs are queued", || writer.status().queue_depth == 5).await;
        io.release();
        let mut receipts = vec![first.await.expect("joined").expect("receipt")];
        for task in rest {
            receipts.push(task.await.expect("joined").expect("receipt"));
        }
        // Started, the first job alone, then the five together.
        let (appends, syncs) = io.with(|d| (d.appends, d.syncs));
        assert_eq!((appends, syncs), (3, 3), "{:?}", io.calls());
        let mut seqs: Vec<u64> = receipts.iter().map(PendingReceipt::seq).collect();
        seqs.sort_unstable();
        assert_eq!(seqs, [2, 3, 4, 5, 6, 7]);
        for receipt in &receipts {
            receipt.mark_dial_started();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_appends_form_one_verified_chain_with_dense_sequence_numbers() {
        let io = FakeIo::new();
        let (writer, _) = open_with_sealer(&io, DestSealer::Plain, DestinationLogging::Plain, 64);
        let mut tasks = Vec::new();
        for n in 0..40 {
            let writer = Arc::clone(&writer);
            tasks.push(tokio::spawn(async move {
                let target =
                    canonicalize(RawTarget::Name(format!("h{n}.example").into_bytes(), 80))
                        .expect("target");
                writer
                    .append_denied(
                        DeniedEvent {
                            peer: "uid:1000",
                            peer_verified: true,
                            target: &target,
                            profile: "main",
                            matched_rule: None,
                            reason_code: "POLICY_DENY",
                            route: None,
                            coalesced: false,
                        },
                        LONG,
                    )
                    .await
            }));
        }
        let mut seqs = Vec::new();
        for task in tasks {
            match task.await.expect("joined").expect("recorded") {
                DeniedOutcome::Recorded(receipt) => seqs.push(receipt.seq()),
                DeniedOutcome::OverQuota => panic!("no quota in this commit"),
            }
        }
        seqs.sort_unstable();
        assert_eq!(seqs, (2..=41).collect::<Vec<u64>>());
        let on_disk: Vec<u64> = io.records().iter().map(|r| r.seq).collect();
        assert_eq!(on_disk, (1..=41).collect::<Vec<u64>>());
        let status = writer.status();
        assert_eq!(status.entries, 41);
        assert_eq!(status.bytes, u64::try_from(io.len()).expect("fits"));
        assert_eq!(
            Some(status.head),
            io.text()
                .lines()
                .last()
                .map(|l| l.split(' ').next().unwrap_or("").to_owned())
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn per_flow_the_order_is_pending_then_result_then_closed() {
        let io = FakeIo::new();
        let (writer, _) = open_with_sealer(&io, DestSealer::Plain, DestinationLogging::Plain, 64);
        let mut tasks = Vec::new();
        for n in 0..24 {
            let writer = Arc::clone(&writer);
            tasks.push(tokio::spawn(async move {
                let pending = pend(&writer, &format!("h{n}.example"), 443, LONG)
                    .await
                    .expect("pending");
                pending.mark_dial_started();
                let result = writer
                    .append_connected(
                        &pending,
                        ConnectedEvent {
                            chain_kinds: vec!["direct"],
                            dialed: Some(sa("93.184.216.34:443")),
                            attempted: vec![sa("93.184.216.34:443")],
                            answers: Some(1),
                            observations: Vec::new(),
                        },
                        Arc::new(ByteCounts::with_counts(10, 20)),
                        LONG,
                    )
                    .await
                    .expect("connected");
                result
                    .closed(
                        ClosedEvent {
                            bytes_up: 10,
                            bytes_down: 20,
                            reason: CloseReason::Eof,
                        },
                        Duration::from_secs(20),
                    )
                    .await;
            }));
        }
        for task in tasks {
            task.await.expect("joined");
        }
        let records = io.records();
        let mut by_flow: std::collections::BTreeMap<String, Vec<(u64, &'static str)>> =
            std::collections::BTreeMap::new();
        for record in &records {
            if !record.flow_id.is_empty() {
                by_flow
                    .entry(record.flow_id.clone())
                    .or_default()
                    .push((record.seq, record.event.kind()));
            }
        }
        assert_eq!(by_flow.len(), 24);
        for (flow, story) in by_flow {
            let kinds: Vec<&str> = story.iter().map(|(_, k)| *k).collect();
            assert_eq!(kinds, ["pending", "result", "closed"], "{flow}");
            assert!(
                story.windows(2).all(|w| w[0].0 < w[1].0),
                "{flow}: {story:?}"
            );
        }
    }

    // -- faults --------------------------------------------------------------------

    async fn deny(writer: &FlowAuditWriter, waits: Waits) -> Result<DeniedOutcome, AuditError> {
        let target =
            canonicalize(RawTarget::Name(b"blocked.example".to_vec(), 25)).expect("target");
        writer
            .append_denied(
                DeniedEvent {
                    peer: "uid:1000",
                    peer_verified: true,
                    target: &target,
                    profile: "main",
                    matched_rule: Some("deny-1"),
                    reason_code: "POLICY_DENY",
                    route: None,
                    coalesced: false,
                },
                waits,
            )
            .await
    }

    #[tokio::test]
    async fn a_failed_append_is_cut_back_trips_once_and_ends_the_writer() {
        let io = FakeIo::new();
        let (writer, seen) = open_plain(&io);
        let before = io.len();
        io.with(|d| d.fail_append_at = Some(d.appends + 1));
        assert_eq!(
            deny(&writer, LONG).await.err(),
            Some(AuditError::Io("AUDIT_DISK_FULL"))
        );
        // Half of the line reached the file; the writer cut it off again.
        assert_eq!(io.len(), before);
        assert!(io
            .calls()
            .contains(&Call::Truncate(u64::try_from(before).expect("fits"))));
        assert_eq!(*lock_unpoisoned(&seen), [TripReason::AuditWriteFailed]);
        // Nothing is accepted after that, and the trip is not repeated.
        assert_eq!(
            deny(&writer, LONG).await.err(),
            Some(AuditError::WriterDown)
        );
        assert_eq!(writer.status().state, WriterState::Down);
        assert_eq!(lock_unpoisoned(&seen).len(), 1);
        assert_eq!(io.records().len(), 1, "only Started");
        assert!(!writer.try_enqueue_tripped(TrippedEvent {
            reason: TripReason::AuditWriteFailed,
            epoch: 1
        }));
    }

    #[tokio::test]
    async fn a_failed_sync_is_cut_back_and_trips() {
        let io = FakeIo::new();
        let (writer, seen) = open_plain(&io);
        let before = io.len();
        io.with(|d| d.fail_sync_at = Some(d.syncs + 1));
        assert_eq!(
            deny(&writer, LONG).await.err(),
            Some(AuditError::Io("AUDIT_PERMISSION_DENIED"))
        );
        assert_eq!(
            io.len(),
            before,
            "a line that was not synced is not left behind"
        );
        assert_eq!(*lock_unpoisoned(&seen), [TripReason::AuditWriteFailed]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn every_job_of_a_failed_batch_gets_the_fault_and_the_queue_behind_it_gets_writer_down() {
        let io = FakeIo::new();
        let (writer, seen) =
            open_with_sealer(&io, DestSealer::Plain, DestinationLogging::Plain, 16);
        io.block();
        let first = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { deny(&writer, LONG).await })
        };
        eventually("the first job is in its sync", || io.with(|d| d.in_sync)).await;
        // Three more arrive together; the batch they form will fail.
        let mut batch = Vec::new();
        for _ in 0..3 {
            let writer = Arc::clone(&writer);
            batch.push(tokio::spawn(async move { deny(&writer, LONG).await }));
        }
        eventually("three queued", || writer.status().queue_depth == 3).await;
        io.with(|d| d.fail_append_at = Some(d.appends + 1));
        io.release();
        assert!(first.await.expect("joined").is_ok());
        for task in batch {
            assert_eq!(
                task.await.expect("joined").err(),
                Some(AuditError::Io("AUDIT_DISK_FULL"))
            );
        }
        assert_eq!(lock_unpoisoned(&seen).len(), 1);
    }

    #[tokio::test]
    async fn a_file_that_changed_behind_the_writers_back_is_a_write_fault() {
        for case in ["appended", "unlinked", "stat fails"] {
            let io = FakeIo::new();
            let (writer, seen) = open_plain(&io);
            io.with(|d| match case {
                "appended" => d.file.push(b'x'),
                "unlinked" => d.unlinked = true,
                _ => d.stat_fails = true,
            });
            let expected = if case == "stat fails" {
                AuditError::Io("AUDIT_IO")
            } else {
                AuditError::Io("AUDIT_EXTERNAL_MODIFICATION")
            };
            assert_eq!(deny(&writer, LONG).await.err(), Some(expected), "{case}");
            assert_eq!(
                *lock_unpoisoned(&seen),
                [TripReason::AuditWriteFailed],
                "{case}"
            );
            if case == "appended" {
                assert!(
                    !io.calls().iter().any(|c| matches!(c, Call::Append(_)))
                        || io.with(|d| d.appends) == 1,
                    "nothing was appended on top of the foreign byte"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_writer_thread_that_panics_trips_and_every_later_append_is_refused() {
        let io = FakeIo::new();
        let (writer, seen) = open_plain(&io);
        io.with(|d| d.panic_on_append = true);
        assert_eq!(
            deny(&writer, LONG).await.err(),
            Some(AuditError::WriterDown)
        );
        eventually("the guard tripped", || !lock_unpoisoned(&seen).is_empty()).await;
        assert_eq!(*lock_unpoisoned(&seen), [TripReason::AuditWriteFailed]);
        assert_eq!(
            deny(&writer, LONG).await.err(),
            Some(AuditError::WriterDown)
        );
        assert_eq!(writer.status().state, WriterState::Down);
    }

    #[tokio::test]
    async fn the_last_sequence_number_is_written_and_the_next_append_trips() {
        let io = FakeIo::new();
        let (seen, on_trip) = trips();
        let replayed = Replayed {
            last_seq: Some(u64::MAX - 2),
            ..Replayed::fresh()
        };
        // The chain on the double starts at genesis, so give it a matching start.
        let writer = FlowAuditWriter::open_with(
            io.clone(),
            replayed,
            &cfg(DestinationLogging::Plain, 8),
            DestSealer::Plain,
            on_trip,
        )
        .expect("opens");
        assert_eq!(writer.boot_seq(), u64::MAX - 1);
        let last = deny(&writer, LONG)
            .await
            .expect("the last number is a record");
        let DeniedOutcome::Recorded(receipt) = last else {
            panic!("recorded");
        };
        assert_eq!(receipt.seq(), u64::MAX);
        assert_eq!(
            deny(&writer, LONG).await.err(),
            Some(AuditError::SeqExhausted)
        );
        eventually("tripped", || !lock_unpoisoned(&seen).is_empty()).await;
        assert_eq!(writer.status().state, WriterState::Down);
    }

    // -- queue, busy, timeout, cancellation ---------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn a_full_queue_refuses_at_once_and_compensation_bypasses_the_cap() {
        let io = FakeIo::new();
        let (writer, _) = open_with_sealer(&io, DestSealer::Plain, DestinationLogging::Plain, 3);
        io.block();
        let mut tasks = Vec::new();
        {
            let writer = Arc::clone(&writer);
            tasks.push(tokio::spawn(async move { deny(&writer, LONG).await }));
        }
        eventually("in sync", || io.with(|d| d.in_sync)).await;
        for _ in 0..3 {
            let writer = Arc::clone(&writer);
            tasks.push(tokio::spawn(async move { deny(&writer, LONG).await }));
        }
        eventually("three queued", || writer.status().queue_depth == 3).await;
        let started = Instant::now();
        assert_eq!(deny(&writer, LONG).await.err(), Some(AuditError::QueueFull));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "refused without waiting"
        );
        assert_eq!(writer.status().queue_full, 1);
        // The cap does not apply to a record that closes a story.
        assert!(writer.try_enqueue_tripped(TrippedEvent {
            reason: TripReason::AcceptFatal,
            epoch: 4
        }));
        io.release();
        for task in tasks {
            assert!(task.await.expect("joined").is_ok());
        }
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        assert_eq!(writer.status().queue_depth, 0);
        assert!(events(&io).iter().any(|(_, k)| *k == "tripped"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_job_the_writer_never_claimed_is_cancelled_and_never_written() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        io.block();
        let blocker = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { deny(&writer, LONG).await })
        };
        eventually("in sync", || io.with(|d| d.in_sync)).await;
        let waits = Waits {
            queue_wait: Duration::from_millis(60),
            sync_wait: Duration::from_secs(20),
        };
        assert_eq!(
            pend(&writer, "late.example", 443, waits).await.err(),
            Some(AuditError::Busy)
        );
        assert_eq!(writer.status().busy, 1);
        io.release();
        assert!(blocker.await.expect("joined").is_ok());
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        // Started and the blocker only: the cancelled job consumed no sequence number.
        assert_eq!(events(&io), [(1, "started"), (2, "denied")]);
        assert_eq!(writer.status().queue_depth, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_claimed_job_that_is_not_answered_in_time_is_abandoned_and_compensated_when_it_lands()
    {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        io.block();
        // The claim is checked when the first wait ends, so both waits are short.
        let waits = Waits::both(Duration::from_millis(80));
        assert_eq!(
            pend(&writer, "slow.example", 443, waits).await.err(),
            Some(AuditError::Timeout)
        );
        assert_eq!(writer.status().timeouts, 1);
        io.release();
        eventually("the compensation landed", || results(&io).len() == 1).await;
        // The Pending was written (the sync only returned late), nobody holds its
        // receipt, and its story is closed by the writer's own drop of it.
        assert_eq!(events(&io), [(1, "started"), (2, "pending"), (3, "result")]);
        assert_eq!(
            results(&io),
            [(ResultOutcome::NotDialed, Some("AUDIT_ABANDONED".to_owned()))]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_caller_dropped_after_the_claim_leaves_a_closed_story() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        io.block();
        let task = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { pend(&writer, "gone.example", 443, LONG).await })
        };
        eventually("claimed and syncing", || io.with(|d| d.in_sync)).await;
        task.abort();
        let _ = task.await;
        io.release();
        eventually("the compensation landed", || results(&io).len() == 1).await;
        assert_eq!(
            results(&io),
            [(ResultOutcome::NotDialed, Some("AUDIT_ABANDONED".to_owned()))]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_caller_dropped_while_queued_is_never_written() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        io.block();
        let blocker = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { deny(&writer, LONG).await })
        };
        eventually("in sync", || io.with(|d| d.in_sync)).await;
        let queued = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { pend(&writer, "never.example", 443, LONG).await })
        };
        eventually("queued", || writer.status().queue_depth == 1).await;
        queued.abort();
        let _ = queued.await;
        io.release();
        assert!(blocker.await.expect("joined").is_ok());
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        assert_eq!(events(&io), [(1, "started"), (2, "denied")]);
        assert!(!io.text().contains("never.example"));
    }

    // -- the receipts ------------------------------------------------------------------

    #[tokio::test]
    async fn a_pending_dropped_without_a_dial_closes_its_story_with_not_dialed() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let receipt = pend(&writer, "example.com", 443, LONG)
            .await
            .expect("pending");
        drop(receipt);
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        assert_eq!(
            results(&io),
            [(ResultOutcome::NotDialed, Some("FLOW_DROPPED".to_owned()))]
        );
    }

    #[tokio::test]
    async fn a_pending_dropped_after_the_dial_started_closes_its_story_with_aborted() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let receipt = pend(&writer, "example.com", 443, LONG)
            .await
            .expect("pending");
        receipt.mark_dial_started();
        drop(receipt);
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        assert_eq!(
            results(&io),
            [(
                ResultOutcome::Aborted,
                Some("DIAL_NOT_COMPLETED".to_owned())
            )]
        );
    }

    #[tokio::test]
    async fn a_result_that_was_submitted_is_not_compensated_again() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let receipt = pend(&writer, "example.com", 443, LONG)
            .await
            .expect("pending");
        receipt.mark_dial_started();
        let result = writer
            .append_failed(&receipt, FailedEvent::code("NETCORE_TIMEOUT"), LONG)
            .await
            .expect("recorded");
        assert_eq!(result.seq(), 3);
        // A second result for the same Pending is a bug, and is refused.
        assert_eq!(
            writer
                .append_not_dialed(&receipt, "GATE_CLOSED", Duration::from_secs(5))
                .await
                .err(),
            Some(AuditError::Invalid("result already submitted"))
        );
        drop(receipt);
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        assert_eq!(
            results(&io),
            [(ResultOutcome::Failed, Some("NETCORE_TIMEOUT".to_owned()))]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_result_that_could_not_be_recorded_is_written_by_the_drop_with_the_honest_code() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let dialed = pend(&writer, "dialed.example", 443, LONG)
            .await
            .expect("pending");
        let undialed = pend(&writer, "undialed.example", 443, LONG)
            .await
            .expect("pending");
        io.block();
        let blocker = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { deny(&writer, LONG).await })
        };
        eventually("in sync", || io.with(|d| d.in_sync)).await;
        let short = Duration::from_millis(40);
        dialed.mark_dial_started();
        assert_eq!(
            writer
                .append_connected(
                    &dialed,
                    ConnectedEvent::default(),
                    Arc::new(ByteCounts::default()),
                    Waits::both(short)
                )
                .await
                .err(),
            Some(AuditError::Busy)
        );
        assert_eq!(
            writer
                .append_not_dialed(&undialed, "GATE_CLOSED", short)
                .await
                .err(),
            Some(AuditError::Busy)
        );
        drop(dialed);
        drop(undialed);
        io.release();
        assert!(blocker.await.expect("joined").is_ok());
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        let mut got = results(&io);
        got.sort_by_key(|(_, code)| code.clone());
        assert_eq!(
            got,
            [
                (ResultOutcome::NotDialed, Some("GATE_CLOSED".to_owned())),
                (
                    ResultOutcome::Aborted,
                    Some("RESULT_NOT_RECORDED".to_owned())
                ),
            ]
        );
    }

    #[tokio::test]
    async fn a_connected_result_is_the_proof_and_closed_consumes_it_exactly_once() {
        fn needs_proof<P: ResultProof>(_: &P) {}
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let pending = pend(&writer, "example.com", 443, LONG)
            .await
            .expect("pending");
        pending.mark_dial_started();
        let counts = Arc::new(ByteCounts::with_counts(11, 22));
        let result = writer
            .append_connected(
                &pending,
                ConnectedEvent {
                    chain_kinds: vec!["direct"],
                    dialed: Some(sa("93.184.216.34:443")),
                    attempted: vec![sa("93.184.216.34:443"), sa("[2606:2800:220:1::1]:443")],
                    answers: Some(2),
                    observations: Vec::new(),
                },
                counts,
                LONG,
            )
            .await
            .expect("connected");
        needs_proof(&result);
        assert_eq!(result.seq(), 3);
        result
            .closed(
                ClosedEvent {
                    bytes_up: 100,
                    bytes_down: 200,
                    reason: CloseReason::IdleTimeout,
                },
                Duration::from_secs(5),
            )
            .await;
        drop(pending);
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        let kinds: Vec<&str> = events(&io).iter().map(|(_, k)| *k).collect();
        assert_eq!(kinds, ["started", "pending", "result", "closed"]);
        match &io.records().last().expect("closed").event {
            FlowAuditEvent::Closed {
                bytes_up,
                bytes_down,
                reason,
                ..
            } => assert_eq!(
                (*bytes_up, *bytes_down, reason.as_str()),
                (100, 200, "idle_timeout")
            ),
            other => panic!("not Closed: {other:?}"),
        }
        match &io.records().get(2).expect("result").event {
            FlowAuditEvent::Result {
                outcome,
                dialed,
                attempted,
                answers,
                chain_kinds,
                ..
            } => {
                assert_eq!(*outcome, ResultOutcome::Connected);
                assert_eq!(attempted.len(), 2);
                assert!(dialed.is_some());
                assert_eq!(
                    (*answers, chain_kinds.as_slice()),
                    (Some(2), ["direct".to_owned()].as_slice())
                );
            }
            other => panic!("not Result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_result_receipt_dropped_open_writes_closed_with_the_counted_bytes() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let pending = pend(&writer, "example.com", 443, LONG)
            .await
            .expect("pending");
        pending.mark_dial_started();
        let result = writer
            .append_connected(
                &pending,
                ConnectedEvent::default(),
                Arc::new(ByteCounts::with_counts(7, 9)),
                LONG,
            )
            .await
            .expect("connected");
        drop(result);
        drop(pending);
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        match &io.records().last().expect("closed").event {
            FlowAuditEvent::Closed {
                bytes_up,
                bytes_down,
                reason,
                ..
            } => assert_eq!((*bytes_up, *bytes_down, reason.as_str()), (7, 9, "aborted")),
            other => panic!("not Closed: {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_closed_that_could_not_be_written_is_written_by_the_drop_as_audit_abandoned() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let pending = pend(&writer, "example.com", 443, LONG)
            .await
            .expect("pending");
        pending.mark_dial_started();
        let result = writer
            .append_connected(
                &pending,
                ConnectedEvent::default(),
                Arc::new(ByteCounts::with_counts(1, 1)),
                LONG,
            )
            .await
            .expect("connected");
        io.block();
        let blocker = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { deny(&writer, LONG).await })
        };
        eventually("in sync", || io.with(|d| d.in_sync)).await;
        // The Closed cannot get a place within its bound: the drop writes it, with
        // the bytes the flow reported and the honest reason.
        result
            .closed(
                ClosedEvent {
                    bytes_up: 5,
                    bytes_down: 6,
                    reason: CloseReason::Eof,
                },
                Duration::from_millis(40),
            )
            .await;
        io.release();
        assert!(blocker.await.expect("joined").is_ok());
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        match &io.records().last().expect("closed").event {
            FlowAuditEvent::Closed {
                bytes_up,
                bytes_down,
                reason,
                ..
            } => assert_eq!(
                (*bytes_up, *bytes_down, reason.as_str()),
                (5, 6, "audit_abandoned")
            ),
            other => panic!("not Closed: {other:?}"),
        }
        drop(pending);
    }

    #[tokio::test]
    async fn an_arm_receipt_always_ends_in_a_record_that_says_what_became_of_it() {
        fn armed(epoch: u64) -> ArmedEvent {
            ArmedEvent {
                actor: Actor::Operator {
                    peer: Some(Arc::from("uid:1000")),
                    client: ClientLabel::Desktop,
                },
                profile: "main".to_owned(),
                epoch,
                profile_digest: "0".repeat(64),
                rules: RuleTable {
                    total: 0,
                    truncated: false,
                    rules: Vec::new(),
                },
                observations: Vec::new(),
            }
        }
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let applied = writer.append_armed(armed(1), LONG).await.expect("armed");
        applied.applied();
        let superseded = writer.append_armed(armed(2), LONG).await.expect("armed");
        superseded.superseded();
        let not_applied = writer.append_armed(armed(3), LONG).await.expect("armed");
        not_applied.not_applied();
        drop(writer.append_armed(armed(4), LONG).await.expect("armed"));
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        let disarmed: Vec<(String, u64)> = io
            .records()
            .into_iter()
            .filter_map(|r| match r.event {
                FlowAuditEvent::Disarmed { cause, epoch } => Some((cause, epoch)),
                _ => None,
            })
            .collect();
        assert_eq!(
            disarmed,
            [
                ("arm_superseded".to_owned(), 2),
                ("arm_not_applied".to_owned(), 3),
                ("arm_abandoned".to_owned(), 4)
            ]
        );
        match &io.records().get(1).expect("armed").event {
            FlowAuditEvent::Armed {
                cause,
                client,
                requested_by,
                epoch,
                ..
            } => {
                assert_eq!(
                    (
                        cause.as_str(),
                        client.as_str(),
                        requested_by.as_str(),
                        *epoch
                    ),
                    ("operator", "desktop", "uid:1000", 1)
                );
            }
            other => panic!("not Armed: {other:?}"),
        }
    }

    #[tokio::test]
    async fn disarmed_never_fails_the_caller_and_tripped_and_summary_ride_the_side_channel() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        writer
            .append_disarmed(
                DisarmedEvent {
                    cause: DisarmCause::Operator,
                    epoch: 9,
                },
                Duration::from_secs(5),
            )
            .await;
        assert!(writer.try_enqueue_tripped(TrippedEvent {
            reason: TripReason::AuditStalled,
            epoch: 9
        }));
        assert!(writer.queue_summary(SummaryEvent {
            window_ms: 60_000,
            other_keys: 3,
            ..SummaryEvent::default()
        }));
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        let kinds: Vec<&str> = events(&io).iter().map(|(_, k)| *k).collect();
        assert_eq!(kinds, ["started", "disarmed", "tripped", "summary"]);
        match &io.records().get(2).expect("tripped").event {
            FlowAuditEvent::Tripped { reason, epoch } => {
                assert_eq!((reason.as_str(), *epoch), ("audit_stalled", 9));
            }
            other => panic!("not Tripped: {other:?}"),
        }
    }

    // -- what the ledger says ---------------------------------------------------------------

    #[tokio::test]
    async fn hashed_mode_leaks_no_host_and_no_address_into_the_ledger() {
        let io = FakeIo::new();
        let key = Arc::new(DestKey::from_bytes([9; 32]));
        let (writer, _) = open_with_sealer(
            &io,
            DestSealer::Hashed(Arc::clone(&key)),
            DestinationLogging::Hashed,
            8,
        );
        let pending = pend(&writer, "secret-host.example", 443, LONG)
            .await
            .expect("pending");
        pending.mark_dial_started();
        let result = writer
            .append_connected(
                &pending,
                ConnectedEvent {
                    chain_kinds: vec!["direct"],
                    dialed: Some(sa("198.51.100.77:443")),
                    attempted: vec![sa("198.51.100.77:443"), sa("[2001:db8::77]:443")],
                    answers: Some(2),
                    observations: Vec::new(),
                },
                Arc::new(ByteCounts::default()),
                LONG,
            )
            .await
            .expect("connected");
        let failed = pend(&writer, "other-host.example", 443, LONG)
            .await
            .expect("pending");
        writer
            .append_failed(
                &failed,
                FailedEvent {
                    error_code: "NETCORE_TIMEOUT",
                    refusal: None,
                    attempted: vec![sa("203.0.113.9:443")],
                    answers: Some(1),
                    observations: Vec::new(),
                },
                LONG,
            )
            .await
            .expect("failed");
        let text = || io.text();
        for secret in [
            "secret-host.example",
            "other-host.example",
            "198.51.100.77",
            "2001:db8::77",
            "203.0.113.9",
        ] {
            assert!(!text().contains(secret), "{secret} reached the ledger");
        }
        let expected_token = key
            .token(HostKind::Name, "secret-host.example")
            .expect("token");
        assert!(text().contains(&expected_token));
        assert!(text().contains(key.kid()));
        // A refusal is evidence and is in clear in either mode.
        deny(&writer, LONG).await.expect("denied");
        assert!(text().contains("blocked.example"));
        result
            .closed(
                ClosedEvent {
                    bytes_up: 0,
                    bytes_down: 0,
                    reason: CloseReason::Eof,
                },
                Duration::from_secs(5),
            )
            .await;
    }

    #[tokio::test]
    async fn more_than_eight_attempted_addresses_are_cut_not_refused() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let pending = pend(&writer, "example.com", 443, LONG)
            .await
            .expect("pending");
        let many: Vec<std::net::SocketAddr> = (1..=12)
            .map(|n| sa(&format!("93.184.216.{n}:443")))
            .collect();
        writer
            .append_failed(
                &pending,
                FailedEvent {
                    error_code: "NETCORE_TIMEOUT",
                    refusal: None,
                    attempted: many,
                    answers: Some(12),
                    observations: Vec::new(),
                },
                LONG,
            )
            .await
            .expect("recorded");
        match &io.records().last().expect("result").event {
            FlowAuditEvent::Result { attempted, .. } => {
                assert_eq!(attempted.len(), MAX_ATTEMPTED);
                // The first eight, in start order.
                assert!(matches!(
                    attempted.first(),
                    Some(AddrRef::Plain { ip, .. }) if ip == "93.184.216.1"
                ));
                assert!(matches!(
                    attempted.last(),
                    Some(AddrRef::Plain { ip, .. }) if ip == "93.184.216.8"
                ));
            }
            other => panic!("not Result: {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_armed_record_that_lands_after_its_caller_gave_up_is_disarmed() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        io.block();
        let event = ArmedEvent {
            actor: Actor::ConfigAutostart,
            profile: "main".to_owned(),
            epoch: 5,
            profile_digest: "0".repeat(64),
            rules: RuleTable {
                total: 0,
                truncated: false,
                rules: Vec::new(),
            },
            observations: Vec::new(),
        };
        assert_eq!(
            writer
                .append_armed(event, Waits::both(Duration::from_millis(80)))
                .await
                .err(),
            Some(AuditError::Timeout)
        );
        io.release();
        eventually("the Armed record and its Disarmed landed", || {
            events(&io).len() == 3
        })
        .await;
        match &io.records().last().expect("disarmed").event {
            FlowAuditEvent::Disarmed { cause, epoch } => {
                assert_eq!((cause.as_str(), *epoch), ("arm_abandoned", 5));
            }
            other => panic!("not Disarmed: {other:?}"),
        }
        match &io.records().get(1).expect("armed").event {
            FlowAuditEvent::Armed { cause, client, .. } => {
                assert_eq!(
                    (cause.as_str(), client.as_str()),
                    ("config_autostart", "config")
                );
            }
            other => panic!("not Armed: {other:?}"),
        }
    }

    #[tokio::test]
    async fn plain_mode_writes_the_host_and_the_pinned_addresses() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let pending = pend(&writer, "example.com", 8443, LONG)
            .await
            .expect("pending");
        writer
            .append_failed(
                &pending,
                FailedEvent {
                    error_code: "NETCORE_ADDR_REFUSED",
                    refusal: Some("loopback"),
                    attempted: Vec::new(),
                    answers: Some(3),
                    observations: Vec::new(),
                },
                LONG,
            )
            .await
            .expect("failed");
        let text = io.text();
        assert!(
            text.contains("\"host\":\"example.com\",\"port\":8443"),
            "{text}"
        );
        assert!(text.contains("\"refusal\":\"loopback\""));
    }

    #[tokio::test]
    async fn a_code_outside_its_closed_list_is_written_as_the_generic_word_and_counted() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let pending = pend(&writer, "example.com", 443, LONG)
            .await
            .expect("pending");
        writer
            .append_failed(
                &pending,
                FailedEvent {
                    error_code: "MADE_UP_ERROR",
                    refusal: Some("made_up_refusal"),
                    attempted: Vec::new(),
                    answers: None,
                    observations: Vec::new(),
                },
                LONG,
            )
            .await
            .expect("failed");
        let other = pend(&writer, "example.org", 443, LONG)
            .await
            .expect("pending");
        writer
            .append_not_dialed(&other, "MADE_UP", Duration::from_secs(5))
            .await
            .expect("recorded");
        let target = canonicalize(RawTarget::Name(b"x.example".to_vec(), 1)).expect("target");
        writer
            .append_denied(
                DeniedEvent {
                    peer: "uid:1",
                    peer_verified: true,
                    target: &target,
                    profile: "main",
                    matched_rule: None,
                    reason_code: "MADE_UP",
                    route: None,
                    coalesced: false,
                },
                LONG,
            )
            .await
            .expect("recorded");
        let text = io.text();
        assert!(!text.contains("MADE_UP"));
        assert_eq!(
            text.matches("UNKNOWN_CODE").count(),
            4, // the error code and the refusal of the first, one each of the others
        );
        assert_eq!(writer.status().unknown_codes, 3);
    }

    // -- the binding -------------------------------------------------------------------------------

    #[tokio::test]
    async fn the_binding_covers_kind_host_port_and_route() {
        let base = binding_of(TargetKind::Name, "example.com", 443, "Direct");
        assert_eq!(
            base,
            binding_of(TargetKind::Name, "example.com", 443, "Direct")
        );
        for other in [
            binding_of(TargetKind::Ipv4, "example.com", 443, "Direct"),
            binding_of(TargetKind::Name, "example.org", 443, "Direct"),
            binding_of(TargetKind::Name, "example.com", 444, "Direct"),
            binding_of(TargetKind::Name, "example.com", 443, "Via(a)"),
        ] {
            assert_ne!(base, other);
        }
        // The host runs into the port: without its terminator these two are the same
        // bytes, "abcd" followed by two zero bytes (host "ab", port "cd", route
        // "\0"; host "abc", port "d\0", route "").
        assert_ne!(
            binding_of(TargetKind::Name, "ab", 0x6364, "\0"),
            binding_of(TargetKind::Name, "abc", 0x6400, "")
        );

        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let receipt = pend(&writer, "example.com", 443, LONG)
            .await
            .expect("pending");
        assert!(receipt.matches(&token("example.com", 443)));
        assert!(!receipt.matches(&token("example.org", 443)));
        assert!(!receipt.matches(&token("example.com", 8443)));
        // The same host and port, recorded as a different kind, is another binding.
        let literal = pend_kind(&writer, "example.com", 443, TargetKind::Ipv4, LONG)
            .await
            .expect("pending");
        assert!(literal.matches(&token("example.com", 443)));
        assert_ne!(receipt.binding, literal.binding);
    }

    // -- close, flush, status ------------------------------------------------------------------------

    #[tokio::test]
    async fn close_drains_what_was_queued_refuses_the_rest_and_is_idempotent() {
        let io = FakeIo::new();
        let (writer, seen) = open_plain(&io);
        let pending = pend(&writer, "example.com", 443, LONG)
            .await
            .expect("pending");
        drop(pending); // queues its Result before close
        writer.close(Duration::from_secs(10)).await;
        assert!(
            lock_unpoisoned(&seen).is_empty(),
            "a clean close is not a trip"
        );
        assert_eq!(writer.status().state, WriterState::Closing);
        assert_eq!(
            results(&io),
            [(ResultOutcome::NotDialed, Some("FLOW_DROPPED".to_owned()))],
            "a compensation queued before close is drained"
        );
        assert_eq!(deny(&writer, LONG).await.err(), Some(AuditError::Closing));
        writer.close(Duration::from_secs(10)).await;
        // A receipt dropped after the thread ended is counted as lost, not a panic.
        let lost_before = writer.status().compensations_lost;
        let late = ArmReceipt {
            core: Arc::clone(&writer.core),
            epoch: 1,
            seq: 0,
            entry_hash: String::new(),
            resolved: false,
        };
        drop(late);
        assert_eq!(writer.status().compensations_lost, lost_before + 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn flush_waits_for_everything_before_it_and_times_out_on_a_stuck_disk() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        io.block();
        let blocker = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { deny(&writer, LONG).await })
        };
        eventually("in sync", || io.with(|d| d.in_sync)).await;
        assert_eq!(
            writer.flush(Duration::from_millis(60)).await.err(),
            Some(AuditError::Timeout)
        );
        io.release();
        assert!(blocker.await.expect("joined").is_ok());
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_running_sync_is_visible_to_the_watchdog_and_clears_afterwards() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        assert_eq!(writer.io_in_progress_for(), None);
        io.block();
        let blocker = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { deny(&writer, LONG).await })
        };
        eventually("in sync", || io.with(|d| d.in_sync)).await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        let stuck = writer.io_in_progress_for().expect("a sync is running");
        assert!(stuck >= Duration::from_millis(40), "{stuck:?}");
        io.release();
        assert!(blocker.await.expect("joined").is_ok());
        assert_eq!(writer.io_in_progress_for(), None);
        assert!(writer.status().sync_max_ms >= 40);
    }

    #[tokio::test]
    async fn status_follows_the_ledger_and_carries_the_mode() {
        let io = FakeIo::new();
        let key = Arc::new(DestKey::from_bytes([3; 32]));
        let kid = key.kid().to_owned();
        let (writer, _) =
            open_with_sealer(&io, DestSealer::Hashed(key), DestinationLogging::Hashed, 8);
        let before = writer.status();
        assert_eq!(before.entries, 1);
        assert_eq!(before.destination_logging, DestinationLogging::Hashed);
        assert_eq!(before.dest_key_id.as_deref(), Some(kid.as_str()));
        assert_eq!(before.state, WriterState::Ok);
        let DeniedOutcome::Recorded(receipt) = deny(&writer, LONG).await.expect("recorded") else {
            panic!("recorded");
        };
        let after = writer.status();
        assert_eq!(after.entries, 2);
        assert_eq!(after.head, receipt.entry_hash());
        assert_ne!(after.head, before.head);
        assert!(after.bytes > before.bytes);
        assert_eq!(after.queue_depth, 0);
    }

    #[test]
    fn the_error_codes_are_stable_labels_and_only_the_faults_trip() {
        let all = [
            (AuditError::QueueFull, "AUDIT_QUEUE_FULL", false),
            (AuditError::Busy, "AUDIT_BUSY", false),
            (AuditError::Timeout, "AUDIT_TIMEOUT", false),
            (AuditError::Capacity, "AUDIT_CAPACITY", false),
            (AuditError::Closing, "AUDIT_CLOSING", false),
            (AuditError::RecordTooLarge, "AUDIT_RECORD_TOO_LARGE", false),
            (AuditError::Invalid("x"), "AUDIT_INVALID_RECORD", false),
            (AuditError::WriterDown, "AUDIT_WRITER_DOWN", true),
            (AuditError::SeqExhausted, "AUDIT_SEQ_EXHAUSTED", true),
            (AuditError::Io("AUDIT_IO"), "AUDIT_IO", true),
        ];
        for (error, code, trips) in all {
            assert_eq!(error.code(), code);
            assert_eq!(error.trips(), trips, "{code}");
        }
        assert_eq!(Waits::DEFAULT.queue_wait, Duration::from_secs(2));
        assert_eq!(Waits::DEFAULT.sync_wait, Duration::from_secs(5));
    }

    // -- every field of every record ----------------------------------------------------------

    #[tokio::test]
    async fn the_pending_record_carries_exactly_what_the_flow_was_admitted_with() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let token = token("example.com", 8443);
        let adapters = vec!["adapter-a".to_owned(), "adapter-b".to_owned()];
        let receipt = writer
            .append_pending(
                PendingInput {
                    token: &token,
                    flow_id: "ingress:b1:77",
                    profile: "work",
                    matched_rule: Some("rule-7"),
                    peer: "uid:1234",
                    peer_verified: false,
                    target_kind: TargetKind::Name,
                    provenance: Provenance::ClientSuppliedLiteral,
                    resolution: Resolution::ProxyResolved,
                    planned_adapters: &adapters,
                },
                LONG,
            )
            .await
            .expect("pending");
        assert_eq!(receipt.flow_id(), "ingress:b1:77");
        let record = io.records().pop().expect("pending record");
        assert_eq!(record.flow_id, "ingress:b1:77");
        let route = summarise_route(token.route());
        assert_eq!(
            record.event,
            FlowAuditEvent::Pending {
                peer: "uid:1234".into(),
                peer_verified: false,
                dest: crate::ingress::types::DestRef::Plain {
                    host: "example.com".into(),
                    port: 8443
                },
                target_provenance: "client_supplied_literal".into(),
                target_kind: "name".into(),
                resolution: Resolution::ProxyResolved,
                profile: "work".into(),
                matched_rule: Some("rule-7".into()),
                route,
                planned_adapters: adapters,
            }
        );
        // No matched rule is no field, not an empty one.
        let none = writer
            .append_pending(
                PendingInput {
                    token: &token,
                    flow_id: "ingress:b1:78",
                    profile: "work",
                    matched_rule: None,
                    peer: "uid:1234",
                    peer_verified: true,
                    target_kind: TargetKind::Ipv4,
                    provenance: Provenance::ClientSuppliedName,
                    resolution: Resolution::Literal,
                    planned_adapters: &[],
                },
                LONG,
            )
            .await
            .expect("pending");
        match io.records().pop().expect("record").event {
            FlowAuditEvent::Pending {
                matched_rule,
                peer_verified,
                target_kind,
                target_provenance,
                resolution,
                planned_adapters,
                ..
            } => {
                assert_eq!(matched_rule, None);
                assert!(peer_verified);
                assert_eq!(target_kind, "ipv4");
                assert_eq!(target_provenance, "client_supplied_name");
                assert_eq!(resolution, Resolution::Literal);
                assert!(planned_adapters.is_empty());
            }
            other => panic!("not Pending: {other:?}"),
        }
        none.mark_dial_started();
        receipt.mark_dial_started();
    }

    #[tokio::test]
    async fn the_result_records_carry_exactly_what_the_dial_reported() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let observation = |kind: &str, value: &str| crate::ingress::types::Observation {
            kind: kind.to_owned(),
            value: value.to_owned(),
        };
        let connected = pend(&writer, "example.com", 443, LONG)
            .await
            .expect("pending");
        connected.mark_dial_started();
        let proof = writer
            .append_connected(
                &connected,
                ConnectedEvent {
                    chain_kinds: vec!["socks5", "tls_tunnel"],
                    dialed: Some(sa("93.184.216.34:443")),
                    attempted: vec![sa("[2606:2800:220:1::1]:443"), sa("93.184.216.34:443")],
                    answers: Some(2),
                    observations: vec![observation("egress_local", "10.0.0.5")],
                },
                Arc::new(ByteCounts::default()),
                LONG,
            )
            .await
            .expect("connected");
        let failed = pend(&writer, "example.org", 80, LONG)
            .await
            .expect("pending");
        writer
            .append_failed(
                &failed,
                FailedEvent {
                    error_code: "NETCORE_ADDR_REFUSED",
                    refusal: Some("private"),
                    attempted: vec![sa("10.1.2.3:80")],
                    answers: Some(1),
                    observations: vec![observation("os_route_if", "dev0")],
                },
                LONG,
            )
            .await
            .expect("failed");
        let mut connected_record = None;
        let mut failed_record = None;
        for record in io.records() {
            if let FlowAuditEvent::Result { .. } = record.event {
                if record.flow_id == connected.flow_id() {
                    connected_record = Some(record.event);
                } else if record.flow_id == failed.flow_id() {
                    failed_record = Some(record.event);
                }
            }
        }
        assert_eq!(
            connected_record,
            Some(FlowAuditEvent::Result {
                outcome: ResultOutcome::Connected,
                error_code: None,
                refusal: None,
                chain_kinds: vec!["socks5".into(), "tls_tunnel".into()],
                dialed: Some(AddrRef::Plain {
                    ip: "93.184.216.34".into(),
                    port: 443
                }),
                attempted: vec![
                    AddrRef::Plain {
                        ip: "2606:2800:220:1::1".into(),
                        port: 443
                    },
                    AddrRef::Plain {
                        ip: "93.184.216.34".into(),
                        port: 443
                    },
                ],
                answers: Some(2),
                observations: vec![observation("egress_local", "10.0.0.5")],
            })
        );
        assert_eq!(
            failed_record,
            Some(FlowAuditEvent::Result {
                outcome: ResultOutcome::Failed,
                error_code: Some("NETCORE_ADDR_REFUSED".into()),
                refusal: Some("private".into()),
                chain_kinds: Vec::new(),
                dialed: None,
                attempted: vec![AddrRef::Plain {
                    ip: "10.1.2.3".into(),
                    port: 80
                }],
                answers: Some(1),
                observations: vec![observation("os_route_if", "dev0")],
            })
        );
        drop(proof);
    }

    #[tokio::test]
    async fn the_denied_record_carries_exactly_what_was_refused() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let target = canonicalize(RawTarget::V4("169.254.169.254".parse().expect("ip"), 80))
            .expect("target");
        writer
            .append_denied(
                DeniedEvent {
                    peer: "sid:S-1-5-21-1",
                    peer_verified: false,
                    target: &target,
                    profile: "work",
                    matched_rule: Some("rule-9"),
                    reason_code: "SPECIAL_USE_NEEDS_EXACT_RULE",
                    route: Some("Direct".into()),
                    coalesced: true,
                },
                LONG,
            )
            .await
            .expect("recorded");
        let record = io.records().pop().expect("denied");
        assert_eq!(record.flow_id, "", "a refusal belongs to no flow");
        assert_eq!(
            record.event,
            FlowAuditEvent::Denied {
                peer: "sid:S-1-5-21-1".into(),
                peer_verified: false,
                dest: crate::ingress::types::DestRef::Plain {
                    host: "169.254.169.254".into(),
                    port: 80
                },
                target_provenance: "client_supplied_literal".into(),
                target_kind: "ipv4".into(),
                profile: "work".into(),
                matched_rule: Some("rule-9".into()),
                reason_code: "SPECIAL_USE_NEEDS_EXACT_RULE".into(),
                route: Some("Direct".into()),
                coalesced: true,
            }
        );
    }

    #[tokio::test]
    async fn the_summary_record_carries_exactly_what_was_counted() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let event = SummaryEvent {
            window_ms: 60_000,
            pre_admission_rejects: [("busy".to_owned(), 4_u64)].into_iter().collect(),
            denials_suppressed: [("POLICY_DENY".to_owned(), 9_u64)].into_iter().collect(),
            denials_over_quota: [("NOT_ARMED".to_owned(), 2_u64)].into_iter().collect(),
            denials_repeated: vec![super::super::record::RepeatCount {
                profile: "main".into(),
                host: "blocked.example".into(),
                port: 25,
                reason: "POLICY_DENY".into(),
                rule: Some("deny-1".into()),
                count: 9,
            }],
            other_keys: 3,
        };
        assert!(writer.queue_summary(event.clone()));
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        assert_eq!(
            io.records().pop().expect("summary").event,
            FlowAuditEvent::Summary {
                window_ms: event.window_ms,
                pre_admission_rejects: event.pre_admission_rejects,
                denials_suppressed: event.denials_suppressed,
                denials_over_quota: event.denials_over_quota,
                denials_repeated: event.denials_repeated,
                other_keys: 3,
            }
        );
    }

    #[tokio::test]
    async fn an_unknown_refusal_label_alone_is_counted_too() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let pending = pend(&writer, "example.com", 443, LONG)
            .await
            .expect("pending");
        writer
            .append_failed(
                &pending,
                FailedEvent {
                    error_code: "NETCORE_TIMEOUT",
                    refusal: Some("made_up_label"),
                    attempted: Vec::new(),
                    answers: None,
                    observations: Vec::new(),
                },
                LONG,
            )
            .await
            .expect("recorded");
        assert_eq!(writer.status().unknown_codes, 1);
        assert!(io.text().contains("\"refusal\":\"UNKNOWN_CODE\""));
    }

    // -- more faults ------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_flush_after_a_write_fault_says_the_writer_is_down() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        io.with(|d| d.fail_append_at = Some(d.appends + 1));
        assert!(deny(&writer, LONG).await.is_err());
        assert_eq!(
            writer.flush(Duration::from_secs(5)).await.err(),
            Some(AuditError::WriterDown)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn jobs_queued_behind_a_failed_batch_are_answered_writer_down_at_once() {
        let io = FakeIo::new();
        let (writer, seen) =
            open_with_sealer(&io, DestSealer::Plain, DestinationLogging::Plain, 200);
        io.block();
        let mut tasks = Vec::new();
        {
            let writer = Arc::clone(&writer);
            tasks.push(tokio::spawn(async move { deny(&writer, LONG).await }));
        }
        eventually("in sync", || io.with(|d| d.in_sync)).await;
        // More than one batch worth, queued while the writer is stuck.
        for _ in 0..(BATCH_MAX + 6) {
            let writer = Arc::clone(&writer);
            tasks.push(tokio::spawn(async move { deny(&writer, LONG).await }));
        }
        eventually("all queued", || {
            writer.status().queue_depth == BATCH_MAX + 6
        })
        .await;
        // The first batch (one job) succeeds; the second (64 jobs) fails.
        io.with(|d| d.fail_append_at = Some(d.appends + 1));
        io.release();
        let (mut faults, mut down, mut ok) = (0_usize, 0_usize, 0_usize);
        for task in tasks {
            match task.await.expect("joined") {
                Ok(_) => ok += 1,
                Err(AuditError::Io(_)) => faults += 1,
                Err(AuditError::WriterDown) => down += 1,
                Err(other) => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!((ok, faults, down), (1, BATCH_MAX, 6));
        assert_eq!(lock_unpoisoned(&seen).len(), 1);
    }

    /// Whoever sees the error also sees the trip: the writer trips first and
    /// answers second.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_gate_is_tripped_before_any_caller_is_told_about_the_fault() {
        let io = FakeIo::new();
        let entered = Arc::new(AtomicBool::new(false));
        let proceed = Arc::new((Mutex::new(false), Condvar::new()));
        let on_trip: TripFn = {
            let entered = Arc::clone(&entered);
            let proceed = Arc::clone(&proceed);
            Arc::new(move |_reason| {
                entered.store(true, Ordering::Release);
                let (lock, cv) = &*proceed;
                let mut open = lock_unpoisoned(lock);
                while !*open {
                    open = cv
                        .wait(open)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
            })
        };
        let writer = Arc::new(
            FlowAuditWriter::open_with(
                io.clone(),
                Replayed::fresh(),
                &cfg(DestinationLogging::Plain, 8),
                DestSealer::Plain,
                on_trip,
            )
            .expect("opens"),
        );
        io.with(|d| d.fail_append_at = Some(d.appends + 1));
        let task = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { deny(&writer, LONG).await })
        };
        eventually("the trip callback is running", || {
            entered.load(Ordering::Acquire)
        })
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !task.is_finished(),
            "the caller was answered before the trip finished"
        );
        {
            let (lock, cv) = &*proceed;
            *lock_unpoisoned(lock) = true;
            cv.notify_all();
        }
        assert!(task.await.expect("joined").is_err());
    }

    // -- the pieces under the writer ----------------------------------------------------------

    struct Probe(Arc<AtomicBool>);

    impl Delivered for Probe {
        fn abandoned(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    fn written() -> Written {
        Written {
            seq: 5,
            hash: "0".repeat(64),
        }
    }

    #[test]
    fn a_delivery_marks_a_value_abandoned_when_nobody_is_waiting_any_more() {
        // The receiver went away after the claim.
        let flag = Arc::new(AtomicBool::new(false));
        let state = Arc::new(AtomicU8::new(CLAIMED));
        let (tx, rx) = oneshot::channel::<Result<Probe, AuditError>>();
        drop(rx);
        let probe = Probe(Arc::clone(&flag));
        deliver_fn(Arc::clone(&state), tx, move |_| probe)(Ok(written()));
        assert!(flag.load(Ordering::Acquire), "the value was told");
        assert_eq!(state.load(Ordering::Acquire), DONE);

        // The caller abandoned the job after the claim: it gets nothing, and the
        // value is told.
        let flag = Arc::new(AtomicBool::new(false));
        let state = Arc::new(AtomicU8::new(ABANDONED));
        let (tx, mut rx) = oneshot::channel::<Result<Probe, AuditError>>();
        let probe = Probe(Arc::clone(&flag));
        deliver_fn(Arc::clone(&state), tx, move |_| probe)(Ok(written()));
        assert!(flag.load(Ordering::Acquire));
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        assert_eq!(state.load(Ordering::Acquire), ABANDONED);

        // The ordinary case: delivered, and not told anything.
        let flag = Arc::new(AtomicBool::new(false));
        let state = Arc::new(AtomicU8::new(CLAIMED));
        let (tx, mut rx) = oneshot::channel::<Result<Probe, AuditError>>();
        let probe = Probe(Arc::clone(&flag));
        deliver_fn(Arc::clone(&state), tx, move |_| probe)(Ok(written()));
        assert!(matches!(rx.try_recv(), Ok(Ok(_))));
        assert!(!flag.load(Ordering::Acquire));
        assert_eq!(state.load(Ordering::Acquire), DONE);
    }

    #[test]
    fn a_fault_is_answered_only_to_a_caller_that_is_still_waiting() {
        let state = Arc::new(AtomicU8::new(CLAIMED));
        let (tx, mut rx) = oneshot::channel::<Result<Probe, AuditError>>();
        deliver_fn(Arc::clone(&state), tx, |_| {
            unreachable!("no record was written")
        })(Err(AuditError::Io("AUDIT_IO")));
        assert!(matches!(rx.try_recv(), Ok(Err(AuditError::Io("AUDIT_IO")))));
        assert_eq!(state.load(Ordering::Acquire), DONE);

        // A caller that gave up after the claim is not answered.
        let state = Arc::new(AtomicU8::new(ABANDONED));
        let (tx, mut rx) = oneshot::channel::<Result<Probe, AuditError>>();
        deliver_fn(Arc::clone(&state), tx, |_| {
            unreachable!("no record was written")
        })(Err(AuditError::Io("AUDIT_IO")));
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        assert_eq!(state.load(Ordering::Acquire), ABANDONED);
    }

    fn inner_with_a_closed_channel() -> Arc<Inner> {
        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx);
        Arc::new(Inner {
            tx,
            shared: Arc::new(Shared::new(&Replayed::fresh())),
            queue_cap: 8,
            closing: AtomicBool::new(false),
            sealer: DestSealer::Plain,
            boot_seq: 1,
            flow_counter: AtomicU64::new(0),
            thread: Mutex::new(None),
            base: Instant::now(),
        })
    }

    #[tokio::test]
    async fn a_writer_whose_channel_is_closed_refuses_and_does_not_leak_a_queue_slot() {
        let inner = inner_with_a_closed_channel();
        let event = FlowAuditEvent::Disarmed {
            cause: "operator".into(),
            epoch: 1,
        };
        let result = inner
            .submit(
                String::new(),
                event.clone(),
                Waits::both(Duration::from_secs(1)),
                |written, _| Receipt::new(written),
            )
            .await;
        assert_eq!(result.err(), Some(AuditError::WriterDown));
        assert_eq!(inner.shared.queued.load(Ordering::Acquire), 0);
        assert!(!inner.send_comp(String::new(), event));
        assert_eq!(inner.shared.compensations_lost.load(Ordering::Relaxed), 1);
    }

    // -- the cases the first mutation run found uncovered --------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn while_the_trip_is_running_new_appends_are_refused_at_once() {
        let io = FakeIo::new();
        let entered = Arc::new(AtomicBool::new(false));
        let proceed = Arc::new((Mutex::new(false), Condvar::new()));
        let on_trip: TripFn = {
            let entered = Arc::clone(&entered);
            let proceed = Arc::clone(&proceed);
            Arc::new(move |_reason| {
                entered.store(true, Ordering::Release);
                let (lock, cv) = &*proceed;
                let mut open = lock_unpoisoned(lock);
                while !*open {
                    open = cv
                        .wait(open)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
            })
        };
        let writer = Arc::new(
            FlowAuditWriter::open_with(
                io.clone(),
                Replayed::fresh(),
                &cfg(DestinationLogging::Plain, 8),
                DestSealer::Plain,
                on_trip,
            )
            .expect("opens"),
        );
        io.with(|d| d.fail_append_at = Some(d.appends + 1));
        let first = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { deny(&writer, LONG).await })
        };
        eventually("the trip callback is running", || {
            entered.load(Ordering::Acquire)
        })
        .await;
        // The channel is still open and nobody has been answered, yet the writer is
        // known to be down: a new append is refused without waiting for anything.
        let started = Instant::now();
        assert_eq!(
            deny(&writer, Waits::both(Duration::from_secs(10)))
                .await
                .err(),
            Some(AuditError::WriterDown)
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!writer.try_enqueue_tripped(TrippedEvent {
            reason: TripReason::AcceptFatal,
            epoch: 1
        }));
        {
            let (lock, cv) = &*proceed;
            *lock_unpoisoned(lock) = true;
            cv.notify_all();
        }
        assert!(first.await.expect("joined").is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_closed_that_times_out_is_not_written_a_second_time() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let pending = pend(&writer, "example.com", 443, LONG)
            .await
            .expect("pending");
        pending.mark_dial_started();
        let result = writer
            .append_connected(
                &pending,
                ConnectedEvent::default(),
                Arc::new(ByteCounts::with_counts(1, 2)),
                LONG,
            )
            .await
            .expect("connected");
        io.block();
        // Claimed at once, then stuck in the sync: the wait ends in a timeout, but
        // the record will land.
        result
            .closed(
                ClosedEvent {
                    bytes_up: 8,
                    bytes_down: 9,
                    reason: CloseReason::Eof,
                },
                Duration::from_millis(60),
            )
            .await;
        io.release();
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        let closed: Vec<(u64, u64, String)> = io
            .records()
            .into_iter()
            .filter_map(|r| match r.event {
                FlowAuditEvent::Closed {
                    bytes_up,
                    bytes_down,
                    reason,
                    ..
                } => Some((bytes_up, bytes_down, reason)),
                _ => None,
            })
            .collect();
        assert_eq!(closed, [(8, 9, "eof".to_owned())]);
        drop(pending);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_connected_result_that_lands_after_its_caller_gave_up_is_closed_as_abandoned() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let pending = pend(&writer, "example.com", 443, LONG)
            .await
            .expect("pending");
        pending.mark_dial_started();
        io.block();
        let timed_out = writer
            .append_connected(
                &pending,
                ConnectedEvent::default(),
                Arc::new(ByteCounts::with_counts(3, 4)),
                Waits::both(Duration::from_millis(60)),
            )
            .await;
        assert_eq!(timed_out.err(), Some(AuditError::Timeout));
        io.release();
        eventually("the Closed landed", || events(&io).len() == 4).await;
        let kinds: Vec<&str> = events(&io).iter().map(|(_, k)| *k).collect();
        assert_eq!(kinds, ["started", "pending", "result", "closed"]);
        match &io.records().last().expect("closed").event {
            FlowAuditEvent::Closed {
                bytes_up,
                bytes_down,
                reason,
                ..
            } => assert_eq!(
                (*bytes_up, *bytes_down, reason.as_str()),
                (3, 4, "audit_abandoned")
            ),
            other => panic!("not Closed: {other:?}"),
        }
        // The Pending's own story was told by that Result; nothing more is written.
        drop(pending);
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        assert_eq!(events(&io).len(), 4);
    }

    #[tokio::test]
    async fn a_compensation_that_cannot_be_encoded_is_counted_and_the_writer_goes_on() {
        let io = FakeIo::new();
        let (writer, seen) = open_plain(&io);
        // A host in capitals is not a canonical host: the format refuses the record.
        assert!(writer.queue_summary(SummaryEvent {
            denials_repeated: vec![super::super::record::RepeatCount {
                profile: "main".into(),
                host: "NOT-CANONICAL".into(),
                port: 1,
                reason: "POLICY_DENY".into(),
                rule: None,
                count: 1,
            }],
            ..SummaryEvent::default()
        }));
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        assert_eq!(writer.status().compensations_lost, 1);
        assert_eq!(events(&io), [(1, "started")]);
        // And it is not a write fault.
        assert!(lock_unpoisoned(&seen).is_empty());
        assert!(deny(&writer, LONG).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_batch_that_runs_out_of_sequence_numbers_writes_what_fits_and_trips() {
        let io = FakeIo::new();
        let (seen, on_trip) = trips();
        // Started takes u64::MAX - 2; two more numbers remain.
        let replayed = Replayed {
            last_seq: Some(u64::MAX - 3),
            ..Replayed::fresh()
        };
        let writer = Arc::new(
            FlowAuditWriter::open_with(
                io.clone(),
                replayed,
                &cfg(DestinationLogging::Plain, 8),
                DestSealer::Plain,
                on_trip,
            )
            .expect("opens"),
        );
        io.block();
        let mut tasks = Vec::new();
        {
            let writer = Arc::clone(&writer);
            tasks.push(tokio::spawn(async move { deny(&writer, LONG).await }));
        }
        eventually("in sync", || io.with(|d| d.in_sync)).await;
        for _ in 0..3 {
            let writer = Arc::clone(&writer);
            tasks.push(tokio::spawn(async move { deny(&writer, LONG).await }));
        }
        eventually("three queued", || writer.status().queue_depth == 3).await;
        io.release();
        let mut recorded = 0;
        let mut exhausted = 0;
        for task in tasks {
            match task.await.expect("joined") {
                Ok(_) => recorded += 1,
                Err(AuditError::SeqExhausted) => exhausted += 1,
                Err(other) => panic!("unexpected {other:?}"),
            }
        }
        // The first alone took MAX - 1; of the three behind it, one fits.
        assert_eq!((recorded, exhausted), (2, 2));
        eventually("tripped", || !lock_unpoisoned(&seen).is_empty()).await;
        assert_eq!(*lock_unpoisoned(&seen), [TripReason::AuditWriteFailed]);
        assert_eq!(writer.status().state, WriterState::Down);
        let last = io.records().last().map(|r| r.seq);
        assert_eq!(last, Some(u64::MAX));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_flush_in_a_batch_that_fails_is_told_the_writer_is_down() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        io.block();
        let blocker = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { deny(&writer, LONG).await })
        };
        eventually("in sync", || io.with(|d| d.in_sync)).await;
        let doomed = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { deny(&writer, LONG).await })
        };
        eventually("queued", || writer.status().queue_depth == 1).await;
        let flush = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { writer.flush(Duration::from_secs(20)).await })
        };
        // The flush sits in the channel behind the doomed job.
        tokio::time::sleep(Duration::from_millis(80)).await;
        io.with(|d| d.fail_append_at = Some(d.appends + 1));
        io.release();
        assert!(blocker.await.expect("joined").is_ok());
        assert!(doomed.await.expect("joined").is_err());
        assert_eq!(
            flush.await.expect("joined").err(),
            Some(AuditError::WriterDown)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_compensation_and_a_flush_behind_a_failed_batch_are_counted_and_refused() {
        let io = FakeIo::new();
        let (writer, _) = open_with_sealer(&io, DestSealer::Plain, DestinationLogging::Plain, 200);
        io.block();
        let mut tasks = Vec::new();
        {
            let writer = Arc::clone(&writer);
            tasks.push(tokio::spawn(async move { deny(&writer, LONG).await }));
        }
        eventually("in sync", || io.with(|d| d.in_sync)).await;
        for _ in 0..(BATCH_MAX + 2) {
            let writer = Arc::clone(&writer);
            tasks.push(tokio::spawn(async move { deny(&writer, LONG).await }));
        }
        eventually("all queued", || {
            writer.status().queue_depth == BATCH_MAX + 2
        })
        .await;
        assert!(writer.try_enqueue_tripped(TrippedEvent {
            reason: TripReason::AcceptFatal,
            epoch: 1
        }));
        let flush = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { writer.flush(Duration::from_secs(20)).await })
        };
        tokio::time::sleep(Duration::from_millis(80)).await;
        io.with(|d| d.fail_append_at = Some(d.appends + 1));
        io.release();
        for task in tasks {
            let _ = task.await.expect("joined");
        }
        assert_eq!(
            flush.await.expect("joined").err(),
            Some(AuditError::WriterDown)
        );
        assert_eq!(writer.status().compensations_lost, 1);
        assert_eq!(writer.status().queue_depth, 0, "every slot was given back");
    }

    #[tokio::test]
    async fn recovered_is_written_for_either_reason_alone() {
        for (tail, after_trip) in [(9_u64, None), (0, Some("audit_stalled".to_owned()))] {
            let io = FakeIo::new();
            let (_seen, on_trip) = trips();
            let replayed = Replayed {
                truncated_tail_bytes: tail,
                after_trip: after_trip.clone(),
                ..Replayed::fresh()
            };
            let _writer = FlowAuditWriter::open_with(
                io.clone(),
                replayed,
                &cfg(DestinationLogging::Plain, 8),
                DestSealer::Plain,
                on_trip,
            )
            .expect("opens");
            let kinds: Vec<&str> = events(&io).iter().map(|(_, k)| *k).collect();
            assert_eq!(kinds, ["recovered", "started"], "{tail} {after_trip:?}");
            match &io.records().first().expect("recovered").event {
                FlowAuditEvent::Recovered {
                    truncated_tail_bytes,
                    after_trip: seen,
                    ..
                } => assert_eq!((*truncated_tail_bytes, seen), (tail, &after_trip)),
                other => panic!("not Recovered: {other:?}"),
            }
        }
    }

    // -- the findings of the independent review ------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn a_result_future_dropped_while_queued_leaves_the_pending_to_write_its_own_result() {
        for case in ["connected", "failed", "not_dialed"] {
            let io = FakeIo::new();
            let (writer, _) = open_plain(&io);
            let pending = pend(&writer, "example.com", 443, LONG)
                .await
                .expect("pending");
            pending.mark_dial_started();
            let pending = Arc::new(pending);
            io.block();
            let blocker = {
                let writer = Arc::clone(&writer);
                tokio::spawn(async move { deny(&writer, LONG).await })
            };
            eventually("in sync", || io.with(|d| d.in_sync)).await;
            let task = {
                let writer = Arc::clone(&writer);
                let pending = Arc::clone(&pending);
                tokio::spawn(async move {
                    match case {
                        "connected" => {
                            let _ = writer
                                .append_connected(
                                    &pending,
                                    ConnectedEvent::default(),
                                    Arc::new(ByteCounts::default()),
                                    LONG,
                                )
                                .await;
                        }
                        "failed" => {
                            let _ = writer
                                .append_failed(&pending, FailedEvent::code("NETCORE_TIMEOUT"), LONG)
                                .await;
                        }
                        _ => {
                            let _ = writer
                                .append_not_dialed(&pending, "GATE_CLOSED", Duration::from_secs(20))
                                .await;
                        }
                    }
                })
            };
            eventually("the result is queued", || writer.status().queue_depth == 1).await;
            // The flow task is aborted (a shutdown, a client that went away).
            task.abort();
            let _ = task.await;
            io.release();
            assert!(blocker.await.expect("joined").is_ok());
            drop(Arc::into_inner(pending).expect("the last reference"));
            writer
                .flush(Duration::from_secs(10))
                .await
                .expect("flushed");
            // Exactly one Result for the Pending, written by its drop: the dial had
            // started and the result was never recorded -- or, for the explicit
            // `NotDialed`, the code the flow had chosen.
            let got = results(&io);
            // The dial had started, so the Pending's drop says `Aborted`, whichever
            // result was in flight.
            let expected = (
                ResultOutcome::Aborted,
                Some("RESULT_NOT_RECORDED".to_owned()),
            );
            assert_eq!(got, [expected], "{case}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unrecorded_not_dialed_keeps_the_code_the_flow_chose() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let pending = Arc::new(
            pend(&writer, "example.com", 443, LONG)
                .await
                .expect("pending"),
        );
        io.block();
        let blocker = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { deny(&writer, LONG).await })
        };
        eventually("in sync", || io.with(|d| d.in_sync)).await;
        let task = {
            let writer = Arc::clone(&writer);
            let pending = Arc::clone(&pending);
            tokio::spawn(async move {
                let _ = writer
                    .append_not_dialed(&pending, "GATE_CLOSED", Duration::from_secs(20))
                    .await;
            })
        };
        eventually("queued", || writer.status().queue_depth == 1).await;
        task.abort();
        let _ = task.await;
        io.release();
        assert!(blocker.await.expect("joined").is_ok());
        drop(Arc::into_inner(pending).expect("the last reference"));
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        assert_eq!(
            results(&io),
            [(ResultOutcome::NotDialed, Some("GATE_CLOSED".to_owned()))]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_result_future_dropped_after_the_claim_does_not_get_a_second_result() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let pending = Arc::new(
            pend(&writer, "example.com", 443, LONG)
                .await
                .expect("pending"),
        );
        pending.mark_dial_started();
        io.block();
        let task = {
            let writer = Arc::clone(&writer);
            let pending = Arc::clone(&pending);
            tokio::spawn(async move {
                let _ = writer
                    .append_failed(&pending, FailedEvent::code("NETCORE_TIMEOUT"), LONG)
                    .await;
            })
        };
        // The writer claims it at once and is stuck in the sync.
        eventually("claimed and syncing", || io.with(|d| d.in_sync)).await;
        task.abort();
        let _ = task.await;
        io.release();
        drop(Arc::into_inner(pending).expect("the last reference"));
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        // The Failed result lands by itself; the Pending adds nothing.
        assert_eq!(
            results(&io),
            [(ResultOutcome::Failed, Some("NETCORE_TIMEOUT".to_owned()))]
        );
    }

    fn closed_records(io: &FakeIo) -> Vec<(u64, u64, String)> {
        io.records()
            .into_iter()
            .filter_map(|r| match r.event {
                FlowAuditEvent::Closed {
                    bytes_up,
                    bytes_down,
                    reason,
                    ..
                } => Some((bytes_up, bytes_down, reason)),
                _ => None,
            })
            .collect()
    }

    async fn connected(writer: &FlowAuditWriter) -> (PendingReceipt, ResultReceipt) {
        let pending = pend(writer, "example.com", 443, LONG)
            .await
            .expect("pending");
        pending.mark_dial_started();
        let result = writer
            .append_connected(
                &pending,
                ConnectedEvent::default(),
                Arc::new(ByteCounts::with_counts(1, 2)),
                LONG,
            )
            .await
            .expect("connected");
        (pending, result)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_closed_future_dropped_while_queued_still_leaves_a_closed_record() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let (pending, result) = connected(&writer).await;
        io.block();
        let blocker = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { deny(&writer, LONG).await })
        };
        eventually("in sync", || io.with(|d| d.in_sync)).await;
        let task = tokio::spawn(async move {
            result
                .closed(
                    ClosedEvent {
                        bytes_up: 40,
                        bytes_down: 50,
                        reason: CloseReason::Eof,
                    },
                    Duration::from_secs(20),
                )
                .await;
        });
        eventually("queued", || writer.status().queue_depth == 1).await;
        task.abort();
        let _ = task.await;
        io.release();
        assert!(blocker.await.expect("joined").is_ok());
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        // The real counts, and the honest reason: the tunnel ended, the normal
        // record was never written.
        assert_eq!(
            closed_records(&io),
            [(40, 50, "audit_abandoned".to_owned())]
        );
        drop(pending);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_closed_future_dropped_after_the_claim_lands_once_with_its_own_reason() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let (pending, result) = connected(&writer).await;
        io.block();
        let task = tokio::spawn(async move {
            result
                .closed(
                    ClosedEvent {
                        bytes_up: 40,
                        bytes_down: 50,
                        reason: CloseReason::ClientError,
                    },
                    Duration::from_secs(20),
                )
                .await;
        });
        eventually("claimed and syncing", || io.with(|d| d.in_sync)).await;
        task.abort();
        let _ = task.await;
        io.release();
        writer
            .flush(Duration::from_secs(10))
            .await
            .expect("flushed");
        assert_eq!(closed_records(&io), [(40, 50, "client_error".to_owned())]);
        drop(pending);
    }

    type Gate = Arc<(Mutex<bool>, Condvar)>;

    /// A trip callback that blocks until the test lets it go, for the tests of
    /// "tripped before anyone is told".
    fn blocking_trip() -> (TripFn, Arc<AtomicBool>, Gate) {
        let entered = Arc::new(AtomicBool::new(false));
        let proceed = Arc::new((Mutex::new(false), Condvar::new()));
        let on_trip: TripFn = {
            let entered = Arc::clone(&entered);
            let proceed = Arc::clone(&proceed);
            Arc::new(move |_reason| {
                entered.store(true, Ordering::Release);
                let (lock, cv) = &*proceed;
                let mut open = lock_unpoisoned(lock);
                while !*open {
                    open = cv
                        .wait(open)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
            })
        };
        (on_trip, entered, proceed)
    }

    fn let_go(proceed: &Gate) {
        let (lock, cv) = &**proceed;
        *lock_unpoisoned(lock) = true;
        cv.notify_all();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_writer_that_panics_trips_before_any_caller_is_told() {
        let io = FakeIo::new();
        let (on_trip, entered, proceed) = blocking_trip();
        let writer = Arc::new(
            FlowAuditWriter::open_with(
                io.clone(),
                Replayed::fresh(),
                &cfg(DestinationLogging::Plain, 8),
                DestSealer::Plain,
                on_trip,
            )
            .expect("opens"),
        );
        io.with(|d| d.panic_on_append = true);
        let task = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { deny(&writer, LONG).await })
        };
        eventually("the trip callback is running", || {
            entered.load(Ordering::Acquire)
        })
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !task.is_finished(),
            "the caller was told before the trip finished"
        );
        let_go(&proceed);
        assert_eq!(
            task.await.expect("joined").err(),
            Some(AuditError::WriterDown)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_batch_that_runs_out_of_numbers_trips_before_the_refused_are_told() {
        let io = FakeIo::new();
        let (on_trip, entered, proceed) = blocking_trip();
        // Started takes u64::MAX - 1; one number remains.
        let replayed = Replayed {
            last_seq: Some(u64::MAX - 2),
            ..Replayed::fresh()
        };
        let writer = Arc::new(
            FlowAuditWriter::open_with(
                io.clone(),
                replayed,
                &cfg(DestinationLogging::Plain, 8),
                DestSealer::Plain,
                on_trip,
            )
            .expect("opens"),
        );
        io.block();
        let mut tasks = Vec::new();
        {
            let writer = Arc::clone(&writer);
            tasks.push(tokio::spawn(async move { deny(&writer, LONG).await }));
        }
        eventually("in sync", || io.with(|d| d.in_sync)).await;
        // The first job took the last number; these two have none.
        for _ in 0..2 {
            let writer = Arc::clone(&writer);
            tasks.push(tokio::spawn(async move { deny(&writer, LONG).await }));
        }
        eventually("two queued", || writer.status().queue_depth == 2).await;
        io.release();
        eventually("the trip callback is running", || {
            entered.load(Ordering::Acquire)
        })
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut finished = 0;
        for task in &tasks {
            finished += usize::from(task.is_finished());
        }
        // Only the first, whose record is durable, may have been answered.
        assert!(
            finished <= 1,
            "{finished} callers were told before the trip finished"
        );
        let_go(&proceed);
        let mut refused = 0;
        for task in tasks {
            if task.await.expect("joined") == Err(AuditError::SeqExhausted) {
                refused += 1;
            }
        }
        assert_eq!(refused, 2);
    }

    #[tokio::test]
    async fn compensations_dropped_with_a_failed_batch_are_counted() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        let pending = pend(&writer, "example.com", 443, LONG)
            .await
            .expect("pending");
        io.with(|d| d.fail_append_at = Some(d.appends + 1));
        // Its Result is the only job in the batch that fails.
        drop(pending);
        eventually("the writer went down", || {
            writer.status().state == WriterState::Down
        })
        .await;
        assert_eq!(writer.status().compensations_lost, 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_stuck_append_is_visible_to_the_watchdog_as_well() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        assert_eq!(writer.io_in_progress_for(), None);
        io.with(|d| d.block_append = true);
        let task = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { deny(&writer, LONG).await })
        };
        eventually("in append", || io.with(|d| d.in_append)).await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        let stuck = writer
            .io_in_progress_for()
            .expect("the disk part is running");
        assert!(stuck >= Duration::from_millis(40), "{stuck:?}");
        io.release();
        assert!(task.await.expect("joined").is_ok());
        assert_eq!(writer.io_in_progress_for(), None);
    }

    #[tokio::test]
    async fn a_disarmed_that_cannot_be_written_is_counted() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        writer.close(Duration::from_secs(10)).await;
        let before = writer.status().compensations_lost;
        writer
            .append_disarmed(
                DisarmedEvent {
                    cause: DisarmCause::Shutdown,
                    epoch: 3,
                },
                Duration::from_secs(1),
            )
            .await;
        assert_eq!(writer.status().compensations_lost, before + 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_record_queued_behind_the_shutdown_marker_is_still_written() {
        let io = FakeIo::new();
        let (writer, _) = open_plain(&io);
        io.block();
        let blocker = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { deny(&writer, LONG).await })
        };
        eventually("in sync", || io.with(|d| d.in_sync)).await;
        // The marker and a record both reach the channel before the writer looks.
        writer.core.closing.store(true, Ordering::Release);
        assert!(writer.core.tx.send(Job::Shutdown).is_ok());
        assert!(writer.try_enqueue_tripped(TrippedEvent {
            reason: TripReason::AcceptFatal,
            epoch: 2
        }));
        io.release();
        assert!(blocker.await.expect("joined").is_ok());
        let handle = lock_unpoisoned(&writer.core.thread).take().expect("thread");
        tokio::task::spawn_blocking(move || handle.join())
            .await
            .expect("joined")
            .expect("clean exit");
        let kinds: Vec<&str> = events(&io).iter().map(|(_, k)| *k).collect();
        assert_eq!(kinds, ["started", "denied", "tripped"]);
        // And the thread is gone: a record sent now is refused and counted.
        assert!(!writer.try_enqueue_tripped(TrippedEvent {
            reason: TripReason::AcceptFatal,
            epoch: 3
        }));
    }

    // -- the proof is sealed ---------------------------------------------------------------------------

    /// `ResultReceipt` is the only implementor of the sealed marker outside test
    /// modules, and nothing else in the tree can add one without this test
    /// noticing. (Test modules of other files implement it for their own doubles.)
    #[test]
    fn only_the_result_receipt_implements_the_sealed_marker() {
        fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("read dir") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    rust_files(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&root, &mut files);
        let mut impls = Vec::new();
        for file in files {
            let text = std::fs::read_to_string(&file).expect("read");
            // Everything except the file's test module (from `mod tests {` at the
            // start of a line to the closing brace at the start of a line).
            let production = match text.find("\nmod tests {") {
                Some(start) => {
                    let after = text.get(start + 1..).unwrap_or_default();
                    let end = after.find("\n}\n").map_or(after.len(), |at| at + 3);
                    format!("{}{}", &text[..start], after.get(end..).unwrap_or_default())
                }
                None => text.clone(),
            };
            for line in production.lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.contains("Sealed for") || trimmed.contains("ResultProof for") {
                    impls.push((
                        file.file_name()
                            .expect("name")
                            .to_string_lossy()
                            .into_owned(),
                        trimmed.to_owned(),
                    ));
                }
            }
        }
        impls.sort();
        assert_eq!(
            impls,
            [
                (
                    "writer.rs".to_owned(),
                    "impl ResultProof for ResultReceipt {}".to_owned()
                ),
                (
                    "writer.rs".to_owned(),
                    "impl sealed::Sealed for ResultReceipt {}".to_owned()
                ),
            ]
        );
    }
}
