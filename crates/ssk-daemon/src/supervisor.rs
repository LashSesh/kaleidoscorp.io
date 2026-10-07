#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ssk_ipc::server::{BoxFuture, CommandHandler, Request, Response};
use ssk_ipc::{
    AdapterHealthSummaryDto, AuditEntryDto, DaemonState, DoctorCheckDto, DoctorReportDto,
    ExplainResponse, IngressStatusDto, IpcError, PeerIdentity, ProfileSummaryDto, RouteTraceDto,
    StatusDto, VerifyAuditChainResponse, IPC_PROTOCOL_VERSION,
};
use ssk_netadmin::audit::AuditOutcome;
use ssk_netadmin::{FlowDescriptor, FlowRecord, ForensicEntry, ProtocolKind, RiskLevel, RouteKind};
use ssk_netcore::{DataPlane, EgressSession};
use ssk_tensor::GenericFileLedgerBackend;
use tokio::sync::{Mutex, MutexGuard, Semaphore};

use crate::config_load::DaemonConfigError;
use crate::killswitch::{KillSwitchProvider, KillSwitchView};
use crate::routing::{ConfigState, ConfiguredRouting, Decided};
use crate::state::StateMachine;

type PersistedAuditLedger =
    ssk_netadmin::audit::AuditLedger<GenericFileLedgerBackend<ForensicEntry>>;

/// Upper bound on one activation dial. The supervisor mutex is held across the
/// dial, so this is also the longest a silent upstream can keep every other
/// request waiting. It is deliberately shorter than the executor's own dial
/// deadline: the executor's bound still protects callers that do not pass
/// through here (probes), but the daemon must not depend on it for its own
/// availability.
const ACTIVATE_DIAL_DEADLINE: Duration = Duration::from_secs(20);

/// Machine code for a dial that outlived [`ACTIVATE_DIAL_DEADLINE`].
const ACTIVATION_CONNECT_TIMEOUT: &str = "ACTIVATION_CONNECT_TIMEOUT";

/// Machine code for an activation whose request ended while it was dialing: its
/// future was dropped (the client went away, a caller's timeout, shutdown) or
/// its handler panicked. The requester is gone by then, so clients read it from
/// `GetStatus` and the warning event, never as a reply.
const ACTIVATION_CANCELLED: &str = "ACTIVATION_CANCELLED";

/// How long a request that can be answered around an activation (`GetStatus`
/// and the other callers of `inner_unless_activating`) waits for the supervisor
/// mutex before it asks whether an activation is the reason. The desktop client
/// gives up on a status read after 2 s, so the wait has to be a small fraction
/// of that; it is long enough that an ordinary short handler never trips it.
const STATUS_LOCK_WAIT: Duration = Duration::from_millis(100);

/// Machine code for a request the daemon turned away at once, changing nothing,
/// instead of queueing it: it needs the state an activation dial holds, or two
/// mutating requests are already in flight. Retriable by definition.
const DAEMON_BUSY: &str = "DAEMON_BUSY";

/// Machine code for a request about the local proxy (arm, disarm, read its
/// ledger) that this daemon cannot serve because there is no proxy: the answer
/// of every `SetIngress` and `GetIngressAudit` until the listener exists.
/// Nothing was changed.
const INGRESS_DISABLED: &str = "INGRESS_DISABLED";

/// What the `notice` of an ingress status says, word for word (design 6.1.1): the
/// coverage of the proxy and what it leaves out. It makes no claim of
/// protection, and a test keeps the words the product never uses out of it.
/// `ingress/types.rs` takes this definition over together with the rest of the
/// vocabulary, and this copy goes when the stub below does.
const INGRESS_COVERAGE_NOTICE: &str = "Covers only applications that are configured to use this proxy. Everything else is not covered. Names an application resolves itself are not covered. Names this proxy resolves for direct routes are resolved by the operating system.";

/// How many requests that change the daemon's state (`ActivateProfile`,
/// `Deactivate`) may be in flight at once: the one that holds the mutex, and
/// one queued behind it. The IPC server serves a bounded number of connections
/// and a request that queues behind a dial keeps its connection, so without
/// this bound enough waiting mutators leave a status read nowhere to arrive.
const MAX_MUTATORS: usize = 2;

/// How long the supervisor waits for a held session to shut down gracefully
/// before it drops it. A TLS stream's shutdown writes `close_notify` and
/// flushes, and with a peer that does not read that never finishes; the mutex
/// is held meanwhile. Kept below the desktop client's 2 s read deadline.
const SESSION_SHUTDOWN_BOUND: Duration = Duration::from_secs(1);

/// What the daemon can say about an adapter of a held session. The session was
/// connected when activation finished; nothing probes or reads it afterwards,
/// so anything stronger ("live") would be a claim no code backs.
const ADAPTER_HEALTH_AT_ACTIVATION: &str = "connected at activation; liveness not monitored";

/// The daemon's product runtime: owns the live state machine, the persisted
/// audit ledger, and a real `ssk-netcore`-backed data plane (Phase 3 is no
/// longer a mock — see `ssk_netcore::NetcoreDataPlane`). Implements
/// `ssk_ipc::CommandHandler` to answer every IPC request.
pub struct Supervisor {
    inner: Mutex<Inner>,
    /// Fixed at construction and never written afterwards, so it needs no
    /// lock: outside `Inner`, readable while an activation holds the mutex.
    /// `Inner` keeps a second handle on the same allocation for the methods
    /// that run where only the guard is at hand.
    config: Arc<ConfigState>,
    /// The planner, compiled once from that configuration and shared with
    /// whoever else needs it (the executor's registry comes from the same
    /// compilation). Outside `Inner` for the same reason as `config`.
    routing: Arc<ConfiguredRouting>,
    /// What an activation dials through. Outside `Inner` for the same reason as
    /// `config`, and because it is read while the mutex is already held by the
    /// dial it serves.
    data_plane: Arc<dyn DataPlane>,
    /// Deliberately **outside** `Inner`: reading it must not require the
    /// supervisor's async mutex, and it holds no daemon state of its own — it
    /// is a window onto a different process's authoritative answer.
    kill_switch: Box<dyn KillSwitchProvider>,
    /// Outside `Inner` for the same reason as `kill_switch`: it is read while
    /// the mutex is already held by the dial it bounds.
    activation_deadline: Duration,
    /// Outside `Inner` because its whole purpose is to be readable while
    /// `Inner` is held by an activation dial.
    activations: ActivationsInFlight,
    /// Permits for the requests that change the daemon's state, taken with
    /// `try_acquire` and never awaited: a request that finds none is refused
    /// with `DAEMON_BUSY`. Outside `Inner` because it is consulted before the
    /// mutex is.
    mutators: Semaphore,
    /// A clone of the sender inside `Inner.state`. Outside `Inner` because its
    /// whole purpose is to be usable while `Inner` is held by an activation
    /// dial; it holds no daemon state, only the bus transitions are published on.
    events: tokio::sync::broadcast::Sender<ssk_ipc::Event>,
}

/// How many `ActivateProfile` requests are between "accepted" and "answered",
/// including those still queued for `Inner`.
///
/// A count and not a flag: a second activation can queue behind the first, and
/// a flag cleared by whichever finishes first would hide the other. It is
/// raised before the request awaits `Inner`, because the mutex is exactly what
/// the reader cannot wait for. A request still queued counts too, which can
/// only make a status answer say less than is enforced (the previous session
/// is not cleared yet), never more.
#[derive(Default)]
struct ActivationsInFlight(AtomicUsize);

impl ActivationsInFlight {
    fn enter(&self) -> ActivationInFlight<'_> {
        self.0.fetch_add(1, Ordering::SeqCst);
        ActivationInFlight(self)
    }

    fn any(&self) -> bool {
        self.0.load(Ordering::SeqCst) > 0
    }

    fn leave(&self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Lowers the count on every way out of the request: a normal return, a panic
/// (unwinding runs `Drop`) and cancellation (a dropped future drops its
/// locals). A marker that outlived its request would report `Activating`
/// forever.
struct ActivationInFlight<'a>(&'a ActivationsInFlight);

impl Drop for ActivationInFlight<'_> {
    fn drop(&mut self) {
        self.0.leave();
    }
}

/// What a reader that must not queue behind an activation dial got.
enum InnerAccess<'a> {
    Held(MutexGuard<'a, Inner>),
    /// The mutex stayed taken for the whole wait and an activation is in
    /// flight. The reader answers from what the daemon holds outside the mutex,
    /// or says `DAEMON_BUSY`; it does not wait for the dial.
    ActivationInFlight,
}

struct Inner {
    state: StateMachine,
    active_profile: Option<String>,
    audit: PersistedAuditLedger,
    /// The allocation `Supervisor.config` points at, not a copy. Here because
    /// `refuse_activation` and `status` are reached from `ActivationScope`'s
    /// `Drop`, which holds the guard and nothing else.
    config: Arc<ConfigState>,
    activation_error: Option<IpcError>,
    /// The real, live egress session backing `Active`/`Protected` state.
    /// `None` whenever the daemon is not really holding an open connection —
    /// there is no state in which `Protected` is reported without one.
    ///
    /// A status read that cannot get `Inner` because an activation is in flight
    /// is answered `Activating` without reading this field (`activating_status`).
    /// An activation that holds `Inner` has cleared it (`clear_egress`) before it
    /// dials; one still queued has not, so that answer can say less than is held,
    /// never more (`ActivationsInFlight`).
    active_egress: Option<EgressSession>,
    /// Set from the real session's adapter chain at activation time; never
    /// hardcoded `true`.
    dns_protected: bool,
    /// The flow and route of an activation whose `DispatchPending` intent is in
    /// the ledger and whose result is not: set when `record_activation` writes
    /// the intent, cleared by any other outcome it writes and by
    /// `refuse_activation` (that activation is over, even when its result could
    /// not be written). It names the entry an abandoned activation still owes a
    /// result to, and never one of an earlier activation.
    pending_activation: Option<(String, RouteKind)>,
}

impl Inner {
    fn clear_egress(&mut self) {
        // Drop closes the transport even when a graceful shutdown would wait
        // on an unresponsive peer. Failure paths must not retain an old session.
        self.active_egress = None;
        self.active_profile = None;
        self.dns_protected = false;
    }

    fn refuse_activation(&mut self, error: IpcError) -> Response {
        self.clear_egress();
        self.pending_activation = None;
        let state = if self.config.is_err() {
            DaemonState::ConfigInvalid
        } else {
            DaemonState::FailClosed
        };
        let unchanged = self.state.current() == state
            && self
                .activation_error
                .as_ref()
                .is_some_and(|old| old.code == error.code && old.message == error.message);
        if !unchanged {
            tracing::error!(code = %error.code, error = %error, "activation refused");
            self.state.transition(state, &error.message);
            self.state.emit(ssk_ipc::Event::Warning {
                code: error.code.clone(),
                message: error.message.clone(),
            });
        }
        self.activation_error = Some(error.clone());
        Response::Err(error)
    }

    fn record_activation(
        &mut self,
        flow_id: &str,
        route: &RouteKind,
        outcome: AuditOutcome,
    ) -> Result<(), IpcError> {
        // Refuse a corrupt existing chain, including a change during connect.
        // This is prefix integrity, not an independently anchored checkpoint.
        self.audit.verify()?;
        let seq = u64::try_from(self.audit.len()?).map_err(|_| {
            IpcError::new(
                "Integrity",
                "AUDIT_SEQUENCE_EXHAUSTED",
                "audit sequence exhausted",
            )
        })?;
        let entry = self.audit.record(
            format!("activate-{seq}"),
            flow_id,
            None,
            None,
            route,
            outcome,
            0,
        )?;
        // Deriving the sequence from the persisted ledger prevents a restart
        // from reusing activate-0 and keeps events aligned with entry IDs.
        self.state.emit(ssk_ipc::Event::AuditAppended {
            seq,
            entry_hash: entry.entry_hash,
        });
        self.pending_activation = match outcome {
            AuditOutcome::DispatchPending => Some((flow_id.to_string(), route.clone())),
            _ => None,
        };
        Ok(())
    }

    /// Settle an activation whose request ended while the daemon was in
    /// `Activating`: the future was dropped at the dial (the only `await` after
    /// the transition) or the handler panicked. Both leave `Inner` behind with
    /// no session and a state nothing else would ever reset, so the daemon ends
    /// fail-closed and, when it can, gives the pending intent its result.
    fn settle_abandoned_activation(&mut self) {
        let pending = self.pending_activation.take();
        // A panic that unwinds out of this drop while the thread is already
        // unwinding aborts the whole process, and the ledger write is file IO
        // and a chain walk. The state still settles; the intent then stays
        // without a result, as it would after a crash.
        if !std::thread::panicking() {
            if let Some((flow_id, route)) = pending {
                if let Err(error) =
                    self.record_activation(&flow_id, &route, AuditOutcome::FailClosed)
                {
                    tracing::error!(
                        code = %error.code,
                        error = %error,
                        "abandoned activation could not be given a result in the ledger"
                    );
                }
            }
        }
        self.refuse_activation(IpcError::new(
            "Runtime",
            ACTIVATION_CANCELLED,
            "the activation was interrupted before it completed; no session is held",
        ));
    }

    fn status(&mut self, view: KillSwitchView) -> StatusDto {
        let audit_head = match self.audit.entries() {
            Ok(entries) => entries.last().map(|entry| entry.entry_hash.clone()),
            Err(error) => {
                if self.config.is_ok() {
                    self.refuse_activation(error.into());
                }
                None
            }
        };
        let (kill_switch, broker_error) = kill_switch_fields(view);
        let mut last_error = self.activation_error.clone();
        if let Some(broker_error) = broker_error {
            if let Some(error) = &mut last_error {
                // The activation failure takes priority, but an unknown
                // kill-switch must remain explicitly visible on the wire.
                error
                    .next_steps
                    .push(format!("{}: {}", broker_error.code, broker_error.message));
                error.next_steps.extend(broker_error.next_steps);
            } else {
                last_error = Some(broker_error);
            }
        }
        StatusDto {
            state: self.state.current(),
            active_profile: self.active_profile.clone(),
            adapters: self
                .active_egress
                .as_ref()
                .map(adapter_health_from_session)
                .unwrap_or_default(),
            dns_protected: self.dns_protected,
            kill_switch,
            audit_head,
            version: env!("CARGO_PKG_VERSION").to_string(),
            last_error,
            protocol: IPC_PROTOCOL_VERSION,
            ingress: Some(disabled_ingress_status()),
        }
    }
}

/// The supervisor lock as an `ActivateProfile` request holds it. Dropping the
/// request's future or unwinding through it must not leave the daemon in
/// `Activating`: the state is entered under this lock and every normal way out
/// of the request has left it, so finding it still there when the lock is
/// released means the request was abandoned. Checking the state, and not a flag
/// that each exit has to remember to clear, is what keeps a new early return
/// from forgetting it.
struct ActivationScope<'a>(MutexGuard<'a, Inner>);

impl std::ops::Deref for ActivationScope<'_> {
    type Target = Inner;

    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl std::ops::DerefMut for ActivationScope<'_> {
    fn deref_mut(&mut self) -> &mut Inner {
        &mut self.0
    }
}

impl Drop for ActivationScope<'_> {
    fn drop(&mut self) {
        if self.0.state.current() == DaemonState::Activating {
            self.0.settle_abandoned_activation();
        }
    }
}

/// Build the two `StatusDto` fields that carry the kill-switch answer.
///
/// The wire type (`ssk_ipc::StatusDto::kill_switch: bool`) has no room for
/// "unknown", and `ssk-ipc` was outside this change's file scope, so the third
/// value is carried by the DTO's existing `last_error` instead of being rounded
/// to the reassuring side. The pairing is the contract:
///
/// * `(true,  None)`        — confirmed engaged.
/// * `(false, None)`        — confirmed **not** engaged.
/// * `(false, Some(adv))`   — **unknown**: the bool is a lossy projection and
///   the advisory says so, with a stable
///   [`crate::killswitch::KILL_SWITCH_STATUS_UNKNOWN`] code.
///
/// `(true, Some(_))` is unreachable by construction — `advisory()` is `Some`
/// only for `Unknown`, and `Unknown` never sets the bool.
fn kill_switch_fields(view: KillSwitchView) -> (bool, Option<IpcError>) {
    (view.is_confirmed_engaged(), view.advisory())
}

/// The answer to a status read that could not get `Inner` because an
/// activation holds it across its dial.
///
/// Built from nothing but what is true at that moment, not from a copy of an
/// earlier answer. An activation clears the old session before it dials, so a
/// remembered `Protected`, profile, adapter list or `dns_protected` would
/// describe protection that no longer exists, and a remembered `last_error`
/// belongs to a run this activation replaced. The kill-switch fields come from
/// the provider as of this call; it sits outside the mutex for exactly this.
/// The ledger is only readable under the mutex, so no audit head is claimed.
fn activating_status(view: KillSwitchView) -> StatusDto {
    let (kill_switch, last_error) = kill_switch_fields(view);
    StatusDto {
        state: DaemonState::Activating,
        active_profile: None,
        adapters: Vec::new(),
        dns_protected: false,
        kill_switch,
        audit_head: None,
        version: env!("CARGO_PKG_VERSION").to_string(),
        last_error,
        protocol: IPC_PROTOCOL_VERSION,
        // Built here, now, like the rest of this answer: the proxy's block never
        // needs the mutex an activation holds, and a copy kept from before the
        // dial could say `armed` about a proxy that has since been disarmed.
        ingress: Some(disabled_ingress_status()),
    }
}

/// The local proxy's block while there is no proxy: the daemon opens no listener
/// yet, whatever the configuration says. A daemon of protocol 1 never answers
/// `ingress: None` (that would say "predates the proxy"), so a proxy that is off
/// is this block, and everything it does not know stays at the unknown default.
/// It claims no coverage and no activity, and nothing in it names a VPN or
/// anything else that is not this daemon's own fact.
///
/// Both literals of [`StatusDto`] call it; `status_answer` swaps it for the real
/// snapshot when the proxy exists.
fn disabled_ingress_status() -> IngressStatusDto {
    IngressStatusDto {
        state: "disabled".into(),
        coverage: "none".into(),
        system_wide: false,
        notice: INGRESS_COVERAGE_NOTICE.into(),
        ..IngressStatusDto::default()
    }
}

/// The refusal of a request about a proxy that does not exist. Not retriable:
/// asking again does not create it, so the one next step offered is to read the
/// status.
fn ingress_disabled() -> IpcError {
    IpcError::new(
        "Config",
        INGRESS_DISABLED,
        "the local proxy is off in this daemon; nothing was changed",
    )
    .with_next_step(
        "`ssk status` reports the proxy under `ingress`; `disabled` means no listener exists.",
    )
}

/// A request turned away because an activation is in flight and the state it
/// needs is the state the dial holds. Nothing was changed.
fn busy_during_activation() -> IpcError {
    IpcError::new(
        "Runtime",
        DAEMON_BUSY,
        "an activation is in progress and this request needs the state it holds; nothing was changed",
    )
    .retriable()
    .with_next_step("Retry once the activation has finished.")
    .with_next_step("`ssk status` answers while an activation is in progress.")
}

/// A request turned away because two requests that change the daemon's state
/// are already in flight. Nothing was changed.
fn busy_mutators() -> IpcError {
    IpcError::new(
        "Runtime",
        DAEMON_BUSY,
        "two requests that change the daemon's state are already in progress; nothing was changed",
    )
    .retriable()
    .with_next_step("Retry once one of them has finished.")
    .with_next_step("`ssk status` shows what the daemon is doing.")
}

/// Wait for `shutdown` for at most `bound`; `false` when the bound ended the
/// wait. The caller drops what it was shutting down either way.
async fn finishes_within<F>(bound: Duration, shutdown: F) -> bool
where
    F: std::future::Future<Output = std::io::Result<()>>,
{
    // A shutdown that fails is as good as one that finished: the session is
    // dropped next, and dropping closes the transport.
    tokio::time::timeout(bound, shutdown).await.is_ok()
}

/// Shut a held session down gracefully, for at most [`SESSION_SHUTDOWN_BOUND`],
/// and let the caller drop it. Every place that closes a held session while it
/// holds `Inner` goes through here, which is what makes "the mutex is only held
/// for short, bounded work" true outside the dial.
async fn close_bounded(session: &mut EgressSession) {
    if !finishes_within(SESSION_SHUTDOWN_BOUND, session.shutdown()).await {
        tracing::warn!(
            bound = ?SESSION_SHUTDOWN_BOUND,
            "a held session did not shut down in time; dropping its transport"
        );
    }
}

/// Startup validation, shared by both constructors. Even a caller that built a
/// `LoadedConfig` by hand gets it validated, and a failure becomes the
/// `CONFIG_INVALID` answer the daemon keeps serving diagnosis with.
fn validated(config: Result<ssk_config::LoadedConfig, DaemonConfigError>) -> ConfigState {
    config
        .and_then(|loaded| {
            loaded.config.validate()?;
            Ok(loaded)
        })
        .map_err(|error| {
            IpcError::new("Config", "CONFIG_INVALID", error.to_string()).with_next_step(
                "Fix SSK_CONFIG_PATH and its configuration, then restart the daemon.",
            )
        })
}

impl Supervisor {
    /// `kill_switch` is the injected read-only view of the privileged broker
    /// (roadmap P3). It is a seam for the same reason `data_plane` is: the real
    /// implementation dials a LocalSystem-owned named pipe, which no test on an
    /// unelevated machine can stand up. Pass
    /// [`crate::killswitch::NoProvider`] when there is no broker to ask — it
    /// answers `Unknown`, never `NotEngaged`.
    /// `config` is mandatory: a failed load keeps diagnosis reachable in
    /// `ConfigInvalid` and cannot be replaced by implicit defaults here.
    #[must_use]
    pub fn new(
        audit_path: PathBuf,
        data_plane: Box<dyn DataPlane>,
        kill_switch: Box<dyn KillSwitchProvider>,
        config: Result<ssk_config::LoadedConfig, DaemonConfigError>,
    ) -> Self {
        let config = validated(config);
        let routing = Arc::new(ConfiguredRouting::new(
            &config
                .as_ref()
                .map(|loaded| loaded.config.routing.clone())
                .unwrap_or_default(),
        ));
        Self::assemble(
            audit_path,
            routing,
            Arc::from(data_plane),
            kill_switch,
            config,
        )
    }

    /// Like [`Supervisor::new`], for a caller that compiled the planner itself
    /// and keeps using it: `routing` is what activations and `TraceRoute` plan
    /// with and what [`Supervisor::routing`] hands back, and `data_plane` is what
    /// an activation dials through. The caller compiles `routing` from the same
    /// validated configuration it passes as `config`; that is how the executor's
    /// adapter registry and this planner come from one compilation and not two.
    /// When `config` turns out invalid, `routing` is never consulted: every
    /// handler that reads it answers the configuration error first.
    #[must_use]
    pub fn from_parts(
        audit_path: PathBuf,
        routing: Arc<ConfiguredRouting>,
        data_plane: Arc<dyn DataPlane>,
        kill_switch: Box<dyn KillSwitchProvider>,
        config: Result<ssk_config::LoadedConfig, DaemonConfigError>,
    ) -> Self {
        Self::assemble(
            audit_path,
            routing,
            data_plane,
            kill_switch,
            validated(config),
        )
    }

    fn assemble(
        audit_path: PathBuf,
        routing: Arc<ConfiguredRouting>,
        data_plane: Arc<dyn DataPlane>,
        kill_switch: Box<dyn KillSwitchProvider>,
        config: ConfigState,
    ) -> Self {
        let activation_error = config.as_ref().err().cloned();
        let config = Arc::new(config);
        let mut state = StateMachine::default();
        if let Some(error) = &activation_error {
            state.transition(DaemonState::ConfigInvalid, &error.message);
        }
        // Taken before the state machine moves into the mutex.
        let events = state.event_sender();
        Self {
            config: Arc::clone(&config),
            routing,
            data_plane,
            kill_switch,
            activation_deadline: ACTIVATE_DIAL_DEADLINE,
            activations: ActivationsInFlight::default(),
            mutators: Semaphore::new(MAX_MUTATORS),
            events,
            inner: Mutex::new(Inner {
                state,
                active_profile: None,
                audit: PersistedAuditLedger::persisted(audit_path),
                config,
                activation_error,
                active_egress: None,
                dns_protected: false,
                pending_activation: None,
            }),
        }
    }

    /// The planner activations and `TraceRoute` decide with. Shared, not
    /// copied: whoever holds this handle sees the one compilation of the
    /// configuration, which is how the ingress will plan with exactly the
    /// routing the supervisor holds.
    #[must_use]
    pub fn routing(&self) -> &Arc<ConfiguredRouting> {
        &self.routing
    }

    /// The data plane an activation dials through. Not the ingress's own.
    #[must_use]
    pub fn data_plane(&self) -> &Arc<dyn DataPlane> {
        &self.data_plane
    }

    /// Replace the activation dial deadline (default 20 s). Exists so tests can
    /// end a silent upstream in milliseconds; expiry is an ordinary failed
    /// connect, never a way to proceed without the route.
    #[must_use]
    pub fn with_activation_deadline(mut self, deadline: Duration) -> Self {
        self.activation_deadline = deadline;
        self
    }

    /// The current kill-switch view. Non-blocking — see
    /// [`crate::killswitch::KillSwitchProvider`]'s contract.
    #[must_use]
    pub fn kill_switch_view(&self) -> KillSwitchView {
        self.kill_switch.view()
    }

    /// Subscribe to the daemon's event bus. The IPC `SubscribeEvents` request
    /// does not come through here (it answers `Ack`); the callers are tests.
    ///
    /// Does not take the supervisor mutex, so it answers during an activation
    /// dial. It stays `async` so existing callers keep compiling unchanged.
    pub async fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<ssk_ipc::Event> {
        self.events.subscribe()
    }

    pub async fn current_state(&self) -> DaemonState {
        self.inner.lock().await.state.current()
    }

    /// The supervisor mutex for a reader that must not queue behind an
    /// activation dial.
    ///
    /// The mutex is held across the whole dial, so a reader that simply awaits
    /// it waits the dial out. This waits [`STATUS_LOCK_WAIT`] and, if the mutex
    /// is still taken, asks whether an activation is the reason: only then does
    /// it answer `ActivationInFlight`. Any other holder is short and mid-change,
    /// and what it is changing is what the reader must report, so that case
    /// keeps waiting.
    async fn inner_unless_activating(&self) -> InnerAccess<'_> {
        // Joined once and kept: dropping the timed-out wait would forfeit this
        // request's place in the mutex's queue.
        let acquire = self.inner.lock();
        tokio::pin!(acquire);
        match tokio::time::timeout(STATUS_LOCK_WAIT, &mut acquire).await {
            Ok(inner) => InnerAccess::Held(inner),
            Err(_elapsed) if self.activations.any() => InnerAccess::ActivationInFlight,
            Err(_elapsed) => InnerAccess::Held(acquire.await),
        }
    }

    /// The one place a status answer is built for a caller that does not hold
    /// the mutex. What is read fresh at this call (the kill-switch view) is read
    /// here, so no answer carries a copy that an activation has made false.
    async fn status_answer(&self) -> StatusDto {
        match self.inner_unless_activating().await {
            InnerAccess::Held(mut inner) => self.status_held(&mut inner),
            InnerAccess::ActivationInFlight => activating_status(self.kill_switch.view()),
        }
    }

    /// The status answer of a handler that already holds the mutex
    /// (`ActivateProfile`, `Deactivate`): `status_answer` for the case where
    /// there is nothing to wait for.
    fn status_held(&self, inner: &mut Inner) -> StatusDto {
        inner.status(self.kill_switch.view())
    }

    /// Record that a previously-spawned activation task died unexpectedly
    /// (crash/kill). Moves the daemon to a safe, fail-closed state rather
    /// than silently staying in `Activating` forever.
    pub async fn record_task_failure(&self, reason: impl Into<String>) {
        let mut inner = self.inner.lock().await;
        let target = if inner.active_profile.is_some() {
            DaemonState::Degraded
        } else {
            DaemonState::FailClosed
        };
        // A worker we lost track of might still be holding the real egress
        // open in an unknown state; close it for real rather than leaving a
        // dangling connection behind an inconsistent supervisor.
        if let Some(mut session) = inner.active_egress.take() {
            close_bounded(&mut session).await;
        }
        inner.dns_protected = false;
        inner.state.transition(target, reason);
    }

    /// Spawn `task` as a supervised background job (e.g. a future data-plane
    /// worker) and return an `AbortHandle` the caller can use to cancel it.
    /// If the task panics or is aborted, a separate watchdog task observes
    /// that via the underlying `JoinHandle` and calls
    /// [`Supervisor::record_task_failure`] — the daemon never silently loses
    /// track of a dead worker. This is the literal mechanism behind the
    /// architecture's AC: "a killed daemon task transitions to
    /// degraded/fail_closed and emits an event".
    pub fn spawn_supervised<F>(
        self: &Arc<Self>,
        reason: &'static str,
        task: F,
    ) -> tokio::task::AbortHandle
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let handle = tokio::spawn(task);
        let abort_handle = handle.abort_handle();
        let sup = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(join_err) = handle.await {
                let detail = if join_err.is_cancelled() {
                    format!("{reason}: task was cancelled/aborted")
                } else {
                    format!("{reason}: task panicked: {join_err}")
                };
                sup.record_task_failure(detail).await;
            }
        });
        abort_handle
    }
}

fn parse_protocol(s: &str) -> ProtocolKind {
    match s.to_ascii_lowercase().as_str() {
        "udp" => ProtocolKind::Udp,
        "tls" => ProtocolKind::Tls,
        "http" => ProtocolKind::Http,
        "https" => ProtocolKind::Https,
        "dns" => ProtocolKind::Dns,
        "tcp" => ProtocolKind::Tcp,
        _ => ProtocolKind::Custom,
    }
}

/// Per-adapter entries derived from the held session's actual traversed chain.
/// The health text states only what activation established; see
/// [`ADAPTER_HEALTH_AT_ACTIVATION`].
fn adapter_health_from_session(session: &EgressSession) -> Vec<AdapterHealthSummaryDto> {
    session
        .chain()
        .iter()
        .map(|kind| AdapterHealthSummaryDto {
            id: format!("{kind:?}"),
            health: ADAPTER_HEALTH_AT_ACTIVATION.into(),
        })
        .collect()
}

/// `true` only when DNS resolution genuinely could not leak to the plain OS
/// resolver: either the destination was already a literal IP (no lookup
/// happened at all) or the real chain traversed a `DnsOverride` adapter.
/// Never hardcoded.
fn dns_protected_for(dest_host: &str, session: &EgressSession) -> bool {
    dest_host.parse::<std::net::IpAddr>().is_ok()
        || session
            .chain()
            .contains(&ssk_netadmin::adapter::AdapterKind::DnsOverride)
}

fn parse_risk(s: &str) -> RiskLevel {
    match s.to_ascii_lowercase().as_str() {
        "medium" => RiskLevel::Medium,
        "high" => RiskLevel::High,
        "critical" => RiskLevel::Critical,
        _ => RiskLevel::Low,
    }
}

/// Longest accepted `profile_id`.
const MAX_PROFILE_ID_LEN: usize = 64;

/// Why a `profile_id` was refused. Two distinct codes because the operator
/// actions differ: one is "fix your input", the other is "that profile is not
/// configured".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileRejection {
    /// Failed the shape check: empty, over-long, or containing bytes outside
    /// `[a-z0-9._-]`.
    Malformed,
    /// Well-formed, but not in the configured registry.
    Unknown,
}

/// Shape check first, then set membership.
///
/// The shape check is cheap, purely local, and it runs first for a security
/// reason rather than a stylistic one: without it, a caller could use the error
/// message and the derived flow id as an arbitrary-string injection oracle into
/// the logs and the ledger.
///
/// P2 authenticated the Windows IPC surface (the peer's SID must match the
/// daemon's), so the caller is no longer *anonymous* — but it is still any
/// process running as the same user, which is precisely the reach this check
/// exists to bound. Authentication narrowed the attacker set; it did not remove
/// the need for input validation on a value that reaches a hash-chained ledger.
fn validate_profile_id(id: &str, profiles: &[ProfileSummaryDto]) -> Result<(), ProfileRejection> {
    if id.is_empty()
        || id.len() > MAX_PROFILE_ID_LEN
        || !id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
    {
        return Err(ProfileRejection::Malformed);
    }
    if !profiles.iter().any(|p| p.id == id) {
        return Err(ProfileRejection::Unknown);
    }
    Ok(())
}

fn known_profile_ids(profiles: &[ProfileSummaryDto]) -> String {
    profiles
        .iter()
        .map(|p| p.id.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Real environment probes, equivalent to (but independently implemented
/// from) `ssk-cli`'s `doctor` checks — same intentional-duplication rationale
/// as `config_load`, **except for the entropy probe**: that duplication
/// produced the identical `/dev/urandom` defect in both places, so it now
/// lives once in [`ssk_diag::entropy`], which `ssk`, `sskd` and `ssk-svc` all
/// link.
fn run_doctor_checks() -> Vec<DoctorCheckDto> {
    let mut checks = Vec::new();

    let clock_ok = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .is_ok();
    checks.push(DoctorCheckDto {
        name: "system_clock".into(),
        ok: clock_ok,
        detail: if clock_ok {
            "system clock is readable and monotonic".into()
        } else {
            "system clock is before the UNIX epoch".into()
        },
        next_step: if clock_ok {
            None
        } else {
            Some("Fix the system clock before operating the daemon.".into())
        },
    });

    let entropy = ssk_diag::entropy::probe();
    checks.push(DoctorCheckDto {
        name: "entropy".into(),
        ok: entropy.ok,
        detail: entropy.detail,
        next_step: entropy.next_step,
    });

    // The daemon's *state directory*, not the working directory. The old check
    // asserted `current_dir()` was readable, which is both trivially true and
    // irrelevant now that state no longer lives relative to the CWD; what an
    // operator needs to know is whether `sskd` has a home at all.
    let paths = crate::paths::resolve();
    checks.push(match paths {
        Ok(root) => DoctorCheckDto {
            name: "paths".into(),
            ok: true,
            detail: format!("state directory resolves to {}", root.display()),
            next_step: None,
        },
        Err(err) => DoctorCheckDto {
            name: "paths".into(),
            ok: false,
            detail: format!("state directory is unresolvable: {err}"),
            next_step: Some(
                "Set SSK_STATE_DIR to an absolute path, or repair the platform's \
                 %LOCALAPPDATA% / $HOME environment."
                    .into(),
            ),
        },
    });

    checks
}

impl CommandHandler for Supervisor {
    fn handle<'a>(&'a self, req: Request, _peer: &'a PeerIdentity) -> BoxFuture<'a, Response> {
        Box::pin(async move {
            match req {
                Request::GetStatus => Response::Status(self.status_answer().await),
                Request::ActivateProfile(req) => {
                    // At most two requests that change the state are in flight,
                    // so at most two connections can be occupied by one waiting
                    // for the dial. Taken first and never awaited; declared
                    // before everything below, so it is the last thing released.
                    let Ok(_mutator) = self.mutators.try_acquire() else {
                        tracing::debug!(target: "ssk.lifecycle", "activate_profile refused: mutator gate full");
                        return Response::Err(busy_mutators());
                    };
                    // Before the first await: from here to the answer, a status
                    // read that cannot get `Inner` knows why. Declared before
                    // `inner` so it is released after the mutex is: a reader
                    // must never find the mutex still held by this activation
                    // with the marker already gone. The scope settles an
                    // abandoned activation while it still holds the mutex, so
                    // that too is finished before the marker goes.
                    let _in_flight = self.activations.enter();
                    let mut inner = ActivationScope(self.inner.lock().await);
                    if let Err(error) = &*self.config {
                        let error = error.clone();
                        return inner.refuse_activation(error);
                    }

                    // Validation runs before *anything* with a side effect —
                    // before the `Activating` transition, before the
                    // destination check, before a flow id is derived from
                    // attacker-controlled text.
                    //
                    // A rejected request must NOT move the daemon to
                    // `FailClosed`. `FailClosed` is documented as "cannot
                    // guarantee protection; traffic blocked" — a statement
                    // about the protection posture, not about the last
                    // request. Conflating them would let any peer drive the
                    // daemon into a blocked state with one garbage string,
                    // turning a validation bug into a remote DoS and turning
                    // `FailClosed` into noise operators learn to ignore. So:
                    // the request fails closed; the daemon does not change
                    // state.
                    //
                    // No audit entry is appended for the rejection either, and
                    // that is a decision rather than an omission. The ledger
                    // attests to *enforcement actions*, it is append-only and
                    // hash-chained, and any process of the same user can drive
                    // it: an attacker-controlled unbounded append is a
                    // disk-exhaustion DoS against the one artifact that must
                    // survive. The rejection is observable as an event and a
                    // log line instead.
                    let profiles = self.routing.profiles();
                    if let Err(rejection) = validate_profile_id(&req.profile_id, &profiles) {
                        let (code, message) = match rejection {
                            ProfileRejection::Malformed => (
                                "PROFILE_ID_INVALID",
                                format!(
                                    "profile_id must be 1..={MAX_PROFILE_ID_LEN} characters of \
                                     [a-z0-9._-]; known profiles: {}",
                                    known_profile_ids(&profiles)
                                ),
                            ),
                            ProfileRejection::Unknown => (
                                "UNKNOWN_PROFILE",
                                format!(
                                    "no profile `{}` is configured; known profiles: {}",
                                    req.profile_id,
                                    known_profile_ids(&profiles)
                                ),
                            ),
                        };
                        tracing::warn!(
                            target: "ssk.lifecycle",
                            code,
                            profile_id = %req.profile_id.escape_debug(),
                            state = ?inner.state.current(),
                            "activate_profile refused: unknown or malformed profile id"
                        );
                        inner.state.emit(ssk_ipc::Event::Warning {
                            code: code.to_string(),
                            message: message.clone(),
                        });
                        return Response::Err(
                            IpcError::new("Usage", code, message).with_next_step(
                                "Run `ssk list-profiles` to see the configured profiles.",
                            ),
                        );
                    }

                    inner.clear_egress();
                    inner.activation_error = None;
                    inner
                        .state
                        .transition(DaemonState::Activating, "activate_profile requested");

                    let (dest_host, dest_port) = match (req.dest_host.clone(), req.dest_port) {
                        (Some(host), Some(port)) => (host, port),
                        _ => {
                            // No real destination to protect. Rather than
                            // hold onto `Activating` or fabricate
                            // `Protected` (the exact false-reassurance bug
                            // the previous mock produced), fail closed with
                            // an explicit, actionable reason.
                            inner.active_profile = None;
                            inner.state.transition(
                                DaemonState::FailClosed,
                                "activate_profile requires dest_host/dest_port: there is nothing to protect without a real destination",
                            );
                            return Response::Err(
                                // Class `Usage`, not `Validation`: `ssk-cli`'s
                                // `From<IpcError>` mapping has no `Validation`
                                // arm, so that string fell through to
                                // `ErrorClass::Runtime` and this already-shipping
                                // path returned the wrong exit code.
                                IpcError::new(
                                    "Usage",
                                    "DEST_REQUIRED",
                                    "activate_profile requires dest_host and dest_port; there is nothing to protect without a real destination",
                                )
                                .with_next_step("Pass --dest host:port to `ssk activate`."),
                            );
                        }
                    };

                    if !ssk_config::routing::valid_host(&dest_host) || dest_port == 0 {
                        return inner.refuse_activation(IpcError::new(
                            "Usage",
                            "DEST_INVALID",
                            "destination requires a valid hostname/IP and nonzero port",
                        ));
                    }

                    let flow = FlowRecord::new(
                        format!("activate:{}", req.profile_id),
                        0,
                        FlowDescriptor::new(
                            "sskd-activate",
                            &dest_host,
                            dest_port,
                            ProtocolKind::Tcp,
                            RiskLevel::Low,
                        ),
                    );
                    let (decision, route) = match self.routing.decide(&req.profile_id, &flow) {
                        Ok(Decided {
                            decision,
                            candidate,
                        }) => (decision, candidate.route),
                        Err(err) => {
                            inner.active_profile = None;
                            inner.state.transition(
                                DaemonState::FailClosed,
                                format!("route planning failed: {err}"),
                            );
                            return Response::Err(err.into());
                        }
                    };

                    let admission = match self.routing.orchestrator.admit(&flow, &decision) {
                        Ok(admission) => admission,
                        Err(error) => {
                            if let Err(audit_error) =
                                inner.record_activation(&flow.flow_id, &route, AuditOutcome::Denied)
                            {
                                return inner.refuse_activation(audit_error);
                            }
                            return inner.refuse_activation(error.into());
                        }
                    };
                    // A durable intent precedes every network attempt. It is
                    // explicitly pending, never a fabricated successful dispatch.
                    if let Err(error) = inner.record_activation(
                        &flow.flow_id,
                        &route,
                        AuditOutcome::DispatchPending,
                    ) {
                        return inner.refuse_activation(error);
                    }
                    // Dropping the timed-out dial closes its half-built
                    // transport; the expiry then takes the same durable
                    // `FailClosed` path as any other failed connect.
                    let deadline = self.activation_deadline;
                    let connected = match tokio::time::timeout(
                        deadline,
                        self.data_plane.connect_route(admission),
                    )
                    .await
                    {
                        Ok(result) => result
                            .map_err(|err| IpcError::new("Runtime", err.code(), err.to_string())),
                        Err(_elapsed) => Err(IpcError::new(
                            "Runtime",
                            ACTIVATION_CONNECT_TIMEOUT,
                            format!("activation connect did not complete within {deadline:?}"),
                        )
                        .with_next_step(
                            "Check that the configured proxy or upstream is reachable and \
                             completes its handshake; no direct connection is made instead.",
                        )),
                    };
                    let outcome = if connected.is_ok() {
                        AuditOutcome::Dispatched
                    } else {
                        AuditOutcome::FailClosed
                    };
                    if let Err(error) = inner.record_activation(&flow.flow_id, &route, outcome) {
                        // Keep the new session local until its result is durable.
                        // Drop closes it before any failure response or event.
                        drop(connected);
                        return inner.refuse_activation(error);
                    }
                    match connected {
                        Ok(session) => {
                            inner.dns_protected = dns_protected_for(&dest_host, &session);
                            let reason =
                                format!("real egress established via {:?}", session.chain());
                            inner.active_egress = Some(session);
                            inner.active_profile = Some(req.profile_id.clone());
                            inner.state.transition(DaemonState::Protected, reason);
                        }
                        Err(err) => {
                            inner.activation_error = Some(err.clone());
                            inner.active_profile = None;
                            inner.dns_protected = false;
                            inner.state.transition(
                                DaemonState::FailClosed,
                                format!("no viable route for profile `{}`: {err}", req.profile_id),
                            );
                        }
                    }

                    Response::Status(self.status_held(&mut inner))
                }
                Request::Deactivate(req) => {
                    // One of the two mutators; see `ActivateProfile`.
                    let Ok(_mutator) = self.mutators.try_acquire() else {
                        tracing::debug!(target: "ssk.lifecycle", "deactivate refused: mutator gate full");
                        return Response::Err(busy_mutators());
                    };
                    // Not answered around an activation dial: the mutex is FIFO,
                    // so a `Deactivate` sent after an `ActivateProfile` runs
                    // after it and is never undone by it. It waits at most for
                    // the activation deadline.
                    let mut inner = self.inner.lock().await;
                    if inner.state.current() == DaemonState::FailClosed && !req.release_kill_switch
                    {
                        // The code stays because clients match on it, but what it
                        // names is the daemon's own fail-closed state and not the
                        // firewall rule the broker owns (see the comment below).
                        return Response::Err(
                            IpcError::new(
                                "Permission",
                                "KILL_SWITCH_ARMED",
                                "the daemon is in its fail-closed state; pass release_kill_switch=true to deactivate anyway",
                            )
                            .with_next_step(
                                "Resolve the underlying route/adapter issue and activate again, or pass release_kill_switch=true to return the daemon to its inactive state.",
                            ),
                        );
                    }
                    // Real teardown: closing the boxed transport actually
                    // shuts down the TCP/TLS/proxy tunnel, not just a state
                    // label — this is the concrete kill-switch-adjacent
                    // mechanism for the one session the daemon holds.
                    if let Some(mut session) = inner.active_egress.take() {
                        close_bounded(&mut session).await;
                    }
                    inner.active_profile = None;
                    inner.dns_protected = false;
                    let state = if self.config.is_err() {
                        DaemonState::ConfigInvalid
                    } else {
                        DaemonState::Inactive
                    };
                    inner.state.transition(state, "deactivate requested");

                    // Deactivating this daemon's own egress session says
                    // nothing about the privileged broker's kill-switch: the
                    // two are different mechanisms in different processes, and
                    // a `release_kill_switch=true` here does not reach the
                    // broker (routing that verb through it is P3 CLI work, not
                    // done). So this is re-read, not assumed released.
                    Response::Status(self.status_held(&mut inner))
                }
                // Read from the configuration and the routing, which sit outside
                // `Inner`, so an activation dial does not delay the answer.
                Request::ListProfiles => match &*self.config {
                    Ok(_) => Response::Profiles(self.routing.profiles()),
                    Err(error) => Response::Err(error.clone()),
                },
                Request::InspectFlow { flow_id: _ } => Response::Err(IpcError::new(
                    "Runtime",
                    "FLOW_NOT_FOUND",
                    "No captured flow is available; use trace-route for a policy preview.",
                )),
                Request::TraceRoute(req) => {
                    if let Err(error) = &*self.config {
                        return Response::Err(error.clone());
                    }
                    // The held session's profile, else the default. The held
                    // session is `Inner`'s, and while an activation dials it is
                    // being replaced: neither the old profile nor the default
                    // would be what the activation is about to make true, so
                    // the answer is "busy", not a guess. No other source of a
                    // profile exists yet that would not need `Inner`: the
                    // request names none and no ingress is armed.
                    //
                    // An activation plans with the profile it was asked for and
                    // a different flow, and goes on to admit and dial; what the
                    // two share is `decide`, not their inputs, so a trace
                    // answers for the inputs it was given and no more.
                    let held_profile = match self.inner_unless_activating().await {
                        InnerAccess::Held(inner) => inner.active_profile.clone(),
                        InnerAccess::ActivationInFlight => {
                            return Response::Err(busy_during_activation());
                        }
                    };
                    let profile_source = if held_profile.is_some() {
                        "active_session"
                    } else {
                        "default_profile"
                    };
                    let profile = held_profile
                        .as_deref()
                        .unwrap_or(&self.routing.default_profile);
                    let app_id = req.app_id.as_deref().unwrap_or("unknown-app");
                    let flow = FlowRecord::new(
                        "trace",
                        0,
                        FlowDescriptor::new(
                            app_id,
                            &req.dest_host,
                            req.dest_port,
                            parse_protocol(&req.protocol),
                            parse_risk(&req.risk),
                        ),
                    );
                    match self.routing.decide(profile, &flow) {
                        Ok(Decided { candidate, .. }) => {
                            let hops = match &candidate.route {
                                ssk_netadmin::RouteKind::SingleHop(h) => vec![h.adapter_id.clone()],
                                ssk_netadmin::RouteKind::MultiHop(hops) => {
                                    hops.iter().map(|h| h.adapter_id.clone()).collect()
                                }
                                RouteKind::OpenVpn { adapter_id, .. } => vec![adapter_id.clone()],
                                _ => vec![],
                            };
                            // Which inputs this preview used, so that a client
                            // can tell it from the one it asked for. The only
                            // evaluation is the activation's, and `profile_id`
                            // of the request is not acted on yet: the answer
                            // says which profile it did use.
                            Response::RouteTrace(RouteTraceDto {
                                route: candidate.route,
                                hops,
                                requires_attestation: candidate.requires_attestation,
                                profile_used: Some(profile.to_string()),
                                profile_source: Some(profile_source.to_string()),
                                evaluated_as: Some("legacy_activation".to_string()),
                                app_id_used: Some(app_id.to_string()),
                                refusal: None,
                                guards_skipped: Vec::new(),
                            })
                        }
                        Err(err) => Response::Err(err.into()),
                    }
                }
                Request::ListRecentFlows { limit: _ } => {
                    // Honestly empty: no traffic ingress exists until
                    // `ssk-capture` ships (Phase 4). Never fabricate flows.
                    Response::RecentFlows(vec![])
                }
                Request::GetAuditEntries { limit } => {
                    // The legacy ledger is `Inner`'s and is only readable under
                    // the mutex: say "busy" rather than queue behind the dial.
                    let inner = match self.inner_unless_activating().await {
                        InnerAccess::Held(inner) => inner,
                        InnerAccess::ActivationInFlight => {
                            return Response::Err(busy_during_activation());
                        }
                    };
                    match inner.audit.entries() {
                        Ok(entries) => {
                            let dtos: Vec<AuditEntryDto> = entries
                                .iter()
                                .rev()
                                .take(limit.max(1))
                                .map(AuditEntryDto::from)
                                .collect();
                            Response::AuditEntries(dtos)
                        }
                        Err(err) => Response::Err(err.into()),
                    }
                }
                Request::VerifyAuditChain => {
                    // As for `GetAuditEntries`.
                    let inner = match self.inner_unless_activating().await {
                        InnerAccess::Held(inner) => inner,
                        InnerAccess::ActivationInFlight => {
                            return Response::Err(busy_during_activation());
                        }
                    };
                    match inner.audit.verify() {
                        Ok(()) => {
                            let head = inner
                                .audit
                                .entries()
                                .ok()
                                .and_then(|e| e.last().map(|e| e.entry_hash.clone()));
                            Response::AuditVerify(VerifyAuditChainResponse {
                                ok: true,
                                head,
                                broken_at: None,
                            })
                        }
                        Err(err) => Response::AuditVerify(VerifyAuditChainResponse {
                            ok: false,
                            head: None,
                            broken_at: Some(err.to_string()),
                        }),
                    }
                }
                Request::RunDoctor => {
                    // Environment probes and the hoisted configuration: nothing
                    // here is `Inner`'s, so a dial does not delay it.
                    let mut checks = run_doctor_checks();
                    let (ok, detail, next_step) = match &*self.config {
                        Ok(loaded) => (
                            true,
                            format!(
                                "validated startup config v{}; routing uses validated configured profiles (unmatched flows denied)",
                                loaded.config.version
                            ),
                            None,
                        ),
                        Err(error) => (
                            false,
                            error.message.clone(),
                            error.next_steps.first().cloned(),
                        ),
                    };
                    checks.push(DoctorCheckDto {
                        name: "config".into(),
                        ok,
                        detail,
                        next_step,
                    });
                    if let Ok(loaded) = &*self.config {
                        for adapter in &loaded.config.routing.adapters {
                            if matches!(
                                adapter.transport,
                                ssk_config::routing::AdapterTransport::OpenVpn { .. }
                            ) {
                                checks.push(DoctorCheckDto {
                                    name: format!("openvpn:{}", adapter.id), ok: false,
                                    detail: "OPENVPN_NOT_READY: profile configured; privileged broker lifecycle is not implemented".into(),
                                    next_step: Some("OpenVPN activation requires the forthcoming broker integration; no direct fallback is permitted.".into()),
                                });
                            }
                        }
                    }
                    Response::Doctor(DoctorReportDto { checks })
                }
                Request::ExplainError(req) => Response::Explain(explain_code(&req.code)),
                Request::SubscribeEvents(_req) => {
                    // Actual event delivery happens out-of-band over the
                    // transport's push channel; this response just
                    // acknowledges the subscription request.
                    Response::Ack
                }
                // The proxy does not exist yet, so there is nothing to arm, to
                // disarm or to read. Both directions are refused, the disarm
                // too: no client sends the request before the proxy is wired,
                // and the real handler answers a disarm of a disabled proxy
                // with the status. Neither touches `Inner`, so neither waits
                // for an activation.
                Request::SetIngress(_req) => Response::Err(ingress_disabled()),
                Request::GetIngressAudit { .. } => Response::Err(ingress_disabled()),
            }
        })
    }
}

fn explain_code(code: &str) -> ExplainResponse {
    let (summary, details, next_steps): (&str, &str, Vec<&str>) = match code {
        "OPENVPN_NOT_READY" => (
            "The configured OpenVPN adapter is not available in this build.",
            "A broker-managed OpenVPN lifecycle and verified tunnel binding are not implemented. This selection opens no direct connection.",
            vec!["Keep the VPN requirement in the profile; OpenVPN support must be completed before activating it."],
        ),
        "ATTESTATION_REQUIRED" => (
            "The matched rule requires a verified attestation.",
            "The daemon does not yet accept flow-bound attestation evidence. Required attestation denies dispatch.",
            vec!["Complete the flow-bound attestation verifier before activating this rule."],
        ),
        "DEST_INVALID" => (
            "The destination is invalid.",
            "A hostname or literal IP and a nonzero port are required.",
            vec!["Pass a valid --dest host:port."],
        ),
        "CONFIG_INVALID" => (
            "The daemon's startup configuration is invalid or unreadable.",
            "Activation is disabled; status and diagnostics remain available. Deactivation does not clear the configuration error.",
            vec!["Fix SSK_CONFIG_PATH and its configuration, then restart the daemon."],
        ),
        "LEDGER_IO_FAILED" => (
            "The audit ledger could not be read or durably written.",
            "Activation requires a durable intent before dispatch and a durable result before Protected. A connection without that result is closed.",
            vec!["Inspect the ledger path, available storage and permissions; preserve the existing ledger before recovery."],
        ),
        "AUDIT_SEQUENCE_EXHAUSTED" => (
            "The audit sequence cannot represent another entry.",
            "The daemon refuses activation instead of reusing an audit identifier.",
            vec!["Preserve and archive the ledger using an approved retention procedure before recovery."],
        ),
        ACTIVATION_CANCELLED => (
            "The activation was interrupted before it completed.",
            "The request that was dialing the route ended before the dial did: its caller went away, the daemon was shutting down, or the handler failed unexpectedly. The attempt was dropped, no session is held and the daemon is fail-closed. An attempt that was cancelled leaves a fail-closed result after its pending intent in the audit ledger; after an unexpected failure of the handler the intent stays without a result.",
            vec![
                "Check the daemon log for the cause.",
                "Activate again once the daemon is running normally.",
            ],
        ),
        ACTIVATION_CONNECT_TIMEOUT => (
            "The activation connection did not complete in time.",
            "The route's upstream accepted or stalled the connection but did not finish its handshake before the daemon's activation deadline. The attempt was closed, the daemon is fail-closed, and no direct connection was made instead.",
            vec![
                "Check that the configured proxy or upstream is reachable and answering.",
                "Retry the activation once the upstream responds.",
            ],
        ),
        "NO_POLICY_MATCH" => (
            "No policy rule matched this flow.",
            "The policy engine evaluates rules by priority; when none match, the flow is denied fail-closed.",
            vec!["Add a policy rule covering this destination/app/risk combination."],
        ),
        "ATTESTATION_INVALID" => (
            "Attestation verification failed.",
            "The presented attestation's MAC/signature did not match the expected value.",
            vec!["Re-issue the attestation with the correct key."],
        ),
        "NO_VIABLE_ROUTE" => (
            "No viable route exists for this flow.",
            "The route orchestrator could not resolve any adapter for the matched policy action.",
            vec!["Register the missing adapter or fix the policy action."],
        ),
        "UNKNOWN_ADAPTER" => (
            "The referenced adapter is not registered.",
            "Unknown adapters fail closed by design — there is no silent fallback to Direct.",
            vec!["Register the adapter, or fix the adapter id in the policy/config."],
        ),
        "AUDIT_CHAIN_BROKEN" => (
            "The audit hash chain failed integrity verification.",
            "An entry's hash or chain linkage did not match what was recomputed from its contents.",
            vec![
                "Freeze writes and export diagnostics.",
                "Treat the audit trail as untrusted until investigated.",
            ],
        ),
        "FAIL_CLOSED" => (
            "The flow was denied by fail-closed policy.",
            "No rule explicitly allowed this flow, so it was denied rather than silently passed.",
            vec!["Add an explicit policy rule if this traffic should be allowed."],
        ),
        "INSECURE_KEY_REJECTED" => (
            "An all-zero attestation/MAC key was rejected.",
            "Zero keys are reserved for test builds only; production requires a real secret key.",
            vec!["Supply a real, non-zero key from a secret manager."],
        ),
        "KILL_SWITCH_ARMED" => (
            "The daemon is in its fail-closed state and did not deactivate.",
            "After a failed or interrupted activation the daemon stays fail-closed until it is told to let go, so Deactivate refuses unless release_kill_switch=true is passed. This concerns the daemon's own state only: the flag does not reach the firewall kill switch, which the privileged broker owns and the status answer reports separately.",
            vec![
                "Resolve the underlying route or adapter problem and activate again.",
                "Pass release_kill_switch=true to return the daemon to its inactive state.",
            ],
        ),
        DAEMON_BUSY => (
            "The daemon turned the request away because it is busy.",
            "Either an activation is dialing and the request needs the state the dial holds (TraceRoute, GetAuditEntries, VerifyAuditChain), or two requests that change the daemon's state (ActivateProfile, Deactivate) are already in progress. Nothing was changed. GetStatus keeps answering during an activation and reports it as in progress.",
            vec![
                "Retry the request once the activation has finished; a dial is bounded by the daemon's activation deadline.",
                "Use `ssk status` to see whether an activation is in progress.",
            ],
        ),
        INGRESS_DISABLED => (
            "The local proxy is off.",
            "The request was about the local proxy (arming it, disarming it or reading its ledger) and this daemon has no proxy: its configuration section is off, and a build that has no listener yet treats every configuration as off. Nothing was changed, and no listener, record or session was created.",
            vec![
                "Read `ingress.state` in `ssk status`: `disabled` means there is no listener.",
                "Enabling the proxy needs a daemon build that includes it and `ingress.enabled: true` in the configuration, then a restart.",
            ],
        ),
        "DAEMON_TOO_OLD" => (
            "The running daemon is older than this client.",
            "A client that needs a feature checks the IPC protocol the daemon announces in its status before it sends the request. A running sskd keeps executing the binary it was started from, so a daemon that was started before the client was installed still speaks the older protocol. Nothing was sent and nothing was changed.",
            vec![
                "Restart sskd so that it runs the installed binary.",
                "Use `ssk status` to see which protocol the running daemon reports.",
            ],
        ),
        "NETCORE_TIMEOUT" => (
            "A connection attempt timed out.",
            "A TCP connect, a name lookup or a whole dial did not finish within its time limit. The attempt was closed and no direct connection was made instead. An activation is cut at the daemon's own deadline first and reports ACTIVATION_CONNECT_TIMEOUT; this code is for a single connect or lookup that ran out earlier, and for dials the daemon does not bound itself.",
            vec![
                "Check that the host or proxy is reachable and answering.",
                "Retry once it responds.",
            ],
        ),
        "NETCORE_CONNECTION_REFUSED" => (
            "The connection was refused.",
            "The host or proxy answered the TCP connection with a refusal: nothing is listening on that address and port, or something rejected it. Nothing was sent and no direct connection was made instead.",
            vec![
                "Check the adapter's host and port in the configuration.",
                "Start the proxy or correct the address, then retry.",
            ],
        ),
        "NETCORE_DNS_FAILED" => (
            "A host name could not be resolved.",
            "The name of a destination or of an adapter host did not resolve, or the lookup returned no address. Nothing was connected.",
            vec![
                "Check the spelling of the name and the system's name resolution.",
                "Use an IP literal if the address is meant to be fixed.",
            ],
        ),
        "NETCORE_TLS_FAILED" => (
            "A TLS handshake or its setup failed.",
            "The TLS layer of a route could not be established: no trust anchors could be loaded, the client certificate was refused, or the relay's certificate or handshake failed verification. The connection was closed and no direct connection was made instead.",
            vec![
                "Check the relay's certificate and the configured client certificate.",
                "Check that the system trust store can be read.",
            ],
        ),
        "NETCORE_PROXY_REJECTED" => (
            "A proxy refused the request.",
            "The SOCKS5 or HTTP CONNECT proxy was reached but declined to carry the connection, for example because it requires authentication, does not allow the destination or has no route to it. No direct connection was made instead.",
            vec![
                "Check the proxy's credentials and its rules for this destination.",
                "Read the proxy's own log for the reason.",
            ],
        ),
        "NETCORE_UNSUPPORTED_ADAPTER" => (
            "The adapter cannot carry a connection.",
            "The route names an adapter whose kind has no executor, for example a DNS override used as a hop. Selecting it opens no connection and falls back to nothing.",
            vec!["Use SOCKS5, HTTP CONNECT or TLS tunnel adapters as the hops of a route."],
        ),
        "NETCORE_POLICY_DENIED" => (
            "The route was denied by policy.",
            "The planned route is a denial, so the dial was refused before any socket was opened.",
            vec!["Add a policy rule that allows this destination, if it should be reachable."],
        ),
        "NETCORE_NO_ROUTE" => (
            "There is no route that can be dialed.",
            "The route could not be executed: it has no hops, or it is a fallback route, which the daemon never dials because a retry on another route could end in an unintended direct connection.",
            vec!["Fix the profile so that the matching rule names a dialable route."],
        ),
        "NETCORE_UNKNOWN_ADAPTER" => (
            "The route names an adapter that is not registered.",
            "The adapter id of a hop is not in the registry the daemon was started with. There is no fallback to a direct connection.",
            vec![
                "Register the adapter, or fix its id in the rule.",
                "Restart the daemon after editing the configuration.",
            ],
        ),
        "NETCORE_IO_ERROR" => (
            "A network operation failed.",
            "A connect failed for a reason other than a refusal or a timeout (for example the network or host is unreachable), or a read or write on an open connection to a proxy, relay or resolver failed. The connection was closed and no direct connection was made instead.",
            vec![
                "Check the network path to the peer named in the message.",
                "Retry; if it repeats, read the peer's log.",
            ],
        ),
        "NETCORE_PROTOCOL_ERROR" => (
            "A peer answered with something that is not the expected protocol.",
            "The proxy or resolver sent a malformed, truncated or unexpected response during its handshake. The connection was closed.",
            vec!["Check that the configured port belongs to the protocol the adapter says it speaks."],
        ),
        "NETCORE_INVALID_TARGET" => (
            "The destination was refused before anything was sent.",
            "The target host is not an IP address or a resolvable name, or it contains whitespace or a control character that could end a proxy request early. The text is not repeated in the message.",
            vec!["Pass a valid host name or IP address and a nonzero port."],
        ),
        "NETCORE_RESOLVER_BUSY" => (
            "The name resolver had no free slot.",
            "Lookups of destination names are limited in number and in how many may wait. No lookup was started and nothing was connected. Literals and proxied names do not use the resolver.",
            vec!["Retry in a moment; stuck lookups free their slot when the system resolver returns."],
        ),
        "NETCORE_ADDR_REFUSED" => (
            "The address guard refused an address a name resolved to.",
            "When a direct dial is guarded, a name whose answers include an address that must not be dialed is refused as a whole, because a mixed answer is what DNS rebinding looks like. No socket was opened. The message does not repeat the name or the address.",
            vec!["Use a name that resolves only to addresses the daemon may dial."],
        ),
        "NETCORE_FAMILY_DISABLED" => (
            "No address of an enabled address family was available.",
            "Every address of the dial belongs to an address family that is switched off for this executor, so nothing was dialed.",
            vec!["Use a destination that has an address of an enabled family, or change which families the dial may use."],
        ),
        crate::killswitch::KILL_SWITCH_STATUS_UNKNOWN => (
            "The kill-switch state could not be established.",
            "The authoritative kill-switch state lives in the privileged broker, not in this \
             daemon. When the broker cannot be reached, or reports that its journal and the \
             observed OS enforcement disagree, `kill_switch` on the wire falls back to `false` \
             because the field is a bool — and this advisory is what marks that `false` as \
             UNKNOWN rather than OFF. Do not render a reassuring state while it is present.",
            vec![
                "Check that the privileged broker service is installed, running, and reachable.",
                "Re-read status; this condition is transient if the broker simply restarted.",
            ],
        ),
        _ => (
            "Unknown error code.",
            "No explanation is registered for this code.",
            vec!["Check the code for typos or consult the release notes."],
        ),
    };
    ExplainResponse {
        summary: summary.to_string(),
        details: details.to_string(),
        next_steps: next_steps.into_iter().map(str::to_string).collect(),
    }
}

#[cfg(test)]
mod tests {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/support/routing_config.rs"
    ));
    use super::*;
    use ssk_netcore::{AdapterRegistry, NetcoreDataPlane, RouteExecutor};
    use tokio::net::TcpListener;

    fn supervisor_with(data_plane: Box<dyn DataPlane>) -> (Supervisor, tempfile::TempDir) {
        supervisor_with_kill_switch(data_plane, Box::new(crate::killswitch::NoProvider))
    }

    /// The pre-P3 tests in this module are about state transitions, not about
    /// the kill-switch, so they get `NoProvider` — which answers `Unknown`, the
    /// truth for a build with no broker. The kill-switch answer itself is
    /// covered by `tests/kill_switch_status.rs` against a real `Broker`.
    fn supervisor_with_kill_switch(
        data_plane: Box<dyn DataPlane>,
        kill_switch: Box<dyn crate::killswitch::KillSwitchProvider>,
    ) -> (Supervisor, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_path = dir.path().join("audit.json");
        (
            Supervisor::new(audit_path, data_plane, kill_switch, Ok(loopback_config())),
            dir,
        )
    }

    /// A provider that answers a fixed view, so the DTO projection can be
    /// asserted without standing up a broker.
    struct Fixed(KillSwitchView);

    impl crate::killswitch::KillSwitchProvider for Fixed {
        fn view(&self) -> KillSwitchView {
            self.0
        }
    }

    async fn status_of(view: KillSwitchView) -> StatusDto {
        let (sup, _dir) = supervisor_with_kill_switch(real_data_plane(), Box::new(Fixed(view)));
        match call(&sup, Request::GetStatus).await {
            Response::Status(dto) => dto,
            other => panic!("expected a status response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_unknown_kill_switch_never_reaches_the_wire_as_a_bare_false() {
        let dto = status_of(KillSwitchView::Unknown {
            reason: "the privileged broker could not be reached",
        })
        .await;
        assert!(!dto.kill_switch);
        let err = dto
            .last_error
            .expect("an unknown kill-switch must be marked on the wire, not silently rounded off");
        assert_eq!(err.code, crate::killswitch::KILL_SWITCH_STATUS_UNKNOWN);
        assert!(err.message.contains("could not be reached"));
    }

    #[tokio::test]
    async fn a_confirmed_engagement_sets_the_wire_bool_with_no_advisory() {
        let dto = status_of(KillSwitchView::EngagedConfirmed).await;
        assert!(dto.kill_switch);
        assert!(dto.last_error.is_none());
    }

    #[tokio::test]
    async fn a_confirmed_not_engaged_is_a_clean_false() {
        let dto = status_of(KillSwitchView::NotEngaged).await;
        assert!(!dto.kill_switch);
        assert!(
            dto.last_error.is_none(),
            "a definite 'not engaged' must be distinguishable from 'cannot tell'"
        );
    }

    #[tokio::test]
    async fn the_unknown_code_is_explainable() {
        let explained = explain_code(crate::killswitch::KILL_SWITCH_STATUS_UNKNOWN);
        assert!(
            !explained.summary.starts_with("Unknown error code"),
            "a code the daemon emits must have an explanation registered: {explained:?}"
        );
        assert!(!explained.next_steps.is_empty());
    }

    #[tokio::test]
    async fn the_activation_cancelled_code_is_explainable() {
        let explained = explain_code(ACTIVATION_CANCELLED);
        assert!(
            !explained.summary.starts_with("Unknown error code"),
            "a code the daemon emits must have an explanation registered: {explained:?}"
        );
        assert!(!explained.next_steps.is_empty());
    }

    #[tokio::test]
    async fn the_activation_timeout_code_is_explainable() {
        let explained = explain_code(ACTIVATION_CONNECT_TIMEOUT);
        assert!(
            !explained.summary.starts_with("Unknown error code"),
            "a code the daemon emits must have an explanation registered: {explained:?}"
        );
        assert!(!explained.next_steps.is_empty());
    }

    /// The real `ssk-netcore` data plane — no test double remains anywhere
    /// in this module. "Up"/"down" scenarios are produced by pointing it at
    /// a real reachable or real closed local port, never by a hardcoded
    /// bool.
    fn real_data_plane() -> Box<dyn DataPlane> {
        Box::new(NetcoreDataPlane::new(Arc::new(RouteExecutor::new(
            AdapterRegistry::new(),
        ))))
    }

    /// A real, reachable local listener. The caller must keep accepting on
    /// it (or drop it after the exchange) for the real TCP handshake this
    /// test drives to complete.
    async fn reachable_dest() -> (TcpListener, String, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        (listener, "127.0.0.1".to_string(), addr.port())
    }

    /// Reserve the port without listening. Keeping the socket alive prevents
    /// another parallel test from reusing a supposedly closed destination.
    fn unreachable_dest() -> (tokio::net::TcpSocket, String, u16) {
        let socket = tokio::net::TcpSocket::new_v4().expect("socket");
        socket
            .bind("127.0.0.1:0".parse().expect("address"))
            .expect("bind");
        let port = socket.local_addr().expect("addr").port();
        (socket, "127.0.0.1".to_string(), port)
    }

    /// The identity a transport would have verified. Every test drives the
    /// handler as the same-user peer the transport's authentication step is
    /// the only producer of.
    fn test_peer() -> PeerIdentity {
        #[cfg(unix)]
        {
            PeerIdentity::Uid(0)
        }
        #[cfg(not(unix))]
        {
            PeerIdentity::Sid("S-1-5-21-0-0-0-1000".into())
        }
    }

    async fn call(sup: &Supervisor, req: Request) -> Response {
        sup.handle(req, &test_peer()).await
    }

    #[tokio::test]
    async fn activate_with_available_route_reaches_protected() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let (listener, host, port) = reachable_dest().await;
        let accept = tokio::spawn(async move { listener.accept().await });
        let resp = call(
            &sup,
            Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                profile_id: "default".into(),
                dest_host: Some(host),
                dest_port: Some(port),
            }),
        )
        .await;
        match resp {
            Response::Status(status) => {
                assert_eq!(status.state, DaemonState::Protected);
                assert!(
                    status.dns_protected,
                    "127.0.0.1 is a literal IP: no DNS lookup happened"
                );
                assert_eq!(
                    status.adapters.len(),
                    1,
                    "must report the one real adapter traversed"
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert_eq!(sup.current_state().await, DaemonState::Protected);
        accept.await.expect("join").expect("accept");
    }

    /// Nothing re-checks a held session after activation: the daemon never
    /// probes it and never reads from it, so "live" was a claim no code backed.
    /// The health string may say only what activation established.
    #[tokio::test]
    async fn adapter_health_claims_only_what_activation_established() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let (listener, host, port) = reachable_dest().await;
        let accept = tokio::spawn(async move { listener.accept().await });
        let resp = call(
            &sup,
            Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                profile_id: "default".into(),
                dest_host: Some(host),
                dest_port: Some(port),
            }),
        )
        .await;
        match resp {
            Response::Status(status) => {
                assert_eq!(status.state, DaemonState::Protected);
                let health: Vec<_> = status.adapters.iter().map(|a| a.health.as_str()).collect();
                assert_eq!(health, ["connected at activation; liveness not monitored"]);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        accept.await.expect("join").expect("accept");
    }

    /// A timed-out status read is answered without the mutex only when an
    /// activation is the reason for the wait. Any other holder keeps the old
    /// behaviour: wait, then read the live state. A cached `Protected` served
    /// while some other handler is mid-change would be a claim nobody holds.
    #[tokio::test]
    async fn status_keeps_waiting_when_the_lock_is_held_by_something_else() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let sup = Arc::new(sup);
        let (listener, host, port) = reachable_dest().await;
        let accept = tokio::spawn(async move { listener.accept().await });
        call(
            &sup,
            Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                profile_id: "default".into(),
                dest_host: Some(host),
                dest_port: Some(port),
            }),
        )
        .await;
        accept.await.expect("join").expect("accept");
        assert_eq!(sup.current_state().await, DaemonState::Protected);

        // Stands in for any non-activation handler that holds the mutex.
        let mut other_handler = sup.inner.lock().await;
        let asker = {
            let sup = Arc::clone(&sup);
            tokio::spawn(async move { call(&sup, Request::GetStatus).await })
        };
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(
            !asker.is_finished(),
            "with no activation in flight GetStatus must wait for the lock, not answer"
        );
        other_handler
            .state
            .transition(DaemonState::Degraded, "changed while status waited");
        drop(other_handler);

        match tokio::time::timeout(Duration::from_secs(5), asker)
            .await
            .expect("status answers once the lock is free")
            .expect("join")
        {
            Response::Status(status) => assert_eq!(
                status.state,
                DaemonState::Degraded,
                "the answer must be the live state read under the lock"
            ),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn activate_with_no_route_fails_closed() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let (_reserved, host, port) = unreachable_dest();
        let resp = call(
            &sup,
            Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                profile_id: "default".into(),
                dest_host: Some(host),
                dest_port: Some(port),
            }),
        )
        .await;
        match resp {
            Response::Status(status) => assert_eq!(status.state, DaemonState::FailClosed),
            other => panic!("unexpected response: {other:?}"),
        }
        let inner = sup.inner.lock().await;
        let entries = inner.audit.entries().expect("persisted failed attempt");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].outcome, AuditOutcome::DispatchPending);
        assert_eq!(entries[1].outcome, AuditOutcome::FailClosed);
    }

    #[tokio::test]
    async fn activate_without_a_destination_fails_closed_with_a_clear_reason() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let resp = call(
            &sup,
            Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                profile_id: "default".into(),
                dest_host: None,
                dest_port: None,
            }),
        )
        .await;
        match resp {
            Response::Err(err) => assert_eq!(err.code, "DEST_REQUIRED"),
            other => panic!("unexpected response: {other:?}"),
        }
        assert_eq!(
            sup.current_state().await,
            DaemonState::FailClosed,
            "must never report Protected/Active with nothing to protect"
        );
    }

    /// `127.1` is 127.0.0.1 to the OS resolver but a name to a label grammar.
    /// The activation destination obeys the same host grammar as the
    /// configuration, so it is refused up front: nothing is recorded or dialled.
    #[tokio::test]
    async fn activate_refuses_a_numeric_alias_destination_before_any_dial() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let before = audit_entry_count(&sup).await;
        for host in ["127.1", "0x7f.0.0.1", "2130706433"] {
            let resp = call(
                &sup,
                Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                    profile_id: "default".into(),
                    dest_host: Some(host.into()),
                    dest_port: Some(80),
                }),
            )
            .await;
            match resp {
                Response::Err(err) => assert_eq!(err.code, "DEST_INVALID", "{host}"),
                other => panic!("{host} must be refused as invalid, got: {other:?}"),
            }
        }
        assert_eq!(audit_entry_count(&sup).await, before);
    }

    #[tokio::test]
    async fn deactivate_requires_kill_switch_release_when_fail_closed() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let (_reserved, host, port) = unreachable_dest();
        call(
            &sup,
            Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                profile_id: "default".into(),
                dest_host: Some(host),
                dest_port: Some(port),
            }),
        )
        .await;
        let resp = call(
            &sup,
            Request::Deactivate(ssk_ipc::DeactivateRequest {
                release_kill_switch: false,
            }),
        )
        .await;
        assert!(matches!(resp, Response::Err(_)));
        assert_eq!(sup.current_state().await, DaemonState::FailClosed);

        let resp = call(
            &sup,
            Request::Deactivate(ssk_ipc::DeactivateRequest {
                release_kill_switch: true,
            }),
        )
        .await;
        match resp {
            Response::Status(status) => assert_eq!(status.state, DaemonState::Inactive),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_status_reflects_current_state() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let resp = call(&sup, Request::GetStatus).await;
        match resp {
            Response::Status(status) => assert_eq!(status.state, DaemonState::Inactive),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    /// Every status says which IPC protocol this daemon speaks and carries an
    /// ingress block. While no listener exists the block says so, and it is
    /// still present: `None` would mean "a daemon that predates the proxy", which
    /// is the one thing this build is not. Nothing in it claims coverage.
    #[tokio::test]
    async fn status_reports_protocol_and_a_disabled_ingress_block() {
        fn assert_disabled(status: &StatusDto, what: &str) {
            assert_eq!(status.protocol, ssk_ipc::IPC_PROTOCOL_VERSION, "{what}");
            let ingress = status
                .ingress
                .as_ref()
                .unwrap_or_else(|| panic!("{what}: a daemon of this build never answers None"));
            assert_eq!(ingress.state, "disabled", "{what}");
            assert_eq!(ingress.coverage, "none", "{what}");
            assert!(!ingress.system_wide, "{what}");
            assert!(
                ingress.listen.is_none() && ingress.armed_profile.is_none(),
                "{what}"
            );
            assert_eq!(
                ingress.counters.admitted + ingress.counters.denied,
                0,
                "{what}"
            );
            assert!(ingress.last_error.is_none(), "{what}");
            // The notice is the one fixed sentence, and it is none of the
            // claims the proxy must never make (design 10.7).
            assert_eq!(ingress.notice, INGRESS_COVERAGE_NOTICE, "{what}");
            let notice = ingress.notice.to_lowercase();
            for word in [
                "protected",
                "protection",
                "secure",
                "system-wide",
                "system wide",
                "all traffic",
                "vpn",
                "tunnel",
                "anonym",
            ] {
                assert!(!notice.contains(word), "{what}: the notice says `{word}`");
            }
        }

        let (sup, _dir) = supervisor_with(real_data_plane());
        match call(&sup, Request::GetStatus).await {
            Response::Status(status) => assert_disabled(&status, "idle"),
            other => panic!("unexpected response: {other:?}"),
        }

        // A daemon whose configuration is invalid still answers the block: the
        // proxy is as off there as anywhere.
        let dir = tempfile::tempdir().expect("tempdir");
        let invalid = Supervisor::new(
            dir.path().join("audit.json"),
            real_data_plane(),
            Box::new(crate::killswitch::NoProvider),
            Err(DaemonConfigError::UnknownFormat("daemon.ini".into())),
        );
        match call(&invalid, Request::GetStatus).await {
            Response::Status(status) => {
                assert_eq!(status.state, DaemonState::ConfigInvalid);
                assert_disabled(&status, "config invalid");
            }
            other => panic!("unexpected response: {other:?}"),
        }

        // And so does the answer built around an activation dial, which is a
        // different literal.
        assert_disabled(&activating_status(KillSwitchView::NotEngaged), "activating");
        assert_eq!(
            activating_status(KillSwitchView::NotEngaged).state,
            DaemonState::Activating
        );
    }

    /// The request that would arm or disarm the proxy, and the one that would
    /// read its ledger, are refused while there is no proxy: with a code that
    /// says so, no change, no ledger entry and no state change.
    #[tokio::test]
    async fn set_ingress_is_refused_while_the_section_is_off() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let before = audit_entry_count(&sup).await;

        for armed in [true, false] {
            let request = Request::SetIngress(ssk_ipc::SetIngressRequest {
                armed,
                profile_id: None,
                client: Some("cli".into()),
                expect_profile: None,
                expect_routing_digest: None,
            });
            match call(&sup, request).await {
                Response::Err(error) => {
                    assert_eq!(error.code, INGRESS_DISABLED, "armed = {armed}");
                    assert_eq!(error.class, "Config");
                    assert!(!error.retriable, "the proxy does not appear by retrying");
                    assert!(
                        error.message.contains("nothing was changed"),
                        "{}",
                        error.message
                    );
                }
                other => panic!("armed = {armed}: a refusal was expected, got {other:?}"),
            }
        }
        match call(
            &sup,
            Request::GetIngressAudit {
                limit: 10,
                before_seq: None,
                verify: false,
            },
        )
        .await
        {
            Response::Err(error) => assert_eq!(error.code, INGRESS_DISABLED),
            other => panic!("there is no ingress ledger to read: {other:?}"),
        }

        // Nothing moved: the same state, the same block, no new ledger entry.
        assert_eq!(sup.current_state().await, DaemonState::Inactive);
        assert_eq!(audit_entry_count(&sup).await, before);
        match call(&sup, Request::GetStatus).await {
            Response::Status(status) => {
                assert_eq!(status.ingress.expect("a block").state, "disabled");
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    /// A code this daemon puts on the wire is one `ssk explain` can say
    /// something about, and a client that learns `DAEMON_TOO_OLD` can look it up
    /// in a daemon that is new enough to know it.
    #[test]
    fn the_codes_of_the_wire_additions_are_explainable() {
        for code in [INGRESS_DISABLED, "DAEMON_TOO_OLD"] {
            let explained = explain_code(code);
            assert!(
                !explained.summary.starts_with("Unknown error code"),
                "{code} has no explanation: {explained:?}"
            );
            assert!(!explained.next_steps.is_empty(), "{code}");
        }
    }

    /// The preview names the profile and the flow context it was computed for
    /// (design 11.7). Only the legacy evaluation exists, so that is what it says.
    #[tokio::test]
    async fn trace_route_reports_the_profile_it_used_and_how_it_chose_it() {
        let trace = |app_id: Option<&str>| {
            Request::TraceRoute(ssk_ipc::RouteTraceRequest {
                app_id: app_id.map(str::to_string),
                dest_host: "127.0.0.1".into(),
                dest_port: 443,
                protocol: "tcp".into(),
                risk: "low".into(),
                profile_id: None,
            })
        };
        let (sup, _dir) = supervisor_with(real_data_plane());
        match call(&sup, trace(None)).await {
            Response::RouteTrace(answer) => {
                assert_eq!(answer.profile_used.as_deref(), Some("default"));
                assert_eq!(answer.profile_source.as_deref(), Some("default_profile"));
                assert_eq!(answer.evaluated_as.as_deref(), Some("legacy_activation"));
                assert_eq!(answer.app_id_used.as_deref(), Some("unknown-app"));
                assert_eq!(answer.refusal, None);
                assert!(answer.guards_skipped.is_empty());
            }
            other => panic!("unexpected response: {other:?}"),
        }

        sup.inner.lock().await.active_profile = Some("default".into());
        match call(&sup, trace(Some("browser"))).await {
            Response::RouteTrace(answer) => {
                assert_eq!(answer.profile_used.as_deref(), Some("default"));
                assert_eq!(answer.profile_source.as_deref(), Some("active_session"));
                assert_eq!(answer.app_id_used.as_deref(), Some("browser"));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn audit_chain_verifies_after_activation_and_is_not_vacuous() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let (listener, host, port) = reachable_dest().await;
        let accept = tokio::spawn(async move { listener.accept().await });
        call(
            &sup,
            Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                profile_id: "default".into(),
                dest_host: Some(host),
                dest_port: Some(port),
            }),
        )
        .await;
        let resp = call(&sup, Request::VerifyAuditChain).await;
        match resp {
            Response::AuditVerify(v) => {
                assert!(v.ok);
                assert!(
                    v.head.is_some(),
                    "a real activation must append a real audit entry, not verify an empty chain"
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
        accept.await.expect("join").expect("accept");
    }

    #[tokio::test]
    async fn run_doctor_reports_real_checks() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let resp = call(&sup, Request::RunDoctor).await;
        match resp {
            Response::Doctor(report) => {
                assert!(report.checks.iter().any(|c| c.name == "system_clock"));
                assert!(report.checks.iter().all(|c| c.ok));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    async fn audit_entry_count(sup: &Supervisor) -> usize {
        match call(sup, Request::GetAuditEntries { limit: usize::MAX }).await {
            Response::AuditEntries(entries) => entries.len(),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    /// The literal defect an auditor demonstrated: `activate` of a profile
    /// that does not exist returned `Protected` and appended a hash-chained
    /// audit entry, so the ledger cryptographically attested to protection
    /// that never existed.
    #[tokio::test]
    async fn activating_an_unknown_profile_is_refused_and_appends_no_audit_entry() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let (listener, host, port) = reachable_dest().await;
        let before = audit_entry_count(&sup).await;

        let resp = call(
            &sup,
            Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                profile_id: "totally-made-up-profile".into(),
                dest_host: Some(host),
                dest_port: Some(port),
            }),
        )
        .await;

        match resp {
            Response::Err(err) => {
                assert_eq!(err.code, "UNKNOWN_PROFILE");
                assert_eq!(err.class, "Usage");
                assert!(!err.retriable, "an unknown profile will not become known");
                assert!(
                    err.message.contains("default"),
                    "the error must name the known profiles: {}",
                    err.message
                );
            }
            other => panic!("an unknown profile must be refused, got: {other:?}"),
        }

        assert_eq!(
            audit_entry_count(&sup).await,
            before,
            "the ledger must not attest to a profile that does not exist"
        );
        assert!(
            !matches!(
                call(&sup, Request::VerifyAuditChain).await,
                Response::AuditVerify(v) if !v.ok
            ),
            "the chain must still verify"
        );
        drop(listener);
    }

    /// A rejected *request* is not a degraded *posture*. If it were, any
    /// unauthenticated peer could block the daemon with one garbage string.
    #[tokio::test]
    async fn an_unknown_profile_does_not_move_the_daemon_to_fail_closed() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        assert_eq!(sup.current_state().await, DaemonState::Inactive);
        call(
            &sup,
            Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                profile_id: "nope".into(),
                dest_host: Some("127.0.0.1".into()),
                dest_port: Some(9),
            }),
        )
        .await;
        assert_eq!(
            sup.current_state().await,
            DaemonState::Inactive,
            "a malformed request must not be able to drive the protection posture"
        );
    }

    #[tokio::test]
    async fn an_unknown_profile_emits_an_observable_warning() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let mut events = sup.subscribe_events().await;
        call(
            &sup,
            Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                profile_id: "nope".into(),
                dest_host: Some("127.0.0.1".into()),
                dest_port: Some(9),
            }),
        )
        .await;
        match events.recv().await.expect("event") {
            ssk_ipc::Event::Warning { code, .. } => assert_eq!(code, "UNKNOWN_PROFILE"),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_malformed_profile_id_is_refused_before_it_reaches_a_flow_id() {
        // Shape rejection is distinct from set rejection, and it runs first so
        // arbitrary bytes never reach a log line, a flow id or the ledger.
        let cases = [
            "",
            "UPPERCASE",
            "has space",
            "semi;colon",
            "new\nline",
            "../../etc/passwd",
            "ünïcøde",
        ];
        for case in cases {
            let (sup, _dir) = supervisor_with(real_data_plane());
            let before = audit_entry_count(&sup).await;
            let resp = call(
                &sup,
                Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                    profile_id: case.into(),
                    dest_host: Some("127.0.0.1".into()),
                    dest_port: Some(9),
                }),
            )
            .await;
            match resp {
                Response::Err(err) => assert_eq!(
                    err.code, "PROFILE_ID_INVALID",
                    "`{case}` must be refused on shape"
                ),
                other => panic!("`{case}` must be refused, got: {other:?}"),
            }
            assert_eq!(audit_entry_count(&sup).await, before);
            assert_eq!(sup.current_state().await, DaemonState::Inactive);
        }
    }

    #[tokio::test]
    async fn an_overlong_profile_id_is_refused() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let resp = call(
            &sup,
            Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                profile_id: "a".repeat(MAX_PROFILE_ID_LEN + 1),
                dest_host: Some("127.0.0.1".into()),
                dest_port: Some(9),
            }),
        )
        .await;
        match resp {
            Response::Err(err) => assert_eq!(err.code, "PROFILE_ID_INVALID"),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    /// The invariant, quantified over the registry: `activate(p)` may succeed
    /// only for `p ∈ list_profiles()`. When Phase 5 replaces the constant
    /// registry with a config-driven one, this inherits the guarantee.
    #[tokio::test]
    async fn activate_succeeds_only_for_ids_that_list_profiles_reports() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let listed = match call(&sup, Request::ListProfiles).await {
            Response::Profiles(p) => p,
            other => panic!("unexpected response: {other:?}"),
        };
        assert!(
            !listed.is_empty(),
            "the registry must not be vacuously empty"
        );

        for profile in &listed {
            assert!(
                validate_profile_id(&profile.id, &listed).is_ok(),
                "`{}` is listed, so it must be activatable",
                profile.id
            );
        }
        for candidate in ["default-", "defaul", "defaultx", "other", "profile.1"] {
            let is_listed = listed.iter().any(|p| p.id == candidate);
            assert_eq!(
                validate_profile_id(candidate, &listed).is_ok(),
                is_listed,
                "`{candidate}` must be activatable exactly when it is listed"
            );
        }
    }

    #[tokio::test]
    async fn list_profiles_and_the_validator_share_one_registry() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        match call(&sup, Request::ListProfiles).await {
            Response::Profiles(p) => {
                let ids: Vec<_> = p.iter().map(|x| x.id.clone()).collect();
                let known: Vec<_> = sup
                    .routing()
                    .profiles()
                    .iter()
                    .map(|x| x.id.clone())
                    .collect();
                assert_eq!(ids, known);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    /// The whole point of `from_parts`: the planner the caller compiled once is
    /// the planner the supervisor uses, and the data plane it was given is the
    /// one an activation dials through. Neither is rebuilt or copied.
    #[tokio::test]
    async fn from_parts_shares_the_routing_and_data_plane_it_is_given() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = loopback_config();
        let routing = Arc::new(ConfiguredRouting::new(&config.config.routing));
        let data_plane: Arc<dyn DataPlane> = Arc::from(real_data_plane());
        let sup = Supervisor::from_parts(
            dir.path().join("audit.json"),
            Arc::clone(&routing),
            Arc::clone(&data_plane),
            Box::new(crate::killswitch::NoProvider),
            Ok(config),
        );
        assert!(Arc::ptr_eq(sup.routing(), &routing));
        assert!(Arc::ptr_eq(sup.data_plane(), &data_plane));
    }

    /// A routing that does not match the supervisor's own configuration is not
    /// something a caller should build, but it is the one way to make the
    /// planner fail with a validated config, and it shows which routing an
    /// activation really consults: the supervisor's own would plan `Direct` for
    /// this destination and connect.
    fn redirecting_loopback_to(adapter: &str, registered: bool) -> Arc<ConfiguredRouting> {
        use ssk_config::routing::{AdapterTransport, RoutingAction, RoutingAdapter};
        let mut routing = loopback_config().config.routing;
        routing.profiles[0].rules[0].action = RoutingAction::Adapter {
            adapter_id: adapter.into(),
        };
        if registered {
            routing.adapters.push(RoutingAdapter {
                id: adapter.into(),
                transport: AdapterTransport::Socks5 {
                    host: "127.0.0.1".into(),
                    port: 9,
                },
            });
        }
        Arc::new(ConfiguredRouting::new(&routing))
    }

    fn supervisor_over(routing: Arc<ConfiguredRouting>) -> (Supervisor, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let sup = Supervisor::from_parts(
            dir.path().join("audit.json"),
            routing,
            Arc::from(real_data_plane()),
            Box::new(crate::killswitch::NoProvider),
            Ok(loopback_config()),
        );
        (sup, dir)
    }

    #[tokio::test]
    async fn an_activation_that_cannot_be_planned_fails_closed_before_it_records_or_dials() {
        let (sup, _dir) = supervisor_over(redirecting_loopback_to("absent", false));
        let mut events = sup.subscribe_events().await;
        let (listener, host, port) = reachable_dest().await;
        let resp = call(
            &sup,
            Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                profile_id: "default".into(),
                dest_host: Some(host),
                dest_port: Some(port),
            }),
        )
        .await;
        match resp {
            Response::Err(err) => assert_eq!(err.code, "UNKNOWN_ADAPTER"),
            other => panic!("an unplannable route must be refused, got: {other:?}"),
        }
        assert_eq!(sup.current_state().await, DaemonState::FailClosed);
        assert_eq!(
            audit_entry_count(&sup).await,
            0,
            "planning fails before any intent is written"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "nothing may be dialled for a route that could not be planned"
        );
        let mut reason = None;
        while let Ok(event) = events.try_recv() {
            if let ssk_ipc::Event::StateChanged {
                to: DaemonState::FailClosed,
                reason: why,
                ..
            } = event
            {
                reason = Some(why);
            }
        }
        assert_eq!(
            reason.as_deref(),
            Some("route planning failed: control plane: unknown adapter `absent`")
        );
    }

    #[tokio::test]
    async fn trace_route_plans_with_the_routing_the_supervisor_was_given() {
        let (sup, _dir) = supervisor_over(redirecting_loopback_to("given-exit", true));
        let resp = call(
            &sup,
            Request::TraceRoute(ssk_ipc::RouteTraceRequest {
                app_id: None,
                dest_host: "127.0.0.1".into(),
                dest_port: 443,
                protocol: "tcp".into(),
                risk: "low".into(),
                profile_id: None,
            }),
        )
        .await;
        match resp {
            Response::RouteTrace(trace) => {
                assert_eq!(trace.hops, ["given-exit"]);
                assert!(matches!(trace.route, RouteKind::SingleHop(_)));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    /// `TraceRoute` takes its profile from `active_profile`, which the
    /// activation arm only ever sets to a validated id, so a profile the
    /// registry does not know is not reachable through the wire. Should it ever
    /// be reached anyway, the answer is an error, never a panic in a handler
    /// that holds the supervisor lock.
    #[tokio::test]
    async fn trace_route_with_an_unconfigured_active_profile_is_an_error_not_a_panic() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        sup.inner.lock().await.active_profile = Some("ghost".into());
        let resp = call(
            &sup,
            Request::TraceRoute(ssk_ipc::RouteTraceRequest {
                app_id: None,
                dest_host: "127.0.0.1".into(),
                dest_port: 443,
                protocol: "tcp".into(),
                risk: "low".into(),
                profile_id: None,
            }),
        )
        .await;
        match resp {
            Response::Err(err) => assert_eq!(err.code, "UNKNOWN_PROFILE"),
            other => panic!("an unknown profile must be an error, got: {other:?}"),
        }
    }

    #[test]
    fn the_doctor_entropy_check_no_longer_names_a_unix_device() {
        let checks = run_doctor_checks();
        let entropy = checks
            .iter()
            .find(|c| c.name == "entropy")
            .expect("an entropy check must exist");
        assert!(
            !entropy.detail.contains("/dev/urandom"),
            "{}",
            entropy.detail
        );
        assert!(entropy.ok, "{}", entropy.detail);
    }

    #[test]
    fn the_doctor_paths_check_reports_the_state_directory_not_the_cwd() {
        let checks = run_doctor_checks();
        let paths = checks
            .iter()
            .find(|c| c.name == "paths")
            .expect("a paths check must exist");
        assert!(paths.detail.contains("state directory"), "{}", paths.detail);
    }

    /// The intent an abandoned activation still owes a result to must be the
    /// unfinished one and nothing older: a written result, a refusal and a new
    /// intent each replace it.
    #[tokio::test]
    async fn the_pending_activation_names_only_the_unfinished_intent() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let mut inner = sup.inner.lock().await;
        let route = RouteKind::Direct;
        assert!(inner.pending_activation.is_none());

        inner
            .record_activation("flow-1", &route, AuditOutcome::DispatchPending)
            .expect("intent");
        assert_eq!(
            inner.pending_activation,
            Some(("flow-1".to_string(), route.clone()))
        );
        inner
            .record_activation("flow-1", &route, AuditOutcome::FailClosed)
            .expect("result");
        assert!(inner.pending_activation.is_none(), "the result ends it");

        inner
            .record_activation("flow-2", &route, AuditOutcome::DispatchPending)
            .expect("intent");
        inner.refuse_activation(IpcError::new("Integrity", "LEDGER_IO_FAILED", "disk full"));
        assert!(
            inner.pending_activation.is_none(),
            "a refusal ends the activation even when its result was never written"
        );
    }

    /// A marker that outlived its request would answer `Activating` for ever,
    /// so every way out of the request must lower it, and one request leaving
    /// must not hide another that is still in flight.
    #[tokio::test]
    async fn the_in_flight_marker_clears_on_every_exit_path() {
        let marker = ActivationsInFlight::default();
        assert!(!marker.any());

        drop(marker.enter());
        assert!(!marker.any(), "normal exit");

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = marker.enter();
            panic!("a handler panicked mid-activation");
        }));
        assert!(panicked.is_err());
        assert!(!marker.any(), "unwinding");

        let cancelled = tokio::time::timeout(Duration::from_millis(20), async {
            let _guard = marker.enter();
            std::future::pending::<()>().await;
        })
        .await;
        assert!(cancelled.is_err(), "the pending future was cancelled");
        assert!(!marker.any(), "cancellation drops the future's locals");

        let first = marker.enter();
        let second = marker.enter();
        drop(first);
        assert!(marker.any(), "the second request is still in flight");
        drop(second);
        assert!(!marker.any());
    }

    /// The marker is raised before the request awaits `Inner`, because the
    /// mutex is what a status read cannot wait for. An activation that has
    /// been accepted but is still queued behind another holder is therefore
    /// already visible, and cancelling it while queued leaves no trace.
    #[tokio::test]
    async fn an_activation_queued_for_the_lock_is_already_in_flight() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let sup = Arc::new(sup);
        let other_handler = sup.inner.lock().await;
        let activation = {
            let sup = Arc::clone(&sup);
            tokio::spawn(async move {
                call(
                    &sup,
                    Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                        profile_id: "default".into(),
                        dest_host: Some("127.0.0.1".into()),
                        dest_port: Some(9),
                    }),
                )
                .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            while !sup.activations.any() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the request must be marked before it gets the lock");

        match tokio::time::timeout(Duration::from_secs(1), call(&sup, Request::GetStatus))
            .await
            .expect("status must answer around a queued activation")
        {
            Response::Status(status) => assert_eq!(status.state, DaemonState::Activating),
            other => panic!("unexpected response: {other:?}"),
        }

        activation.abort();
        assert!(activation.await.expect_err("aborted").is_cancelled());
        assert!(
            !sup.activations.any(),
            "an activation cancelled while queued must not stay in flight"
        );
        drop(other_handler);
        assert_eq!(
            sup.current_state().await,
            DaemonState::Inactive,
            "the cancelled activation never ran, so it changed nothing"
        );
    }

    #[tokio::test]
    async fn record_task_failure_moves_to_fail_closed_when_inactive() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        sup.record_task_failure("activation task panicked").await;
        assert_eq!(sup.current_state().await, DaemonState::FailClosed);
    }

    #[tokio::test]
    async fn record_task_failure_moves_to_degraded_when_active() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let (listener, host, port) = reachable_dest().await;
        let accept = tokio::spawn(async move { listener.accept().await });
        call(
            &sup,
            Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                profile_id: "default".into(),
                dest_host: Some(host),
                dest_port: Some(port),
            }),
        )
        .await;
        sup.record_task_failure("adapter task panicked").await;
        assert_eq!(sup.current_state().await, DaemonState::Degraded);
        accept.await.expect("join").expect("accept");
    }

    /// The shutdown of a held session runs while `Inner` is held, so it must end
    /// by a deadline of the daemon's own. A peer that never reads leaves a TLS
    /// `close_notify` unwritten for ever; the answer is to stop waiting and let
    /// the caller drop the transport, which closes it.
    #[tokio::test]
    async fn close_bounded_gives_up_after_the_bound() {
        let bound = Duration::from_millis(50);
        let started = std::time::Instant::now();
        assert!(
            !finishes_within(bound, std::future::pending::<std::io::Result<()>>()).await,
            "a shutdown that never finishes must be given up on"
        );
        assert!(started.elapsed() >= bound, "gave up before the bound");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "did not give up at the bound: {:?}",
            started.elapsed()
        );

        // A shutdown that ends in time is not cut, whether or not it succeeded:
        // either way the caller drops the session next.
        assert!(finishes_within(Duration::from_secs(5), async { Ok(()) }).await);
        assert!(
            finishes_within(Duration::from_secs(5), async {
                Err(std::io::Error::other("peer reset"))
            })
            .await
        );

        // The bound `close_bounded` really passes stays under the desktop
        // client's 2 s read deadline, or a status behind it would not be seen.
        assert!(SESSION_SHUTDOWN_BOUND < Duration::from_secs(2));
    }

    /// `Inner` is held while a session shuts down, so a second, unbounded call
    /// site would put the mutex back in the hands of the slowest peer.
    #[test]
    fn session_shutdown_is_only_called_through_close_bounded() {
        let source = include_str!("supervisor.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("the file has a production part");
        let calls: Vec<&str> = production
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("//") && line.contains(".shutdown()"))
            .collect();
        assert_eq!(
            calls,
            ["if !finishes_within(SESSION_SHUTDOWN_BOUND, session.shutdown()).await {"],
            "a held session must only be shut down through `close_bounded`"
        );
    }

    /// The mutex wait of a reader is what it was for `GetStatus`: a holder that
    /// is not an activation is waited for, and the wait that already ran out is
    /// not given back, or a reader would queue behind everyone who arrived while
    /// it was deciding.
    #[tokio::test]
    async fn inner_unless_activating_waits_for_a_short_holder_and_keeps_its_place() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let sup = Arc::new(sup);
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));

        let holder = sup.inner.lock().await;
        let reader = {
            let (sup, order) = (Arc::clone(&sup), Arc::clone(&order));
            tokio::spawn(async move {
                match sup.inner_unless_activating().await {
                    InnerAccess::Held(_inner) => order.lock().expect("order").push("reader"),
                    InnerAccess::ActivationInFlight => {
                        order.lock().expect("order").push("reader-busy")
                    }
                }
            })
        };
        // Queues up while the reader is still inside its own wait. A reader
        // that gave up its place at the end of that wait and queued again would
        // land behind this one.
        tokio::time::sleep(STATUS_LOCK_WAIT / 3).await;
        let latecomer = {
            let (sup, order) = (Arc::clone(&sup), Arc::clone(&order));
            tokio::spawn(async move {
                let _inner = sup.inner.lock().await;
                order.lock().expect("order").push("latecomer");
            })
        };
        // Past the reader's wait, so it has stopped waiting for the mutex to
        // free up on its own and now waits for the holder.
        tokio::time::sleep(STATUS_LOCK_WAIT * 2).await;
        assert!(
            order.lock().expect("order").is_empty(),
            "nobody may get past a short holder"
        );
        drop(holder);

        reader.await.expect("reader");
        latecomer.await.expect("latecomer");
        assert_eq!(*order.lock().expect("order"), ["reader", "latecomer"]);
    }

    /// With an activation in flight the same wait ends in an answer around it,
    /// after the lock wait and not before.
    #[tokio::test]
    async fn inner_unless_activating_answers_around_an_activation() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        assert!(
            matches!(sup.inner_unless_activating().await, InnerAccess::Held(_)),
            "a free mutex is just taken"
        );

        let _dial = sup.inner.lock().await;
        let _in_flight = sup.activations.enter();
        let started = std::time::Instant::now();
        assert!(matches!(
            sup.inner_unless_activating().await,
            InnerAccess::ActivationInFlight
        ));
        assert!(
            started.elapsed() >= STATUS_LOCK_WAIT,
            "the mutex is given its wait first"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// A mutating request that is cancelled (its client left, the task was
    /// aborted) must give its slot back, or two disconnects would leave the
    /// daemon refusing every activation for ever.
    #[tokio::test]
    async fn a_cancelled_mutator_gives_its_slot_back() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let sup = Arc::new(sup);
        let other_handler = sup.inner.lock().await;
        let queued = [
            Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                profile_id: "default".into(),
                dest_host: Some("127.0.0.1".into()),
                dest_port: Some(9),
            }),
            Request::Deactivate(ssk_ipc::DeactivateRequest {
                release_kill_switch: true,
            }),
        ]
        .map(|request| {
            let sup = Arc::clone(&sup);
            tokio::spawn(async move { call(&sup, request).await })
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while sup.mutators.available_permits() > 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both requests must take a slot");

        match call(
            &sup,
            Request::Deactivate(ssk_ipc::DeactivateRequest {
                release_kill_switch: true,
            }),
        )
        .await
        {
            Response::Err(error) => assert_eq!(error.code, DAEMON_BUSY),
            other => panic!("a third mutator must be refused, got: {other:?}"),
        }

        for task in queued {
            task.abort();
            assert!(task.await.expect_err("aborted").is_cancelled());
        }
        assert_eq!(sup.mutators.available_permits(), MAX_MUTATORS);
        drop(other_handler);
    }

    #[tokio::test]
    async fn the_daemon_busy_code_is_explainable() {
        let explained = explain_code(DAEMON_BUSY);
        assert!(
            !explained.summary.starts_with("Unknown error code"),
            "a code the daemon emits must have an explanation registered: {explained:?}"
        );
        assert!(!explained.next_steps.is_empty());
        assert!(busy_during_activation().retriable && busy_mutators().retriable);
        assert_eq!(busy_during_activation().code, DAEMON_BUSY);
        assert_eq!(busy_mutators().code, DAEMON_BUSY);
    }

    /// Every code a failed dial can put into a status is one `ssk explain` can
    /// say something about. The `match` has no wildcard, so a new `NetcoreError`
    /// variant does not compile here until it is listed, and the list is then
    /// checked against the variants it must cover.
    #[test]
    fn every_netcore_code_is_explainable() {
        use ssk_netadmin::adapter::AdapterKind;
        use ssk_netcore::{DialAttempts, NetcoreError as E};

        const VARIANTS: usize = 17;
        fn index(error: &E) -> usize {
            match error {
                E::OpenVpnNotReady(_) => 0,
                E::Timeout(..) => 1,
                E::ConnectionRefused(..) => 2,
                E::DnsResolutionFailed(..) => 3,
                E::TlsHandshakeFailed(..) => 4,
                E::ProxyRejected(..) => 5,
                E::Unsupported(_) => 6,
                E::PolicyDenied(_) => 7,
                E::NoRoute(_) => 8,
                E::UnknownAdapter(_) => 9,
                E::Io(..) => 10,
                E::ProtocolError(..) => 11,
                E::InvalidTarget(_) => 12,
                E::ResolverBusy => 13,
                E::AddressRefused { .. } => 14,
                E::FamilyDisabled => 15,
                E::DialFailed { .. } => 16,
            }
        }
        let one_of_each = vec![
            E::OpenVpnNotReady("p".into()),
            E::Timeout("h:1".into(), Duration::from_secs(1)),
            E::ConnectionRefused("h:1".into(), "refused".into()),
            E::DnsResolutionFailed("h".into(), "os-resolver".into(), "no addresses".into()),
            E::TlsHandshakeFailed("relay".into(), "bad certificate".into()),
            E::ProxyRejected("proxy".into(), "denied".into()),
            E::Unsupported(AdapterKind::DnsOverride),
            E::PolicyDenied("no rule".into()),
            E::NoRoute("empty hop chain".into()),
            E::UnknownAdapter("a".into()),
            E::Io("h:1".into(), std::io::Error::other("unreachable")),
            E::ProtocolError("proxy".into(), "short reply".into()),
            E::InvalidTarget("not a host".into()),
            E::ResolverBusy,
            E::AddressRefused {
                code: "loopback",
                refused: 1,
                answers: 1,
            },
            E::FamilyDisabled,
            E::DialFailed {
                source: Box::new(E::ResolverBusy),
                attempts: DialAttempts {
                    answers: 0,
                    attempted: Vec::new(),
                },
            },
        ];
        let mut covered: Vec<usize> = one_of_each.iter().map(index).collect();
        covered.sort_unstable();
        assert_eq!(
            covered,
            (0..VARIANTS).collect::<Vec<_>>(),
            "the list must hold every variant of NetcoreError exactly once"
        );

        for error in &one_of_each {
            let explained = explain_code(error.code());
            assert!(
                !explained.summary.starts_with("Unknown error code"),
                "{} has no explanation: {explained:?}",
                error.code()
            );
            assert!(!explained.next_steps.is_empty(), "{}", error.code());
        }
    }

    /// `KILL_SWITCH_ARMED` is the answer of a `Deactivate` while the daemon is in
    /// its own fail-closed state. It never described the firewall rule, which
    /// the broker owns and `release_kill_switch` does not reach.
    #[tokio::test]
    async fn the_kill_switch_armed_answer_describes_the_daemons_fail_closed_state() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let (_reserved, host, port) = unreachable_dest();
        call(
            &sup,
            Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
                profile_id: "default".into(),
                dest_host: Some(host),
                dest_port: Some(port),
            }),
        )
        .await;
        let error = match call(
            &sup,
            Request::Deactivate(ssk_ipc::DeactivateRequest {
                release_kill_switch: false,
            }),
        )
        .await
        {
            Response::Err(error) => error,
            other => panic!("a fail-closed daemon must refuse to deactivate: {other:?}"),
        };
        assert_eq!(error.code, "KILL_SWITCH_ARMED");
        assert!(
            error.message.contains("fail-closed state"),
            "{}",
            error.message
        );
        let explained = explain_code(&error.code);
        for text in [&error.message, &explained.summary, &explained.details] {
            assert!(
                !text.contains("kill switch is armed"),
                "the daemon's own state was called the kill switch: {text}"
            );
        }
        assert!(explained.summary.contains("fail-closed"));
    }
}
