#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ssk_ipc::server::{BoxFuture, CommandHandler, Request, Response};
use ssk_ipc::{
    AdapterHealthSummaryDto, AuditEntryDto, DaemonState, DoctorCheckDto, DoctorReportDto,
    ExplainResponse, IpcError, PeerIdentity, ProfileSummaryDto, RouteTraceDto, StatusDto,
    VerifyAuditChainResponse,
};
use ssk_netadmin::audit::AuditOutcome;
use ssk_netadmin::{FlowDescriptor, FlowRecord, ForensicEntry, ProtocolKind, RiskLevel, RouteKind};
use ssk_netcore::{DataPlane, EgressSession};
use ssk_tensor::GenericFileLedgerBackend;
use tokio::sync::{Mutex, MutexGuard};

use crate::config_load::DaemonConfigError;
use crate::killswitch::{KillSwitchProvider, KillSwitchView};
use crate::routing::ConfiguredRouting;
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

/// How long `GetStatus` waits for the supervisor mutex before it asks whether
/// an activation is the reason. The desktop client gives up on a status read
/// after 2 s, so the wait has to be a small fraction of that; it is long
/// enough that an ordinary short handler never trips it.
const STATUS_LOCK_WAIT: Duration = Duration::from_millis(100);

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

struct Inner {
    state: StateMachine,
    active_profile: Option<String>,
    audit: PersistedAuditLedger,
    config: Result<ssk_config::LoadedConfig, IpcError>,
    routing: ConfiguredRouting,
    activation_error: Option<IpcError>,
    data_plane: Box<dyn DataPlane>,
    /// The real, live egress session backing `Active`/`Protected` state.
    /// `None` whenever the daemon is not really holding an open connection —
    /// there is no state in which `Protected` is reported without one.
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
    }
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
        // Even callers constructing LoadedConfig directly must validate it.
        let config = config
            .and_then(|loaded| {
                loaded.config.validate()?;
                Ok(loaded)
            })
            .map_err(|error| {
                IpcError::new("Config", "CONFIG_INVALID", error.to_string()).with_next_step(
                    "Fix SSK_CONFIG_PATH and its configuration, then restart the daemon.",
                )
            });
        let routing = ConfiguredRouting::new(
            &config
                .as_ref()
                .map(|loaded| loaded.config.routing.clone())
                .unwrap_or_default(),
        );
        let mut state = StateMachine::default();
        let activation_error = config.as_ref().err().cloned();
        if let Some(error) = &activation_error {
            state.transition(DaemonState::ConfigInvalid, &error.message);
        }
        Self {
            kill_switch,
            activation_deadline: ACTIVATE_DIAL_DEADLINE,
            activations: ActivationsInFlight::default(),
            inner: Mutex::new(Inner {
                state,
                active_profile: None,
                audit: PersistedAuditLedger::persisted(audit_path),
                config,
                routing,
                activation_error,
                data_plane,
                active_egress: None,
                dns_protected: false,
                pending_activation: None,
            }),
        }
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

    /// Subscribe to the daemon's event bus (used both by `subscribe_events`
    /// IPC requests and by tests).
    pub async fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<ssk_ipc::Event> {
        self.inner.lock().await.state.subscribe()
    }

    pub async fn current_state(&self) -> DaemonState {
        self.inner.lock().await.state.current()
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
            let _ = session.shutdown().await;
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
                Request::GetStatus => {
                    // Joined once and kept: dropping the timed-out wait would
                    // forfeit this request's place in the mutex's queue.
                    let acquire = self.inner.lock();
                    tokio::pin!(acquire);
                    let mut inner = match tokio::time::timeout(STATUS_LOCK_WAIT, &mut acquire).await
                    {
                        Ok(inner) => inner,
                        // Only an activation is allowed to be answered around.
                        // Any other holder is short and mid-change, and what it
                        // is changing is what this read must report.
                        Err(_elapsed) if self.activations.any() => {
                            return Response::Status(activating_status(self.kill_switch.view()));
                        }
                        Err(_elapsed) => acquire.await,
                    };
                    Response::Status(inner.status(self.kill_switch.view()))
                }
                Request::ActivateProfile(req) => {
                    // Before the first await: from here to the answer, a status
                    // read that cannot get `Inner` knows why. Declared before
                    // `inner` so it is released after the mutex is: a reader
                    // must never find the mutex still held by this activation
                    // with the marker already gone. The scope settles an
                    // abandoned activation while it still holds the mutex, so
                    // that too is finished before the marker goes.
                    let _in_flight = self.activations.enter();
                    let mut inner = ActivationScope(self.inner.lock().await);
                    if let Err(error) = &inner.config {
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
                    // hash-chained, and until the peer-SID check lands any
                    // local process can drive it: an attacker-controlled
                    // unbounded append is a disk-exhaustion DoS against the one
                    // artifact that must survive. The rejection is observable
                    // as an event and a log line instead.
                    let profiles = inner.routing.profiles();
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

                    let engine = inner
                        .routing
                        .engine(&req.profile_id)
                        .expect("validated profile");
                    let orchestrator = &inner.routing.orchestrator;
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
                    let planned = engine.evaluate(&flow).and_then(|decision| {
                        orchestrator
                            .plan(&flow, &decision)
                            .map(|candidate| (decision, candidate.route))
                    });

                    let (decision, route) = match planned {
                        Ok(plan) => plan,
                        Err(err) => {
                            inner.active_profile = None;
                            inner.state.transition(
                                DaemonState::FailClosed,
                                format!("route planning failed: {err}"),
                            );
                            return Response::Err(err.into());
                        }
                    };

                    let admission = match inner.routing.orchestrator.admit(&flow, &decision) {
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
                        inner.data_plane.connect_route(admission),
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

                    Response::Status(inner.status(self.kill_switch.view()))
                }
                Request::Deactivate(req) => {
                    let mut inner = self.inner.lock().await;
                    if inner.state.current() == DaemonState::FailClosed && !req.release_kill_switch
                    {
                        return Response::Err(
                            IpcError::new(
                                "Permission",
                                "KILL_SWITCH_ARMED",
                                "kill switch is armed; pass release_kill_switch=true to override",
                            )
                            .with_next_step(
                                "Resolve the underlying route/adapter issue, or explicitly release the kill switch.",
                            ),
                        );
                    }
                    // Real teardown: closing the boxed transport actually
                    // shuts down the TCP/TLS/proxy tunnel, not just a state
                    // label — this is the concrete kill-switch-adjacent
                    // mechanism for the one session the daemon holds.
                    if let Some(mut session) = inner.active_egress.take() {
                        let _ = session.shutdown().await;
                    }
                    inner.active_profile = None;
                    inner.dns_protected = false;
                    let state = if inner.config.is_err() {
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
                    Response::Status(inner.status(self.kill_switch.view()))
                }
                Request::ListProfiles => {
                    let inner = self.inner.lock().await;
                    match &inner.config {
                        Ok(_) => Response::Profiles(inner.routing.profiles()),
                        Err(error) => Response::Err(error.clone()),
                    }
                }
                Request::InspectFlow { flow_id: _ } => Response::Err(IpcError::new(
                    "Runtime",
                    "FLOW_NOT_FOUND",
                    "No captured flow is available; use trace-route for a policy preview.",
                )),
                Request::TraceRoute(req) => {
                    let inner = self.inner.lock().await;
                    if let Err(error) = &inner.config {
                        return Response::Err(error.clone());
                    }
                    let profile = inner
                        .active_profile
                        .as_ref()
                        .unwrap_or(&inner.routing.default_profile);
                    let engine = inner
                        .routing
                        .engine(profile)
                        .expect("validated default/active profile");
                    let orchestrator = &inner.routing.orchestrator;
                    let flow = FlowRecord::new(
                        "trace",
                        0,
                        FlowDescriptor::new(
                            req.app_id.as_deref().unwrap_or("unknown-app"),
                            &req.dest_host,
                            req.dest_port,
                            parse_protocol(&req.protocol),
                            parse_risk(&req.risk),
                        ),
                    );
                    let result = engine.evaluate(&flow).and_then(|decision| {
                        orchestrator
                            .plan(&flow, &decision)
                            .map(|candidate| (decision, candidate))
                    });
                    match result {
                        Ok((_, candidate)) => {
                            let hops = match &candidate.route {
                                ssk_netadmin::RouteKind::SingleHop(h) => vec![h.adapter_id.clone()],
                                ssk_netadmin::RouteKind::MultiHop(hops) => {
                                    hops.iter().map(|h| h.adapter_id.clone()).collect()
                                }
                                RouteKind::OpenVpn { adapter_id, .. } => vec![adapter_id.clone()],
                                _ => vec![],
                            };
                            Response::RouteTrace(RouteTraceDto {
                                route: candidate.route,
                                hops,
                                requires_attestation: candidate.requires_attestation,
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
                    let inner = self.inner.lock().await;
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
                    let inner = self.inner.lock().await;
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
                    let inner = self.inner.lock().await;
                    let mut checks = run_doctor_checks();
                    let (ok, detail, next_step) = match &inner.config {
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
                    if let Ok(loaded) = &inner.config {
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
            "The kill switch is armed and blocking deactivation.",
            "Deactivating while the kill switch is armed would silently drop protection.",
            vec!["Pass release_kill_switch=true if you intend to restore direct networking."],
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
                    .inner
                    .lock()
                    .await
                    .routing
                    .profiles()
                    .iter()
                    .map(|x| x.id.clone())
                    .collect();
                assert_eq!(ids, known);
            }
            other => panic!("unexpected response: {other:?}"),
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
}
