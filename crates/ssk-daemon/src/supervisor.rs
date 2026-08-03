#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use ssk_ipc::server::{BoxFuture, CommandHandler, Request, Response};
use ssk_ipc::{
    AdapterHealthSummaryDto, AuditEntryDto, DaemonState, DoctorCheckDto, DoctorReportDto,
    ExplainResponse, FlowInspectionDto, IpcError, PeerIdentity, ProfileSummaryDto, RouteTraceDto,
    StatusDto, VerifyAuditChainResponse,
};
use ssk_netadmin::audit::AuditOutcome;
use ssk_netadmin::policy::MatchCriteria;
use ssk_netadmin::route::AdapterRegistryEntry;
use ssk_netadmin::{
    FlowDescriptor, FlowRecord, ForensicEntry, HopSpec, PolicyAction, PolicyEngine, PolicyRule,
    ProtocolKind, RiskLevel, RouteKind, RouteOrchestrator,
};
use ssk_netcore::{DataPlane, EgressSession};
use ssk_tensor::GenericFileLedgerBackend;
use tokio::sync::Mutex;

use crate::killswitch::{KillSwitchProvider, KillSwitchView};
use crate::state::StateMachine;

type PersistedAuditLedger =
    ssk_netadmin::audit::AuditLedger<GenericFileLedgerBackend<ForensicEntry>>;

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
}

struct Inner {
    state: StateMachine,
    active_profile: Option<String>,
    audit: PersistedAuditLedger,
    audit_seq: u64,
    data_plane: Box<dyn DataPlane>,
    /// The real, live egress session backing `Active`/`Protected` state.
    /// `None` whenever the daemon is not really holding an open connection —
    /// there is no state in which `Protected` is reported without one.
    active_egress: Option<EgressSession>,
    /// Set from the real session's adapter chain at activation time; never
    /// hardcoded `true`.
    dns_protected: bool,
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

impl Supervisor {
    /// `kill_switch` is the injected read-only view of the privileged broker
    /// (roadmap P3). It is a seam for the same reason `data_plane` is: the real
    /// implementation dials a LocalSystem-owned named pipe, which no test on an
    /// unelevated machine can stand up. Pass
    /// [`crate::killswitch::NoProvider`] when there is no broker to ask — it
    /// answers `Unknown`, never `NotEngaged`.
    #[must_use]
    pub fn new(
        audit_path: PathBuf,
        data_plane: Box<dyn DataPlane>,
        kill_switch: Box<dyn KillSwitchProvider>,
    ) -> Self {
        Self {
            kill_switch,
            inner: Mutex::new(Inner {
                state: StateMachine::default(),
                active_profile: None,
                audit: PersistedAuditLedger::persisted(audit_path),
                audit_seq: 0,
                data_plane,
                active_egress: None,
                dns_protected: false,
            }),
        }
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

fn reference_policy_engine() -> PolicyEngine {
    // Same reference ruleset as `ssk-cli`'s `default_policy_engine` /
    // `default_route_orchestrator` (`crates/ssk-cli/src/main.rs`). Real
    // policy evaluation and route planning — not a stub — using a built-in
    // demo ruleset until Phase 5's config-driven profile model ships.
    PolicyEngine::new(vec![
        PolicyRule {
            rule_id: "allow-internal".into(),
            description: "allow internal low-risk traffic".into(),
            priority: 10,
            criteria: MatchCriteria {
                app_prefix: None,
                dest_suffix: Some(".internal".into()),
                protocol: None,
                min_risk: None,
                max_risk: Some(RiskLevel::Low),
            },
            action: PolicyAction::Allow,
        },
        PolicyRule {
            rule_id: "proxy-high-risk".into(),
            description: "route high-risk external traffic via socks5".into(),
            priority: 20,
            criteria: MatchCriteria {
                app_prefix: None,
                dest_suffix: None,
                protocol: None,
                min_risk: Some(RiskLevel::High),
                max_risk: None,
            },
            action: PolicyAction::Redirect {
                adapter_id: "socks5-exit".into(),
            },
        },
        PolicyRule {
            rule_id: "allow-low-risk-direct".into(),
            description: "default profile: allow low-risk traffic direct".into(),
            priority: 30,
            criteria: MatchCriteria {
                app_prefix: None,
                dest_suffix: None,
                protocol: None,
                min_risk: None,
                max_risk: Some(RiskLevel::Low),
            },
            action: PolicyAction::Allow,
        },
    ])
}

fn reference_route_orchestrator() -> RouteOrchestrator {
    RouteOrchestrator::new(vec![AdapterRegistryEntry {
        adapter_id: "socks5-exit".into(),
        default_hop: HopSpec::new("socks5-exit", "proxy.corp.com", 1080),
    }])
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

/// Real per-adapter health derived from the live session's actual traversed
/// chain — never a hardcoded placeholder string.
fn adapter_health_from_session(session: &EgressSession) -> Vec<AdapterHealthSummaryDto> {
    session
        .chain()
        .iter()
        .map(|kind| AdapterHealthSummaryDto {
            id: format!("{kind:?}"),
            health: "live (real, connected)".into(),
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

/// The profiles this daemon actually knows about — the **single source of
/// truth** for both `ListProfiles` and `ActivateProfile`.
///
/// Before this existed, `ListProfiles` hardcoded `"default"` and
/// `ActivateProfile` never compared anything: `req.profile_id` was only
/// `format!`ed into a flow id and stored. An auditor activated
/// `totally-made-up-profile` and received `Protected` plus a hash-chained
/// audit entry — the ledger cryptographically attesting to protection under a
/// profile that does not exist. The ledger was not wrong about the hash; it
/// was wrong about the world, which is the worst failure mode a tamper-evident
/// record has.
///
/// Today the registry is exactly one entry. When a config-driven registry
/// replaces the constant, the `activate ⊆ list` invariant is inherited rather
/// than reimplemented, because both arms read this function.
fn known_profiles() -> &'static [ProfileSummaryDto] {
    static PROFILES: std::sync::OnceLock<Vec<ProfileSummaryDto>> = std::sync::OnceLock::new();
    PROFILES.get_or_init(|| {
        vec![ProfileSummaryDto {
            id: "default".into(),
            name: "Default".into(),
        }]
    })
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
    /// Well-formed, but not in [`known_profiles`].
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
fn validate_profile_id(id: &str) -> Result<(), ProfileRejection> {
    if id.is_empty()
        || id.len() > MAX_PROFILE_ID_LEN
        || !id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
    {
        return Err(ProfileRejection::Malformed);
    }
    if !known_profiles().iter().any(|p| p.id == id) {
        return Err(ProfileRejection::Unknown);
    }
    Ok(())
}

fn known_profile_ids() -> String {
    known_profiles()
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
                    let inner = self.inner.lock().await;
                    let audit_head = inner
                        .audit
                        .entries()
                        .ok()
                        .and_then(|entries| entries.last().map(|e| e.entry_hash.clone()));
                    let adapters = inner
                        .active_egress
                        .as_ref()
                        .map(adapter_health_from_session)
                        .unwrap_or_default();
                    // The authoritative answer comes from the privileged
                    // broker, not from this process. Until P3 there was no
                    // broker to ask and this was a literal `false`; now that
                    // one exists, a hardcoded `false` would be a fabricated
                    // safe-looking value rather than an honest absence.
                    let (kill_switch, last_error) = kill_switch_fields(self.kill_switch.view());
                    Response::Status(StatusDto {
                        state: inner.state.current(),
                        active_profile: inner.active_profile.clone(),
                        adapters,
                        dns_protected: inner.dns_protected,
                        kill_switch,
                        audit_head,
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        last_error,
                    })
                }
                Request::ActivateProfile(req) => {
                    let mut inner = self.inner.lock().await;

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
                    if let Err(rejection) = validate_profile_id(&req.profile_id) {
                        let (code, message) = match rejection {
                            ProfileRejection::Malformed => (
                                "PROFILE_ID_INVALID",
                                format!(
                                    "profile_id must be 1..={MAX_PROFILE_ID_LEN} characters of \
                                     [a-z0-9._-]; known profiles: {}",
                                    known_profile_ids()
                                ),
                            ),
                            ProfileRejection::Unknown => (
                                "UNKNOWN_PROFILE",
                                format!(
                                    "no profile `{}` is configured; known profiles: {}",
                                    req.profile_id,
                                    known_profile_ids()
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

                    let engine = reference_policy_engine();
                    let orchestrator = reference_route_orchestrator();
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
                            .map(|candidate| candidate.route)
                    });

                    let route = match planned {
                        Ok(route) => route,
                        Err(err) => {
                            inner.active_profile = None;
                            inner.state.transition(
                                DaemonState::FailClosed,
                                format!("route planning failed: {err}"),
                            );
                            return Response::Err(err.into());
                        }
                    };

                    let outcome = if matches!(route, RouteKind::Denied { .. }) {
                        AuditOutcome::Denied
                    } else {
                        AuditOutcome::Dispatched
                    };
                    let seq = inner.audit_seq;
                    inner.audit_seq += 1;

                    match inner
                        .data_plane
                        .connect_route(&route, (&dest_host, dest_port))
                        .await
                    {
                        Ok(session) => {
                            inner.dns_protected = dns_protected_for(&dest_host, &session);
                            let reason =
                                format!("real egress established via {:?}", session.chain());
                            inner.active_egress = Some(session);
                            inner.active_profile = Some(req.profile_id.clone());
                            inner.state.transition(DaemonState::Protected, reason);
                        }
                        Err(err) => {
                            inner.active_profile = None;
                            inner.dns_protected = false;
                            inner.state.transition(
                                DaemonState::FailClosed,
                                format!("no viable route for profile `{}`: {err}", req.profile_id),
                            );
                        }
                    }

                    let record_outcome = if inner.state.current() == DaemonState::Protected {
                        outcome
                    } else {
                        AuditOutcome::FailClosed
                    };
                    let entry_hash = inner
                        .audit
                        .record(
                            format!("activate-{seq}"),
                            flow.flow_id.clone(),
                            None,
                            None,
                            &route,
                            record_outcome,
                            0,
                        )
                        .ok()
                        .map(|e| e.entry_hash);
                    if let Some(entry_hash) = entry_hash {
                        inner
                            .state
                            .emit(ssk_ipc::Event::AuditAppended { seq, entry_hash });
                    }

                    let state = inner.state.current();
                    let active_profile = inner.active_profile.clone();
                    let adapters = inner
                        .active_egress
                        .as_ref()
                        .map(adapter_health_from_session)
                        .unwrap_or_default();
                    let dns_protected = inner.dns_protected;
                    let audit_head = inner
                        .audit
                        .entries()
                        .ok()
                        .and_then(|entries| entries.last().map(|e| e.entry_hash.clone()));
                    // Same source of truth as `GetStatus`. Reporting the
                    // kill-switch on the activation response too is what stops
                    // a client that only ever activates from being told
                    // "kill_switch: false" forever.
                    let (kill_switch, last_error) = kill_switch_fields(self.kill_switch.view());
                    Response::Status(StatusDto {
                        state,
                        active_profile,
                        adapters,
                        dns_protected,
                        kill_switch,
                        audit_head,
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        last_error,
                    })
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
                    inner
                        .state
                        .transition(DaemonState::Inactive, "deactivate requested");
                    let audit_head = inner
                        .audit
                        .entries()
                        .ok()
                        .and_then(|entries| entries.last().map(|e| e.entry_hash.clone()));

                    // Deactivating this daemon's own egress session says
                    // nothing about the privileged broker's kill-switch: the
                    // two are different mechanisms in different processes, and
                    // a `release_kill_switch=true` here does not reach the
                    // broker (routing that verb through it is P3 CLI work, not
                    // done). So this is re-read, not assumed released.
                    let (kill_switch, last_error) = kill_switch_fields(self.kill_switch.view());
                    Response::Status(StatusDto {
                        state: DaemonState::Inactive,
                        active_profile: None,
                        adapters: vec![],
                        dns_protected: false,
                        kill_switch,
                        audit_head,
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        last_error,
                    })
                }
                Request::ListProfiles => {
                    // Same source of truth `ActivateProfile` validates
                    // against, so `list` and `activate` cannot drift apart.
                    // Phase 5 (config v3) replaces the constant registry with
                    // a config-driven one; the invariant survives that change
                    // because both arms read `known_profiles()`.
                    Response::Profiles(known_profiles().to_vec())
                }
                Request::InspectFlow { flow_id } => {
                    let engine = reference_policy_engine();
                    let flow = FlowRecord::new(
                        &flow_id,
                        0,
                        FlowDescriptor::new(
                            "unknown-app",
                            "unknown.host",
                            0,
                            ProtocolKind::Tcp,
                            RiskLevel::Low,
                        ),
                    );
                    match engine.evaluate(&flow) {
                        Ok(decision) => Response::FlowInspection(FlowInspectionDto {
                            descriptor: flow.descriptor.clone(),
                            matched_rule: decision.matched_rule.clone(),
                            action: decision.action.clone(),
                            route: ssk_netadmin::RouteKind::Denied {
                                reason: "inspect_flow does not execute a route, only classifies"
                                    .into(),
                            },
                            requires_attestation: false,
                        }),
                        Err(err) => Response::Err(err.into()),
                    }
                }
                Request::TraceRoute(req) => {
                    let engine = reference_policy_engine();
                    let orchestrator = reference_route_orchestrator();
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
                Request::RunDoctor => Response::Doctor(DoctorReportDto {
                    checks: run_doctor_checks(),
                }),
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
        "NO_POLICY_MATCH" => (
            "No policy rule matched this flow.",
            "The policy engine evaluates rules by priority; when none match, the flow is denied fail-closed.",
            vec!["Add a policy rule covering this destination/app/risk combination."],
        ),
        "ATTESTATION_REQUIRED" => (
            "Attestation is required but was not presented.",
            "The matched route requires a verified capability attestation before dispatch.",
            vec!["Present a signed attestation for this flow."],
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
        "CONFIG_INVALID" => (
            "The configuration file failed validation.",
            "Config validation is fail-closed: an invalid file is rejected rather than partially applied.",
            vec!["Fix the reported field and reload."],
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
        (Supervisor::new(audit_path, data_plane, kill_switch), dir)
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

    /// A real, guaranteed-closed port: bound then immediately dropped, so
    /// connecting to it genuinely fails (`ECONNREFUSED`), never simulated.
    async fn unreachable_dest() -> (String, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        ("127.0.0.1".to_string(), port)
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

    #[tokio::test]
    async fn activate_with_no_route_fails_closed() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let (host, port) = unreachable_dest().await;
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
        let (host, port) = unreachable_dest().await;
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
    async fn trace_route_classifies_high_risk_via_socks5() {
        let (sup, _dir) = supervisor_with(real_data_plane());
        let resp = call(
            &sup,
            Request::TraceRoute(ssk_ipc::RouteTraceRequest {
                app_id: Some("browser".into()),
                dest_host: "risky.example.com".into(),
                dest_port: 443,
                protocol: "https".into(),
                risk: "high".into(),
            }),
        )
        .await;
        match resp {
            Response::RouteTrace(dto) => {
                assert!(matches!(dto.route, ssk_netadmin::RouteKind::SingleHop(_)));
                assert_eq!(dto.hops, vec!["socks5-exit".to_string()]);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    /// `trace_route_classifies_high_risk_via_socks5` above proves the
    /// *plan*; this proves the *dispatch* — that the daemon's reference
    /// `socks5-exit` adapter (the same one `main.rs` registers in its real
    /// `AdapterRegistry`) genuinely round-trips a SOCKS5 handshake when a
    /// real `RouteExecutor` is pointed at a real (fake, but wire-protocol
    /// compliant) SOCKS5 server — not just Direct, which every other test
    /// in this module exercises.
    #[tokio::test]
    async fn high_risk_route_really_dispatches_through_a_real_socks5_proxy() {
        use ssk_netadmin::adapter::{AdapterDescriptor, AdapterKind};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut greeting = [0u8; 2];
            sock.read_exact(&mut greeting).await.expect("greeting");
            let mut methods = vec![0u8; greeting[1] as usize];
            sock.read_exact(&mut methods).await.expect("methods");
            sock.write_all(&[0x05, 0x00]).await.expect("method reply");

            let mut head = [0u8; 4];
            sock.read_exact(&mut head).await.expect("req head");
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await.expect("domain len");
            let mut domain = vec![0u8; len[0] as usize];
            sock.read_exact(&mut domain).await.expect("domain");
            let mut port = [0u8; 2];
            sock.read_exact(&mut port).await.expect("port");
            assert_eq!(&domain, b"risky.example.com");

            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .expect("success reply");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        let engine = reference_policy_engine();
        let flow = FlowRecord::new(
            "high-risk-flow",
            0,
            FlowDescriptor::new(
                "browser",
                "risky.example.com",
                443,
                ProtocolKind::Https,
                RiskLevel::High,
            ),
        );
        let decision = engine.evaluate(&flow).expect("policy eval");
        assert_eq!(
            decision.action,
            PolicyAction::Redirect {
                adapter_id: "socks5-exit".into()
            },
            "the real policy engine must select the socks5-exit redirect for high risk"
        );

        // `reference_route_orchestrator()`'s `HopSpec` hardcodes a
        // non-functional placeholder address (`proxy.corp.com:1080` — a
        // demo value, same as `ssk-cli`'s `default_route_orchestrator`),
        // exactly like a real deployment's config would name a real relay.
        // To prove *dispatch* rather than *planning* for real, this test
        // builds the same `RouteKind::SingleHop("socks5-exit", ...)` shape
        // the real orchestrator would plan, but pointed at this test's own
        // real, reachable fake proxy instead of the placeholder domain.
        let route = ssk_netadmin::route::RouteKind::SingleHop(HopSpec::new(
            "socks5-exit",
            "127.0.0.1",
            proxy_addr.port(),
        ));
        let mut registry = AdapterRegistry::new();
        registry.register(AdapterDescriptor {
            adapter_id: "socks5-exit".into(),
            kind: AdapterKind::Socks5,
            address: "127.0.0.1".into(),
            port: proxy_addr.port(),
            metadata: vec![],
        });
        let executor = RouteExecutor::new(registry);
        let session = executor
            .connect(&route, ("risky.example.com", 443))
            .await
            .expect("the socks5-exit route must really dispatch through the proxy");
        assert_eq!(session.chain(), &[AdapterKind::Socks5]);
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
                validate_profile_id(&profile.id).is_ok(),
                "`{}` is listed, so it must be activatable",
                profile.id
            );
        }
        for candidate in ["default-", "defaul", "defaultx", "other", "profile.1"] {
            let is_listed = listed.iter().any(|p| p.id == candidate);
            assert_eq!(
                validate_profile_id(candidate).is_ok(),
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
                let known: Vec<_> = known_profiles().iter().map(|x| x.id.clone()).collect();
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
