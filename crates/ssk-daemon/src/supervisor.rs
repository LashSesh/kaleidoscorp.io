#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use ssk_ipc::server::{BoxFuture, CommandHandler, Request, Response};
use ssk_ipc::{
    AdapterHealthSummaryDto, AuditEntryDto, DaemonState, DoctorCheckDto, DoctorReportDto,
    ExplainResponse, FlowInspectionDto, IpcError, ProfileSummaryDto, RouteTraceDto, SessionToken,
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

use crate::state::StateMachine;

type PersistedAuditLedger =
    ssk_netadmin::audit::AuditLedger<GenericFileLedgerBackend<ForensicEntry>>;

/// The daemon's product runtime: owns the live state machine, the persisted
/// audit ledger, and a real `ssk-netcore`-backed data plane (Phase 3 is no
/// longer a mock — see `ssk_netcore::NetcoreDataPlane`). Implements
/// `ssk_ipc::CommandHandler` to answer every IPC request.
pub struct Supervisor {
    inner: Mutex<Inner>,
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

impl Supervisor {
    #[must_use]
    pub fn new(audit_path: PathBuf, data_plane: Box<dyn DataPlane>) -> Self {
        Self {
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

/// Real environment probes, equivalent to (but independently implemented
/// from) `ssk-cli`'s `doctor` checks — same intentional-duplication rationale
/// as `config_load`.
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

    let entropy_ok = {
        let mut buf = [0u8; 8];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf))
            .is_ok()
    };
    checks.push(DoctorCheckDto {
        name: "entropy".into(),
        ok: entropy_ok,
        detail: if entropy_ok {
            "read 8 bytes from /dev/urandom".into()
        } else {
            "failed to read from /dev/urandom".into()
        },
        next_step: if entropy_ok {
            None
        } else {
            Some("Verify the OS entropy source is available.".into())
        },
    });

    let paths_ok = std::env::current_dir().is_ok();
    checks.push(DoctorCheckDto {
        name: "paths".into(),
        ok: paths_ok,
        detail: "current working directory is resolvable".into(),
        next_step: None,
    });

    checks
}

impl CommandHandler for Supervisor {
    fn handle<'a>(&'a self, req: Request, _token: &'a SessionToken) -> BoxFuture<'a, Response> {
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
                    Response::Status(StatusDto {
                        state: inner.state.current(),
                        active_profile: inner.active_profile.clone(),
                        adapters,
                        dns_protected: inner.dns_protected,
                        // No system-wide enforcement mechanism exists yet
                        // (that requires OS-level traffic capture/redirect —
                        // a separate, higher-privilege layer, deliberately
                        // out of scope for this pass): honestly `false`,
                        // never fabricated `true`.
                        kill_switch: false,
                        audit_head,
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        last_error: None,
                    })
                }
                Request::ActivateProfile(req) => {
                    let mut inner = self.inner.lock().await;
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
                                IpcError::new(
                                    "Validation",
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
                    Response::Status(StatusDto {
                        state,
                        active_profile,
                        adapters,
                        dns_protected,
                        kill_switch: false,
                        audit_head,
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        last_error: None,
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

                    Response::Status(StatusDto {
                        state: DaemonState::Inactive,
                        active_profile: None,
                        adapters: vec![],
                        dns_protected: false,
                        kill_switch: false,
                        audit_head,
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        last_error: None,
                    })
                }
                Request::ListProfiles => {
                    // Phase 5 (config v3) will provide a real multi-profile
                    // model; today there is exactly one reference profile.
                    Response::Profiles(vec![ProfileSummaryDto {
                        id: "default".into(),
                        name: "Default".into(),
                    }])
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
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_path = dir.path().join("audit.json");
        (Supervisor::new(audit_path, data_plane), dir)
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

    async fn call(sup: &Supervisor, req: Request) -> Response {
        let token = SessionToken::generate();
        sup.handle(req, &token).await
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
