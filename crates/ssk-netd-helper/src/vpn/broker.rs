use super::{
    journal::{Event, Journal, Kind, Store},
    Command, Failure, Phase, Policy, ProcessIdentity, RecoveryEvidence, RecoveryFailure, Reject,
    Request, Response, Status, Verb,
};
use crate::{AuthenticatedPeer, CapabilityToken, IdempotencyKey};
use ssk_vpnctl::ProfileId;
use std::{
    collections::{HashMap, HashSet},
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const SESSION_LIMIT: usize = 4096;

/// OS implementation must continuously supervise an owned, kill-on-close child.
/// No release-hold capability is exposed through this seam.
pub trait LiveSession {
    fn poll(&mut self) -> Observation;
    fn stop(&mut self);
    fn abort_and_confirm(&mut self) -> bool;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    Held,
    Stopping,
    Terminating,
    Exited { failed: bool },
    Unconfirmed,
}
#[derive(Debug, Clone, Copy)]
pub struct PrepareError {
    pub exit_confirmed: Option<bool>,
    pub cancelled: bool,
}
pub trait Backend: Send + 'static {
    /// Runs on the worker. Check cancellation during bounded startup/cleanup.
    /// Create suspended in an atomic kill-on-close job. Invoke on_created once;
    /// resume ONLY after it returns true. False requires owned-handle cleanup.
    fn prepare(
        &mut self,
        profile: &ProfileId,
        cancelled: &AtomicBool,
        on_created: &mut dyn FnMut(ProcessIdentity) -> bool,
    ) -> Result<Box<dyn LiveSession>, PrepareError>;
    /// Read-only OS identity/exit verification, then exact private-file cleanup.
    /// Never terminate, reattach to, or otherwise actuate a reopened PID.
    fn recover(
        &mut self,
        _identity: ProcessIdentity,
        _cancelled: &AtomicBool,
    ) -> Result<RecoveryEvidence, RecoveryFailure> {
        Err(RecoveryFailure::ProcessQuery)
    }
}

struct Inner {
    status: Status,
    journal: Journal,
    pending: Option<Command>,
    seen: HashSet<(String, [u8; 16])>,
    cache: HashMap<(String, [u8; 16]), (Command, Status)>,
}
pub struct Broker {
    inner: Mutex<Inner>,
    policy: Policy,
    token: CapabilityToken,
    cancelled: AtomicBool,
}
/// Owns and joins the worker independently of client connection lifetimes.
pub struct Service {
    broker: Arc<Broker>,
    worker: Option<JoinHandle<()>>,
}
impl Service {
    pub fn start(
        policy: Policy,
        token: CapabilityToken,
        store: Box<dyn Store>,
        backend: impl Backend,
    ) -> io::Result<Self> {
        Self::start_with_journal(policy, token, Journal::open(store)?, backend)
    }

    /// The host acquires and verifies the journal before loading its matching
    /// configuration snapshot. The same journal remains owned throughout boot.
    pub fn start_with_journal(
        policy: Policy,
        token: CapabilityToken,
        mut journal: Journal,
        backend: impl Backend,
    ) -> io::Result<Self> {
        if journal.has_pending_maintenance() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "VPN deployment requires offline reconciliation",
            ));
        }
        let mut status = journal.last().cloned().unwrap_or_default();
        // Never reattach to a recorded PID, auto-prepare, or infer observed exit
        // from the old host's crash containment contract.
        let clean = matches!(status.phase, Phase::Idle | Phase::Shutdown | Phase::Failed)
            && status.exit_confirmed != Some(false)
            && status.audit_healthy;
        status.phase = if clean {
            Phase::Idle
        } else {
            Phase::RecoveryRequired
        };
        if clean {
            status.profile = None;
            status.operation = None;
            status.failure = None;
            status.process_identity = None;
            status.recovery_evidence = None;
            status.recovery_failure = None;
        }
        status.revision = status
            .revision
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        journal.append(Event {
            kind: Kind::Boot,
            actor: "service".into(),
            command: None,
            status: status.clone(),
            deployment: None,
        })?;
        let broker = Arc::new(Broker {
            inner: Mutex::new(Inner {
                status,
                journal,
                pending: None,
                seen: HashSet::new(),
                cache: HashMap::new(),
            }),
            policy,
            token,
            cancelled: AtomicBool::new(false),
        });
        let worker_broker = broker.clone();
        let worker = thread::Builder::new()
            .name("ssk-vpn".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(&worker_broker, backend)
                }));
                if result.is_err() {
                    worker_broker.cancelled.store(true, Ordering::Release);
                    let mut inner = worker_broker
                        .inner
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    inner.status.phase = Phase::RecoveryRequired;
                    inner.status.failure = Some(Failure::Worker);
                    inner.status.exit_confirmed = Some(false);
                    record(&mut inner, Kind::Observation, "service", None);
                }
            })?;
        Ok(Self {
            broker,
            worker: Some(worker),
        })
    }
    pub fn broker(&self) -> Arc<Broker> {
        self.broker.clone()
    }
    /// Refuse new work immediately, even while the host is joining pipe listeners.
    pub fn request_shutdown(&self) {
        self.broker.cancelled.store(true, Ordering::Release);
    }
    pub fn shutdown(&mut self) -> Status {
        self.request_shutdown();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.broker
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .status
            .clone()
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Broker {
    /// The peer is furnished by the authenticated transport, never the envelope.
    pub fn handle(&self, peer: &AuthenticatedPeer, request: Request) -> Response {
        let command = &request.command;
        if ProfileId::new(&command.profile).is_err() {
            return Response::Rejected(Reject::Malformed);
        }
        if !self.policy.permits(peer, &command.profile, command.verb) {
            return Response::Rejected(Reject::Unauthorized);
        }
        if !self.token.ct_eq(&request.session_token) {
            return Response::Rejected(Reject::BadToken);
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if command.verb == Verb::Status {
            // A profile grant must not disclose another profile's operation.
            if inner
                .status
                .profile
                .as_ref()
                .is_some_and(|p| p != &command.profile)
            {
                if matches!(inner.status.phase, Phase::Idle | Phase::Failed)
                    && inner.status.exit_confirmed != Some(false)
                    && inner.status.audit_healthy
                {
                    return Response::Status(Status {
                        revision: inner.status.revision,
                        ..Status::default()
                    });
                }
                return Response::Rejected(Reject::Busy);
            }
            return Response::Status(inner.status.clone());
        }
        if self.cancelled.load(Ordering::Acquire) {
            return Response::Rejected(Reject::ShuttingDown);
        }
        if !inner.status.audit_healthy {
            return Response::Rejected(Reject::AuditUnavailable);
        }
        let nonce = (peer.sid.as_str().to_owned(), request.nonce.0);
        if inner.seen.contains(&nonce) {
            return Response::Rejected(Reject::ReplayedNonce);
        }
        if inner.seen.len() >= SESSION_LIMIT {
            return Response::Rejected(Reject::SessionLimit);
        }
        inner.seen.insert(nonce);
        let key = (peer.sid.as_str().to_owned(), request.idempotency_key.0);
        if let Some((cached, accepted)) = inner.cache.get(&key) {
            return if cached == command {
                Response::Duplicate(accepted.clone())
            } else {
                Response::Rejected(Reject::IdempotencyConflict)
            };
        }
        if inner.status.revision != request.expected_revision {
            return Response::Rejected(Reject::StaleRevision {
                actual: inner.status.revision,
            });
        }
        if inner.status.phase == Phase::RecoveryRequired && command.verb != Verb::Recover {
            return Response::Rejected(Reject::RecoveryRequired);
        }
        if !inner.journal.accepts_intent() {
            return Response::Rejected(Reject::AuditUnavailable);
        }
        if command.verb == Verb::Recover
            && inner.status.phase == Phase::RecoveryRequired
            && inner.status.profile.as_ref() == Some(&command.profile)
            && !inner.status.process_identity.is_some_and(|id| id.valid())
        {
            return Response::Rejected(Reject::EvidenceUnavailable);
        }
        let allowed = match command.verb {
            Verb::Prepare => {
                matches!(inner.status.phase, Phase::Idle | Phase::Failed)
                    && inner.status.exit_confirmed != Some(false)
            }
            Verb::Stop => {
                inner.status.phase == Phase::PreparedHeld
                    && inner.status.profile.as_ref() == Some(&command.profile)
            }
            Verb::Recover => {
                inner.status.phase == Phase::RecoveryRequired
                    && inner.status.profile.as_ref() == Some(&command.profile)
            }
            Verb::Status => unreachable!(),
        };
        if !allowed || inner.pending.is_some() {
            return Response::Rejected(Reject::Busy);
        }
        inner.status.phase = match command.verb {
            Verb::Prepare => {
                // A crash during a new attempt must never recover an older child.
                inner.status.process_identity = None;
                Phase::Preparing
            }
            Verb::Stop => Phase::Stopping,
            Verb::Recover => Phase::Recovering,
            Verb::Status => unreachable!(),
        };
        inner.status.recovery_evidence = None;
        inner.status.recovery_failure = None;
        inner.status.profile = Some(command.profile.clone());
        inner.status.operation = Some(IdempotencyKey(request.idempotency_key.0));
        inner.status.failure = None;
        // Pending preparation may create a child. Crash recovery must assume it did.
        inner.status.exit_confirmed = Some(false);
        if !record(
            &mut inner,
            Kind::Intent,
            peer.sid.as_str(),
            Some(command.clone()),
        ) {
            return Response::Rejected(Reject::AuditUnavailable);
        }
        let accepted = inner.status.clone();
        inner.cache.insert(key, (command.clone(), accepted.clone()));
        inner.pending = Some(command.clone()); // published only AFTER durable intent
        Response::Accepted(accepted)
    }
}

fn record(inner: &mut Inner, kind: Kind, actor: &str, command: Option<Command>) -> bool {
    let Some(revision) = inner.status.revision.checked_add(1) else {
        inner.status.audit_healthy = false;
        inner.status.failure = Some(Failure::Audit);
        inner.status.phase = Phase::RecoveryRequired;
        return false;
    };
    inner.status.revision = revision;
    if !inner.status.audit_healthy {
        return false;
    }
    let event = Event {
        kind,
        actor: actor.into(),
        command,
        status: inner.status.clone(),
        deployment: None,
    };
    if inner.journal.append(event).is_err() {
        inner.status.audit_healthy = false;
        inner.status.failure = Some(Failure::Audit);
        inner.status.phase = Phase::RecoveryRequired;
        return false;
    }
    true
}

fn run(broker: &Broker, mut backend: impl Backend) {
    let mut live: Option<Box<dyn LiveSession>> = None;
    loop {
        if broker.cancelled.load(Ordering::Acquire) {
            break;
        }
        let command = broker
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending
            .take();
        if let Some(command) = command {
            match command.verb {
                Verb::Prepare => {
                    // Handle is owned only on this worker; never sent to a caller.
                    let mut on_created = |identity: ProcessIdentity| {
                        let mut inner = broker.inner.lock().unwrap_or_else(|e| e.into_inner());
                        if broker.cancelled.load(Ordering::Acquire)
                            || !identity.valid()
                            || inner.status.process_identity.is_some()
                            || inner.status.phase != Phase::Preparing
                            || !inner.status.audit_healthy
                        {
                            return false;
                        }
                        inner.status.process_identity = Some(identity);
                        record(&mut inner, Kind::ProcessCreated, "service", None)
                    };
                    let result = backend.prepare(
                        &ProfileId::new(&command.profile).expect("validated"),
                        &broker.cancelled,
                        &mut on_created,
                    );
                    let mut inner = broker.inner.lock().unwrap_or_else(|e| e.into_inner());
                    match result {
                        Ok(session) => {
                            live = Some(session);
                            if inner.status.audit_healthy && inner.status.process_identity.is_some()
                            {
                                inner.status.phase = Phase::PreparedHeld;
                            } else {
                                // A backend that omitted its proof cannot become ready.
                                inner.status.phase = Phase::RecoveryRequired;
                                inner.status.audit_healthy = false;
                                inner.status.failure = Some(Failure::Audit);
                            }
                        }
                        Err(error) => {
                            inner.status.phase = if !inner.status.audit_healthy
                                || error.exit_confirmed == Some(false)
                            {
                                Phase::RecoveryRequired
                            } else {
                                Phase::Failed
                            };
                            inner.status.failure = Some(if !inner.status.audit_healthy {
                                Failure::Audit
                            } else if error.cancelled {
                                Failure::Cancelled
                            } else {
                                Failure::Preparation
                            });
                            inner.status.exit_confirmed = error.exit_confirmed;
                        }
                    }
                    record(&mut inner, Kind::Result, "service", Some(command));
                }
                Verb::Stop => {
                    if let Some(session) = &mut live {
                        session.stop();
                    }
                }
                Verb::Recover => {
                    let identity = broker
                        .inner
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .status
                        .process_identity;
                    // During this host's lifetime an owned handle is stronger evidence.
                    // Drop it only after observed exit, before deleting locked run files.
                    let local_ended = match live.as_mut() {
                        Some(session) => matches!(session.poll(), Observation::Exited { .. }),
                        None => true,
                    };
                    let result = if !local_ended {
                        Err(RecoveryFailure::ProcessAlive)
                    } else {
                        live.take();
                        match identity {
                            Some(id) if id.valid() => backend.recover(id, &broker.cancelled),
                            _ => Err(RecoveryFailure::MissingIdentity),
                        }
                    };
                    let mut inner = broker.inner.lock().unwrap_or_else(|e| e.into_inner());
                    match result {
                        Ok(evidence) => {
                            inner.status.phase = Phase::Idle;
                            inner.status.exit_confirmed = Some(true);
                            inner.status.recovery_evidence = Some(evidence);
                        }
                        Err(error) => {
                            inner.status.phase = Phase::RecoveryRequired;
                            inner.status.failure = Some(Failure::Recovery);
                            inner.status.recovery_failure = Some(error);
                        }
                    }
                    record(&mut inner, Kind::Result, "service", Some(command));
                }
                Verb::Status => unreachable!(),
            }
        }
        let audit_failed = !broker
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .status
            .audit_healthy;
        if audit_failed {
            if let Some(mut session) = live.take() {
                let confirmed = session.abort_and_confirm();
                let mut inner = broker.inner.lock().unwrap_or_else(|e| e.into_inner());
                inner.status.exit_confirmed = Some(confirmed);
                record(&mut inner, Kind::Observation, "service", None);
            }
        } else if let Some(session) = &mut live {
            let observed = session.poll();
            let mut inner = broker.inner.lock().unwrap_or_else(|e| e.into_inner());
            // A recover intent may arrive while poll ran outside the mutex.
            // Keep its phase/identity stable until this worker executes it.
            if inner.status.phase == Phase::Recovering {
                continue;
            }
            let before = inner.status.clone();
            match observed {
                Observation::Held | Observation::Stopping => {}
                Observation::Terminating => {
                    inner.status.phase = Phase::Failed;
                    inner.status.failure = Some(Failure::Management);
                }
                Observation::Unconfirmed => {
                    inner.status.phase = Phase::RecoveryRequired;
                    inner.status.failure = Some(Failure::ExitUnconfirmed);
                }
                Observation::Exited { failed } => {
                    inner.status.exit_confirmed = Some(true);
                    inner.status.phase = if failed { Phase::Failed } else { Phase::Idle };
                    if failed {
                        inner.status.failure = Some(Failure::Management);
                    }
                    live.take();
                }
            }
            if inner.status != before {
                record(&mut inner, Kind::Observation, "service", None);
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    let confirmed = live.as_mut().map(|session| session.abort_and_confirm());
    drop(live);
    let mut inner = broker.inner.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(confirmed) = confirmed {
        inner.status.exit_confirmed = Some(confirmed);
        if !confirmed && inner.status.failure.is_none() {
            inner.status.failure = Some(Failure::ExitUnconfirmed);
        }
    } else if inner
        .pending
        .take()
        .is_some_and(|c| c.verb == Verb::Prepare)
    {
        inner.status.exit_confirmed = None;
    }
    // Preserve prior unknown exits/recovery alarms; shutdown is not remediation.
    if inner.status.exit_confirmed != Some(false) && inner.status.phase != Phase::RecoveryRequired {
        inner.status.phase = Phase::Shutdown;
    } else {
        inner.status.phase = Phase::RecoveryRequired;
    }
    record(&mut inner, Kind::Shutdown, "service", None);
}
