use super::*;
use crate::{AuthenticatedPeer, CapabilityToken, IdempotencyKey, Nonce, PeerIdentity, PeerToken};
use journal::{Kind, Record, Store};
use std::{
    io,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Default)]
struct Memory {
    records: Arc<Mutex<Vec<Record>>>,
    fail: Arc<Mutex<Option<Kind>>>,
}
impl Store for Memory {
    fn load(&mut self) -> io::Result<Vec<Record>> {
        Ok(self.records.lock().unwrap().clone())
    }
    fn append(&mut self, record: &Record) -> io::Result<()> {
        if *self.fail.lock().unwrap() == Some(record.event.kind) {
            return Err(io::ErrorKind::StorageFull.into());
        }
        self.records.lock().unwrap().push(record.clone());
        Ok(())
    }
}
struct Effects {
    starts: AtomicUsize,
    recoveries: AtomicUsize,
    stops: AtomicUsize,
    aborts: AtomicUsize,
    blocked: AtomicBool,
    poll_paused: AtomicBool,
    poll_entered: AtomicBool,
    fail: AtomicBool,
    unconfirmed: AtomicBool,
    panic: AtomicBool,
    observation: Mutex<Observation>,
}
impl Default for Effects {
    fn default() -> Self {
        Self {
            starts: AtomicUsize::new(0),
            recoveries: AtomicUsize::new(0),
            stops: AtomicUsize::new(0),
            aborts: AtomicUsize::new(0),
            blocked: AtomicBool::new(false),
            poll_paused: AtomicBool::new(false),
            poll_entered: AtomicBool::new(false),
            fail: AtomicBool::new(false),
            unconfirmed: AtomicBool::new(false),
            panic: AtomicBool::new(false),
            observation: Mutex::new(Observation::Held),
        }
    }
}
struct FakeBackend(Arc<Effects>, Memory);
impl Backend for FakeBackend {
    fn prepare(
        &mut self,
        _: &ssk_vpnctl::ProfileId,
        cancelled: &AtomicBool,
        on_created: &mut dyn FnMut(ProcessIdentity) -> bool,
    ) -> Result<Box<dyn LiveSession>, PrepareError> {
        assert_eq!(
            self.1.records.lock().unwrap().last().unwrap().event.kind,
            Kind::Intent,
            "the backend must never precede durable intent"
        );
        self.0.starts.fetch_add(1, Ordering::SeqCst);
        while self.0.blocked.load(Ordering::Acquire) && !cancelled.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(2));
        }
        assert!(
            !self.0.panic.load(Ordering::Acquire),
            "injected backend panic"
        );
        if cancelled.load(Ordering::Acquire) || self.0.fail.load(Ordering::Acquire) {
            return Err(PrepareError {
                exit_confirmed: None,
                cancelled: cancelled.load(Ordering::Acquire),
            });
        }
        if !on_created(identity()) {
            return Err(PrepareError {
                exit_confirmed: Some(true),
                cancelled: false,
            });
        }
        assert_eq!(
            self.1.records.lock().unwrap().last().unwrap().event.kind,
            Kind::ProcessCreated
        );
        Ok(Box::new(FakeSession(self.0.clone())))
    }
    fn recover(
        &mut self,
        _: ProcessIdentity,
        cancelled: &AtomicBool,
    ) -> Result<RecoveryEvidence, RecoveryFailure> {
        assert_eq!(
            self.1.records.lock().unwrap().last().unwrap().event.kind,
            Kind::Intent
        );
        self.0.recoveries.fetch_add(1, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.0.blocked.load(Ordering::Acquire)
            && !cancelled.load(Ordering::Acquire)
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(2));
        }
        if cancelled.load(Ordering::Acquire) {
            return Err(RecoveryFailure::Cancelled);
        }
        if self.0.unconfirmed.load(Ordering::Acquire) {
            return Err(RecoveryFailure::ProcessAlive);
        }
        Ok(RecoveryEvidence::ProcessExited)
    }
}
fn identity() -> ProcessIdentity {
    ProcessIdentity {
        pid: 4242,
        created_at: 123456789,
        launch_id: [8; 16],
    }
}
struct FakeSession(Arc<Effects>);
impl LiveSession for FakeSession {
    fn poll(&mut self) -> Observation {
        let deadline = Instant::now() + Duration::from_secs(2);
        if self.0.poll_paused.load(Ordering::Acquire) {
            self.0.poll_entered.store(true, Ordering::Release);
        }
        while self.0.poll_paused.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(2));
        }
        *self.0.observation.lock().unwrap()
    }
    fn stop(&mut self) {
        self.0.stops.fetch_add(1, Ordering::SeqCst);
        *self.0.observation.lock().unwrap() = Observation::Exited { failed: false };
    }
    fn abort_and_confirm(&mut self) -> bool {
        self.0.aborts.fetch_add(1, Ordering::SeqCst);
        !self.0.unconfirmed.load(Ordering::Acquire)
    }
}
fn peer(id: u32) -> AuthenticatedPeer {
    AuthenticatedPeer {
        sid: PeerIdentity::parse_sid(&format!("S-1-5-21-1-2-3-{id}")).unwrap(),
        token: PeerToken::unprivileged(),
    }
}
fn policy() -> Policy {
    Policy::parse(
        br#"{"schema":1,"grants":[
        {"sid":"S-1-5-21-1-2-3-1001","profile":"corp","verbs":["status","prepare","stop","recover"]},
        {"sid":"S-1-5-21-1-2-3-1001","profile":"other","verbs":["status","prepare","recover"]},
        {"sid":"S-1-5-21-1-2-3-1002","profile":"corp","verbs":["status","prepare","stop"]}] }"#,
    )
    .unwrap()
}
fn service(memory: Memory, effects: Arc<Effects>) -> Service {
    Service::start(
        policy(),
        CapabilityToken([9; 16]),
        Box::new(memory.clone()),
        FakeBackend(effects, memory),
    )
    .unwrap()
}
fn request(verb: Verb, revision: u64, nonce: u128, key: u128) -> Request {
    Request {
        session_token: CapabilityToken([9; 16]),
        nonce: Nonce(nonce.to_le_bytes()),
        idempotency_key: IdempotencyKey(key.to_le_bytes()),
        expected_revision: revision,
        command: Command {
            verb,
            profile: "corp".into(),
        },
    }
}
fn status(broker: &Broker) -> Status {
    match broker.handle(&peer(1001), request(Verb::Status, 0, 0, 0)) {
        Response::Status(s) => s,
        other => panic!("{other:?}"),
    }
}
fn until(broker: &Broker, predicate: impl Fn(&Status) -> bool) -> Status {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let s = status(broker);
        if predicate(&s) {
            return s;
        }
        assert!(Instant::now() < deadline, "last status: {s:?}");
        thread::sleep(Duration::from_millis(5));
    }
}
fn start(broker: &Broker) -> Status {
    let s = status(broker);
    assert!(matches!(
        broker.handle(&peer(1001), request(Verb::Prepare, s.revision, 1, 1)),
        Response::Accepted(_)
    ));
    until(broker, |s| s.phase == Phase::PreparedHeld)
}

#[test]
fn policy_is_explicit_per_sid_profile_and_verb_even_for_elevated_admins() {
    let p = Policy::parse(br#"{"schema":1,"grants":[{"sid":"S-1-5-21-1-2-3-1001","profile":"corp","verbs":["status"]}]}"#).unwrap();
    let mut admin = peer(1002);
    admin.token.elevated_admin = true;
    assert!(p.permits(&peer(1001), "corp", Verb::Status));
    assert!(!p.permits(&peer(1001), "corp", Verb::Prepare));
    assert!(!p.permits(&peer(1001), "other", Verb::Status));
    assert!(!p.permits(&admin, "corp", Verb::Prepare));
    for bad in [
        r#"{"schema":2,"grants":[]}"#,
        r#"{"schema":1,"grants":[],"allow_all":true}"#,
        r#"{"schema":1,"schema":1,"grants":[]}"#,
        r#"{"schema":1,"grants":[{"sid":"S-1-5-18","profile":"../corp","verbs":["prepare"]}]}"#,
        r#"{"schema":1,"grants":[{"sid":"S-1-5-18","profile":"corp","verbs":["prepare","prepare"]}]}"#,
        r#"{"schema":1,"grants":[{"sid":"S-1-5-18","profile":"corp","verbs":["connect"]}]}"#,
    ] {
        assert!(Policy::parse(bad.as_bytes()).is_err(), "{bad}");
    }
}

#[test]
fn authorization_and_token_fail_before_intent_or_process_work() {
    let m = Memory::default();
    let e = Arc::new(Effects::default());
    let service = service(m.clone(), e.clone());
    let b = service.broker();
    let mut req = request(Verb::Prepare, 1, 1, 1);
    assert_eq!(
        b.handle(&peer(9999), req.clone()),
        Response::Rejected(Reject::Unauthorized)
    );
    req.command.profile = "../../corp".into();
    assert_eq!(
        b.handle(&peer(1001), req.clone()),
        Response::Rejected(Reject::Malformed)
    );
    req.command.profile = "corp".into();
    req.session_token = CapabilityToken([0; 16]);
    assert_eq!(
        b.handle(&peer(1001), req),
        Response::Rejected(Reject::BadToken)
    );
    assert_eq!(m.records.lock().unwrap().len(), 1);
    assert_eq!(e.starts.load(Ordering::SeqCst), 0);
}

#[test]
fn durable_intent_precedes_async_prepare_status_remains_responsive_and_stop_confirms_exit() {
    let m = Memory::default();
    let e = Arc::new(Effects::default());
    e.blocked.store(true, Ordering::Release);
    let service = service(m.clone(), e.clone());
    let b = service.broker();
    let accepted = b.handle(&peer(1001), request(Verb::Prepare, 1, 1, 1));
    assert!(matches!(
        accepted,
        Response::Accepted(Status {
            phase: Phase::Preparing,
            ..
        })
    ));
    for _ in 0..100 {
        assert_eq!(status(&b).phase, Phase::Preparing);
    }
    let preparing = status(&b);
    assert_eq!(
        b.handle(
            &peer(1001),
            request(Verb::Prepare, preparing.revision, 2, 2)
        ),
        Response::Rejected(Reject::Busy)
    );
    e.blocked.store(false, Ordering::Release);
    let held = until(&b, |s| s.phase == Phase::PreparedHeld);
    assert!(matches!(
        b.handle(&peer(1001), request(Verb::Stop, held.revision, 3, 3)),
        Response::Accepted(_)
    ));
    let stopped = until(&b, |s| s.phase == Phase::Idle);
    assert_eq!(stopped.exit_confirmed, Some(true));
    assert_eq!(e.starts.load(Ordering::SeqCst), 1);
    assert_eq!(e.stops.load(Ordering::SeqCst), 1);
    let records = m.records.lock().unwrap();
    assert!(records
        .iter()
        .any(|r| r.event.kind == Kind::Intent && r.event.actor == peer(1001).sid.as_str()));
    assert_eq!(records.last().unwrap().event.status, stopped);
}

#[test]
fn duplicate_replay_conflict_and_stale_revision_never_launch_twice() {
    let e = Arc::new(Effects::default());
    let service = service(Memory::default(), e.clone());
    let b = service.broker();
    start(&b);
    assert_eq!(
        b.handle(&peer(1001), request(Verb::Prepare, 1, 1, 1)),
        Response::Rejected(Reject::ReplayedNonce)
    );
    assert!(matches!(
        b.handle(&peer(1001), request(Verb::Prepare, 1, 2, 1)),
        Response::Duplicate(Status {
            phase: Phase::Preparing,
            ..
        })
    ));
    assert_eq!(
        b.handle(&peer(1001), request(Verb::Stop, 1, 3, 1)),
        Response::Rejected(Reject::IdempotencyConflict)
    );
    assert!(matches!(
        b.handle(&peer(1001), request(Verb::Stop, 0, 4, 4)),
        Response::Rejected(Reject::StaleRevision { .. })
    ));
    assert_eq!(e.starts.load(Ordering::SeqCst), 1);
    assert_eq!(e.stops.load(Ordering::SeqCst), 0);
}

#[test]
fn idempotency_and_nonces_are_bound_to_the_authenticated_principal() {
    let e = Arc::new(Effects::default());
    let service = service(Memory::default(), e.clone());
    let b = service.broker();
    let held = start(&b);
    b.handle(&peer(1001), request(Verb::Stop, held.revision, 2, 2));
    let idle = until(&b, |s| s.phase == Phase::Idle);
    *e.observation.lock().unwrap() = Observation::Held;
    assert!(matches!(
        b.handle(&peer(1002), request(Verb::Prepare, idle.revision, 1, 1)),
        Response::Accepted(_)
    ));
    until(&b, |s| s.phase == Phase::PreparedHeld);
    assert_eq!(e.starts.load(Ordering::SeqCst), 2);
}

#[test]
fn intent_sync_failure_prevents_process_creation() {
    let m = Memory::default();
    let e = Arc::new(Effects::default());
    let service = service(m.clone(), e.clone());
    let b = service.broker();
    *m.fail.lock().unwrap() = Some(Kind::Intent);
    assert_eq!(
        b.handle(&peer(1001), request(Verb::Prepare, 1, 1, 1)),
        Response::Rejected(Reject::AuditUnavailable)
    );
    assert!(!status(&b).audit_healthy);
    assert_eq!(e.starts.load(Ordering::SeqCst), 0);
}

#[test]
fn result_sync_failure_aborts_owned_process_and_latches_the_audit_fault() {
    let m = Memory::default();
    let e = Arc::new(Effects::default());
    let service = service(m.clone(), e.clone());
    let b = service.broker();
    *m.fail.lock().unwrap() = Some(Kind::Result);
    assert!(matches!(
        b.handle(&peer(1001), request(Verb::Prepare, 1, 1, 1)),
        Response::Accepted(_)
    ));
    let failed = until(&b, |s| !s.audit_healthy && s.exit_confirmed == Some(true));
    assert_eq!(failed.phase, Phase::RecoveryRequired);
    assert_eq!(failed.failure, Some(Failure::Audit));
    assert_eq!(e.aborts.load(Ordering::SeqCst), 1);
    assert_eq!(
        b.handle(&peer(1001), request(Verb::Prepare, failed.revision, 2, 2)),
        Response::Rejected(Reject::AuditUnavailable)
    );
}

#[test]
fn management_failures_and_unconfirmed_exit_prevent_replacement() {
    let e = Arc::new(Effects::default());
    let service = service(Memory::default(), e.clone());
    let b = service.broker();
    start(&b);
    *e.observation.lock().unwrap() = Observation::Terminating;
    let failing = until(&b, |s| s.phase == Phase::Failed);
    assert_eq!(
        b.handle(&peer(1001), request(Verb::Prepare, failing.revision, 2, 2)),
        Response::Rejected(Reject::Busy)
    );
    *e.observation.lock().unwrap() = Observation::Unconfirmed;
    let unknown = until(&b, |s| s.phase == Phase::RecoveryRequired);
    assert_eq!(
        b.handle(&peer(1001), request(Verb::Prepare, unknown.revision, 3, 3)),
        Response::Rejected(Reject::RecoveryRequired)
    );
    *e.observation.lock().unwrap() = Observation::Exited { failed: true };
    assert_eq!(
        until(&b, |s| s.exit_confirmed == Some(true)).phase,
        Phase::Failed
    );
}

#[test]
fn shutdown_cancels_blocked_preparation_and_refuses_new_requests() {
    let e = Arc::new(Effects::default());
    e.blocked.store(true, Ordering::Release);
    let mut service = service(Memory::default(), e.clone());
    let b = service.broker();
    b.handle(&peer(1001), request(Verb::Prepare, 1, 1, 1));
    let deadline = Instant::now() + Duration::from_secs(3);
    while e.starts.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
    service.request_shutdown();
    assert_eq!(
        b.handle(&peer(1001), request(Verb::Prepare, 1, 2, 2)),
        Response::Rejected(Reject::ShuttingDown)
    );
    let stopped = service.shutdown();
    assert_eq!(stopped.phase, Phase::Shutdown);
    assert_eq!(stopped.exit_confirmed, None);
}

#[test]
fn shutdown_requires_actual_exit_and_worker_panics_remain_visible() {
    let e = Arc::new(Effects::default());
    e.unconfirmed.store(true, Ordering::Release);
    let mut s = service(Memory::default(), e);
    start(&s.broker());
    let stopped = s.shutdown();
    assert_eq!(stopped.phase, Phase::RecoveryRequired);
    assert_eq!(stopped.exit_confirmed, Some(false));
    let e = Arc::new(Effects::default());
    e.panic.store(true, Ordering::Release);
    let s = service(Memory::default(), e);
    let b = s.broker();
    b.handle(&peer(1001), request(Verb::Prepare, 1, 1, 1));
    assert_eq!(
        until(&b, |s| s.phase == Phase::RecoveryRequired).failure,
        Some(Failure::Worker)
    );
}

#[test]
fn restart_with_an_unfinished_or_held_operation_requires_recovery_without_launch() {
    let m = Memory::default();
    let e = Arc::new(Effects::default());
    let mut s = service(m.clone(), e.clone());
    start(&s.broker());
    let dirty = m.records.lock().unwrap().clone();
    s.shutdown();
    for length in [2, dirty.len()] {
        // intent and held-result crash points
        let records = dirty[..length].to_vec();
        let m = Memory {
            records: Arc::new(Mutex::new(records)),
            ..Memory::default()
        };
        let e = Arc::new(Effects::default());
        let mut restarted = service(m, e.clone());
        let b = restarted.broker();
        assert_eq!(status(&b).phase, Phase::RecoveryRequired);
        let req = request(Verb::Prepare, status(&b).revision, 3, 3);
        assert_eq!(
            b.handle(&peer(1001), req),
            Response::Rejected(Reject::RecoveryRequired)
        );
        assert_eq!(e.starts.load(Ordering::SeqCst), 0);
        assert_eq!(restarted.shutdown().phase, Phase::RecoveryRequired);
    }
}

#[test]
fn clean_restart_preserves_revision_and_detects_corrupt_chain() {
    let m = Memory::default();
    let mut s = service(m.clone(), Arc::new(Effects::default()));
    let stopped = s.shutdown();
    let mut restarted = service(m.clone(), Arc::new(Effects::default()));
    assert_eq!(status(&restarted.broker()).revision, stopped.revision + 1);
    assert_eq!(status(&restarted.broker()).phase, Phase::Idle);
    restarted.shutdown();
    m.records.lock().unwrap()[0].event.actor = "forged".into();
    assert!(journal::Journal::open(Box::new(m)).is_err());
}

#[test]
fn session_limit_does_not_evict_nonces_or_prevent_status() {
    let s = service(Memory::default(), Arc::new(Effects::default()));
    let b = s.broker();
    for n in 1..=4096 {
        assert!(matches!(
            b.handle(&peer(1001), request(Verb::Prepare, 0, n, n)),
            Response::Rejected(Reject::StaleRevision { .. })
        ));
    }
    assert_eq!(
        b.handle(&peer(1001), request(Verb::Prepare, 1, 4097, 4097)),
        Response::Rejected(Reject::SessionLimit)
    );
    assert_eq!(
        b.handle(&peer(1001), request(Verb::Prepare, 1, 1, 1)),
        Response::Rejected(Reject::ReplayedNonce)
    );
    assert_eq!(status(&b).phase, Phase::Idle);
}

#[test]
fn strict_vpn_wire_rejects_unknown_fields_trailing_values_and_legacy_commands() {
    let req = request(Verb::Prepare, 1, 1, 1);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&req, &mut bytes).unwrap();
    assert_eq!(protocol::decode(&bytes), Ok(req.clone()));
    bytes.push(0);
    assert_eq!(protocol::decode(&bytes), Err(Reject::Malformed));
    let mut value = serde_json::to_value(req).unwrap();
    value["executable"] = "evil.exe".into();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).unwrap();
    assert!(protocol::decode(&bytes).is_err());
    assert!(protocol::decode(&vec![0; protocol::MAX_FRAME + 1]).is_err());
    let legacy = crate::CommandEnvelope {
        session_token: CapabilityToken([9; 16]),
        nonce: Nonce([1; 16]),
        idempotency_key: IdempotencyKey([1; 16]),
        expected_state_version: 0,
        command: crate::Command::EngageKillSwitch,
    };
    assert!(protocol::decode(&crate::protocol::encode_envelope(&legacy).unwrap()).is_err());
}

#[test]
fn vpn_client_refuses_protocol_downgrade_and_emits_only_vpn_envelopes() {
    use crate::{
        handshake::PRIV_HANDSHAKE_MAGIC,
        testing::{framed_value, FakeTransport},
        LeaseId, ServerHandshake, ServerHello,
    };
    let answer = |version| {
        ServerHandshake::Accepted(ServerHello {
            magic: PRIV_HANDSHAKE_MAGIC,
            protocol_version: version,
            session_token: CapabilityToken([9; 16]),
            lease: LeaseId([0; 16]),
            state_version: 999,
        })
    };
    for old_version in [1, 2] {
        assert!(
            client::Client::connect(FakeTransport::with_inbound(framed_value(&answer(
                old_version
            ))))
            .is_err()
        );
    }
    let mut data = framed_value(&answer(protocol::PROTOCOL_VERSION));
    data.extend(framed_value(&Response::Status(Status::default())));
    let mut client = client::Client::connect(FakeTransport::with_inbound(data)).unwrap();
    assert!(matches!(
        client
            .send(
                Command {
                    verb: Verb::Status,
                    profile: "corp".into()
                },
                0,
                IdempotencyKey([1; 16]),
                Nonce([2; 16])
            )
            .unwrap(),
        Response::Status(_)
    ));
}

#[test]
fn journal_refuses_sequence_gaps_schema_changes_and_forged_status_revisions() {
    let m = Memory::default();
    let s = service(m.clone(), Arc::new(Effects::default()));
    drop(s);
    for change in 0..3 {
        let copied = Memory {
            records: Arc::new(Mutex::new(m.records.lock().unwrap().clone())),
            ..Memory::default()
        };
        {
            let mut records = copied.records.lock().unwrap();
            match change {
                0 => records[0].sequence += 1,
                1 => records[0].schema = 9,
                _ => records[0].event.status.revision = 4,
            }
        }
        assert!(journal::Journal::open(Box::new(copied)).is_err());
    }
}

#[test]
fn idle_status_for_another_granted_profile_is_redacted_but_allows_the_next_prepare() {
    let s = service(Memory::default(), Arc::new(Effects::default()));
    let b = s.broker();
    let held = start(&b);
    let mut other = request(Verb::Status, 0, 0, 0);
    other.command.profile = "other".into();
    assert_eq!(
        b.handle(&peer(1001), other.clone()),
        Response::Rejected(Reject::Busy)
    );
    b.handle(&peer(1001), request(Verb::Stop, held.revision, 2, 2));
    let idle = until(&b, |s| s.phase == Phase::Idle);
    let Response::Status(redacted) = b.handle(&peer(1001), other) else {
        panic!("idle status unavailable")
    };
    assert_eq!(redacted.profile, None);
    assert_eq!(redacted.operation, None);
    assert_eq!(redacted.revision, idle.revision);
}

fn crashed_memory(with_identity: bool) -> Memory {
    let m = Memory::default();
    let mut s = service(m.clone(), Arc::new(Effects::default()));
    start(&s.broker());
    let records = m.records.lock().unwrap().clone();
    s.shutdown();
    Memory {
        records: Arc::new(Mutex::new(if with_identity {
            records
        } else {
            records[..2].to_vec()
        })),
        ..Memory::default()
    }
}

#[test]
fn process_identity_sync_failure_prevents_ready_and_preserves_audit_alarm() {
    let m = Memory::default();
    *m.fail.lock().unwrap() = Some(Kind::ProcessCreated);
    let s = service(m.clone(), Arc::new(Effects::default()));
    let b = s.broker();
    b.handle(&peer(1001), request(Verb::Prepare, 1, 1, 1));
    let failed = until(&b, |s| s.exit_confirmed == Some(true));
    assert_eq!(failed.phase, Phase::RecoveryRequired);
    assert!(!failed.audit_healthy);
    assert_eq!(failed.failure, Some(Failure::Audit));
    assert!(!m
        .records
        .lock()
        .unwrap()
        .iter()
        .any(|r| r.event.status.phase == Phase::PreparedHeld));
}

#[test]
fn recovery_requires_separate_grant_matching_profile_and_durable_identity() {
    for has_identity in [false, true] {
        let e = Arc::new(Effects::default());
        let s = service(crashed_memory(has_identity), e.clone());
        let b = s.broker();
        let revision = status(&b).revision;
        assert_eq!(
            b.handle(&peer(1002), request(Verb::Recover, revision, 1, 1)),
            Response::Rejected(Reject::Unauthorized)
        );
        let mut wrong = request(Verb::Recover, revision, 2, 2);
        wrong.command.profile = "other".into();
        assert_eq!(
            b.handle(&peer(1001), wrong),
            Response::Rejected(Reject::Busy)
        );
        if !has_identity {
            assert_eq!(
                b.handle(&peer(1001), request(Verb::Recover, revision, 3, 3)),
                Response::Rejected(Reject::EvidenceUnavailable)
            );
            assert_eq!(e.recoveries.load(Ordering::SeqCst), 0);
        }
    }
}

#[test]
fn recovery_proof_is_audited_idempotent_and_survives_a_clean_restart() {
    let m = crashed_memory(true);
    let e = Arc::new(Effects::default());
    let mut s = service(m.clone(), e.clone());
    let b = s.broker();
    let revision = status(&b).revision;
    let accepted = b.handle(&peer(1001), request(Verb::Recover, revision, 1, 1));
    let Response::Accepted(original) = accepted else {
        panic!("{accepted:?}")
    };
    assert_eq!(original.phase, Phase::Recovering);
    let idle = until(&b, |s| s.phase == Phase::Idle);
    assert_eq!(idle.exit_confirmed, Some(true));
    assert_eq!(
        idle.recovery_evidence,
        Some(RecoveryEvidence::ProcessExited)
    );
    assert_eq!(
        b.handle(&peer(1001), request(Verb::Recover, revision, 1, 1)),
        Response::Rejected(Reject::ReplayedNonce)
    );
    assert_eq!(
        b.handle(&peer(1001), request(Verb::Recover, revision, 2, 1)),
        Response::Duplicate(original)
    );
    assert_eq!(e.recoveries.load(Ordering::SeqCst), 1);
    assert_eq!(e.starts.load(Ordering::SeqCst), 0);
    assert_eq!(m.records.lock().unwrap().last().unwrap().event.status, idle);
    s.shutdown();
    drop(b);
    drop(s);
    let next = service(m, Arc::new(Effects::default()));
    assert_eq!(status(&next.broker()).phase, Phase::Idle);
}

#[test]
fn live_process_refusal_stays_blocked_and_fresh_recovery_can_succeed_later() {
    let e = Arc::new(Effects::default());
    e.unconfirmed.store(true, Ordering::Release);
    let s = service(crashed_memory(true), e.clone());
    let b = s.broker();
    b.handle(
        &peer(1001),
        request(Verb::Recover, status(&b).revision, 1, 1),
    );
    let failed = until(&b, |s| s.recovery_failure.is_some());
    assert_eq!(failed.phase, Phase::RecoveryRequired);
    assert_eq!(failed.recovery_failure, Some(RecoveryFailure::ProcessAlive));
    assert_eq!(
        b.handle(&peer(1001), request(Verb::Prepare, failed.revision, 2, 2)),
        Response::Rejected(Reject::RecoveryRequired)
    );
    e.unconfirmed.store(false, Ordering::Release);
    b.handle(&peer(1001), request(Verb::Recover, failed.revision, 3, 3));
    let idle = until(&b, |s| s.phase == Phase::Idle);
    assert_eq!(idle.failure, None);
    assert_eq!(idle.recovery_failure, None);
}

#[test]
fn recovery_sync_failures_never_advertise_a_successful_reset() {
    for kind in [Kind::Intent, Kind::Result] {
        let m = crashed_memory(true);
        let e = Arc::new(Effects::default());
        let s = service(m.clone(), e.clone());
        *m.fail.lock().unwrap() = Some(kind);
        let b = s.broker();
        let answer = b.handle(
            &peer(1001),
            request(Verb::Recover, status(&b).revision, 1, 1),
        );
        if kind == Kind::Intent {
            assert_eq!(answer, Response::Rejected(Reject::AuditUnavailable));
        }
        let failed = until(&b, |s| !s.audit_healthy);
        assert_eq!(failed.phase, Phase::RecoveryRequired);
        assert_eq!(failed.failure, Some(Failure::Audit));
        assert_eq!(
            e.recoveries.load(Ordering::SeqCst),
            usize::from(kind == Kind::Result)
        );
    }
}

#[test]
fn interrupted_recovery_is_retried_from_its_original_process_identity() {
    let m = crashed_memory(true);
    let s = service(m.clone(), Arc::new(Effects::default()));
    let b = s.broker();
    b.handle(
        &peer(1001),
        request(Verb::Recover, status(&b).revision, 1, 1),
    );
    until(&b, |s| s.phase == Phase::Idle);
    let records = m.records.lock().unwrap().clone();
    let end = records
        .iter()
        .position(|r| r.event.status.phase == Phase::Recovering)
        .unwrap()
        + 1;
    let crash = Memory {
        records: Arc::new(Mutex::new(records[..end].to_vec())),
        ..Memory::default()
    };
    let next = service(crash, Arc::new(Effects::default()));
    let b = next.broker();
    assert_eq!(status(&b).phase, Phase::RecoveryRequired);
    assert_eq!(status(&b).process_identity, Some(identity()));
    b.handle(
        &peer(1001),
        request(Verb::Recover, status(&b).revision, 1, 1),
    );
    until(&b, |s| s.phase == Phase::Idle);
}

#[test]
fn a_new_attempt_clears_old_identity_before_any_process_effect() {
    let e = Arc::new(Effects::default());
    let s = service(crashed_memory(true), e.clone());
    let b = s.broker();
    b.handle(
        &peer(1001),
        request(Verb::Recover, status(&b).revision, 1, 1),
    );
    let idle = until(&b, |s| s.phase == Phase::Idle);
    e.blocked.store(true, Ordering::Release);
    let Response::Accepted(preparing) =
        b.handle(&peer(1001), request(Verb::Prepare, idle.revision, 2, 2))
    else {
        panic!("not accepted")
    };
    assert_eq!(preparing.process_identity, None);
    assert_eq!(preparing.recovery_evidence, None);
    assert_eq!(preparing.exit_confirmed, Some(false));
}

#[test]
fn original_schema_one_journal_bytes_and_hashes_remain_readable() {
    // Independent pre-recovery shape, including field order; a missing optional
    // field must not become a serialized null and invalidate existing hashes.
    #[derive(serde::Serialize)]
    struct LegacyStatus {
        revision: u64,
        profile: Option<String>,
        phase: Phase,
        operation: Option<IdempotencyKey>,
        failure: Option<Failure>,
        exit_confirmed: Option<bool>,
        audit_healthy: bool,
    }
    #[derive(serde::Serialize)]
    struct LegacyEvent {
        kind: Kind,
        actor: String,
        command: Option<Command>,
        status: LegacyStatus,
    }
    for phase in [
        Phase::Idle,
        Phase::Preparing,
        Phase::PreparedHeld,
        Phase::Stopping,
        Phase::Failed,
        Phase::RecoveryRequired,
        Phase::Shutdown,
    ] {
        let old = LegacyEvent {
            kind: Kind::Observation,
            actor: "service".into(),
            command: None,
            status: LegacyStatus {
                revision: 1,
                profile: Some("corp".into()),
                phase,
                operation: None,
                failure: None,
                exit_confirmed: Some(false),
                audit_healthy: true,
            },
        };
        let old_bytes = ssk_types::canonical_bytes(&old).unwrap();
        let current: journal::Event = crate::framing::decode_strict(&old_bytes).unwrap();
        assert_eq!(ssk_types::canonical_bytes(&current).unwrap(), old_bytes);
        let hash = ssk_types::digest_of(
            &(1u32, 1u64, ssk_types::Digest::GENESIS, old),
            ssk_types::HashAlg::Blake3,
        )
        .unwrap();
        let m = Memory::default();
        m.records.lock().unwrap().push(Record {
            schema: 1,
            sequence: 1,
            previous: ssk_types::Digest::GENESIS,
            event: current,
            hash,
        });
        assert!(journal::Journal::open(Box::new(m)).is_ok());
    }
}

#[test]
fn an_exit_observed_concurrently_with_recover_cannot_overwrite_the_pending_intent() {
    let e = Arc::new(Effects::default());
    let s = service(Memory::default(), e.clone());
    let b = s.broker();
    start(&b);
    *e.observation.lock().unwrap() = Observation::Unconfirmed;
    until(&b, |s| s.phase == Phase::RecoveryRequired);
    e.poll_paused.store(true, Ordering::Release);
    let deadline = Instant::now() + Duration::from_secs(1);
    while !e.poll_entered.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
    e.blocked.store(true, Ordering::Release);
    let revision = status(&b).revision;
    assert!(matches!(
        b.handle(&peer(1001), request(Verb::Recover, revision, 2, 2)),
        Response::Accepted(_)
    ));
    *e.observation.lock().unwrap() = Observation::Exited { failed: false };
    e.poll_paused.store(false, Ordering::Release);
    let deadline = Instant::now() + Duration::from_secs(1);
    while e.recoveries.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
    let recovering = status(&b);
    assert_eq!(recovering.phase, Phase::Recovering);
    assert_eq!(
        b.handle(
            &peer(1001),
            request(Verb::Prepare, recovering.revision, 3, 3)
        ),
        Response::Rejected(Reject::Busy)
    );
    assert_eq!(
        b.handle(
            &peer(1001),
            request(Verb::Recover, recovering.revision, 4, 4)
        ),
        Response::Rejected(Reject::Busy)
    );
    e.blocked.store(false, Ordering::Release);
    until(&b, |s| s.phase == Phase::Idle);
}

#[test]
fn journal_uses_streaming_replay_and_binds_the_storage_schema_to_its_hash() {
    struct Streaming(Memory);
    impl Store for Streaming {
        fn load(&mut self) -> io::Result<Vec<Record>> {
            panic!("streaming journal must not materialize load")
        }
        fn replay(&mut self, visit: &mut dyn FnMut(Record) -> io::Result<()>) -> io::Result<()> {
            for r in self.0.records.lock().unwrap().iter().cloned() {
                visit(r)?;
            }
            Ok(())
        }
        fn append(&mut self, r: &Record) -> io::Result<()> {
            self.0.append(r)
        }
    }
    let m = Memory::default();
    drop(service(m.clone(), Arc::new(Effects::default())));
    let inspected = journal::Journal::open(Box::new(Streaming(m.clone())))
        .unwrap()
        .inspection();
    assert_eq!(inspected.records, 2);
    assert_eq!(m.records.lock().unwrap()[0].schema, 2);
    // Re-labeling a v2 record as an accepted older schema cannot bypass integrity.
    m.records.lock().unwrap()[0].schema = 1;
    assert!(journal::Journal::open(Box::new(Streaming(m))).is_err());
}

#[test]
fn platform_capacity_refusal_preserves_emergency_space_before_any_new_effect() {
    struct Full(Memory);
    impl Store for Full {
        fn load(&mut self) -> io::Result<Vec<Record>> {
            self.0.load()
        }
        fn append(&mut self, r: &Record) -> io::Result<()> {
            self.0.append(r)
        }
        fn has_capacity(&self, records: usize) -> bool {
            assert_eq!(records, journal::EMERGENCY_RECORDS + 1);
            false
        }
    }
    let m = Memory::default();
    let e = Arc::new(Effects::default());
    let s = Service::start(
        policy(),
        CapabilityToken([9; 16]),
        Box::new(Full(m.clone())),
        FakeBackend(e.clone(), m.clone()),
    )
    .unwrap();
    let b = s.broker();
    assert_eq!(
        b.handle(&peer(1001), request(Verb::Prepare, 1, 1, 1)),
        Response::Rejected(Reject::AuditUnavailable)
    );
    assert_eq!(e.starts.load(Ordering::SeqCst), 0);
    assert_eq!(m.records.lock().unwrap().len(), 1);
    assert!(
        status(&b).audit_healthy,
        "capacity pressure is not fabricated corruption"
    );
}

fn deployment_change() -> journal::DeploymentChange {
    journal::DeploymentChange {
        target: journal::DeploymentTarget::Package,
        id: [3; 16],
        previous: None,
        candidate: [4; 32],
    }
}

#[test]
fn pending_deployment_blocks_service_boot_without_effects_or_history_changes() {
    let memory = Memory::default();
    let effects = Arc::new(Effects::default());
    let mut journal = journal::Journal::open(Box::new(memory.clone())).unwrap();
    journal
        .deployment(
            "S-1-5-18",
            journal::DeploymentEvent::Begin(deployment_change()),
        )
        .unwrap();
    drop(journal);
    let result = Service::start(
        policy(),
        CapabilityToken([9; 16]),
        Box::new(memory.clone()),
        FakeBackend(effects.clone(), memory.clone()),
    );
    assert!(matches!(result, Err(ref e) if e.kind() == io::ErrorKind::WouldBlock));
    assert_eq!(memory.records.lock().unwrap().len(), 1);
    assert_eq!(effects.starts.load(Ordering::SeqCst), 0);
    let mut journal = journal::Journal::open(Box::new(memory.clone())).unwrap();
    journal
        .deployment(
            "S-1-5-18",
            journal::DeploymentEvent::Unchanged(deployment_change()),
        )
        .unwrap();
    drop(journal);
    drop(service(memory.clone(), effects));
    assert_eq!(memory.records.lock().unwrap()[2].event.kind, Kind::Boot);
}

#[test]
fn deployment_journal_requires_matching_completion_and_rejects_interleaving() {
    use journal::DeploymentEvent::{Begin, Committed, Unchanged};
    let memory = Memory::default();
    let mut journal = journal::Journal::open(Box::new(memory.clone())).unwrap();
    let change = deployment_change();
    assert!(journal
        .deployment("S-1-5-18", Committed(change.clone()))
        .is_err());
    assert!(journal
        .deployment("caller-supplied-name", Begin(change.clone()))
        .is_err());
    journal
        .deployment("S-1-5-18", Begin(change.clone()))
        .unwrap();
    assert!(journal
        .deployment("S-1-5-18", Begin(change.clone()))
        .is_err());
    let other = journal::DeploymentChange {
        id: [8; 16],
        ..change.clone()
    };
    assert!(journal.deployment("S-1-5-18", Unchanged(other)).is_err());
    assert!(journal
        .append(journal::Event {
            kind: Kind::Boot,
            actor: "service".into(),
            command: None,
            status: Status {
                revision: 2,
                ..Status::default()
            },
            deployment: None
        })
        .is_err());
    assert_eq!(memory.records.lock().unwrap().len(), 1);
    journal.deployment("S-1-5-18", Committed(change)).unwrap();
    assert!(journal.pending_deployment().is_none());
    assert!(journal::Journal::open(Box::new(memory))
        .unwrap()
        .pending_deployment()
        .is_none());
}

#[test]
fn deployment_cannot_clear_unresolved_process_state_or_change_status_fields() {
    let memory = Memory::default();
    let mut journal = journal::Journal::open(Box::new(memory.clone())).unwrap();
    let status = Status {
        revision: 1,
        phase: Phase::RecoveryRequired,
        exit_confirmed: Some(false),
        ..Status::default()
    };
    journal
        .append(journal::Event {
            kind: Kind::Observation,
            actor: "service".into(),
            command: None,
            status,
            deployment: None,
        })
        .unwrap();
    assert!(journal
        .deployment(
            "S-1-5-18",
            journal::DeploymentEvent::Begin(deployment_change())
        )
        .is_err());
    assert!(journal
        .append(journal::Event {
            kind: Kind::Deployment,
            actor: "S-1-5-18".into(),
            command: None,
            status: Status {
                revision: 2,
                ..Status::default()
            },
            deployment: Some(journal::DeploymentEvent::Begin(deployment_change()))
        })
        .is_err());
    assert_eq!(memory.records.lock().unwrap().len(), 1);
}

#[test]
fn rejected_deployment_audit_does_not_advance_transaction_state() {
    let memory = Memory::default();
    let mut journal = journal::Journal::open(Box::new(memory.clone())).unwrap();
    *memory.fail.lock().unwrap() = Some(Kind::Deployment);
    assert!(journal
        .deployment(
            "S-1-5-18",
            journal::DeploymentEvent::Begin(deployment_change())
        )
        .is_err());
    assert!(journal.pending_deployment().is_none());
    *memory.fail.lock().unwrap() = None;
    journal
        .deployment(
            "S-1-5-18",
            journal::DeploymentEvent::Begin(deployment_change()),
        )
        .unwrap();
    *memory.fail.lock().unwrap() = Some(Kind::Deployment);
    assert!(journal
        .deployment(
            "S-1-5-18",
            journal::DeploymentEvent::Committed(deployment_change())
        )
        .is_err());
    assert!(journal.pending_deployment().is_some());
    assert_eq!(memory.records.lock().unwrap().len(), 1);
}

#[test]
fn configuration_digest_replays_and_cannot_be_replaced_by_a_package_event() {
    use journal::{
        DeploymentEvent::{Begin, Committed, Unchanged},
        DeploymentTarget,
    };
    let memory = Memory::default();
    let mut journal = journal::Journal::open(Box::new(memory.clone())).unwrap();
    let mut change = deployment_change();
    change.target = DeploymentTarget::Configuration;
    journal
        .deployment("S-1-5-18", Begin(change.clone()))
        .unwrap();
    let wrong = journal::DeploymentChange {
        target: DeploymentTarget::Package,
        ..change.clone()
    };
    assert!(journal.deployment("S-1-5-18", Committed(wrong)).is_err());
    journal
        .deployment("S-1-5-18", Committed(change.clone()))
        .unwrap();
    assert_eq!(journal.configuration_digest(), Some(change.candidate));
    assert!(journal
        .deployment("S-1-5-18", Begin(change.clone()))
        .is_err());
    let next = journal::DeploymentChange {
        previous: Some(change.candidate),
        candidate: [5; 32],
        id: [6; 16],
        ..change
    };
    journal.deployment("S-1-5-18", Begin(next.clone())).unwrap();
    journal.deployment("S-1-5-18", Unchanged(next)).unwrap();
    let package = deployment_change();
    journal
        .deployment("S-1-5-18", Begin(package.clone()))
        .unwrap();
    journal.deployment("S-1-5-18", Committed(package)).unwrap();
    assert_eq!(
        journal::Journal::open(Box::new(memory))
            .unwrap()
            .configuration_digest(),
        Some([4; 32])
    );
}

#[test]
fn package_deployment_bytes_from_before_configuration_support_keep_their_hash() {
    #[derive(serde::Serialize)]
    struct OldChange {
        id: [u8; 16],
        previous: Option<[u8; 32]>,
        candidate: [u8; 32],
    }
    #[derive(serde::Serialize)]
    enum OldDeployment {
        Begin(OldChange),
    }
    #[derive(serde::Serialize)]
    struct OldEvent {
        kind: Kind,
        actor: String,
        command: Option<Command>,
        status: Status,
        deployment: Option<OldDeployment>,
    }
    let old = OldEvent {
        kind: Kind::Deployment,
        actor: "S-1-5-18".into(),
        command: None,
        status: Status {
            revision: 1,
            ..Status::default()
        },
        deployment: Some(OldDeployment::Begin(OldChange {
            id: [3; 16],
            previous: None,
            candidate: [4; 32],
        })),
    };
    let bytes = ssk_types::canonical_bytes(&old).unwrap();
    let current: journal::Event = crate::framing::decode_strict(&bytes).unwrap();
    assert_eq!(ssk_types::canonical_bytes(&current).unwrap(), bytes);
    let hash = ssk_types::digest_of(
        &(2u32, 1u64, ssk_types::Digest::GENESIS, old),
        ssk_types::HashAlg::Blake3,
    )
    .unwrap();
    let memory = Memory::default();
    memory.records.lock().unwrap().push(Record {
        schema: 2,
        sequence: 1,
        previous: ssk_types::Digest::GENESIS,
        event: current,
        hash,
    });
    let journal = journal::Journal::open(Box::new(memory)).unwrap();
    assert_eq!(
        journal.pending_deployment().unwrap().target,
        journal::DeploymentTarget::Package
    );
    assert_eq!(journal.configuration_digest(), None);
}

#[test]
fn pending_configuration_refuses_broker_start_and_preserves_last_committed_digest() {
    let memory = Memory::default();
    let effects = Arc::new(Effects::default());
    let mut journal = journal::Journal::open(Box::new(memory.clone())).unwrap();
    let mut change = deployment_change();
    change.target = journal::DeploymentTarget::Configuration;
    journal
        .deployment("S-1-5-18", journal::DeploymentEvent::Begin(change))
        .unwrap();
    assert!(Service::start_with_journal(
        policy(),
        CapabilityToken([9; 16]),
        journal,
        FakeBackend(effects.clone(), memory.clone())
    )
    .is_err());
    assert_eq!(memory.records.lock().unwrap().len(), 1);
    assert_eq!(effects.starts.load(Ordering::SeqCst), 0);
    assert_eq!(
        journal::Journal::open(Box::new(memory))
            .unwrap()
            .configuration_digest(),
        None
    );
}

fn committed_configuration_journal(memory: &Memory) -> journal::Journal {
    let mut journal = journal::Journal::open(Box::new(memory.clone())).unwrap();
    let change = journal::DeploymentChange {
        target: journal::DeploymentTarget::Configuration,
        ..deployment_change()
    };
    journal
        .deployment("S-1-5-18", journal::DeploymentEvent::Begin(change.clone()))
        .unwrap();
    journal
        .deployment("S-1-5-18", journal::DeploymentEvent::Committed(change))
        .unwrap();
    journal
}
fn repair_change() -> journal::RepairChange {
    journal::RepairChange {
        id: [7; 16],
        configuration: [4; 32],
        observed: Some([8; 32]),
    }
}

#[test]
fn configuration_repair_preserves_process_recovery_state_and_blocks_boot_until_completion() {
    use journal::DeploymentEvent::{RestoreBegin, RestoreCompleted};
    let memory = Memory::default();
    let effects = Arc::new(Effects::default());
    let mut journal = committed_configuration_journal(&memory);
    let status = Status {
        revision: 3,
        phase: Phase::RecoveryRequired,
        profile: Some("corp".into()),
        exit_confirmed: Some(false),
        process_identity: Some(identity()),
        ..Status::default()
    };
    journal
        .append(journal::Event {
            kind: Kind::Observation,
            actor: "service".into(),
            command: None,
            status: status.clone(),
            deployment: None,
        })
        .unwrap();
    journal
        .deployment("S-1-5-18", RestoreBegin(repair_change()))
        .unwrap();
    assert!(Service::start_with_journal(
        policy(),
        CapabilityToken([9; 16]),
        journal,
        FakeBackend(effects.clone(), memory.clone())
    )
    .is_err());
    let mut journal = journal::Journal::open(Box::new(memory.clone())).unwrap();
    assert!(journal.pending_repair().is_some());
    assert_eq!(memory.records.lock().unwrap().len(), 4);
    journal
        .deployment("S-1-5-18", RestoreCompleted(repair_change()))
        .unwrap();
    assert_eq!(
        journal.last(),
        Some(&Status {
            revision: 5,
            ..status
        })
    );
    assert_eq!(journal.configuration_digest(), Some([4; 32]));
    let service = Service::start_with_journal(
        policy(),
        CapabilityToken([9; 16]),
        journal,
        FakeBackend(effects.clone(), memory),
    )
    .unwrap();
    assert_eq!(
        service
            .broker()
            .handle(&peer(1001), request(Verb::Prepare, 6, 1, 1)),
        Response::Rejected(Reject::RecoveryRequired)
    );
    assert_eq!(effects.starts.load(Ordering::SeqCst), 0);
}

#[test]
fn repair_refuses_wrong_commit_interleaving_mismatched_completion_and_status_reset() {
    use journal::DeploymentEvent::{Begin, RestoreBegin, RestoreCompleted, RestoreUnchanged};
    let memory = Memory::default();
    let mut journal = committed_configuration_journal(&memory);
    let wrong = journal::RepairChange {
        configuration: [5; 32],
        ..repair_change()
    };
    assert!(journal.deployment("S-1-5-18", RestoreBegin(wrong)).is_err());
    let unchanged = journal::RepairChange {
        observed: Some([4; 32]),
        ..repair_change()
    };
    assert!(journal
        .deployment("S-1-5-18", RestoreBegin(unchanged))
        .is_err());
    journal
        .deployment("S-1-5-18", RestoreBegin(repair_change()))
        .unwrap();
    assert!(journal
        .deployment("S-1-5-18", Begin(deployment_change()))
        .is_err());
    assert!(journal
        .deployment("S-1-5-18", RestoreBegin(repair_change()))
        .is_err());
    let wrong = journal::RepairChange {
        observed: None,
        ..repair_change()
    };
    assert!(journal
        .deployment("S-1-5-18", RestoreCompleted(wrong))
        .is_err());
    assert!(journal
        .append(journal::Event {
            kind: Kind::Deployment,
            actor: "S-1-5-18".into(),
            command: None,
            status: Status {
                revision: 4,
                exit_confirmed: Some(true),
                ..Status::default()
            },
            deployment: Some(RestoreCompleted(repair_change()))
        })
        .is_err());
    journal
        .deployment("S-1-5-18", RestoreUnchanged(repair_change()))
        .unwrap();
    assert!(!journal.has_pending_maintenance());
    assert_eq!(journal.configuration_digest(), Some([4; 32]));
}

#[test]
fn repair_audit_failure_never_clears_pending_state_or_committed_permissions() {
    use journal::DeploymentEvent::{RestoreBegin, RestoreCompleted};
    let memory = Memory::default();
    let mut journal = committed_configuration_journal(&memory);
    *memory.fail.lock().unwrap() = Some(Kind::Deployment);
    assert!(journal
        .deployment("S-1-5-18", RestoreBegin(repair_change()))
        .is_err());
    assert!(!journal.has_pending_maintenance());
    *memory.fail.lock().unwrap() = None;
    journal
        .deployment("S-1-5-18", RestoreBegin(repair_change()))
        .unwrap();
    *memory.fail.lock().unwrap() = Some(Kind::Deployment);
    assert!(journal
        .deployment("S-1-5-18", RestoreCompleted(repair_change()))
        .is_err());
    let journal = journal::Journal::open(Box::new(memory)).unwrap();
    assert!(journal.pending_repair().is_some());
    assert_eq!(journal.configuration_digest(), Some([4; 32]));
}
