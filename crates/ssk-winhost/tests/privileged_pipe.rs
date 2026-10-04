//! The P3 privileged control plane, end to end, on a real Windows named pipe.
//!
//! Everything here is real except the two things that need Administrator or
//! LocalSystem: the firewall actuator (a counting mock) and the principal split
//! (server and client are the same unelevated user, because this machine has one
//! interactive account and a hard no-system-changes rule).
//!
//! What that means for what these tests prove — stated up front so a green run
//! is not over-read:
//!
//! * **Proven:** a real `ssk_netd_helper::Broker` is driven through a real
//!   `CreateNamedPipeW` instance carrying a real DACL, through real
//!   `ImpersonateNamedPipeClient` peer authentication, through the real framing
//!   and versioned handshake, by a real `PrivilegedClient` — and engage/release
//!   round-trips, lease claims die with the connection, an unlisted peer is
//!   refused, and the accept loop stops on demand.
//! * **Not proven:** that a *different* OS user is refused, that a
//!   SYSTEM-created pipe carries `O:SY`, that `0x12019b` denies instance
//!   creation across principals, or that any firewall rule was ever touched.
//!   Those are operator legs. See the crate's module docs and
//!   `docs/OPERATOR_VM_VALIDATION.md`.

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ssk_boundary::{
    BoundaryEnforcer, BoundaryError, BoundaryPolicy, BoundaryScope, EnforcementReceipt,
    KillSwitchState, BOUNDARY_CONTROL_USE,
};
use ssk_netd_helper::authz::{ControlVerb, PeerIdentity, TieredSidAuthorizer};
use ssk_netd_helper::client::{pinned_hello, session_hello, NonceSource, PrivilegedClient};
use ssk_netd_helper::framing::FrameTransport;
use ssk_netd_helper::lease::LeaseKind;
use ssk_netd_helper::{
    Broker, BrokerConfig, CapabilityToken, EgressObserver, FileReceiptStore, LeaseId,
};
use ssk_signature::policy::{AuthorizationPolicyTable, Principal, PrivilegedUse};
use ssk_signature::AuthorizationManifest;
use ssk_types::SessionId;
use ssk_winhost::privileged::{CsprngLeaseIds, NamedPipeClientTransport};
use ssk_winhost::{current_user_sid, PrivilegedPipeHost, PrivilegedPipeHostConfig};

// ---------------------------------------------------------------------------
// The one thing that cannot be real here: the firewall.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    severed: AtomicBool,
    engage_calls: AtomicU32,
    release_calls: AtomicU32,
}

struct MockEnforcer(Arc<MockState>);
struct MockObserver(Arc<MockState>);

impl BoundaryEnforcer for MockEnforcer {
    fn engage(&self, scope: &BoundaryScope) -> Result<EnforcementReceipt, BoundaryError> {
        self.0.engage_calls.fetch_add(1, Ordering::SeqCst);
        let prior = if self.0.severed.load(Ordering::SeqCst) {
            "severed"
        } else {
            "flowing"
        };
        let receipt = EnforcementReceipt::new(scope, prior);
        self.0.severed.store(true, Ordering::SeqCst);
        Ok(receipt)
    }

    fn release(&self, _receipt: &EnforcementReceipt) -> Result<(), BoundaryError> {
        self.0.release_calls.fetch_add(1, Ordering::SeqCst);
        self.0.severed.store(false, Ordering::SeqCst);
        Ok(())
    }
}

impl EgressObserver for MockObserver {
    fn rule_present(&self, _scope_label: &str) -> Option<bool> {
        Some(self.0.severed.load(Ordering::SeqCst))
    }
}

/// Deterministic nonces. The broker's anti-replay set is what makes them
/// matter, and a fixed sequence makes a replay reproducible.
struct CountingNonces(u128);

impl NonceSource for CountingNonces {
    fn next(&mut self) -> [u8; 16] {
        self.0 += 1;
        self.0.to_be_bytes()
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

static PIPE_COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique_pipe_name(tag: &str) -> String {
    let n = PIPE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\ssk-winhost-p3-{}-{tag}-{n}", std::process::id())
}

const PRINCIPAL: &str = "ssk-netd-helper";

fn actuation_manifest() -> AuthorizationManifest {
    AuthorizationManifest::new(PRINCIPAL, "system", "privileged broker")
        .with_allowed_uses([BOUNDARY_CONTROL_USE])
        .with_principal(Principal::parse(PRINCIPAL).expect("a well-formed principal"))
}

fn actuation_table() -> AuthorizationPolicyTable {
    AuthorizationPolicyTable::deny_all().allow(
        Principal::parse(PRINCIPAL).expect("a well-formed principal"),
        PrivilegedUse::BoundaryControl,
    )
}

/// A broker whose allow-list is exactly `granted`, backed by a real
/// `FileReceiptStore` in a scratch directory.
fn broker(
    dir: &std::path::Path,
    state: Arc<MockState>,
    granted: &[(PeerIdentity, ControlVerb)],
) -> Broker {
    let mut authorizer = TieredSidAuthorizer::deny_all();
    for (sid, verb) in granted {
        authorizer = authorizer.allow(sid.clone(), *verb);
    }
    Broker::recover_privileged(
        BrokerConfig {
            session_token: CapabilityToken([9u8; 16]),
            actuation_auth: actuation_manifest(),
            scope: BoundaryScope::all_egress(),
            policy: BoundaryPolicy::default(),
            session: SessionId::new("p3-privileged-pipe"),
        },
        actuation_table(),
        Box::new(authorizer),
        Box::new(FileReceiptStore::open_existing(dir).expect("scratch store")),
        Box::new(MockEnforcer(Arc::clone(&state))),
        Box::new(MockObserver(state)),
    )
    .expect("recover a privileged broker")
}

/// The unelevated developer identity this process runs as. It is both the
/// server principal and the client principal here — the limitation this file's
/// header names.
fn this_user() -> PeerIdentity {
    PeerIdentity::parse_sid(&current_user_sid().expect("this process must know its own SID"))
        .expect("a kernel-produced SID must satisfy the allow-list grammar")
}

/// Runs one listener on a background thread and stops it on drop, so a failing
/// assertion cannot leave a pipe (or a thread) behind.
struct Listening {
    host: Arc<PrivilegedPipeHost>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Listening {
    fn start(name: &str, broker: Arc<Broker>) -> Self {
        Self::start_with_vpn(name, broker, None)
    }

    fn start_with_vpn(
        name: &str,
        broker: Arc<Broker>,
        vpn: Option<Arc<ssk_netd_helper::vpn::Broker>>,
    ) -> Self {
        let sid = current_user_sid().expect("sid");
        let host = Arc::new(
            PrivilegedPipeHost::new(PrivilegedPipeHostConfig {
                pipe_name: name.to_owned(),
                // NOT the production descriptor: that one carries `O:SY` and an
                // unelevated process cannot create it. Same masks, same shape,
                // this user's SID in place of SYSTEM's.
                sddl: ssk_winhost::sddl_for_user_owned_pipe(&sid).expect("descriptor"),
                max_instances: 8,
            })
            .expect("host"),
        );
        let thread = {
            let host = Arc::clone(&host);
            std::thread::spawn(move || {
                let mut ids = CsprngLeaseIds::default();
                match host.run_listener_with_vpn(&broker, &mut ids, vpn.as_deref()) {
                    Ok(_report) => {}
                    Err(e) => panic!("listener failed: {e}"),
                }
            })
        };
        // Deliberately NO readiness probe here. `std::fs::metadata` on a pipe
        // path *opens* it, which consumes the listener's one pending instance
        // and makes the host count a connection that was never a client — a
        // measurement that changes what it measures. Callers wait by retrying
        // the real connect instead (see `client`).
        Listening {
            host,
            thread: Some(thread),
        }
    }
}

impl Drop for Listening {
    fn drop(&mut self) {
        self.host.stop_signal().stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Connect, tolerating the startup race.
///
/// `connect` itself retries `ERROR_PIPE_BUSY` because that is a real client
/// concern; it deliberately does **not** retry `ERROR_FILE_NOT_FOUND`, because
/// in production that means "no broker is running" and hanging on it would be
/// wrong. A test that has just spawned the listener is exactly the case where
/// waiting is correct, so the wait lives here rather than in the product.
fn client(name: &str) -> NamedPipeClientTransport {
    let sid = current_user_sid().expect("sid");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match NamedPipeClientTransport::connect(name, &sid) {
            Ok(t) => return t.with_read_timeout(Duration::from_secs(5)),
            Err(e) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
                let _ = e;
            }
            Err(e) => panic!("connect to the listener: {e}"),
        }
    }
}

/// A raw client handle that shares no code with the transport under test.
/// Same startup-race tolerance as [`client`].
fn raw_client(name: &str) -> std::fs::File {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(name)
        {
            Ok(f) => return f,
            Err(e) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
                let _ = e;
            }
            Err(e) => panic!("a raw client opens the pipe: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The headline: an authorized peer engages and releases the kill-switch
/// through the broker, over a real pipe, and the enforcer is actually driven.
#[test]
fn an_allow_listed_peer_engages_and_releases_through_the_real_pipe() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let name = unique_pipe_name("round-trip");
    let state = Arc::new(MockState::default());
    let me = this_user();
    let broker = Arc::new(broker(
        dir.path(),
        Arc::clone(&state),
        &[
            (me.clone(), ControlVerb::ReadStatus),
            (me.clone(), ControlVerb::EngageKillSwitch),
            (me, ControlVerb::ReleaseKillSwitch),
        ],
    ));
    let _listening = Listening::start(&name, Arc::clone(&broker));

    let mut c = PrivilegedClient::connect(client(&name), CountingNonces(0), session_hello())
        .expect("handshake");

    let status = c.status().expect("status is tier R and always answerable");
    assert_eq!(status.logical_state, KillSwitchState::Armed);

    let engaged = c.engage().expect("an allow-listed peer may engage");
    assert_eq!(engaged.logical_state, KillSwitchState::Engaged);
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 1);
    assert!(state.severed.load(Ordering::SeqCst));

    let released = c.release().expect("an allow-listed peer may release");
    assert_eq!(released.logical_state, KillSwitchState::Released);
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 1);
    assert!(!state.severed.load(Ordering::SeqCst));
}

/// The negative that carries the phase. An authenticated peer with **no** grant
/// is refused the mutating verb — and the refusal reaches it as a typed answer
/// over the same connection, not as a dropped pipe.
///
/// Paired in-test with the mutation that must break it: the *same* peer, the
/// *same* pipe, against a broker that granted the verb, succeeds. Without that
/// pairing "refused" could mean the pipe was simply broken.
#[test]
fn an_unlisted_peer_is_refused_the_mutating_verb_but_still_reads_status() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let name = unique_pipe_name("unlisted");
    let state = Arc::new(MockState::default());
    // Grant nothing at all. `ReadStatus` is tier R and needs no grant.
    let broker = Arc::new(broker(dir.path(), Arc::clone(&state), &[]));
    let _listening = Listening::start(&name, Arc::clone(&broker));

    let mut c = PrivilegedClient::connect(client(&name), CountingNonces(0), session_hello())
        .expect("handshake succeeds: authentication is not authorization");

    // Tier R still answers, so a severed machine stays diagnosable.
    let status = c.status().expect("status must remain readable");
    assert_eq!(status.logical_state, KillSwitchState::Armed);

    let err = c
        .engage()
        .expect_err("a peer with no grant must not be able to sever egress");
    assert!(
        err.to_string().to_lowercase().contains("author")
            || err.code().contains("REJECT")
            || err.code().contains("UNAUTH"),
        "the refusal must name authorization: code={} err={err}",
        err.code()
    );
    assert_eq!(
        state.engage_calls.load(Ordering::SeqCst),
        0,
        "the enforcer must never be reached by an unauthorized peer"
    );
    assert!(!state.severed.load(Ordering::SeqCst));
}

/// The complement of the test above, on a second broker: the identical peer and
/// the identical call succeed once the grant exists. This is what makes the
/// refusal attributable to the allow-list rather than to anything else.
#[test]
fn the_same_peer_and_the_same_call_succeed_once_the_grant_exists() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let name = unique_pipe_name("granted");
    let state = Arc::new(MockState::default());
    let broker = Arc::new(broker(
        dir.path(),
        Arc::clone(&state),
        &[(this_user(), ControlVerb::EngageKillSwitch)],
    ));
    let _listening = Listening::start(&name, Arc::clone(&broker));

    let mut c = PrivilegedClient::connect(client(&name), CountingNonces(0), session_hello())
        .expect("handshake");
    c.engage().expect("the grant is what changes the outcome");
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 1);

    // And an engage grant does not imply a release grant.
    let err = c.release().expect_err("tier C is per-verb, not per-tier");
    assert!(!err.to_string().is_empty());
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 0);
}

/// A session claim dies with the connection. This is the property that makes
/// the cross-session refcount structurally unable to leak: no connection
/// outlives the process that accepted it.
#[test]
fn a_session_claim_dies_when_the_connection_does() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let name = unique_pipe_name("session-claim");
    let state = Arc::new(MockState::default());
    let me = this_user();
    let broker = Arc::new(broker(
        dir.path(),
        Arc::clone(&state),
        &[
            (me.clone(), ControlVerb::EngageKillSwitch),
            (me, ControlVerb::ReleaseKillSwitch),
        ],
    ));
    let _listening = Listening::start(&name, Arc::clone(&broker));

    {
        let mut c = PrivilegedClient::connect(client(&name), CountingNonces(0), session_hello())
            .expect("handshake");
        c.engage().expect("engage");
        assert_eq!(broker.leases().len(), 1, "the connection holds one claim");
        assert!(state.severed.load(Ordering::SeqCst));
    }

    // The client is gone. The listener notices, and the claim goes with it.
    for _ in 0..200 {
        if broker.leases().is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        broker.leases().is_empty(),
        "a session claim must not survive its connection"
    );
    assert!(
        !state.severed.load(Ordering::SeqCst),
        "the last claim going away must actually restore egress"
    );
}

/// A pinned claim deliberately does *not* die with the connection — that is
/// what "an operator engaged this" means — and it can be adopted by a later
/// connection and released by id.
#[test]
fn a_pinned_claim_outlives_its_connection_and_can_be_adopted() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let name = unique_pipe_name("pinned-claim");
    let state = Arc::new(MockState::default());
    let me = this_user();
    let broker = Arc::new(broker(
        dir.path(),
        Arc::clone(&state),
        &[
            (me.clone(), ControlVerb::EngageKillSwitch),
            (me, ControlVerb::ReleaseKillSwitch),
        ],
    ));
    let _listening = Listening::start(&name, Arc::clone(&broker));

    let pinned: LeaseId = {
        let mut c = PrivilegedClient::connect(client(&name), CountingNonces(0), pinned_hello())
            .expect("handshake");
        c.engage().expect("engage");
        c.lease()
    };

    std::thread::sleep(Duration::from_millis(150));
    assert!(
        state.severed.load(Ordering::SeqCst),
        "a pinned claim keeps the machine severed after its connection ends"
    );
    let held = broker.leases();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].kind, LeaseKind::Pinned);
    assert_eq!(held[0].id, pinned);

    // A later connection adopts it by id and releases it.
    let mut c = PrivilegedClient::connect(
        client(&name),
        CountingNonces(1_000),
        ssk_netd_helper::handshake::ClientHello::adopting(pinned),
    )
    .expect("adopt the pinned claim");
    assert_eq!(c.lease(), pinned);
    c.release().expect("release the adopted claim");
    assert!(!state.severed.load(Ordering::SeqCst));
    assert!(broker.leases().is_empty());
}

/// The client's owner check, driven against the live endpoint. A pipe owned by
/// this user is refused when SYSTEM is demanded — which is exactly what would
/// happen to a squatter on the production name.
#[test]
fn a_client_refuses_an_endpoint_that_is_not_owned_by_the_expected_principal() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let name = unique_pipe_name("owner-check");
    let state = Arc::new(MockState::default());
    let broker = Arc::new(broker(dir.path(), Arc::clone(&state), &[]));
    let _listening = Listening::start(&name, Arc::clone(&broker));

    // Retry past the startup race (`NotFound` = the listener has not created
    // its first instance yet) without retrying past the answer we are after.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let err = loop {
        match NamedPipeClientTransport::connect(&name, ssk_winhost::LOCAL_SYSTEM_SID) {
            Ok(_) => panic!(
                "a user-owned pipe must be refused when the client requires the SYSTEM-owned \
                 broker"
            ),
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => break e,
        }
    };
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        err.to_string().contains("S-1-5-18"),
        "the refusal must name the principal that was required: {err}"
    );

    // And the same endpoint is accepted when the true owner is demanded, so the
    // refusal is about the owner and not about the pipe being unusable.
    let sid = current_user_sid().expect("sid");
    let mut transport =
        NamedPipeClientTransport::connect(&name, &sid).expect("the true owner is accepted");
    // The connection is live: a zero-length write is a real syscall.
    transport.write_all(&[]).expect("the pipe is usable");
}

/// The accept loop serves connection after connection, and stops when asked.
/// Without this, "the service honours Stop" rests on the SCM handler alone.
#[test]
fn the_listener_serves_repeatedly_and_stops_on_demand() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let name = unique_pipe_name("lifecycle");
    let state = Arc::new(MockState::default());
    let broker = Arc::new(broker(
        dir.path(),
        Arc::clone(&state),
        &[(this_user(), ControlVerb::ReadStatus)],
    ));
    let listening = Listening::start(&name, Arc::clone(&broker));

    for round in 0..3u128 {
        let mut c = PrivilegedClient::connect(
            client(&name),
            CountingNonces(round * 1_000),
            session_hello(),
        )
        .unwrap_or_else(|e| panic!("round {round} handshake: {e}"));
        c.status().unwrap_or_else(|e| panic!("round {round}: {e}"));
    }
    assert_eq!(listening.host.accepted(), 3);

    // Stopping must actually end the loop, within a small multiple of the
    // accept poll interval.
    listening.host.stop_signal().stop();
    let started = std::time::Instant::now();
    drop(listening);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the listener must return promptly after the stop signal, took {:?}",
        started.elapsed()
    );
}

/// A client that connects and says nothing must not hold the listener forever.
/// The bound is the transport's read timeout, and it is the only thing standing
/// between one hung peer and an unreachable kill-switch.
#[test]
fn a_silent_peer_does_not_wedge_the_listener() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let name = unique_pipe_name("silent");
    let state = Arc::new(MockState::default());
    let broker = Arc::new(broker(
        dir.path(),
        Arc::clone(&state),
        &[(this_user(), ControlVerb::ReadStatus)],
    ));
    let listening = Listening::start(&name, Arc::clone(&broker));

    // Open the pipe and write nothing at all.
    let silent = raw_client(&name);

    // The listener is now blocked reading the hello. It must recover on its own
    // once the timeout fires; until then a second client cannot be served,
    // which is the disclosed cost of a single listener.
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(listening.host.accepted(), 1);
    drop(silent);

    // With the silent peer gone, the next client is served normally.
    let mut c = PrivilegedClient::connect(client(&name), CountingNonces(0), session_hello())
        .expect("the listener must recover");
    c.status().expect("status");
    assert_eq!(listening.host.accepted(), 2);
}

#[test]
fn vpn_v3_authenticates_real_pipe_peer_and_never_dispatches_boundary_commands() {
    use ssk_netd_helper::{
        framing::{read_frame, write_frame},
        vpn::{
            self,
            journal::{Record, Store},
        },
        IdempotencyKey, Nonce,
    };
    struct Memory(Vec<Record>);
    impl Store for Memory {
        fn load(&mut self) -> std::io::Result<Vec<Record>> {
            Ok(self.0.clone())
        }
        fn append(&mut self, record: &Record) -> std::io::Result<()> {
            self.0.push(record.clone());
            Ok(())
        }
    }
    struct NoLaunch;
    impl vpn::Backend for NoLaunch {
        fn prepare(
            &mut self,
            _: &ssk_vpnctl::ProfileId,
            _: &AtomicBool,
            _: &mut dyn FnMut(vpn::ProcessIdentity) -> bool,
        ) -> Result<Box<dyn vpn::LiveSession>, vpn::PrepareError> {
            panic!("a status-only grant must never launch")
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(MockState::default());
    let boundary = Arc::new(broker(
        dir.path(),
        state.clone(),
        &[(this_user(), ControlVerb::EngageKillSwitch)],
    ));
    let policy = vpn::Policy::parse(
        &serde_json::to_vec(&serde_json::json!({"schema":1,"grants":[
            {"sid":current_user_sid().unwrap(),"profile":"corp","verbs":["status"]}
        ]}))
        .unwrap(),
    )
    .unwrap();
    let mut service = vpn::Service::start(
        policy,
        CapabilityToken([9; 16]),
        Box::new(Memory(vec![])),
        NoLaunch,
    )
    .unwrap();
    let name = unique_pipe_name("vpn-v3");
    let listening = Listening::start_with_vpn(&name, boundary.clone(), Some(service.broker()));
    {
        let mut client = vpn::client::Client::connect(client(&name)).unwrap();
        assert!(matches!(
            client
                .send(
                    vpn::Command {
                        verb: vpn::Verb::Status,
                        profile: "corp".into()
                    },
                    0,
                    IdempotencyKey([1; 16]),
                    Nonce([1; 16])
                )
                .unwrap(),
            vpn::Response::Status(_)
        ));
        assert_eq!(
            client
                .send(
                    vpn::Command {
                        verb: vpn::Verb::Prepare,
                        profile: "corp".into()
                    },
                    1,
                    IdempotencyKey([2; 16]),
                    Nonce([2; 16])
                )
                .unwrap(),
            vpn::Response::Rejected(vpn::Reject::Unauthorized)
        );
    }
    {
        let mut transport = client(&name);
        write_frame(
            &mut transport,
            &vpn::client::hello(),
            ssk_netd_helper::MAX_HANDSHAKE_FRAME,
        )
        .unwrap();
        let _: ssk_netd_helper::ServerHandshake =
            read_frame(&mut transport, ssk_netd_helper::MAX_HANDSHAKE_FRAME).unwrap();
        let legacy = ssk_netd_helper::CommandEnvelope {
            session_token: CapabilityToken([9; 16]),
            nonce: Nonce([3; 16]),
            idempotency_key: IdempotencyKey([3; 16]),
            expected_state_version: 0,
            command: ssk_netd_helper::Command::EngageKillSwitch,
        };
        write_frame(&mut transport, &legacy, vpn::protocol::MAX_FRAME).unwrap();
        let response: vpn::Response = read_frame(&mut transport, vpn::protocol::MAX_FRAME).unwrap();
        assert_eq!(response, vpn::Response::Rejected(vpn::Reject::Malformed));
    }
    {
        // v1 remains usable on the same listener with a v3 domain attached.
        let mut legacy =
            PrivilegedClient::connect(client(&name), CountingNonces(0), session_hello()).unwrap();
        assert_eq!(legacy.status().unwrap().state_version, 0);
    }
    drop(listening);
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0);
    assert!(boundary.leases().is_empty());
    assert_eq!(service.shutdown().phase, vpn::Phase::Shutdown);
}
