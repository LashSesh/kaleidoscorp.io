//! The daemon's kill-switch answer, driven against a **real**
//! `ssk_netd_helper::Broker` (roadmap P3).
//!
//! # What is real here and what is not
//!
//! Real: the broker, its hash-chained journal, its `FileReceiptStore` on disk,
//! its peer authorization, the versioned handshake, the `[u32 BE][CBOR]`
//! framing, `PrivilegedServer`'s accept-and-dispatch loop, `PrivilegedClient`,
//! the daemon's `CachedBrokerView`, the whole `Supervisor` command path, and the
//! `StatusDto` a client would actually receive.
//!
//! Not real, and named rather than implied:
//!
//! * **The transport is a loopback TCP socket, not the LocalSystem-owned named
//!   pipe.** `FrameTransport` is the seam precisely so the framing and dispatch
//!   can be exercised without one; what a socket cannot exercise is the pipe's
//!   DACL, the `S-1-5-18` owner check, and the impersonation-based peer
//!   authentication. Those are `ssk-winhost`'s operator legs.
//! * **The firewall is a counting mock.** No OS enforcement is touched by this
//!   file — the machine it runs on is the developer's, unelevated.
//! * **Server and client are the same process and the same principal.** A
//!   genuinely different, non-allow-listed OS user being refused is untestable
//!   here for the same reason it was untestable in P2.
//!
//! What this file *does* establish is the thing it was written for: that the
//! daemon reports the broker's authoritative answer, and that when it cannot
//! obtain one it says so instead of reporting "off".

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/support/routing_config.rs"
));

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ssk_boundary::{
    BoundaryEnforcer, BoundaryError, BoundaryPolicy, BoundaryScope, EnforcementReceipt,
    BOUNDARY_CONTROL_USE,
};
use ssk_daemon::killswitch::{
    BrokerLinkError, BrokerStatusSource, CachedBrokerView, KillSwitchView, RefreshableKillSwitch,
    KILL_SWITCH_STATUS_UNKNOWN,
};
use ssk_daemon::supervisor::Supervisor;
use ssk_ipc::{CommandHandler, PeerIdentity as IpcPeer, StatusDto};
use ssk_netcore::{AdapterRegistry, DataPlane, NetcoreDataPlane, RouteExecutor};
use ssk_netd_helper::authz::{ControlVerb, PeerIdentity, PeerToken, TieredSidAuthorizer};
use ssk_netd_helper::client::{pinned_hello, session_hello, NonceSource, PrivilegedClient};
use ssk_netd_helper::framing::{FrameTransport, TransportError};
use ssk_netd_helper::server::{PrivilegedServer, SequentialLeaseIds};
use ssk_netd_helper::{
    AuthenticatedPeer, Broker, BrokerConfig, CapabilityToken, EgressObserver, FileReceiptStore,
    KillSwitchStatus,
};
use ssk_signature::policy::{AuthorizationPolicyTable, Principal, PrivilegedUse};
use ssk_signature::AuthorizationManifest;
use ssk_types::SessionId;

// ---------------------------------------------------------------------------
// The one thing that cannot be real: the firewall.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    /// What the enforcer did.
    severed: AtomicBool,
    /// What the *observer* sees. Kept separate from `severed` on purpose: the
    /// inconsistent case is exactly "the journal says engaged and the OS says
    /// the rule is gone", which requires the two to be able to disagree.
    rule_present: AtomicBool,
    engage_calls: AtomicU32,
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
        self.0.rule_present.store(true, Ordering::SeqCst);
        Ok(receipt)
    }

    fn release(&self, _receipt: &EnforcementReceipt) -> Result<(), BoundaryError> {
        self.0.severed.store(false, Ordering::SeqCst);
        self.0.rule_present.store(false, Ordering::SeqCst);
        Ok(())
    }
}

impl EgressObserver for MockObserver {
    fn rule_present(&self, _scope_label: &str) -> Option<bool> {
        Some(self.0.rule_present.load(Ordering::SeqCst))
    }
}

// ---------------------------------------------------------------------------
// A `FrameTransport` over a loopback socket.
// ---------------------------------------------------------------------------

struct SocketTransport(TcpStream);

impl FrameTransport for SocketTransport {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        match self.0.read(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(TransportError::TimedOut),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(TransportError::Closed),
            Err(e) => Err(TransportError::Io(e.to_string())),
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.0
            .write_all(bytes)
            .map_err(|e| TransportError::Io(e.to_string()))
    }

    fn flush(&mut self) -> Result<(), TransportError> {
        self.0
            .flush()
            .map_err(|e| TransportError::Io(e.to_string()))
    }
}

/// Process-wide unique nonces. The broker's anti-replay set spans connections,
/// so a per-client counter starting at zero would make the second connection
/// look like a replay of the first.
static NONCE: AtomicU64 = AtomicU64::new(1);

/// Per-connection lease-id salt, so two connections cannot mint the same claim
/// id.
static SALT: AtomicU64 = AtomicU64::new(1);

struct UniqueNonces;

impl NonceSource for UniqueNonces {
    fn next(&mut self) -> [u8; 16] {
        let n = NONCE.fetch_add(1, Ordering::SeqCst);
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&n.to_be_bytes());
        out
    }
}

// ---------------------------------------------------------------------------
// A broker behind a real accept loop.
// ---------------------------------------------------------------------------

const CLIENT_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";
const PRINCIPAL: &str = "ssk-netd-helper";

fn peer() -> AuthenticatedPeer {
    AuthenticatedPeer::new(
        PeerIdentity::parse_sid(CLIENT_SID).expect("a well-formed SID"),
        PeerToken::unprivileged(),
    )
}

fn broker(dir: &std::path::Path, state: Arc<MockState>) -> Broker {
    let authorizer = TieredSidAuthorizer::deny_all()
        .allow(
            PeerIdentity::parse_sid(CLIENT_SID).expect("sid"),
            ControlVerb::EngageKillSwitch,
        )
        .allow(
            PeerIdentity::parse_sid(CLIENT_SID).expect("sid"),
            ControlVerb::ReleaseKillSwitch,
        );
    let principal = Principal::parse(PRINCIPAL).expect("a well-formed principal");
    Broker::recover_privileged(
        BrokerConfig {
            session_token: CapabilityToken([7u8; 16]),
            actuation_auth: AuthorizationManifest::new(PRINCIPAL, "system", "privileged broker")
                .with_allowed_uses([BOUNDARY_CONTROL_USE])
                .with_principal(principal.clone()),
            scope: BoundaryScope::all_egress(),
            policy: BoundaryPolicy::default(),
            session: SessionId::new("ssk-daemon-kill-switch-test"),
        },
        AuthorizationPolicyTable::deny_all().allow(principal, PrivilegedUse::BoundaryControl),
        Box::new(authorizer),
        Box::new(FileReceiptStore::open_existing(dir).expect("scratch store")),
        Box::new(MockEnforcer(Arc::clone(&state))),
        Box::new(MockObserver(state)),
    )
    .expect("recover a privileged broker")
}

/// Serves `broker` on a loopback port until dropped.
struct Serving {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Serving {
    fn start(broker: Arc<Broker>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        listener.set_nonblocking(true).expect("nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut workers = Vec::new();
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).expect("blocking");
                            stream
                                .set_read_timeout(Some(Duration::from_secs(10)))
                                .expect("read timeout");
                            // One worker per connection, like the real host's
                            // listener pool. A single-connection-at-a-time loop
                            // would let a client that holds its connection open
                            // wedge every later read, which is a property of
                            // this fixture rather than of the broker.
                            let broker = Arc::clone(&broker);
                            workers.push(std::thread::spawn(move || {
                                let salt = SALT.fetch_add(1, Ordering::SeqCst).to_be_bytes();
                                let mut ids = SequentialLeaseIds::new(salt);
                                let server = PrivilegedServer::new(&broker);
                                let mut transport = SocketTransport(stream);
                                let _ = server.serve_connection(&mut transport, &peer(), &mut ids);
                            }));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
                for w in workers {
                    let _ = w.join();
                }
            })
        };
        Serving {
            addr,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The daemon-side source: one connection per read, exactly like the real
/// `PrivilegedPipeStatus`.
struct SocketBrokerSource {
    addr: SocketAddr,
}

impl BrokerStatusSource for SocketBrokerSource {
    fn status(&self) -> Result<KillSwitchStatus, BrokerLinkError> {
        let stream = TcpStream::connect_timeout(&self.addr, Duration::from_secs(2))
            .map_err(|e| BrokerLinkError::Unreachable(e.to_string()))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| BrokerLinkError::Unreachable(e.to_string()))?;
        let mut client =
            PrivilegedClient::connect(SocketTransport(stream), UniqueNonces, session_hello())
                .map_err(|e| BrokerLinkError::Refused(e.to_string()))?;
        client
            .status()
            .map_err(|e| BrokerLinkError::Refused(e.to_string()))
    }
}

/// Drive an engage as an authorized client, so the broker's state is changed
/// the way a real caller would change it — not by reaching into it.
///
/// The claim is [`ssk_netd_helper::LeaseKind::Pinned`], which is what an
/// operator typing `killswitch engage` means and, here, what lets the caller
/// disconnect without releasing. A `Session` claim would die with this
/// connection and un-sever the machine before the daemon ever read status.
fn engage_via_broker(addr: SocketAddr) {
    let stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let mut client =
        PrivilegedClient::connect(SocketTransport(stream), UniqueNonces, pinned_hello())
            .expect("handshake");
    client.engage().expect("engage");
}

// ---------------------------------------------------------------------------
// The daemon side.
// ---------------------------------------------------------------------------

fn real_data_plane() -> Box<dyn DataPlane> {
    Box::new(NetcoreDataPlane::new(Arc::new(RouteExecutor::new(
        AdapterRegistry::new(),
    ))))
}

fn ipc_peer() -> IpcPeer {
    #[cfg(unix)]
    {
        IpcPeer::Uid(0)
    }
    #[cfg(not(unix))]
    {
        IpcPeer::Sid("S-1-5-21-0-0-0-1000".into())
    }
}

/// Build a supervisor over `source`, poll the broker once, and return both the
/// `StatusDto` a client would receive and the view the daemon computed.
async fn daemon_status(source: SocketBrokerSource) -> (StatusDto, KillSwitchView) {
    let cached = Arc::new(CachedBrokerView::new(source));
    cached.refresh_once();
    let view = cached.view_now();
    let dir = tempfile::tempdir().expect("tempdir");
    let sup = Supervisor::new(
        dir.path().join("audit.json"),
        real_data_plane(),
        Box::new(Arc::clone(&cached)),
        Ok(loopback_config()),
    );
    let dto = match sup
        .handle(ssk_ipc::server::Request::GetStatus, &ipc_peer())
        .await
    {
        ssk_ipc::server::Response::Status(dto) => dto,
        other => panic!("expected a status response, got {other:?}"),
    };
    (dto, view)
}

/// `KillSwitchProvider::view` under a name that does not need the trait in
/// scope at every call site.
trait ViewNow {
    fn view_now(&self) -> KillSwitchView;
}

impl<T: ssk_daemon::killswitch::KillSwitchProvider + ?Sized> ViewNow for T {
    fn view_now(&self) -> KillSwitchView {
        self.view()
    }
}

// ---------------------------------------------------------------------------
// The four cases the phase asked for.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn broker_reachable_and_engaged_is_reported_as_engaged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(MockState::default());
    let b = Arc::new(broker(dir.path(), Arc::clone(&state)));
    let serving = Serving::start(Arc::clone(&b));

    engage_via_broker(serving.addr);
    assert_eq!(
        state.engage_calls.load(Ordering::SeqCst),
        1,
        "the enforcer must actually have been driven"
    );

    let (dto, view) = daemon_status(SocketBrokerSource { addr: serving.addr }).await;

    assert_eq!(view, KillSwitchView::EngagedConfirmed);
    assert!(
        dto.kill_switch,
        "an engagement the broker confirms must reach the wire as true"
    );
    assert!(
        dto.last_error.is_none(),
        "a confirmed answer carries no advisory: {:?}",
        dto.last_error
    );
}

#[tokio::test]
async fn broker_reachable_and_released_is_reported_as_not_engaged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(MockState::default());
    let b = Arc::new(broker(dir.path(), Arc::clone(&state)));
    let serving = Serving::start(Arc::clone(&b));

    // Engage, then let the connection (and therefore the only claim) go: the
    // broker releases when the last claim drops, which is the real "released"
    // path rather than a broker that was never engaged.
    {
        let stream = TcpStream::connect(serving.addr).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let mut client =
            PrivilegedClient::connect(SocketTransport(stream), UniqueNonces, session_hello())
                .expect("handshake");
        client.engage().expect("engage");
    }
    // The claim is dropped when the server observes the close; give the accept
    // loop a moment to finish that connection.
    for _ in 0..100 {
        if !state.severed.load(Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !state.severed.load(Ordering::SeqCst),
        "the session claim should have died with its connection"
    );

    let (dto, view) = daemon_status(SocketBrokerSource { addr: serving.addr }).await;

    assert_eq!(view, KillSwitchView::NotEngaged);
    assert!(!dto.kill_switch);
    assert!(
        dto.last_error.is_none(),
        "a definite 'not engaged' must be distinguishable from 'cannot tell'"
    );
}

#[tokio::test]
async fn an_unreachable_broker_is_reported_as_unknown_never_as_off() {
    // A port that is guaranteed closed: bound, its address read, then dropped.
    let addr = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr")
    };

    let (dto, view) = daemon_status(SocketBrokerSource { addr }).await;

    assert!(
        matches!(view, KillSwitchView::Unknown { .. }),
        "an unreachable broker must not produce a definite answer; got {view:?}"
    );
    assert!(!dto.kill_switch);
    let err = dto.last_error.expect(
        "an unreachable broker must be marked on the wire; a bare `kill_switch: false` here is \
         the fabricated-safe-value defect this seam replaced",
    );
    assert_eq!(err.code, KILL_SWITCH_STATUS_UNKNOWN);
    assert_eq!(err.class, "Boundary");
    assert!(err.retriable);
    assert!(
        !err.next_steps.is_empty(),
        "an operator must be told what to do about it"
    );
}

#[tokio::test]
async fn an_inconsistent_broker_is_reported_as_unknown_not_as_engaged_and_not_as_off() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(MockState::default());
    let b = Arc::new(broker(dir.path(), Arc::clone(&state)));
    let serving = Serving::start(Arc::clone(&b));

    engage_via_broker(serving.addr);

    // Someone removed the OS enforcement underneath the broker: the journal
    // still says Engaged, the observer now says the rule is absent. That is
    // `Recovery::Inconsistent` — a claim of severed egress with nothing behind
    // it, and the one case where reporting either `true` or a clean `false`
    // would be a lie in a different direction.
    state.rule_present.store(false, Ordering::SeqCst);

    let (dto, view) = daemon_status(SocketBrokerSource { addr: serving.addr }).await;

    assert!(
        matches!(view, KillSwitchView::Unknown { .. }),
        "an inconsistent broker must not produce a definite answer; got {view:?}"
    );
    assert!(
        !dto.kill_switch,
        "an unconfirmed severed-egress claim must not be reported as protection"
    );
    let err = dto
        .last_error
        .expect("an inconsistent broker must be marked on the wire");
    assert_eq!(err.code, KILL_SWITCH_STATUS_UNKNOWN);

    // And the broker really did say Inconsistent, so the assertion above is
    // about the daemon's mapping rather than about a coincidence.
    assert_eq!(
        b.status().recovery,
        ssk_netd_helper::Recovery::Inconsistent,
        "the fixture must actually have produced the inconsistent case"
    );
}

// ---------------------------------------------------------------------------
// Two properties the four cases above do not pin on their own.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_broker_that_dies_after_answering_does_not_leave_engaged_standing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(MockState::default());
    let b = Arc::new(broker(dir.path(), Arc::clone(&state)));
    let serving = Serving::start(Arc::clone(&b));
    engage_via_broker(serving.addr);

    let cached = Arc::new(CachedBrokerView::new(SocketBrokerSource {
        addr: serving.addr,
    }));
    cached.refresh_once();
    assert_eq!(cached.view_now(), KillSwitchView::EngagedConfirmed);

    // The broker goes away. The daemon must stop claiming protection at the
    // next poll — not keep repeating the last good answer.
    drop(serving);
    cached.refresh_once();
    let after = cached.view_now();
    assert!(
        matches!(after, KillSwitchView::Unknown { .. }),
        "a dead broker must retract the protection claim, not let it ride: got {after:?}"
    );
}

#[tokio::test]
async fn the_daemon_holds_no_privileged_connection_between_reads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(MockState::default());
    let b = Arc::new(broker(dir.path(), Arc::clone(&state)));
    let serving = Serving::start(Arc::clone(&b));

    let cached = Arc::new(CachedBrokerView::new(SocketBrokerSource {
        addr: serving.addr,
    }));
    for _ in 0..3 {
        cached.refresh_once();
        assert_eq!(cached.view_now(), KillSwitchView::NotEngaged);
    }

    // Reading status must never take a claim on the switch. If it did, a daemon
    // that polls every few seconds would be permanently holding the kill-switch
    // open, and its own liveness would become a security-relevant input.
    assert!(
        b.leases().is_empty(),
        "a status read must leave no claim behind: {:?}",
        b.leases()
    );
    assert_eq!(
        state.engage_calls.load(Ordering::SeqCst),
        0,
        "reading status must never actuate"
    );
}
