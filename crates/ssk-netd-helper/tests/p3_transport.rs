//! P3 — the privileged transport: framing, the versioned handshake, and the
//! serve loop, driven end to end through the **public** API.
//!
//! The transport under test is a pair of channel-backed byte streams, not a
//! named pipe. That is the point of the seam: everything from the length prefix
//! upward is portable Rust, so it can be attacked here rather than only on an
//! elevated Windows VM. What is **not** covered by any test in this file is
//! stated in the crate's own docs and in the operator checklist: pipe creation,
//! the SDDL, the peer token, the read timeout, and the client-side
//! owner-is-`S-1-5-18` check are syscalls in `ssk-winhost`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

use ssk_boundary::{
    BoundaryEnforcer, BoundaryError, BoundaryPolicy, BoundaryScope, EnforcementReceipt,
    KillSwitchState, BOUNDARY_CONTROL_USE,
};
use ssk_signature::policy::{AuthorizationPolicyTable, Principal, PrivilegedUse};
use ssk_signature::AuthorizationManifest;
use ssk_types::SessionId;

use ssk_netd_helper::{
    AuthenticatedPeer, Broker, BrokerConfig, BrokerResponse, CapabilityToken, ClientHello, Command,
    CommandEnvelope, ConnectionLimiter, ConnectionOutcome, ControlVerb, EgressObserver,
    FrameTransport, HandshakeReject, HelperError, IdempotencyKey, LeaseId, LeaseKind, Nonce,
    NonceSource, PeerIdentity, PeerToken, PersistedState, PrivilegedClient, PrivilegedServer,
    ReceiptStore, RejectReason, SequentialLeaseIds, ServerHandshake, TieredSidAuthorizer,
    TransportError, MAX_HANDSHAKE_FRAME, MAX_PRIV_FRAME, PRIV_MIN_PROTOCOL_VERSION,
    PRIV_PROTOCOL_VERSION,
};

const OPERATOR: &str = "S-1-5-21-650032732-2086122598-1934225963-1001";
const STRANGER: &str = "S-1-5-21-650032732-2086122598-1934225963-1002";
const BROKER_PRINCIPAL: &str = "ssk-netd-helper";

// ── fixtures ────────────────────────────────────────────────────────────────

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
        self.0.severed.store(true, Ordering::SeqCst);
        Ok(EnforcementReceipt::new(scope, "flowing"))
    }
    fn release(&self, _receipt: &EnforcementReceipt) -> Result<(), BoundaryError> {
        self.0.release_calls.fetch_add(1, Ordering::SeqCst);
        self.0.severed.store(false, Ordering::SeqCst);
        Ok(())
    }
}

impl EgressObserver for MockObserver {
    fn rule_present(&self, _scope: &str) -> Option<bool> {
        Some(self.0.severed.load(Ordering::SeqCst))
    }
}

#[derive(Default)]
struct MemStore(std::sync::Mutex<Option<PersistedState>>);
impl ReceiptStore for MemStore {
    fn save(&self, state: &PersistedState) -> Result<(), HelperError> {
        *self.0.lock().unwrap() = Some(state.clone());
        Ok(())
    }
    fn load(&self) -> Result<Option<PersistedState>, HelperError> {
        Ok(self.0.lock().unwrap().clone())
    }
}

fn actuation_auth() -> AuthorizationManifest {
    AuthorizationManifest::new(BROKER_PRINCIPAL, "system", "privileged broker")
        .with_allowed_uses([BOUNDARY_CONTROL_USE])
        .with_principal(Principal::parse(BROKER_PRINCIPAL).unwrap())
}

fn broker_table() -> AuthorizationPolicyTable {
    AuthorizationPolicyTable::deny_all().allow(
        Principal::parse(BROKER_PRINCIPAL).unwrap(),
        PrivilegedUse::BoundaryControl,
    )
}

fn operator_authorizer() -> TieredSidAuthorizer {
    let sid = PeerIdentity::parse_sid(OPERATOR).unwrap();
    TieredSidAuthorizer::deny_all()
        .allow(sid.clone(), ControlVerb::EngageKillSwitch)
        .allow(sid, ControlVerb::ReleaseKillSwitch)
}

fn privileged_broker(state: Arc<MockState>, authorizer: TieredSidAuthorizer) -> Broker {
    Broker::recover_privileged(
        BrokerConfig {
            session_token: CapabilityToken([0x5a; 16]),
            actuation_auth: actuation_auth(),
            scope: BoundaryScope::all_egress(),
            policy: BoundaryPolicy::default(),
            session: SessionId::new("sess-p3"),
        },
        broker_table(),
        Box::new(authorizer),
        Box::new(MemStore::default()),
        Box::new(MockEnforcer(state.clone())),
        Box::new(MockObserver(state)),
    )
    .unwrap()
}

fn peer(sid: &str) -> AuthenticatedPeer {
    AuthenticatedPeer::new(
        PeerIdentity::parse_sid(sid).unwrap(),
        PeerToken::unprivileged(),
    )
}

// ── a byte-stream pair, so client and server can run in two threads ─────────

struct ChannelTransport {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    pending: VecDeque<u8>,
}

impl FrameTransport for ChannelTransport {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        while self.pending.is_empty() {
            match self.rx.recv() {
                Ok(chunk) => self.pending.extend(chunk),
                // The far end dropped its transport: a clean close.
                Err(_) => return Ok(0),
            }
        }
        let n = buf.len().min(self.pending.len());
        for slot in buf.iter_mut().take(n) {
            *slot = self.pending.pop_front().expect("non-empty");
        }
        Ok(n)
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.tx
            .send(bytes.to_vec())
            .map_err(|_| TransportError::Closed)
    }
}

fn transport_pair() -> (ChannelTransport, ChannelTransport) {
    let (a_tx, b_rx) = channel();
    let (b_tx, a_rx) = channel();
    (
        ChannelTransport {
            tx: a_tx,
            rx: a_rx,
            pending: VecDeque::new(),
        },
        ChannelTransport {
            tx: b_tx,
            rx: b_rx,
            pending: VecDeque::new(),
        },
    )
}

/// A transport that replays a scripted inbound stream and records what the
/// server wrote — for the cases where the client is hostile and would never
/// finish a real handshake.
#[derive(Default)]
struct ScriptedTransport {
    inbound: Vec<u8>,
    cursor: usize,
    written: Vec<u8>,
    fail_read_at_eof: Option<TransportError>,
}

impl ScriptedTransport {
    fn frames_written(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut at = 0usize;
        while at + 4 <= self.written.len() {
            let len = u32::from_be_bytes([
                self.written[at],
                self.written[at + 1],
                self.written[at + 2],
                self.written[at + 3],
            ]) as usize;
            at += 4;
            if at + len > self.written.len() {
                break;
            }
            out.push(self.written[at..at + len].to_vec());
            at += len;
        }
        out
    }
}

impl FrameTransport for ScriptedTransport {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let remaining = self.inbound.len() - self.cursor;
        if remaining == 0 {
            return match self.fail_read_at_eof.clone() {
                Some(e) => Err(e),
                None => Ok(0),
            };
        }
        let n = remaining.min(buf.len());
        buf[..n].copy_from_slice(&self.inbound[self.cursor..self.cursor + n]);
        self.cursor += n;
        Ok(n)
    }
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.written.extend_from_slice(bytes);
        Ok(())
    }
}

fn framed<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut body = Vec::new();
    ciborium::ser::into_writer(value, &mut body).unwrap();
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

struct SeqNonces(u128);
impl NonceSource for SeqNonces {
    fn next(&mut self) -> [u8; 16] {
        self.0 += 1;
        self.0.to_le_bytes()
    }
}

/// Run one client closure against one served connection.
///
/// `nonce_seed` is per-connection on purpose. The broker's anti-replay window is
/// the **broker session**, not the connection (see `MAX_SESSION_MUTATIONS`), so
/// a second connection that restarted its nonce counter would have every command
/// refused as a replay — which is correct, and is asserted directly by
/// `a_second_connection_reusing_the_first_connections_nonces_is_refused`.
/// Production supplies a CSPRNG.
fn round_trip<R: Send>(
    broker: &Broker,
    peer: AuthenticatedPeer,
    hello: ClientHello,
    nonce_seed: u128,
    client_body: impl FnOnce(&mut PrivilegedClient<ChannelTransport, SeqNonces>) -> R + Send,
) -> (ConnectionOutcome, R) {
    let (client_side, mut server_side) = transport_pair();
    std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            let s = PrivilegedServer::new(broker);
            // A fresh source per connection is deliberately *not* what a real
            // accept loop does — it owns one source and mints from it, so ids
            // are distinct across connections. The salt here stands in for that,
            // and `minted_lease_ids_are_distinct_...` asserts the real property.
            let mut ids = SequentialLeaseIds::new((nonce_seed as u64).to_be_bytes());
            s.serve_connection(&mut server_side, &peer, &mut ids)
        });
        let mut client = PrivilegedClient::connect(client_side, SeqNonces(nonce_seed), hello)
            .expect("handshake");
        let out = client_body(&mut client);
        drop(client.into_transport());
        (server.join().expect("server thread"), out)
    })
}

// ── the happy path, end to end ──────────────────────────────────────────────

#[test]
fn a_granted_peer_engages_and_releases_over_the_real_framing() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state.clone(), operator_authorizer());

    let (outcome, (engaged, released)) = round_trip(
        &broker,
        peer(OPERATOR),
        ClientHello::new(LeaseKind::Session),
        1000,
        |client| {
            assert_eq!(client.protocol_version(), PRIV_PROTOCOL_VERSION);
            let status = client.status().expect("status");
            assert_eq!(status.logical_state, KillSwitchState::Armed);
            let engaged = client.engage().expect("engage");
            let released = client.release().expect("release");
            (engaged, released)
        },
    );

    assert_eq!(engaged.logical_state, KillSwitchState::Engaged);
    assert_eq!(engaged.state_version, 1);
    assert_eq!(released.logical_state, KillSwitchState::Released);
    assert_eq!(released.state_version, 2);
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 1);
    assert!(!state.severed.load(Ordering::SeqCst), "egress restored");

    match outcome {
        ConnectionOutcome::Served { frames, .. } => assert_eq!(frames, 3),
        other => panic!("{other:?}"),
    }
}

/// The whole point of `LeaseKind::Session`: the claim dies with the connection.
/// A holder that engages and then vanishes must not strand the machine.
#[test]
fn a_session_claim_is_dropped_when_the_connection_ends_and_egress_is_restored() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state.clone(), operator_authorizer());

    let (outcome, ()) = round_trip(
        &broker,
        peer(OPERATOR),
        ClientHello::new(LeaseKind::Session),
        2000,
        |client| {
            client.engage().expect("engage");
            assert!(state.severed.load(Ordering::SeqCst));
            // The client simply goes away without releasing.
        },
    );

    match outcome {
        ConnectionOutcome::Served {
            claim_dropped,
            lease_kind,
            ..
        } => {
            assert!(claim_dropped, "a session claim must be dropped on close");
            assert_eq!(lease_kind, LeaseKind::Session);
        }
        other => panic!("{other:?}"),
    }
    assert!(
        broker.leases().is_empty(),
        "no claim may outlive the connection that took it"
    );
    assert_eq!(broker.status().logical_state, KillSwitchState::Released);
    assert!(
        !state.severed.load(Ordering::SeqCst),
        "the machine must not be left severed with no holder"
    );
}

/// The opposite contract: an operator's pinned claim deliberately survives the
/// connection, because "engage" typed at a prompt means "stay severed".
#[test]
fn a_pinned_claim_survives_the_connection_that_took_it() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state.clone(), operator_authorizer());

    let (outcome, ()) = round_trip(
        &broker,
        peer(OPERATOR),
        ClientHello::new(LeaseKind::Pinned),
        3000,
        |client| {
            client.engage().expect("engage");
        },
    );

    match outcome {
        ConnectionOutcome::Served { claim_dropped, .. } => assert!(!claim_dropped),
        other => panic!("{other:?}"),
    }
    assert_eq!(broker.leases().len(), 1);
    assert_eq!(broker.leases()[0].kind, LeaseKind::Pinned);
    assert_eq!(
        broker.leases()[0].holder,
        OPERATOR,
        "the audited holder is the SID the transport authenticated"
    );
    assert!(state.severed.load(Ordering::SeqCst), "still severed");
}

/// Adopting is how the operator releases in a second session what they engaged
/// in a first.
#[test]
fn a_pinned_claim_can_be_adopted_by_a_later_connection_and_released() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state.clone(), operator_authorizer());

    let (_, lease) = round_trip(
        &broker,
        peer(OPERATOR),
        ClientHello::new(LeaseKind::Pinned),
        4000,
        |client| {
            client.engage().expect("engage");
            client.lease()
        },
    );
    assert!(state.severed.load(Ordering::SeqCst));

    let (_, released) = round_trip(
        &broker,
        peer(OPERATOR),
        ClientHello::adopting(lease),
        5000,
        |client| {
            assert_eq!(
                client.lease(),
                lease,
                "the server handed back the same claim"
            );
            client.release().expect("release")
        },
    );
    assert_eq!(released.logical_state, KillSwitchState::Released);
    assert!(broker.leases().is_empty());
    assert!(!state.severed.load(Ordering::SeqCst));
}

#[test]
fn adopting_a_claim_that_is_not_held_is_refused_at_the_handshake() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state, operator_authorizer());

    let (client_side, mut server_side) = transport_pair();
    let p = peer(OPERATOR);
    std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            let s = PrivilegedServer::new(&broker);
            let mut ids = SequentialLeaseIds::new(*b"p3testid");
            s.serve_connection(&mut server_side, &p, &mut ids)
        });
        let err = PrivilegedClient::connect(
            client_side,
            SeqNonces(0),
            ClientHello::adopting(LeaseId([0xab; 16])),
        )
        .expect_err("a claim nobody holds must not be mintable by the client");
        assert_eq!(err.code(), "PRIV_LEASE_UNAVAILABLE");
        match server.join().unwrap() {
            ConnectionOutcome::Refused(HandshakeReject::LeaseUnavailable(detail)) => {
                assert!(detail.contains("no claim"), "{detail}");
            }
            other => panic!("{other:?}"),
        }
    });
}

// ── two holders: the refcount ───────────────────────────────────────────────

/// Two connections both want egress severed. The first release must **not**
/// restore egress — that is the entire reason the refcount exists.
#[test]
fn two_holders_mean_the_first_release_does_not_restore_egress() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state.clone(), operator_authorizer());

    let (_, first_lease) = round_trip(
        &broker,
        peer(OPERATOR),
        ClientHello::new(LeaseKind::Pinned),
        6000,
        |client| {
            client.engage().expect("first engage");
            client.lease()
        },
    );

    let (_, second_lease) = round_trip(
        &broker,
        peer(OPERATOR),
        ClientHello::new(LeaseKind::Pinned),
        7000,
        |client| {
            let status = client.engage().expect("second engage");
            assert_eq!(status.logical_state, KillSwitchState::Engaged);
            client.lease()
        },
    );
    assert_ne!(first_lease, second_lease, "two distinct claims");
    assert_eq!(broker.leases().len(), 2);
    assert_eq!(
        state.engage_calls.load(Ordering::SeqCst),
        1,
        "the OS effect is applied once, not once per holder"
    );

    // Holder one lets go.
    round_trip(
        &broker,
        peer(OPERATOR),
        ClientHello::adopting(first_lease),
        8000,
        |client| {
            let status = client.release().expect("release one");
            assert_eq!(
                status.logical_state,
                KillSwitchState::Engaged,
                "still engaged: another holder still wants it"
            );
        },
    );
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 0);
    assert!(state.severed.load(Ordering::SeqCst));

    // Holder two lets go: now, and only now, egress comes back.
    round_trip(
        &broker,
        peer(OPERATOR),
        ClientHello::adopting(second_lease),
        9000,
        |client| {
            let status = client.release().expect("release two");
            assert_eq!(status.logical_state, KillSwitchState::Released);
        },
    );
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 1);
    assert!(!state.severed.load(Ordering::SeqCst));
}

// ── authorization is on the served path, not only on the broker API ────────

/// The transport-level counterpart to `p3_authorization.rs`: an unlisted peer
/// that completes a perfectly valid handshake still cannot sever egress. This
/// exists because a mutation that deletes the authorization call from
/// `handle_from_peer` was otherwise invisible to every test in *this* file —
/// the positive path stays green under it, which is exactly the shape of
/// evidence that proves nothing.
#[test]
fn an_unlisted_peer_completes_the_handshake_and_is_still_refused_the_verb() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state.clone(), operator_authorizer());

    let (outcome, (status, engage)) = round_trip(
        &broker,
        peer(STRANGER),
        ClientHello::new(LeaseKind::Session),
        31_000,
        |client| {
            // Tier R: reading is allowed, so the machine stays diagnosable.
            let status = client.status().expect("status is readable");
            // Tier C: severing is not.
            let engage = client
                .exchange(Command::EngageKillSwitch)
                .expect("exchange");
            (status, engage)
        },
    );

    assert_eq!(status.logical_state, KillSwitchState::Armed);
    match engage {
        BrokerResponse::Rejected(RejectReason::PeerUnauthorized { code, .. }) => {
            assert_eq!(code, "PEER_NOT_GRANTED");
        }
        other => panic!("an unlisted peer must not be able to sever egress: {other:?}"),
    }
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0);
    assert!(!state.severed.load(Ordering::SeqCst));
    assert!(broker.leases().is_empty());
    assert!(
        matches!(outcome, ConnectionOutcome::Served { .. }),
        "{outcome:?}"
    );
}

// ── the handshake, attacked ─────────────────────────────────────────────────

fn serve_scripted(broker: &Broker, inbound: Vec<u8>) -> (ConnectionOutcome, ScriptedTransport) {
    let mut t = ScriptedTransport {
        inbound,
        ..ScriptedTransport::default()
    };
    let s = PrivilegedServer::new(broker);
    let mut ids = SequentialLeaseIds::new(*b"p3testid");
    let outcome = s.serve_connection(&mut t, &peer(OPERATOR), &mut ids);
    (outcome, t)
}

#[test]
fn a_hello_with_the_wrong_magic_is_refused_and_nothing_is_served() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state.clone(), operator_authorizer());
    let mut hello = ClientHello::new(LeaseKind::Session);
    hello.magic = *b"HTTP/1.1";

    let (outcome, transport) = serve_scripted(&broker, framed(&hello));
    assert_eq!(
        outcome,
        ConnectionOutcome::Refused(HandshakeReject::BadMagic)
    );
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0);

    let frames = transport.frames_written();
    assert_eq!(frames.len(), 1, "one rejection frame, then nothing");
    let answer: ServerHandshake = ciborium::de::from_reader(&frames[0][..]).unwrap();
    assert_eq!(
        answer,
        ServerHandshake::Rejected(HandshakeReject::BadMagic),
        "the client is told why, rather than seeing a dropped connection"
    );
}

#[test]
fn a_client_speaking_only_a_future_version_is_refused_with_both_ranges() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state, operator_authorizer());
    let mut hello = ClientHello::new(LeaseKind::Session);
    hello.min_protocol_version = ssk_netd_helper::vpn::protocol::PROTOCOL_VERSION + 1;
    hello.max_protocol_version = ssk_netd_helper::vpn::protocol::PROTOCOL_VERSION + 1;

    let (outcome, _) = serve_scripted(&broker, framed(&hello));
    assert_eq!(
        outcome,
        ConnectionOutcome::Refused(HandshakeReject::VersionMismatch {
            server_min: PRIV_MIN_PROTOCOL_VERSION,
            server_max: PRIV_PROTOCOL_VERSION,
            client_min: ssk_netd_helper::vpn::protocol::PROTOCOL_VERSION + 1,
            client_max: ssk_netd_helper::vpn::protocol::PROTOCOL_VERSION + 1,
        })
    );
}

/// The pre-auth allocation bound on the served path: a peer that has proved
/// nothing declares a 4 GiB hello. It must cost four bytes, and the connection
/// must die rather than continue on a desynchronised stream.
#[test]
fn an_oversized_hello_frame_kills_the_connection_before_any_body_is_read() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state.clone(), operator_authorizer());

    let (outcome, transport) = serve_scripted(&broker, u32::MAX.to_be_bytes().to_vec());
    match outcome {
        ConnectionOutcome::TransportFailed(e) => {
            assert_eq!(e.code(), "PRIV_FRAME_TOO_LARGE");
        }
        other => panic!("{other:?}"),
    }
    assert!(
        transport.frames_written().is_empty(),
        "nothing is written back on a desynchronised stream"
    );
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn a_hello_over_the_handshake_cap_is_refused_even_though_it_is_under_the_command_cap() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state, operator_authorizer());
    let big = vec![0u8; MAX_HANDSHAKE_FRAME + 1];
    assert!(big.len() < MAX_PRIV_FRAME);
    let mut inbound = (big.len() as u32).to_be_bytes().to_vec();
    inbound.extend_from_slice(&big);

    let (outcome, _) = serve_scripted(&broker, inbound);
    match outcome {
        ConnectionOutcome::TransportFailed(e) => assert_eq!(e.code(), "PRIV_FRAME_TOO_LARGE"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn garbage_in_place_of_a_hello_is_refused_as_malformed() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state, operator_authorizer());
    let (outcome, transport) = serve_scripted(&broker, {
        let body = [0xffu8, 0xff, 0xff];
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    });
    match outcome {
        ConnectionOutcome::Refused(HandshakeReject::Malformed(_)) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(
        transport.frames_written().len(),
        1,
        "a typed rejection is sent"
    );
}

// ── the command loop, attacked ──────────────────────────────────────────────

/// A malformed *body* is answerable — the frame boundary came from the length
/// prefix, so the stream is still synchronised. The connection stays usable and
/// the peer gets a typed rejection.
#[test]
fn a_malformed_command_body_is_answered_and_the_connection_survives() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state.clone(), operator_authorizer());

    let mut inbound = framed(&ClientHello::new(LeaseKind::Session));
    // A body that is valid CBOR but not a CommandEnvelope.
    inbound.extend({
        let mut body = Vec::new();
        ciborium::ser::into_writer(&"not an envelope", &mut body).unwrap();
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    });
    // ...followed by a well-formed status read on the same connection.
    inbound.extend(framed(&CommandEnvelope {
        session_token: broker.session_token(),
        nonce: Nonce([1u8; 16]),
        idempotency_key: IdempotencyKey([1u8; 16]),
        expected_state_version: 0,
        command: Command::GetStatus,
    }));

    let (outcome, transport) = serve_scripted(&broker, inbound);
    match outcome {
        ConnectionOutcome::Served { frames, .. } => assert_eq!(frames, 2),
        other => panic!("{other:?}"),
    }
    let frames = transport.frames_written();
    assert_eq!(frames.len(), 3, "hello + two responses");
    let first: BrokerResponse = ciborium::de::from_reader(&frames[1][..]).unwrap();
    assert_eq!(
        first,
        BrokerResponse::Rejected(RejectReason::MalformedCommand)
    );
    let second: BrokerResponse = ciborium::de::from_reader(&frames[2][..]).unwrap();
    assert!(matches!(second, BrokerResponse::Ok(_)), "{second:?}");
}

/// Bytes appended after a well-formed envelope are a smuggling attempt, not a
/// well-formed command with a suffix.
#[test]
fn trailing_bytes_after_a_valid_envelope_are_refused() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state.clone(), operator_authorizer());

    let envelope = CommandEnvelope {
        session_token: broker.session_token(),
        nonce: Nonce([1u8; 16]),
        idempotency_key: IdempotencyKey([1u8; 16]),
        expected_state_version: 0,
        command: Command::EngageKillSwitch,
    };
    let mut body = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut body).unwrap();
    body.push(0x00);

    let mut inbound = framed(&ClientHello::new(LeaseKind::Session));
    inbound.extend({
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    });

    let (_, transport) = serve_scripted(&broker, inbound);
    let frames = transport.frames_written();
    let response: BrokerResponse = ciborium::de::from_reader(&frames[1][..]).unwrap();
    assert_eq!(
        response,
        BrokerResponse::Rejected(RejectReason::MalformedCommand)
    );
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0, "no OS effect");
}

#[test]
fn an_oversized_command_frame_kills_the_connection_after_a_valid_handshake() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state, operator_authorizer());
    let mut inbound = framed(&ClientHello::new(LeaseKind::Session));
    inbound.extend(u32::MAX.to_be_bytes());

    let (outcome, _) = serve_scripted(&broker, inbound);
    match outcome {
        ConnectionOutcome::TransportFailed(e) => assert_eq!(e.code(), "PRIV_FRAME_TOO_LARGE"),
        other => panic!("{other:?}"),
    }
}

/// A transport that reports [`TransportError::TimedOut`] is what a real
/// implementation of the read timeout looks like from this side of the seam.
/// The serve loop must treat it as fatal rather than spin.
#[test]
fn a_read_timeout_ends_the_connection() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state, operator_authorizer());
    let mut t = ScriptedTransport {
        inbound: framed(&ClientHello::new(LeaseKind::Session)),
        fail_read_at_eof: Some(TransportError::TimedOut),
        ..ScriptedTransport::default()
    };
    let s = PrivilegedServer::new(&broker);
    let mut ids = SequentialLeaseIds::new(*b"p3testid");
    match s.serve_connection(&mut t, &peer(OPERATOR), &mut ids) {
        ConnectionOutcome::TransportFailed(e) => assert_eq!(e.code(), "PRIV_READ_TIMEOUT"),
        other => panic!("{other:?}"),
    }
}

// ── the connection cap ──────────────────────────────────────────────────────

#[test]
fn the_connection_cap_refuses_with_a_typed_answer_and_serves_nothing() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state.clone(), operator_authorizer());
    let limiter = ConnectionLimiter::new(1);
    let _held = limiter.try_acquire().expect("occupy the only slot");

    let mut t = ScriptedTransport {
        inbound: framed(&ClientHello::new(LeaseKind::Session)),
        ..ScriptedTransport::default()
    };
    let s = PrivilegedServer::with_limiter(&broker, limiter);
    let mut ids = SequentialLeaseIds::new(*b"p3testid");
    let outcome = s.serve_connection(&mut t, &peer(OPERATOR), &mut ids);

    assert_eq!(
        outcome,
        ConnectionOutcome::Refused(HandshakeReject::AtCapacity)
    );
    assert_eq!(
        t.cursor, 0,
        "a refused connection must not even read the peer's hello"
    );
    let frames = t.frames_written();
    assert_eq!(frames.len(), 1);
    let answer: ServerHandshake = ciborium::de::from_reader(&frames[0][..]).unwrap();
    assert_eq!(
        answer,
        ServerHandshake::Rejected(HandshakeReject::AtCapacity)
    );
}

#[test]
fn a_served_connection_returns_its_slot() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state, operator_authorizer());
    let limiter = ConnectionLimiter::new(1);
    let s = PrivilegedServer::with_limiter(&broker, limiter.clone());
    let mut ids = SequentialLeaseIds::new(*b"p3testid");
    for _ in 0..3 {
        let mut t = ScriptedTransport {
            inbound: framed(&ClientHello::new(LeaseKind::Session)),
            ..ScriptedTransport::default()
        };
        let outcome = s.serve_connection(&mut t, &peer(OPERATOR), &mut ids);
        assert!(
            matches!(outcome, ConnectionOutcome::Served { .. }),
            "{outcome:?}"
        );
        assert_eq!(limiter.active(), 0, "the slot is returned each time");
    }
}

/// The anti-replay window is the **broker session**, not the connection: a new
/// connection does not reset it. A client whose nonce source restarts from a
/// fixed seed therefore has its commands refused as replays — which is correct,
/// and is why production must supply a CSPRNG rather than a counter.
///
/// Asserted rather than left implicit, because the opposite (per-connection
/// nonce sets) would let anyone who can open a second connection replay the
/// first connection's engage.
#[test]
fn a_second_connection_reusing_the_first_connections_nonces_is_refused_as_a_replay() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state.clone(), operator_authorizer());

    round_trip(
        &broker,
        peer(OPERATOR),
        ClientHello::new(LeaseKind::Pinned),
        7,
        |client| {
            client.engage().expect("first engage");
        },
    );

    let (_, replayed) = round_trip(
        &broker,
        peer(OPERATOR),
        ClientHello::new(LeaseKind::Pinned),
        7, // the same nonce seed as above
        |client| {
            client
                .exchange(Command::ReleaseKillSwitch)
                .expect("exchange")
        },
    );
    assert_eq!(
        replayed,
        BrokerResponse::Rejected(RejectReason::ReplayedNonce)
    );
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 0);
    assert!(state.severed.load(Ordering::SeqCst), "still severed");
}

// ── adoption is authorization-gated (the P3→P4 regression) ─────────────────
//
// Reproduced against the **real** `Broker`/store/dispatch/handshake/framing
// stack — only the enforcer and observer are mocked — exactly as an
// adversarial reviewer found it: a connecting peer names someone else's
// durable `Pinned` claim in `hello.adopt_lease`, self-declares
// `hello.lease_kind: Session` on its *own* hello (not the claim's real kind),
// sends zero commands, and disconnects. Before the fix, the disconnect
// handler trusted that self-declared field to decide whether to drop the
// *adopted* claim, so this un-severed the machine with no authorization
// check anywhere on the path — for a peer who never held `ReleaseKillSwitch`,
// and even for a peer with no grant whatsoever. After the fix, adoption of
// someone else's `Pinned` claim itself requires `ControlVerb::ReleaseKillSwitch`
// (`Broker::adopt_lease`), so neither peer below ever receives a lease to
// drop in the first place.

/// A hand-built hello, deliberately **not** `ClientHello::adopting` (which
/// forces `LeaseKind::Pinned`): the exploit's exact wire shape is an adopting
/// hello that self-declares `Session` on someone else's `Pinned` claim.
fn adopting_session_hello(id: LeaseId) -> ClientHello {
    ClientHello {
        lease_kind: LeaseKind::Session,
        adopt_lease: Some(id),
        ..ClientHello::new(LeaseKind::Session)
    }
}

/// Drive one connection to completion whose handshake is expected to be
/// **refused** — so the client side never gets a lease at all, unlike
/// `round_trip` which asserts the handshake succeeds.
fn refused_round_trip(
    broker: &Broker,
    peer: AuthenticatedPeer,
    hello: ClientHello,
    nonce_seed: u128,
    lease_salt: [u8; 8],
) -> ConnectionOutcome {
    let (client_side, mut server_side) = transport_pair();
    std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            let s = PrivilegedServer::new(broker);
            let mut ids = SequentialLeaseIds::new(lease_salt);
            s.serve_connection(&mut server_side, &peer, &mut ids)
        });
        let err = PrivilegedClient::connect(client_side, SeqNonces(nonce_seed), hello)
            .expect_err("a refused adoption must not complete the handshake");
        assert_eq!(err.code(), "PRIV_PEER_REFUSED");
        server.join().expect("server thread")
    })
}

/// **Exploit variant 1: an engage-only peer.** Peer A (`OPERATOR`) holds a
/// real `Pinned` claim, taken under a real `EngageKillSwitch` grant. Peer B is
/// granted `EngageKillSwitch` **and nothing else** — no `ReleaseKillSwitch` —
/// and tries to adopt A's claim. This must be refused at the handshake, and
/// nothing about A's claim or the machine's severed state may change.
#[test]
fn an_engage_only_peer_cannot_adopt_and_drop_someone_elses_pinned_claim() {
    const ENGAGE_ONLY: &str = "S-1-5-21-650032732-2086122598-1934225963-1003";
    let state = Arc::new(MockState::default());
    let authorizer = TieredSidAuthorizer::deny_all()
        .allow(
            PeerIdentity::parse_sid(OPERATOR).unwrap(),
            ControlVerb::EngageKillSwitch,
        )
        .allow(
            PeerIdentity::parse_sid(OPERATOR).unwrap(),
            ControlVerb::ReleaseKillSwitch,
        )
        .allow(
            PeerIdentity::parse_sid(ENGAGE_ONLY).unwrap(),
            ControlVerb::EngageKillSwitch,
        );
    let broker = privileged_broker(state.clone(), authorizer);

    // Peer A engages for real: a durable Pinned claim, egress severed.
    let (_, a_lease) = round_trip(
        &broker,
        peer(OPERATOR),
        ClientHello::new(LeaseKind::Pinned),
        50_000,
        |client| {
            client.engage().expect("A engages");
            client.lease()
        },
    );
    assert!(state.severed.load(Ordering::SeqCst));
    assert_eq!(broker.leases().len(), 1);
    assert_eq!(broker.leases()[0].holder, OPERATOR);

    // Peer B (engage-only grant, no release) tries to adopt A's claim,
    // self-declaring `lease_kind: Session`, and sends zero commands before
    // hanging up.
    let outcome = refused_round_trip(
        &broker,
        peer(ENGAGE_ONLY),
        adopting_session_hello(a_lease),
        51_000,
        *b"engageon",
    );
    match outcome {
        ConnectionOutcome::Refused(HandshakeReject::PeerRefused(detail)) => {
            assert!(detail.contains(ENGAGE_ONLY), "{detail}");
            assert!(detail.contains("release_kill_switch"), "{detail}");
        }
        other => panic!("{other:?}"),
    }

    // The critical invariant: nothing changed. A's claim is untouched, egress
    // is still severed, and the enforcer's release was never called.
    assert_eq!(
        state.release_calls.load(Ordering::SeqCst),
        0,
        "an unauthorized adoption must never reach the enforcer"
    );
    assert!(
        state.severed.load(Ordering::SeqCst),
        "must still be severed"
    );
    assert_eq!(broker.leases().len(), 1);
    assert_eq!(broker.leases()[0].id, a_lease);
    assert_eq!(broker.leases()[0].holder, OPERATOR);
}

/// **Exploit variant 2: a zero-grant peer.** Identical to variant 1, except
/// the adopting peer (`STRANGER`) holds no grant whatsoever — not even
/// `EngageKillSwitch`. This is the "worse" case the adversarial review named:
/// adoption must be refused even harder here, and the outcome must be
/// identical in every observable way to variant 1.
#[test]
fn a_zero_grant_peer_cannot_adopt_and_drop_someone_elses_pinned_claim() {
    let state = Arc::new(MockState::default());
    // STRANGER is deliberately absent from every `.allow(...)` call: zero
    // grants at all, not even ReadStatus-adjacent Tier C engage.
    let authorizer = TieredSidAuthorizer::deny_all()
        .allow(
            PeerIdentity::parse_sid(OPERATOR).unwrap(),
            ControlVerb::EngageKillSwitch,
        )
        .allow(
            PeerIdentity::parse_sid(OPERATOR).unwrap(),
            ControlVerb::ReleaseKillSwitch,
        );
    let broker = privileged_broker(state.clone(), authorizer);

    let (_, a_lease) = round_trip(
        &broker,
        peer(OPERATOR),
        ClientHello::new(LeaseKind::Pinned),
        52_000,
        |client| {
            client.engage().expect("A engages");
            client.lease()
        },
    );
    assert!(state.severed.load(Ordering::SeqCst));

    let outcome = refused_round_trip(
        &broker,
        peer(STRANGER),
        adopting_session_hello(a_lease),
        53_000,
        *b"zerogran",
    );
    match outcome {
        ConnectionOutcome::Refused(HandshakeReject::PeerRefused(detail)) => {
            assert!(detail.contains(STRANGER), "{detail}");
            assert!(detail.contains("release_kill_switch"), "{detail}");
        }
        other => panic!("{other:?}"),
    }

    assert_eq!(state.release_calls.load(Ordering::SeqCst), 0);
    assert!(
        state.severed.load(Ordering::SeqCst),
        "must still be severed"
    );
    assert_eq!(broker.leases().len(), 1);
    assert_eq!(broker.leases()[0].id, a_lease);
    assert_eq!(broker.leases()[0].holder, OPERATOR);
}

/// **The fail-safe survives.** A peer granted `EngageKillSwitch` **alone** —
/// never `ReleaseKillSwitch` — takes their own `Session` claim (no adoption
/// involved) and vanishes without releasing. The connection's natural end
/// must still drop the claim and restore egress, with **no fresh grant**:
/// this is the property `Broker::close_lease`'s doc now states explicitly is
/// still safe, and it must not have been collateral damage from gating
/// adoption.
#[test]
fn an_engage_only_peers_own_natural_session_disconnect_still_restores_egress() {
    const ENGAGE_ONLY: &str = "S-1-5-21-650032732-2086122598-1934225963-1004";
    let state = Arc::new(MockState::default());
    let authorizer = TieredSidAuthorizer::deny_all().allow(
        PeerIdentity::parse_sid(ENGAGE_ONLY).unwrap(),
        ControlVerb::EngageKillSwitch,
    );
    let broker = privileged_broker(state.clone(), authorizer);

    let (outcome, ()) = round_trip(
        &broker,
        peer(ENGAGE_ONLY),
        ClientHello::new(LeaseKind::Session),
        60_000,
        |client| {
            client
                .engage()
                .expect("an engage-only peer may still engage");
            assert!(state.severed.load(Ordering::SeqCst));
            // The client vanishes without releasing. No adoption happened on
            // this connection — this is the peer's own claim, taken and
            // dropped on the same connection.
        },
    );

    match outcome {
        ConnectionOutcome::Served {
            claim_dropped,
            lease_kind,
            ..
        } => {
            assert!(
                claim_dropped,
                "a session claim must be dropped on close even with no Release grant"
            );
            assert_eq!(lease_kind, LeaseKind::Session);
        }
        other => panic!("{other:?}"),
    }
    assert!(
        broker.leases().is_empty(),
        "no claim may outlive the connection that took it"
    );
    assert_eq!(broker.status().logical_state, KillSwitchState::Released);
    assert!(
        !state.severed.load(Ordering::SeqCst),
        "the fail-safe must restore egress without a fresh grant"
    );
}

// ── lease ids ───────────────────────────────────────────────────────────────

#[test]
fn minted_lease_ids_are_distinct_and_never_collide_with_the_in_process_lease() {
    let mut ids = SequentialLeaseIds::new([0xff; 8]);
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..1000 {
        let id = ssk_netd_helper::LeaseIdSource::next(&mut ids);
        assert_ne!(id, LeaseId::IN_PROCESS);
        assert!(seen.insert(id), "a lease id was minted twice");
    }
}

// ── the transport is genuinely transport-agnostic ───────────────────────────

/// Every byte the server writes is framed CBOR with nothing else in it: no
/// text protocol, no sentinel, nothing that depends on what the byte stream
/// underneath happens to be.
#[test]
fn the_wire_is_nothing_but_length_prefixed_cbor() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state, operator_authorizer());
    let (_, transport) = serve_scripted(&broker, framed(&ClientHello::new(LeaseKind::Session)));

    let mut at = 0usize;
    let mut frames = 0usize;
    while at < transport.written.len() {
        assert!(
            at + 4 <= transport.written.len(),
            "a truncated length prefix"
        );
        let len = u32::from_be_bytes([
            transport.written[at],
            transport.written[at + 1],
            transport.written[at + 2],
            transport.written[at + 3],
        ]) as usize;
        at += 4;
        assert!(len <= MAX_PRIV_FRAME);
        assert!(at + len <= transport.written.len());
        let mut cursor = std::io::Cursor::new(&transport.written[at..at + len]);
        let _: ciborium::value::Value =
            ciborium::de::from_reader(&mut cursor).expect("every frame body is CBOR");
        assert_eq!(
            cursor.position() as usize,
            len,
            "no trailing bytes in a frame"
        );
        at += len;
        frames += 1;
    }
    assert_eq!(frames, 1);
}

#[test]
fn vpn_version_three_without_a_configured_domain_reports_unavailable() {
    use ssk_netd_helper::vpn;
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state.clone(), operator_authorizer());
    let mut bytes = framed(&vpn::client::hello());
    bytes.extend(framed(&vpn::Request {
        session_token: CapabilityToken([0x5a; 16]),
        nonce: Nonce([1; 16]),
        idempotency_key: IdempotencyKey([1; 16]),
        expected_revision: 0,
        command: vpn::Command {
            verb: vpn::Verb::Prepare,
            profile: "corp".into(),
        },
    }));
    let (outcome, transport) = serve_scripted(&broker, bytes);
    assert!(matches!(
        outcome,
        ConnectionOutcome::Served {
            frames: 1,
            claim_dropped: false,
            ..
        }
    ));
    let response: vpn::Response =
        ciborium::de::from_reader(&transport.frames_written()[1][..]).unwrap();
    assert_eq!(response, vpn::Response::Rejected(vpn::Reject::Unavailable));
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0);
    assert!(broker.leases().is_empty());
}

#[test]
fn vpn_version_three_cannot_adopt_a_boundary_lease_or_negotiate_a_pinned_claim() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state, operator_authorizer());
    for pinned in [true, false] {
        let mut hello = ssk_netd_helper::vpn::client::hello();
        if pinned {
            hello.lease_kind = LeaseKind::Pinned;
        } else {
            hello.adopt_lease = Some(LeaseId([1; 16]));
        }
        let (outcome, _) = serve_scripted(&broker, framed(&hello));
        assert!(matches!(
            outcome,
            ConnectionOutcome::Refused(HandshakeReject::Malformed(_))
        ));
        assert!(broker.leases().is_empty());
    }
}

#[test]
fn obsolete_vpn_version_two_is_rejected_before_command_dispatch() {
    let state = Arc::new(MockState::default());
    let broker = privileged_broker(state.clone(), operator_authorizer());
    let mut hello = ssk_netd_helper::vpn::client::hello();
    hello.min_protocol_version = 2;
    hello.max_protocol_version = 2;
    let (outcome, _) = serve_scripted(&broker, framed(&hello));
    assert!(matches!(
        outcome,
        ConnectionOutcome::Refused(HandshakeReject::VersionMismatch { .. })
    ));
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0);
}
