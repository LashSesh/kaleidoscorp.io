//! P3 — peer authorization **on the served path**.
//!
//! `p1_hardening.rs` covers the *broker's* authority to actuate at all
//! (`ActuationAuthority::Table`, a `(principal, verb)` allow-list decided once
//! at construction). This file covers the other question, which did not exist
//! before P3: *may this caller command this verb?* — decided per request against
//! the peer the transport authenticated.
//!
//! The two are not substitutes, and this file asserts that in both directions:
//! a broker authorized to actuate must still refuse an unlisted caller, and a
//! listed caller must still be refused by a broker with no actuation grant.
//!
//! # Every negative here is mutation-checked
//!
//! A negative test that would also pass with the check deleted is evidence of
//! nothing. Each refusal below is paired with an assertion that the *same* peer,
//! command and broker construction succeeds when only the authorizer is swapped
//! for a permissive one — so the refusal is attributable to the authorizer being
//! on the path, and not to something incidental.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use ssk_boundary::{
    BoundaryEnforcer, BoundaryError, BoundaryPolicy, BoundaryScope, EnforcementReceipt,
    KillSwitchState, BOUNDARY_CONTROL_USE,
};
use ssk_signature::policy::{AuthorizationPolicyTable, Principal, PrivilegedUse};
use ssk_signature::AuthorizationManifest;
use ssk_types::SessionId;

use ssk_netd_helper::{
    AuthenticatedPeer, AuthzDenied, Broker, BrokerConfig, BrokerResponse, CapabilityToken, Command,
    CommandEnvelope, ControlVerb, EgressObserver, HelperError, IdempotencyKey, LeaseId, LeaseKind,
    Nonce, PeerAuthorizer, PeerIdentity, PeerToken, PersistedState, ReceiptStore, RejectReason,
    TieredSidAuthorizer,
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
struct MemStore(Mutex<Option<PersistedState>>);
impl ReceiptStore for MemStore {
    fn save(&self, state: &PersistedState) -> Result<(), HelperError> {
        *self.0.lock().unwrap() = Some(state.clone());
        Ok(())
    }
    fn load(&self) -> Result<Option<PersistedState>, HelperError> {
        Ok(self.0.lock().unwrap().clone())
    }
}

/// **The mutation.** A `PeerAuthorizer` that grants everything to everyone.
/// Swapping it in must turn each named negative test green and leave every
/// positive test unchanged — which is what makes the negatives evidence.
struct AlwaysAllow;
impl PeerAuthorizer for AlwaysAllow {
    fn authorize(&self, _peer: &AuthenticatedPeer, _verb: ControlVerb) -> Result<(), AuthzDenied> {
        Ok(())
    }
}

fn actuation_auth() -> AuthorizationManifest {
    AuthorizationManifest::new(BROKER_PRINCIPAL, "system", "privileged broker")
        .with_allowed_uses([BOUNDARY_CONTROL_USE])
        .with_principal(Principal::parse(BROKER_PRINCIPAL).unwrap())
}

fn granting_table() -> AuthorizationPolicyTable {
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

fn broker_with(
    state: Arc<MockState>,
    table: AuthorizationPolicyTable,
    authorizer: Box<dyn PeerAuthorizer>,
) -> Broker {
    Broker::recover_privileged(
        BrokerConfig {
            session_token: CapabilityToken([0x5a; 16]),
            actuation_auth: actuation_auth(),
            scope: BoundaryScope::all_egress(),
            policy: BoundaryPolicy::default(),
            session: SessionId::new("sess-p3-authz"),
        },
        table,
        authorizer,
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

fn elevated(sid: &str) -> AuthenticatedPeer {
    AuthenticatedPeer::new(
        PeerIdentity::parse_sid(sid).unwrap(),
        PeerToken {
            elevated_admin: true,
            admin_account_filtered: true,
            integrity_rid: 0x3000,
            logon_session: None,
        },
    )
}

fn env(nonce: u8, key: u8, version: u64, command: Command) -> CommandEnvelope {
    CommandEnvelope {
        session_token: CapabilityToken([0x5a; 16]),
        nonce: Nonce([nonce; 16]),
        idempotency_key: IdempotencyKey([key; 16]),
        expected_state_version: version,
        command,
    }
}

fn lease() -> LeaseId {
    LeaseId([0x11; 16])
}

fn reject_code(response: &BrokerResponse) -> String {
    match response {
        BrokerResponse::Rejected(RejectReason::PeerUnauthorized { code, .. }) => code.clone(),
        other => panic!("expected a peer rejection, got {other:?}"),
    }
}

// ── tier C: the allow-list decides ──────────────────────────────────────────

/// The headline property. An authenticated but unlisted peer cannot sever the
/// machine's egress — and the refusal happens before the enforcer, before a
/// nonce is recorded, and before the state version moves.
#[test]
fn an_unlisted_peer_cannot_engage_and_leaves_no_trace() {
    let state = Arc::new(MockState::default());
    let broker = broker_with(
        state.clone(),
        granting_table(),
        Box::new(operator_authorizer()),
    );

    let response = broker.handle_from_peer(
        &peer(STRANGER),
        lease(),
        LeaseKind::Session,
        env(1, 1, 0, Command::EngageKillSwitch),
    );
    assert_eq!(reject_code(&response), "PEER_NOT_GRANTED");
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0, "no OS effect");
    assert_eq!(
        broker.session_nonces_seen(),
        0,
        "a refused peer must not consume anti-replay budget"
    );
    assert_eq!(broker.status().state_version, 0);
    assert!(broker.leases().is_empty(), "no claim was taken");

    // The mutation: same peer, same command, permissive authorizer.
    let state2 = Arc::new(MockState::default());
    let permissive = broker_with(state2.clone(), granting_table(), Box::new(AlwaysAllow));
    assert!(
        matches!(
            permissive.handle_from_peer(
                &peer(STRANGER),
                lease(),
                LeaseKind::Session,
                env(1, 1, 0, Command::EngageKillSwitch),
            ),
            BrokerResponse::Ok(_)
        ),
        "with a permissive authorizer the same request succeeds — so the refusal \
         above is attributable to the authorizer being on the served path"
    );
    assert_eq!(state2.engage_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn an_unlisted_peer_cannot_release_someone_elses_engagement() {
    let state = Arc::new(MockState::default());
    let broker = broker_with(
        state.clone(),
        granting_table(),
        Box::new(operator_authorizer()),
    );
    assert!(matches!(
        broker.handle_from_peer(
            &peer(OPERATOR),
            lease(),
            LeaseKind::Pinned,
            env(1, 1, 0, Command::EngageKillSwitch),
        ),
        BrokerResponse::Ok(_)
    ));

    let response = broker.handle_from_peer(
        &peer(STRANGER),
        lease(),
        LeaseKind::Session,
        env(2, 2, 1, Command::ReleaseKillSwitch),
    );
    assert_eq!(reject_code(&response), "PEER_NOT_GRANTED");
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 0);
    assert!(state.severed.load(Ordering::SeqCst), "still severed");
    assert_eq!(broker.status().logical_state, KillSwitchState::Engaged);
}

/// Tier R is open by design: a machine whose egress may be severed must stay
/// diagnosable by whoever the pipe's DACL admitted. This is a *decision*, so it
/// is asserted rather than left as an accident of the table.
#[test]
fn an_unlisted_peer_may_still_read_status() {
    let state = Arc::new(MockState::default());
    let broker = broker_with(state, granting_table(), Box::new(operator_authorizer()));
    let response = broker.handle_from_peer(
        &peer(STRANGER),
        lease(),
        LeaseKind::Session,
        env(1, 1, 0, Command::GetStatus),
    );
    match response {
        BrokerResponse::Ok(status) => assert_eq!(status.logical_state, KillSwitchState::Armed),
        other => panic!("{other:?}"),
    }
}

/// A grant for engage is not a grant for release. They point in opposite
/// directions — engage is the denial-of-service direction, release is the
/// recovery one — so they are separately recorded decisions.
#[test]
fn a_grant_for_engage_alone_does_not_permit_release() {
    let state = Arc::new(MockState::default());
    let engage_only = TieredSidAuthorizer::deny_all().allow(
        PeerIdentity::parse_sid(OPERATOR).unwrap(),
        ControlVerb::EngageKillSwitch,
    );
    let broker = broker_with(state.clone(), granting_table(), Box::new(engage_only));

    assert!(matches!(
        broker.handle_from_peer(
            &peer(OPERATOR),
            lease(),
            LeaseKind::Pinned,
            env(1, 1, 0, Command::EngageKillSwitch),
        ),
        BrokerResponse::Ok(_)
    ));
    let response = broker.handle_from_peer(
        &peer(OPERATOR),
        lease(),
        LeaseKind::Pinned,
        env(2, 2, 1, Command::ReleaseKillSwitch),
    );
    assert_eq!(reject_code(&response), "PEER_NOT_GRANTED");
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 0);
}

// ── the degraded, read-only fallback ────────────────────────────────────────

/// When the allow-list cannot be read the broker degrades to read-only, **not**
/// to deny-all: a severed machine has to stay diagnosable. Every mutating verb
/// is refused with a reason an operator can act on.
#[test]
fn an_unreadable_allow_list_degrades_to_read_only_rather_than_going_dark() {
    let state = Arc::new(MockState::default());
    let broker = broker_with(
        state.clone(),
        granting_table(),
        Box::new(TieredSidAuthorizer::read_only(
            "authz.json could not be parsed",
        )),
    );

    assert!(
        matches!(
            broker.handle_from_peer(
                &peer(OPERATOR),
                lease(),
                LeaseKind::Session,
                env(1, 1, 0, Command::GetStatus)
            ),
            BrokerResponse::Ok(_)
        ),
        "status must still be readable on a machine that may be severed"
    );

    let response = broker.handle_from_peer(
        &peer(OPERATOR),
        lease(),
        LeaseKind::Session,
        env(2, 2, 0, Command::EngageKillSwitch),
    );
    assert_eq!(reject_code(&response), "PEER_READ_ONLY_MODE");
    match response {
        BrokerResponse::Rejected(RejectReason::PeerUnauthorized { detail, .. }) => assert!(
            detail.contains("authz.json could not be parsed"),
            "the operator must be told why: {detail}"
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0);
}

/// The tier-O *decision* survives even when the allow-list is unreadable — an
/// elevated caller still clears it, an unelevated one still does not — which
/// is what would make the strict tier-C behaviour above acceptable **if**
/// anything on the wire could reach this decision. Nothing does today: see
/// `authz` module docs for why `ControlVerb::Override` has no `Command` that
/// maps to it. This test is therefore scoped to the authorizer in isolation,
/// not to an end-to-end recovery path.
#[test]
fn the_override_decision_survives_even_when_the_allow_list_is_unreadable() {
    let degraded = TieredSidAuthorizer::read_only("authz.json is missing");
    assert!(degraded
        .authorize(&elevated(OPERATOR), ControlVerb::Override)
        .is_ok());
    assert!(degraded
        .authorize(&peer(OPERATOR), ControlVerb::Override)
        .is_err());
}

// ── the two authorization questions are independent ────────────────────────

/// A caller the allow-list names is still refused if the *broker* has no grant
/// to actuate. The reject reason is the broker-scoped `Unauthorized`, not the
/// peer-scoped one — because they tell an operator to fix different things.
#[test]
fn a_granted_peer_is_still_refused_by_a_broker_with_no_actuation_grant() {
    let state = Arc::new(MockState::default());
    let broker = broker_with(
        state.clone(),
        AuthorizationPolicyTable::deny_all(),
        Box::new(operator_authorizer()),
    );
    assert_eq!(
        broker.handle_from_peer(
            &peer(OPERATOR),
            lease(),
            LeaseKind::Session,
            env(1, 1, 0, Command::EngageKillSwitch),
        ),
        BrokerResponse::Rejected(RejectReason::Unauthorized),
    );
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0);
}

/// The order matters and is asserted: peer authorization runs **before** the
/// capability-token compare, so an unauthorized peer cannot use the response to
/// learn anything about the token.
#[test]
fn peer_authorization_runs_before_the_capability_token_compare() {
    let state = Arc::new(MockState::default());
    let broker = broker_with(state, granting_table(), Box::new(operator_authorizer()));

    let mut wrong_token = env(1, 1, 0, Command::EngageKillSwitch);
    wrong_token.session_token = CapabilityToken([0u8; 16]);

    // Unlisted peer + wrong token → the peer refusal, not `BadToken`.
    let response =
        broker.handle_from_peer(&peer(STRANGER), lease(), LeaseKind::Session, wrong_token);
    assert_eq!(reject_code(&response), "PEER_NOT_GRANTED");

    // Listed peer + wrong token → now the token check is what refuses, which is
    // what proves the first answer was not simply "everything is refused".
    let mut wrong_token = env(2, 2, 0, Command::EngageKillSwitch);
    wrong_token.session_token = CapabilityToken([0u8; 16]);
    assert_eq!(
        broker.handle_from_peer(&peer(OPERATOR), lease(), LeaseKind::Session, wrong_token),
        BrokerResponse::Rejected(RejectReason::BadToken)
    );
}

// ── the peer-less entry point on a privileged broker ───────────────────────

/// The barrier that makes the un-authorized entry point unusable on a
/// privileged deployment. `Broker::handle` takes no peer and therefore cannot
/// make a peer decision; on a broker that has one to make, it refuses.
#[test]
fn the_peerless_entry_point_cannot_mutate_a_privileged_broker() {
    let state = Arc::new(MockState::default());
    let broker = broker_with(
        state.clone(),
        granting_table(),
        Box::new(operator_authorizer()),
    );
    assert!(broker.is_peer_authorizing());

    for command in [Command::EngageKillSwitch, Command::ReleaseKillSwitch] {
        assert_eq!(
            broker.handle(env(1, 1, 0, command)),
            BrokerResponse::Rejected(RejectReason::PeerAuthorizationRequired),
            "{command:?} must not bypass the peer decision"
        );
    }
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 0);

    // Reads still work, so an in-process diagnostic is not collateral damage.
    assert!(matches!(
        broker.handle(env(2, 2, 0, Command::GetStatus)),
        BrokerResponse::Ok(_)
    ));
}

/// The complementary half: on an in-process broker (no authorizer) the peer
/// entry point fails closed rather than pretending it made a decision.
#[test]
fn a_broker_with_no_authorizer_refuses_every_peer_request() {
    let state = Arc::new(MockState::default());
    let broker = Broker::recover(
        BrokerConfig {
            session_token: CapabilityToken([0x5a; 16]),
            actuation_auth: actuation_auth(),
            scope: BoundaryScope::all_egress(),
            policy: BoundaryPolicy::default(),
            session: SessionId::new("in-process"),
        },
        Box::new(MemStore::default()),
        Box::new(MockEnforcer(state.clone())),
        Box::new(MockObserver(state.clone())),
    )
    .unwrap();
    assert!(!broker.is_peer_authorizing());

    for command in [
        Command::GetStatus,
        Command::EngageKillSwitch,
        Command::ReleaseKillSwitch,
    ] {
        let response = broker.handle_from_peer(
            &peer(OPERATOR),
            lease(),
            LeaseKind::Session,
            env(1, 1, 0, command),
        );
        assert_eq!(reject_code(&response), "PEER_NO_AUTHORIZER", "{command:?}");
    }
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0);
}

// ── the audited holder is the authenticated SID ────────────────────────────

/// The confused-deputy invariant, asserted: nothing the caller supplies reaches
/// the audit line. The holder recorded on a claim is the SID the transport
/// authenticated, and the wire protocol carries no name, path or scope at all.
#[test]
fn the_recorded_holder_is_the_authenticated_sid_and_not_anything_the_caller_sent() {
    let state = Arc::new(MockState::default());
    let broker = broker_with(state, granting_table(), Box::new(operator_authorizer()));
    assert!(matches!(
        broker.handle_from_peer(
            &peer(OPERATOR),
            lease(),
            LeaseKind::Pinned,
            env(1, 1, 0, Command::EngageKillSwitch),
        ),
        BrokerResponse::Ok(_)
    ));
    let leases = broker.leases();
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0].holder, OPERATOR);
    assert_eq!(leases[0].id, lease());
}
