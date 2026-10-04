//! P1 hardening of the privileged broker (roadmap §P1):
//!
//! * the idempotency cache key is bound to the command discriminant,
//! * `seen_nonces` / the idempotency cache are bounded without re-opening the
//!   replay window,
//! * the session token is compared in constant time,
//! * actuation is gated on a real `(principal, verb)` allow-list, and
//! * a persisted receipt is re-verified against the configured scope on
//!   recovery rather than trusted.
//!
//! Runs against a mock enforcer, as `p0_broker.rs` does; the real Windows
//! firewall edge is `#[cfg(windows)]` in `ssk-winhost`.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use ssk_boundary::{
    BoundaryEnforcer, BoundaryError, BoundaryPolicy, BoundaryScope, EnforcementReceipt,
    KillSwitchState, BOUNDARY_CONTROL_USE, BOUNDARY_OVERRIDE_USE,
};
use ssk_signature::policy::{AuthorizationPolicyTable, Principal, PrivilegedUse};
use ssk_signature::AuthorizationManifest;
use ssk_types::SessionId;

use ssk_netd_helper::{
    ActuationAuthority, Broker, BrokerConfig, BrokerResponse, CapabilityToken, Command,
    CommandEnvelope, EgressObserver, FileReceiptStore, HelperError, IdempotencyKey, Nonce,
    ReceiptStore, RejectReason, MAX_SESSION_MUTATIONS,
};

const TOKEN: CapabilityToken = CapabilityToken([7u8; 16]);
const BROKER_PRINCIPAL: &str = "ssk-netd-helper";

struct MockState {
    severed: AtomicBool,
    engage_calls: AtomicU32,
    release_calls: AtomicU32,
}

impl MockState {
    fn new() -> Arc<Self> {
        Arc::new(MockState {
            severed: AtomicBool::new(false),
            engage_calls: AtomicU32::new(0),
            release_calls: AtomicU32::new(0),
        })
    }
}

struct MockEnforcer(Arc<MockState>);
struct MockObserver(Arc<MockState>);

impl BoundaryEnforcer for MockEnforcer {
    fn engage(&self, scope: &BoundaryScope) -> Result<EnforcementReceipt, BoundaryError> {
        self.0.engage_calls.fetch_add(1, Ordering::SeqCst);
        let receipt = EnforcementReceipt::new(scope, "flowing");
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

/// The broker's actuation manifest, carrying a real principal.
fn actuation_auth() -> AuthorizationManifest {
    AuthorizationManifest::new(BROKER_PRINCIPAL, "system", "privileged broker")
        .with_allowed_uses([BOUNDARY_CONTROL_USE])
        .with_principal(Principal::parse(BROKER_PRINCIPAL).unwrap())
}

fn config() -> BrokerConfig {
    BrokerConfig {
        session_token: TOKEN,
        actuation_auth: actuation_auth(),
        scope: BoundaryScope::all_egress(),
        policy: BoundaryPolicy::default(),
        session: SessionId::new("sess-p1"),
    }
}

fn broker_with(
    authority: ActuationAuthority,
    dir: &std::path::Path,
    state: Arc<MockState>,
) -> Broker {
    Broker::recover_with_policy(
        config(),
        authority,
        Box::new(FileReceiptStore::open_existing(dir).unwrap()),
        Box::new(MockEnforcer(state.clone())),
        Box::new(MockObserver(state)),
    )
    .unwrap()
}

fn env(nonce: u64, key: u64, ver: u64, command: Command) -> CommandEnvelope {
    let mut n = [0u8; 16];
    n[..8].copy_from_slice(&nonce.to_le_bytes());
    let mut k = [0u8; 16];
    k[..8].copy_from_slice(&key.to_le_bytes());
    CommandEnvelope {
        session_token: TOKEN,
        nonce: Nonce(n),
        idempotency_key: IdempotencyKey(k),
        expected_state_version: ver,
        command,
    }
}

// ── Idempotency key ↔ command binding ───────────────────────────────────────

/// Before the fix the cache was keyed on the raw idempotency key alone, so a
/// `ReleaseKillSwitch` submitted under an `EngageKillSwitch`'s key returned the
/// **cached engage status**: the caller is told `logical_state = Engaged`,
/// `os_rule_present = true` for a release it asked for, the enforcer is never
/// called, and egress stays severed with the client believing otherwise.
#[test]
fn an_idempotency_key_reused_across_commands_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let state = MockState::new();
    let broker = broker_with(ActuationAuthority::SelfAsserted, dir.path(), state.clone());

    let engaged = broker.handle(env(1, 42, 0, Command::EngageKillSwitch));
    assert!(matches!(engaged, BrokerResponse::Ok(_)), "{engaged:?}");

    // Fresh nonce, SAME key, DIFFERENT command.
    let crossed = broker.handle(env(2, 42, 1, Command::ReleaseKillSwitch));
    assert_eq!(
        crossed,
        BrokerResponse::Rejected(RejectReason::IdempotencyKeyConflict {
            cached: Command::EngageKillSwitch,
            submitted: Command::ReleaseKillSwitch,
        }),
        "a key that names an engage must not answer a release"
    );

    // The pre-fix failure mode, asserted directly so this test still has teeth
    // if the reject variant is ever renamed: nothing was released, and the
    // caller was not handed a stale success.
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 0);
    assert!(state.severed.load(Ordering::SeqCst), "still severed");
    assert!(
        !matches!(crossed, BrokerResponse::Ok(_)),
        "a cross-command reuse must never produce Ok"
    );
    assert_eq!(broker.status().logical_state, KillSwitchState::Engaged);
}

#[test]
fn the_same_key_with_the_same_command_still_returns_the_cached_result() {
    let dir = tempfile::tempdir().unwrap();
    let state = MockState::new();
    let broker = broker_with(ActuationAuthority::SelfAsserted, dir.path(), state.clone());

    let first = match broker.handle(env(1, 42, 0, Command::EngageKillSwitch)) {
        BrokerResponse::Ok(s) => s,
        o => panic!("{o:?}"),
    };
    // Fresh nonce, same key, same command, stale version → the original result.
    match broker.handle(env(2, 42, 0, Command::EngageKillSwitch)) {
        BrokerResponse::Ok(s) => assert_eq!(s, first),
        o => panic!("expected the cached Ok, got {o:?}"),
    }
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 1);
}

// ── Bounded session state that does not forget a nonce ──────────────────────

#[test]
fn the_session_budget_refuses_new_nonces_and_never_forgets_an_old_one() {
    let dir = tempfile::tempdir().unwrap();
    let state = MockState::new();
    let broker = broker_with(ActuationAuthority::SelfAsserted, dir.path(), state);

    // Burn the whole budget with distinct nonces. Every one is rejected at the
    // version gate, which is *after* the nonce is recorded — the exact shape of
    // the unbounded-growth vector.
    for i in 0..MAX_SESSION_MUTATIONS {
        let resp = broker.handle(env(i, i, u64::MAX, Command::EngageKillSwitch));
        assert!(
            matches!(
                resp,
                BrokerResponse::Rejected(RejectReason::StaleVersion { .. })
            ),
            "iteration {i}: {resp:?}"
        );
    }
    assert_eq!(broker.session_nonces_seen(), MAX_SESSION_MUTATIONS);

    // A *new* nonce is now refused — bounded, and fail-closed.
    assert_eq!(
        broker.handle(env(MAX_SESSION_MUTATIONS, 0, 0, Command::EngageKillSwitch)),
        BrokerResponse::Rejected(RejectReason::SessionMutationLimitReached {
            limit: MAX_SESSION_MUTATIONS
        })
    );
    assert_eq!(
        broker.session_nonces_seen(),
        MAX_SESSION_MUTATIONS,
        "a refused command records nothing"
    );

    // ...and an *already seen* nonce is still detected as a replay. This is the
    // property an LRU/TTL bound would have destroyed.
    assert_eq!(
        broker.handle(env(0, 0, 0, Command::EngageKillSwitch)),
        BrokerResponse::Rejected(RejectReason::ReplayedNonce)
    );

    // Read-only verbs never consume budget, so an exhausted session stays
    // observable rather than going dark.
    assert!(matches!(
        broker.handle(env(MAX_SESSION_MUTATIONS + 1, 0, 0, Command::GetStatus)),
        BrokerResponse::Ok(_)
    ));
}

// ── Constant-time token comparison ──────────────────────────────────────────

#[test]
fn the_capability_token_compare_is_constant_time_and_still_correct() {
    let good = CapabilityToken([7u8; 16]);
    assert!(good.ct_eq(&TOKEN));
    // Differs only in the LAST byte — the case a short-circuiting compare
    // takes longest to reject, and the one an attacker walks toward.
    let mut tail = [7u8; 16];
    tail[15] = 8;
    assert!(!CapabilityToken(tail).ct_eq(&TOKEN));
    // Differs only in the FIRST byte.
    let mut head = [7u8; 16];
    head[0] = 8;
    assert!(!CapabilityToken(head).ct_eq(&TOKEN));
    assert!(!CapabilityToken([0u8; 16]).ct_eq(&TOKEN));

    // And the broker still rejects a bad token with no effect.
    let dir = tempfile::tempdir().unwrap();
    let state = MockState::new();
    let broker = broker_with(ActuationAuthority::SelfAsserted, dir.path(), state.clone());
    let mut bad = env(1, 1, 0, Command::EngageKillSwitch);
    bad.session_token = CapabilityToken(tail);
    assert_eq!(
        broker.handle(bad),
        BrokerResponse::Rejected(RejectReason::BadToken)
    );
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0);
}

// ── Real actuation authorization ────────────────────────────────────────────

#[test]
fn a_deny_all_policy_table_stops_actuation_before_the_enforcer() {
    let dir = tempfile::tempdir().unwrap();
    let state = MockState::new();
    let broker = broker_with(
        ActuationAuthority::Table(AuthorizationPolicyTable::deny_all()),
        dir.path(),
        state.clone(),
    );
    assert_eq!(
        broker.handle(env(1, 1, 0, Command::EngageKillSwitch)),
        BrokerResponse::Rejected(RejectReason::Unauthorized)
    );
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0, "no OS effect");
    assert_eq!(
        broker.session_nonces_seen(),
        0,
        "an unauthorized command records no nonce"
    );
    assert_eq!(broker.status().logical_state, KillSwitchState::Armed);

    // Read-only status is still served: authorization gates actuation, not
    // observation.
    assert!(matches!(
        broker.handle(env(2, 2, 0, Command::GetStatus)),
        BrokerResponse::Ok(_)
    ));
}

#[test]
fn a_grant_for_the_wrong_verb_or_principal_does_not_authorize_actuation() {
    for table in [
        // right principal, wrong verb
        AuthorizationPolicyTable::deny_all().allow(
            Principal::parse(BROKER_PRINCIPAL).unwrap(),
            PrivilegedUse::ProfileControl,
        ),
        // right verb, wrong principal
        AuthorizationPolicyTable::deny_all().allow(
            Principal::parse("someone-else").unwrap(),
            PrivilegedUse::BoundaryControl,
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let state = MockState::new();
        let broker = broker_with(ActuationAuthority::Table(table), dir.path(), state.clone());
        assert_eq!(
            broker.handle(env(1, 1, 0, Command::EngageKillSwitch)),
            BrokerResponse::Rejected(RejectReason::Unauthorized)
        );
        assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn an_explicit_principal_verb_grant_authorizes_actuation() {
    let dir = tempfile::tempdir().unwrap();
    let state = MockState::new();
    let table = AuthorizationPolicyTable::deny_all().allow(
        Principal::parse(BROKER_PRINCIPAL).unwrap(),
        PrivilegedUse::BoundaryControl,
    );
    let broker = broker_with(ActuationAuthority::Table(table), dir.path(), state.clone());

    let resp = broker.handle(env(1, 1, 0, Command::EngageKillSwitch));
    assert!(matches!(resp, BrokerResponse::Ok(_)), "{resp:?}");
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        broker.handle(env(2, 2, 1, Command::ReleaseKillSwitch)),
        BrokerResponse::Ok(_)
    ));
    assert!(!state.severed.load(Ordering::SeqCst));
}

/// A manifest that self-declares `boundary_control` but carries **no
/// principal** — today's shape everywhere in the workspace — cannot satisfy the
/// table. This is what separates `authorize` from `is_valid_for`.
#[test]
fn a_principal_less_manifest_cannot_satisfy_the_table() {
    let dir = tempfile::tempdir().unwrap();
    let state = MockState::new();
    let mut cfg = config();
    cfg.actuation_auth =
        AuthorizationManifest::new(BROKER_PRINCIPAL, "system", "privileged broker")
            .with_allowed_uses([BOUNDARY_CONTROL_USE]);
    let table = AuthorizationPolicyTable::deny_all().allow(
        Principal::parse(BROKER_PRINCIPAL).unwrap(),
        PrivilegedUse::BoundaryControl,
    );
    let broker = Broker::recover_with_policy(
        cfg,
        ActuationAuthority::Table(table),
        Box::new(FileReceiptStore::open_existing(dir.path()).unwrap()),
        Box::new(MockEnforcer(state.clone())),
        Box::new(MockObserver(state.clone())),
    )
    .unwrap();
    assert_eq!(
        broker.handle(env(1, 1, 0, Command::EngageKillSwitch)),
        BrokerResponse::Rejected(RejectReason::Unauthorized)
    );
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0);
}

/// Drift guard for the duplicated verb literals in
/// `ssk_signature::policy::PrivilegedUse`. `ssk-netd-helper` is the crate that
/// can see both `ssk-signature` and `ssk-boundary`, so it owns this assertion.
/// The `profile_*` and `service_control` verbs have no such guard — no crate in
/// the workspace depends on both sides. Recorded, not hidden.
#[test]
fn privileged_use_literals_match_the_boundary_crate_constants() {
    assert_eq!(
        PrivilegedUse::BoundaryControl.as_str(),
        BOUNDARY_CONTROL_USE
    );
    assert_eq!(
        PrivilegedUse::BoundaryOverride.as_str(),
        BOUNDARY_OVERRIDE_USE
    );
}

// ── Receipt integrity on recovery ───────────────────────────────────────────

#[test]
fn a_tampered_persisted_receipt_is_rejected_on_recovery() {
    let dir = tempfile::tempdir().unwrap();
    {
        let state = MockState::new();
        let broker = broker_with(ActuationAuthority::SelfAsserted, dir.path(), state);
        assert!(matches!(
            broker.handle(env(1, 1, 0, Command::EngageKillSwitch)),
            BrokerResponse::Ok(_)
        ));
    }

    // Edit `prior_state` in place without rehashing — the naive tamper.
    let store = FileReceiptStore::open_existing(dir.path()).unwrap();
    let mut snap = store.load().unwrap().unwrap();
    snap.receipt.as_mut().unwrap().prior_state = "severed;rule=all".to_owned();
    store.save(&snap).unwrap();

    let state = MockState::new();
    let outcome = Broker::recover(
        config(),
        Box::new(FileReceiptStore::open_existing(dir.path()).unwrap()),
        Box::new(MockEnforcer(state.clone())),
        Box::new(MockObserver(state.clone())),
    );
    let Err(err) = outcome else {
        panic!("a receipt whose id does not match its contents must not rehydrate");
    };
    assert!(
        matches!(err, HelperError::CorruptState(ref m) if m.contains("receipt")),
        "{err:?}"
    );
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 0);
}

/// The limit of the check above, stated as a test rather than as prose:
/// `receipt_id` is unkeyed, so a writer who *rehashes* passes. Forgery is
/// bounded by the store DACL and by the enforcer re-deriving the rule name from
/// the scope — not here.
#[test]
fn a_rehashed_receipt_is_not_detected_because_the_digest_is_unkeyed() {
    let dir = tempfile::tempdir().unwrap();
    {
        let state = MockState::new();
        let broker = broker_with(ActuationAuthority::SelfAsserted, dir.path(), state);
        broker.handle(env(1, 1, 0, Command::EngageKillSwitch));
    }
    let store = FileReceiptStore::open_existing(dir.path()).unwrap();
    let mut snap = store.load().unwrap().unwrap();
    // Recompute the id for the forged prior_state — anyone who can write the
    // file can do this.
    snap.receipt = Some(EnforcementReceipt::new(
        &BoundaryScope::all_egress(),
        "severed;rule=all",
    ));
    store.save(&snap).unwrap();

    let state = MockState::new();
    assert!(
        Broker::recover(
            config(),
            Box::new(FileReceiptStore::open_existing(dir.path()).unwrap()),
            Box::new(MockEnforcer(state.clone())),
            Box::new(MockObserver(state)),
        )
        .is_ok(),
        "documented: digest recomputation detects corruption, not forgery"
    );
}
