//! P0 vertical slice (SPEC_TAURI_GUI.md §12): GetStatus + KillSwitch
//! engage/release over the authenticated command channel, through the
//! ssk-boundary gate + hash-chained audit, with a durable receipt, the §6
//! rollback contract, and crash recovery. Tested on Linux against a mock
//! enforcer; the real Windows firewall edge is `#[cfg(windows)]` in ssk-winhost.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use ssk_boundary::{
    BoundaryEnforcer, BoundaryError, BoundaryPolicy, BoundaryScope, EnforcementReceipt,
    KillSwitchState, BOUNDARY_CONTROL_USE,
};
use ssk_signature::AuthorizationManifest;
use ssk_types::SessionId;

use ssk_netd_helper::{
    decode_envelope, encode_envelope, Broker, BrokerConfig, BrokerResponse, CapabilityToken,
    Command, CommandEnvelope, EgressObserver, FileReceiptStore, IdempotencyKey, Nonce,
    ReceiptStore, Recovery, RejectReason, MAX_PRIV_FRAME,
};

const TOKEN: CapabilityToken = CapabilityToken([7u8; 16]);

/// Shared mock state, driven by both the enforcer and the observer views.
struct MockState {
    severed: AtomicBool,
    engage_calls: AtomicU32,
    fail_engage: AtomicBool,
    /// If set, the observer reports this instead of the real severed flag —
    /// used to simulate an OS rule that disagrees with the journal.
    observed_override: Mutex<Option<bool>>,
}

impl MockState {
    fn new(severed: bool) -> Arc<Self> {
        Arc::new(MockState {
            severed: AtomicBool::new(severed),
            engage_calls: AtomicU32::new(0),
            fail_engage: AtomicBool::new(false),
            observed_override: Mutex::new(None),
        })
    }
}

struct MockEnforcer(Arc<MockState>);
struct MockObserver(Arc<MockState>);

impl BoundaryEnforcer for MockEnforcer {
    fn engage(&self, scope: &BoundaryScope) -> Result<EnforcementReceipt, BoundaryError> {
        if self.0.fail_engage.load(Ordering::SeqCst) {
            return Err(BoundaryError::Enforcement("mock engage failure".to_owned()));
        }
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
        self.0.severed.store(false, Ordering::SeqCst);
        Ok(())
    }
}

impl EgressObserver for MockObserver {
    fn rule_present(&self, _scope_label: &str) -> Option<bool> {
        match *self.0.observed_override.lock().unwrap() {
            Some(b) => Some(b),
            None => Some(self.0.severed.load(Ordering::SeqCst)),
        }
    }
}

fn actuation_auth() -> AuthorizationManifest {
    AuthorizationManifest::new("ssk-netd-helper", "system", "privileged broker")
        .with_allowed_uses([BOUNDARY_CONTROL_USE])
}

fn mk(dir: &Path, state: Arc<MockState>) -> Broker {
    let store = Box::new(FileReceiptStore::open(dir).unwrap());
    let cfg = BrokerConfig {
        session_token: TOKEN,
        actuation_auth: actuation_auth(),
        scope: BoundaryScope::all_egress(),
        policy: BoundaryPolicy::default(),
        session: SessionId::new("sess-p0"),
    };
    Broker::recover(
        cfg,
        store,
        Box::new(MockEnforcer(state.clone())),
        Box::new(MockObserver(state)),
    )
    .unwrap()
}

fn env(token: CapabilityToken, nonce: u8, key: u8, ver: u64, command: Command) -> CommandEnvelope {
    CommandEnvelope {
        session_token: token,
        nonce: Nonce([nonce; 16]),
        idempotency_key: IdempotencyKey([key; 16]),
        expected_state_version: ver,
        command,
    }
}

// ── Command-auth ────────────────────────────────────────────────────────────
#[test]
fn wrong_token_is_rejected_with_no_effect() {
    let dir = tempfile::tempdir().unwrap();
    let state = MockState::new(false);
    let broker = mk(dir.path(), state.clone());
    let bad = CapabilityToken([0u8; 16]);
    let resp = broker.handle(env(bad, 1, 1, 0, Command::EngageKillSwitch));
    assert_eq!(resp, BrokerResponse::Rejected(RejectReason::BadToken));
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0, "no effect");
    assert_eq!(broker.status().logical_state, KillSwitchState::Armed);
}

// ── GetStatus (read path) ───────────────────────────────────────────────────
#[test]
fn get_status_reads_authoritative_state() {
    let dir = tempfile::tempdir().unwrap();
    let broker = mk(dir.path(), MockState::new(false));
    let resp = broker.handle(env(TOKEN, 1, 1, 0, Command::GetStatus));
    match resp {
        BrokerResponse::Ok(status) => {
            assert_eq!(status.logical_state, KillSwitchState::Armed);
            assert_eq!(status.state_version, 0);
            assert!(status.receipt.is_none());
        }
        other => panic!("expected Ok status, got {other:?}"),
    }
}

// ── Engage → durable receipt → authoritative Engaged ────────────────────────
#[test]
fn engage_severs_persists_and_is_authoritative() {
    let dir = tempfile::tempdir().unwrap();
    let state = MockState::new(false);
    let broker = mk(dir.path(), state.clone());

    let resp = broker.handle(env(TOKEN, 1, 1, 0, Command::EngageKillSwitch));
    let status = match resp {
        BrokerResponse::Ok(s) => s,
        other => panic!("expected Ok, got {other:?}"),
    };
    assert_eq!(status.logical_state, KillSwitchState::Engaged);
    assert_eq!(status.state_version, 1);
    assert!(status.receipt.is_some());
    assert_eq!(status.os_rule_present, Some(true));
    assert_eq!(status.recovery, Recovery::Consistent);
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 1);

    // The durable store now holds an Engaged snapshot with the receipt.
    let reloaded = FileReceiptStore::open(dir.path())
        .unwrap()
        .load()
        .unwrap()
        .expect("a snapshot was persisted");
    assert_eq!(reloaded.logical_state, KillSwitchState::Engaged);
    assert_eq!(reloaded.state_version, 1);
    assert!(reloaded.receipt.is_some());
    assert!(!reloaded.journal.is_empty());
}

// ── Anti-replay ─────────────────────────────────────────────────────────────
#[test]
fn a_replayed_nonce_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let state = MockState::new(false);
    let broker = mk(dir.path(), state.clone());
    let first = broker.handle(env(TOKEN, 9, 1, 0, Command::EngageKillSwitch));
    assert!(matches!(first, BrokerResponse::Ok(_)));
    // Exact same envelope (same nonce) → replay.
    let replay = broker.handle(env(TOKEN, 9, 1, 1, Command::EngageKillSwitch));
    assert_eq!(
        replay,
        BrokerResponse::Rejected(RejectReason::ReplayedNonce)
    );
    assert_eq!(
        state.engage_calls.load(Ordering::SeqCst),
        1,
        "no re-execution"
    );
}

// ── Idempotency (retry with fresh nonce, same key) ──────────────────────────
#[test]
fn a_repeated_idempotency_key_returns_cached_without_re_executing() {
    let dir = tempfile::tempdir().unwrap();
    let state = MockState::new(false);
    let broker = mk(dir.path(), state.clone());
    let first = broker.handle(env(TOKEN, 1, 42, 0, Command::EngageKillSwitch));
    let s1 = match first {
        BrokerResponse::Ok(s) => s,
        o => panic!("{o:?}"),
    };
    // Retry: fresh nonce, SAME key, stale version — still returns the original.
    let retry = broker.handle(env(TOKEN, 2, 42, 0, Command::EngageKillSwitch));
    match retry {
        BrokerResponse::Ok(s2) => assert_eq!(s1, s2, "cached result returned verbatim"),
        o => panic!("expected cached Ok, got {o:?}"),
    }
    assert_eq!(
        state.engage_calls.load(Ordering::SeqCst),
        1,
        "the OS effect ran exactly once"
    );
}

// ── Optimistic concurrency ──────────────────────────────────────────────────
#[test]
fn a_stale_expected_version_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let broker = mk(dir.path(), MockState::new(false));
    broker.handle(env(TOKEN, 1, 1, 0, Command::EngageKillSwitch)); // version → 1
                                                                   // Release with the wrong expected version.
    let resp = broker.handle(env(TOKEN, 2, 2, 0, Command::ReleaseKillSwitch));
    assert_eq!(
        resp,
        BrokerResponse::Rejected(RejectReason::StaleVersion {
            expected: 0,
            actual: 1
        })
    );
}

// ── Release consumes the broker-held receipt; audit re-verifies ─────────────
#[test]
fn release_restores_egress_and_audit_reverifies() {
    let dir = tempfile::tempdir().unwrap();
    let state = MockState::new(false);
    let broker = mk(dir.path(), state.clone());
    broker.handle(env(TOKEN, 1, 1, 0, Command::EngageKillSwitch));
    let resp = broker.handle(env(TOKEN, 2, 2, 1, Command::ReleaseKillSwitch));
    let status = match resp {
        BrokerResponse::Ok(s) => s,
        o => panic!("{o:?}"),
    };
    assert_eq!(status.logical_state, KillSwitchState::Released);
    assert_eq!(status.state_version, 2);
    assert!(status.receipt.is_none(), "receipt consumed on release");
    assert!(!state.severed.load(Ordering::SeqCst), "egress restored");
    assert!(status.audit_len >= 2, "engage + release are both audited");

    // The persisted journal still rehydrates (chain intact) after release.
    let snap = FileReceiptStore::open(dir.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(snap.logical_state, KillSwitchState::Released);
}

// ── Rollback contract: an enforcer failure leaves no state (SPEC §6) ────────
#[test]
fn engage_failure_rolls_back_with_no_persisted_state() {
    let dir = tempfile::tempdir().unwrap();
    let state = MockState::new(false);
    state.fail_engage.store(true, Ordering::SeqCst);
    let broker = mk(dir.path(), state.clone());

    let resp = broker.handle(env(TOKEN, 1, 1, 0, Command::EngageKillSwitch));
    assert!(matches!(resp, BrokerResponse::Failed(_)), "enforcer failed");
    // State machine unchanged, version unchanged, nothing persisted.
    let status = broker.status();
    assert_eq!(status.logical_state, KillSwitchState::Armed);
    assert_eq!(status.state_version, 0);
    assert!(FileReceiptStore::open(dir.path())
        .unwrap()
        .load()
        .unwrap()
        .is_none());
}

// ── Strict framing / decode (SPEC §5.3–§5.4) ────────────────────────────────
#[test]
fn framing_enforces_size_and_strictness() {
    let good = env(TOKEN, 1, 1, 0, Command::EngageKillSwitch);
    let bytes = encode_envelope(&good).unwrap();
    // Round-trips exactly.
    assert_eq!(decode_envelope(&bytes).unwrap(), good);

    // Trailing bytes → malformed (a command must be exactly one value).
    let mut trailing = bytes.clone();
    trailing.push(0x00);
    assert_eq!(
        decode_envelope(&trailing),
        Err(RejectReason::MalformedCommand)
    );

    // Oversized frame → rejected before decode.
    let huge = vec![0u8; MAX_PRIV_FRAME + 1];
    assert_eq!(decode_envelope(&huge), Err(RejectReason::FrameTooLarge));

    // Garbage → malformed.
    assert_eq!(
        decode_envelope(&[0xff, 0xff, 0xff]),
        Err(RejectReason::MalformedCommand)
    );
}

// ── Operation lock: concurrent engages serialize; one wins ──────────────────
#[test]
fn concurrent_engages_serialize_to_a_single_effect() {
    let dir = tempfile::tempdir().unwrap();
    let state = MockState::new(false);
    let broker = Arc::new(mk(dir.path(), state.clone()));

    let b1 = Arc::clone(&broker);
    let b2 = Arc::clone(&broker);
    let h1 =
        std::thread::spawn(move || b1.handle(env(TOKEN, 10, 10, 0, Command::EngageKillSwitch)));
    let h2 =
        std::thread::spawn(move || b2.handle(env(TOKEN, 20, 20, 0, Command::EngageKillSwitch)));
    let r1 = h1.join().unwrap();
    let r2 = h2.join().unwrap();

    // Exactly one Ok(Engaged v1); the other loses the version race.
    let oks = [&r1, &r2]
        .iter()
        .filter(|r| matches!(r, BrokerResponse::Ok(_)))
        .count();
    assert_eq!(
        oks, 1,
        "the op-lock + version gate admit exactly one engage"
    );
    assert_eq!(
        state.engage_calls.load(Ordering::SeqCst),
        1,
        "the OS effect ran once despite the race"
    );
    let loser = [&r1, &r2]
        .into_iter()
        .find(|r| !matches!(r, BrokerResponse::Ok(_)))
        .unwrap();
    assert!(matches!(
        loser,
        BrokerResponse::Rejected(RejectReason::StaleVersion { .. })
    ));
}

// ── Crash recovery: engage → drop → recover → Engaged → release ─────────────
#[test]
fn crash_recovery_restores_engaged_state_and_can_release() {
    let dir = tempfile::tempdir().unwrap();

    // Session A: engage, then "crash" (drop the broker, keep the store on disk).
    {
        let state_a = MockState::new(false);
        let broker_a = mk(dir.path(), state_a);
        let resp = broker_a.handle(env(TOKEN, 1, 1, 0, Command::EngageKillSwitch));
        assert!(matches!(resp, BrokerResponse::Ok(_)));
        // broker_a dropped here — in-memory state gone, durable snapshot remains.
    }

    // Session B: a fresh broker + fresh enforcer where the OS rule is still
    // present (severed = true), simulating the firewall rule surviving the crash.
    let state_b = MockState::new(true);
    let broker_b = mk(dir.path(), state_b.clone());
    let status = broker_b.status();
    assert_eq!(
        status.logical_state,
        KillSwitchState::Engaged,
        "recovered from the durable journal"
    );
    assert_eq!(status.recovery, Recovery::Reconciled);
    assert!(
        status.receipt.is_some(),
        "the rollback receipt was recovered"
    );
    assert_eq!(status.state_version, 1);

    // The recovered broker can release using the recovered receipt.
    let resp = broker_b.handle(env(TOKEN, 2, 2, 1, Command::ReleaseKillSwitch));
    let released = match resp {
        BrokerResponse::Ok(s) => s,
        o => panic!("expected Ok, got {o:?}"),
    };
    assert_eq!(released.logical_state, KillSwitchState::Released);
    assert!(!state_b.severed.load(Ordering::SeqCst), "egress restored");
}

// ── Reconcile alarm: journal says Engaged but the OS rule is gone ───────────
#[test]
fn recovery_flags_inconsistent_when_os_rule_disagrees() {
    let dir = tempfile::tempdir().unwrap();
    {
        let broker_a = mk(dir.path(), MockState::new(false));
        broker_a.handle(env(TOKEN, 1, 1, 0, Command::EngageKillSwitch));
    }
    // Session B: the OS rule is NOT present (override to false), contradicting
    // the persisted Engaged journal.
    let state_b = MockState::new(true);
    *state_b.observed_override.lock().unwrap() = Some(false);
    let broker_b = mk(dir.path(), state_b);
    let status = broker_b.status();
    assert_eq!(status.logical_state, KillSwitchState::Engaged);
    assert_eq!(status.os_rule_present, Some(false));
    assert_eq!(status.recovery, Recovery::Inconsistent);
    assert!(
        status.is_alarm(),
        "a journal/OS disagreement is a fail-closed alarm"
    );
}
