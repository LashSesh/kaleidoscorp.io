//! P2 control-layer tests (SPEC_TAURI_GUI.md §12/P2): drive the privileged
//! kill-switch verbs through the bridge control layer end-to-end against a real
//! in-process broker + mock enforcer, on Linux. The named-pipe transport +
//! client-SID auth are the Windows seam (later); the command construction,
//! response mapping, and stale-version auto-retry are verified here.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use ssk_boundary::{
    BoundaryEnforcer, BoundaryError, BoundaryPolicy, BoundaryScope, EnforcementReceipt,
    KillSwitchState, BOUNDARY_CONTROL_USE,
};
use ssk_signature::AuthorizationManifest;
use ssk_types::SessionId;

use ssk_netd_helper::{
    Broker, BrokerConfig, BrokerResponse, CapabilityToken, CommandEnvelope, EgressObserver,
    HelperError, PersistedState, ReceiptStore,
};

use ssk_tauri_bridge::control::{ControlClient, ControlError, KillSwitchControl, NonceSource};

const TOKEN: CapabilityToken = CapabilityToken([7u8; 16]);

// ── mocks (mirrors the P0 broker test) ───────────────────────────────────────

struct MockState {
    severed: AtomicBool,
    engage_calls: AtomicU32,
    fail_engage: AtomicBool,
}
impl MockState {
    fn new() -> Arc<Self> {
        Arc::new(MockState {
            severed: AtomicBool::new(false),
            engage_calls: AtomicU32::new(0),
            fail_engage: AtomicBool::new(false),
        })
    }
}
struct MockEnforcer(Arc<MockState>);
struct MockObserver(Arc<MockState>);
impl BoundaryEnforcer for MockEnforcer {
    fn engage(&self, scope: &BoundaryScope) -> Result<EnforcementReceipt, BoundaryError> {
        if self.0.fail_engage.load(Ordering::SeqCst) {
            return Err(BoundaryError::Enforcement("mock fail".to_owned()));
        }
        self.0.engage_calls.fetch_add(1, Ordering::SeqCst);
        let r = EnforcementReceipt::new(scope, "flowing");
        self.0.severed.store(true, Ordering::SeqCst);
        Ok(r)
    }
    fn release(&self, _r: &EnforcementReceipt) -> Result<(), BoundaryError> {
        self.0.severed.store(false, Ordering::SeqCst);
        Ok(())
    }
}
impl EgressObserver for MockObserver {
    fn rule_present(&self, _scope: &str) -> Option<bool> {
        Some(self.0.severed.load(Ordering::SeqCst))
    }
}

/// An in-memory durable store, so the control tests need no filesystem.
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

/// A deterministic nonce/key source for tests (production supplies a CSPRNG).
struct SeqNonces(u128);
impl NonceSource for SeqNonces {
    fn next(&mut self) -> [u8; 16] {
        self.0 += 1;
        self.0.to_le_bytes()
    }
}

/// The in-process transport: the control layer sends straight into a `Broker`.
struct InProcess<'a>(&'a Broker);
impl ControlClient for InProcess<'_> {
    fn send(&self, envelope: CommandEnvelope) -> BrokerResponse {
        self.0.handle(envelope)
    }
}

fn broker(state: Arc<MockState>, token: CapabilityToken) -> Broker {
    let cfg = BrokerConfig {
        session_token: token,
        actuation_auth: AuthorizationManifest::new("helper", "system", "broker")
            .with_allowed_uses([BOUNDARY_CONTROL_USE]),
        scope: BoundaryScope::all_egress(),
        policy: BoundaryPolicy::default(),
        session: SessionId::new("sess-p2"),
    };
    Broker::recover(
        cfg,
        Box::new(MemStore::default()),
        Box::new(MockEnforcer(state.clone())),
        Box::new(MockObserver(state)),
    )
    .unwrap()
}

// ── tests ────────────────────────────────────────────────────────────────────

#[test]
fn engage_then_release_through_the_control_layer() {
    let state = MockState::new();
    let b = broker(state.clone(), TOKEN);
    let mut ctl = KillSwitchControl::new(InProcess(&b), SeqNonces(0), TOKEN, 0);

    let engaged = ctl.engage().unwrap();
    assert_eq!(engaged.logical_state, KillSwitchState::Engaged);
    assert_eq!(engaged.state_version, 1);
    assert_eq!(ctl.known_version(), 1, "the driver tracks the new version");
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 1);

    let released = ctl.release().unwrap();
    assert_eq!(released.logical_state, KillSwitchState::Released);
    assert_eq!(released.state_version, 2);
    assert_eq!(ctl.known_version(), 2);
    assert!(!state.severed.load(Ordering::SeqCst), "egress restored");
}

#[test]
fn refresh_reads_authoritative_status() {
    let b = broker(MockState::new(), TOKEN);
    let mut ctl = KillSwitchControl::new(InProcess(&b), SeqNonces(0), TOKEN, 0);
    let status = ctl.refresh().unwrap();
    assert_eq!(status.logical_state, KillSwitchState::Armed);
    assert_eq!(status.state_version, 0);
}

// A driver that started with a wrong (stale) version still succeeds: it adopts
// the broker's real version and retries once with a fresh nonce.
#[test]
fn a_stale_starting_version_is_refreshed_and_retried_once() {
    let state = MockState::new();
    let b = broker(state.clone(), TOKEN);
    // The driver wrongly believes the version is 5; the broker is at 0.
    let mut ctl = KillSwitchControl::new(InProcess(&b), SeqNonces(0), TOKEN, 5);

    let engaged = ctl.engage().unwrap();
    assert_eq!(engaged.logical_state, KillSwitchState::Engaged);
    assert_eq!(engaged.state_version, 1);
    assert_eq!(
        state.engage_calls.load(Ordering::SeqCst),
        1,
        "the OS effect ran exactly once despite the retry"
    );
}

#[test]
fn a_bad_token_is_a_typed_rejection() {
    let b = broker(MockState::new(), TOKEN);
    let wrong = CapabilityToken([0u8; 16]);
    let mut ctl = KillSwitchControl::new(InProcess(&b), SeqNonces(0), wrong, 0);
    let err = ctl.engage().unwrap_err();
    assert!(matches!(err, ControlError::Rejected(_)), "got {err:?}");
}

#[test]
fn an_enforcer_failure_surfaces_as_failed_with_no_state_change() {
    let state = MockState::new();
    state.fail_engage.store(true, Ordering::SeqCst);
    let b = broker(state.clone(), TOKEN);
    let mut ctl = KillSwitchControl::new(InProcess(&b), SeqNonces(0), TOKEN, 0);

    let err = ctl.engage().unwrap_err();
    assert!(matches!(err, ControlError::Failed(_)), "got {err:?}");
    // The broker's state is unchanged (rollback contract).
    assert_eq!(ctl.refresh().unwrap().logical_state, KillSwitchState::Armed);
}
