//! P3 — crash-safe startup reconciliation and cross-session refcounting.
//!
//! Everything here drives injected seams: a scripted `BoundaryEnforcer`, a
//! scripted `EgressObserver`, a call-recording `BoundaryRecoverer` and a
//! temp-dir `ReceiptStore`. The whole (journal × observation × claim-set)
//! decision table is enumerated rather than spot-checked, because a change to
//! one cell must not be able to quietly move another.
//!
//! What is **not** proven here, and must not be read as if it were: that a
//! real firewall rule survives a `taskkill`, that a real probe ever returns
//! `Some(false)`, or that the receipt-less sweep removes anything on a real
//! machine. Those need an elevated VM.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use ssk_boundary::{
    BoundaryEnforcer, BoundaryError, BoundaryPolicy, BoundaryScope, EnforcementReceipt,
    KillSwitchState, ReleaseOutcome, BOUNDARY_CONTROL_USE,
};
use ssk_signature::AuthorizationManifest;
use ssk_types::SessionId;

use ssk_netd_helper::{
    BoundaryRecoverer, Broker, BrokerConfig, BrokerResponse, CapabilityToken, Command,
    CommandEnvelope, EgressObserver, FileReceiptStore, HelperError, IdempotencyKey, Lease, LeaseId,
    LeaseKind, Nonce, PersistedState, ReceiptStore, ReconcileAction, ReconcilePolicy, Recovery,
};

const TOKEN: CapabilityToken = CapabilityToken([7u8; 16]);

// ── scripted seams ──────────────────────────────────────────────────────────

#[derive(Default)]
struct Scripted {
    severed: AtomicBool,
    engage_calls: AtomicU32,
    release_calls: AtomicU32,
    recover_calls: AtomicU32,
    /// When set, the observer reports this instead of the real severed flag —
    /// `None` inside the `Some` means "the probe could not answer".
    observed_override: Mutex<Option<Option<bool>>>,
    fail_engage: AtomicBool,
}

impl Scripted {
    fn new() -> Arc<Self> {
        Arc::new(Scripted::default())
    }
    fn observe_as(self: &Arc<Self>, value: Option<bool>) {
        *self.observed_override.lock().unwrap() = Some(value);
    }
}

struct Enforcer(Arc<Scripted>);
struct Observer(Arc<Scripted>);
struct Recoverer(Arc<Scripted>);

impl BoundaryEnforcer for Enforcer {
    fn engage(&self, scope: &BoundaryScope) -> Result<EnforcementReceipt, BoundaryError> {
        if self.0.fail_engage.load(Ordering::SeqCst) {
            return Err(BoundaryError::Enforcement("scripted failure".to_owned()));
        }
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

impl EgressObserver for Observer {
    fn rule_present(&self, _scope: &str) -> Option<bool> {
        match *self.0.observed_override.lock().unwrap() {
            Some(value) => value,
            None => Some(self.0.severed.load(Ordering::SeqCst)),
        }
    }
}

impl BoundaryRecoverer for Recoverer {
    fn recover(&self, _scope: &BoundaryScope) -> Result<ReleaseOutcome, BoundaryError> {
        self.0.recover_calls.fetch_add(1, Ordering::SeqCst);
        // The receipt-less sweep is idempotent: removing something that is not
        // there is `AlreadyAbsent`, not an error.
        let was = self.0.severed.swap(false, Ordering::SeqCst);
        Ok(if was {
            ReleaseOutcome::Reverted
        } else {
            ReleaseOutcome::AlreadyAbsent
        })
    }
}

fn config(session: &str) -> BrokerConfig {
    BrokerConfig {
        session_token: TOKEN,
        actuation_auth: AuthorizationManifest::new("ssk-netd-helper", "system", "broker")
            .with_allowed_uses([BOUNDARY_CONTROL_USE]),
        scope: BoundaryScope::all_egress(),
        policy: BoundaryPolicy::default(),
        session: SessionId::new(session),
    }
}

fn broker(dir: &std::path::Path, state: Arc<Scripted>, with_recoverer: bool) -> Broker {
    let b = Broker::recover(
        config("sess-p3-reconcile"),
        Box::new(FileReceiptStore::open_existing(dir).unwrap()),
        Box::new(Enforcer(state.clone())),
        Box::new(Observer(state.clone())),
    )
    .unwrap();
    if with_recoverer {
        b.with_recoverer(Box::new(Recoverer(state)))
    } else {
        b
    }
}

fn env(nonce: u8, key: u8, version: u64, command: Command) -> CommandEnvelope {
    CommandEnvelope {
        session_token: TOKEN,
        nonce: Nonce([nonce; 16]),
        idempotency_key: IdempotencyKey([key; 16]),
        expected_state_version: version,
        command,
    }
}

/// Write a snapshot directly, so a test can construct any (journal, claim-set)
/// pair a crash could have left behind — including ones the happy path cannot
/// produce.
fn plant(dir: &std::path::Path, snapshot: &PersistedState) {
    FileReceiptStore::open_existing(dir)
        .unwrap()
        .save(snapshot)
        .unwrap();
}

fn engaged_snapshot(version: u64, leases: Vec<Lease>) -> PersistedState {
    // The receipt and journal are produced by a real engage so the audit chain
    // and the receipt digest are genuine; only the claim set is synthesised.
    let dir = tempfile::tempdir().unwrap();
    let state = Scripted::new();
    let b = broker(dir.path(), state, false);
    assert!(matches!(
        b.handle(env(1, 1, 0, Command::EngageKillSwitch)),
        BrokerResponse::Ok(_)
    ));
    let mut snap = FileReceiptStore::open_existing(dir.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    snap.state_version = version;
    snap.leases = leases;
    snap
}

fn session_lease(byte: u8) -> Lease {
    Lease {
        id: LeaseId([byte; 16]),
        kind: LeaseKind::Session,
        holder: "S-1-5-21-1-2-3-1001".to_owned(),
        taken_at_version: 0,
    }
}

fn pinned_lease(byte: u8) -> Lease {
    Lease {
        kind: LeaseKind::Pinned,
        ..session_lease(byte)
    }
}

// ── ObserveOnly: zero side effects, whatever the table says ────────────────

/// `killswitch status` must be able to run on a machine it is not allowed to
/// change. Every branch of the table is exercised under `ObserveOnly` and none
/// of them may touch the enforcer, the recoverer, the claim set or the version.
#[test]
fn observe_only_never_touches_anything_in_any_cell_of_the_table() {
    for (label, snapshot, observed) in [
        (
            "engaged, rule present, one dead session claim",
            engaged_snapshot(1, vec![session_lease(1)]),
            Some(true),
        ),
        (
            "engaged, rule gone",
            engaged_snapshot(1, vec![pinned_lease(2)]),
            Some(false),
        ),
        (
            "engaged, probe cannot answer",
            engaged_snapshot(1, vec![pinned_lease(3)]),
            None,
        ),
        (
            "engaged with no remaining holder",
            engaged_snapshot(1, Vec::new()),
            Some(true),
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        plant(dir.path(), &snapshot);
        let state = Scripted::new();
        state.severed.store(true, Ordering::SeqCst);
        state.observe_as(observed);
        let b = broker(dir.path(), state.clone(), true);

        let report = b.reconcile_startup(ReconcilePolicy::ObserveOnly).unwrap();
        assert_eq!(report.action, ReconcileAction::Observed, "{label}");
        assert!(!report.action.touched_the_os(), "{label}");
        assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0, "{label}");
        assert_eq!(state.release_calls.load(Ordering::SeqCst), 0, "{label}");
        assert_eq!(state.recover_calls.load(Ordering::SeqCst), 0, "{label}");
        assert_eq!(report.state_version, 1, "{label}: version did not move");
        assert!(
            report.leases_discarded.is_empty(),
            "{label}: no claim may be discarded by a look"
        );
        assert_eq!(
            b.leases().len(),
            snapshot.leases.len(),
            "{label}: the claim set is untouched"
        );
    }
}

// ── EnforceJournal: the decision table ─────────────────────────────────────

#[test]
fn engaged_with_a_live_holder_and_a_present_rule_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    plant(dir.path(), &engaged_snapshot(1, vec![pinned_lease(1)]));
    let state = Scripted::new();
    state.severed.store(true, Ordering::SeqCst);
    let b = broker(dir.path(), state.clone(), true);

    let report = b
        .reconcile_startup(ReconcilePolicy::EnforceJournal)
        .unwrap();
    assert_eq!(report.action, ReconcileAction::None);
    assert_eq!(report.logical_state, KillSwitchState::Engaged);
    assert_eq!(report.verdict, Recovery::Reconciled);
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.recover_calls.load(Ordering::SeqCst), 0);
    assert!(state.severed.load(Ordering::SeqCst));
}

/// Someone deleted our rule while a holder still wants it. A kill-switch does
/// not disarm itself because its rule was removed: it re-asserts.
#[test]
fn engaged_with_a_live_holder_and_an_absent_rule_re_engages_and_stays_engaged() {
    let dir = tempfile::tempdir().unwrap();
    plant(dir.path(), &engaged_snapshot(1, vec![pinned_lease(1)]));
    let state = Scripted::new();
    state.severed.store(false, Ordering::SeqCst); // the rule is gone
    let b = broker(dir.path(), state.clone(), true);

    let report = b
        .reconcile_startup(ReconcilePolicy::EnforceJournal)
        .unwrap();
    assert_eq!(report.action, ReconcileAction::ReEngaged);
    assert_eq!(report.logical_state, KillSwitchState::Engaged);
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 0);
    assert!(state.severed.load(Ordering::SeqCst), "enforcement restored");
    assert_eq!(
        report.verdict,
        Recovery::Reconciled,
        "the verdict describes the machine after the repair, not before it"
    );
    // The original receipt is preserved: it records the true pre-engagement
    // state, and overwriting it would destroy the only record of what to
    // restore to.
    assert!(b.status().receipt.is_some());
    assert_eq!(b.leases().len(), 1, "the holder still holds");
}

/// Mutating on an observation you do not have is how a kill-switch comes to
/// report restored egress it never restored. This branch must do nothing at all
/// and raise the alarm.
#[test]
fn engaged_with_a_live_holder_and_an_unanswerable_probe_defers_and_alarms() {
    let dir = tempfile::tempdir().unwrap();
    plant(dir.path(), &engaged_snapshot(1, vec![pinned_lease(1)]));
    let state = Scripted::new();
    state.severed.store(true, Ordering::SeqCst);
    state.observe_as(None);
    let b = broker(dir.path(), state.clone(), true);

    let report = b
        .reconcile_startup(ReconcilePolicy::EnforceJournal)
        .unwrap();
    assert!(
        matches!(report.action, ReconcileAction::Deferred { .. }),
        "{:?}",
        report.action
    );
    assert_eq!(report.verdict, Recovery::Inconsistent);
    assert!(report.is_alarm());
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.recover_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        b.status().logical_state,
        KillSwitchState::Engaged,
        "the switch stays engaged holding its receipt, so it is still releasable"
    );
}

/// The strand, and its removal. Every claim was a session claim from a process
/// that is gone, so nothing wants the machine severed any more.
#[test]
fn engaged_with_only_dead_session_claims_releases_and_reports_the_discards() {
    let dir = tempfile::tempdir().unwrap();
    plant(
        dir.path(),
        &engaged_snapshot(1, vec![session_lease(1), session_lease(2)]),
    );
    let state = Scripted::new();
    state.severed.store(true, Ordering::SeqCst);
    let b = broker(dir.path(), state.clone(), true);

    let report = b
        .reconcile_startup(ReconcilePolicy::EnforceJournal)
        .unwrap();
    assert!(
        matches!(
            report.action,
            ReconcileAction::ReleasedWithNoRemainingHolder(_)
        ),
        "{:?}",
        report.action
    );
    assert_eq!(report.leases_discarded.len(), 2);
    assert!(report
        .leases_discarded
        .iter()
        .all(|l| l.kind == LeaseKind::Session));
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 1);
    assert!(
        !state.severed.load(Ordering::SeqCst),
        "a machine severed only by claims that are provably dead must not stay severed"
    );
    assert_eq!(report.logical_state, KillSwitchState::Released);
    assert!(b.leases().is_empty());
    assert!(report.state_version > 1, "the transition was committed");
}

/// A pinned claim is exactly the case that must *not* be swept away by a
/// restart: an operator deliberately severed this machine.
#[test]
fn a_pinned_claim_keeps_the_machine_severed_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    plant(
        dir.path(),
        &engaged_snapshot(1, vec![session_lease(1), pinned_lease(2)]),
    );
    let state = Scripted::new();
    state.severed.store(true, Ordering::SeqCst);
    let b = broker(dir.path(), state.clone(), true);

    let report = b
        .reconcile_startup(ReconcilePolicy::EnforceJournal)
        .unwrap();
    assert_eq!(report.action, ReconcileAction::None);
    assert_eq!(report.leases_discarded.len(), 1, "only the session claim");
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 0);
    assert!(state.severed.load(Ordering::SeqCst), "still severed");
    assert_eq!(b.leases().len(), 1);
    assert_eq!(b.leases()[0].kind, LeaseKind::Pinned);
}

// ── the unconditional sweep ────────────────────────────────────────────────

/// The single most load-bearing decision in the reconciler. Under a probe that
/// can confirm presence but never conclude absence — which is what the shipped
/// netsh probe is — `Armed + Indeterminate` is exactly what a stranded orphan
/// rule looks like. Gating the sweep on the observation would make the
/// crash-strand case invisible, so it is unconditional.
#[test]
fn a_non_engaged_journal_sweeps_unconditionally_including_when_the_probe_cannot_answer() {
    for observed in [Some(true), Some(false), None] {
        let dir = tempfile::tempdir().unwrap();
        let state = Scripted::new();
        // A rule is stranded on the machine from a previous run, and the journal
        // knows nothing about it.
        state.severed.store(true, Ordering::SeqCst);
        state.observe_as(observed);
        let b = broker(dir.path(), state.clone(), true);
        assert_eq!(b.status().logical_state, KillSwitchState::Armed);

        let report = b
            .reconcile_startup(ReconcilePolicy::EnforceJournal)
            .unwrap();
        assert!(
            matches!(report.action, ReconcileAction::Swept(_)),
            "observed={observed:?}: {:?}",
            report.action
        );
        assert_eq!(
            state.recover_calls.load(Ordering::SeqCst),
            1,
            "observed={observed:?}: the sweep must not be gated on the observation"
        );
        assert!(
            !state.severed.load(Ordering::SeqCst),
            "observed={observed:?}: the orphan is gone"
        );
    }
}

/// The sweep is idempotent, so running it on a genuinely clean machine costs
/// nothing and reports the truth rather than inventing a removal.
#[test]
fn sweeping_a_clean_machine_reports_already_absent() {
    let dir = tempfile::tempdir().unwrap();
    let state = Scripted::new();
    let b = broker(dir.path(), state.clone(), true);
    let report = b
        .reconcile_startup(ReconcilePolicy::EnforceJournal)
        .unwrap();
    assert_eq!(
        report.action,
        ReconcileAction::Swept(ReleaseOutcome::AlreadyAbsent)
    );
    assert_eq!(state.recover_calls.load(Ordering::SeqCst), 1);

    // ...and again.
    let again = b
        .reconcile_startup(ReconcilePolicy::EnforceJournal)
        .unwrap();
    assert_eq!(
        again.action,
        ReconcileAction::Swept(ReleaseOutcome::AlreadyAbsent)
    );
}

/// Without a recoverer the sweep cannot run. That is reported as a deferral
/// with the reason, not as a clean start — an absent capability must never look
/// like a satisfied one.
#[test]
fn without_a_recoverer_the_sweep_defers_and_says_why() {
    let dir = tempfile::tempdir().unwrap();
    let state = Scripted::new();
    state.severed.store(true, Ordering::SeqCst);
    let b = broker(dir.path(), state.clone(), false);

    let report = b
        .reconcile_startup(ReconcilePolicy::EnforceJournal)
        .unwrap();
    match &report.action {
        ReconcileAction::Deferred { detail } => {
            assert!(detail.contains("BoundaryRecoverer"), "{detail}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(report.verdict, Recovery::Inconsistent);
    assert_eq!(state.recover_calls.load(Ordering::SeqCst), 0);
    assert!(
        state.severed.load(Ordering::SeqCst),
        "nothing was swept, and the report does not claim otherwise"
    );
}

// ── refcounting through the in-process entry point ─────────────────────────

/// The claim set is durable: it is part of the snapshot, not in-memory
/// bookkeeping. Without this a restart would forget who is holding the switch.
#[test]
fn the_claim_set_is_part_of_the_durable_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let state = Scripted::new();
    {
        let b = broker(dir.path(), state.clone(), false);
        assert!(matches!(
            b.handle(env(1, 1, 0, Command::EngageKillSwitch)),
            BrokerResponse::Ok(_)
        ));
        assert_eq!(b.leases().len(), 1);
    }
    let snapshot = FileReceiptStore::open_existing(dir.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.leases.len(), 1);
    assert_eq!(snapshot.leases[0].id, LeaseId::IN_PROCESS);

    let b = broker(dir.path(), state, false);
    assert_eq!(b.leases().len(), 1, "the claim survived the restart");
}

/// Re-engaging under a claim you already hold is a no-op: nothing changed, so
/// nothing is persisted and — importantly — the state version does not move.
/// A version bump for a no-op would invalidate every other client's optimistic
/// concurrency token for free.
#[test]
fn re_engaging_under_a_claim_you_already_hold_does_not_move_the_version() {
    let dir = tempfile::tempdir().unwrap();
    let state = Scripted::new();
    let b = broker(dir.path(), state.clone(), false);

    assert!(matches!(
        b.handle(env(1, 1, 0, Command::EngageKillSwitch)),
        BrokerResponse::Ok(_)
    ));
    assert_eq!(b.status().state_version, 1);

    // Fresh nonce, fresh key, correct version.
    match b.handle(env(2, 2, 1, Command::EngageKillSwitch)) {
        BrokerResponse::Ok(status) => {
            assert_eq!(status.logical_state, KillSwitchState::Engaged);
            assert_eq!(status.state_version, 1, "no transition, no bump");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(state.engage_calls.load(Ordering::SeqCst), 1);
    assert_eq!(b.leases().len(), 1);
}

/// Releasing is idempotent in every branch: dropping a claim that is not held,
/// or releasing a switch that is not engaged, is `Ok` with the authoritative
/// status attached. A transport retries, and turning a retry into an error is
/// how a caller comes to retry a release that already happened.
#[test]
fn releasing_when_nothing_is_engaged_is_idempotent_and_touches_no_enforcer() {
    let dir = tempfile::tempdir().unwrap();
    let state = Scripted::new();
    let b = broker(dir.path(), state.clone(), false);

    match b.handle(env(1, 1, 0, Command::ReleaseKillSwitch)) {
        BrokerResponse::Ok(status) => {
            assert_eq!(status.logical_state, KillSwitchState::Armed);
            assert_eq!(status.state_version, 0);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 0);

    assert!(b.close_lease(&LeaseId([0xcd; 16])).is_ok());
    assert_eq!(state.release_calls.load(Ordering::SeqCst), 0);
}

/// An enforcer failure during release must not drop the claim: a severed
/// machine with an empty claim set is the strand this phase exists to remove.
#[test]
fn a_failed_release_puts_the_claim_back() {
    struct FailingRelease(Arc<Scripted>);
    impl BoundaryEnforcer for FailingRelease {
        fn engage(&self, scope: &BoundaryScope) -> Result<EnforcementReceipt, BoundaryError> {
            self.0.engage_calls.fetch_add(1, Ordering::SeqCst);
            self.0.severed.store(true, Ordering::SeqCst);
            Ok(EnforcementReceipt::new(scope, "flowing"))
        }
        fn release(&self, _receipt: &EnforcementReceipt) -> Result<(), BoundaryError> {
            Err(BoundaryError::Enforcement("netsh refused".to_owned()))
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let state = Scripted::new();
    let b = Broker::recover(
        config("failing-release"),
        Box::new(FileReceiptStore::open_existing(dir.path()).unwrap()),
        Box::new(FailingRelease(state.clone())),
        Box::new(Observer(state.clone())),
    )
    .unwrap();

    assert!(matches!(
        b.handle(env(1, 1, 0, Command::EngageKillSwitch)),
        BrokerResponse::Ok(_)
    ));
    assert_eq!(b.leases().len(), 1);

    let response = b.handle(env(2, 2, 1, Command::ReleaseKillSwitch));
    assert!(
        matches!(response, BrokerResponse::Failed(_)),
        "{response:?}"
    );
    assert_eq!(
        b.leases().len(),
        1,
        "the claim must be restored: enforcement is still in place and something \
         has to keep naming a holder for it"
    );
    assert_eq!(b.status().logical_state, KillSwitchState::Engaged);
    assert!(state.severed.load(Ordering::SeqCst));
}

/// A duplicate lease id in the snapshot is corruption, not a doubled claim.
/// Counting it twice would keep the machine severed after every legitimate
/// holder let go.
#[test]
fn a_duplicated_claim_in_the_snapshot_is_counted_once_and_reported() {
    let dir = tempfile::tempdir().unwrap();
    plant(
        dir.path(),
        &engaged_snapshot(1, vec![pinned_lease(1), pinned_lease(1)]),
    );
    let state = Scripted::new();
    state.severed.store(true, Ordering::SeqCst);
    let b = broker(dir.path(), state, true);

    assert_eq!(b.leases().len(), 1);
    let report = b
        .reconcile_startup(ReconcilePolicy::EnforceJournal)
        .unwrap();
    assert_eq!(report.duplicate_leases, 1, "corruption is surfaced");
}

/// The startup reconciliation is a privileged action and is gated on the
/// broker's own actuation authority, exactly like a verb is.
#[test]
fn reconciliation_is_refused_when_the_broker_has_no_actuation_grant() {
    use ssk_netd_helper::ActuationAuthority;

    let dir = tempfile::tempdir().unwrap();
    let state = Scripted::new();
    state.severed.store(true, Ordering::SeqCst);
    let b = Broker::recover_with_policy(
        config("no-grant"),
        ActuationAuthority::Table(ssk_signature::policy::AuthorizationPolicyTable::deny_all()),
        Box::new(FileReceiptStore::open_existing(dir.path()).unwrap()),
        Box::new(Enforcer(state.clone())),
        Box::new(Observer(state.clone())),
    )
    .unwrap()
    .with_recoverer(Box::new(Recoverer(state.clone())));

    let err = b
        .reconcile_startup(ReconcilePolicy::EnforceJournal)
        .expect_err("an unauthorized broker must not sweep");
    assert!(matches!(err, HelperError::Boundary(_)), "{err:?}");
    assert_eq!(state.recover_calls.load(Ordering::SeqCst), 0);

    // ...but looking is still allowed, because looking changes nothing.
    assert!(b.reconcile_startup(ReconcilePolicy::ObserveOnly).is_ok());
}
