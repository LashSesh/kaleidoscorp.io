//! Crash-safe startup reconciliation (roadmap P3).
//!
//! # The problem
//!
//! The broker persists its journal *after* the OS effect succeeds, so a crash
//! never leaves a half-committed journal — but it can leave a **stranded**
//! machine: enforcement in place with no live process that knows about it. The
//! journal and the OS can disagree in six ways, and only one of them is
//! "everything is fine".
//!
//! [`crate::Broker::reconcile_startup`] is the single place that decision is
//! made, and [`ReconcilePolicy`] is what separates *looking* from *acting*.
//!
//! # The sweep is unconditional, and that is the load-bearing decision
//!
//! On a non-`Engaged` journal the reconciler runs [`BoundaryRecoverer::recover`]
//! **whatever the observation says** — including when the observation is
//! `None` ("the probe could not answer").
//!
//! The reason is specific and measured: the shipped netsh probe classifies
//! purely on exit code, and exit code 1 covers *no match*, *invalid value*,
//! *wrong argument count* and *unknown command* alike. It can therefore confirm
//! presence and can never conclude absence, so it never returns `Some(false)` —
//! it returns `None`. Under that probe, `Armed + None` is **exactly what a
//! stranded orphan rule looks like**, and
//! [`crate::status::KillSwitchStatus::reconcile`] correctly maps it to
//! `Consistent`. Gating the sweep on the observation would therefore make the
//! crash-strand case — the entire reason this phase exists — invisible.
//!
//! The sweep is safe to run unconditionally because it is
//! **receipt-less and idempotent**: the enforcement to remove is re-derived from
//! the [`ssk_boundary::BoundaryScope`] the broker is configured with, so nothing
//! on disk influences a privileged action, and removing something that is not
//! there reports [`ssk_boundary::ReleaseOutcome::AlreadyAbsent`].
//!
//! # The other direction is not symmetric
//!
//! On an `Engaged` journal with an *unanswerable* observation the reconciler
//! does **nothing** and raises [`crate::Recovery::Inconsistent`]. Mutating on an
//! observation you do not have is how a kill-switch comes to report restored
//! egress it never restored. The switch stays `Engaged` holding its receipt, so
//! it remains releasable.

use ssk_boundary::{BoundaryError, BoundaryScope, KillSwitchState, ReleaseOutcome};

use crate::lease::Lease;
use crate::status::Recovery;

/// Remove the enforcement a scope maps to, with **no receipt involved**.
///
/// Deliberately separate from [`ssk_boundary::BoundaryEnforcer`]: `release`
/// requires a receipt, and the whole point of the startup sweep is that no
/// receipt is trusted — or exists. An implementation derives the rule name or
/// filter key from the scope itself, which is the same discipline
/// `release_scoped` already establishes (re-derive what you own; never trust a
/// name carried in a file).
///
/// `ssk_winhost::WindowsEgressEnforcer::recover(&self, scope: &BoundaryScope)
/// -> Result<ReleaseOutcome, BoundaryError>` already has exactly this shape, so
/// the production implementation is an `impl` block, not new logic.
pub trait BoundaryRecoverer: Send {
    /// # Errors
    /// [`BoundaryError::Enforcement`] if the removal or its post-condition
    /// failed.
    fn recover(&self, scope: &BoundaryScope) -> Result<ReleaseOutcome, BoundaryError>;
}

/// What the reconciler is allowed to do about a disagreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReconcilePolicy {
    /// Report only. **No OS effect is attempted at all**, and no lease is
    /// discarded. For `killswitch status` and for a diagnostic run.
    ObserveOnly,
    /// Make the OS match the journal. The service-start policy.
    EnforceJournal,
}

/// What the reconciler actually did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReconcileAction {
    /// Journal and OS agreed; nothing was touched.
    None,
    /// The journal said `Engaged` and the enforcement was positively **absent**:
    /// the enforcer was re-driven. The switch keeps its `Engaged` state — a
    /// kill-switch does not disarm itself because someone deleted its rule.
    ReEngaged,
    /// The journal was not `Engaged`, so the receipt-less sweep ran. See the
    /// module header for why this is unconditional.
    Swept(ReleaseOutcome),
    /// Every live claim on an `Engaged` switch was provably dead (all
    /// `Session`, all from a previous process), so the switch was released.
    ReleasedWithNoRemainingHolder(ReleaseOutcome),
    /// A branch that must not guess: nothing was mutated and the verdict is
    /// [`Recovery::Inconsistent`].
    Deferred { detail: String },
    /// [`ReconcilePolicy::ObserveOnly`] was in force. Nothing was mutated,
    /// whatever the table said.
    Observed,
}

impl ReconcileAction {
    /// Whether this action attempted an OS effect. Used by the tests that pin
    /// [`ReconcilePolicy::ObserveOnly`] to zero side effects.
    #[must_use]
    pub fn touched_the_os(&self) -> bool {
        match self {
            ReconcileAction::ReEngaged
            | ReconcileAction::Swept(_)
            | ReconcileAction::ReleasedWithNoRemainingHolder(_) => true,
            ReconcileAction::None
            | ReconcileAction::Deferred { .. }
            | ReconcileAction::Observed => false,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            ReconcileAction::None => "none",
            ReconcileAction::ReEngaged => "re_engaged",
            ReconcileAction::Swept(_) => "swept",
            ReconcileAction::ReleasedWithNoRemainingHolder(_) => "released_no_holder",
            ReconcileAction::Deferred { .. } => "deferred",
            ReconcileAction::Observed => "observed",
        }
    }
}

/// The outcome of one reconciliation, in full.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReconcileReport {
    /// The journal state **after** reconciling.
    pub logical_state: KillSwitchState,
    /// The observation the decision was made on.
    pub observed: Option<bool>,
    /// The verdict a caller should surface.
    pub verdict: Recovery,
    pub action: ReconcileAction,
    /// The claims discarded as provably dead, each of which is also audited.
    pub leases_discarded: Vec<Lease>,
    /// Duplicate lease ids found in the persisted snapshot (corruption, counted
    /// once — see [`crate::lease::LeaseSet::from_persisted`]).
    pub duplicate_leases: usize,
    /// The state version after reconciling.
    pub state_version: u64,
}

impl ReconcileReport {
    /// Whether an operator must be shown this in red.
    #[must_use]
    pub fn is_alarm(&self) -> bool {
        matches!(self.verdict, Recovery::Inconsistent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_mutating_actions_report_touching_the_os() {
        assert!(!ReconcileAction::None.touched_the_os());
        assert!(!ReconcileAction::Observed.touched_the_os());
        assert!(!ReconcileAction::Deferred {
            detail: String::new()
        }
        .touched_the_os());
        assert!(ReconcileAction::ReEngaged.touched_the_os());
        assert!(ReconcileAction::Swept(ReleaseOutcome::AlreadyAbsent).touched_the_os());
        assert!(
            ReconcileAction::ReleasedWithNoRemainingHolder(ReleaseOutcome::Reverted)
                .touched_the_os()
        );
    }

    #[test]
    fn action_names_are_distinct() {
        let names = [
            ReconcileAction::None.as_str(),
            ReconcileAction::ReEngaged.as_str(),
            ReconcileAction::Swept(ReleaseOutcome::Reverted).as_str(),
            ReconcileAction::ReleasedWithNoRemainingHolder(ReleaseOutcome::Reverted).as_str(),
            ReconcileAction::Deferred {
                detail: String::new(),
            }
            .as_str(),
            ReconcileAction::Observed.as_str(),
        ];
        let unique: std::collections::BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(unique.len(), names.len());
    }

    #[test]
    fn a_report_is_an_alarm_exactly_when_the_verdict_is_inconsistent() {
        let base = ReconcileReport {
            logical_state: KillSwitchState::Armed,
            observed: None,
            verdict: Recovery::Consistent,
            action: ReconcileAction::None,
            leases_discarded: Vec::new(),
            duplicate_leases: 0,
            state_version: 0,
        };
        assert!(!base.is_alarm());
        assert!(!ReconcileReport {
            verdict: Recovery::Reconciled,
            ..base.clone()
        }
        .is_alarm());
        assert!(ReconcileReport {
            verdict: Recovery::Inconsistent,
            ..base
        }
        .is_alarm());
    }
}
