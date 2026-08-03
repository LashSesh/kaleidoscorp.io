//! The two `ssk-netd-helper` seams that *read* and *undo* the real firewall.
//!
//! Both are one-line bridges onto machinery P1 already built and tested. They
//! live here, together, because they answer the same question from opposite
//! ends — "is the enforcement in place?" and "make it not be, without trusting
//! a receipt" — and because the pure crate that declares them
//! (`#![forbid(unsafe_code)]`) can hold neither a `netsh` spawn nor a firewall
//! handle.
//!
//! * [`TieredEgressObserver`] implements
//!   [`ssk_netd_helper::EgressObserver`]. It contains **no netsh knowledge at
//!   all**: it composes [`ssk_boundary::BoundaryProbe`] implementations, so P1's
//!   exit-code-only, never-read-the-text classification is inherited rather than
//!   re-implemented.
//! * [`ssk_netd_helper::BoundaryRecoverer`] is implemented for
//!   [`WindowsEgressEnforcer`], whose inherent `recover` already has exactly
//!   that signature.
//!
//! # The finding this module exposes, stated rather than hidden
//!
//! P1's [`crate::firewall::classify_show`] **never returns
//! [`Presence::Absent`]** — deliberately, because netsh's exit code cannot
//! distinguish "no such rule" from "bad argument" from "service unreachable".
//! That is correct, and it has a consequence the roadmap's P3 exit criterion
//! depends on:
//!
//! | `reconcile(Engaged, …)` | reachable on the netsh mechanism? |
//! |---|---|
//! | `None` → `Inconsistent` (cannot confirm a severed claim) | **yes** |
//! | `Some(false)` → `Inconsistent` (the rule was removed underneath us) | **no** |
//!
//! So *"raises `Inconsistent` when the OS rule was removed underneath it"* is
//! **not satisfiable by the shipped netsh probe**. It needs a negative-capable
//! mechanism: WFP's `FwpmFilterGetByKey0` → `FWP_E_FILTER_NOT_FOUND`, or P1's
//! already-evaluated `Get-NetFirewallRule` cold path (read
//! `FullyQualifiedErrorId`, never `.Message`; ~31× slower; degrades under
//! Constrained Language Mode / AppLocker / ASR).
//!
//! The tier list exists precisely so such a probe can be appended as tier 2
//! without changing tier 1 or this type. Neither negative-capable probe is
//! implemented in this change, and nothing here pretends otherwise — with only
//! the netsh probe configured, `rule_present` returns `Some(true)` or `None`
//! and never `Some(false)`. That is asserted by a test.

use ssk_boundary::{
    BoundaryError, BoundaryObservation, BoundaryProbe, BoundaryScope, Presence, ReleaseOutcome,
};
use ssk_netd_helper::{BoundaryRecoverer, EgressObserver};

use crate::firewall::WindowsEgressEnforcer;

/// Mechanism label reported when no probe was configured at all. Not a real
/// actuator; it exists so a `BoundaryObservation` always names *something* and
/// the "nobody asked anybody" case is distinguishable in a log from "netsh
/// could not answer".
pub const MECHANISM_NONE: &str = "no-probe";

/// Answers [`EgressObserver`] from one or more real [`BoundaryProbe`]s.
///
/// It holds the whole [`BoundaryScope`], not just a label. The rule identity is
/// a function of the *entire* scope — `rule_name_for_scope` digests
/// `{label, targets}` — so an observer given only a `&str` label would have to
/// invent a scope and would then be answering about a different rule.
pub struct TieredEgressObserver {
    scope: BoundaryScope,
    /// Ordered fast → slow. The **first decisive** answer ([`Presence::Present`]
    /// or [`Presence::Absent`]) wins; [`Presence::Indeterminate`] falls through
    /// to the next tier. If every tier is indeterminate the observation is
    /// indeterminate. **No path turns a failure into `Absent`.**
    probes: Vec<Box<dyn BoundaryProbe + Send + Sync>>,
}

impl TieredEgressObserver {
    /// Build an observer over `probes`, ordered fast → slow.
    ///
    /// An empty `probes` list is accepted and answers
    /// [`Presence::Indeterminate`] forever. That is deliberate: refusing to
    /// construct would push the caller toward a "no observer" fallback, and a
    /// broker with no observer is exactly the thing whose `Engaged` status
    /// cannot be checked. An observer that says "I cannot tell" is fail-closed;
    /// an absent observer is not.
    #[must_use]
    pub fn new(scope: BoundaryScope, probes: Vec<Box<dyn BoundaryProbe + Send + Sync>>) -> Self {
        TieredEgressObserver { scope, probes }
    }

    /// The default production stack: P1's `netsh advfirewall` probe alone.
    ///
    /// One tier, and the module header says what that costs: `Some(false)` is
    /// unreachable, so the "someone deleted our rule" alarm cannot fire on this
    /// mechanism.
    #[must_use]
    pub fn netsh_only(scope: BoundaryScope) -> Self {
        Self::new(scope, vec![Box::new(WindowsEgressEnforcer::new())])
    }

    /// The scope this observer answers about.
    #[must_use]
    pub fn scope(&self) -> &BoundaryScope {
        &self.scope
    }

    /// How many tiers are configured. Observability for a startup log line —
    /// never a decision.
    #[must_use]
    pub fn tier_count(&self) -> usize {
        self.probes.len()
    }

    /// The full three-valued observation, with the mechanism that produced it
    /// and its opaque evidence — for logs and for an operator-facing
    /// `killswitch status`.
    ///
    /// [`EgressObserver::rule_present`] is the lossy `Option<bool>` bridge the
    /// broker's status reconciliation speaks; this is what actually happened.
    #[must_use]
    pub fn observe(&self) -> BoundaryObservation {
        let mut reasons: Vec<String> = Vec::with_capacity(self.probes.len());
        let mut last_mechanism = MECHANISM_NONE;
        for probe in &self.probes {
            let observation = probe.observe(&self.scope);
            last_mechanism = observation.mechanism;
            match &observation.presence {
                // Decisive in either direction: stop. A later, slower tier
                // cannot improve on a positive observation, and asking it
                // anyway would let a flaky tier overturn a good answer.
                Presence::Present | Presence::Absent => return observation,
                Presence::Indeterminate { detail } => {
                    reasons.push(format!("{}: {detail}", observation.mechanism));
                }
                // `Presence` is `#[non_exhaustive]`, so a wildcard is forced.
                // A future variant this code has never seen is treated as
                // *unanswered*, which is the fail-closed direction: it falls
                // through to the next tier and, if nothing answers, reads as
                // `None`. It must never be folded into `Present`/`Absent`.
                other => {
                    reasons.push(format!(
                        "{}: unrecognised presence variant {other:?}, treated as unanswered",
                        observation.mechanism
                    ));
                }
            }
        }
        let detail = if reasons.is_empty() {
            "no boundary probe is configured, so enforcement presence cannot be observed at all"
                .to_owned()
        } else {
            reasons.join(" | ")
        };
        BoundaryObservation {
            evidence: detail.clone(),
            presence: Presence::Indeterminate { detail },
            mechanism: last_mechanism,
        }
    }
}

impl EgressObserver for TieredEgressObserver {
    fn rule_present(&self, scope_label: &str) -> Option<bool> {
        if scope_label != self.scope.label {
            // A label that is not ours is not a question we can answer. `None`
            // ("cannot determine"), never `Some(false)` — the broker treats an
            // unanswerable probe on an `Engaged` journal as a fail-closed
            // alarm, and `Some(false)` would instead assert that the rule this
            // observer never looked for is gone.
            return None;
        }
        self.observe().presence.as_option_bool()
    }
}

/// The receipt-less sweep, bound to P1's inherent
/// [`WindowsEgressEnforcer::recover`].
///
/// Deliberately not `BoundaryEnforcer::release`: `release` requires a receipt,
/// and the whole point of the startup sweep is that no receipt is trusted — or
/// exists. The rule name is re-derived from the scope inside `recover`, so
/// nothing read from disk influences which rule is deleted.
impl BoundaryRecoverer for WindowsEgressEnforcer {
    fn recover(&self, scope: &BoundaryScope) -> Result<ReleaseOutcome, BoundaryError> {
        // Fully qualified so this cannot silently become a recursive call into
        // the trait method it is implementing.
        WindowsEgressEnforcer::recover(self, scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A probe that returns a scripted sequence of presences and counts how
    /// many times it was asked. Counting is what makes "the first decisive
    /// answer wins" falsifiable: a later tier must not even be consulted.
    struct ScriptedProbe {
        presence: Presence,
        mechanism: &'static str,
        calls: Arc<AtomicUsize>,
    }

    impl ScriptedProbe {
        fn new(presence: Presence, mechanism: &'static str) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                ScriptedProbe {
                    presence,
                    mechanism,
                    calls: Arc::clone(&calls),
                },
                calls,
            )
        }
    }

    impl BoundaryProbe for ScriptedProbe {
        fn observe(&self, _scope: &BoundaryScope) -> BoundaryObservation {
            self.calls.fetch_add(1, Ordering::SeqCst);
            BoundaryObservation {
                presence: self.presence.clone(),
                mechanism: self.mechanism,
                evidence: format!("scripted evidence from {}", self.mechanism),
            }
        }
    }

    fn indeterminate(detail: &str) -> Presence {
        Presence::Indeterminate {
            detail: detail.to_owned(),
        }
    }

    fn scope() -> BoundaryScope {
        BoundaryScope::all_egress()
    }

    #[test]
    fn the_first_decisive_tier_wins_and_later_tiers_are_not_consulted() {
        for decisive in [Presence::Present, Presence::Absent] {
            let (first, first_calls) = ScriptedProbe::new(decisive.clone(), "tier-1");
            let (second, second_calls) = ScriptedProbe::new(Presence::Present, "tier-2");
            let observer =
                TieredEgressObserver::new(scope(), vec![Box::new(first), Box::new(second)]);

            let observed = observer.observe();
            assert_eq!(observed.presence, decisive);
            assert_eq!(observed.mechanism, "tier-1");
            assert_eq!(first_calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                second_calls.load(Ordering::SeqCst),
                0,
                "a decisive tier must short-circuit; consulting a slower tier lets it overturn a \
                 good answer"
            );
        }
    }

    #[test]
    fn an_indeterminate_tier_falls_through_to_the_next() {
        let (first, first_calls) = ScriptedProbe::new(indeterminate("netsh exited 1"), "tier-1");
        let (second, second_calls) = ScriptedProbe::new(Presence::Absent, "tier-2");
        let observer = TieredEgressObserver::new(scope(), vec![Box::new(first), Box::new(second)]);

        assert_eq!(observer.observe().presence, Presence::Absent);
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_calls.load(Ordering::SeqCst), 1);
        assert_eq!(observer.rule_present("all_egress"), Some(false));
    }

    /// The load-bearing negative: no combination of failures may synthesise
    /// `Absent`. A mutation making the all-indeterminate fallback return
    /// `Presence::Absent` turns this red.
    #[test]
    fn every_tier_failing_is_indeterminate_and_never_absent() {
        let (first, _) = ScriptedProbe::new(indeterminate("spawn failed"), "tier-1");
        let (second, _) = ScriptedProbe::new(indeterminate("access denied"), "tier-2");
        let observer = TieredEgressObserver::new(scope(), vec![Box::new(first), Box::new(second)]);

        let observed = observer.observe();
        assert!(
            matches!(observed.presence, Presence::Indeterminate { .. }),
            "{observed:?}"
        );
        assert_eq!(
            observer.rule_present("all_egress"),
            None,
            "an inconclusive probe must read as `cannot determine`, never as `not severed`"
        );
        // Every tier's reason survives, so an operator can see which mechanism
        // failed and why without re-running anything.
        let Presence::Indeterminate { detail } = &observed.presence else {
            unreachable!()
        };
        assert!(detail.contains("spawn failed"), "{detail}");
        assert!(detail.contains("access denied"), "{detail}");
    }

    #[test]
    fn an_observer_with_no_probes_says_so_rather_than_answering() {
        let observer = TieredEgressObserver::new(scope(), Vec::new());
        assert_eq!(observer.tier_count(), 0);
        assert_eq!(observer.rule_present("all_egress"), None);
        let Presence::Indeterminate { detail } = observer.observe().presence else {
            panic!("no probe can only be indeterminate")
        };
        assert!(
            detail.contains("no boundary probe is configured"),
            "{detail}"
        );
    }

    /// A label that is not ours is not an answer about our scope. `Some(false)`
    /// here would tell the broker the rule is gone when nothing looked for it.
    #[test]
    fn a_foreign_scope_label_is_unanswerable_not_absent() {
        let (probe, calls) = ScriptedProbe::new(Presence::Present, "tier-1");
        let observer = TieredEgressObserver::new(scope(), vec![Box::new(probe)]);

        assert_eq!(observer.rule_present("some_other_scope"), None);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a foreign label must be refused before any probe is spawned"
        );
        // And the real label still works, so the guard is not just refusing
        // everything.
        assert_eq!(observer.rule_present("all_egress"), Some(true));
    }

    /// Pins the module header's claim about the shipped mechanism, so a future
    /// change that makes `classify_show` return `Absent` cannot land without
    /// this documentation being revisited. It asserts the *classifier's*
    /// property, not a live firewall observation: `classify_show` is a pure
    /// function of an exit code.
    #[test]
    fn the_shipped_netsh_classifier_cannot_produce_absent() {
        use crate::firewall::{classify_show, RawInvocation};
        for exit in [None, Some(0), Some(1), Some(5), Some(-1), Some(i32::MAX)] {
            let inv = RawInvocation::new(exit, b"whatever the tool printed".to_vec(), Vec::new());
            assert_ne!(
                classify_show(&inv),
                Presence::Absent,
                "netsh's exit code cannot establish absence (exit {exit:?}); if this ever \
                 changes, `TieredEgressObserver`'s module header is out of date"
            );
        }
    }
}
