//! 4π-Closure (IMDF 11; IMRT Axiom A7, Satz 12.4) — oriented orientation return.
//!
//! A single 2π orientation pass is not enough to establish closure: like a
//! spinor in a ℤ/2-graded (double-cover) bundle, one full turn lands at the
//! `Minus` grade (−1), and only a *second* pass (4π total) returns to the `Plus`
//! grade (+1). Closure (Satz 12.4) requires **both** conjuncts:
//!
//! 1. the orientation returned — an even number of agreeing 2π passes brings the
//!    ℤ/2 grade back to `Plus` (`ω²(c)=c`), and
//! 2. the self-class was preserved across the 4π — `[S]_can` at the closing pass
//!    equals `[S]_can` at the opening pass.
//!
//! If the orientation returns but the self-class was *not* preserved, closure is
//! **not** granted; instead a **Gegenhorizontmasse** residue (𝒳_FourPi) — a
//! real, typed [`BoundaryResidue`] (`ResidueKind::Identity`) a caller can
//! `.emit()` into a `ResidueRegister`, not a bare digest — is emitted, so the
//! un-closed mass is visible rather than silently dropped (Axiom A4 applied to
//! closure). Visible 2π return is never mistaken for oriented 4π return.
//!
//! A cascade may run deeper than one double-turn. [`FourPiClosure::evaluate`]
//! judges the **most recently completed double-turn** (a sliding window over
//! `passes[n-2]`/`passes[n-1]`), not just the first two passes ever recorded —
//! so an interior drift at depth > 2 is surfaced when it happens rather than
//! being hidden behind a coincidental first-vs-last agreement (Bemerkung
//! 14.10: a return to the same position must become tracked accumulation, not
//! be read as if nothing happened).

use serde::{Deserialize, Serialize};
use ssk_types::{
    digest_of, BoundaryResidue, Digest, GateId, HashAlg, NextAction, ResidueId, ResidueKind,
    ResidueStatus, Severity, TraceId,
};

use crate::error::ImdfError;

/// The ℤ/2 orientation grade of the spinor double cover. `Plus` (+1) is the
/// identity grade; a single 2π turn lands at `Minus` (−1); a second 2π (4π
/// total) returns to `Plus`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Orientation {
    Plus,
    Minus,
}

impl Orientation {
    /// The grade after `turns` 2π passes: `Plus` for an even count (a 4π
    /// multiple), `Minus` for an odd count. This is the minimal ℤ/2 rotor:
    /// `R(2π)ψ = −ψ`, `R(4π)ψ = +ψ`.
    #[must_use]
    pub fn after_turns(turns: usize) -> Self {
        if turns.is_multiple_of(2) {
            Orientation::Plus
        } else {
            Orientation::Minus
        }
    }

    /// The signed grade (`+1` / `-1`).
    #[must_use]
    pub fn sign(self) -> i8 {
        match self {
            Orientation::Plus => 1,
            Orientation::Minus => -1,
        }
    }
}

/// One recorded orientation observation: the oriented wavefront digest and the
/// canonical self-class `[S]_can` in effect at that pass (needed for the second
/// Satz 12.4 conjunct).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrientationPass {
    pub digest: Digest,
    /// The canonical self-class digest at this pass — closure requires it to be
    /// preserved across the 4π return.
    pub anchor_class: Digest,
}

impl OrientationPass {
    #[must_use]
    pub fn new(digest: Digest, anchor_class: Digest) -> Self {
        OrientationPass {
            digest,
            anchor_class,
        }
    }
}

/// Whether orientation has returned to identity *and* preserved the self-class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClosureState {
    Open,
    Closed,
}

/// The full closure verdict (both Satz 12.4 conjuncts + the residue).
///
/// Not `Copy` (unlike its predecessor): [`gegenhorizont`](Self::gegenhorizont)
/// is now a real, typed [`BoundaryResidue`] (carrying owned `String` fields),
/// not a bare [`Digest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureReport {
    pub state: ClosureState,
    /// The ℤ/2 grade after the recorded passes.
    pub orientation: Orientation,
    /// Whether the oriented return conjunct holds (≥2 passes, agreeing digests,
    /// `Plus` grade).
    pub oriented_return: bool,
    /// Whether the self-class was preserved across the 4π (second conjunct).
    pub self_class_preserved: bool,
    /// The Gegenhorizontmasse residue (𝒳_FourPi): `Some` iff the orientation
    /// returned but the self-class was **not** preserved — the un-closed mass,
    /// made visible as a real, typed [`BoundaryResidue`] instead of silently
    /// dropped (or, previously, instead of a bare digest nothing could register).
    /// `FourPiClosure` itself stays side-effect-free (`evaluate` takes `&self`
    /// and never emits into a register on its own) — the caller owns the
    /// `ResidueRegister` and is expected to `.emit()` this value exactly once
    /// per real event.
    pub gegenhorizont: Option<BoundaryResidue>,
}

/// Accumulates orientation passes; closes only on a consistent second pass that
/// also preserves the self-class. Evaluation is a **sliding window** over the
/// most recently recorded double-turn (`passes[n-2]`/`passes[n-1]`), not just
/// the first two passes — so a cascade of depth > 2 is judged on its current
/// state, not silently truncated back to the opening pass (see [`evaluate`](
/// Self::evaluate)).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FourPiClosure {
    passes: Vec<OrientationPass>,
    /// The real origin trace this cascade/crossing is attributed to. Required
    /// so any Gegenhorizontmasse residue this closure emits has a genuine
    /// `TraceId` origin (an empty/fabricated origin would misroute the residue
    /// to the ρ* catch-all per `EdgeClass::of`'s own emptiness check) — fixed
    /// once at construction, matching "one `FourPiClosure` = one cascade".
    origin: TraceId,
}

impl FourPiClosure {
    #[must_use]
    pub fn new(origin: TraceId) -> Self {
        FourPiClosure {
            passes: Vec::new(),
            origin,
        }
    }

    /// Record an orientation pass (one 2π turn).
    pub fn record_pass(&mut self, pass: OrientationPass) {
        self.passes.push(pass);
    }

    #[must_use]
    pub fn pass_count(&self) -> usize {
        self.passes.len()
    }

    /// The ℤ/2 orientation grade after the recorded passes.
    #[must_use]
    pub fn orientation(&self) -> Orientation {
        Orientation::after_turns(self.passes.len())
    }

    /// The full Satz 12.4 verdict.
    ///
    /// * `oriented_return`: at least two passes recorded, the **most recently
    ///   completed double-turn** (`passes[n-2]`/`passes[n-1]`) agree, and the
    ///   grade is back to `Plus` (a genuine 4π, not a lone 2π). This is a
    ///   **sliding window**, not a first/last bijection: at depth 2 it behaves
    ///   identically to comparing the opening and closing pass (no regression),
    ///   but at depth > 2 it judges the cascade's current state instead of
    ///   silently comparing only the very first two passes ever recorded (which
    ///   would let interior drift hide behind a coincidental first-vs-last
    ///   match — see `four_pi_at_depth_four_does_not_silently_reset_to_the_
    ///   opening_pass` and Bemerkung 14.10: a return to the same position must
    ///   become tracked accumulation, not be read as if nothing happened).
    /// * `self_class_preserved`: the most recent double-turn's `[S]_can` at the
    ///   closing pass equals `[S]_can` at its opening pass (same window).
    /// * The ℤ/2 `orientation` grade itself stays over the *full* pass count
    ///   (not windowed) — the spinor parity is cumulative history, not a
    ///   windowed quantity.
    /// * Closed iff both hold. If the orientation returned but the class was not
    ///   preserved, `state` stays `Open` and a Gegenhorizontmasse residue
    ///   (`ResidueKind::Identity`, the self/identity edge) is emitted (the
    ///   un-closed mass is visible, never silently absorbed — A4).
    #[must_use]
    pub fn evaluate(&self) -> ClosureReport {
        let orientation = self.orientation();
        let n = self.passes.len();

        // Sliding window: judge the cascade's most recently completed
        // double-turn, not merely the first two passes ever recorded.
        let oriented_return = n >= 2
            && self.passes[n - 2].digest == self.passes[n - 1].digest
            && orientation == Orientation::Plus;

        let self_class_preserved =
            n >= 2 && self.passes[n - 2].anchor_class == self.passes[n - 1].anchor_class;

        let (state, gegenhorizont) = if oriented_return && self_class_preserved {
            (ClosureState::Closed, None)
        } else if oriented_return && !self_class_preserved {
            // First conjunct holds, second fails: the un-closed self-class mass
            // becomes a visible Gegenhorizontmasse residue committing to the
            // opening vs closing class mismatch of the current window.
            let opened = &self.passes[n - 2].anchor_class;
            let closed = &self.passes[n - 1].anchor_class;
            #[derive(Serialize)]
            struct Form<'a> {
                domain: &'a str,
                opened: &'a Digest,
                closed: &'a Digest,
            }
            let residue_digest = digest_of(
                &Form {
                    domain: "imdf/four-pi/gegenhorizont/v1",
                    opened,
                    closed,
                },
                HashAlg::Blake3,
            )
            .expect("gegenhorizont form is serializable");
            let residue = BoundaryResidue::new_full(
                ResidueId::new(format!(
                    "gegenhorizont:{}:{}",
                    opened.to_hex(),
                    closed.to_hex()
                )),
                ResidueKind::Identity,
                GateId::Bcik,
                Some(residue_digest.to_hex()),
                "4-pi orientation returned but the self-class drifted across the closing pass \
                 (Gegenhorizontmasse)",
                Severity::Critical,
                self.origin.clone(),
                ResidueStatus::Open,
                NextAction::Escalate,
            );
            (ClosureState::Open, Some(residue))
        } else {
            (ClosureState::Open, None)
        };

        ClosureReport {
            state,
            orientation,
            oriented_return,
            self_class_preserved,
            gegenhorizont,
        }
    }

    /// Closed iff both Satz 12.4 conjuncts hold.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.evaluate().state == ClosureState::Closed
    }

    #[must_use]
    pub fn state(&self) -> ClosureState {
        self.evaluate().state
    }

    /// The Gegenhorizontmasse residue, if the orientation returned but the
    /// self-class was not preserved. A real, typed [`BoundaryResidue`] the
    /// caller can `.emit()` into a [`ssk_types::ResidueRegister`] — not a bare
    /// digest nothing could register.
    #[must_use]
    pub fn gegenhorizont(&self) -> Option<BoundaryResidue> {
        self.evaluate().gegenhorizont
    }

    /// Require closure.
    ///
    /// # Errors
    /// [`ImdfError::ClosureIncomplete`] if not both conjuncts hold.
    pub fn require_closed(&self) -> Result<(), ImdfError> {
        if self.is_closed() {
            Ok(())
        } else {
            Err(ImdfError::ClosureIncomplete)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(tag: &str) -> Digest {
        digest_of(&tag, HashAlg::Blake3).unwrap()
    }

    // One oriented pass over a fixed self-class.
    fn pass(tag: &str, class: &str) -> OrientationPass {
        OrientationPass::new(digest(tag), digest(class))
    }

    fn closure_with_origin() -> FourPiClosure {
        FourPiClosure::new(TraceId::new("trace-1"))
    }

    // G5: the ℤ/2 rotor — a lone 2π is Minus (−1), 4π returns to Plus (+1).
    #[test]
    fn orientation_is_zz2_graded() {
        assert_eq!(Orientation::after_turns(0), Orientation::Plus);
        assert_eq!(Orientation::after_turns(1), Orientation::Minus);
        assert_eq!(Orientation::after_turns(2), Orientation::Plus);
        assert_eq!(Orientation::after_turns(1).sign(), -1);
        assert_eq!(Orientation::after_turns(2).sign(), 1);
    }

    // IMDF Appendix A + G6: closure needs a second orientation pass AND a
    // preserved self-class.
    #[test]
    fn four_pi_requires_second_orientation_pass() {
        let mut closure = closure_with_origin();
        assert_eq!(closure.state(), ClosureState::Open);
        assert_eq!(
            closure.require_closed().unwrap_err(),
            ImdfError::ClosureIncomplete
        );

        // One 2π pass: grade is Minus, not enough.
        closure.record_pass(pass("north", "S"));
        assert!(!closure.is_closed());
        assert_eq!(closure.orientation(), Orientation::Minus);
        assert_eq!(
            closure.require_closed().unwrap_err(),
            ImdfError::ClosureIncomplete
        );

        // A consistent second pass over the same self-class (4π) closes it.
        closure.record_pass(pass("north", "S"));
        let report = closure.evaluate();
        assert!(report.oriented_return);
        assert!(report.self_class_preserved);
        assert_eq!(report.orientation, Orientation::Plus);
        assert_eq!(report.state, ClosureState::Closed);
        assert!(report.gegenhorizont.is_none());
        assert!(closure.require_closed().is_ok());
    }

    #[test]
    fn inconsistent_second_pass_does_not_close() {
        let mut closure = closure_with_origin();
        closure.record_pass(pass("north", "S"));
        closure.record_pass(pass("south", "S"));
        assert!(
            !closure.is_closed(),
            "a disagreeing second pass leaves orientation open"
        );
        // Orientation did not return, so no Gegenhorizontmasse is emitted here.
        assert!(closure.gegenhorizont().is_none());
    }

    // G6: the second Satz 12.4 conjunct — orientation returns but the self-class
    // drifted across the 4π → NOT closed, and a Gegenhorizontmasse residue is
    // emitted (the un-closed mass is visible, not silently dropped).
    #[test]
    fn drifted_self_class_yields_gegenhorizontmasse_not_closure() {
        let mut closure = closure_with_origin();
        closure.record_pass(pass("north", "S_before"));
        closure.record_pass(pass("north", "S_after")); // same orientation, drifted class
        let report = closure.evaluate();
        assert!(report.oriented_return, "the orientation did return (4π)");
        assert!(!report.self_class_preserved, "but the self-class drifted");
        assert_eq!(report.state, ClosureState::Open, "so it is NOT closed");
        assert!(
            report.gegenhorizont.is_some(),
            "the un-closed mass is a visible Gegenhorizontmasse residue"
        );
        assert!(closure.require_closed().is_err());
    }

    // Gegenhorizontmasse is now a real, typed BoundaryResidue — proving it is
    // genuinely visible in a ResidueRegister, not just a bare digest a caller
    // has no way to register or classify.
    #[test]
    fn gegenhorizontmasse_is_a_real_residue_visible_in_a_register() {
        let mut closure = FourPiClosure::new(TraceId::new("trace-gegenhorizont"));
        closure.record_pass(pass("north", "S_before"));
        closure.record_pass(pass("north", "S_after"));
        let residue = closure
            .gegenhorizont()
            .expect("orientation returned but self-class drifted");

        // It carries a genuine origin trace (never fabricated/empty — an empty
        // origin would misroute the residue to the rho* catch-all instead of a
        // real edge class).
        assert_eq!(residue.origin, TraceId::new("trace-gegenhorizont"));
        assert_eq!(residue.kind, ResidueKind::Identity);
        assert_eq!(residue.status, ResidueStatus::Open);
        assert_eq!(residue.next_action, NextAction::Escalate);
        assert!(residue.open_obligation());
        assert!(residue.fragment.is_some(), "carries the mismatch digest");

        // The load-bearing claim: it is now visible in a real ResidueRegister's
        // enumeration, not merely returned as a value nothing can register.
        let mut register = ssk_types::ResidueRegister::new();
        let id = register.emit(residue.clone());
        assert_eq!(register.len(), 1);
        assert_eq!(register.entries(), &[residue]);
        assert_eq!(register.open_obligations().count(), 1);
        assert_eq!(
            register.open_obligations().next().unwrap().id,
            id,
            "the emitted id round-trips through the register"
        );
    }

    // The un-closed mass has a genuine origin edge under EdgeClass::of, not the
    // rho* catch-all — the residue is attributable, not a fabricated stand-in.
    #[test]
    fn gegenhorizontmasse_lands_on_a_real_edge_class_not_rho_star() {
        let mut closure = FourPiClosure::new(TraceId::new("trace-edge"));
        closure.record_pass(pass("north", "S_before"));
        closure.record_pass(pass("north", "S_after"));
        let residue = closure.gegenhorizont().unwrap();
        assert_eq!(
            ssk_types::EdgeClass::of(&residue),
            Some(ssk_types::EdgeClass::SelfEdge),
            "identity-class Gegenhorizontmasse attributes to the self edge, not rho*"
        );
    }

    // The depth>2 fix, proven the way it must fail before it: a cascade of
    // depth 4 where the FIRST two passes agree (would have closed under the
    // old "always compare passes[0]/passes[1]" logic, no matter how many later
    // passes were recorded) but the cascade's *current*, most-recently-reached
    // double-turn disagrees. The sliding window must report the true, current
    // state — not silently reset to the opening pass.
    #[test]
    fn four_pi_at_depth_four_does_not_silently_reset_to_the_opening_pass() {
        let mut closure = closure_with_origin();
        // p0/p1: a clean, closing 4π over class S — old code would latch onto
        // this pair forever, regardless of what comes after.
        closure.record_pass(pass("north", "S"));
        closure.record_pass(pass("north", "S"));
        assert!(
            closure.is_closed(),
            "sanity: at depth 2 the cascade is genuinely closed"
        );

        // p2: a THIRD pass with a disagreeing digest and a drifted class. Under
        // the old code (hardcoded passes[0]/passes[1]) this is invisible —
        // is_closed() would keep reporting Closed forever. Under the sliding
        // window, the cascade must now report Open (no oriented return in the
        // current window), because passes[1] ("north") vs passes[2] ("south")
        // disagree on digest.
        closure.record_pass(pass("south", "S2"));
        let n3 = closure.evaluate();
        assert!(
            !n3.oriented_return,
            "depth 3: the current window (p1,p2) disagrees on digest"
        );
        assert_eq!(
            closure.state(),
            ClosureState::Open,
            "depth 3 must NOT silently read as closed just because p0/p1 once agreed"
        );
        assert!(
            n3.gegenhorizont.is_none(),
            "no oriented return in this window, so no Gegenhorizontmasse yet"
        );

        // p3: a fourth pass whose digest agrees with p2 ("south") but whose
        // class ("S3") drifted from p2's ("S2"). The current window is now
        // (p2,p3). Meanwhile p0's class ("S") coincidentally differs from p3's
        // class ("S3") too, so neither a first/last bijection NOR the sliding
        // window would report Closed here — but only the sliding window
        // correctly attributes the drift to the (p2,p3) window and emits a
        // Gegenhorizontmasse residue for THIS window, not the stale (p0,p1) one.
        closure.record_pass(pass("south", "S3"));
        let n4 = closure.evaluate();
        assert!(
            n4.oriented_return,
            "depth 4: the current window (p2,p3) agrees on digest (south == south)"
        );
        assert!(
            !n4.self_class_preserved,
            "depth 4: the current window's class drifted (S2 != S3)"
        );
        assert_eq!(closure.state(), ClosureState::Open);
        let residue = n4.gegenhorizont.expect("current-window drift is residued");
        // The residue commits to the CURRENT window's classes (S2 vs S3), not
        // the stale opening pair (S vs S) — proving the fix inspects the live
        // cascade state, not a frozen first-two-passes snapshot.
        #[derive(Serialize)]
        struct ExpectedForm<'a> {
            domain: &'a str,
            opened: &'a Digest,
            closed: &'a Digest,
        }
        let opened_digest = digest("S2");
        let closed_digest = digest("S3");
        let expected_digest = digest_of(
            &ExpectedForm {
                domain: "imdf/four-pi/gegenhorizont/v1",
                opened: &opened_digest,
                closed: &closed_digest,
            },
            HashAlg::Blake3,
        )
        .unwrap();
        assert_eq!(residue.fragment, Some(expected_digest.to_hex()));
        // And distinct from the stale (p0,p1) pair's would-be digest, so this
        // genuinely proves the residue tracks the live window.
        let stale_s = digest("S");
        let stale_digest = digest_of(
            &ExpectedForm {
                domain: "imdf/four-pi/gegenhorizont/v1",
                opened: &stale_s,
                closed: &stale_s,
            },
            HashAlg::Blake3,
        )
        .unwrap();
        assert_ne!(residue.fragment, Some(stale_digest.to_hex()));

        // pass_count (the ratchet/gang-index) accumulated monotonically over
        // the whole cascade and never shrank, even though the *evaluated*
        // window is local — the ratchet still counts all four passes.
        assert_eq!(closure.pass_count(), 4);
    }

    // Depth 2 must behave identically before and after the sliding-window
    // change — no regression at the base case the original theory covers.
    #[test]
    fn depth_two_is_unaffected_by_the_sliding_window_generalization() {
        let mut closed = closure_with_origin();
        closed.record_pass(pass("north", "S"));
        closed.record_pass(pass("north", "S"));
        assert!(closed.is_closed());

        let mut open = closure_with_origin();
        open.record_pass(pass("north", "S"));
        open.record_pass(pass("south", "S"));
        assert!(!open.is_closed());
        assert!(open.gegenhorizont().is_none());
    }
}
