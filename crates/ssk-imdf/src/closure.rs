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
//! **not** granted; instead a **Gegenhorizontmasse** residue (𝒳_FourPi) is
//! emitted, so the un-closed mass is visible rather than silently dropped
//! (Axiom A4 applied to closure). Visible 2π return is never mistaken for
//! oriented 4π return.

use serde::{Deserialize, Serialize};
use ssk_types::{digest_of, Digest, HashAlg};

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// made visible instead of silently dropped.
    pub gegenhorizont: Option<Digest>,
}

/// Accumulates orientation passes; closes only on a consistent second pass that
/// also preserves the self-class.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FourPiClosure {
    passes: Vec<OrientationPass>,
}

impl FourPiClosure {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
    /// * `oriented_return`: at least two passes, the first two agree, and the
    ///   grade is back to `Plus` (a genuine 4π, not a lone 2π).
    /// * `self_class_preserved`: the closing pass' `[S]_can` equals the opening
    ///   pass' `[S]_can`.
    /// * Closed iff both hold. If the orientation returned but the class was not
    ///   preserved, `state` stays `Open` and a Gegenhorizontmasse residue is
    ///   emitted (the un-closed mass is visible).
    #[must_use]
    pub fn evaluate(&self) -> ClosureReport {
        let orientation = self.orientation();
        let oriented_return = self.passes.len() >= 2
            && self.passes[0].digest == self.passes[1].digest
            && orientation == Orientation::Plus;

        let self_class_preserved = match (self.passes.first(), self.passes.get(1)) {
            (Some(open), Some(close)) => open.anchor_class == close.anchor_class,
            _ => false,
        };

        let (state, gegenhorizont) = if oriented_return && self_class_preserved {
            (ClosureState::Closed, None)
        } else if oriented_return && !self_class_preserved {
            // First conjunct holds, second fails: the un-closed self-class mass
            // becomes a visible Gegenhorizontmasse residue committing to the
            // opening vs closing class mismatch.
            #[derive(Serialize)]
            struct Form<'a> {
                domain: &'a str,
                opened: &'a Digest,
                closed: &'a Digest,
            }
            let residue = digest_of(
                &Form {
                    domain: "imdf/four-pi/gegenhorizont/v1",
                    opened: &self.passes[0].anchor_class,
                    closed: &self.passes[1].anchor_class,
                },
                HashAlg::Blake3,
            )
            .expect("gegenhorizont form is serializable");
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
    /// self-class was not preserved.
    #[must_use]
    pub fn gegenhorizont(&self) -> Option<Digest> {
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
        let mut closure = FourPiClosure::new();
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
        let mut closure = FourPiClosure::new();
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
        let mut closure = FourPiClosure::new();
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
}
