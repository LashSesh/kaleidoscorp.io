//! The QLOGIC gate g = (κ, H, Π, R, B, Δ) (IMDF 10).
//!
//! Six independent axes, each yielding Pass / Hold / Fail, combined into an
//! overall verdict — **never** collapsed to a single scalar score. The axes:
//!
//! * **κ (kappa)** — coherence: the wavefront measured what its aperture admitted.
//! * **H** — entropy: measurement entropy within bound.
//! * **Π (pi)** — parallax: the birefringent split is consistent.
//! * **R** — replay: replay-equality holds for this observation.
//! * **B** — boundary: no unresolved boundary/residue obligation.
//! * **Δ (delta)** — drift: signature drift from the self-anchor within bound.
//!
//! The verdict is `Fail` if any axis fails, else `Hold` if any axis holds, else
//! `Pass`. Two observations with identical overall verdicts can still differ per
//! axis — the gate keeps the whole vector, so the *reason* is never lost.

use ssk_types::GateOutcomeKind;

/// One QLOGIC axis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QAxis {
    Kappa,
    H,
    Pi,
    R,
    B,
    Delta,
}

impl QAxis {
    #[must_use]
    pub fn symbol(self) -> &'static str {
        match self {
            QAxis::Kappa => "κ",
            QAxis::H => "H",
            QAxis::Pi => "Π",
            QAxis::R => "R",
            QAxis::B => "B",
            QAxis::Delta => "Δ",
        }
    }
}

/// A per-axis outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QOutcome {
    Pass,
    Hold,
    Fail,
}

impl QOutcome {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            QOutcome::Pass => "PASS",
            QOutcome::Hold => "HOLD",
            QOutcome::Fail => "FAIL",
        }
    }

    fn rank(self) -> u8 {
        match self {
            QOutcome::Pass => 0,
            QOutcome::Hold => 1,
            QOutcome::Fail => 2,
        }
    }
}

/// Evidence the gate evaluates. Each field is a typed measurement, not a score.
#[derive(Clone, Debug, PartialEq)]
pub struct QLogicInput {
    /// Fraction of admitted dimensions that were actually measured (coherence).
    pub coherence: f64,
    /// Measurement entropy and its permitted bound.
    pub entropy: f64,
    pub entropy_bound: f64,
    /// Whether the birefringent split is consistent (parallax).
    pub parallax_consistent: bool,
    /// Whether replay-equality holds for this observation.
    pub replay_equal: bool,
    /// Count of unresolved boundary/residue obligations.
    pub open_obligations: usize,
    /// Signature drift from the self-anchor and its bound.
    pub drift: f64,
    pub drift_bound: f64,
}

/// Tunable thresholds for the coherence axis.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct QLogicThresholds {
    /// Below this coherence the κ axis fails; between this and `coherence_pass`
    /// it holds.
    pub coherence_fail: f64,
    pub coherence_pass: f64,
}

impl Default for QLogicThresholds {
    fn default() -> Self {
        QLogicThresholds {
            coherence_fail: 0.5,
            coherence_pass: 0.999,
        }
    }
}

/// The full six-axis outcome vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QLogicVector {
    pub kappa: QOutcome,
    pub h: QOutcome,
    pub pi: QOutcome,
    pub r: QOutcome,
    pub b: QOutcome,
    pub delta: QOutcome,
}

impl QLogicVector {
    /// The six axes in canonical order — the gate is a vector, not a scalar.
    #[must_use]
    pub fn axes(&self) -> [(QAxis, QOutcome); 6] {
        [
            (QAxis::Kappa, self.kappa),
            (QAxis::H, self.h),
            (QAxis::Pi, self.pi),
            (QAxis::R, self.r),
            (QAxis::B, self.b),
            (QAxis::Delta, self.delta),
        ]
    }

    /// Combine into an overall verdict: any Fail → Fail, else any Hold → Hold,
    /// else Pass. Derived from the whole vector, never a single number.
    #[must_use]
    pub fn verdict(&self) -> QOutcome {
        let worst = self.axes().iter().map(|(_, o)| o.rank()).max().unwrap_or(0);
        match worst {
            2 => QOutcome::Fail,
            1 => QOutcome::Hold,
            _ => QOutcome::Pass,
        }
    }

    /// Map the verdict onto the SSK gate outcome kind.
    #[must_use]
    pub fn to_ssk(&self) -> GateOutcomeKind {
        match self.verdict() {
            QOutcome::Pass => GateOutcomeKind::Pass,
            QOutcome::Hold => GateOutcomeKind::Hold,
            QOutcome::Fail => GateOutcomeKind::Reject,
        }
    }

    /// Per-axis reasons — one line per non-passing axis, so the reason a verdict
    /// was reached is preserved (not reducible to a single number).
    #[must_use]
    pub fn reasons(&self) -> Vec<String> {
        self.axes()
            .iter()
            .filter(|(_, o)| *o != QOutcome::Pass)
            .map(|(axis, o)| format!("{}={}", axis.symbol(), o.as_str()))
            .collect()
    }
}

/// The QLOGIC gate.
#[derive(Clone, Copy, Debug, Default)]
pub struct QLogicGate {
    pub thresholds: QLogicThresholds,
}

impl QLogicGate {
    /// Evaluate the six axes from typed evidence.
    #[must_use]
    pub fn evaluate(&self, input: &QLogicInput) -> QLogicVector {
        // Non-finite coherence (e.g. a 0/0 zero-aperture measurement) must fail
        // conservatively, not fall through to Pass. `is_finite` is checked
        // explicitly rather than relying on `<` alone: unlike H/Delta below
        // (which test the *pass* side, so a NaN double-false falls to their
        // final Fail arm), kappa tests the *fail* side first, and `NaN < x` is
        // always false — a naive `< fail` / `< pass` chain would let NaN slip
        // through both comparisons to the final `else` arm, which here is Pass.
        let kappa =
            if !input.coherence.is_finite() || input.coherence < self.thresholds.coherence_fail {
                QOutcome::Fail
            } else if input.coherence < self.thresholds.coherence_pass {
                QOutcome::Hold
            } else {
                QOutcome::Pass
            };
        // Entropy: within bound passes; up to twice the bound holds; beyond fails.
        let h = if input.entropy <= input.entropy_bound {
            QOutcome::Pass
        } else if input.entropy <= input.entropy_bound * 2.0 {
            QOutcome::Hold
        } else {
            QOutcome::Fail
        };
        let pi = if input.parallax_consistent {
            QOutcome::Pass
        } else {
            QOutcome::Fail
        };
        let r = if input.replay_equal {
            QOutcome::Pass
        } else {
            QOutcome::Fail
        };
        let b = if input.open_obligations == 0 {
            QOutcome::Pass
        } else {
            QOutcome::Hold
        };
        let delta = if input.drift <= input.drift_bound {
            QOutcome::Pass
        } else if input.drift <= input.drift_bound * 2.0 {
            QOutcome::Hold
        } else {
            QOutcome::Fail
        };
        QLogicVector {
            kappa,
            h,
            pi,
            r,
            b,
            delta,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean() -> QLogicInput {
        QLogicInput {
            coherence: 1.0,
            entropy: 0.2,
            entropy_bound: 0.5,
            parallax_consistent: true,
            replay_equal: true,
            open_obligations: 0,
            drift: 0.1,
            drift_bound: 0.35,
        }
    }

    // IMDF Appendix A: gate_vector_is_not_single_score.
    #[test]
    fn gate_vector_is_not_single_score() {
        let gate = QLogicGate::default();

        // All axes pass -> Pass, and the vector genuinely has six axes.
        let v = gate.evaluate(&clean());
        assert_eq!(v.verdict(), QOutcome::Pass);
        assert_eq!(v.axes().len(), 6);
        assert!(v.reasons().is_empty());

        // A single failing axis (Δ drift) fails the whole gate...
        let mut drifted = clean();
        drifted.drift = 10.0;
        let vd = gate.evaluate(&drifted);
        assert_eq!(vd.verdict(), QOutcome::Fail);
        assert_eq!(vd.delta, QOutcome::Fail);

        // ...while a different failing axis (Π parallax) also fails, but the
        // *vector* distinguishes them — the reason is not lost to one number.
        let mut split = clean();
        split.parallax_consistent = false;
        let vp = gate.evaluate(&split);
        assert_eq!(vp.verdict(), QOutcome::Fail);
        assert_eq!(vp.pi, QOutcome::Fail);
        assert_ne!(
            vd.axes(),
            vp.axes(),
            "two Fail verdicts still differ per axis"
        );
        assert_ne!(vd.reasons(), vp.reasons());

        // An open obligation holds (not fails) — Hold is a distinct third state.
        let mut held = clean();
        held.open_obligations = 2;
        let vh = gate.evaluate(&held);
        assert_eq!(vh.verdict(), QOutcome::Hold);
        assert_eq!(vh.to_ssk(), GateOutcomeKind::Hold);
    }

    // Regression: non-finite coherence (e.g. 0/0 from a zero-aperture
    // measurement) must fail the kappa axis, not bypass it to Pass. Before the
    // fix, `NaN < fail` and `NaN < pass` were both false, falling through to
    // the final `else` arm, which was Pass — the worst possible input ranked
    // better than a merely-bad coherence of 0.0.
    #[test]
    fn non_finite_coherence_fails_kappa_not_bypasses_it() {
        let gate = QLogicGate::default();

        let mut nan_input = clean();
        nan_input.coherence = f64::NAN;
        let v_nan = gate.evaluate(&nan_input);
        assert_eq!(
            v_nan.kappa,
            QOutcome::Fail,
            "NaN coherence must fail the kappa axis"
        );
        assert_eq!(v_nan.verdict(), QOutcome::Fail);

        // NaN must not rank better than an ordinary bad coherence value.
        let mut zero_input = clean();
        zero_input.coherence = 0.0;
        let v_zero = gate.evaluate(&zero_input);
        assert_eq!(v_zero.kappa, QOutcome::Fail);

        let mut inf_input = clean();
        inf_input.coherence = f64::NEG_INFINITY;
        let v_inf = gate.evaluate(&inf_input);
        assert_eq!(v_inf.kappa, QOutcome::Fail);
    }
}
