//! The QLOGIC gate g = (κ, H, Π, R, B, Δ) (IMDF 10; IMRT Axiom A6, Def. 8.13).
//!
//! Six independent axes, each yielding Pass / Hold / Fail, combined into an
//! overall verdict — **never** collapsed to a single scalar score. The axes
//! carry the theory's *specific* meanings (IMRT §8.13 / §10.6):
//!
//! * **κ (kappa)** — coherence: the wavefront measured what its aperture admitted.
//! * **H** — entropy: measurement entropy within bound.
//! * **Π (pi)** — projection quality (*Projektionsgüte*): how completely the
//!   captured field was reconstructed/coupled into the wavefront. This is **not**
//!   parallax — parallax is the A3 obligation, evaluated separately by the
//!   composition (`ssk-system`), never on this axis.
//! * **R** — residue load (*Residuenlast*, λ = |X|/|M|): the fraction of measured
//!   mass left as unintegrated residue. This is **not** replay — replay-equality
//!   is an A8 / stability obligation, evaluated separately by the composition.
//! * **B** — boundary stability (*Boundary-Stabilität*): the boundary
//!   (egress/kill-switch, seam) is stable and carries no open boundary residue.
//! * **Δ (delta)** — drift: signature drift from the self-anchor within bound.
//!
//! The verdict is `Fail` if any axis fails, else `Hold` if any axis holds, else
//! `Pass`. Two observations with identical overall verdicts can still differ per
//! axis — the gate keeps the whole vector, so the *reason* is never lost.
//!
//! ## Resolution note (A6 axis semantics, Fassung 1.1 → SSK)
//! Earlier the code fed `parallax_consistent`, `replay_equal` and
//! `open_obligations` onto the Π, R and B axes respectively — the divergence the
//! implementation spec flagged (G3). This is now corrected: each axis reads its
//! theory quantity, computed from a real signal, and parallax/replay are
//! relocated to their correct axioms (A3, A8) in the composition. No check is
//! dropped — only attributed to the right axis. (Per IMRT Regel 3.2 this is a
//! conformance correction, not a registered divergence.)

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

/// Evidence the gate evaluates. Each field is a typed measurement bound to its
/// theory axis (IMRT §8.13), not a score.
#[derive(Clone, Debug, PartialEq)]
pub struct QLogicInput {
    /// **κ** — fraction of admitted dimensions that were actually measured
    /// (coherence).
    pub coherence: f64,
    /// **H** — measurement entropy and its permitted bound.
    pub entropy: f64,
    pub entropy_bound: f64,
    /// **Π** — projection quality (*Projektionsgüte*): how completely the
    /// captured field was reconstructed/coupled (1.0 = full projection, lower =
    /// more projection residue). NOT parallax.
    pub projection_quality: f64,
    /// **R** — residue load (*Residuenlast*, λ = |X|/|M|): fraction of measured
    /// mass left as unintegrated residue (0.0 = nothing open). NOT replay.
    pub residue_load: f64,
    /// **B** — boundary stability (*Boundary-Stabilität*): the boundary
    /// (egress/kill-switch, seam) is stable and carries no open boundary residue.
    pub boundary_stable: bool,
    /// **Δ** — signature drift from the self-anchor and its bound.
    pub drift: f64,
    pub drift_bound: f64,
}

/// Tunable thresholds. Each threshold pair delimits Pass / Hold / Fail for one
/// axis; the *semantics* of each axis are fixed by the theory (Def. 8.13), only
/// the numeric bounds are policy (IMRT ρ06/ρ16).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct QLogicThresholds {
    /// κ: below `coherence_fail` fails; between it and `coherence_pass` holds.
    pub coherence_fail: f64,
    pub coherence_pass: f64,
    /// Π: at/above `projection_pass` passes; at/above `projection_hold` holds;
    /// below fails (higher projection quality is better).
    pub projection_pass: f64,
    pub projection_hold: f64,
    /// R: at/below `residue_pass` passes; at/below `residue_hold` holds; above
    /// fails (lower residue load is better).
    pub residue_pass: f64,
    pub residue_hold: f64,
}

impl Default for QLogicThresholds {
    fn default() -> Self {
        QLogicThresholds {
            coherence_fail: 0.5,
            coherence_pass: 0.999,
            projection_pass: 0.999,
            projection_hold: 0.5,
            residue_pass: 0.0,
            residue_hold: 0.5,
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
        // Π — projection quality: higher is better. Non-finite fails closed
        // (same reasoning as κ: it tests the *pass* side, so a NaN would slip to
        // the final arm — guard it explicitly).
        let pi = if !input.projection_quality.is_finite()
            || input.projection_quality < self.thresholds.projection_hold
        {
            QOutcome::Fail
        } else if input.projection_quality < self.thresholds.projection_pass {
            QOutcome::Hold
        } else {
            QOutcome::Pass
        };
        // R — residue load: lower is better; 0 passes, some holds, heavy fails.
        // Non-finite (incl. a NaN from a 0/0 load) fails closed rather than
        // slipping past both `>` comparisons to Pass.
        let r = if !input.residue_load.is_finite()
            || input.residue_load > self.thresholds.residue_hold
        {
            QOutcome::Fail
        } else if input.residue_load > self.thresholds.residue_pass {
            QOutcome::Hold
        } else {
            QOutcome::Pass
        };
        // B — boundary stability: an unstable boundary (kill-switch engaged, or
        // an open boundary residue) holds conservatively; a hard kill-switch
        // Deny is enforced above this axis by the Crown.
        let b = if input.boundary_stable {
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
            projection_quality: 1.0,
            residue_load: 0.0,
            boundary_stable: true,
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

        // ...while a different failing axis (Π projection quality) also fails,
        // but the *vector* distinguishes them — the reason is not lost.
        let mut low_projection = clean();
        low_projection.projection_quality = 0.0;
        let vp = gate.evaluate(&low_projection);
        assert_eq!(vp.verdict(), QOutcome::Fail);
        assert_eq!(vp.pi, QOutcome::Fail);
        assert_ne!(
            vd.axes(),
            vp.axes(),
            "two Fail verdicts still differ per axis"
        );
        assert_ne!(vd.reasons(), vp.reasons());

        // A residue load holds (not fails) — Hold is a distinct third state.
        let mut held = clean();
        held.residue_load = 0.3;
        let vh = gate.evaluate(&held);
        assert_eq!(vh.verdict(), QOutcome::Hold);
        assert_eq!(vh.r, QOutcome::Hold);
        assert_eq!(vh.to_ssk(), GateOutcomeKind::Hold);
    }

    // A6/G3+G4: each axis reads its own theory quantity and nothing else. This
    // pins the corrected semantics: Π reads projection_quality (not parallax),
    // R reads residue_load (not replay), B reads boundary_stable (not an
    // obligation count) — a regression that re-purposed any axis would fail here.
    #[test]
    fn each_axis_binds_to_its_theory_quantity() {
        let gate = QLogicGate::default();

        // Π is driven ONLY by projection_quality.
        let mut pi_only = clean();
        pi_only.projection_quality = 0.0;
        let v = gate.evaluate(&pi_only);
        assert_eq!(v.pi, QOutcome::Fail);
        assert_eq!(v.r, QOutcome::Pass, "projection quality must not move R");
        assert_eq!(v.b, QOutcome::Pass, "projection quality must not move B");

        // R is driven ONLY by residue_load.
        let mut r_only = clean();
        r_only.residue_load = 0.9;
        let v = gate.evaluate(&r_only);
        assert_eq!(v.r, QOutcome::Fail);
        assert_eq!(v.pi, QOutcome::Pass, "residue load must not move Π");
        assert_eq!(v.b, QOutcome::Pass, "residue load must not move B");

        // B is driven ONLY by boundary_stable.
        let mut b_only = clean();
        b_only.boundary_stable = false;
        let v = gate.evaluate(&b_only);
        assert_eq!(v.b, QOutcome::Hold);
        assert_eq!(v.pi, QOutcome::Pass, "boundary stability must not move Π");
        assert_eq!(v.r, QOutcome::Pass, "boundary stability must not move R");
    }

    // A6: Π and R fail closed on a non-finite measurement, just like κ — a NaN
    // must never slip past the pass-side comparisons to a spurious Pass.
    #[test]
    fn non_finite_projection_and_residue_fail_closed() {
        let gate = QLogicGate::default();

        let mut nan_pi = clean();
        nan_pi.projection_quality = f64::NAN;
        assert_eq!(gate.evaluate(&nan_pi).pi, QOutcome::Fail);

        let mut nan_r = clean();
        nan_r.residue_load = f64::NAN;
        assert_eq!(gate.evaluate(&nan_r).r, QOutcome::Fail);
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
