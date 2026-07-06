#![forbid(unsafe_code)]

//! # ssk-meta-resonance — the MetaResonanceController (FCHL-MPK Band B)
//!
//! A PID + symmetry-feedback loop over the FieldTensorSkin's δF drift signal
//! (setpoint = zero drift). It produces a [`ResonanceResponse`] that can
//! **stabilize** or **delay**, but two invariants are structural, not advisory:
//!
//! * **Never bypasses a gate.** [`MetaResonanceController::apply_to_gate`] can
//!   only keep a gate outcome or make it *more* conservative — it can never
//!   promote `Hold`/`Reject`/`Quarantine` toward `Pass`. The response has no
//!   "bypass" action at all.
//! * **No gate-flicker.** `apply_to_gate` is deterministic and monotone, so the
//!   same `(outcome, response)` always maps the same way and a decision never
//!   oscillates toward `Pass`.
//!
//! The loop is meta-stable: the integral term is anti-windup clamped and the
//! output is bounded, so a persistent drift produces a bounded response, never a
//! runaway.
//!
//! Alongside the PID it carries the run-transition [`DriftMode`] (IMRT
//! Def. 16.8): a persisted, path-dependent mode over the drift Δ governed by
//! **double-threshold hysteresis** (θ_on > θ_off). Inside the band both modes
//! are reachable at the same Δ (Satz 16.9), so the compensate-vs-new-run
//! boundary is *not* a single-threshold point predicate — the provably wrong
//! form. This mode is a signal over Δ; it does not change the Δ gate axis or
//! `IMRTValid` (Bemerkung 16.17).

use serde::{Deserialize, Serialize};
use ssk_types::GateOutcomeKind;

/// What the controller recommends. There is deliberately no `Bypass`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResonanceAction {
    /// Drift is under control; proceed.
    Stabilize,
    /// Drift is elevated; delay (downgrade a pass to a hold).
    Delay,
    /// Drift is high; hold.
    Hold,
}

/// The run-transition drift mode (IMRT Def. 16.8, Satz 16.9): whether the
/// current drift is being **compensated** within the same run, or has crossed
/// the upper threshold so a **new run** is required. It is deliberately a
/// *persisted, path-dependent* mode over the drift Δ — not a point predicate on
/// the current value — because a single-threshold criterion is provably the
/// wrong form of the boundary (Satz 16.9): inside the hysteresis band both modes
/// are reachable at the same Δ, decided only by the approach path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftMode {
    /// Compensate the drift — the same run continues.
    Komp,
    /// The drift crossed the upper threshold — a new run is required.
    Neu,
}

/// The controller's response for one step.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResonanceResponse {
    pub action: ResonanceAction,
    /// The (clamped, bounded) PID adjustment.
    pub adjustment: f64,
    /// The drift the response was computed from.
    pub measured_drift: f64,
    /// The persisted, hysteretic drift mode after this step (Def. 16.8). This is
    /// a mode *over* Δ; it does not change the Δ gate axis or `IMRTValid`
    /// (Bemerkung 16.17) — it signals the run-transition consumer whether a new
    /// run is required.
    pub drift_mode: DriftMode,
}

/// PID gains and thresholds.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ResonanceConfig {
    pub kp: f64,
    pub ki: f64,
    pub kd: f64,
    /// Anti-windup / output clamp magnitude.
    pub clamp: f64,
    /// Drift at or below which the loop is considered stabilized.
    pub stable_threshold: f64,
    /// Drift above which the loop holds rather than merely delays.
    pub hold_threshold: f64,
    /// θ_on (Def. 16.8): drift at or above which `Komp` switches to `Neu`
    /// (a new run is required). Must be strictly greater than `drift_mode_off`.
    pub drift_mode_on: f64,
    /// θ_off (Def. 16.8): drift at or below which `Neu` switches back to `Komp`.
    pub drift_mode_off: f64,
}

impl Default for ResonanceConfig {
    fn default() -> Self {
        ResonanceConfig {
            kp: 0.6,
            ki: 0.1,
            kd: 0.2,
            clamp: 10.0,
            stable_threshold: 0.05,
            hold_threshold: 0.5,
            drift_mode_on: 0.5,
            drift_mode_off: 0.2,
        }
    }
}

/// The PID + symmetry-feedback controller.
#[derive(Clone, Debug)]
pub struct MetaResonanceController {
    config: ResonanceConfig,
    integral: f64,
    prev_error: f64,
    /// The persisted, hysteretic run-transition mode (Def. 16.8). Starts in
    /// `Komp` (compensate) and only flips per the double-threshold rule.
    drift_mode: DriftMode,
}

impl Default for MetaResonanceController {
    fn default() -> Self {
        Self::new(ResonanceConfig::default())
    }
}

impl MetaResonanceController {
    #[must_use]
    pub fn new(config: ResonanceConfig) -> Self {
        MetaResonanceController {
            config,
            integral: 0.0,
            prev_error: 0.0,
            drift_mode: DriftMode::Komp,
        }
    }

    /// The current persisted drift mode.
    #[must_use]
    pub fn drift_mode(&self) -> DriftMode {
        self.drift_mode
    }

    /// Advance the loop by one drift measurement (setpoint is zero drift).
    pub fn step(&mut self, measured_drift: f64) -> ResonanceResponse {
        let c = &self.config;
        let error = measured_drift; // setpoint 0
        self.integral = (self.integral + error).clamp(-c.clamp, c.clamp);
        let derivative = error - self.prev_error;
        self.prev_error = error;
        let raw = c.kp * error + c.ki * self.integral + c.kd * derivative;
        let adjustment = raw.clamp(-c.clamp, c.clamp);

        let action = if measured_drift <= c.stable_threshold {
            ResonanceAction::Stabilize
        } else if measured_drift <= c.hold_threshold {
            ResonanceAction::Delay
        } else {
            ResonanceAction::Hold
        };

        // Double-threshold hysteresis (Def. 16.8): Komp→Neu only at/above θ_on,
        // Neu→Komp only at/below θ_off; inside the band the mode is unchanged,
        // so it is path-dependent (Satz 16.9), never a point predicate on Δ. A
        // non-finite drift is treated conservatively as requiring a new run.
        self.drift_mode = if !measured_drift.is_finite() {
            DriftMode::Neu
        } else {
            match self.drift_mode {
                DriftMode::Komp if measured_drift >= c.drift_mode_on => DriftMode::Neu,
                DriftMode::Neu if measured_drift <= c.drift_mode_off => DriftMode::Komp,
                unchanged => unchanged,
            }
        };

        ResonanceResponse {
            action,
            adjustment,
            measured_drift,
            drift_mode: self.drift_mode,
        }
    }

    /// Apply a response to a gate outcome. This can only keep the outcome or make
    /// it more conservative — it never promotes toward `Pass` (no gate bypass,
    /// no upward flicker).
    #[must_use]
    pub fn apply_to_gate(
        &self,
        gate: GateOutcomeKind,
        response: &ResonanceResponse,
    ) -> GateOutcomeKind {
        match gate {
            // Non-passing outcomes are never upgraded by resonance.
            GateOutcomeKind::Reject => GateOutcomeKind::Reject,
            GateOutcomeKind::Quarantine => GateOutcomeKind::Quarantine,
            GateOutcomeKind::Hold => GateOutcomeKind::Hold,
            GateOutcomeKind::Refine => GateOutcomeKind::Refine,
            // A pass may be held back when drift is elevated, but is otherwise kept.
            GateOutcomeKind::Pass => match response.action {
                ResonanceAction::Stabilize => GateOutcomeKind::Pass,
                ResonanceAction::Delay | ResonanceAction::Hold => GateOutcomeKind::Hold,
            },
        }
    }

    #[must_use]
    pub fn integral(&self) -> f64 {
        self.integral
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller() -> MetaResonanceController {
        MetaResonanceController::default()
    }

    // FCHL-MPK: the MPK/resonance signal only stabilizes or delays — it never
    // bypasses a gate (never promotes a non-pass toward Pass).
    #[test]
    fn resonance_never_bypasses_a_gate() {
        let ctrl = controller();
        // A high-drift response with every possible action.
        for drift in [0.0, 0.3, 2.0] {
            let mut c = controller();
            let resp = c.step(drift);
            // No response can turn a Reject/Quarantine/Hold/Refine into a Pass.
            for gate in [
                GateOutcomeKind::Reject,
                GateOutcomeKind::Quarantine,
                GateOutcomeKind::Hold,
                GateOutcomeKind::Refine,
            ] {
                assert_ne!(ctrl.apply_to_gate(gate, &resp), GateOutcomeKind::Pass);
                assert_eq!(
                    ctrl.apply_to_gate(gate, &resp),
                    gate,
                    "non-pass outcomes are preserved"
                );
            }
        }
    }

    // No gate-flicker: apply_to_gate is deterministic and monotone-conservative;
    // a Pass under elevated drift is held and stays held on re-application.
    #[test]
    fn no_gate_flicker() {
        let ctrl = controller();
        let mut c = controller();
        let elevated = c.step(0.3); // Delay
        let held = ctrl.apply_to_gate(GateOutcomeKind::Pass, &elevated);
        assert_eq!(
            held,
            GateOutcomeKind::Hold,
            "elevated drift delays a pass to a hold"
        );
        // Re-applying to the now-held outcome keeps it held — no oscillation.
        assert_eq!(ctrl.apply_to_gate(held, &elevated), GateOutcomeKind::Hold);
        // Determinism: the same inputs always map the same way.
        assert_eq!(
            ctrl.apply_to_gate(GateOutcomeKind::Pass, &elevated),
            ctrl.apply_to_gate(GateOutcomeKind::Pass, &elevated)
        );
        // A stabilized response keeps a pass.
        let mut c2 = controller();
        let stable = c2.step(0.0);
        assert_eq!(stable.action, ResonanceAction::Stabilize);
        assert_eq!(
            ctrl.apply_to_gate(GateOutcomeKind::Pass, &stable),
            GateOutcomeKind::Pass
        );
    }

    // G15 / Satz 16.9: the drift mode is bistable inside the hysteresis band —
    // for Δ ∈ (θ_off, θ_on), approaching from below yields Komp and approaching
    // from above yields Neu at the SAME Δ. This is the property a single
    // threshold cannot express.
    #[test]
    fn drift_mode_is_bistable_in_the_band() {
        let cfg = ResonanceConfig::default();
        let band = (cfg.drift_mode_off + cfg.drift_mode_on) / 2.0; // 0.35, inside (0.2, 0.5)
        assert!(band > cfg.drift_mode_off && band < cfg.drift_mode_on);

        // Approach from below: start calm, then the band value → stays Komp.
        let mut from_below = controller();
        from_below.step(0.0);
        let r_below = from_below.step(band);
        assert_eq!(
            r_below.drift_mode,
            DriftMode::Komp,
            "band from below stays Komp"
        );

        // Approach from above: cross θ_on to Neu, then the same band value →
        // stays Neu. Same Δ, different mode — decided by the path, not the value.
        let mut from_above = controller();
        from_above.step(0.9); // ≥ θ_on → Neu
        let r_above = from_above.step(band);
        assert_eq!(
            r_above.drift_mode,
            DriftMode::Neu,
            "band from above stays Neu"
        );

        assert_eq!(r_below.measured_drift, r_above.measured_drift);
        assert_ne!(r_below.drift_mode, r_above.drift_mode);
    }

    // The mode only flips at the thresholds, and a non-finite drift is
    // conservatively treated as requiring a new run.
    #[test]
    fn drift_mode_flips_only_at_thresholds() {
        let mut c = controller();
        assert_eq!(c.drift_mode(), DriftMode::Komp);
        assert_eq!(
            c.step(0.49).drift_mode,
            DriftMode::Komp,
            "just below θ_on holds"
        );
        assert_eq!(
            c.step(0.5).drift_mode,
            DriftMode::Neu,
            "at θ_on flips to Neu"
        );
        assert_eq!(
            c.step(0.21).drift_mode,
            DriftMode::Neu,
            "just above θ_off holds Neu"
        );
        assert_eq!(
            c.step(0.2).drift_mode,
            DriftMode::Komp,
            "at θ_off flips back to Komp"
        );

        let mut nan = controller();
        assert_eq!(
            nan.step(f64::NAN).drift_mode,
            DriftMode::Neu,
            "non-finite → new run"
        );
    }

    // Meta-stability: a persistent drift produces a bounded response; the
    // integral never winds up past the clamp.
    #[test]
    fn loop_is_meta_stable_and_bounded() {
        let mut c = controller();
        let clamp = ResonanceConfig::default().clamp;
        let mut last = 0.0;
        for _ in 0..1000 {
            let resp = c.step(2.0);
            assert!(resp.adjustment.abs() <= clamp, "output stays clamped");
            last = resp.adjustment;
        }
        assert!(
            c.integral().abs() <= clamp,
            "integral is anti-windup clamped"
        );
        // Persistent high drift resolves to a Hold action.
        assert!(last.abs() <= clamp);
    }
}
