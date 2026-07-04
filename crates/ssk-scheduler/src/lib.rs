#![forbid(unsafe_code)]

use rand::Rng;
use rand_pcg::Pcg64;
use ssk_types::{
    FrequencyVector, Phase, PhaseVector, SchedulerMode, SchedulerSeed, SchedulerState, Window,
    PHASE_MODULUS,
};

/// Deterministic phase scheduler on the hypertorus `T^n` (Master Spec Ω+1
/// ch. 7). Wall-clock time enters only through the runtime driver, never the
/// domain model — this is what makes replay possible. Renamed from
/// `DeterministicScheduler`: the old name undersold that `Seeded` mode is
/// also fully deterministic given its recorded seed.
#[derive(Debug, Clone)]
pub struct HypertoroidalScheduler {
    state: SchedulerState,
}

impl HypertoroidalScheduler {
    #[must_use]
    pub fn new(
        theta0: PhaseVector,
        freq: FrequencyVector,
        mode: SchedulerMode,
        epoch: u64,
    ) -> Self {
        Self {
            state: SchedulerState {
                theta0,
                freq,
                mode,
                epoch,
                ticks: 0,
            },
        }
    }

    #[must_use]
    pub fn tick(&mut self) -> PhaseVector {
        self.state.ticks += 1;
        let jitter = self.jitter();
        self.state.theta0.identity = advance(
            self.state.theta0.identity,
            self.state.freq.identity,
            jitter[0],
        );
        self.state.theta0.locator = advance(
            self.state.theta0.locator,
            self.state.freq.locator,
            jitter[1],
        );
        self.state.theta0.protocol = advance(
            self.state.theta0.protocol,
            self.state.freq.protocol,
            jitter[2],
        );
        self.state.theta0.timing =
            advance(self.state.theta0.timing, self.state.freq.timing, jitter[3]);
        self.state.theta0.risk = advance(self.state.theta0.risk, self.state.freq.risk, jitter[4]);
        self.state.theta0.replay =
            advance(self.state.theta0.replay, self.state.freq.replay, jitter[5]);
        self.state.theta0.focus =
            advance(self.state.theta0.focus, self.state.freq.focus, jitter[6]);
        self.state.theta0.clone()
    }

    /// Per-axis jitter for this tick: zero under `Deterministic` mode; a
    /// value seeded deterministically from `(seed, tick count)` under
    /// `Seeded` mode, so replaying the same `RunDescriptor` reproduces
    /// identical phase points bit-for-bit (ch. 7.2's replay requirement).
    fn jitter(&self) -> [u32; 7] {
        match self.state.mode {
            SchedulerMode::Deterministic => [0; 7],
            SchedulerMode::Seeded(SchedulerSeed(seed)) => {
                let mut rng = Pcg64::new(
                    seed as u128 ^ (self.state.ticks as u128) << 64,
                    0x0a02_bdbf_7bb3_c0a7_ac28_fa16_a64a_bf96,
                );
                let mut out = [0u32; 7];
                for slot in &mut out {
                    *slot = rng.gen_range(0..PHASE_MODULUS / 1000);
                }
                out
            }
        }
    }

    #[must_use]
    pub fn phase(&self) -> &PhaseVector {
        &self.state.theta0
    }

    #[must_use]
    pub fn state(&self) -> SchedulerState {
        self.state.clone()
    }

    /// Visibility predicate: `R_eps(x, theta) = 1{ d_T(theta, psi(x)) < eps_x }`
    /// (ch. 7.2, verbatim). A necessary precondition for candidate formation,
    /// never a sufficient condition for materialization.
    #[must_use]
    pub fn visible(&self, target: &PhaseVector, w: Window) -> bool {
        let theta = &self.state.theta0;
        [
            toroidal_distance(theta.identity, target.identity),
            toroidal_distance(theta.locator, target.locator),
            toroidal_distance(theta.protocol, target.protocol),
            toroidal_distance(theta.timing, target.timing),
            toroidal_distance(theta.risk, target.risk),
            toroidal_distance(theta.replay, target.replay),
            toroidal_distance(theta.focus, target.focus),
        ]
        .into_iter()
        .all(|d| d < w.epsilon)
    }
}

fn advance(phase: Phase, freq: u32, jitter: u32) -> Phase {
    Phase((phase.0 + freq + jitter) % PHASE_MODULUS)
}

/// Toroidal distance (ch. 7.2, verbatim): `d(a, b) = min(|a-b|, M-|a-b|)`
/// with `M = PHASE_MODULUS`.
fn toroidal_distance(a: Phase, b: Phase) -> u32 {
    let diff = a.0.abs_diff(b.0);
    diff.min(PHASE_MODULUS - diff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn deterministic_tick(seed in any::<u64>()) {
            let freq = FrequencyVector::deterministic();
            let theta = PhaseVector::zero();
            let mut a = HypertoroidalScheduler::new(theta.clone(), freq.clone(), SchedulerMode::Seeded(SchedulerSeed(seed)), 0);
            let mut b = HypertoroidalScheduler::new(theta, freq, SchedulerMode::Seeded(SchedulerSeed(seed)), 0);
            for _ in 0..10 {
                prop_assert_eq!(a.tick(), b.tick());
            }
        }
    }

    #[test]
    fn deterministic_mode_applies_no_jitter() {
        let freq = FrequencyVector::deterministic();
        let mut sched = HypertoroidalScheduler::new(
            PhaseVector::zero(),
            freq.clone(),
            SchedulerMode::Deterministic,
            0,
        );
        let theta = sched.tick();
        assert_eq!(theta.identity, Phase(freq.identity));
    }

    #[test]
    fn a_scheduler_is_self_visible_at_zero_epsilon_distance() {
        let sched = HypertoroidalScheduler::new(
            PhaseVector::zero(),
            FrequencyVector::deterministic(),
            SchedulerMode::Deterministic,
            0,
        );
        assert!(sched.visible(&PhaseVector::zero(), Window { epsilon: 1 }));
        assert!(!sched.visible(&PhaseVector::zero(), Window { epsilon: 0 }));
    }

    #[test]
    fn visibility_respects_toroidal_wraparound() {
        let sched = HypertoroidalScheduler::new(
            PhaseVector::zero(),
            FrequencyVector::deterministic(),
            SchedulerMode::Deterministic,
            0,
        );
        let near_wrap = PhaseVector {
            identity: Phase(PHASE_MODULUS - 1),
            ..PhaseVector::zero()
        };
        // Toroidal distance from 0 to M-1 is 1, not M-1.
        assert!(sched.visible(&near_wrap, Window { epsilon: 2 }));
        assert!(!sched.visible(&near_wrap, Window { epsilon: 1 }));
    }
}
