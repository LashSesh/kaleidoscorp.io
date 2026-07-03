#![forbid(unsafe_code)]

use ssk_types::{FrequencyVector, Phase, PhaseVector, SchedulerState, PHASE_MODULUS};

#[derive(Debug, Clone)]
pub struct DeterministicScheduler {
    state: SchedulerState,
}

impl DeterministicScheduler {
    #[must_use]
    pub fn new(theta0: PhaseVector, freq: FrequencyVector, seeded: bool, epoch: u64) -> Self {
        Self {
            state: SchedulerState {
                theta0: theta0.clone(),
                freq,
                seeded,
                epoch,
                ticks: 0,
            },
        }
    }

    #[must_use]
    pub fn tick(&mut self) -> PhaseVector {
        self.state.ticks += 1;
        self.state.theta0.identity = Phase((self.state.theta0.identity.0 + self.state.freq.identity) % PHASE_MODULUS);
        self.state.theta0.locator = Phase((self.state.theta0.locator.0 + self.state.freq.locator) % PHASE_MODULUS);
        self.state.theta0.protocol = Phase((self.state.theta0.protocol.0 + self.state.freq.protocol) % PHASE_MODULUS);
        self.state.theta0.timing = Phase((self.state.theta0.timing.0 + self.state.freq.timing) % PHASE_MODULUS);
        self.state.theta0.risk = Phase((self.state.theta0.risk.0 + self.state.freq.risk) % PHASE_MODULUS);
        self.state.theta0.replay = Phase((self.state.theta0.replay.0 + self.state.freq.replay) % PHASE_MODULUS);
        self.state.theta0.focus = Phase((self.state.theta0.focus.0 + self.state.freq.focus) % PHASE_MODULUS);
        self.state.theta0.clone()
    }

    #[must_use]
    pub fn state(&self) -> SchedulerState {
        self.state.clone()
    }
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
            let mut a = DeterministicScheduler::new(theta.clone(), freq.clone(), true, seed);
            let mut b = DeterministicScheduler::new(theta, freq, true, seed);
            for _ in 0..10 {
                prop_assert_eq!(a.tick(), b.tick());
            }
        }
    }
}
