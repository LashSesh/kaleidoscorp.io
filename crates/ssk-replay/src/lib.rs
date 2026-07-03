#![forbid(unsafe_code)]

use ssk_types::{ReplayManifest, ReplayVerdict, RuntimeOutcome};

pub trait ReplayEngine {
    fn replay(&self, manifest: &ReplayManifest, actual: &RuntimeOutcome, expected: &RuntimeOutcome) -> ReplayVerdict;
}

#[derive(Default)]
pub struct DeterministicReplayEngine;

impl ReplayEngine for DeterministicReplayEngine {
    fn replay(&self, manifest: &ReplayManifest, actual: &RuntimeOutcome, expected: &RuntimeOutcome) -> ReplayVerdict {
        if manifest.run == actual.run
            && actual.gate_report == expected.gate_report
            && actual.stitch == expected.stitch
            && actual.traces == expected.traces
        {
            ReplayVerdict::Deterministic
        } else {
            ReplayVerdict::Divergent {
                first_diff: ssk_types::PipelineStep::Replay,
                detail: "replay diff detected".to_string(),
            }
        }
    }
}
