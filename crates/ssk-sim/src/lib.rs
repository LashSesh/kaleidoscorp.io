#![forbid(unsafe_code)]

use ssk_types::RuntimeOutcome;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimSummary {
    pub residues_seen: usize,
    pub accepted: bool,
}

#[must_use]
pub fn evaluate(outcome: &RuntimeOutcome) -> SimSummary {
    SimSummary {
        residues_seen: outcome.residues.len(),
        accepted: outcome.stitch.is_some(),
    }
}
