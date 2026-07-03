#![forbid(unsafe_code)]

use ssk_types::StitchCandidate;

#[must_use]
pub fn refocuses(candidate: &StitchCandidate) -> bool {
    candidate.focus_ready && candidate.facet.core_id == candidate.core.id
}
