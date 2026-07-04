#![forbid(unsafe_code)]

use ssk_types::LocatorFacet;

#[must_use]
pub fn linkability_score(locator: &LocatorFacet) -> u8 {
    if locator.trusted {
        locator.risk_score / 2
    } else {
        locator.risk_score
    }
}
