#![forbid(unsafe_code)]

use ssk_types::Locator;

#[must_use]
pub fn linkability_score(locator: &Locator) -> u8 {
    if locator.trusted { locator.risk_score / 2 } else { locator.risk_score }
}
