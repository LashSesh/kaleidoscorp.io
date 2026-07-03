#![forbid(unsafe_code)]

use ssk_types::BoundaryResidue;

#[must_use]
pub fn has_critical_fault(residues: &[BoundaryResidue]) -> bool {
    !residues.is_empty()
}
