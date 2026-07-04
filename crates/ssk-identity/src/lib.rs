#![forbid(unsafe_code)]

use ssk_core::MirrorOrbit;
use ssk_types::{CoreNode, MirrorFacet, PhaseVector, Sector};

#[must_use]
pub fn derive_identity_facet(core: &CoreNode) -> MirrorFacet {
    MirrorOrbit::for_core(core).derive(&PhaseVector::zero(), Sector::Identity)
}

#[must_use]
pub fn recover_identity(facet: &MirrorFacet, core: &CoreNode) -> bool {
    MirrorOrbit::for_core(core).recover(facet).is_ok()
}
