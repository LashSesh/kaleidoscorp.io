#![forbid(unsafe_code)]

use ssk_core::Orbit;
use ssk_types::{CoreNode, MirrorFacet, Sector};

#[must_use]
pub fn derive_identity_facet(core: &CoreNode) -> MirrorFacet {
    Orbit::derive(core, Sector::Identity)
}

#[must_use]
pub fn recover_identity(facet: &MirrorFacet, core: &CoreNode) -> bool {
    Orbit::recover(facet, core)
}
