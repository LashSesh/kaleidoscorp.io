#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use serde::{Deserialize, Serialize};
use ssk_types::{CoreNode, Id, MirrorFacet, ReplayRoot, Sector};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Orbit;

impl Orbit {
    pub fn derive(core: &CoreNode, sector: Sector) -> MirrorFacet {
        MirrorFacet {
            facet_id: Id::new(format!("facet:{}:{sector:?}", core.id.0 .0)),
            core_id: core.id.clone(),
            sector,
            replay_root: ReplayRoot::new(format!("replay:{}", core.id.0 .0)),
        }
    }

    pub fn recover(facet: &MirrorFacet, core: &CoreNode) -> bool {
        facet.core_id == core.id && facet.replay_root.0 .0.starts_with("replay:")
    }
}

pub trait SealedCoreObject: private::Sealed {}
impl SealedCoreObject for CoreNode {}
impl SealedCoreObject for MirrorFacet {}

mod private {
    pub trait Sealed {}
    impl Sealed for ssk_types::CoreNode {}
    impl Sealed for ssk_types::MirrorFacet {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use ssk_types::{CoreId, PolicyId};

    fn mk_core(seed: u64) -> CoreNode {
        CoreNode {
            id: CoreId::new(format!("core-{seed}")),
            canonical_name: "alpha".to_string(),
            policy_root: PolicyId::new("policy"),
            signature_ok: true,
        }
    }

    proptest! {
        #[test]
        fn facet_recovers_to_core(seed in any::<u64>()) {
            let c = mk_core(seed);
            let f = Orbit::derive(&c, Sector::Identity);
            prop_assert!(Orbit::recover(&f, &c));
        }
    }
}
