#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use serde::{Deserialize, Serialize};
use ssk_types::{
    CoreNode, Id, MirrorFacet, ObjectKind, ReplayRoot, ResidueKind, ResiduePolicy, Sector,
};

pub mod connection;

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

/// Only foundation types implement `CoreObject`; downstream crates cannot,
/// since `sealed::Sealed` is not exported (Master Spec Ω+1 ch. 3.2).
pub trait CoreObject: sealed::Sealed {
    fn object_kind(&self) -> ObjectKind;
    fn residue_policy(&self) -> ResiduePolicy;
}

impl CoreObject for CoreNode {
    fn object_kind(&self) -> ObjectKind {
        ObjectKind::Core
    }

    fn residue_policy(&self) -> ResiduePolicy {
        // Matches the gate table's "residue on fail" column for CoreGate (ch. 11.2).
        ResiduePolicy(ResidueKind::Identity)
    }
}

impl CoreObject for MirrorFacet {
    fn object_kind(&self) -> ObjectKind {
        ObjectKind::MirrorFacet
    }

    fn residue_policy(&self) -> ResiduePolicy {
        // Matches the gate table's "residue on fail" column for MirrorGate (ch. 11.2).
        ResiduePolicy(ResidueKind::Identity)
    }
}

mod sealed {
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

    #[test]
    fn core_node_object_kind_and_residue_policy() {
        let c = mk_core(1);
        assert_eq!(c.object_kind(), ObjectKind::Core);
        assert_eq!(c.residue_policy(), ResiduePolicy(ResidueKind::Identity));
    }

    #[test]
    fn mirror_facet_object_kind_and_residue_policy() {
        let c = mk_core(1);
        let f = Orbit::derive(&c, Sector::Identity);
        assert_eq!(f.object_kind(), ObjectKind::MirrorFacet);
        assert_eq!(f.residue_policy(), ResiduePolicy(ResidueKind::Identity));
    }
}
