#![forbid(unsafe_code)]

use ssk_types::{ConnectionIntent, MirrorFacet, StitchCandidate, StitchId};

pub fn from_intent(
    intent: ConnectionIntent,
    facet: MirrorFacet,
    locator: ssk_types::LocatorFacet,
) -> StitchCandidate {
    StitchCandidate {
        id: StitchId::new(format!("stitch:{}:{}", intent.run.0 .0, locator.id.0 .0)),
        run: intent.run,
        core: intent.core,
        facet,
        locator,
        capability: intent.capability,
        seam_ok: true,
        boundary_complete: true,
        replay_ready: true,
        focus_ready: true,
        ttl_epoch: intent.ttl_epoch,
    }
}
