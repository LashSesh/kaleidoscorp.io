//! `SelfAnchor` — the Mirror Dome's canonical own-identity (IMDF 4.1), held
//! rigorously distinct from a `Locator`.
//!
//! A [`SelfAnchor`] answers *who am I* (scope, owner, policy, key context,
//! replay root, boundary). A [`DomeLocator`] answers *where is it* (an address).
//! They are separate types over separate, **domain-separated** content-address
//! id spaces: even built from the same source string they never produce the same
//! id, and neither exposes the other's fields, so a location can never be read as
//! an identity. Relating the two is only ever a gated BCIK crossing — never an
//! implicit conversion. This is the Locator≠Identity invariant, enforced at the
//! type level.

use serde::{Deserialize, Serialize};
use ssk_types::{
    content_id, digest_of, BoundaryRef, Digest, HashAlg, KeyContextRef, PolicyId, ReplayRoot,
};

content_id!(SelfAnchorId);
content_id!(LocatorAddressId);

/// Domain tag folded into the canonical bytes so an identity id and a locator id
/// derived from overlapping data can never collide.
const SELF_ANCHOR_DOMAIN: &str = "imdf/self-anchor/v1";
const LOCATOR_DOMAIN: &str = "imdf/locator/v1";

/// The canonical own-identity of a Mirror Dome subject (IMDF 4.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfAnchor {
    pub id: SelfAnchorId,
    pub scope: String,
    pub owner: String,
    pub policy: PolicyId,
    pub key_context: KeyContextRef,
    pub replay_root: ReplayRoot,
    pub boundary: BoundaryRef,
}

#[derive(Serialize)]
struct SelfAnchorForm<'a> {
    domain: &'a str,
    scope: &'a str,
    owner: &'a str,
    policy: &'a PolicyId,
    key_context: &'a KeyContextRef,
    replay_root: &'a ReplayRoot,
    boundary: &'a BoundaryRef,
}

impl SelfAnchor {
    /// Construct a self-anchor, deriving its id from the identity fields under
    /// the self-anchor domain tag.
    #[must_use]
    pub fn new(
        scope: impl Into<String>,
        owner: impl Into<String>,
        policy: PolicyId,
        key_context: KeyContextRef,
        replay_root: ReplayRoot,
        boundary: BoundaryRef,
    ) -> Self {
        let scope = scope.into();
        let owner = owner.into();
        let id = SelfAnchorId::of(
            &SelfAnchorForm {
                domain: SELF_ANCHOR_DOMAIN,
                scope: &scope,
                owner: &owner,
                policy: &policy,
                key_context: &key_context,
                replay_root: &replay_root,
                boundary: &boundary,
            },
            HashAlg::Blake3,
        )
        .expect("self-anchor form is serializable");
        SelfAnchor {
            id,
            scope,
            owner,
            policy,
            key_context,
            replay_root,
            boundary,
        }
    }

    /// The identity digest (the content the anchor commits to).
    #[must_use]
    pub fn identity_digest(&self) -> Digest {
        self.id.0
    }
}

/// A *where-address* — deliberately holds no identity fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomeLocator {
    pub id: LocatorAddressId,
    pub address: String,
}

#[derive(Serialize)]
struct LocatorForm<'a> {
    domain: &'a str,
    address: &'a str,
}

impl DomeLocator {
    /// Construct a locator from an address, under the locator domain tag.
    #[must_use]
    pub fn new(address: impl Into<String>) -> Self {
        let address = address.into();
        let id = LocatorAddressId::of(
            &LocatorForm {
                domain: LOCATOR_DOMAIN,
                address: &address,
            },
            HashAlg::Blake3,
        )
        .expect("locator form is serializable");
        DomeLocator { id, address }
    }

    /// The address digest.
    #[must_use]
    pub fn address_digest(&self) -> Digest {
        self.id.0
    }
}

/// A gated BCIK-style crossing witness: the *only* way to relate a locator to an
/// anchor. It records the crossing but never equates the two ids — identity and
/// location remain distinct even after an authorized crossing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BcikCrossing {
    pub anchor: SelfAnchorId,
    pub locator: LocatorAddressId,
    pub witness: Digest,
}

impl BcikCrossing {
    /// Record an authorized crossing between an anchor and a locator.
    #[must_use]
    pub fn record(anchor: &SelfAnchor, locator: &DomeLocator) -> Self {
        #[derive(Serialize)]
        struct Witness<'a> {
            domain: &'a str,
            anchor: &'a SelfAnchorId,
            locator: &'a LocatorAddressId,
        }
        let witness = digest_of(
            &Witness {
                domain: "imdf/bcik-crossing/v1",
                anchor: &anchor.id,
                locator: &locator.id,
            },
            HashAlg::Blake3,
        )
        .expect("crossing witness is serializable");
        BcikCrossing {
            anchor: anchor.id,
            locator: locator.id,
            witness,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor_for(owner: &str, scope: &str) -> SelfAnchor {
        SelfAnchor::new(
            scope,
            owner,
            PolicyId::new("policy-1"),
            KeyContextRef::new("kc-1"),
            ReplayRoot::new("rr-1"),
            BoundaryRef::new("b-1"),
        )
    }

    // IMDF Appendix A: self_anchor_is_not_locator.
    #[test]
    fn self_anchor_is_not_locator() {
        // Built to be "about the same subject" by the same string.
        let anchor = anchor_for("alice", "host-a");
        let locator = DomeLocator::new("alice");
        // Distinct content-address spaces: the digests never coincide.
        assert_ne!(anchor.identity_digest(), locator.address_digest());
        // Even an anchor whose owner *is* the locator's address stays distinct.
        let anchor_named_like_address = anchor_for("alice", "host-a");
        assert_ne!(
            anchor_named_like_address.identity_digest(),
            locator.address_digest()
        );
        // A gated crossing relates them but still does not equate the ids.
        let crossing = BcikCrossing::record(&anchor, &locator);
        assert_eq!(crossing.anchor, anchor.id);
        assert_eq!(crossing.locator, locator.id);
        assert_ne!(crossing.anchor.0, crossing.locator.0);
    }

    #[test]
    fn anchor_id_is_deterministic_and_field_sensitive() {
        assert_eq!(
            anchor_for("alice", "host-a").id,
            anchor_for("alice", "host-a").id
        );
        assert_ne!(
            anchor_for("alice", "host-a").id,
            anchor_for("alice", "host-b").id
        );
        assert_ne!(
            anchor_for("alice", "host-a").id,
            anchor_for("bob", "host-a").id
        );
    }
}
