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

/// Domain tag for the L0 null-anchor commitment.
const NULL_ANCHOR_DOMAIN: &str = "imdf/null-anchor/v1";

/// The **L0 NullAnchor `Z`** (IMRT Def. 8.1): the internal, *prätemporal*
/// ordering reference relative to which projections are ordered and recovered.
///
/// Axiom A1 forbids `Z` from ever being *entered, emitted, or materialized as a
/// locator*. That invariant is enforced structurally, not by convention:
/// `NullAnchor` deliberately does **not** derive `Serialize`/`Deserialize`, so
/// the compiler rejects placing it in any serialized atlas, ledger, or wire
/// payload — it physically cannot cross a boundary. The *only* representation of
/// `Z` that may cross a boundary is its content-address [`NullAnchor::commitment`]
/// (a [`Digest`]); the raw `order_ref`/`recovery_root` never do. `Z` **orders** a
/// [`SelfAnchor`] via [`NullAnchor::order`], binding the anchor's replay root to
/// `Z`'s commitment so every reconstruction traces back to `Z` without exposing
/// it (Def. 8.1: *Z ordnet S*).
#[derive(Clone, Debug)]
pub struct NullAnchor {
    order_ref: String,
    recovery_root: String,
}

impl NullAnchor {
    /// A null anchor from an order reference and a recovery root. These are
    /// internal ordering material and never leave the process except as the
    /// digest [`commitment`](NullAnchor::commitment).
    #[must_use]
    pub fn new(order_ref: impl Into<String>, recovery_root: impl Into<String>) -> Self {
        NullAnchor {
            order_ref: order_ref.into(),
            recovery_root: recovery_root.into(),
        }
    }

    /// The content-address commitment to this null anchor — the ONLY
    /// representation of `Z` that may cross a boundary. `Z` itself never does.
    #[must_use]
    pub fn commitment(&self) -> Digest {
        #[derive(Serialize)]
        struct Form<'a> {
            domain: &'a str,
            order_ref: &'a str,
            recovery_root: &'a str,
        }
        digest_of(
            &Form {
                domain: NULL_ANCHOR_DOMAIN,
                order_ref: &self.order_ref,
                recovery_root: &self.recovery_root,
            },
            HashAlg::Blake3,
        )
        .expect("null-anchor form is serializable")
    }

    /// Order a [`SelfAnchor`] against this null fixpoint (A1: `Z` orders `S`).
    /// The resulting anchor's replay root is bound to `Z`'s *commitment* (never
    /// its raw material), so the reconstruction traces back to `Z` without
    /// emitting it.
    #[must_use]
    pub fn order(
        &self,
        scope: impl Into<String>,
        owner: impl Into<String>,
        policy: PolicyId,
        key_context: KeyContextRef,
        boundary: BoundaryRef,
    ) -> SelfAnchor {
        SelfAnchor::new(
            scope,
            owner,
            policy,
            key_context,
            ReplayRoot::new(self.commitment().to_hex()),
            boundary,
        )
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

    // G1/A1: the L0 NullAnchor commitment is deterministic, field-sensitive, and
    // domain-separated from a locator built off the same string.
    #[test]
    fn null_anchor_commitment_is_deterministic_and_domain_separated() {
        let z = NullAnchor::new("order-1", "recover-1");
        assert_eq!(
            z.commitment(),
            NullAnchor::new("order-1", "recover-1").commitment()
        );
        assert_ne!(
            z.commitment(),
            NullAnchor::new("order-1", "recover-2").commitment()
        );
        // Even built off the same string, Z's commitment never collides with a
        // locator address digest (distinct domain tags).
        assert_ne!(z.commitment(), DomeLocator::new("order-1").address_digest());
    }

    // G1/A1: Z orders S, and Z is NEVER emitted — the anchor's serialized form
    // carries Z's *commitment* (the allowed reference) but not its raw material.
    #[test]
    fn null_anchor_orders_the_self_anchor_without_emitting_z() {
        let z = NullAnchor::new("order-secret", "recover-secret");
        let anchor = z.order(
            "host-a",
            "alice",
            PolicyId::new("p"),
            KeyContextRef::new("kc"),
            BoundaryRef::new("b"),
        );
        // The anchor traces back to Z via its commitment.
        assert_eq!(anchor.replay_root, ReplayRoot::new(z.commitment().to_hex()));

        // Z's raw ordering material must NOT appear anywhere the anchor can be
        // serialized to (A1: Z is never entered/emitted/materialized). This is
        // the runtime witness of the structural "not Serialize" guarantee.
        let serialized = serde_json::to_string(&anchor).expect("anchor serializes");
        assert!(!serialized.contains("order-secret"), "Z order_ref leaked");
        assert!(
            !serialized.contains("recover-secret"),
            "Z recovery_root leaked"
        );
        // The commitment hex IS present — the one allowed boundary-crossing form.
        assert!(serialized.contains(&z.commitment().to_hex()));
    }

    // Two anchors ordered by the same Z share the same recovery binding; a
    // different Z yields a different binding — Z genuinely orders S.
    #[test]
    fn same_null_anchor_binds_anchors_to_the_same_recovery_root() {
        let z1 = NullAnchor::new("o", "r");
        let z2 = NullAnchor::new("o", "different");
        let mk = |z: &NullAnchor| {
            z.order(
                "s",
                "o",
                PolicyId::new("p"),
                KeyContextRef::new("kc"),
                BoundaryRef::new("b"),
            )
            .replay_root
        };
        assert_eq!(mk(&z1), mk(&z1));
        assert_ne!(mk(&z1), mk(&z2));
    }
}
