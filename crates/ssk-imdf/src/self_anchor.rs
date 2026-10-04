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

/// The **L0 NullAnchor `Z_∂`** (IMRT Def. 8.1): the boundary-aperture holding
/// the internal, *prätemporal* ordering material relative to which projections
/// are ordered and recovered.
///
/// Axiom A1 forbids `Z_∂` from ever being *entered, emitted, or materialized as
/// a locator*. That invariant is enforced structurally, not by convention:
/// `NullAnchor` deliberately does **not** derive `Serialize`/`Deserialize`, so
/// the compiler rejects placing it in any serialized atlas, ledger, or wire
/// payload — it physically cannot cross a boundary. The *only* representation
/// of `Z_∂` that may cross a boundary is its content-address
/// [`NullAnchor::commitment`] (a [`Digest`]); the raw `order_ref`/
/// `recovery_root` never do.
///
/// `NullAnchor` is deliberately **not** the type that couples — that capability
/// lives on [`NullFixpoint`] (`N_int`), reachable only via [`NullAnchor::fixpoint`].
/// Splitting the boundary-aperture (`Z_∂`, non-inhabitable raw material) from the
/// coupling-active fixpoint (`N_int`, `Coupling(N_int) > 0`) means the *only*
/// path from raw ordering material to a coupled [`SelfAnchor`] runs through a
/// content-address digest — the compiler forces that step, so raw material can
/// never be coupled directly.
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
    /// representation of `Z_∂` that may cross a boundary. `Z_∂` itself never does.
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

    /// Derive the `N_int` coupling fixpoint from this `Z_∂`'s commitment. This
    /// is the *only* path from `NullAnchor` to a [`NullFixpoint`] — the raw
    /// `order_ref`/`recovery_root` material never reaches a `NullFixpoint`
    /// directly, only its already-hashed, boundary-safe commitment does.
    #[must_use]
    pub fn fixpoint(&self) -> NullFixpoint {
        NullFixpoint(self.commitment())
    }
}

/// The **L0 coupling fixpoint `N_int`** (IMRT Def. 8.1, Def. 15.3): the
/// coupling-active counterpart to [`NullAnchor`]'s (`Z_∂`) boundary-aperture,
/// `Coupling(N_int) > 0`.
///
/// Deliberately a distinct type from `NullAnchor`, not a re-labelling of it:
/// there is no `From`/`Into` or other bridging trait between the two, and
/// `NullFixpoint` never stores `order_ref`/`recovery_root` — only the already
/// content-addressed [`Digest`] produced by [`NullAnchor::commitment`]. A
/// caller cannot accidentally couple directly off `Z_∂`'s raw material; the
/// compiler forces the commitment step in between via [`NullAnchor::fixpoint`].
///
/// `NullFixpoint` still deliberately does **not** derive `Serialize`: per
/// Def. 15.3, `Π_0`/`N_int` is not itself a system state (`A ∩ X = ∅`) — only
/// its *effect* (an ordered [`SelfAnchor`], produced by [`NullFixpoint::order`])
/// is meant to cross a boundary, never the fixpoint handle itself.
///
/// This is a compile-time guarantee, not a convention — attempting to
/// serialize a `NullFixpoint` is a compile error:
///
/// ```compile_fail
/// let z = ssk_imdf::NullAnchor::new("o", "r");
/// let fp = z.fixpoint();
/// let _ = serde_json::to_string(&fp); // fails: NullFixpoint is not Serialize
/// ```
///
/// Likewise, `NullAnchor` no longer exposes coupling directly — raw ordering
/// material cannot be ordered without first passing through the commitment
/// digest via [`NullAnchor::fixpoint`]:
///
/// ```compile_fail
/// let z = ssk_imdf::NullAnchor::new("o", "r");
/// let _ = z.order( // fails: NullAnchor has no method `order` anymore
///     "s",
///     "own",
///     ssk_types::PolicyId::new("p"),
///     ssk_types::KeyContextRef::new("k"),
///     ssk_types::BoundaryRef::new("b"),
/// );
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NullFixpoint(Digest);

impl NullFixpoint {
    /// The `Z_∂` commitment this fixpoint was derived from.
    #[must_use]
    pub fn commitment(&self) -> Digest {
        self.0
    }

    /// Order a [`SelfAnchor`] against this null fixpoint (A1: `Z` orders `S`).
    /// The resulting anchor's replay root is bound to `Z_∂`'s *commitment*
    /// (never its raw material), so the reconstruction traces back to `Z_∂`
    /// without emitting it.
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
            ReplayRoot::new(self.0.to_hex()),
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
        let anchor = z.fixpoint().order(
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
            z.fixpoint()
                .order(
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

    // The NullAnchor split (S1 item 2): Z_∂ (boundary-aperture) and N_int
    // (coupling-active fixpoint) are genuinely un-conflatable, not just
    // conventionally separated.
    //
    // 1. `NullFixpoint` is reachable ONLY via `NullAnchor::fixpoint` — there is
    //    no constructor that takes raw order_ref/recovery_root material
    //    directly, so the coupling-active type can never be built by
    //    accidentally skipping the digest step.
    // 2. Two `NullFixpoint`s derived from equal-material `NullAnchor`s are
    //    equal; from different material they are different — `NullFixpoint`'s
    //    identity is wholly determined by the Z_∂ commitment, it carries
    //    nothing else (structurally, it has no other field to carry).
    // 3. The coupling role is genuinely exercised through the fixpoint, not
    //    the anchor: `NullFixpoint::order` produces the same ordered
    //    `SelfAnchor` a direct `NullAnchor::order` used to.
    #[test]
    fn null_anchor_and_null_fixpoint_are_genuinely_un_conflatable() {
        let z = NullAnchor::new("order-x", "recover-x");
        let fp1 = z.fixpoint();
        let fp2 = NullAnchor::new("order-x", "recover-x").fixpoint();
        let fp_other = NullAnchor::new("order-y", "recover-x").fixpoint();

        // Same material -> same fixpoint; different material -> different
        // fixpoint. NullFixpoint's whole identity is the Z_∂ commitment.
        assert_eq!(fp1, fp2);
        assert_ne!(fp1, fp_other);
        assert_eq!(fp1.commitment(), z.commitment());

        // The coupling capability lives on NullFixpoint and produces the same
        // ordering effect NullAnchor::order used to.
        let ordered = fp1.order(
            "scope",
            "owner",
            PolicyId::new("p"),
            KeyContextRef::new("kc"),
            BoundaryRef::new("b"),
        );
        assert_eq!(
            ordered.replay_root,
            ReplayRoot::new(z.commitment().to_hex())
        );
    }
}
