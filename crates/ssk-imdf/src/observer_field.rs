//! ObserverField — the k-way observer aggregate (IMDF; IMRT A5, A3).
//!
//! An [`ObserverField`] is a set of authorized [`ObserverModel`]s under a
//! **distinctness invariant**: no two observers may share an identity (their
//! content-derived ids must all differ). It feeds the atlas' ObserverManifold —
//! it *enumerates every observer* — and produces the **k-way parallax** over a
//! surface as a [`RaySet`] of one ray per observer. A field of fewer than two
//! distinct observers carries no parallax and is not gate-relevant (A3: a
//! gate-relevant claim's parallax must be over ≥2 members).

use std::collections::BTreeSet;

use ssk_signature::SpectralSignature;

use crate::error::ImdfError;
use crate::observer::{ObserverId, ObserverModel};
use crate::wavefront::{Ray, RaySet, Wavefront};

/// A distinct set of authorized observers.
#[derive(Clone, Debug)]
pub struct ObserverField {
    observers: Vec<ObserverModel>,
}

impl ObserverField {
    /// Build an observer field, enforcing the **distinctness invariant**: every
    /// observer id must be unique (no two identical perspectives).
    ///
    /// # Errors
    /// [`ImdfError::DuplicateObserver`] if two observers share an id.
    pub fn new(observers: Vec<ObserverModel>) -> Result<Self, ImdfError> {
        let mut seen = BTreeSet::new();
        for o in &observers {
            if !seen.insert(o.id) {
                return Err(ImdfError::DuplicateObserver);
            }
        }
        Ok(ObserverField { observers })
    }

    /// Every observer in the field, in construction order — the ObserverManifold
    /// enumerates all of them.
    #[must_use]
    pub fn observers(&self) -> &[ObserverModel] {
        &self.observers
    }

    /// The ids of every observer (the manifold's enumeration).
    #[must_use]
    pub fn observer_ids(&self) -> Vec<ObserverId> {
        self.observers.iter().map(|o| o.id).collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.observers.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observers.is_empty()
    }

    /// Whether the field is gate-relevant for a parallax obligation: it must hold
    /// **≥2** distinct observers (A3 — a single ray is a copy, not a split).
    #[must_use]
    pub fn is_gate_relevant(&self) -> bool {
        self.observers.len() >= 2
    }

    /// The **k-way parallax** over a surface: capture one ray per observer and
    /// return the [`RaySet`] the parallax operator consumes. Requires ≥2
    /// observers (else there is no parallax to take).
    ///
    /// # Errors
    /// [`ImdfError::ParallaxUnderdetermined`] if the field has fewer than two
    /// observers; [`ImdfError::ApertureRequired`] if any observer's aperture is
    /// closed.
    pub fn parallax(&self, signature: &SpectralSignature) -> Result<RaySet, ImdfError> {
        if !self.is_gate_relevant() {
            return Err(ImdfError::ParallaxUnderdetermined);
        }
        let mut rays = Vec::with_capacity(self.observers.len());
        for o in &self.observers {
            rays.push(Ray::of(Wavefront::capture(o, signature)?));
        }
        RaySet::new(rays).ok_or(ImdfError::ParallaxUnderdetermined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aperture::Aperture;
    use crate::observer::{Lens, TrustLevel, Vantage};
    use ssk_signature::{signature_for, AuthorizationManifest, OrderedMap, SurfaceObject, Value};
    use ssk_types::ReplayRoot;

    fn auth() -> AuthorizationManifest {
        AuthorizationManifest::new("owned-dome", "me", "self-owned")
            .with_allowed_uses([crate::observer::SELF_OBSERVATION_USE])
    }

    fn observer(vantage: &str) -> ObserverModel {
        ObserverModel::new(
            "host-a",
            Vantage::new(vantage),
            Aperture::admitting("wide", ["shape", "ordering", "semantic"]),
            Lens::new("l", ["shape"]),
            vec![],
            TrustLevel::Observed,
            ReplayRoot::new("rr"),
            &auth(),
        )
        .unwrap()
    }

    fn surface() -> SpectralSignature {
        let fields = OrderedMap::from_iter([
            ("method".to_owned(), Value::Text("GET".to_owned())),
            (
                "url".to_owned(),
                Value::Text("https://example.test/a".to_owned()),
            ),
            ("status".to_owned(), Value::Num(200.0)),
        ]);
        signature_for(
            &SurfaceObject::new("application/trace+json", fields)
                .with_declared_protocol_class("http"),
        )
    }

    // G25 (A5/A3): the field enforces distinctness, enumerates every observer,
    // and its k-way parallax is over >=2 rays.
    #[test]
    fn observer_field_enumerates_distinct_observers_and_takes_k_way_parallax() {
        let a = observer("front");
        let b = observer("left");
        let c = observer("right");

        let field = ObserverField::new(vec![a.clone(), b.clone(), c.clone()]).unwrap();
        // Enumerates every observer.
        assert_eq!(field.len(), 3);
        assert_eq!(field.observer_ids(), vec![a.id, b.id, c.id]);
        assert!(
            field.is_gate_relevant(),
            "3 distinct observers are gate-relevant"
        );

        // k-way parallax: one ray per observer, all orthogonal (distinct vantages).
        let rays = field.parallax(&surface()).unwrap();
        assert_eq!(rays.len(), 3, "k-way parallax has one ray per observer");
        assert!(
            rays.is_orthogonal(),
            "distinct vantages are orthogonal rays"
        );
    }

    // The distinctness invariant: two identical observers cannot both be in the
    // field (same content-derived id).
    #[test]
    fn observer_field_rejects_duplicate_observers() {
        let a = observer("front");
        let dup = observer("front"); // identical config → identical id
        assert_eq!(a.id, dup.id);
        assert_eq!(
            ObserverField::new(vec![a, dup]).unwrap_err(),
            ImdfError::DuplicateObserver
        );
    }

    // A single-observer field carries no parallax and is not gate-relevant.
    #[test]
    fn single_observer_field_has_no_parallax() {
        let field = ObserverField::new(vec![observer("front")]).unwrap();
        assert!(!field.is_gate_relevant());
        assert_eq!(
            field.parallax(&surface()).unwrap_err(),
            ImdfError::ParallaxUnderdetermined
        );
    }
}
