//! Wavefront + BirefringentSplit / Parallax (IMDF 7).
//!
//! A [`Wavefront`] is one authorized, apertured observation of a surface from an
//! observer's vantage. A [`BirefringentSplit`] observes the same underlying
//! surface from two vantages; its [`Parallax`] compares the two views and flags
//! any dimension on which they disagree. This is the anti-false-uniqueness
//! guard: a surface that reads differently through two lenses is not treated as
//! one coherent thing.

use std::collections::{BTreeMap, BTreeSet};

use ssk_signature::SpectralSignature;
use ssk_types::Digest;

use crate::aperture::Reading;
use crate::error::ImdfError;
use crate::observer::{ObserverId, ObserverModel};

/// One authorized, apertured observation of a surface.
#[derive(Clone, Debug, PartialEq)]
pub struct Wavefront {
    pub observer: ObserverId,
    pub vantage: String,
    pub source_digest: Digest,
    pub readings: BTreeMap<String, Reading>,
    pub hidden_dimensions: Vec<String>,
}

impl Wavefront {
    /// Capture a wavefront: open the observer's aperture and focus the surface.
    ///
    /// # Errors
    /// [`ImdfError::ApertureRequired`] if the observer's aperture is closed.
    pub fn capture(
        observer: &ObserverModel,
        signature: &SpectralSignature,
    ) -> Result<Self, ImdfError> {
        let focus = observer.open_aperture()?.focus(signature);
        Ok(Wavefront {
            observer: observer.id,
            vantage: observer.vantage.label.clone(),
            source_digest: signature.digest,
            readings: focus.readings,
            hidden_dimensions: focus.hidden_dimensions,
        })
    }

    /// The measured (non-blind) dimensions and their digests.
    #[must_use]
    pub fn measured(&self) -> BTreeMap<&str, &str> {
        self.readings
            .iter()
            .filter_map(|(d, r)| r.as_measured_digest().map(|dg| (d.as_str(), dg)))
            .collect()
    }
}

/// The comparison of two wavefronts over the same surface.
#[derive(Clone, Debug, PartialEq)]
pub struct Parallax {
    pub shared_dimensions: Vec<String>,
    pub disagreements: Vec<String>,
    pub only_left: Vec<String>,
    pub only_right: Vec<String>,
    pub consistent: bool,
    /// Whether the two views come from genuinely orthogonal roles (distinct
    /// vantages). A same-vantage pair is a mere *copy*, not a split (Def. Split:
    /// ≥2 orthogonal roles, "sonst kein Split, nur Kopie") — it earns no
    /// parallax obligation (A3).
    pub orthogonal: bool,
}

impl Parallax {
    /// The parallax *divergence* Parx(r_i, r_j): a symmetric set-difference
    /// distance between the two views (disagreeing shared dimensions plus
    /// dimensions unique to either side). It is a pseudometric — `Parx(r,r)=0`
    /// and symmetric — realizing IMRT Inv. 9.6 (a finding stable in only one ray
    /// registers a non-zero divergence).
    #[must_use]
    pub fn divergence(&self) -> usize {
        self.disagreements.len() + self.only_left.len() + self.only_right.len()
    }

    /// Whether this split **discharges** its A3 parallax obligation — the verdict
    /// a caller feeds into the system's A3 gate (`parallax_consistent`).
    ///
    /// A non-orthogonal pair is a mere *copy* and carries no parallax obligation
    /// at all ("sonst kein Split, nur Kopie"), so it discharges trivially. A
    /// genuine orthogonal split discharges the obligation only when the two rays
    /// agree (zero divergence). This is the load-bearing meaning of
    /// [`orthogonal`](Self::orthogonal): it decides whether inconsistency is a
    /// real A3 violation or an irrelevant copy artifact.
    #[must_use]
    pub fn discharges_a3(&self) -> bool {
        !self.orthogonal || self.consistent
    }
}

/// Two views of one surface, split birefringently across two vantages.
#[derive(Clone, Debug, PartialEq)]
pub struct BirefringentSplit {
    pub left: Wavefront,
    pub right: Wavefront,
}

impl BirefringentSplit {
    #[must_use]
    pub fn of(left: Wavefront, right: Wavefront) -> Self {
        BirefringentSplit { left, right }
    }

    /// Compare the two views. Dimensions measured by both must agree on their
    /// content digest; any disagreement makes the split inconsistent.
    #[must_use]
    pub fn parallax(&self) -> Parallax {
        let left = self.left.measured();
        let right = self.right.measured();
        let left_dims: BTreeSet<&str> = left.keys().copied().collect();
        let right_dims: BTreeSet<&str> = right.keys().copied().collect();

        let mut shared: Vec<String> = left_dims
            .intersection(&right_dims)
            .map(|d| (*d).to_owned())
            .collect();
        shared.sort();
        let disagreements: Vec<String> = shared
            .iter()
            .filter(|d| left.get(d.as_str()) != right.get(d.as_str()))
            .cloned()
            .collect();
        let only_left: Vec<String> = left_dims
            .difference(&right_dims)
            .map(|d| (*d).to_owned())
            .collect();
        let only_right: Vec<String> = right_dims
            .difference(&left_dims)
            .map(|d| (*d).to_owned())
            .collect();

        Parallax {
            consistent: disagreements.is_empty(),
            shared_dimensions: shared,
            disagreements,
            only_left,
            only_right,
            // A split earns a parallax obligation only when the two rays are
            // genuinely orthogonal roles (distinct vantages). Same-vantage is a
            // mere copy — "sonst kein Split, nur Kopie" (Def. Split).
            orthogonal: self.left.vantage != self.right.vantage,
        }
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
            Aperture::admitting("wide", ["shape", "ordering", "semantic", "http_surface"]),
            Lens::new("l", ["shape"]),
            vec![],
            TrustLevel::Observed,
            ReplayRoot::new("rr"),
            &auth(),
        )
        .unwrap()
    }

    fn surface(method: &str, status: f64) -> SpectralSignature {
        let fields = OrderedMap::from_iter([
            ("method".to_owned(), Value::Text(method.to_owned())),
            (
                "url".to_owned(),
                Value::Text("https://example.test/a".to_owned()),
            ),
            ("status".to_owned(), Value::Num(status)),
        ]);
        signature_for(
            &SurfaceObject::new("application/trace+json", fields)
                .with_declared_protocol_class("http"),
        )
    }

    // IMDF Appendix A: split_parallax_detects_inconsistent_views.
    #[test]
    fn split_parallax_detects_inconsistent_views() {
        let left_obs = observer("left");
        let right_obs = observer("right");

        // Consistent: both view the same surface -> shared dims agree.
        let sig = surface("GET", 200.0);
        let split_ok = BirefringentSplit::of(
            Wavefront::capture(&left_obs, &sig).unwrap(),
            Wavefront::capture(&right_obs, &sig).unwrap(),
        );
        let p_ok = split_ok.parallax();
        assert!(
            p_ok.consistent,
            "same surface must be consistent across vantages"
        );
        assert!(p_ok.disagreements.is_empty());
        assert!(!p_ok.shared_dimensions.is_empty());

        // Inconsistent: the two views disagree on the underlying surface.
        let split_bad = BirefringentSplit::of(
            Wavefront::capture(&left_obs, &surface("GET", 200.0)).unwrap(),
            Wavefront::capture(&right_obs, &surface("POST", 503.0)).unwrap(),
        );
        let p_bad = split_bad.parallax();
        assert!(
            !p_bad.consistent,
            "diverging views must be flagged inconsistent"
        );
        assert!(!p_bad.disagreements.is_empty());
    }

    // G28: the parallax divergence Parx is a pseudometric — `Parx(r,r)=0` and
    // symmetric — realizing IMRT Inv. 9.6 (a finding stable in only one ray
    // registers a non-zero divergence, and comparing a view with itself is zero).
    #[test]
    fn parallax_divergence_is_symmetric_and_zero_on_self() {
        let left_obs = observer("left");
        let right_obs = observer("right");

        // Parx(r, r) = 0: a view compared with an identical view of the same
        // surface has zero divergence.
        let sig = surface("GET", 200.0);
        let self_split = BirefringentSplit::of(
            Wavefront::capture(&left_obs, &sig).unwrap(),
            Wavefront::capture(&right_obs, &sig).unwrap(),
        );
        assert_eq!(
            self_split.parallax().divergence(),
            0,
            "identical views over the same surface have zero divergence"
        );

        // Symmetry: Parx(r_i, r_j) = Parx(r_j, r_i) — swapping left/right must
        // not change the divergence (only_left and only_right swap roles).
        let a = Wavefront::capture(&left_obs, &surface("GET", 200.0)).unwrap();
        let b = Wavefront::capture(&right_obs, &surface("POST", 503.0)).unwrap();
        let forward = BirefringentSplit::of(a.clone(), b.clone()).parallax();
        let backward = BirefringentSplit::of(b, a).parallax();
        assert_eq!(
            forward.divergence(),
            backward.divergence(),
            "divergence must be symmetric across the two rays"
        );
        assert!(
            forward.divergence() > 0,
            "diverging views register a non-zero divergence (Inv. 9.6)"
        );
    }

    // G29: a BirefringentSplit of two same-vantage views is a mere *copy*, not a
    // genuine split — it carries no parallax obligation. "≥2 orthogonal roles,
    // sonst kein Split, nur Kopie" (Def. Split).
    #[test]
    fn birefringent_split_of_a_copy_is_not_orthogonal() {
        let obs = observer("same");
        let sig = surface("GET", 200.0);

        // Two wavefronts from the SAME vantage: consistent, but not orthogonal.
        let copy_split = BirefringentSplit::of(
            Wavefront::capture(&obs, &sig).unwrap(),
            Wavefront::capture(&obs, &sig).unwrap(),
        );
        let p_copy = copy_split.parallax();
        assert!(
            !p_copy.orthogonal,
            "a same-vantage pair is a copy, not an orthogonal split"
        );

        // Distinct vantages DO form an orthogonal split (A3 obligation applies).
        let left_obs = observer("left");
        let right_obs = observer("right");
        let real_split = BirefringentSplit::of(
            Wavefront::capture(&left_obs, &sig).unwrap(),
            Wavefront::capture(&right_obs, &sig).unwrap(),
        );
        assert!(
            real_split.parallax().orthogonal,
            "distinct vantages form a genuine orthogonal split"
        );
    }

    // G29 (A3 obligation wiring): the copy-vs-split distinction is load-bearing —
    // an inconsistent *copy* discharges A3 trivially (no obligation), while an
    // inconsistent orthogonal *split* fails to discharge it (a real A3 violation).
    #[test]
    fn a3_obligation_binds_only_to_orthogonal_splits() {
        let left_obs = observer("left");
        let right_obs = observer("right");
        let same_obs = observer("same");

        // Orthogonal split, disagreeing views: A3 obligation NOT discharged.
        let diverging_split = BirefringentSplit::of(
            Wavefront::capture(&left_obs, &surface("GET", 200.0)).unwrap(),
            Wavefront::capture(&right_obs, &surface("POST", 503.0)).unwrap(),
        );
        let p = diverging_split.parallax();
        assert!(p.orthogonal && !p.consistent);
        assert!(
            !p.discharges_a3(),
            "an inconsistent orthogonal split is a real A3 violation"
        );

        // Same-vantage copy (would-be inconsistent): no obligation, discharges.
        let copy_split = BirefringentSplit::of(
            Wavefront::capture(&same_obs, &surface("GET", 200.0)).unwrap(),
            Wavefront::capture(&same_obs, &surface("GET", 200.0)).unwrap(),
        );
        assert!(
            copy_split.parallax().discharges_a3(),
            "a copy carries no parallax obligation"
        );

        // Orthogonal split, agreeing views: obligation discharged.
        let agreeing_split = BirefringentSplit::of(
            Wavefront::capture(&left_obs, &surface("GET", 200.0)).unwrap(),
            Wavefront::capture(&right_obs, &surface("GET", 200.0)).unwrap(),
        );
        assert!(
            agreeing_split.parallax().discharges_a3(),
            "an agreeing orthogonal split discharges A3"
        );
    }
}
