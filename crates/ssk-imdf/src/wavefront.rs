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
}
