//! `ObserverModel` (IMDF 5.1) — an authorized self-perspective.
//!
//! An observer is `(id, scope, vantage, aperture, lens, blindspots, trust,
//! replay)`. It can only be constructed with an [`AuthorizationManifest`] valid
//! for self-observation — an unauthorized observer is impossible to build. Focus
//! is reachable only through [`ObserverModel::open_aperture`], which fails if the
//! aperture is closed, enforcing Focus ⇒ ∃A.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use ssk_signature::AuthorizationManifest;
use ssk_types::{content_id, HashAlg, ReplayRoot};

use crate::aperture::{Aperture, ApertureSession};
use crate::error::ImdfError;

content_id!(ObserverId);

/// The IMDF authorization use an observer requires.
pub const SELF_OBSERVATION_USE: &str = "self_observation";

/// The perspective point an observer measures from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vantage {
    pub label: String,
}

impl Vantage {
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Vantage {
            label: label.into(),
        }
    }
}

/// The projection an observer applies — which dimensions it emphasizes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lens {
    pub label: String,
    pub emphasis: BTreeSet<String>,
}

impl Lens {
    #[must_use]
    pub fn new<I: IntoIterator<Item = S>, S: Into<String>>(
        label: impl Into<String>,
        emphasis: I,
    ) -> Self {
        Lens {
            label: label.into(),
            emphasis: emphasis.into_iter().map(Into::into).collect(),
        }
    }
}

/// A declared region the observer cannot see — a typed *unknown*, never a fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blindspot {
    pub region: String,
    pub reason: String,
}

impl Blindspot {
    #[must_use]
    pub fn new(region: impl Into<String>, reason: impl Into<String>) -> Self {
        Blindspot {
            region: region.into(),
            reason: reason.into(),
        }
    }
}

/// How far an observation has been corroborated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    Untrusted,
    Observed,
    Corroborated,
}

/// An authorized self-perspective. Not serialized whole — the atlas records its
/// content id ([`ObserverId`]); the live aperture stays in memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObserverModel {
    pub id: ObserverId,
    pub scope: String,
    pub vantage: Vantage,
    pub aperture_label: String,
    pub lens: Lens,
    pub blindspots: Vec<Blindspot>,
    pub trust: TrustLevel,
    pub replay_root: ReplayRoot,
    aperture: Aperture,
}

#[derive(Serialize)]
struct ObserverForm<'a> {
    domain: &'a str,
    scope: &'a str,
    vantage: &'a Vantage,
    aperture_label: &'a str,
    lens: &'a Lens,
    blindspots: &'a [Blindspot],
}

impl ObserverModel {
    /// Construct an authorized observer.
    ///
    /// # Errors
    /// [`ImdfError::Unauthorized`] if the manifest is not valid for
    /// self-observation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: impl Into<String>,
        vantage: Vantage,
        aperture: Aperture,
        lens: Lens,
        blindspots: Vec<Blindspot>,
        trust: TrustLevel,
        replay_root: ReplayRoot,
        authorization: &AuthorizationManifest,
    ) -> Result<Self, ImdfError> {
        if !authorization.is_valid_for(SELF_OBSERVATION_USE) {
            return Err(ImdfError::Unauthorized);
        }
        let scope = scope.into();
        let id = ObserverId::of(
            &ObserverForm {
                domain: "imdf/observer/v1",
                scope: &scope,
                vantage: &vantage,
                aperture_label: &aperture.label,
                lens: &lens,
                blindspots: &blindspots,
            },
            HashAlg::Blake3,
        )
        .expect("observer form is serializable");
        Ok(ObserverModel {
            id,
            scope,
            vantage,
            aperture_label: aperture.label.clone(),
            lens,
            blindspots,
            trust,
            replay_root,
            aperture,
        })
    }

    /// Open the observer's aperture, returning a session through which focus is
    /// reachable. Enforces Focus ⇒ ∃A.
    ///
    /// # Errors
    /// [`ImdfError::ApertureRequired`] if the aperture is closed.
    pub fn open_aperture(&self) -> Result<ApertureSession<'_>, ImdfError> {
        if !self.aperture.is_open() {
            return Err(ImdfError::ApertureRequired);
        }
        Ok(ApertureSession {
            aperture: &self.aperture,
            blindspot_regions: self.blindspots.iter().map(|b| b.region.clone()).collect(),
        })
    }

    /// The observer's aperture (read-only).
    #[must_use]
    pub fn aperture(&self) -> &Aperture {
        &self.aperture
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_signature::{signature_for, OrderedMap, SurfaceObject, Value};

    fn authorized() -> AuthorizationManifest {
        AuthorizationManifest::new("owned-dome", "me", "self-owned")
            .with_allowed_uses([SELF_OBSERVATION_USE])
    }

    fn observer(
        aperture: Aperture,
        blindspots: Vec<Blindspot>,
        auth: &AuthorizationManifest,
    ) -> Result<ObserverModel, ImdfError> {
        ObserverModel::new(
            "host-a",
            Vantage::new("local"),
            aperture,
            Lens::new("shape-lens", ["shape"]),
            blindspots,
            TrustLevel::Observed,
            ReplayRoot::new("rr-1"),
            auth,
        )
    }

    fn sample_signature() -> ssk_signature::SpectralSignature {
        let fields = OrderedMap::from_iter([
            ("method".to_owned(), Value::Text("GET".to_owned())),
            ("status".to_owned(), Value::Num(200.0)),
        ]);
        signature_for(
            &SurfaceObject::new("application/trace+json", fields)
                .with_declared_protocol_class("http"),
        )
    }

    // IMDF Appendix A: observer_without_authorization_fails.
    #[test]
    fn observer_without_authorization_fails() {
        let bad = AuthorizationManifest::new("", "", "").with_allowed_uses(Vec::<String>::new());
        assert_eq!(
            observer(Aperture::admitting("a", ["shape"]), vec![], &bad).unwrap_err(),
            ImdfError::Unauthorized
        );
        // A manifest lacking the self-observation use also fails.
        let wrong = AuthorizationManifest::new("owned", "me", "self")
            .with_allowed_uses(["offline_analysis"]);
        assert_eq!(
            observer(Aperture::admitting("a", ["shape"]), vec![], &wrong).unwrap_err(),
            ImdfError::Unauthorized
        );
        // A valid manifest succeeds.
        assert!(observer(Aperture::admitting("a", ["shape"]), vec![], &authorized()).is_ok());
    }

    // IMDF Appendix A: aperture_before_focus_required.
    #[test]
    fn aperture_before_focus_required() {
        let auth = authorized();
        let closed = observer(Aperture::closed("closed"), vec![], &auth).unwrap();
        assert_eq!(
            closed.open_aperture().unwrap_err(),
            ImdfError::ApertureRequired
        );
        // An open aperture yields a session (through which focus is reachable).
        let open = observer(Aperture::admitting("open", ["shape"]), vec![], &auth).unwrap();
        assert!(open.open_aperture().is_ok());
    }

    // IMDF Appendix A: hidden_surface_becomes_residue.
    #[test]
    fn hidden_surface_becomes_residue() {
        let auth = authorized();
        // Aperture admits only "shape"; the signature carries many more dims.
        let obs = observer(Aperture::admitting("narrow", ["shape"]), vec![], &auth).unwrap();
        let result = obs.open_aperture().unwrap().focus(&sample_signature());
        assert!(
            !result.hidden_dimensions.is_empty(),
            "other dimensions must become residues"
        );
        assert!(!result.residues.by_surface("focus").is_empty());
        // The admitted dimension is measured.
        assert!(result
            .readings
            .get("shape")
            .unwrap()
            .as_measured_digest()
            .is_some());
    }

    // IMDF Appendix A: blindspot_is_not_reported_as_fact.
    #[test]
    fn blindspot_is_not_reported_as_fact() {
        let auth = authorized();
        // "shape" is admitted but declared a blindspot.
        let obs = observer(
            Aperture::admitting("wide", ["shape", "ordering", "semantic"]),
            vec![Blindspot::new("shape", "sensor unavailable")],
            &auth,
        )
        .unwrap();
        let result = obs.open_aperture().unwrap().focus(&sample_signature());
        let reading = result
            .readings
            .get("shape")
            .expect("shape is in the aperture");
        assert!(reading.is_blind(), "a blindspot must not be measured");
        assert!(
            reading.as_measured_digest().is_none(),
            "a blindspot yields no value"
        );
        assert!(result.blindspot_dimensions.contains(&"shape".to_owned()));
    }
}
