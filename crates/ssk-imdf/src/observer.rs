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

/// A declared region the observer cannot see — a typed *unknown*, never a fact
/// (Vertrag 13.3). The full 5-tuple: which `region` is blind, which
/// `missing_instrument` would be needed to see it, `reason` it is blind, the
/// `impact` of not seeing it, and the `required_aperture` that would resolve it
/// — so the blindspot residue can *drive a remediation*, not just record a gap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blindspot {
    pub region: String,
    pub missing_instrument: String,
    pub reason: String,
    pub impact: String,
    pub required_aperture: String,
}

impl Blindspot {
    /// A minimal, honest blindspot: only the region and reason are known. The
    /// instrument/impact/required-aperture are left unspecified (a known-unknown
    /// with no declared remediation). Prefer [`new_full`](Self::new_full) or the
    /// `with_*` builders when the remediation is known.
    #[must_use]
    pub fn new(region: impl Into<String>, reason: impl Into<String>) -> Self {
        Blindspot {
            region: region.into(),
            missing_instrument: String::new(),
            reason: reason.into(),
            impact: String::new(),
            required_aperture: String::new(),
        }
    }

    /// The complete actionable 5-tuple.
    #[must_use]
    pub fn new_full(
        region: impl Into<String>,
        missing_instrument: impl Into<String>,
        reason: impl Into<String>,
        impact: impl Into<String>,
        required_aperture: impl Into<String>,
    ) -> Self {
        Blindspot {
            region: region.into(),
            missing_instrument: missing_instrument.into(),
            reason: reason.into(),
            impact: impact.into(),
            required_aperture: required_aperture.into(),
        }
    }

    /// Name the instrument whose absence causes the blindspot.
    #[must_use]
    pub fn with_missing_instrument(mut self, instrument: impl Into<String>) -> Self {
        self.missing_instrument = instrument.into();
        self
    }

    /// Declare the consequence of not seeing this region.
    #[must_use]
    pub fn with_impact(mut self, impact: impl Into<String>) -> Self {
        self.impact = impact.into();
        self
    }

    /// Declare the aperture that would resolve the blindspot.
    #[must_use]
    pub fn with_required_aperture(mut self, aperture: impl Into<String>) -> Self {
        self.required_aperture = aperture.into();
        self
    }

    /// Whether every field of the 5-tuple is populated — a fully-actionable
    /// blindspot that names its own remediation.
    #[must_use]
    pub fn is_fully_specified(&self) -> bool {
        !self.region.is_empty()
            && !self.missing_instrument.is_empty()
            && !self.reason.is_empty()
            && !self.impact.is_empty()
            && !self.required_aperture.is_empty()
    }

    /// Lift the blindspot into a conserved residue (A4), attributed to
    /// `observer`. A blindspot that names a `required_aperture` is a standing
    /// remediation obligation (`Open`/`Reacquire`, blocking); one with no known
    /// remediation is an honest accepted known-unknown (`Deferred`/`Accept`).
    /// The `Fragment` is the blind region; the observer id is carried explicitly
    /// in the reason so the residue is attributable.
    #[must_use]
    pub fn to_residue(
        &self,
        observer: ObserverId,
        origin: ssk_types::TraceId,
    ) -> ssk_types::BoundaryResidue {
        let rid = ssk_types::digest_of(
            &(
                "imdf/blindspot/v1",
                observer.0,
                &self.region,
                &self.missing_instrument,
                &self.required_aperture,
            ),
            HashAlg::Blake3,
        )
        .expect("blindspot residue key is serializable")
        .to_hex();
        let (status, next_action, severity) = if self.required_aperture.is_empty() {
            (
                ssk_types::ResidueStatus::Deferred,
                ssk_types::NextAction::Accept,
                ssk_types::Severity::Low,
            )
        } else {
            (
                ssk_types::ResidueStatus::Open,
                ssk_types::NextAction::Reacquire,
                ssk_types::Severity::High,
            )
        };
        ssk_types::BoundaryResidue::new_full(
            ssk_types::ResidueId::new(rid),
            ssk_types::ResidueKind::Focus,
            ssk_types::GateId::Focus,
            Some(self.region.clone()),
            format!(
                "blindspot [{}]: {} (impact: {}; missing instrument: {}; required aperture: {})",
                observer.0.to_hex(),
                if self.reason.is_empty() {
                    "unspecified"
                } else {
                    &self.reason
                },
                if self.impact.is_empty() {
                    "unspecified"
                } else {
                    &self.impact
                },
                if self.missing_instrument.is_empty() {
                    "unspecified"
                } else {
                    &self.missing_instrument
                },
                if self.required_aperture.is_empty() {
                    "none"
                } else {
                    &self.required_aperture
                },
            ),
            severity,
            origin,
            status,
            next_action,
        )
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

    // G26: a fully-specified blindspot exposes all five fields, non-empty.
    #[test]
    fn blindspot_is_the_full_five_tuple() {
        let minimal = Blindspot::new("shape", "sensor unavailable");
        assert!(
            !minimal.is_fully_specified(),
            "a 2-field blindspot is honest but not fully actionable"
        );

        let full = Blindspot::new_full(
            "tls_handshake",
            "tls-inspector",
            "no MITM instrument attached",
            "cannot attest cipher suite",
            "tls-inspecting-aperture",
        );
        assert!(full.is_fully_specified());
        assert!(!full.region.is_empty());
        assert!(!full.missing_instrument.is_empty());
        assert!(!full.reason.is_empty());
        assert!(!full.impact.is_empty());
        assert!(!full.required_aperture.is_empty());

        // The builders reach the same fully-specified state.
        let built = Blindspot::new("tls_handshake", "no MITM instrument attached")
            .with_missing_instrument("tls-inspector")
            .with_impact("cannot attest cipher suite")
            .with_required_aperture("tls-inspecting-aperture");
        assert_eq!(built, full);
    }

    // G27: the blindspot residue is actionable — a named required-aperture makes
    // it a standing Open/Reacquire remediation obligation naming that aperture in
    // its fragment/reason; a blindspot with no known remediation is an honest,
    // non-blocking Deferred/Accept known-unknown.
    #[test]
    fn blindspot_residue_drives_required_aperture_remediation() {
        let obs = observer(
            Aperture::admitting("wide", ["shape"]),
            vec![],
            &authorized(),
        )
        .unwrap();
        let origin = ssk_types::TraceId::new("t");

        let actionable = Blindspot::new_full(
            "tls_handshake",
            "tls-inspector",
            "no MITM instrument",
            "cannot attest cipher suite",
            "tls-inspecting-aperture",
        );
        let r = actionable.to_residue(obs.id, origin.clone());
        assert_eq!(r.kind, ssk_types::ResidueKind::Focus);
        assert_eq!(r.fragment.as_deref(), Some("tls_handshake"));
        assert_eq!(r.status, ssk_types::ResidueStatus::Open);
        assert_eq!(r.next_action, ssk_types::NextAction::Reacquire);
        assert!(r.open_obligation(), "a remediable blindspot blocks");
        assert!(
            r.detail.contains("tls-inspecting-aperture"),
            "the residue names the required aperture that resolves it"
        );
        assert!(
            r.detail.contains(&obs.id.0.to_hex()),
            "the residue carries the observer id explicitly"
        );

        // No known remediation → honest, non-blocking.
        let honest = Blindspot::new("dark_region", "no instrument exists");
        let hr = honest.to_residue(obs.id, origin);
        assert_eq!(hr.status, ssk_types::ResidueStatus::Deferred);
        assert_eq!(hr.next_action, ssk_types::NextAction::Accept);
        assert!(!hr.open_obligation());
    }
}
