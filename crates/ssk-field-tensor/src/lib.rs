#![forbid(unsafe_code)]

//! # ssk-field-tensor — the FieldTensorSkin (FTCSA, FCHL-MPK Band B)
//!
//! An **observation surface** that couples captured traffic spectra to discrete
//! symmetry windows. The full surface is
//!
//! ```text
//! F = T_surface + T_res + C_coupling + δF
//! ```
//!
//! * `T_surface` — the spectra of the captured [`CanonicalTrafficSurface`]s
//!   (`ssk-capture` → `ssk-signature`).
//! * `T_res` — the residue tensor (what was not integrated; no silent loss).
//! * `C_coupling` — the coupling to discrete MPK windows (`ssk-mpk` samples).
//! * `δF` — the field-delta signals: drift, anomaly, linkability impulse, route
//!   change, service fault, OS event.
//!
//! **Honesty type (the one retained constraint, the author's own labeling rule,
//! FTCSA Nicht-Ziel 8):** the [`ObjCard`] declares this a *bookkeeping /
//! observation* surface. It is never asserted as a literal physical field, and a
//! [`FieldProjection`] is always over *discrete windows only*. That is an
//! auditability guarantee, not a capability limit.

use serde::{Deserialize, Serialize};
use ssk_capture::SystemTrafficField;
use ssk_mpk::{Graph, MpkFieldSample};
use ssk_signature::{round6, FeatureValue, Residue, ResidueSeverity, SpectralSignature};
use ssk_types::{digest_of, Digest, HashAlg};

/// The object card: an honest declaration of what this surface *is*. Its
/// `asserts_physics` is always `false` — the FieldTensorSkin is bookkeeping.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjCard {
    pub kind: String,
    pub role: String,
    pub asserts_physics: bool,
    pub note: String,
}

impl ObjCard {
    /// The one and only object card for a FieldTensorSkin. Cannot be constructed
    /// asserting physics.
    #[must_use]
    pub fn field_tensor_skin() -> Self {
        ObjCard {
            kind: "field_tensor_skin".to_owned(),
            role: "observation_surface".to_owned(),
            asserts_physics: false,
            note: "Bookkeeping surface over discrete windows; not a literal physical field."
                .to_owned(),
        }
    }
}

/// The δF signal vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeltaSignalKind {
    Drift,
    Anomaly,
    LinkabilityImpulse,
    RouteChange,
    ServiceFault,
    OsEvent,
}

impl DeltaSignalKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DeltaSignalKind::Drift => "drift",
            DeltaSignalKind::Anomaly => "anomaly",
            DeltaSignalKind::LinkabilityImpulse => "linkability_impulse",
            DeltaSignalKind::RouteChange => "route_change",
            DeltaSignalKind::ServiceFault => "service_fault",
            DeltaSignalKind::OsEvent => "os_event",
        }
    }
}

/// One δF signal.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeltaSignal {
    pub kind: DeltaSignalKind,
    pub magnitude: f64,
    pub detail: String,
    /// Which window index (into `T_surface`) the signal is about.
    pub window: usize,
}

/// A projection of the field onto discrete windows. It is always discrete —
/// there is no continuous / physical projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldProjection {
    pub is_discrete: bool,
    pub window_count: usize,
    pub sample_ids: Vec<Digest>,
}

/// The FieldTensorSkin surface `F = T_surface + T_res + C_coupling + δF`.
#[derive(Clone, Debug, PartialEq)]
pub struct FieldTensorSkin {
    /// `T_surface`: the spectra of the captured surfaces.
    pub surface_tensor: Vec<SpectralSignature>,
    /// `T_res`: residues (no silent loss).
    pub residue_tensor: Vec<Residue>,
    /// `C_coupling`: coupling to discrete MPK windows.
    pub coupling: Vec<MpkFieldSample>,
    /// `δF`: field-delta signals.
    pub delta: Vec<DeltaSignal>,
}

fn has_authorization(sig: &SpectralSignature) -> bool {
    sig.dimensions
        .get("linkability")
        .and_then(|d| d.get("has_authorization"))
        == Some(&FeatureValue::Num(1.0))
}

impl FieldTensorSkin {
    /// The object card. Every FieldTensorSkin is an observation surface.
    #[must_use]
    pub fn obj_card() -> ObjCard {
        ObjCard::field_tensor_skin()
    }

    /// Assemble a FieldTensorSkin from a captured traffic field coupled to a set
    /// of discrete symmetry windows. Automatically derives the drift and
    /// linkability-impulse δF signals and the linkability residues; further δF
    /// signals (route change, service fault, OS event, anomaly) are added with
    /// [`FieldTensorSkin::with_signal`].
    #[must_use]
    pub fn from_field(traffic: &SystemTrafficField, windows: &[Graph]) -> Self {
        let surface_tensor = traffic.signatures();
        let coupling: Vec<MpkFieldSample> = windows.iter().map(MpkFieldSample::of).collect();

        let mut residue_tensor = Vec::new();
        let mut delta = Vec::new();

        for (index, sig) in surface_tensor.iter().enumerate() {
            // T_res: a captured surface carrying a sensitive header is a
            // linkability residue — recorded, never dropped silently.
            if has_authorization(sig) {
                residue_tensor.push(Residue {
                    surface: "linkability".to_owned(),
                    severity: ResidueSeverity::Medium,
                    message: format!("authorization surface present at window {index}"),
                });
            }
            // δF drift: distance from the previous window's spectrum.
            if index > 0 {
                let drift = round6(surface_tensor[index - 1].global_distance(sig));
                if drift > 0.0 {
                    delta.push(DeltaSignal {
                        kind: DeltaSignalKind::Drift,
                        magnitude: drift,
                        detail: format!("spectral drift from window {}", index - 1),
                        window: index,
                    });
                }
                // δF linkability impulse: authorization appearing where it was absent.
                if has_authorization(sig) && !has_authorization(&surface_tensor[index - 1]) {
                    delta.push(DeltaSignal {
                        kind: DeltaSignalKind::LinkabilityImpulse,
                        magnitude: 1.0,
                        detail: "authorization surface appeared".to_owned(),
                        window: index,
                    });
                }
            }
        }

        FieldTensorSkin {
            surface_tensor,
            residue_tensor,
            coupling,
            delta,
        }
    }

    /// Inject an externally-observed δF signal (route change, service fault, OS
    /// event, anomaly).
    #[must_use]
    pub fn with_signal(
        mut self,
        kind: DeltaSignalKind,
        magnitude: f64,
        detail: impl Into<String>,
        window: usize,
    ) -> Self {
        self.delta.push(DeltaSignal {
            kind,
            magnitude,
            detail: detail.into(),
            window,
        });
        self
    }

    /// Project the field onto its discrete windows. Always discrete — never a
    /// continuous / physical claim.
    #[must_use]
    pub fn project(&self) -> FieldProjection {
        FieldProjection {
            is_discrete: true,
            window_count: self.coupling.len(),
            sample_ids: self.coupling.iter().map(|s| s.id.0).collect(),
        }
    }

    /// All δF signals of a given kind.
    #[must_use]
    pub fn signals(&self, kind: DeltaSignalKind) -> Vec<&DeltaSignal> {
        self.delta.iter().filter(|s| s.kind == kind).collect()
    }

    /// A content-addressed digest of the whole surface (replay-stable).
    #[must_use]
    pub fn digest(&self) -> Digest {
        #[derive(Serialize)]
        struct Form {
            surfaces: Vec<String>,
            residues: Vec<String>,
            coupling: Vec<String>,
            delta: Vec<(String, String, u64, usize)>,
        }
        let form = Form {
            surfaces: self
                .surface_tensor
                .iter()
                .map(|s| s.digest.to_hex())
                .collect(),
            residues: self
                .residue_tensor
                .iter()
                .map(|r| format!("{}:{}:{}", r.surface, r.severity.as_str(), r.message))
                .collect(),
            coupling: self.coupling.iter().map(|s| s.id.0.to_hex()).collect(),
            delta: self
                .delta
                .iter()
                .map(|d| {
                    (
                        d.kind.as_str().to_owned(),
                        d.detail.clone(),
                        d.magnitude.to_bits(),
                        d.window,
                    )
                })
                .collect(),
        };
        digest_of(&form, HashAlg::Blake3).expect("field tensor form is serializable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_capture::{CaptureMode, CaptureScope, TrafficSource, TrafficWindow};

    // A source that yields a clean window, then one that carries an Authorization
    // header (a linkability impulse), so the field has real drift + impulse.
    struct DriftingSource;
    impl TrafficSource for DriftingSource {
        fn source_id(&self) -> String {
            "tap".to_owned()
        }
        fn windows(&self, _scope: &CaptureScope) -> Vec<TrafficWindow> {
            let mut clean = TrafficWindow::http("http");
            clean.method = Some("GET".to_owned());
            clean.url = Some("https://example.local/a".to_owned());
            clean.status = Some(200);
            clean.response_headers =
                vec![("Content-Type".to_owned(), "application/json".to_owned())];
            clean.payload = b"{}".to_vec();

            let mut sensitive = TrafficWindow::http("http");
            sensitive.method = Some("POST".to_owned());
            sensitive.url = Some("https://example.local/login".to_owned());
            sensitive.status = Some(401);
            sensitive.request_headers =
                vec![("Authorization".to_owned(), "Bearer secret".to_owned())];
            sensitive.response_headers =
                vec![("Content-Type".to_owned(), "application/json".to_owned())];
            sensitive.payload = b"{\"user\":\"x\"}".to_vec();

            vec![clean, sensitive]
        }
    }

    fn field() -> SystemTrafficField {
        SystemTrafficField::capture(
            &DriftingSource,
            &CaptureScope::new("local", ["lo0"]),
            CaptureMode::PassiveLocal,
        )
    }

    fn windows() -> Vec<Graph> {
        vec![
            Graph::from_edges(3, &[(0, 1), (1, 2)]).unwrap(),
            Graph::from_edges(4, &[(0, 1), (1, 2), (2, 3), (3, 0)]).unwrap(),
        ]
    }

    #[test]
    fn obj_card_never_asserts_physics() {
        let card = FieldTensorSkin::obj_card();
        assert!(
            !card.asserts_physics,
            "a FieldTensorSkin is an observation surface, not physics"
        );
        assert_eq!(card.role, "observation_surface");
    }

    #[test]
    fn assembles_all_four_components() {
        let skin = FieldTensorSkin::from_field(&field(), &windows());
        // T_surface: one spectrum per captured window.
        assert_eq!(skin.surface_tensor.len(), 2);
        // C_coupling: one MPK sample per discrete window.
        assert_eq!(skin.coupling.len(), 2);
        // T_res: the sensitive window produced a linkability residue (no silent loss).
        assert!(!skin.residue_tensor.is_empty());
        assert_eq!(skin.residue_tensor[0].surface, "linkability");
        // δF: real drift between the two windows, plus a linkability impulse.
        assert!(!skin.signals(DeltaSignalKind::Drift).is_empty());
        assert_eq!(skin.signals(DeltaSignalKind::LinkabilityImpulse).len(), 1);
    }

    #[test]
    fn projection_is_discrete_only() {
        let skin = FieldTensorSkin::from_field(&field(), &windows());
        let projection = skin.project();
        assert!(
            projection.is_discrete,
            "a field projection is always over discrete windows"
        );
        assert_eq!(projection.window_count, 2);
        assert_eq!(projection.sample_ids.len(), 2);
    }

    #[test]
    fn external_signals_and_digest_are_stable() {
        let a = FieldTensorSkin::from_field(&field(), &windows()).with_signal(
            DeltaSignalKind::RouteChange,
            1.0,
            "default route changed",
            1,
        );
        let b = FieldTensorSkin::from_field(&field(), &windows()).with_signal(
            DeltaSignalKind::RouteChange,
            1.0,
            "default route changed",
            1,
        );
        assert_eq!(a.signals(DeltaSignalKind::RouteChange).len(), 1);
        assert_eq!(
            a.digest(),
            b.digest(),
            "same inputs -> same field digest (replay)"
        );
    }
}
