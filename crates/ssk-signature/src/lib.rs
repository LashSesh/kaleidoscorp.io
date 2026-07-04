#![forbid(unsafe_code)]

//! # ssk-signature — the spectral / signature substrate
//!
//! A faithful Rust port of the **Chameleon Signature Kernel** ("AlignAlign",
//! v0.5), the seed artifact of the SSK architecture. This crate answers the
//! kernel's founding question — *how does a signature behave under
//! transformation and target-profile comparison?* — and provides the
//! payload-neutral **spectrum-as-identity** the rest of the system was missing:
//!
//! * [`SurfaceObject`] — a payload/protocol/log/trace as an abstract surface.
//! * [`canonicalize`] — deterministic normalization + content addressing,
//!   flush with `ssk_types::Digest` / `digest_of`.
//! * [`extract_features`] / [`FeatureVector`] — the six base dimensions plus
//!   five protocol-fingerprint layers.
//! * [`SpectralSignature`] — the multi-dimensional spectrum, a per-dimension +
//!   global distance metric, and a tolerance-gated Pass/Optimize comparison
//!   that never collapses to a single score.
//!
//! ## Architectural role
//!
//! This is Tranche 1 of the port (surface → spectrum). It is the substrate the
//! IMDF Mirror-Dome (`ssk-imdf` SignatureLab / SelfPerceptionAtlas) sits on, the
//! payload-neutral surface the SSCL `CanonicalTrafficSurface` feeds, and an
//! input to the FCHL-MPK field layer. Later tranches add the residue/gate,
//! replay/reanalysis, target-profile/calibration, recursive iterator, profile
//! corpus, and controlled-adapter layers, mapping the Chameleon gate/residue/
//! replay onto the existing SSK `GateVector` / `ResidueRegister` /
//! `DeterministicReplayEngine`.
//!
//! See `CHAMELEON_KERNEL_INTEGRATION_ASSESSMENT.md` for the full crosswalk and
//! the digest-parity rationale (the kernel's own tests assert decisions,
//! distances, and feature values — never digest hex — so the identity is taken
//! through the SSK content-address path rather than reproducing Python's
//! `sha256(json.dumps(...))` byte-for-byte).

pub mod canonical;
pub mod features;
pub mod fingerprints;
pub mod gate;
pub mod object;
pub mod operators;
pub mod policy;
pub mod residue;
pub mod signature;
pub mod target;
pub mod url;
pub mod value;

pub use canonical::{canonicalize, CanonicalObject};
pub use features::{extract_features, FeatureVector};
pub use fingerprints::{
    compare_fingerprint_bundles, extract_fingerprint_bundle, fingerprint_layer_names,
    fingerprint_layer_specs, FingerprintBundle, FingerprintBundleComparison, FingerprintCoverage,
    FingerprintLayerSpec, ProtocolFingerprint,
};
pub use gate::{GateBundle, GateDecision, GateVector};
pub use object::SurfaceObject;
pub use operators::{
    BucketTimingOperator, NormalizeTraceShapeOperator, RedactIdentifierFieldsOperator,
    SortFieldsOperator, TransformOperator, TransformResult,
};
pub use policy::{AuthorizationManifest, ChameleonPolicy, PolicyDecision, PolicyOutcome};
pub use residue::{surface_to_kind, Residue, ResidueDisposition, ResidueReport, ResidueSeverity};
pub use signature::{
    Decision, SignatureComparisonReport, SignatureDimensionDelta, SpectralSignature,
};
pub use target::{OperationalMask, TargetProfile};
pub use url::{urlparse, ParsedUrl};
pub use value::{
    bucket, categorical_equal, round6, shannon_entropy, Dimension, Dimensions, FeatureValue,
    OrderedMap, Value,
};

/// Compute a surface's spectral signature: canonicalize → extract features →
/// build the spectrum. Mirrors Chameleon `ChameleonKernel.signature_for`.
#[must_use]
pub fn signature_for(obj: &SurfaceObject) -> SpectralSignature {
    let canonical = canonicalize(obj);
    let features = extract_features(&canonical, obj);
    SpectralSignature::from_features(&features)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    // Build an HTTP-observation-shaped surface like the Chameleon phase tests.
    fn http_surface() -> SurfaceObject {
        let headers = OrderedMap::from_iter([
            (
                "Content-Type".to_owned(),
                Value::Text("application/json".to_owned()),
            ),
            ("Set-Cookie".to_owned(), Value::Text("sid=abc".to_owned())),
        ]);
        let request_headers = OrderedMap::from_iter([
            (
                "Authorization".to_owned(),
                Value::Text("Bearer x".to_owned()),
            ),
            (
                "X-Forwarded-For".to_owned(),
                Value::Text("203.0.113.7".to_owned()),
            ),
        ]);
        let body = {
            let mut m = OrderedMap::new();
            m.insert("user", Value::Text("alice".to_owned()));
            m.insert("count", Value::Num(3.0));
            Value::Object(m)
        };
        let fields = OrderedMap::from_iter([
            ("method".to_owned(), Value::Text("get".to_owned())),
            (
                "url".to_owned(),
                Value::Text("https://api.example.com/v1/users?limit=10".to_owned()),
            ),
            ("status".to_owned(), Value::Num(200.0)),
            ("headers".to_owned(), Value::Object(headers)),
            ("request_headers".to_owned(), Value::Object(request_headers)),
            (
                "response_header_order".to_owned(),
                Value::Array(vec![
                    Value::Text("content-type".to_owned()),
                    Value::Text("set-cookie".to_owned()),
                ]),
            ),
            (
                "request_header_order".to_owned(),
                Value::Array(vec![
                    Value::Text("authorization".to_owned()),
                    Value::Text("x-forwarded-for".to_owned()),
                ]),
            ),
            ("body".to_owned(), body),
            ("duration_ms".to_owned(), Value::Num(42.0)),
        ]);
        SurfaceObject::new("application/network-observation+http", fields)
            .with_declared_protocol_class("http")
    }

    // Chameleon test_phase3_kernel: linkability dimension detects sensitive fields.
    #[test]
    fn linkability_dimension_flags_sensitive_surface() {
        let sig = signature_for(&http_surface());
        let link = &sig.dimensions["linkability"];
        assert_eq!(link["has_authorization"], FeatureValue::Num(1.0));
        assert_eq!(link["has_ip_surface"], FeatureValue::Num(1.0));
        match &link["sensitive_field_count"] {
            FeatureValue::Num(n) => assert!(*n >= 2.0, "sensitive_field_count = {n}"),
            other => panic!("expected number, got {other:?}"),
        }
    }

    // Chameleon test_phase8_fingerprints: http_surface status_class + content type.
    #[test]
    fn http_surface_fingerprint_values() {
        let sig = signature_for(&http_surface());
        assert_eq!(
            sig.dimensions["http_surface"]["status_class"],
            FeatureValue::Num(2.0)
        );
        assert_eq!(
            sig.dimensions["http_surface"]["content_type_family"],
            FeatureValue::Text("application/json".to_owned())
        );
        assert_eq!(
            sig.dimensions["body_schema"]["schema_kind"],
            FeatureValue::Text("object".to_owned())
        );
        assert_eq!(
            sig.dimensions["linkability_surface"]["has_cookie_surface"],
            FeatureValue::Num(1.0)
        );
    }

    // Chameleon test_phase9_signature_architecture: coverage + comparison.
    #[test]
    fn fingerprint_coverage_and_specs() {
        let bundle = extract_fingerprint_bundle(&http_surface());
        let coverage = bundle.coverage();
        assert_eq!(coverage.layer_count, 5);
        assert!(coverage.missing_layers.is_empty());
        assert_eq!(fingerprint_layer_specs()[0].name, "http_surface");
    }

    #[test]
    fn identical_surfaces_have_equal_signatures() {
        let a = signature_for(&http_surface());
        let b = signature_for(&http_surface());
        assert_eq!(a.digest, b.digest);
        assert_eq!(a.global_distance(&b), 0.0);
    }

    #[test]
    fn different_surfaces_diverge_and_report_optimize() {
        let base = http_surface();
        let sig_a = signature_for(&base);

        // A materially different surface: different method, status, no body.
        let fields = OrderedMap::from_iter([
            ("method".to_owned(), Value::Text("post".to_owned())),
            (
                "url".to_owned(),
                Value::Text("https://other.example.org/a/b/c?x=1&y=2".to_owned()),
            ),
            ("status".to_owned(), Value::Num(503.0)),
        ]);
        let other = SurfaceObject::new("application/network-observation+http", fields)
            .with_declared_protocol_class("http");
        let sig_b = signature_for(&other);

        assert!(sig_a.global_distance(&sig_b) > 0.0);
        let tolerances: BTreeMap<String, f64> = BTreeMap::new();
        let report = sig_a.compare(&sig_b, &tolerances, 0.05, 5);
        assert_eq!(report.decision, Decision::Optimize);
        assert!(!report.top_dimensions.is_empty());
        // http_surface must be among the drifted dimensions (method/status changed).
        assert!(report
            .dimension_deltas
            .iter()
            .any(|d| d.dimension == "http_surface"));
    }

    #[test]
    fn changed_bundle_reports_changed_layers() {
        let left = extract_fingerprint_bundle(&http_surface());
        let fields = OrderedMap::from_iter([
            ("method".to_owned(), Value::Text("delete".to_owned())),
            (
                "url".to_owned(),
                Value::Text("https://api.example.com/v1/users?limit=10".to_owned()),
            ),
            ("status".to_owned(), Value::Num(404.0)),
        ]);
        let right = extract_fingerprint_bundle(
            &SurfaceObject::new("application/network-observation+http", fields)
                .with_declared_protocol_class("http"),
        );
        let comparison = compare_fingerprint_bundles(&left, &right);
        assert!(comparison
            .changed_layers
            .iter()
            .any(|l| l == "http_surface"));
    }
}
