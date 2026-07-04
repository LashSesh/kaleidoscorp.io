//! Reanalysis — Chameleon `reanalysis`.
//!
//! Checks that a transform kept the surface analyzable: the declared protocol
//! class is unchanged and the source→transformed signature drift stays within
//! bound. Yields Pass/Optimize, never a hard verdict — a drift is a signal to
//! improve, not a failure.

use crate::canonical::CanonicalObject;
use crate::signature::{Decision, SpectralSignature};

/// The outcome of reanalyzing a transform.
#[derive(Clone, Debug, PartialEq)]
pub struct ReanalysisResult {
    pub decision: Decision,
    pub same_protocol_class: bool,
    pub signature_stable: bool,
    pub notes: Vec<String>,
}

/// Reanalyze a transform (Chameleon `reanalyze`), defaulting the drift bound to
/// 0.50 as the kernel does.
#[must_use]
pub fn reanalyze(
    source: &CanonicalObject,
    transformed: &CanonicalObject,
    source_signature: &SpectralSignature,
    transformed_signature: &SpectralSignature,
    max_signature_drift: f64,
) -> ReanalysisResult {
    let same_class = source.declared_protocol_class == transformed.declared_protocol_class;
    let drift = source_signature.global_distance(transformed_signature);
    let stable = drift <= max_signature_drift;

    let mut notes = vec![format!("signature_drift={drift}")];
    if !same_class {
        notes.push("protocol_class_changed".to_owned());
    }
    if !stable {
        notes.push("signature_drift_exceeds_limit".to_owned());
    }

    let decision = if same_class && stable {
        Decision::Pass
    } else {
        Decision::Optimize
    };

    ReanalysisResult {
        decision,
        same_protocol_class: same_class,
        signature_stable: stable,
        notes,
    }
}

/// The Chameleon default drift bound.
pub const DEFAULT_MAX_SIGNATURE_DRIFT: f64 = 0.50;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonicalize;
    use crate::object::SurfaceObject;
    use crate::signature_for;
    use crate::value::{OrderedMap, Value};

    fn obj(method: &str, class: &str) -> SurfaceObject {
        let fields = OrderedMap::from_iter([("method".to_owned(), Value::Text(method.to_owned()))]);
        SurfaceObject::new("application/trace+json", fields).with_declared_protocol_class(class)
    }

    #[test]
    fn stable_same_class_passes() {
        let o = obj("GET", "http");
        let c = canonicalize(&o);
        let s = signature_for(&o);
        let r = reanalyze(&c, &c, &s, &s, DEFAULT_MAX_SIGNATURE_DRIFT);
        assert_eq!(r.decision, Decision::Pass);
        assert!(r.same_protocol_class && r.signature_stable);
    }

    #[test]
    fn protocol_class_change_optimizes() {
        let a = obj("GET", "http");
        let b = obj("GET", "grpc");
        let (ca, cb) = (canonicalize(&a), canonicalize(&b));
        let (sa, sb) = (signature_for(&a), signature_for(&b));
        let r = reanalyze(&ca, &cb, &sa, &sb, DEFAULT_MAX_SIGNATURE_DRIFT);
        assert_eq!(r.decision, Decision::Optimize);
        assert!(!r.same_protocol_class);
        assert!(r.notes.iter().any(|n| n == "protocol_class_changed"));
    }
}
