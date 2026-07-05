//! Replay commitment + effectiveness feedback — Chameleon `replay`.
//!
//! A [`ReplayManifest`] is a compact commitment (all input/output digests +
//! the operator name + kernel version) whose own digest identifies the
//! transformation. [`ReplayFeedback`] scores how much the transform moved the
//! signature toward the target. The manifest is the same "commit every input"
//! discipline the SSK `DeterministicReplayEngine` enforces; a later tranche
//! feeds these manifests into that engine for full re-execution equality.

use serde::Serialize;
use ssk_types::{digest_of, HashAlg};

use crate::canonical::CanonicalObject;
use crate::signature::{Decision, SpectralSignature};
use crate::value::round6;

/// The single authoritative kernel version string (the Chameleon package
/// carried three; the port unifies them here — see the integration assessment).
pub const KERNEL_VERSION: &str = "0.8.0";

/// A compact, hashable commitment to one transformation.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReplayManifest {
    pub source_digest: String,
    pub transformed_digest: String,
    pub transformed_signature_digest: String,
    pub operator_name: String,
    pub kernel_version: String,
}

impl ReplayManifest {
    /// Content digest of the manifest itself (Chameleon `ReplayManifest.digest`).
    #[must_use]
    pub fn digest(&self) -> String {
        digest_of(self, HashAlg::Blake3)
            .expect("manifest is serializable")
            .to_hex()
    }
}

/// Build the replay manifest for a transformation.
#[must_use]
pub fn build_replay_manifest(
    source: &CanonicalObject,
    transformed: &CanonicalObject,
    transformed_signature: &SpectralSignature,
    operator_name: &str,
) -> ReplayManifest {
    ReplayManifest {
        source_digest: source.digest.to_hex(),
        transformed_digest: transformed.digest.to_hex(),
        transformed_signature_digest: transformed_signature.digest.to_hex(),
        operator_name: operator_name.to_owned(),
        kernel_version: KERNEL_VERSION.to_owned(),
    }
}

/// How effectively a transform moved the signature toward the target.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplayFeedback {
    pub replay_digest: String,
    pub target_signature_digest: String,
    pub effectiveness_score: f64,
    pub source_distance: f64,
    pub transformed_distance: f64,
    pub optimized_dimensions: Vec<String>,
    pub decision: Decision,
    pub notes: Vec<String>,
}

/// Build replay feedback for a transformation (Chameleon `build_replay_feedback`).
#[must_use]
pub fn build_replay_feedback(
    replay_manifest: &ReplayManifest,
    source_signature: &SpectralSignature,
    transformed_signature: &SpectralSignature,
    target_signature: &SpectralSignature,
) -> ReplayFeedback {
    let source_distance = source_signature.global_distance(target_signature);
    let transformed_distance = transformed_signature.global_distance(target_signature);

    let score = if source_distance == 0.0 && transformed_distance == 0.0 {
        1.0
    } else if source_distance == 0.0 {
        0.0
    } else {
        ((source_distance - transformed_distance) / source_distance).clamp(0.0, 1.0)
    };

    let source_dims = source_signature.distance_by_dimension(target_signature);
    let transformed_dims = transformed_signature.distance_by_dimension(target_signature);
    let mut optimized: Vec<String> = transformed_dims
        .iter()
        .filter(|(dim, &t)| t < *source_dims.get(*dim).unwrap_or(&t))
        .map(|(dim, _)| dim.clone())
        .collect();
    optimized.sort();

    let mut notes = vec![format!(
        "distance_delta={}",
        round6(source_distance - transformed_distance)
    )];
    if optimized.is_empty() && transformed_distance > source_distance {
        notes.push("transform_regressed_distance".to_owned());
    } else if !optimized.is_empty() {
        notes.push("transform_improved_dimensions".to_owned());
    }

    let decision = if transformed_distance <= source_distance {
        Decision::Pass
    } else {
        Decision::Optimize
    };

    ReplayFeedback {
        replay_digest: replay_manifest.digest(),
        target_signature_digest: target_signature.digest.to_hex(),
        effectiveness_score: round6(score),
        source_distance,
        transformed_distance,
        optimized_dimensions: optimized,
        decision,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::SurfaceObject;
    use crate::signature_for;
    use crate::value::{OrderedMap, Value};

    fn sig(method: &str) -> SpectralSignature {
        let fields = OrderedMap::from_iter([
            ("method".to_owned(), Value::Text(method.to_owned())),
            ("status".to_owned(), Value::Num(200.0)),
        ]);
        signature_for(
            &SurfaceObject::new("application/trace+json", fields)
                .with_declared_protocol_class("http"),
        )
    }

    #[test]
    fn manifest_digest_is_nonempty_and_stable() {
        let s = sig("GET");
        let manifest = ReplayManifest {
            source_digest: s.digest.to_hex(),
            transformed_digest: s.digest.to_hex(),
            transformed_signature_digest: s.digest.to_hex(),
            operator_name: "sort_fields".to_owned(),
            kernel_version: KERNEL_VERSION.to_owned(),
        };
        assert!(!manifest.digest().is_empty());
        assert_eq!(manifest.digest(), manifest.digest());
    }

    #[test]
    fn identity_transform_scores_full_effectiveness_when_source_is_target() {
        let s = sig("GET");
        let manifest = build_replay_manifest_from(&s);
        let fb = build_replay_feedback(&manifest, &s, &s, &s);
        assert_eq!(fb.effectiveness_score, 1.0);
        assert_eq!(fb.decision, Decision::Pass);
    }

    fn build_replay_manifest_from(s: &SpectralSignature) -> ReplayManifest {
        ReplayManifest {
            source_digest: s.digest.to_hex(),
            transformed_digest: s.digest.to_hex(),
            transformed_signature_digest: s.digest.to_hex(),
            operator_name: "identity".to_owned(),
            kernel_version: KERNEL_VERSION.to_owned(),
        }
    }
}
