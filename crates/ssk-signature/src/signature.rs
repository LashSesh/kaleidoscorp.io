//! The spectral signature — Chameleon `spectral_signature`.
//!
//! A [`SpectralSignature`] is the multi-dimensional spectrum of a surface plus a
//! content-address [`Digest`]: **the spectrum is the identity**. It supports a
//! per-dimension and global distance metric and a tolerance-gated comparison
//! that yields Pass/Optimize per dimension and overall — the same
//! never-a-single-score contract the SSK gate layer holds.

use std::collections::{BTreeMap, BTreeSet};

use ssk_types::{digest_of, Digest, HashAlg};

use crate::features::FeatureVector;
use crate::value::{categorical_equal, round6, Dimension, Dimensions, FeatureValue};

/// Per-dimension comparison decision (signature level). The gate layer maps
/// these onto `ssk_types::GateOutcomeKind` (`Pass`/`Hold`) in a later tranche.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Pass,
    Optimize,
}

impl Decision {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Pass => "PASS",
            Decision::Optimize => "OPTIMIZE",
        }
    }
}

/// One dimension's contribution to a comparison.
#[derive(Clone, Debug, PartialEq)]
pub struct SignatureDimensionDelta {
    pub dimension: String,
    pub distance: f64,
    pub tolerance: f64,
    pub decision: Decision,
    pub left_digest: String,
    pub right_digest: String,
}

/// The full result of comparing two signatures.
#[derive(Clone, Debug, PartialEq)]
pub struct SignatureComparisonReport {
    pub left_digest: String,
    pub right_digest: String,
    pub global_distance: f64,
    pub global_tolerance: f64,
    pub decision: Decision,
    pub dimension_deltas: Vec<SignatureDimensionDelta>,
    pub top_dimensions: Vec<String>,
    pub shared_dimensions: Vec<String>,
    pub missing_left: Vec<String>,
    pub missing_right: Vec<String>,
}

impl SignatureComparisonReport {
    /// Count deltas by decision (Chameleon `decision_counts`).
    #[must_use]
    pub fn decision_counts(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::new();
        for delta in &self.dimension_deltas {
            *counts.entry(delta.decision.as_str()).or_insert(0) += 1;
        }
        counts
    }
}

/// The multi-dimensional spectrum of a surface plus its content digest.
#[derive(Clone, Debug, PartialEq)]
pub struct SpectralSignature {
    pub dimensions: Dimensions,
    pub digest: Digest,
}

fn digest_dimensions(dims: &Dimensions) -> Digest {
    digest_of(dims, HashAlg::Blake3).expect("dimensions are serializable")
}

fn digest_dimension(dim: Option<&Dimension>) -> String {
    let empty = Dimension::new();
    let dim = dim.unwrap_or(&empty);
    digest_of(dim, HashAlg::Blake3)
        .expect("dimension is serializable")
        .to_hex()
}

impl SpectralSignature {
    /// Build a signature from a feature vector (Chameleon `from_features`).
    #[must_use]
    pub fn from_features(features: &FeatureVector) -> Self {
        let dimensions = features.as_dimensions();
        let digest = digest_dimensions(&dimensions);
        SpectralSignature { dimensions, digest }
    }

    /// Construct directly from a dimension map (used by centroid/profile code).
    #[must_use]
    pub fn from_dimensions(dimensions: Dimensions) -> Self {
        let digest = digest_dimensions(&dimensions);
        SpectralSignature { dimensions, digest }
    }

    /// Lowercase-hex rendering of the digest (the "signature id").
    #[must_use]
    pub fn digest_hex(&self) -> String {
        self.digest.to_hex()
    }

    /// Per-dimension distance to another signature (Chameleon
    /// `distance_by_dimension`): Euclidean over numeric keys (averaged by count)
    /// plus a categorical mismatch rate, rounded to six places.
    #[must_use]
    pub fn distance_by_dimension(&self, other: &SpectralSignature) -> BTreeMap<String, f64> {
        let mut out = BTreeMap::new();
        let dims: BTreeSet<&String> = self
            .dimensions
            .keys()
            .chain(other.dimensions.keys())
            .collect();
        for dim in dims {
            let left = self.dimensions.get(dim);
            let right = other.dimensions.get(dim);
            let keys: BTreeSet<&String> = left
                .into_iter()
                .flat_map(|m| m.keys())
                .chain(right.into_iter().flat_map(|m| m.keys()))
                .collect();

            let mut numeric_total = 0.0;
            let mut numeric_count = 0usize;
            let mut cat_total = 0.0;
            let mut cat_count = 0usize;

            for key in keys {
                let a = left.and_then(|m| m.get(key));
                let b = right.and_then(|m| m.get(key));
                match (a, b) {
                    (Some(FeatureValue::Num(x)), Some(FeatureValue::Num(y))) => {
                        numeric_total += (x - y).powi(2);
                        numeric_count += 1;
                    }
                    _ => {
                        cat_total += if categorical_equal(a, b) { 0.0 } else { 1.0 };
                        cat_count += 1;
                    }
                }
            }

            let numeric_distance = numeric_total.sqrt() / numeric_count.max(1) as f64;
            let categorical_distance = if cat_count > 0 {
                cat_total / cat_count as f64
            } else {
                0.0
            };
            out.insert(dim.clone(), round6(numeric_distance + categorical_distance));
        }
        out
    }

    /// Mean of the per-dimension distances (Chameleon `global_distance`).
    #[must_use]
    pub fn global_distance(&self, other: &SpectralSignature) -> f64 {
        let distances = self.distance_by_dimension(other);
        let sum: f64 = distances.values().sum();
        round6(sum / distances.len().max(1) as f64)
    }

    /// Tolerance-gated comparison (Chameleon `compare`).
    #[must_use]
    pub fn compare(
        &self,
        other: &SpectralSignature,
        dimension_tolerances: &BTreeMap<String, f64>,
        global_tolerance: f64,
        top_n: usize,
    ) -> SignatureComparisonReport {
        let distances = self.distance_by_dimension(other);

        let mut deltas: Vec<SignatureDimensionDelta> = Vec::new();
        for (dimension, &distance) in &distances {
            let tolerance = dimension_tolerances
                .get(dimension)
                .copied()
                .unwrap_or(global_tolerance);
            let decision = if distance <= tolerance {
                Decision::Pass
            } else {
                Decision::Optimize
            };
            deltas.push(SignatureDimensionDelta {
                dimension: dimension.clone(),
                distance,
                tolerance,
                decision,
                left_digest: digest_dimension(self.dimensions.get(dimension)),
                right_digest: digest_dimension(other.dimensions.get(dimension)),
            });
        }

        let global_distance = self.global_distance(other);

        // top_n dimensions by distance descending, positive distances only.
        let mut ranked: Vec<&SignatureDimensionDelta> = deltas.iter().collect();
        ranked.sort_by(|a, b| {
            b.distance
                .partial_cmp(&a.distance)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let top_dimensions: Vec<String> = ranked
            .into_iter()
            .take(top_n)
            .filter(|d| d.distance > 0.0)
            .map(|d| d.dimension.clone())
            .collect();

        let all_pass = deltas.iter().all(|d| d.decision == Decision::Pass);
        let decision = if global_distance <= global_tolerance && all_pass {
            Decision::Pass
        } else {
            Decision::Optimize
        };

        let left_dims: BTreeSet<&String> = self.dimensions.keys().collect();
        let right_dims: BTreeSet<&String> = other.dimensions.keys().collect();
        let shared_dimensions: Vec<String> = left_dims
            .intersection(&right_dims)
            .map(|s| (*s).clone())
            .collect();
        let missing_left: Vec<String> = right_dims
            .difference(&left_dims)
            .map(|s| (*s).clone())
            .collect();
        let missing_right: Vec<String> = left_dims
            .difference(&right_dims)
            .map(|s| (*s).clone())
            .collect();

        SignatureComparisonReport {
            left_digest: self.digest.to_hex(),
            right_digest: other.digest.to_hex(),
            global_distance,
            global_tolerance,
            decision,
            dimension_deltas: deltas,
            top_dimensions,
            shared_dimensions,
            missing_left,
            missing_right,
        }
    }
}
