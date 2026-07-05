//! Profile corpus — Chameleon `corpus`.
//!
//! Versioned centroid signature profiles built from authorized signatures, with
//! nearest-profile lookup, pairwise distances, drift reports, connected-
//! component clustering, and JSON persistence. This is the substrate the IMDF
//! `SelfPerceptionAtlas` is built on: a durable, versioned record of what a
//! surface family looks like, and how a new observation drifts from it. It does
//! no network I/O and no transformation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::signature::SpectralSignature;
use crate::target::{OperationalMask, TargetProfile};
use crate::value::{round6, Dimension, Dimensions, FeatureValue};

/// Errors the corpus can return.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CorpusError {
    #[error("profile already exists: {0}")]
    AlreadyExists(String),
    #[error("profile not found: {0}")]
    NotFound(String),
    #[error("at least one signature is required to build a profile")]
    NoSignatures,
    #[error("profile store io error: {0}")]
    Io(String),
    #[error("profile store decode error: {0}")]
    Decode(String),
}

/// Per-dimension stability information for a corpus profile.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DimensionStats {
    pub numeric_mean: BTreeMap<String, f64>,
    pub numeric_stddev: BTreeMap<String, f64>,
    pub categorical_mode: BTreeMap<String, String>,
    pub categorical_cardinality: BTreeMap<String, usize>,
}

impl DimensionStats {
    /// Collapse into a signature dimension (numeric means + categorical modes).
    #[must_use]
    pub fn as_signature_dimension(&self) -> Dimension {
        let mut dim = Dimension::new();
        for (k, v) in &self.numeric_mean {
            dim.insert(k.clone(), FeatureValue::Num(round6(*v)));
        }
        for (k, v) in &self.categorical_mode {
            dim.insert(k.clone(), FeatureValue::Text(v.clone()));
        }
        dim
    }
}

/// A versioned centroid profile derived from authorized signatures.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignatureProfileRecord {
    pub name: String,
    pub version: String,
    pub signature: SpectralSignature,
    pub dimension_stats: BTreeMap<String, DimensionStats>,
    pub sample_count: usize,
    pub tags: Vec<String>,
    pub created_at: Option<String>,
    pub parent_digest: Option<String>,
    pub notes: Vec<String>,
}

impl SignatureProfileRecord {
    /// Content digest of the record's identity fields.
    #[must_use]
    pub fn digest(&self) -> String {
        #[derive(Serialize)]
        struct Key<'a> {
            name: &'a str,
            version: &'a str,
            signature_digest: String,
            sample_count: usize,
            tags: &'a [String],
            parent_digest: &'a Option<String>,
        }
        ssk_types::digest_of(
            &Key {
                name: &self.name,
                version: &self.version,
                signature_digest: self.signature.digest.to_hex(),
                sample_count: self.sample_count,
                tags: &self.tags,
                parent_digest: &self.parent_digest,
            },
            ssk_types::HashAlg::Blake3,
        )
        .expect("record key is serializable")
        .to_hex()
    }

    fn qualified_name(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }

    #[must_use]
    pub fn to_operational_mask(&self) -> OperationalMask {
        let tolerances: BTreeMap<String, f64> = [
            ("shape", 0.20),
            ("ordering", 0.25),
            ("entropy", 0.50),
            ("timing", 0.75),
            ("semantic", 0.25),
            ("linkability", 0.20),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        OperationalMask {
            name: self.qualified_name(),
            signature: self.signature.clone(),
            dimension_tolerances: tolerances,
            global_tolerance: 0.35,
            residue_externalization_surfaces: vec!["semantic".to_owned(), "linkability".to_owned()],
            enforcement_level: "optimize".to_owned(),
        }
    }

    #[must_use]
    pub fn to_target_profile(&self) -> TargetProfile {
        self.to_operational_mask().to_target_profile()
    }
}

/// A distance between two profiles (or a candidate and a profile).
#[derive(Clone, Debug, PartialEq)]
pub struct ProfileDistance {
    pub left_name: String,
    pub right_name: String,
    pub left_digest: String,
    pub right_digest: String,
    pub global_distance: f64,
    pub dimension_distances: BTreeMap<String, f64>,
}

/// A baseline→candidate drift report.
#[derive(Clone, Debug, PartialEq)]
pub struct DriftReport {
    pub baseline_name: String,
    pub candidate_name: String,
    pub baseline_digest: String,
    pub candidate_digest: String,
    pub decision: String,
    pub global_distance: f64,
    pub dimension_distances: BTreeMap<String, f64>,
    pub drifted_dimensions: Vec<String>,
    pub reasons: Vec<String>,
}

/// A cluster of profiles by centroid distance.
#[derive(Clone, Debug, PartialEq)]
pub struct ClusterReport {
    pub cluster_id: usize,
    pub members: Vec<String>,
    pub member_digests: Vec<String>,
    pub notes: Vec<String>,
}

/// A corpus of versioned signature profiles.
#[derive(Clone, Debug, Default)]
pub struct ProfileCorpus {
    records: Vec<SignatureProfileRecord>,
}

impl ProfileCorpus {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn records(&self) -> &[SignatureProfileRecord] {
        &self.records
    }

    /// Add a record, rejecting a duplicate name@version.
    ///
    /// # Errors
    /// [`CorpusError::AlreadyExists`] if a record with that name+version exists.
    pub fn add_record(
        &mut self,
        record: SignatureProfileRecord,
    ) -> Result<&SignatureProfileRecord, CorpusError> {
        if self
            .records
            .iter()
            .any(|r| r.name == record.name && r.version == record.version)
        {
            return Err(CorpusError::AlreadyExists(record.qualified_name()));
        }
        self.records.push(record);
        Ok(self.records.last().expect("just pushed"))
    }

    /// Build a centroid profile from signatures and add it.
    ///
    /// # Errors
    /// [`CorpusError::NoSignatures`] if empty, or [`CorpusError::AlreadyExists`].
    pub fn build_profile(
        &mut self,
        name: &str,
        version: &str,
        signatures: &[SpectralSignature],
        tags: Vec<String>,
        parent_digest: Option<String>,
        notes: Vec<String>,
    ) -> Result<&SignatureProfileRecord, CorpusError> {
        if signatures.is_empty() {
            return Err(CorpusError::NoSignatures);
        }
        let (centroid, stats) = centroid(signatures);
        let signature = SpectralSignature::from_dimensions(centroid);
        let record = SignatureProfileRecord {
            name: name.to_owned(),
            version: version.to_owned(),
            signature,
            dimension_stats: stats,
            sample_count: signatures.len(),
            tags,
            created_at: None,
            parent_digest,
            notes,
        };
        self.add_record(record)
    }

    /// Get a record by name (and optional version; latest inserted if `None`).
    ///
    /// # Errors
    /// [`CorpusError::NotFound`] if no record matches.
    pub fn get(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<&SignatureProfileRecord, CorpusError> {
        let matches: Vec<&SignatureProfileRecord> = self
            .records
            .iter()
            .filter(|r| r.name == name && version.is_none_or(|v| r.version == v))
            .collect();
        match version {
            Some(v) => matches
                .into_iter()
                .next()
                .ok_or_else(|| CorpusError::NotFound(format!("{name}@{v}"))),
            None => matches
                .into_iter()
                .last()
                .ok_or_else(|| CorpusError::NotFound(format!("{name}@*"))),
        }
    }

    /// The `k` nearest profiles to a candidate signature.
    #[must_use]
    pub fn nearest(&self, signature: &SpectralSignature, k: usize) -> Vec<ProfileDistance> {
        let mut distances: Vec<ProfileDistance> = self
            .records
            .iter()
            .map(|record| ProfileDistance {
                left_name: "candidate".to_owned(),
                right_name: record.qualified_name(),
                left_digest: signature.digest.to_hex(),
                right_digest: record.digest(),
                global_distance: signature.global_distance(&record.signature),
                dimension_distances: signature.distance_by_dimension(&record.signature),
            })
            .collect();
        distances.sort_by(|a, b| {
            a.global_distance
                .partial_cmp(&b.global_distance)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        distances.into_iter().take(k).collect()
    }

    /// All pairwise profile distances.
    #[must_use]
    pub fn pairwise_distances(&self) -> Vec<ProfileDistance> {
        let mut out = Vec::new();
        for (i, left) in self.records.iter().enumerate() {
            for right in &self.records[i + 1..] {
                out.push(ProfileDistance {
                    left_name: left.qualified_name(),
                    right_name: right.qualified_name(),
                    left_digest: left.digest(),
                    right_digest: right.digest(),
                    global_distance: left.signature.global_distance(&right.signature),
                    dimension_distances: left.signature.distance_by_dimension(&right.signature),
                });
            }
        }
        out
    }

    /// A drift report between a baseline and candidate record.
    #[must_use]
    pub fn drift_report(
        &self,
        baseline: &SignatureProfileRecord,
        candidate: &SignatureProfileRecord,
        global_tolerance: f64,
        dimension_tolerances: &BTreeMap<String, f64>,
    ) -> DriftReport {
        let dimension_distances = candidate
            .signature
            .distance_by_dimension(&baseline.signature);
        let global_distance = candidate.signature.global_distance(&baseline.signature);
        let mut drifted: Vec<String> = dimension_distances
            .iter()
            .filter(|(dim, &dist)| {
                dist > dimension_tolerances
                    .get(*dim)
                    .copied()
                    .unwrap_or(global_tolerance)
            })
            .map(|(dim, _)| dim.clone())
            .collect();
        drifted.sort();

        let mut reasons: Vec<String> = Vec::new();
        if global_distance > global_tolerance {
            reasons.push("global_distance_exceeds_tolerance".to_owned());
        }
        if !drifted.is_empty() {
            reasons.push(format!("dimension_drift:{}", drifted.join(",")));
        }
        let decision = if reasons.is_empty() {
            "PASS".to_owned()
        } else if global_distance <= global_tolerance * 3.0 {
            "OPTIMIZE".to_owned()
        } else {
            "FAIL".to_owned()
        };
        DriftReport {
            baseline_name: baseline.qualified_name(),
            candidate_name: candidate.qualified_name(),
            baseline_digest: baseline.digest(),
            candidate_digest: candidate.digest(),
            decision,
            global_distance,
            dimension_distances,
            drifted_dimensions: drifted,
            reasons: if reasons.is_empty() {
                vec!["no_drift".to_owned()]
            } else {
                reasons
            },
        }
    }

    /// Connected-component clustering by centroid distance.
    #[must_use]
    pub fn cluster(&self, threshold: f64) -> Vec<ClusterReport> {
        let n = self.records.len();
        let mut visited = vec![false; n];
        let mut clusters = Vec::new();
        for start in 0..n {
            if visited[start] {
                continue;
            }
            let mut stack = vec![start];
            visited[start] = true;
            let mut component = Vec::new();
            while let Some(idx) = stack.pop() {
                component.push(idx);
                for (j, other) in self.records.iter().enumerate() {
                    if visited[j] {
                        continue;
                    }
                    if self.records[idx]
                        .signature
                        .global_distance(&other.signature)
                        <= threshold
                    {
                        visited[j] = true;
                        stack.push(j);
                    }
                }
            }
            component.sort_unstable();
            clusters.push(ClusterReport {
                cluster_id: clusters.len(),
                members: component
                    .iter()
                    .map(|&i| self.records[i].qualified_name())
                    .collect(),
                member_digests: component
                    .iter()
                    .map(|&i| self.records[i].digest())
                    .collect(),
                notes: vec![format!("threshold={threshold}")],
            });
        }
        clusters
    }
}

fn mode(values: &[String]) -> String {
    if values.is_empty() {
        return "unknown".to_owned();
    }
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for v in values {
        *counts.entry(v.clone()).or_insert(0) += 1;
    }
    // highest count, tie broken by lexicographically smallest value
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
        .map(|(v, _)| v)
        .unwrap_or_else(|| "unknown".to_owned())
}

fn feature_str(v: &FeatureValue) -> String {
    match v {
        FeatureValue::Text(s) => s.clone(),
        FeatureValue::Num(n) => {
            if n.fract() == 0.0 && n.abs() < 1e15 {
                format!("{}", *n as i64)
            } else {
                format!("{n}")
            }
        }
    }
}

fn centroid(signatures: &[SpectralSignature]) -> (Dimensions, BTreeMap<String, DimensionStats>) {
    use std::collections::BTreeSet;
    let all_dims: BTreeSet<&String> = signatures
        .iter()
        .flat_map(|s| s.dimensions.keys())
        .collect();
    let mut centroid: Dimensions = BTreeMap::new();
    let mut stats_by_dim: BTreeMap<String, DimensionStats> = BTreeMap::new();

    for dim in all_dims {
        let keys: BTreeSet<&String> = signatures
            .iter()
            .filter_map(|s| s.dimensions.get(dim))
            .flat_map(|d| d.keys())
            .collect();
        let mut stats = DimensionStats::default();

        for key in keys {
            let values: Vec<&FeatureValue> = signatures
                .iter()
                .filter_map(|s| s.dimensions.get(dim).and_then(|d| d.get(key)))
                .collect();
            let numeric: Vec<f64> = values.iter().filter_map(|v| v.as_num()).collect();
            if !numeric.is_empty() && numeric.len() == values.len() {
                let mean = numeric.iter().sum::<f64>() / numeric.len() as f64;
                stats.numeric_mean.insert(key.clone(), round6(mean));
                let stddev = if numeric.len() > 1 {
                    let var = numeric.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
                        / numeric.len() as f64;
                    round6(var.sqrt())
                } else {
                    0.0
                };
                stats.numeric_stddev.insert(key.clone(), stddev);
            } else {
                let cat: Vec<String> = values.iter().map(|v| feature_str(v)).collect();
                let cardinality = cat.iter().collect::<BTreeSet<_>>().len();
                stats.categorical_mode.insert(key.clone(), mode(&cat));
                stats
                    .categorical_cardinality
                    .insert(key.clone(), cardinality);
            }
        }
        centroid.insert(dim.clone(), stats.as_signature_dimension());
        stats_by_dim.insert(dim.clone(), stats);
    }
    (centroid, stats_by_dim)
}

/// JSON persistence for a profile corpus.
#[derive(Clone, Debug)]
pub struct ProfileStore {
    pub path: PathBuf,
}

impl ProfileStore {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        ProfileStore { path: path.into() }
    }

    /// Persist the corpus as JSON.
    ///
    /// # Errors
    /// [`CorpusError::Io`] / [`CorpusError::Decode`] on write/serialize failure.
    pub fn save(&self, corpus: &ProfileCorpus) -> Result<(), CorpusError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| CorpusError::Io(e.to_string()))?;
        }
        let json = serde_json::to_string_pretty(corpus.records())
            .map_err(|e| CorpusError::Decode(e.to_string()))?;
        std::fs::write(&self.path, json).map_err(|e| CorpusError::Io(e.to_string()))
    }

    /// Load a corpus from JSON (an empty corpus if the file does not exist).
    ///
    /// # Errors
    /// [`CorpusError::Io`] / [`CorpusError::Decode`] on read/parse failure.
    pub fn load(&self) -> Result<ProfileCorpus, CorpusError> {
        if !Path::new(&self.path).exists() {
            return Ok(ProfileCorpus::new());
        }
        let text =
            std::fs::read_to_string(&self.path).map_err(|e| CorpusError::Io(e.to_string()))?;
        let records: Vec<SignatureProfileRecord> =
            serde_json::from_str(&text).map_err(|e| CorpusError::Decode(e.to_string()))?;
        Ok(ProfileCorpus { records })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::SurfaceObject;
    use crate::operators::{NormalizeTraceShapeOperator, TransformOperator};
    use crate::signature_for;
    use crate::value::{OrderedMap, Value};

    fn record_obj(
        method: &str,
        url: &str,
        status: f64,
        duration: f64,
        with_body: bool,
    ) -> SurfaceObject {
        let mut fields = OrderedMap::from_iter([
            ("protocol".to_owned(), Value::Text("http".to_owned())),
            ("method".to_owned(), Value::Text(method.to_owned())),
            ("url".to_owned(), Value::Text(url.to_owned())),
            ("status".to_owned(), Value::Num(status)),
            ("duration_ms".to_owned(), Value::Num(duration)),
        ]);
        if with_body {
            let body = OrderedMap::from_iter([("ok".to_owned(), Value::Bool(true))]);
            fields.insert("body", Value::Object(body));
        }
        SurfaceObject::new("application/trace+json", fields).with_declared_protocol_class("http")
    }

    fn signatures() -> Vec<SpectralSignature> {
        let op = NormalizeTraceShapeOperator;
        [
            record_obj("GET", "/a", 200.0, 100.0, false),
            record_obj("GET", "/b", 200.0, 130.0, false),
            record_obj("POST", "/v1", 201.0, 240.0, true),
        ]
        .iter()
        .map(|o| signature_for(&op.apply(o).transformed))
        .collect()
    }

    #[test]
    fn build_profile_requires_signatures() {
        let mut corpus = ProfileCorpus::new();
        assert_eq!(
            corpus
                .build_profile("empty", "1.0.0", &[], vec![], None, vec![])
                .unwrap_err(),
            CorpusError::NoSignatures
        );
    }

    #[test]
    fn build_profile_creates_centroid() {
        let sigs = signatures();
        let mut corpus = ProfileCorpus::new();
        let record = corpus
            .build_profile("http_fixture", "1.0.0", &sigs[..2], vec![], None, vec![])
            .unwrap();
        assert_eq!(record.sample_count, 2);
        assert!(!record.signature.digest.to_hex().is_empty());
        assert!(record.dimension_stats.contains_key("shape"));
        assert_eq!(record.to_target_profile().name, "http_fixture@1.0.0");
        assert_eq!(record.to_operational_mask().name, "http_fixture@1.0.0");
    }

    #[test]
    fn duplicate_profile_rejected() {
        let sigs = signatures();
        let mut corpus = ProfileCorpus::new();
        corpus
            .build_profile("http_fixture", "1.0.0", &sigs[..1], vec![], None, vec![])
            .unwrap();
        assert!(matches!(
            corpus.build_profile("http_fixture", "1.0.0", &sigs[1..2], vec![], None, vec![]),
            Err(CorpusError::AlreadyExists(_))
        ));
    }

    #[test]
    fn nearest_returns_profile_distances() {
        let sigs = signatures();
        let mut corpus = ProfileCorpus::new();
        let first_sig = corpus
            .build_profile("first", "1.0.0", &sigs[..1], vec![], None, vec![])
            .unwrap()
            .signature
            .clone();
        corpus
            .build_profile("second", "1.0.0", &sigs[1..], vec![], None, vec![])
            .unwrap();
        let nearest = corpus.nearest(&first_sig, 2);
        assert_eq!(nearest[0].right_name, "first@1.0.0");
        assert_eq!(nearest[0].global_distance, 0.0);
        assert_eq!(nearest.len(), 2);
    }

    #[test]
    fn pairwise_and_cluster() {
        let sigs = signatures();
        let mut corpus = ProfileCorpus::new();
        corpus
            .build_profile("a", "1.0.0", &sigs[..1], vec![], None, vec![])
            .unwrap();
        corpus
            .build_profile("b", "1.0.0", &sigs[1..2], vec![], None, vec![])
            .unwrap();
        corpus
            .build_profile("c", "1.0.0", &sigs[2..], vec![], None, vec![])
            .unwrap();
        assert_eq!(corpus.pairwise_distances().len(), 3);
        let clusters = corpus.cluster(10.0);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].members.len(), 3);
    }

    #[test]
    fn drift_report_decides() {
        let sigs = signatures();
        let mut corpus = ProfileCorpus::new();
        let baseline = corpus
            .build_profile("profile", "1.0.0", &sigs[..2], vec![], None, vec![])
            .unwrap()
            .clone();
        let candidate = corpus
            .build_profile("profile", "1.1.0", &sigs[2..], vec![], None, vec![])
            .unwrap()
            .clone();
        let tol: BTreeMap<String, f64> = BTreeMap::new();
        let report = corpus.drift_report(&baseline, &candidate, 0.35, &tol);
        assert!(["PASS", "OPTIMIZE", "FAIL"].contains(&report.decision.as_str()));
        assert_eq!(report.baseline_name, "profile@1.0.0");
        assert_eq!(report.candidate_name, "profile@1.1.0");
    }

    #[test]
    fn profile_store_roundtrip() {
        let sigs = signatures();
        let mut corpus = ProfileCorpus::new();
        corpus
            .build_profile("stored", "1.0.0", &sigs, vec![], None, vec![])
            .unwrap();
        let dir = std::env::temp_dir().join(format!("ssk-sig-corpus-{}", std::process::id()));
        let store = ProfileStore::new(dir.join("profiles.json"));
        store.save(&corpus).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.records().len(), 1);
        assert_eq!(loaded.get("stored", Some("1.0.0")).unwrap().sample_count, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
