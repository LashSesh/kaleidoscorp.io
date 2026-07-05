//! Feature extraction — Chameleon `feature_space`.
//!
//! Turns a canonicalized surface into a six-dimension base feature vector
//! (shape, ordering, entropy, timing, semantic, linkability) plus the five
//! protocol-fingerprint dimensions. Together these are the multi-dimensional
//! spectrum a [`crate::signature::SpectralSignature`] is built from.

use std::collections::{BTreeMap, BTreeSet};

use crate::canonical::CanonicalObject;
use crate::fingerprints::extract_fingerprint_bundle;
use crate::object::SurfaceObject;
use crate::value::{
    bucket, round6, shannon_entropy, Dimension, Dimensions, FeatureValue, OrderedMap, Value,
};

const SENSITIVE_FIELD_HINTS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api_key",
    "token",
    "session",
    "session_id",
    "client_ip",
    "remote_addr",
    "forwarded",
    "x-forwarded-for",
    "x_forwarded_for",
    "user_id",
    "device_id",
];

const IP_SURFACE_HINTS: &[&str] = &[
    "client_ip",
    "remote_addr",
    "x-forwarded-for",
    "x_forwarded_for",
    "forwarded",
];

/// The base + fingerprint feature dimensions of one surface.
#[derive(Clone, Debug, PartialEq)]
pub struct FeatureVector {
    pub shape: Dimension,
    pub ordering: Dimension,
    pub entropy: Dimension,
    pub timing: Dimension,
    pub semantic: Dimension,
    pub linkability: Dimension,
    pub fingerprint: Vec<(String, Dimension)>,
}

impl FeatureVector {
    /// Flatten into the full dimension map (Chameleon `FeatureVector.as_dimensions`).
    #[must_use]
    pub fn as_dimensions(&self) -> Dimensions {
        let mut dims: Dimensions = BTreeMap::new();
        dims.insert("shape".to_owned(), self.shape.clone());
        dims.insert("ordering".to_owned(), self.ordering.clone());
        dims.insert("entropy".to_owned(), self.entropy.clone());
        dims.insert("timing".to_owned(), self.timing.clone());
        dims.insert("semantic".to_owned(), self.semantic.clone());
        dims.insert("linkability".to_owned(), self.linkability.clone());
        for (name, dim) in &self.fingerprint {
            dims.insert(name.clone(), dim.clone());
        }
        dims
    }
}

fn count_nested(value: &Value) -> usize {
    match value {
        Value::Object(m) => m.len() + m.iter().map(|(_, v)| count_nested(v)).sum::<usize>(),
        Value::Array(a) => a.iter().map(count_nested).sum(),
        _ => 0,
    }
}

fn sensitive_hits(fields: &OrderedMap) -> BTreeSet<String> {
    fn walk(value: &Value, key: &str, hits: &mut BTreeSet<String>) {
        let key_l = key.to_lowercase();
        if !key_l.is_empty()
            && (SENSITIVE_FIELD_HINTS.contains(&key_l.as_str())
                || SENSITIVE_FIELD_HINTS.iter().any(|h| key_l.contains(h)))
        {
            hits.insert(key_l.clone());
        }
        match value {
            Value::Object(m) => {
                for (k, v) in m.iter() {
                    walk(v, k, hits);
                }
            }
            Value::Array(a) => {
                for item in a {
                    walk(item, key, hits);
                }
            }
            _ => {}
        }
    }
    let mut hits = BTreeSet::new();
    for (k, v) in fields.iter() {
        walk(v, k, &mut hits);
    }
    hits
}

/// A deterministic, insertion-order-preserving stand-in for Python's
/// `repr(dict)` — used only to size and measure entropy of the payload. Exact
/// Python `repr` is not a cross-language contract; both sides of every distance
/// use this same rendering, so the metric stays internally consistent.
fn payload_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Num(n) => {
            if n.fract() == 0.0 && n.abs() < 1e15 {
                format!("{}", *n as i64)
            } else {
                format!("{n}")
            }
        }
        Value::Text(s) => format!("'{s}'"),
        Value::Array(a) => {
            let inner: Vec<String> = a.iter().map(payload_repr).collect();
            format!("[{}]", inner.join(", "))
        }
        Value::Object(m) => {
            let inner: Vec<String> = m
                .iter()
                .map(|(k, v)| format!("'{k}': {}", payload_repr(v)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

fn text(value: impl Into<String>) -> FeatureValue {
    FeatureValue::Text(value.into())
}

fn num(value: f64) -> FeatureValue {
    FeatureValue::Num(value)
}

fn dimension<const N: usize>(entries: [(&str, FeatureValue); N]) -> Dimension {
    entries
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
}

/// Extract the full feature vector from a canonicalized surface (Chameleon
/// `extract_features`). The fingerprint dimensions read the *original* surface,
/// matching the kernel.
#[must_use]
pub fn extract_features(canonical: &CanonicalObject, original: &SurfaceObject) -> FeatureVector {
    let fields = &canonical.canonical_fields;
    let headers = match fields.get("headers") {
        Some(Value::Object(m)) => m.clone(),
        _ => OrderedMap::new(),
    };
    let serialized = payload_repr(&Value::Object(fields.clone()));
    let sensitive = sensitive_hits(fields);
    let timing = &original.timing_model;
    let fingerprint = extract_fingerprint_bundle(original).as_dimensions();

    let status_class = fields
        .get("status")
        .or_else(|| fields.get("status_code"))
        .and_then(Value::as_number)
        .map_or(-1, |v| (v as i64) / 100);

    let interarrival = timing
        .get("interarrival_ms")
        .or_else(|| timing.get("delta_ms"))
        .and_then(Value::as_number)
        .unwrap_or(-1.0);
    let jitter = timing
        .get("jitter_ms")
        .and_then(Value::as_number)
        .unwrap_or(-1.0);

    let has_body = fields.get("body").is_some_and(|v| !v.is_empty_bodylike());
    let method = fields
        .get("method")
        .and_then(Value::as_text)
        .unwrap_or("unknown")
        .to_uppercase();
    let first_key = fields.keys().next().unwrap_or("").to_owned();

    let shape = dimension([
        ("field_count", num(fields.len() as f64)),
        (
            "nested_field_count",
            num(fields.iter().map(|(_, v)| count_nested(v)).sum::<usize>() as f64),
        ),
        ("header_count", num(headers.len() as f64)),
        ("has_body", num(if has_body { 1.0 } else { 0.0 })),
        ("media_type", text(canonical.media_type.clone())),
    ]);

    let ordering = dimension([
        ("declared_order_len", num(original.ordering.len() as f64)),
        ("canonical_order_len", num(fields.len() as f64)),
        ("first_key", text(first_key)),
    ]);

    let entropy = dimension([
        ("payload_length", num(serialized.chars().count() as f64)),
        ("shannon_entropy", num(round6(shannon_entropy(&serialized)))),
    ]);

    let timing_dim = dimension([
        (
            "interarrival_bucket",
            num(bucket(Some(interarrival), 100, 10) as f64),
        ),
        ("jitter_bucket", num(bucket(Some(jitter), 50, 10) as f64)),
        ("has_timing", num(if timing.is_empty() { 0.0 } else { 1.0 })),
    ]);

    let semantic = dimension([
        (
            "declared_protocol_class",
            text(canonical.declared_protocol_class.clone()),
        ),
        ("method", text(method)),
        ("status_class", num(status_class as f64)),
    ]);

    let has_ip = sensitive
        .iter()
        .any(|s| IP_SURFACE_HINTS.contains(&s.as_str()));
    let linkability = dimension([
        ("sensitive_field_count", num(sensitive.len() as f64)),
        (
            "has_authorization",
            num(if sensitive.contains("authorization") {
                1.0
            } else {
                0.0
            }),
        ),
        (
            "has_cookie",
            num(
                if sensitive.contains("cookie") || sensitive.contains("set-cookie") {
                    1.0
                } else {
                    0.0
                },
            ),
        ),
        ("has_ip_surface", num(if has_ip { 1.0 } else { 0.0 })),
    ]);

    FeatureVector {
        shape,
        ordering,
        entropy,
        timing: timing_dim,
        semantic,
        linkability,
        fingerprint,
    }
}
