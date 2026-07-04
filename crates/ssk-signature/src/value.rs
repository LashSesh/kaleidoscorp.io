//! Dynamic surface values and the deterministic helpers the whole crate shares.
//!
//! Ported from the Chameleon kernel, where `SurfaceObject.fields` is an
//! arbitrary `Mapping[str, Any]` and signature dimensions hold `float | str`.
//! Two value types model that split:
//!
//! * [`Value`] — a JSON-shaped, **insertion-order-preserving** dynamic value for
//!   surface fields. Order preservation matters: the Chameleon feature extractor
//!   reads `first_key` and the header-order fingerprint from dict iteration order
//!   (Python `dict` is ordered), so a `BTreeMap` would silently change results.
//! * [`FeatureValue`] — the `Num | Text` cell of a signature dimension.
//!
//! Determinism note (port divergence, disclosed): the Chameleon kernel hashes
//! signatures with `sha256(json.dumps(..., sort_keys=True, separators=(",",":"),
//! default=str))`, and derives the `entropy` dimension from Python's
//! `repr(dict)`. Neither `json.dumps` float formatting nor `repr` is a stable
//! cross-language contract, and the kernel's own test suite asserts **no** digest
//! hex — only that digests are non-empty and that decisions/distances/feature
//! values match. So this port keeps the *semantics* (multi-dimensional spectrum,
//! per-dimension + global distance, Pass/Optimize gate) and the concrete feature
//! values the tests pin, while taking the digest through the SSK content-address
//! path (`ssk_types::digest_of`, canonical CBOR + Blake3) so a `SpectralSignature`
//! identity is a first-class `ssk_types::Digest`, flush with replay/audit.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A JSON-shaped dynamic value for surface fields, preserving object key
/// insertion order (mirrors Python `dict`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Text(String),
    Array(Vec<Value>),
    Object(OrderedMap),
}

impl Value {
    /// Python-`str()`-equivalent rendering, used by categorical feature
    /// comparison and by a few fingerprint fields. Kept minimal and
    /// deterministic; see the module note on why exact `repr` parity is neither
    /// required nor a stable contract.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_object(&self) -> Option<&OrderedMap> {
        match self {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_empty_bodylike(&self) -> bool {
        // Python: value in (None, "", {}, [])
        match self {
            Value::Null => true,
            Value::Text(s) => s.is_empty(),
            Value::Array(a) => a.is_empty(),
            Value::Object(m) => m.is_empty(),
            _ => false,
        }
    }

    /// Try to read a numeric value the way Python `int(x)` / `float(x)` would
    /// from a field that may be a number or a numeric string. Returns `None`
    /// when the value is not number-like (the caller then uses its fallback).
    #[must_use]
    pub fn as_number(&self) -> Option<f64> {
        match self {
            Value::Num(n) => Some(*n),
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Value::Text(s) => s.trim().parse::<f64>().ok(),
            _ => None,
        }
    }
}

/// An insertion-order-preserving string-keyed map (a small `Vec` of pairs,
/// matching Python `dict` semantics for the sizes surfaces reach).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OrderedMap(pub Vec<(String, Value)>);

impl OrderedMap {
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Insert or overwrite `key`, preserving first-insertion position on
    /// overwrite (Python `dict` assignment semantics).
    pub fn insert(&mut self, key: impl Into<String>, value: Value) {
        let key = key.into();
        if let Some(slot) = self.0.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            self.0.push((key, value));
        }
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.0.iter().any(|(k, _)| k == key)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(k, _)| k.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }
}

impl<K: Into<String>> FromIterator<(K, Value)> for OrderedMap {
    fn from_iter<I: IntoIterator<Item = (K, Value)>>(iter: I) -> Self {
        let mut m = OrderedMap::new();
        for (k, v) in iter {
            m.insert(k, v);
        }
        m
    }
}

/// A single cell of a signature dimension: a number or a category label.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FeatureValue {
    Num(f64),
    Text(String),
}

impl FeatureValue {
    #[must_use]
    pub fn num(n: f64) -> Self {
        FeatureValue::Num(n)
    }

    #[must_use]
    pub fn text(s: impl Into<String>) -> Self {
        FeatureValue::Text(s.into())
    }

    #[must_use]
    pub fn as_num(&self) -> Option<f64> {
        match self {
            FeatureValue::Num(n) => Some(*n),
            FeatureValue::Text(_) => None,
        }
    }
}

/// One signature dimension: an ordered-by-key map of feature cells. `BTreeMap`
/// gives the deterministic key ordering the digest path relies on.
pub type Dimension = BTreeMap<String, FeatureValue>;

/// The full multi-dimensional spectrum: dimension name → dimension.
pub type Dimensions = BTreeMap<String, Dimension>;

/// Convert an arbitrary `serde_json::Value` into a surface [`Value`], preserving
/// object key order. Used by the import adapters (a `serde(untagged)` derive
/// cannot deserialize a JSON object into the order-preserving `Object` variant,
/// so external JSON is converted explicitly).
#[must_use]
pub fn value_from_json(json: &serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => Value::Num(n.as_f64().unwrap_or(0.0)),
        serde_json::Value::String(s) => Value::Text(s.clone()),
        serde_json::Value::Array(a) => Value::Array(a.iter().map(value_from_json).collect()),
        serde_json::Value::Object(o) => {
            let mut m = OrderedMap::new();
            for (k, v) in o {
                m.insert(k.clone(), value_from_json(v));
            }
            Value::Object(m)
        }
    }
}

/// Python `round(x, 6)` — round-half-to-even at six decimal places. Used
/// everywhere distances are produced so comparisons against tolerances are
/// stable and reproducible.
#[must_use]
pub fn round6(x: f64) -> f64 {
    (x * 1_000_000.0).round_ties_even() / 1_000_000.0
}

/// Shannon entropy (bits) of a byte/char string — Chameleon `_shannon_entropy`.
#[must_use]
pub fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    let mut total = 0usize;
    for ch in text.chars() {
        *counts.entry(ch).or_insert(0) += 1;
        total += 1;
    }
    let total = total as f64;
    -counts
        .values()
        .map(|&c| {
            let p = c as f64 / total;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Chameleon `_bucket`: clamp `raw // width` into `[0, max_bucket]`, or `-1` for
/// negative / non-numeric input.
#[must_use]
pub fn bucket(raw: Option<f64>, width: i64, max_bucket: i64) -> i64 {
    match raw {
        Some(v) if v >= 0.0 => {
            let b = (v / width as f64).floor() as i64;
            b.clamp(0, max_bucket)
        }
        _ => -1,
    }
}

/// Categorical equality mirroring Python `str(a) == str(b)` for the distance
/// metric's non-numeric branch. Only reached when the pair is *not* two
/// numbers, so the meaningful cases are text/text and present/absent. A number
/// paired with a missing or text cell renders unequal in Python (`"5.0"` never
/// equals `"None"` or a label), which this models directly; the pathological
/// coincidence of a label literally equal to a float's `str()` is out of the
/// tested surface and disclosed here rather than emulated.
#[must_use]
pub fn categorical_equal(a: Option<&FeatureValue>, b: Option<&FeatureValue>) -> bool {
    match (a, b) {
        (Some(FeatureValue::Text(x)), Some(FeatureValue::Text(y))) => x == y,
        (None, None) => true,
        (Some(FeatureValue::Text(x)), None) | (None, Some(FeatureValue::Text(x))) => x == "None",
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round6_is_half_to_even() {
        assert_eq!(round6(0.123_456_49), 0.123_456);
        assert_eq!(round6(0.123_456_51), 0.123_457);
        // exact tie -> to even
        assert_eq!(round6(0.000_000_5), 0.0);
        assert_eq!(round6(0.000_001_5), 0.000_002);
    }

    #[test]
    fn shannon_entropy_bounds() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        // two equiprobable symbols -> 1 bit
        assert!((shannon_entropy("abab") - 1.0).abs() < 1e-12);
    }

    #[test]
    fn bucket_clamps_and_rejects() {
        assert_eq!(bucket(Some(0.0), 100, 10), 0);
        assert_eq!(bucket(Some(250.0), 100, 10), 2);
        assert_eq!(bucket(Some(99_999.0), 100, 10), 10);
        assert_eq!(bucket(Some(-1.0), 100, 10), -1);
        assert_eq!(bucket(None, 100, 10), -1);
    }

    #[test]
    fn ordered_map_preserves_and_overwrites() {
        let mut m = OrderedMap::new();
        m.insert("b", Value::Num(1.0));
        m.insert("a", Value::Num(2.0));
        m.insert("b", Value::Num(3.0));
        assert_eq!(m.keys().collect::<Vec<_>>(), vec!["b", "a"]);
        assert_eq!(m.get("b"), Some(&Value::Num(3.0)));
    }

    #[test]
    fn categorical_equality_matches_python_str() {
        let g = FeatureValue::text("GET");
        let p = FeatureValue::text("POST");
        let n = FeatureValue::num(5.0);
        assert!(categorical_equal(Some(&g), Some(&g)));
        assert!(!categorical_equal(Some(&g), Some(&p)));
        assert!(!categorical_equal(Some(&n), None));
        assert!(!categorical_equal(Some(&n), Some(&g)));
    }
}
