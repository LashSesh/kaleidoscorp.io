//! Transform operators — Chameleon `transform_operator` + `operators`.
//!
//! An operator maps a surface to a transformed surface and reports, as typed
//! residues, what it did not preserve. Four operators are ported: field sort,
//! trace-shape normalization, identifier redaction, and timing bucketing. Each
//! is total, deterministic, and semantics-annotated.

use crate::object::SurfaceObject;
use crate::residue::{ResidueReport, ResidueSeverity};
use crate::value::{OrderedMap, Value};

/// The result of applying a [`TransformOperator`].
#[derive(Clone, Debug, PartialEq)]
pub struct TransformResult {
    pub transformed: SurfaceObject,
    pub residue_report: ResidueReport,
    pub explanation: String,
}

/// A surface-to-surface transform that reports its residues.
pub trait TransformOperator {
    fn name(&self) -> &str;
    fn risk_level(&self) -> &str;
    fn preserves_semantics(&self) -> bool;
    fn apply(&self, obj: &SurfaceObject) -> TransformResult;
}

/// Sort top-level fields for canonical-shape comparison.
#[derive(Clone, Copy, Debug, Default)]
pub struct SortFieldsOperator;

impl TransformOperator for SortFieldsOperator {
    fn name(&self) -> &str {
        "sort_fields"
    }
    fn risk_level(&self) -> &str {
        "low"
    }
    fn preserves_semantics(&self) -> bool {
        true
    }
    fn apply(&self, obj: &SurfaceObject) -> TransformResult {
        let mut keys: Vec<String> = obj.fields.keys().map(str::to_owned).collect();
        keys.sort();
        let mut new_fields = OrderedMap::new();
        for k in keys {
            if let Some(v) = obj.fields.get(&k) {
                new_fields.insert(k, v.clone());
            }
        }
        let residue =
            ResidueReport::new().add("ordering", ResidueSeverity::Low, "field order normalized");
        TransformResult {
            transformed: obj.with_fields(new_fields, Some(self.name())),
            residue_report: residue,
            explanation: "Sorted top-level fields for canonical shape comparison.".to_owned(),
        }
    }
}

/// Normalize field names (strip, lowercase, `-`→`_`) without touching values.
#[derive(Clone, Copy, Debug, Default)]
pub struct NormalizeTraceShapeOperator;

impl TransformOperator for NormalizeTraceShapeOperator {
    fn name(&self) -> &str {
        "normalize_trace_shape"
    }
    fn risk_level(&self) -> &str {
        "low"
    }
    fn preserves_semantics(&self) -> bool {
        true
    }
    fn apply(&self, obj: &SurfaceObject) -> TransformResult {
        let mut new_fields = OrderedMap::new();
        for (key, value) in obj.fields.iter() {
            let normalized = key.trim().to_lowercase().replace('-', "_");
            new_fields.insert(normalized, value.clone());
        }
        let residue = ResidueReport::new().add(
            "shape",
            ResidueSeverity::Low,
            "field names normalized for trace comparison",
        );
        TransformResult {
            transformed: obj.with_fields(new_fields, Some(self.name())),
            residue_report: residue,
            explanation: "Normalized trace field names without changing values.".to_owned(),
        }
    }
}

/// Redact identifier-bearing fields for authorized analysis.
#[derive(Clone, Debug)]
pub struct RedactIdentifierFieldsOperator {
    pub placeholder: String,
    pub sensitive_key_fragments: Vec<String>,
}

impl Default for RedactIdentifierFieldsOperator {
    fn default() -> Self {
        RedactIdentifierFieldsOperator {
            placeholder: "<redacted>".to_owned(),
            sensitive_key_fragments: [
                "authorization",
                "cookie",
                "token",
                "api_key",
                "session",
                "client_ip",
                "remote_addr",
                "x_forwarded_for",
                "x-forwarded-for",
                "user_id",
                "device_id",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        }
    }
}

impl RedactIdentifierFieldsOperator {
    fn key_is_sensitive(&self, key: &str) -> bool {
        let key_l = key.to_lowercase();
        self.sensitive_key_fragments
            .iter()
            .any(|f| key_l.contains(f.as_str()))
    }

    fn redact(&self, value: &Value, key: &str) -> (Value, usize) {
        if self.key_is_sensitive(key) {
            return (Value::Text(self.placeholder.clone()), 1);
        }
        match value {
            Value::Object(map) => {
                let mut out = OrderedMap::new();
                let mut count = 0;
                for (k, v) in map.iter() {
                    let (nv, n) = self.redact(v, k);
                    out.insert(k, nv);
                    count += n;
                }
                (Value::Object(out), count)
            }
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                let mut count = 0;
                for item in items {
                    let (nv, n) = self.redact(item, key);
                    out.push(nv);
                    count += n;
                }
                (Value::Array(out), count)
            }
            other => (other.clone(), 0),
        }
    }
}

impl TransformOperator for RedactIdentifierFieldsOperator {
    fn name(&self) -> &str {
        "redact_identifier_fields"
    }
    fn risk_level(&self) -> &str {
        "medium"
    }
    fn preserves_semantics(&self) -> bool {
        false
    }
    fn apply(&self, obj: &SurfaceObject) -> TransformResult {
        let mut new_fields = OrderedMap::new();
        let mut count = 0;
        for (key, value) in obj.fields.iter() {
            let (nv, n) = self.redact(value, key);
            new_fields.insert(key, nv);
            count += n;
        }
        let severity = if count > 0 {
            ResidueSeverity::Medium
        } else {
            ResidueSeverity::Low
        };
        let mut residue = ResidueReport::new().add(
            "linkability",
            severity,
            &format!("redacted {count} identifier-bearing fields"),
        );
        if count > 0 {
            residue = residue.add(
                "semantic",
                ResidueSeverity::Medium,
                "redaction may remove semantics required for exact replay",
            );
        }
        TransformResult {
            transformed: obj.with_fields(new_fields, Some(self.name())),
            residue_report: residue,
            explanation: "Redacted identifier-bearing fields for authorized analysis.".to_owned(),
        }
    }
}

/// Bucket timing values to analyze timing-surface stability.
#[derive(Clone, Copy, Debug)]
pub struct BucketTimingOperator {
    pub bucket_ms: i64,
}

impl Default for BucketTimingOperator {
    fn default() -> Self {
        BucketTimingOperator { bucket_ms: 100 }
    }
}

impl TransformOperator for BucketTimingOperator {
    fn name(&self) -> &str {
        "bucket_timing"
    }
    fn risk_level(&self) -> &str {
        "medium"
    }
    fn preserves_semantics(&self) -> bool {
        true
    }
    fn apply(&self, obj: &SurfaceObject) -> TransformResult {
        let mut timing = obj.timing_model.clone();
        let mut changed = 0;
        for key in ["interarrival_ms", "delta_ms", "duration_ms", "jitter_ms"] {
            if let Some(raw) = timing.get(key).and_then(Value::as_number) {
                let bucketed = (raw / self.bucket_ms as f64).floor() * self.bucket_ms as f64;
                timing.insert(key, Value::Num(bucketed));
                changed += 1;
            }
        }
        let severity = if changed > 0 {
            ResidueSeverity::Medium
        } else {
            ResidueSeverity::Low
        };
        let residue = ResidueReport::new().add(
            "timing",
            severity,
            &format!("bucketed {changed} timing fields"),
        );
        TransformResult {
            transformed: obj.with_timing(timing, Some(self.name())),
            residue_report: residue,
            explanation: "Bucketed timing values to analyze timing-surface stability.".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj() -> SurfaceObject {
        let headers = OrderedMap::from_iter([
            ("User-Agent".to_owned(), Value::Text("Demo/1.0".to_owned())),
            (
                "Authorization".to_owned(),
                Value::Text("Bearer local".to_owned()),
            ),
        ]);
        let fields = OrderedMap::from_iter([
            ("method".to_owned(), Value::Text("GET".to_owned())),
            ("headers".to_owned(), Value::Object(headers)),
            ("client_ip".to_owned(), Value::Text("192.0.2.10".to_owned())),
        ]);
        let timing = OrderedMap::from_iter([
            ("interarrival_ms".to_owned(), Value::Num(123.0)),
            ("jitter_ms".to_owned(), Value::Num(17.0)),
        ]);
        SurfaceObject::new("application/trace+json", fields)
            .with_declared_protocol_class("http")
            .with_timing_model(timing)
    }

    #[test]
    fn sort_fields_orders_keys() {
        let r = SortFieldsOperator.apply(&obj());
        assert_eq!(
            r.transformed.fields.keys().collect::<Vec<_>>(),
            vec!["client_ip", "headers", "method"]
        );
        assert!(!r.residue_report.by_surface("ordering").is_empty());
    }

    // Chameleon test_redaction_creates_linkability_and_semantic_residue.
    #[test]
    fn redaction_creates_linkability_and_semantic_residue() {
        let r = RedactIdentifierFieldsOperator::default().apply(&obj());
        assert!(!r.residue_report.by_surface("linkability").is_empty());
        assert!(!r.residue_report.by_surface("semantic").is_empty());
        // the nested Authorization header and top-level client_ip are redacted
        assert_eq!(
            r.transformed.fields.get("client_ip"),
            Some(&Value::Text("<redacted>".to_owned()))
        );
        let headers = r
            .transformed
            .fields
            .get("headers")
            .unwrap()
            .as_object()
            .unwrap();
        assert_eq!(
            headers.get("Authorization"),
            Some(&Value::Text("<redacted>".to_owned()))
        );
        assert_eq!(
            headers.get("User-Agent"),
            Some(&Value::Text("Demo/1.0".to_owned()))
        );
    }

    #[test]
    fn bucket_timing_buckets_and_reports_timing_residue() {
        let r = BucketTimingOperator { bucket_ms: 100 }.apply(&obj());
        assert_eq!(
            r.transformed.timing_model.get("interarrival_ms"),
            Some(&Value::Num(100.0))
        );
        assert_eq!(
            r.transformed.timing_model.get("jitter_ms"),
            Some(&Value::Num(0.0))
        );
        assert!(!r.residue_report.by_surface("timing").is_empty());
    }

    #[test]
    fn normalize_shape_renames_without_touching_values() {
        let fields =
            OrderedMap::from_iter([(" Content-Type ".to_owned(), Value::Text("json".to_owned()))]);
        let obj = SurfaceObject::new("application/trace+json", fields);
        let r = NormalizeTraceShapeOperator.apply(&obj);
        assert_eq!(
            r.transformed.fields.get("content_type"),
            Some(&Value::Text("json".to_owned()))
        );
    }
}
