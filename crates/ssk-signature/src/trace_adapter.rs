//! Trace import adapter — Chameleon `adapters/trace_adapter`.
//!
//! Imports owned/authorized trace records (records, JSONL, JSON, CSV, HAR-like)
//! into [`SurfaceObject`]s. Raw packet-capture parsing is out of scope for the
//! signature layer. Every import is gated on an [`AuthorizationManifest`] valid
//! for `offline_analysis`.

use std::path::Path;

use crate::object::SurfaceObject;
use crate::policy::AuthorizationManifest;
use crate::value::{value_from_json, OrderedMap, Value};

/// Errors the trace importer can return.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TraceImportError {
    #[error("valid trace analysis authorization is required")]
    Authorization,
    #[error("trace io error: {0}")]
    Io(String),
    #[error("trace parse error: {0}")]
    Parse(String),
}

const TIMING_KEYS: &[&str] = &["interarrival_ms", "delta_ms", "duration_ms", "jitter_ms"];

/// Import adapter for owned/authorized trace records.
#[derive(Clone, Debug)]
pub struct TraceAdapter {
    authorization: AuthorizationManifest,
}

impl TraceAdapter {
    /// Build the adapter, requiring authorization valid for `offline_analysis`.
    ///
    /// # Errors
    /// [`TraceImportError::Authorization`] if the manifest is not valid.
    pub fn new(authorization: AuthorizationManifest) -> Result<Self, TraceImportError> {
        if !authorization.is_valid_for("offline_analysis") {
            return Err(TraceImportError::Authorization);
        }
        Ok(TraceAdapter { authorization })
    }

    fn provenance(&self, index: usize) -> OrderedMap {
        let mut p = OrderedMap::new();
        p.insert(
            "source_name",
            Value::Text(self.authorization.source_name.clone()),
        );
        p.insert(
            "owner_or_controller",
            Value::Text(self.authorization.owner_or_controller.clone()),
        );
        p.insert("record_index", Value::Num(index as f64));
        if let Some(ev) = &self.authorization.evidence_ref {
            p.insert("authorization_evidence_ref", Value::Text(ev.clone()));
        }
        p
    }

    /// Convert a batch of record maps into surfaces.
    #[must_use]
    pub fn from_records(&self, records: &[OrderedMap], media_type: &str) -> Vec<SurfaceObject> {
        records
            .iter()
            .enumerate()
            .map(|(index, record)| {
                let mut timing = OrderedMap::new();
                for key in TIMING_KEYS {
                    if let Some(v) = record.get(key) {
                        timing.insert(*key, v.clone());
                    }
                }
                let declared = record
                    .get("protocol")
                    .or_else(|| record.get("declared_protocol_class"))
                    .and_then(Value::as_text)
                    .unwrap_or("unknown")
                    .to_lowercase();
                SurfaceObject::new(media_type, record.clone())
                    .with_declared_protocol_class(declared)
                    .with_timing_model(timing)
                    .with_provenance(self.provenance(index))
            })
            .collect()
    }

    /// Import a JSON array / `{"records": [...]}` / HAR file.
    ///
    /// # Errors
    /// [`TraceImportError::Io`] / [`TraceImportError::Parse`] on failure.
    pub fn from_json_file(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<Vec<SurfaceObject>, TraceImportError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| TraceImportError::Io(e.to_string()))?;
        let data: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| TraceImportError::Parse(e.to_string()))?;
        if data.get("log").is_some() {
            return self.from_har_value(&data);
        }
        let list = if let Some(records) = data.get("records") {
            records.clone()
        } else {
            data
        };
        let array = list.as_array().ok_or_else(|| {
            TraceImportError::Parse(
                "JSON trace file must contain a list or {records:[...]}".to_owned(),
            )
        })?;
        Ok(self.from_records(&json_array_to_records(array), "application/trace+json"))
    }

    /// Import a JSONL file (one record object per line).
    ///
    /// # Errors
    /// [`TraceImportError::Io`] / [`TraceImportError::Parse`] on failure.
    pub fn from_jsonl_file(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<Vec<SurfaceObject>, TraceImportError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| TraceImportError::Io(e.to_string()))?;
        let mut records = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let v: serde_json::Value =
                serde_json::from_str(line).map_err(|e| TraceImportError::Parse(e.to_string()))?;
            records.push(json_object_to_record(&v));
        }
        Ok(self.from_records(&records, "application/trace+json"))
    }

    /// Import a HAR-like dictionary.
    ///
    /// # Errors
    /// [`TraceImportError::Parse`] if `log.entries` is missing.
    pub fn from_har_value(
        &self,
        data: &serde_json::Value,
    ) -> Result<Vec<SurfaceObject>, TraceImportError> {
        let entries = data
            .get("log")
            .and_then(|l| l.get("entries"))
            .and_then(|e| e.as_array())
            .ok_or_else(|| {
                TraceImportError::Parse("HAR-like data must contain log.entries".to_owned())
            })?;
        let mut records = Vec::new();
        for entry in entries {
            let request = entry
                .get("request")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let response = entry
                .get("response")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let mut headers = OrderedMap::new();
            if let Some(hs) = request.get("headers").and_then(|h| h.as_array()) {
                for h in hs {
                    if let (Some(name), value) =
                        (h.get("name").and_then(|n| n.as_str()), h.get("value"))
                    {
                        if !name.is_empty() {
                            headers.insert(
                                name,
                                Value::Text(
                                    value.and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                                ),
                            );
                        }
                    }
                }
            }
            let mut record = OrderedMap::new();
            record.insert("protocol", Value::Text("http".to_owned()));
            record.insert(
                "method",
                Value::Text(
                    request
                        .get("method")
                        .and_then(|m| m.as_str())
                        .unwrap_or("UNKNOWN")
                        .to_owned(),
                ),
            );
            record.insert(
                "url",
                Value::Text(
                    request
                        .get("url")
                        .and_then(|u| u.as_str())
                        .unwrap_or("")
                        .to_owned(),
                ),
            );
            record.insert("headers", Value::Object(headers));
            record.insert(
                "status",
                response
                    .get("status")
                    .map_or(Value::Text("unknown".to_owned()), value_from_json),
            );
            record.insert(
                "duration_ms",
                entry.get("time").map_or(Value::Num(-1.0), value_from_json),
            );
            records.push(record);
        }
        Ok(self.from_records(&records, "application/har+json"))
    }
}

fn json_object_to_record(value: &serde_json::Value) -> OrderedMap {
    match value_from_json(value) {
        Value::Object(m) => m,
        _ => OrderedMap::new(),
    }
}

fn json_array_to_records(array: &[serde_json::Value]) -> Vec<OrderedMap> {
    array.iter().map(json_object_to_record).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> AuthorizationManifest {
        AuthorizationManifest::new("owned-jsonl", "me", "self-owned")
            .with_allowed_uses(["offline_analysis"])
    }

    #[test]
    fn requires_valid_authorization() {
        let bad = AuthorizationManifest::new("", "", "").with_allowed_uses(Vec::<String>::new());
        assert_eq!(
            TraceAdapter::new(bad).unwrap_err(),
            TraceImportError::Authorization
        );
    }

    #[test]
    fn jsonl_importer() {
        let dir = std::env::temp_dir().join(format!("ssk-sig-trace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trace.jsonl");
        std::fs::write(
            &path,
            "{\"protocol\":\"http\",\"method\":\"GET\",\"interarrival_ms\":50}\n",
        )
        .unwrap();
        let objects = TraceAdapter::new(auth())
            .unwrap()
            .from_jsonl_file(&path)
            .unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].declared_protocol_class, "http");
        assert_eq!(
            objects[0].timing_model.get("interarrival_ms"),
            Some(&Value::Num(50.0))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn har_like_importer() {
        let har: serde_json::Value = serde_json::json!({
            "log": {"entries": [{
                "request": {"method": "GET", "url": "https://example.test",
                    "headers": [{"name": "User-Agent", "value": "Demo"}]},
                "response": {"status": 200},
                "time": 42
            }]}
        });
        let objects = TraceAdapter::new(auth())
            .unwrap()
            .from_har_value(&har)
            .unwrap();
        assert_eq!(
            objects[0].fields.get("method"),
            Some(&Value::Text("GET".to_owned()))
        );
        assert_eq!(objects[0].fields.get("status"), Some(&Value::Num(200.0)));
        assert_eq!(
            objects[0].timing_model.get("duration_ms"),
            Some(&Value::Num(42.0))
        );
    }
}
