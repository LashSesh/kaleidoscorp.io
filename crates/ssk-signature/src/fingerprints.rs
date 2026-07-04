//! Protocol fingerprint layers — Chameleon `fingerprints`.
//!
//! Five layers (http_surface, http_header_order, body_schema, transport_timing,
//! linkability_surface) describe a surface's wire shape without exporting raw
//! header values or bodies. Each layer and the bundle carry a content digest;
//! the Chameleon kernel uses `sha256(json.dumps(...))`, this port uses
//! `ssk_types::digest_of` (Blake3) rendered as hex. Digest *values* differ from
//! Python, but the equal/unequal relation the kernel's comparisons rely on is
//! preserved, and the kernel's tests assert relations, never hex.

use serde::Serialize;
use ssk_types::{digest_of, HashAlg};

use crate::object::SurfaceObject;
use crate::url::urlparse;
use crate::value::{bucket, Dimension, FeatureValue, OrderedMap, Value};

/// Static description of one fingerprint layer.
#[derive(Clone, Debug, PartialEq)]
pub struct FingerprintLayerSpec {
    pub name: &'static str,
    pub category: &'static str,
    pub features: &'static [&'static str],
    pub description: &'static str,
}

/// The five layer specs, in canonical order.
#[must_use]
pub fn fingerprint_layer_specs() -> Vec<FingerprintLayerSpec> {
    vec![
        FingerprintLayerSpec {
            name: "http_surface",
            category: "protocol",
            features: &[
                "method",
                "status_class",
                "content_type_family",
                "request_header_count",
                "response_header_count",
                "path_depth",
                "query_key_count",
            ],
            description: "HTTP method/status/header-count/path/query surface.",
        },
        FingerprintLayerSpec {
            name: "http_header_order",
            category: "wire_shape",
            features: &[
                "request_order_digest",
                "response_order_digest",
                "first_response_header",
                "last_response_header",
                "response_order_len",
            ],
            description: "Header ordering surface without exporting raw header values.",
        },
        FingerprintLayerSpec {
            name: "body_schema",
            category: "payload",
            features: &[
                "schema_kind",
                "schema_digest",
                "schema_depth",
                "body_length_bucket",
                "body_truncated",
            ],
            description: "Payload schema and size bucket surface.",
        },
        FingerprintLayerSpec {
            name: "transport_timing",
            category: "transport",
            features: &[
                "scheme",
                "host_ref",
                "host_label_count",
                "port_class",
                "duration_bucket",
            ],
            description: "Transport-facing timing and endpoint-class surface.",
        },
        FingerprintLayerSpec {
            name: "linkability_surface",
            category: "privacy",
            features: &[
                "request_sensitive_header_count",
                "response_sensitive_header_count",
                "request_sensitive_digest",
                "response_sensitive_digest",
                "has_cookie_surface",
            ],
            description: "Sensitive-header and cookie-linkability surface.",
        },
    ]
}

/// Canonical layer names, in order.
#[must_use]
pub fn fingerprint_layer_names() -> Vec<&'static str> {
    fingerprint_layer_specs()
        .into_iter()
        .map(|s| s.name)
        .collect()
}

fn stable_hex(value: &impl Serialize) -> String {
    digest_of(value, HashAlg::Blake3)
        .expect("fingerprint payloads are serializable")
        .to_hex()
}

/// One fingerprint layer's values.
#[derive(Clone, Debug, PartialEq)]
pub struct ProtocolFingerprint {
    pub layer: String,
    pub values: Dimension,
}

impl ProtocolFingerprint {
    #[must_use]
    pub fn digest(&self) -> String {
        #[derive(Serialize)]
        struct Payload<'a> {
            layer: &'a str,
            values: &'a Dimension,
        }
        stable_hex(&Payload {
            layer: &self.layer,
            values: &self.values,
        })
    }
}

/// Coverage of expected layers for a bundle.
#[derive(Clone, Debug, PartialEq)]
pub struct FingerprintCoverage {
    pub layer_count: usize,
    pub layers: Vec<String>,
    pub missing_layers: Vec<String>,
    pub bundle_digest: String,
}

/// The result of comparing two bundles layer-by-layer.
#[derive(Clone, Debug, PartialEq)]
pub struct FingerprintBundleComparison {
    pub left_digest: String,
    pub right_digest: String,
    pub changed_layers: Vec<String>,
    pub unchanged_layers: Vec<String>,
    pub missing_left: Vec<String>,
    pub missing_right: Vec<String>,
}

/// A bundle of protocol fingerprints for one surface.
#[derive(Clone, Debug, PartialEq)]
pub struct FingerprintBundle {
    pub fingerprints: Vec<ProtocolFingerprint>,
}

impl FingerprintBundle {
    #[must_use]
    pub fn digest(&self) -> String {
        #[derive(Serialize)]
        struct Entry<'a> {
            layer: &'a str,
            digest: String,
        }
        let entries: Vec<Entry> = self
            .fingerprints
            .iter()
            .map(|fp| Entry {
                layer: &fp.layer,
                digest: fp.digest(),
            })
            .collect();
        stable_hex(&entries)
    }

    /// Layer name → values, feeding the signature's fingerprint dimensions.
    #[must_use]
    pub fn as_dimensions(&self) -> Vec<(String, Dimension)> {
        self.fingerprints
            .iter()
            .map(|fp| (fp.layer.clone(), fp.values.clone()))
            .collect()
    }

    #[must_use]
    pub fn layer(&self, name: &str) -> Option<&ProtocolFingerprint> {
        self.fingerprints.iter().find(|fp| fp.layer == name)
    }

    #[must_use]
    pub fn layer_digests(&self) -> Vec<(String, String)> {
        self.fingerprints
            .iter()
            .map(|fp| (fp.layer.clone(), fp.digest()))
            .collect()
    }

    #[must_use]
    pub fn coverage(&self) -> FingerprintCoverage {
        let mut layers: Vec<String> = self
            .fingerprints
            .iter()
            .map(|fp| fp.layer.clone())
            .collect();
        layers.sort();
        let missing_layers = fingerprint_layer_names()
            .into_iter()
            .filter(|expected| !layers.iter().any(|l| l == expected))
            .map(str::to_owned)
            .collect();
        FingerprintCoverage {
            layer_count: layers.len(),
            layers,
            missing_layers,
            bundle_digest: self.digest(),
        }
    }
}

/// Compare two bundles by per-layer digest.
#[must_use]
pub fn compare_fingerprint_bundles(
    left: &FingerprintBundle,
    right: &FingerprintBundle,
) -> FingerprintBundleComparison {
    let left_layers = left.layer_digests();
    let right_layers = right.layer_digests();
    let get = |v: &[(String, String)], name: &str| {
        v.iter().find(|(l, _)| l == name).map(|(_, d)| d.clone())
    };

    let mut shared: Vec<String> = left_layers
        .iter()
        .map(|(l, _)| l.clone())
        .filter(|l| right_layers.iter().any(|(rl, _)| rl == l))
        .collect();
    shared.sort();

    let changed = shared
        .iter()
        .filter(|l| get(&left_layers, l) != get(&right_layers, l))
        .cloned()
        .collect();
    let unchanged = shared
        .iter()
        .filter(|l| get(&left_layers, l) == get(&right_layers, l))
        .cloned()
        .collect();
    let mut missing_left: Vec<String> = right_layers
        .iter()
        .map(|(l, _)| l.clone())
        .filter(|l| !left_layers.iter().any(|(ll, _)| ll == l))
        .collect();
    missing_left.sort();
    let mut missing_right: Vec<String> = left_layers
        .iter()
        .map(|(l, _)| l.clone())
        .filter(|l| !right_layers.iter().any(|(rl, _)| rl == l))
        .collect();
    missing_right.sort();

    FingerprintBundleComparison {
        left_digest: left.digest(),
        right_digest: right.digest(),
        changed_layers: changed,
        unchanged_layers: unchanged,
        missing_left,
        missing_right,
    }
}

// ---- surface introspection helpers (mirroring the Chameleon private fns) ----

fn headers_of(fields: &OrderedMap, name: &str) -> OrderedMap {
    match fields.get(name) {
        Some(Value::Object(m)) => m.clone(),
        _ => OrderedMap::new(),
    }
}

fn header_order(fields: &OrderedMap, order_key: &str, headers: &OrderedMap) -> Vec<String> {
    match fields.get(order_key) {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Text(s) => s.to_lowercase(),
                other => value_to_str(other).to_lowercase(),
            })
            .collect(),
        _ => headers.keys().map(str::to_lowercase).collect(),
    }
}

fn content_type_family(headers: &OrderedMap) -> String {
    let raw = headers
        .get("content-type")
        .or_else(|| headers.get("Content-Type"))
        .and_then(Value::as_text)
        .unwrap_or("")
        .to_lowercase();
    if raw.is_empty() {
        return "unknown".to_owned();
    }
    let head = raw.split(';').next().unwrap_or("").trim().to_owned();
    if head.is_empty() {
        "unknown".to_owned()
    } else {
        head
    }
}

fn value_to_str(v: &Value) -> String {
    match v {
        Value::Text(s) => s.clone(),
        Value::Num(n) => format_number(*n),
        Value::Bool(b) => {
            if *b {
                "True".to_owned()
            } else {
                "False".to_owned()
            }
        }
        Value::Null => "None".to_owned(),
        _ => String::new(),
    }
}

// Render a float the way the surfaces need for a length proxy; integral values
// print without a trailing ".0" only where it does not affect a bucketed length.
fn format_number(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

fn status_class(fields: &OrderedMap) -> i64 {
    let status = fields
        .get("status")
        .or_else(|| fields.get("status_code"))
        .and_then(Value::as_number);
    match status {
        Some(v) => (v as i64) / 100,
        None => -1,
    }
}

// ---- body schema (Chameleon `_body_schema` / `_schema_depth`) ----

fn body_schema(value: &Value, depth: usize) -> Value {
    if depth > 6 {
        return schema_node("max_depth", vec![]);
    }
    match value {
        Value::Text(s) => {
            // A string body that itself is JSON is recursed into.
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(s) {
                body_schema(&json_to_value(&parsed), depth + 1)
            } else {
                schema_node(
                    "text",
                    vec![(
                        "length_bucket",
                        Value::Num(bucket(Some(s.chars().count() as f64), 512, 20) as f64),
                    )],
                )
            }
        }
        Value::Object(map) => {
            let mut keys: Vec<String> = map.keys().map(str::to_lowercase).collect();
            keys.sort();
            let mut children = OrderedMap::new();
            let mut sorted_pairs: Vec<(&str, &Value)> = map.iter().collect();
            sorted_pairs.sort_by_key(|(k, _)| k.to_lowercase());
            for (k, v) in sorted_pairs.into_iter().take(24) {
                children.insert(k.to_lowercase(), body_schema(v, depth + 1));
            }
            schema_node(
                "object",
                vec![
                    (
                        "keys",
                        Value::Array(keys.into_iter().map(Value::Text).collect()),
                    ),
                    ("children", Value::Object(children)),
                ],
            )
        }
        Value::Array(items) => {
            let samples: Vec<Value> = items
                .iter()
                .take(8)
                .map(|i| body_schema(i, depth + 1))
                .collect();
            schema_node(
                "array",
                vec![
                    (
                        "length_bucket",
                        Value::Num(bucket(Some(items.len() as f64), 10, 20) as f64),
                    ),
                    ("items", Value::Array(samples)),
                ],
            )
        }
        Value::Null => schema_node("null", vec![]),
        Value::Bool(_) => schema_node("bool", vec![]),
        Value::Num(_) => schema_node("number", vec![]),
    }
}

fn schema_node(kind: &str, extra: Vec<(&str, Value)>) -> Value {
    let mut m = OrderedMap::new();
    m.insert("kind", Value::Text(kind.to_owned()));
    for (k, v) in extra {
        m.insert(k, v);
    }
    Value::Object(m)
}

fn schema_depth(schema: &Value) -> i64 {
    let Some(obj) = schema.as_object() else {
        return 1;
    };
    if let Some(Value::Object(children)) = obj.get("children") {
        if !children.is_empty() {
            let max = children
                .iter()
                .filter_map(|(_, c)| c.as_object().map(|_| schema_depth(c)))
                .max()
                .unwrap_or(0);
            return 1 + max;
        }
    }
    if let Some(Value::Array(items)) = obj.get("items") {
        if !items.is_empty() {
            let max = items
                .iter()
                .filter_map(|i| i.as_object().map(|_| schema_depth(i)))
                .max()
                .unwrap_or(0);
            return 1 + max;
        }
    }
    1
}

fn json_to_value(j: &serde_json::Value) -> Value {
    match j {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => Value::Num(n.as_f64().unwrap_or(0.0)),
        serde_json::Value::String(s) => Value::Text(s.clone()),
        serde_json::Value::Array(a) => Value::Array(a.iter().map(json_to_value).collect()),
        serde_json::Value::Object(o) => {
            let mut m = OrderedMap::new();
            for (k, v) in o {
                m.insert(k.clone(), json_to_value(v));
            }
            Value::Object(m)
        }
    }
}

const SENSITIVE_HEADER_NAMES: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-forwarded-for",
    "forwarded",
];

fn sorted_intersection(order: &[String]) -> Vec<String> {
    let mut hits: Vec<String> = order
        .iter()
        .filter(|h| SENSITIVE_HEADER_NAMES.contains(&h.as_str()))
        .cloned()
        .collect();
    hits.sort();
    hits.dedup();
    hits
}

/// Extract the five-layer fingerprint bundle from a surface (Chameleon
/// `extract_fingerprint_bundle`). Reads the *original* (pre-canonical) fields,
/// as the kernel does.
#[must_use]
pub fn extract_fingerprint_bundle(obj: &SurfaceObject) -> FingerprintBundle {
    let fields = &obj.fields;
    let response_headers = headers_of(fields, "headers");
    let request_headers = headers_of(fields, "request_headers");
    let response_order = header_order(fields, "response_header_order", &response_headers);
    let request_order = header_order(fields, "request_header_order", &request_headers);

    let url = fields.get("url").and_then(Value::as_text).unwrap_or("");
    let parsed = urlparse(url);
    let mut query_keys: Vec<String> = parsed.query_keys();
    query_keys.sort();

    let sclass = status_class(fields);

    let body_value = fields.get("body");
    let body_present = body_value.is_some_and(|v| !v.is_empty_bodylike());
    let schema = if body_present {
        body_schema(body_value.unwrap(), 0)
    } else {
        schema_node("absent", vec![])
    };
    let body_length = fields
        .get("body_length")
        .and_then(Value::as_number)
        .unwrap_or_else(|| {
            if body_present {
                value_to_str(body_value.unwrap()).chars().count() as f64
            } else {
                0.0
            }
        });
    let body_truncated = matches!(fields.get("body_truncated"), Some(v) if truthy(v));

    let duration = fields
        .get("duration_ms")
        .and_then(Value::as_number)
        .or_else(|| {
            obj.timing_model
                .get("duration_ms")
                .and_then(Value::as_number)
        })
        .unwrap_or(-1.0);

    let response_sensitive = sorted_intersection(&response_order);
    let request_sensitive = sorted_intersection(&request_order);
    let has_cookie = request_sensitive
        .iter()
        .chain(response_sensitive.iter())
        .any(|h| h == "cookie" || h == "set-cookie");

    let method = fields
        .get("method")
        .and_then(Value::as_text)
        .unwrap_or("unknown")
        .to_uppercase();

    let http_surface = dim([
        ("method", FeatureValue::text(method)),
        ("status_class", FeatureValue::num(sclass as f64)),
        (
            "content_type_family",
            FeatureValue::text(content_type_family(&response_headers)),
        ),
        (
            "request_header_count",
            FeatureValue::num(request_headers.len() as f64),
        ),
        (
            "response_header_count",
            FeatureValue::num(response_headers.len() as f64),
        ),
        ("path_depth", FeatureValue::num(parsed.path_depth() as f64)),
        (
            "query_key_count",
            FeatureValue::num(query_keys.len() as f64),
        ),
    ]);

    let http_header_order = dim([
        (
            "request_order_digest",
            FeatureValue::text(stable_hex(&request_order)),
        ),
        (
            "response_order_digest",
            FeatureValue::text(stable_hex(&response_order)),
        ),
        (
            "first_response_header",
            FeatureValue::text(response_order.first().cloned().unwrap_or_default()),
        ),
        (
            "last_response_header",
            FeatureValue::text(response_order.last().cloned().unwrap_or_default()),
        ),
        (
            "response_order_len",
            FeatureValue::num(response_order.len() as f64),
        ),
    ]);

    let body_schema_layer = dim([
        (
            "schema_kind",
            FeatureValue::text(
                schema
                    .as_object()
                    .and_then(|o| o.get("kind"))
                    .and_then(Value::as_text)
                    .unwrap_or("unknown")
                    .to_owned(),
            ),
        ),
        ("schema_digest", FeatureValue::text(stable_hex(&schema))),
        (
            "schema_depth",
            FeatureValue::num(schema_depth(&schema) as f64),
        ),
        (
            "body_length_bucket",
            FeatureValue::num(bucket(Some(body_length), 512, 50) as f64),
        ),
        (
            "body_truncated",
            FeatureValue::num(if body_truncated { 1.0 } else { 0.0 }),
        ),
    ]);

    let host = parsed.hostname.clone();
    let transport_timing = dim([
        (
            "scheme",
            FeatureValue::text(if parsed.scheme.is_empty() {
                "unknown".to_owned()
            } else {
                parsed.scheme.clone()
            }),
        ),
        (
            "host_ref",
            FeatureValue::text(stable_hex(&host).chars().take(16).collect::<String>()),
        ),
        (
            "host_label_count",
            FeatureValue::num(parsed.host_label_count() as f64),
        ),
        ("port_class", FeatureValue::text(parsed.port_class())),
        (
            "duration_bucket",
            FeatureValue::num(bucket(Some(duration), 100, 50) as f64),
        ),
    ]);

    let linkability_surface = dim([
        (
            "request_sensitive_header_count",
            FeatureValue::num(request_sensitive.len() as f64),
        ),
        (
            "response_sensitive_header_count",
            FeatureValue::num(response_sensitive.len() as f64),
        ),
        (
            "request_sensitive_digest",
            FeatureValue::text(stable_hex(&request_sensitive)),
        ),
        (
            "response_sensitive_digest",
            FeatureValue::text(stable_hex(&response_sensitive)),
        ),
        (
            "has_cookie_surface",
            FeatureValue::num(if has_cookie { 1.0 } else { 0.0 }),
        ),
    ]);

    FingerprintBundle {
        fingerprints: vec![
            ProtocolFingerprint {
                layer: "http_surface".to_owned(),
                values: http_surface,
            },
            ProtocolFingerprint {
                layer: "http_header_order".to_owned(),
                values: http_header_order,
            },
            ProtocolFingerprint {
                layer: "body_schema".to_owned(),
                values: body_schema_layer,
            },
            ProtocolFingerprint {
                layer: "transport_timing".to_owned(),
                values: transport_timing,
            },
            ProtocolFingerprint {
                layer: "linkability_surface".to_owned(),
                values: linkability_surface,
            },
        ],
    }
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::Num(n) => *n != 0.0,
        Value::Text(s) => !s.is_empty(),
        Value::Null => false,
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
    }
}

fn dim<const N: usize>(entries: [(&str, FeatureValue); N]) -> Dimension {
    entries
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
}
