//! Canonicalization — Chameleon `canonicalizer.canonicalize`.
//!
//! Recursively lowercases object keys, sorts them, and strips leading/trailing
//! whitespace from strings, then content-addresses the result. The Chameleon
//! kernel hashes `sha256(json.dumps(payload, sort_keys=True, ...))`; this port
//! takes the same canonical structure through `ssk_types::digest_of` (canonical
//! CBOR + Blake3) so the resulting id is a first-class `ssk_types::Digest`.

use serde::Serialize;
use ssk_types::{digest_of, Digest, HashAlg};

use crate::object::SurfaceObject;
use crate::value::{OrderedMap, Value};

/// A canonicalized surface: normalized fields plus a content-address digest.
#[derive(Clone, Debug, PartialEq)]
pub struct CanonicalObject {
    pub media_type: String,
    pub canonical_fields: OrderedMap,
    pub declared_protocol_class: String,
    pub digest: Digest,
}

#[derive(Serialize)]
struct CanonicalPayload<'a> {
    media_type: &'a str,
    declared_protocol_class: &'a str,
    fields: &'a OrderedMap,
}

fn normalize_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(normalize_map(map)),
        Value::Array(items) => Value::Array(items.iter().map(normalize_value).collect()),
        Value::Text(s) => Value::Text(s.trim().to_owned()),
        other => other.clone(),
    }
}

fn normalize_map(map: &OrderedMap) -> OrderedMap {
    // Lowercase keys, normalize values, then sort by the lowered key. A stable
    // sort keeps duplicate lowered keys in original order; `insert` then lets
    // the last of a duplicate group win its value while keeping first position
    // — matching Python's `{k.lower(): v for k in sorted(...)}` comprehension.
    let mut pairs: Vec<(String, Value)> = map
        .iter()
        .map(|(k, v)| (k.to_lowercase(), normalize_value(v)))
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = OrderedMap::new();
    for (k, v) in pairs {
        out.insert(k, v);
    }
    out
}

/// Canonicalize a surface object (Chameleon `canonicalize`).
#[must_use]
pub fn canonicalize(obj: &SurfaceObject) -> CanonicalObject {
    let canonical_fields = normalize_map(&obj.fields);
    let media_type = obj.media_type.trim().to_lowercase();
    let declared_protocol_class = obj.declared_protocol_class.trim().to_lowercase();
    let digest = digest_of(
        &CanonicalPayload {
            media_type: &media_type,
            declared_protocol_class: &declared_protocol_class,
            fields: &canonical_fields,
        },
        HashAlg::Blake3,
    )
    .expect("canonical payload is always serializable");
    CanonicalObject {
        media_type,
        canonical_fields,
        declared_protocol_class,
        digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj_with(fields: OrderedMap) -> SurfaceObject {
        SurfaceObject::new("Application/JSON", fields).with_declared_protocol_class("HTTP")
    }

    #[test]
    fn lowercases_and_sorts_keys_and_strips_strings() {
        let fields = OrderedMap::from_iter([
            ("Method".to_owned(), Value::Text("  GET ".to_owned())),
            ("Accept".to_owned(), Value::Text("x".to_owned())),
        ]);
        let c = canonicalize(&obj_with(fields));
        assert_eq!(c.media_type, "application/json");
        assert_eq!(c.declared_protocol_class, "http");
        // sorted: accept before method
        assert_eq!(
            c.canonical_fields.keys().collect::<Vec<_>>(),
            vec!["accept", "method"]
        );
        assert_eq!(
            c.canonical_fields.get("method"),
            Some(&Value::Text("GET".to_owned()))
        );
    }

    #[test]
    fn nested_objects_are_normalized_recursively() {
        let headers = OrderedMap::from_iter([
            (
                "Content-Type".to_owned(),
                Value::Text("application/json".to_owned()),
            ),
            ("Accept".to_owned(), Value::Text(" y ".to_owned())),
        ]);
        let fields = OrderedMap::from_iter([("Headers".to_owned(), Value::Object(headers))]);
        let c = canonicalize(&obj_with(fields));
        let inner = c
            .canonical_fields
            .get("headers")
            .unwrap()
            .as_object()
            .unwrap();
        assert_eq!(
            inner.keys().collect::<Vec<_>>(),
            vec!["accept", "content-type"]
        );
        assert_eq!(inner.get("accept"), Some(&Value::Text("y".to_owned())));
    }

    #[test]
    fn digest_is_deterministic_and_content_sensitive() {
        let a = canonicalize(&obj_with(OrderedMap::from_iter([(
            "k".to_owned(),
            Value::Num(1.0),
        )])));
        let b = canonicalize(&obj_with(OrderedMap::from_iter([(
            "k".to_owned(),
            Value::Num(1.0),
        )])));
        let c = canonicalize(&obj_with(OrderedMap::from_iter([(
            "k".to_owned(),
            Value::Num(2.0),
        )])));
        assert_eq!(a.digest, b.digest);
        assert_ne!(a.digest, c.digest);
    }
}
