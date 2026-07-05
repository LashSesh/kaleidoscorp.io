//! The [`SurfaceObject`] — a payload/protocol/log/trace treated as an abstract
//! surface. Ported from Chameleon `objects.SurfaceObject` (a frozen dataclass);
//! here an immutable value whose `with_*` builders return fresh copies with a
//! provenance note appended, matching the kernel's copy-on-write discipline.

use serde::{Deserialize, Serialize};

use crate::value::{OrderedMap, Value};

/// A payload/protocol/log/trace object treated as an abstract surface.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SurfaceObject {
    pub media_type: String,
    pub fields: OrderedMap,
    /// Declared field order (Chameleon `ordering`), captured separately from
    /// `fields` so an operator can normalize field content without losing the
    /// as-observed order.
    pub ordering: Vec<String>,
    pub timing_model: OrderedMap,
    pub entropy_profile: OrderedMap,
    pub structure_graph: OrderedMap,
    pub declared_protocol_class: String,
    pub provenance: OrderedMap,
}

impl SurfaceObject {
    /// Construct a surface with the minimum required attributes; `ordering`
    /// defaults to the field insertion order, everything else empty.
    #[must_use]
    pub fn new(media_type: impl Into<String>, fields: OrderedMap) -> Self {
        let ordering = fields.keys().map(str::to_owned).collect();
        SurfaceObject {
            media_type: media_type.into(),
            fields,
            ordering,
            timing_model: OrderedMap::new(),
            entropy_profile: OrderedMap::new(),
            structure_graph: OrderedMap::new(),
            declared_protocol_class: "unknown".to_owned(),
            provenance: OrderedMap::new(),
        }
    }

    #[must_use]
    pub fn with_declared_protocol_class(mut self, class: impl Into<String>) -> Self {
        self.declared_protocol_class = class.into();
        self
    }

    #[must_use]
    pub fn with_timing_model(mut self, timing: OrderedMap) -> Self {
        self.timing_model = timing;
        self
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: OrderedMap) -> Self {
        self.provenance = provenance;
        self
    }

    /// Return a copy with replaced fields; `ordering` follows the new field
    /// order and an optional provenance note is appended. Mirrors
    /// `SurfaceObject.with_fields`.
    #[must_use]
    pub fn with_fields(&self, new_fields: OrderedMap, provenance_note: Option<&str>) -> Self {
        let ordering = new_fields.keys().map(str::to_owned).collect();
        SurfaceObject {
            media_type: self.media_type.clone(),
            fields: new_fields,
            ordering,
            timing_model: self.timing_model.clone(),
            entropy_profile: self.entropy_profile.clone(),
            structure_graph: self.structure_graph.clone(),
            declared_protocol_class: self.declared_protocol_class.clone(),
            provenance: append_note(self.provenance.clone(), provenance_note),
        }
    }

    /// Return a copy with a replaced timing model; mirrors
    /// `SurfaceObject.with_timing`.
    #[must_use]
    pub fn with_timing(&self, new_timing: OrderedMap, provenance_note: Option<&str>) -> Self {
        SurfaceObject {
            media_type: self.media_type.clone(),
            fields: self.fields.clone(),
            ordering: self.ordering.clone(),
            timing_model: new_timing,
            entropy_profile: self.entropy_profile.clone(),
            structure_graph: self.structure_graph.clone(),
            declared_protocol_class: self.declared_protocol_class.clone(),
            provenance: append_note(self.provenance.clone(), provenance_note),
        }
    }
}

fn append_note(mut provenance: OrderedMap, note: Option<&str>) -> OrderedMap {
    let Some(note) = note else {
        return provenance;
    };
    let mut notes = match provenance.get("notes") {
        Some(Value::Array(existing)) => existing.clone(),
        _ => Vec::new(),
    };
    notes.push(Value::Text(note.to_owned()));
    provenance.insert("notes", Value::Array(notes));
    provenance
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SurfaceObject {
        let fields = OrderedMap::from_iter([
            ("method".to_owned(), Value::Text("GET".to_owned())),
            ("status".to_owned(), Value::Num(200.0)),
        ]);
        SurfaceObject::new("application/trace+json", fields).with_declared_protocol_class("http")
    }

    #[test]
    fn new_captures_declared_order() {
        let obj = sample();
        assert_eq!(obj.ordering, vec!["method", "status"]);
        assert_eq!(obj.declared_protocol_class, "http");
    }

    #[test]
    fn with_fields_appends_provenance_note() {
        let obj = sample();
        let replaced = obj.with_fields(
            OrderedMap::from_iter([("method".to_owned(), Value::Text("POST".to_owned()))]),
            Some("sort_fields"),
        );
        assert_eq!(
            replaced.fields.get("method"),
            Some(&Value::Text("POST".to_owned()))
        );
        assert_eq!(replaced.ordering, vec!["method"]);
        let notes = replaced.provenance.get("notes").unwrap();
        assert_eq!(
            notes,
            &Value::Array(vec![Value::Text("sort_fields".to_owned())])
        );
        // original is untouched (copy-on-write)
        assert_eq!(
            obj.fields.get("method"),
            Some(&Value::Text("GET".to_owned()))
        );
    }
}
