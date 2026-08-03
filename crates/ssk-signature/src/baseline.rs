//! The persisted per-host signature baseline — the real ground truth
//! `ssk-system`'s signature gate diffs live traffic against.
//!
//! This module owns only the *type*: the schema this crate's `TargetProfile`
//! is written and read as once a caller establishes a baseline. It performs no
//! IO — `ssk-signature` stays a pure, no-IO crate, exactly as its own doc
//! comment (`lib.rs`) already states. The actual file (ProgramData location,
//! ACL, atomic write, schema-mismatch handling) belongs in whichever crate
//! already owns that convention (`ssk-netd-helper::store`'s
//! `PersistedState`/`FileReceiptStore` is the pattern to mirror, not
//! reinvent) — that wiring, and the CLI surface that establishes a baseline,
//! is tracked separately (`docs/WINDOWS_PRODUCT_ROADMAP.md` P5) and is not
//! part of this crate.
//!
//! # Why this exists at all
//!
//! `ssk-system`'s signature gate used to build its comparison [`TargetProfile`]
//! from the very observation it was about to gate
//! (`TargetProfile::new("system", sig.clone())` inside the same evaluation),
//! which makes every dimension distance `0.0` by construction — the gate was
//! trivially satisfiable, not merely hard to trip. [`PersistedBaseline`] is the
//! shape a *real*, previously-established baseline takes once a caller loads
//! one from durable storage and hands it to `ssk-system` as genuine ground
//! truth instead.

use serde::{Deserialize, Serialize};

use crate::target::TargetProfile;

/// The persisted baseline's schema version, so a future format change is
/// *detected*, not mis-decoded — mirrors `ssk_netd_helper::store`'s
/// `SNAPSHOT_SCHEMA` convention exactly.
pub const BASELINE_SCHEMA: u32 = 1;

/// The durable form of a per-host signature baseline.
///
/// `#[serde(deny_unknown_fields)]` for the same reason
/// `ssk_netd_helper::store::PersistedState` uses it: a field this build does
/// not know about should fail to decode, not be silently dropped.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedBaseline {
    /// Schema version so a future format change is detected, not mis-decoded.
    pub schema_version: u32,
    /// The real, previously established comparison ground truth.
    pub target: TargetProfile,
    /// When this baseline was established (RFC3339), for `ssk system doctor`
    /// / audit display. A plain `String` rather than a chrono type: this crate
    /// takes no time-handling dependency, and the value is opaque to every
    /// comparison this crate performs — it is provenance, not an input to the
    /// gate.
    pub established_at: String,
}

impl PersistedBaseline {
    /// Build a baseline record for `target`, established at `established_at`
    /// (an RFC3339 timestamp supplied by the caller — this crate does not
    /// read the clock).
    #[must_use]
    pub fn new(target: TargetProfile, established_at: impl Into<String>) -> Self {
        PersistedBaseline {
            schema_version: BASELINE_SCHEMA,
            target,
            established_at: established_at.into(),
        }
    }

    /// The schema version this build writes.
    #[must_use]
    pub fn schema() -> u32 {
        BASELINE_SCHEMA
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature_for;
    use crate::value::{OrderedMap, Value};
    use crate::SurfaceObject;

    fn sig() -> crate::SpectralSignature {
        let fields = OrderedMap::from_iter([
            ("method".to_owned(), Value::Text("GET".to_owned())),
            (
                "url".to_owned(),
                Value::Text("https://example.test/api".to_owned()),
            ),
            ("status".to_owned(), Value::Num(200.0)),
        ]);
        signature_for(
            &SurfaceObject::new("application/trace+json", fields)
                .with_declared_protocol_class("http"),
        )
    }

    #[test]
    fn new_stamps_the_current_schema() {
        let baseline =
            PersistedBaseline::new(TargetProfile::new("system", sig()), "2026-08-03T00:00:00Z");
        assert_eq!(baseline.schema_version, PersistedBaseline::schema());
        assert_eq!(PersistedBaseline::schema(), 1);
    }

    #[test]
    fn round_trips_through_json_byte_for_byte() {
        let baseline =
            PersistedBaseline::new(TargetProfile::new("system", sig()), "2026-08-03T00:00:00Z");
        let encoded = serde_json::to_string(&baseline).expect("serializable");
        let decoded: PersistedBaseline = serde_json::from_str(&encoded).expect("deserializable");
        assert_eq!(baseline, decoded);
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_silently_dropped() {
        let baseline =
            PersistedBaseline::new(TargetProfile::new("system", sig()), "2026-08-03T00:00:00Z");
        let mut value: serde_json::Value = serde_json::to_value(&baseline).expect("serializable");
        value
            .as_object_mut()
            .expect("object")
            .insert("bogus_field".to_owned(), serde_json::json!(true));
        let err = serde_json::from_value::<PersistedBaseline>(value).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }
}
