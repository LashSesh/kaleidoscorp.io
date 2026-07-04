//! Calibration presets — Chameleon `calibration`.
//!
//! Named operating points: each preset names the dimensions it focuses on and a
//! full per-dimension tolerance vector plus a global tolerance. These are the
//! reusable gate configurations an operator/analyst selects between.

use std::collections::BTreeMap;

/// The default preset name.
pub const DEFAULT_CALIBRATION_PRESET: &str = "Domain surface";

/// A named calibration point.
#[derive(Clone, Debug, PartialEq)]
pub struct CalibrationPreset {
    pub name: String,
    pub dimensions: Vec<String>,
    pub dimension_tolerances: BTreeMap<String, f64>,
    pub global_tolerance: f64,
    pub residue_externalization_surfaces: Vec<String>,
    pub notes: Vec<String>,
}

fn tolerances(pairs: &[(&str, f64)]) -> BTreeMap<String, f64> {
    pairs.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect()
}

fn strs(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn preset(
    name: &str,
    dims: &[&str],
    tol: &[(&str, f64)],
    global_tolerance: f64,
    notes: &[&str],
) -> CalibrationPreset {
    CalibrationPreset {
        name: name.to_owned(),
        dimensions: strs(dims),
        dimension_tolerances: tolerances(tol),
        global_tolerance,
        residue_externalization_surfaces: strs(&["semantic", "linkability"]),
        notes: strs(notes),
    }
}

/// All calibration presets, in canonical order.
#[must_use]
pub fn calibration_spectrum() -> Vec<CalibrationPreset> {
    vec![
        preset(
            "Domain surface",
            &[
                "shape",
                "ordering",
                "entropy",
                "timing",
                "semantic",
                "linkability",
                "http_surface",
                "http_header_order",
                "body_schema",
                "transport_timing",
                "linkability_surface",
            ],
            &[
                ("shape", 0.35),
                ("ordering", 0.35),
                ("entropy", 0.80),
                ("timing", 1.00),
                ("semantic", 0.35),
                ("linkability", 0.35),
                ("http_surface", 0.45),
                ("http_header_order", 0.60),
                ("body_schema", 0.65),
                ("transport_timing", 0.80),
                ("linkability_surface", 0.35),
            ],
            0.70,
            &["broad domain or service baseline"],
        ),
        preset(
            "HTTP fingerprint",
            &[
                "http_surface",
                "http_header_order",
                "body_schema",
                "transport_timing",
                "linkability_surface",
            ],
            &[
                ("shape", 0.50),
                ("ordering", 0.50),
                ("entropy", 0.80),
                ("timing", 0.80),
                ("semantic", 0.45),
                ("linkability", 0.35),
                ("http_surface", 0.22),
                ("http_header_order", 0.25),
                ("body_schema", 0.30),
                ("transport_timing", 0.35),
                ("linkability_surface", 0.20),
            ],
            0.40,
            &["protocol-specific HTTP response and timing fingerprint"],
        ),
        preset(
            "Endpoint shape",
            &[
                "shape",
                "ordering",
                "semantic",
                "entropy",
                "http_surface",
                "body_schema",
            ],
            &[
                ("shape", 0.18),
                ("ordering", 0.20),
                ("entropy", 0.45),
                ("timing", 1.50),
                ("semantic", 0.20),
                ("linkability", 0.60),
                ("http_surface", 0.25),
                ("http_header_order", 0.80),
                ("body_schema", 0.35),
                ("transport_timing", 1.20),
                ("linkability_surface", 0.60),
            ],
            0.45,
            &["single route or small route family"],
        ),
        preset(
            "API family",
            &[
                "shape",
                "semantic",
                "entropy",
                "linkability",
                "http_surface",
                "body_schema",
            ],
            &[
                ("shape", 0.28),
                ("ordering", 0.50),
                ("entropy", 0.65),
                ("timing", 1.25),
                ("semantic", 0.25),
                ("linkability", 0.30),
                ("http_surface", 0.30),
                ("http_header_order", 0.70),
                ("body_schema", 0.28),
                ("transport_timing", 1.00),
                ("linkability_surface", 0.30),
            ],
            0.60,
            &["method/status/header/body family"],
        ),
        preset(
            "Timing stability",
            &["timing", "entropy", "transport_timing"],
            &[
                ("shape", 0.80),
                ("ordering", 0.80),
                ("entropy", 0.70),
                ("timing", 0.35),
                ("semantic", 0.80),
                ("linkability", 0.80),
                ("http_surface", 0.80),
                ("http_header_order", 0.90),
                ("body_schema", 0.90),
                ("transport_timing", 0.25),
                ("linkability_surface", 0.80),
            ],
            0.55,
            &["latency and jitter focused baseline"],
        ),
        preset(
            "Header/body surface",
            &[
                "shape",
                "ordering",
                "entropy",
                "linkability",
                "http_header_order",
                "body_schema",
            ],
            &[
                ("shape", 0.22),
                ("ordering", 0.25),
                ("entropy", 0.50),
                ("timing", 1.50),
                ("semantic", 0.45),
                ("linkability", 0.22),
                ("http_surface", 0.40),
                ("http_header_order", 0.22),
                ("body_schema", 0.22),
                ("transport_timing", 1.20),
                ("linkability_surface", 0.22),
            ],
            0.50,
            &["header count, body presence, payload-size surface"],
        ),
    ]
}

/// Preset names, in canonical order.
#[must_use]
pub fn calibration_preset_names() -> Vec<String> {
    calibration_spectrum().into_iter().map(|p| p.name).collect()
}

/// Look up a preset by name, falling back to the default for an empty name.
///
/// # Errors
/// Returns the unknown name if it does not match any preset.
pub fn get_calibration_preset(name: Option<&str>) -> Result<CalibrationPreset, String> {
    let wanted = match name {
        None | Some("") => DEFAULT_CALIBRATION_PRESET,
        Some(n) => n,
    };
    calibration_spectrum()
        .into_iter()
        .find(|p| p.name == wanted)
        .ok_or_else(|| format!("unknown calibration preset: {wanted}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_names_include_http_fingerprint() {
        assert!(calibration_preset_names()
            .iter()
            .any(|n| n == "HTTP fingerprint"));
        assert_eq!(calibration_preset_names().len(), 6);
    }

    #[test]
    fn default_preset_resolves_and_unknown_errors() {
        assert_eq!(
            get_calibration_preset(None).unwrap().name,
            DEFAULT_CALIBRATION_PRESET
        );
        assert_eq!(
            get_calibration_preset(Some("")).unwrap().name,
            DEFAULT_CALIBRATION_PRESET
        );
        assert!(get_calibration_preset(Some("nope")).is_err());
    }
}
