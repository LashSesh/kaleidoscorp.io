//! Comparison targets — Chameleon `target_profile`.
//!
//! A [`TargetProfile`] is the signature a transformed surface is compared
//! against, plus the per-dimension and global tolerances and the residue
//! surfaces the gate cares about. An [`OperationalMask`] is the runtime-facing
//! projection used to score live observations.

use std::collections::BTreeMap;

use crate::signature::SpectralSignature;

fn default_dimension_tolerances() -> BTreeMap<String, f64> {
    [
        ("shape", 0.20),
        ("ordering", 0.20),
        ("entropy", 0.50),
        ("timing", 0.75),
        ("semantic", 0.20),
        ("linkability", 0.20),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect()
}

fn default_externalization_surfaces() -> Vec<String> {
    vec!["semantic".to_owned(), "linkability".to_owned()]
}

/// The signature + tolerances a transform is gated against.
#[derive(Clone, Debug, PartialEq)]
pub struct TargetProfile {
    pub name: String,
    pub signature: SpectralSignature,
    pub dimension_tolerances: BTreeMap<String, f64>,
    pub global_tolerance: f64,
    pub forbidden_residue_surfaces: Vec<String>,
    pub residue_externalization_surfaces: Vec<String>,
    pub enforcement_level: String,
}

impl TargetProfile {
    /// A target with the Chameleon default tolerances.
    #[must_use]
    pub fn new(name: impl Into<String>, signature: SpectralSignature) -> Self {
        TargetProfile {
            name: name.into(),
            signature,
            dimension_tolerances: default_dimension_tolerances(),
            global_tolerance: 0.35,
            forbidden_residue_surfaces: Vec::new(),
            residue_externalization_surfaces: default_externalization_surfaces(),
            enforcement_level: "optimize".to_owned(),
        }
    }

    #[must_use]
    pub fn with_dimension_tolerances(mut self, tolerances: BTreeMap<String, f64>) -> Self {
        self.dimension_tolerances = tolerances;
        self
    }

    #[must_use]
    pub fn with_global_tolerance(mut self, tolerance: f64) -> Self {
        self.global_tolerance = tolerance;
        self
    }

    #[must_use]
    pub fn with_forbidden_residue_surfaces(mut self, surfaces: Vec<String>) -> Self {
        self.forbidden_residue_surfaces = surfaces;
        self
    }

    #[must_use]
    pub fn with_residue_externalization_surfaces(mut self, surfaces: Vec<String>) -> Self {
        self.residue_externalization_surfaces = surfaces;
        self
    }

    #[must_use]
    pub fn to_operational_mask(&self) -> OperationalMask {
        OperationalMask {
            name: self.name.clone(),
            signature: self.signature.clone(),
            dimension_tolerances: self.dimension_tolerances.clone(),
            global_tolerance: self.global_tolerance,
            residue_externalization_surfaces: self.residue_externalization_surfaces.clone(),
            enforcement_level: self.enforcement_level.clone(),
        }
    }
}

/// The runtime-facing projection of a target, used to score live observations.
#[derive(Clone, Debug, PartialEq)]
pub struct OperationalMask {
    pub name: String,
    pub signature: SpectralSignature,
    pub dimension_tolerances: BTreeMap<String, f64>,
    pub global_tolerance: f64,
    pub residue_externalization_surfaces: Vec<String>,
    pub enforcement_level: String,
}

impl OperationalMask {
    #[must_use]
    pub fn to_target_profile(&self) -> TargetProfile {
        TargetProfile {
            name: self.name.clone(),
            signature: self.signature.clone(),
            dimension_tolerances: self.dimension_tolerances.clone(),
            global_tolerance: self.global_tolerance,
            forbidden_residue_surfaces: Vec::new(),
            residue_externalization_surfaces: self.residue_externalization_surfaces.clone(),
            enforcement_level: self.enforcement_level.clone(),
        }
    }
}
