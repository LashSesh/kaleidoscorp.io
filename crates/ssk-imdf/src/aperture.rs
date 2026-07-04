//! Aperture-before-Focus (IMDF 6.1) — a typed measurement bound.
//!
//! An [`Aperture`] declares which surface dimensions an observer is permitted to
//! measure. Focus is only reachable through an open aperture ([`ApertureSession`],
//! obtained from `ObserverModel::open_aperture`), enforcing *Focus ⇒ ∃A*. When a
//! surface carries a dimension the aperture does not admit, that dimension does
//! not silently vanish — it becomes a **residue** (the "no silent loss"
//! discipline). A dimension the observer has declared a *blindspot* reads as
//! [`Reading::Blind`], never as a fabricated value.

use std::collections::{BTreeMap, BTreeSet};

use ssk_signature::{ResidueReport, ResidueSeverity, SpectralSignature};
use ssk_types::{digest_of, HashAlg};

/// The set of dimensions an observer may measure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aperture {
    pub label: String,
    admitted: BTreeSet<String>,
}

impl Aperture {
    /// A closed aperture admits nothing; an observer holding it cannot focus.
    #[must_use]
    pub fn closed(label: impl Into<String>) -> Self {
        Aperture {
            label: label.into(),
            admitted: BTreeSet::new(),
        }
    }

    /// An aperture admitting the given dimensions.
    #[must_use]
    pub fn admitting<I: IntoIterator<Item = S>, S: Into<String>>(
        label: impl Into<String>,
        dims: I,
    ) -> Self {
        Aperture {
            label: label.into(),
            admitted: dims.into_iter().map(Into::into).collect(),
        }
    }

    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.admitted.is_empty()
    }

    #[must_use]
    pub fn admits(&self, dimension: &str) -> bool {
        self.admitted.contains(dimension)
    }

    pub fn admitted_dimensions(&self) -> impl Iterator<Item = &str> {
        self.admitted.iter().map(String::as_str)
    }
}

/// A single dimension reading. A blindspot is a *declared unknown*, not a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reading {
    /// The content digest of the measured dimension (a replayable measurement
    /// that does not expose raw values).
    Measured(String),
    /// The observer has declared this region a blindspot; no value is asserted.
    Blind { reason: String },
}

impl Reading {
    /// The measured digest, or `None` for a blindspot — a blindspot never yields
    /// a value.
    #[must_use]
    pub fn as_measured_digest(&self) -> Option<&str> {
        match self {
            Reading::Measured(d) => Some(d),
            Reading::Blind { .. } => None,
        }
    }

    #[must_use]
    pub fn is_blind(&self) -> bool {
        matches!(self, Reading::Blind { .. })
    }
}

/// The result of focusing an aperture on a surface.
#[derive(Clone, Debug, PartialEq)]
pub struct FocusResult {
    pub aperture_label: String,
    pub readings: BTreeMap<String, Reading>,
    pub residues: ResidueReport,
    pub hidden_dimensions: Vec<String>,
    pub blindspot_dimensions: Vec<String>,
}

impl FocusResult {
    /// The measured (non-blind) dimensions, in order.
    #[must_use]
    pub fn measured_dimensions(&self) -> Vec<&str> {
        self.readings
            .iter()
            .filter(|(_, r)| !r.is_blind())
            .map(|(d, _)| d.as_str())
            .collect()
    }
}

/// An open measurement session. Only obtainable through an *open* aperture, so a
/// `focus` cannot exist without an aperture (Focus ⇒ ∃A).
#[derive(Debug)]
pub struct ApertureSession<'a> {
    pub(crate) aperture: &'a Aperture,
    pub(crate) blindspot_regions: BTreeSet<String>,
}

impl ApertureSession<'_> {
    /// Focus the aperture on a surface's spectrum. Admitted, non-blindspot
    /// dimensions are measured; blindspot dimensions read [`Reading::Blind`];
    /// dimensions outside the aperture become residues.
    #[must_use]
    pub fn focus(&self, signature: &SpectralSignature) -> FocusResult {
        let mut readings = BTreeMap::new();
        let mut residues = ResidueReport::new();
        let mut hidden = Vec::new();
        let mut blindspot_dims = Vec::new();

        for (dimension, sub) in &signature.dimensions {
            if !self.aperture.admits(dimension) {
                residues = residues.add(
                    "focus",
                    ResidueSeverity::Medium,
                    &format!("hidden surface outside aperture: {dimension}"),
                );
                hidden.push(dimension.clone());
                continue;
            }
            if self.blindspot_regions.contains(dimension) {
                readings.insert(
                    dimension.clone(),
                    Reading::Blind {
                        reason: format!("declared blindspot: {dimension}"),
                    },
                );
                blindspot_dims.push(dimension.clone());
                continue;
            }
            let digest = digest_of(sub, HashAlg::Blake3)
                .expect("dimension is serializable")
                .to_hex();
            readings.insert(dimension.clone(), Reading::Measured(digest));
        }

        FocusResult {
            aperture_label: self.aperture.label.clone(),
            readings,
            residues,
            hidden_dimensions: hidden,
            blindspot_dimensions: blindspot_dims,
        }
    }
}
