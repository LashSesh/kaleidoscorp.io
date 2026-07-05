//! Typed residues — Chameleon `residue_report`, wired to the SSK "no silent
//! loss" currency.
//!
//! A [`Residue`] records a surface (which signature dimension leaked or
//! changed), a [`ResidueSeverity`], and a message. A [`ResidueReport`] is the
//! visible currency of what a transform did not preserve. Every residue can be
//! bridged into an `ssk_types::BoundaryResidue` and emitted into a
//! `ResidueRegister`, so nothing a signature transform touches is dropped
//! silently — the Chameleon residue taxonomy flows into the SSK boundary
//! ledger.

use ssk_types::{
    digest_of, BoundaryResidue, GateId, HashAlg, ResidueId, ResidueKind, Severity, TraceId,
};

/// Ordered residue severity (Chameleon string severities, typed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidueSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl ResidueSeverity {
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            ResidueSeverity::None => 0,
            ResidueSeverity::Low => 1,
            ResidueSeverity::Medium => 2,
            ResidueSeverity::High => 3,
            ResidueSeverity::Critical => 4,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ResidueSeverity::None => "none",
            ResidueSeverity::Low => "low",
            ResidueSeverity::Medium => "medium",
            ResidueSeverity::High => "high",
            ResidueSeverity::Critical => "critical",
        }
    }

    /// Map onto the SSK `Severity` (which has no `Medium`: `medium` folds up to
    /// `High`, disclosed in the port assessment).
    #[must_use]
    pub fn to_ssk(self) -> Severity {
        match self {
            ResidueSeverity::None => Severity::Info,
            ResidueSeverity::Low => Severity::Low,
            ResidueSeverity::Medium | ResidueSeverity::High => Severity::High,
            ResidueSeverity::Critical => Severity::Critical,
        }
    }
}

/// A single residue: a surface, a severity, and a human message.
#[derive(Clone, Debug, PartialEq)]
pub struct Residue {
    pub surface: String,
    pub severity: ResidueSeverity,
    pub message: String,
}

impl Residue {
    /// Bridge into an SSK `BoundaryResidue`. The residue id is content-addressed
    /// from `(surface, severity, message)`; `open_obligation` is set for
    /// `medium`+ residues (the ones the gate treats as hold-worthy).
    #[must_use]
    pub fn to_boundary_residue(&self, source_gate: GateId, origin: TraceId) -> BoundaryResidue {
        #[derive(serde::Serialize)]
        struct Key<'a> {
            surface: &'a str,
            severity: &'a str,
            message: &'a str,
        }
        let id = digest_of(
            &Key {
                surface: &self.surface,
                severity: self.severity.as_str(),
                message: &self.message,
            },
            HashAlg::Blake3,
        )
        .expect("residue key is serializable")
        .to_hex();
        BoundaryResidue::new(
            ResidueId::new(id),
            surface_to_kind(&self.surface),
            source_gate,
            self.message.clone(),
            self.severity.to_ssk(),
            origin,
            self.severity.rank() >= ResidueSeverity::Medium.rank(),
        )
    }
}

/// Map a Chameleon residue surface onto an SSK `ResidueKind`.
#[must_use]
pub fn surface_to_kind(surface: &str) -> ResidueKind {
    match surface {
        "linkability" | "linkability_surface" => ResidueKind::Correlation,
        "timing" | "transport_timing" => ResidueKind::Timing,
        // shape/ordering/entropy/semantic and the http_* fingerprint surfaces
        // are all protocol-surface residues.
        "shape" | "ordering" | "entropy" | "semantic" | "http_surface" | "http_header_order"
        | "body_schema" => ResidueKind::Protocol,
        _ => ResidueKind::Boundary,
    }
}

/// The outcome of externalizing a residue selection (a reference, not the raw
/// residue detail) — Chameleon `ResidueDisposition`.
#[derive(Clone, Debug, PartialEq)]
pub struct ResidueDisposition {
    pub phase: String,
    pub action: String,
    pub residue_ref: String,
    pub count: usize,
    pub max_severity: ResidueSeverity,
}

/// A report of everything a transform did not preserve (Chameleon
/// `ResidueReport`). Immutable-append: [`ResidueReport::add`] returns a new
/// report.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResidueReport {
    pub residues: Vec<Residue>,
}

impl ResidueReport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a new report with one more residue appended.
    #[must_use]
    pub fn add(&self, surface: &str, severity: ResidueSeverity, message: &str) -> Self {
        let mut residues = self.residues.clone();
        residues.push(Residue {
            surface: surface.to_owned(),
            severity,
            message: message.to_owned(),
        });
        ResidueReport { residues }
    }

    #[must_use]
    pub fn by_surface(&self, surface: &str) -> Vec<&Residue> {
        self.residues
            .iter()
            .filter(|r| r.surface == surface)
            .collect()
    }

    /// Any residue on a forbidden surface at `medium`+ severity.
    #[must_use]
    pub fn has_forbidden(&self, forbidden_surfaces: &[String]) -> bool {
        self.residues.iter().any(|r| {
            forbidden_surfaces.iter().any(|s| s == &r.surface)
                && r.severity.rank() >= ResidueSeverity::Medium.rank()
        })
    }

    #[must_use]
    pub fn max_severity(&self) -> ResidueSeverity {
        self.residues
            .iter()
            .map(|r| r.severity)
            .max_by_key(|s| s.rank())
            .unwrap_or(ResidueSeverity::None)
    }

    /// Externalize (by reference) the residues at or above `minimum_severity`
    /// on the given surfaces (empty = all surfaces). Returns `None` if nothing
    /// qualifies. Mirrors Chameleon `ResidueReport.externalize`.
    #[must_use]
    pub fn externalize(
        &self,
        phase: &str,
        surfaces: &[String],
        minimum_severity: ResidueSeverity,
    ) -> Option<ResidueDisposition> {
        let selected: Vec<&Residue> = self
            .residues
            .iter()
            .filter(|r| {
                (surfaces.is_empty() || surfaces.iter().any(|s| s == &r.surface))
                    && r.severity.rank() >= minimum_severity.rank()
            })
            .collect();
        if selected.is_empty() {
            return None;
        }
        let payload = selected
            .iter()
            .map(|r| format!("{}:{}:{}", r.surface, r.severity.as_str(), r.message))
            .collect::<Vec<_>>()
            .join("|");
        let residue_ref = digest_of(&payload, HashAlg::Blake3)
            .expect("payload is serializable")
            .to_hex();
        let max_severity = selected
            .iter()
            .map(|r| r.severity)
            .max_by_key(|s| s.rank())
            .unwrap_or(ResidueSeverity::None);
        Some(ResidueDisposition {
            phase: phase.to_owned(),
            action: "externalized".to_owned(),
            residue_ref,
            count: selected.len(),
            max_severity,
        })
    }

    /// Convenience default externalization (`post_transform`, all surfaces,
    /// `medium` minimum) matching Chameleon `externalize()` with no arguments.
    #[must_use]
    pub fn externalize_default(&self) -> Option<ResidueDisposition> {
        self.externalize("post_transform", &[], ResidueSeverity::Medium)
    }

    /// Bridge every residue into `ssk_types::BoundaryResidue` for emission into
    /// a `ResidueRegister`.
    #[must_use]
    pub fn to_boundary_residues(
        &self,
        source_gate: GateId,
        origin: &TraceId,
    ) -> Vec<BoundaryResidue> {
        self.residues
            .iter()
            .map(|r| r.to_boundary_residue(source_gate, origin.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_is_immutable_and_by_surface_filters() {
        let base = ResidueReport::new();
        let r = base
            .add("linkability", ResidueSeverity::Medium, "redacted 2 fields")
            .add(
                "semantic",
                ResidueSeverity::Medium,
                "redaction may remove semantics",
            );
        assert!(base.residues.is_empty(), "add must not mutate the original");
        assert_eq!(r.by_surface("linkability").len(), 1);
        assert_eq!(r.by_surface("semantic").len(), 1);
        assert_eq!(r.max_severity(), ResidueSeverity::Medium);
    }

    #[test]
    fn externalize_selects_by_surface_and_severity() {
        let r = ResidueReport::new()
            .add("linkability", ResidueSeverity::Medium, "x")
            .add("timing", ResidueSeverity::Low, "y");
        // default: medium+ on all surfaces -> only the linkability residue
        let d = r.externalize_default().expect("a medium residue exists");
        assert_eq!(d.count, 1);
        assert_eq!(d.max_severity, ResidueSeverity::Medium);
        // restrict to timing at low -> the timing residue
        let d2 = r
            .externalize(
                "post_transform",
                &["timing".to_owned()],
                ResidueSeverity::Low,
            )
            .unwrap();
        assert_eq!(d2.count, 1);
        // nothing at critical
        assert!(r
            .externalize("post_transform", &[], ResidueSeverity::Critical)
            .is_none());
    }

    #[test]
    fn forbidden_surface_detection() {
        let r = ResidueReport::new().add("semantic", ResidueSeverity::High, "leak");
        assert!(r.has_forbidden(&["semantic".to_owned()]));
        assert!(!r.has_forbidden(&["timing".to_owned()]));
    }

    #[test]
    fn residue_bridges_to_boundary_residue() {
        let r = Residue {
            surface: "linkability".to_owned(),
            severity: ResidueSeverity::Medium,
            message: "redacted".to_owned(),
        };
        let b = r.to_boundary_residue(GateId::Privacy, TraceId::new("trace-1"));
        assert_eq!(b.kind, ResidueKind::Correlation);
        assert_eq!(b.severity, Severity::High);
        assert!(
            b.open_obligation,
            "medium+ residues carry an open obligation"
        );
        assert_eq!(b.source_gate, GateId::Privacy);
    }
}
