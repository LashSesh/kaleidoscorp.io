//! Contact + Kontaktlücke (IMDF 5/6; IMRT A2, A4) — conserved observation reach.
//!
//! An observer's [`Lens`](crate::observer::Lens) declares an *emphasis*: the
//! dimensions it intends to make **contact** with. When a focus fails to yield a
//! measured reading for an emphasized dimension, that unmet reach is a
//! **Kontaktlücke** (contact gap). Rather than let it vanish silently — the
//! surface simply reads as if the observer never wanted that dimension — the gap
//! is conserved as a residue (A4, No Silent Loss). This also gives the `Lens`
//! genuine load-bearing behavior: it decides what contact was *expected*, so a
//! shortfall against it is measurable.

use std::collections::BTreeSet;

use ssk_types::{
    digest_of, BoundaryResidue, GateId, HashAlg, NextAction, ResidueId, ResidueKind, ResidueStatus,
    Severity, TraceId,
};

use crate::aperture::FocusResult;
use crate::observer::{ObserverId, ObserverModel};

/// Why an emphasized dimension was not contacted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContactGapReason {
    /// The observer declared the region a blindspot — a *typed* unknown, so the
    /// gap is honest, but still conserved (the emphasis went unmet).
    Blindspot,
    /// No measured reading was produced: the dimension is outside the aperture
    /// or absent from the surface. The observer reached and found nothing.
    NoReading,
}

impl ContactGapReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ContactGapReason::Blindspot => "blindspot",
            ContactGapReason::NoReading => "no-reading",
        }
    }
}

/// One unmet contact expectation: an emphasized dimension the focus did not
/// deliver a measured reading for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kontaktluecke {
    pub dimension: String,
    pub reason: ContactGapReason,
}

/// The reach of one observation against its lens: which emphasized dimensions
/// were actually contacted, and which were not (the conserved gaps).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    pub observer: ObserverId,
    pub vantage: String,
    /// Emphasized dimensions that yielded a measured reading.
    pub achieved: BTreeSet<String>,
    /// Emphasized dimensions with no measured reading — the Kontaktlücken.
    pub gaps: Vec<Kontaktluecke>,
}

impl Contact {
    /// Compute the contact reach of an observer's focus against its lens
    /// emphasis. An emphasized dimension is *achieved* if it read as `Measured`,
    /// and a *gap* otherwise (blindspot vs. no-reading distinguished).
    #[must_use]
    pub fn observe(observer: &ObserverModel, focus: &FocusResult) -> Self {
        let measured: BTreeSet<&str> = focus.measured_dimensions().into_iter().collect();
        let blind: BTreeSet<&str> = focus
            .blindspot_dimensions
            .iter()
            .map(String::as_str)
            .collect();

        let mut achieved = BTreeSet::new();
        let mut gaps = Vec::new();
        // Deterministic order: emphasis is a BTreeSet, so iteration is sorted.
        for dim in &observer.lens.emphasis {
            if measured.contains(dim.as_str()) {
                achieved.insert(dim.clone());
            } else if blind.contains(dim.as_str()) {
                gaps.push(Kontaktluecke {
                    dimension: dim.clone(),
                    reason: ContactGapReason::Blindspot,
                });
            } else {
                gaps.push(Kontaktluecke {
                    dimension: dim.clone(),
                    reason: ContactGapReason::NoReading,
                });
            }
        }

        Contact {
            observer: observer.id,
            vantage: observer.vantage.label.clone(),
            achieved,
            gaps,
        }
    }

    /// Whether every emphasized dimension was contacted (no Kontaktlücke).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }

    /// Lift the Kontaktlücken into conserved residues (A4). Each gap becomes a
    /// `Focus`-kind 5-tuple whose `Fragment` is the un-contacted dimension. A
    /// blindspot gap is an *honest* known-unknown (`Deferred`/`Accept`); a
    /// no-reading gap is a standing obligation (`Open`/`Reacquire`).
    #[must_use]
    pub fn to_residues(&self, origin: TraceId) -> Vec<BoundaryResidue> {
        self.gaps
            .iter()
            .map(|gap| {
                let rid = digest_of(
                    &(
                        "imdf/kontaktluecke/v1",
                        self.observer.0,
                        &self.vantage,
                        &gap.dimension,
                        gap.reason.as_str(),
                    ),
                    HashAlg::Blake3,
                )
                .expect("kontaktluecke residue key is serializable")
                .to_hex();
                let (status, next_action, severity) = match gap.reason {
                    ContactGapReason::Blindspot => {
                        (ResidueStatus::Deferred, NextAction::Accept, Severity::Low)
                    }
                    ContactGapReason::NoReading => {
                        (ResidueStatus::Open, NextAction::Reacquire, Severity::High)
                    }
                };
                BoundaryResidue::new_full(
                    ResidueId::new(rid),
                    ResidueKind::Focus,
                    GateId::Focus,
                    Some(gap.dimension.clone()),
                    format!(
                        "kontaktlücke: emphasized dimension '{}' not contacted ({})",
                        gap.dimension,
                        gap.reason.as_str()
                    ),
                    severity,
                    origin.clone(),
                    status,
                    next_action,
                )
            })
            .collect()
    }
}

impl ObserverModel {
    /// Focus on a surface and report the observation's contact reach against the
    /// observer's lens emphasis — the achieved contacts and the conserved
    /// Kontaktlücken.
    ///
    /// # Errors
    /// [`ImdfError::ApertureRequired`](crate::error::ImdfError::ApertureRequired)
    /// if the observer's aperture is closed.
    pub fn contact(
        &self,
        signature: &ssk_signature::SpectralSignature,
    ) -> Result<Contact, crate::error::ImdfError> {
        let focus = self.open_aperture()?.focus(signature);
        Ok(Contact::observe(self, &focus))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aperture::Aperture;
    use crate::observer::{Lens, TrustLevel, Vantage};
    use ssk_signature::{
        signature_for, AuthorizationManifest, OrderedMap, SpectralSignature, SurfaceObject, Value,
    };
    use ssk_types::ReplayRoot;

    fn auth() -> AuthorizationManifest {
        AuthorizationManifest::new("owned-dome", "me", "self-owned")
            .with_allowed_uses([crate::observer::SELF_OBSERVATION_USE])
    }

    // An observer whose lens emphasizes `emphasis`, over an aperture admitting
    // `admits`, with `blindspots` declared blind.
    fn observer(emphasis: &[&str], admits: &[&str], blindspots: &[&str]) -> ObserverModel {
        ObserverModel::new(
            "host-a",
            Vantage::new("front"),
            Aperture::admitting("wide", admits.iter().copied()),
            Lens::new("l", emphasis.iter().copied()),
            blindspots
                .iter()
                .map(|b| crate::observer::Blindspot::new(*b, "declared"))
                .collect(),
            TrustLevel::Observed,
            ReplayRoot::new("rr"),
            &auth(),
        )
        .unwrap()
    }

    fn surface() -> SpectralSignature {
        let fields = OrderedMap::from_iter([
            ("method".to_owned(), Value::Text("GET".to_owned())),
            (
                "url".to_owned(),
                Value::Text("https://example.test/a".to_owned()),
            ),
            ("status".to_owned(), Value::Num(200.0)),
        ]);
        signature_for(
            &SurfaceObject::new("application/trace+json", fields)
                .with_declared_protocol_class("http"),
        )
    }

    // G34: an emphasized dimension that the focus contacts is achieved; one it
    // cannot is a conserved Kontaktlücke, never silently absent.
    #[test]
    fn uncontacted_emphasis_becomes_a_conserved_kontaktluecke() {
        let sig = surface();
        let dims: Vec<&str> = sig.dimensions.keys().map(String::as_str).collect();
        assert!(dims.len() >= 2);
        let contactable = dims[0];
        // Emphasize one contactable dimension plus one that does not exist.
        let obs = observer(&[contactable, "phantom_dimension"], &dims, &[]);

        let contact = obs.contact(&sig).unwrap();
        assert!(
            contact.achieved.contains(contactable),
            "an emphasized, readable dimension is contacted"
        );
        assert!(!contact.is_complete(), "the phantom emphasis is a gap");
        assert_eq!(contact.gaps.len(), 1);
        assert_eq!(contact.gaps[0].dimension, "phantom_dimension");
        assert_eq!(contact.gaps[0].reason, ContactGapReason::NoReading);

        // The gap is conserved as a Focus residue carrying the fragment.
        let residues = contact.to_residues(TraceId::new("t"));
        assert_eq!(residues.len(), 1);
        let r = &residues[0];
        assert_eq!(r.kind, ResidueKind::Focus);
        assert_eq!(r.fragment.as_deref(), Some("phantom_dimension"));
        assert_eq!(r.status, ResidueStatus::Open);
        assert_eq!(r.next_action, NextAction::Reacquire);
        assert!(
            r.open_obligation(),
            "a no-reading gap is a standing obligation"
        );
    }

    // A blindspot gap is honest: it is still conserved, but as a Deferred,
    // Accept-directive residue (a known-unknown), not a blocking obligation.
    #[test]
    fn blindspot_emphasis_is_a_deferred_not_blocking_gap() {
        let sig = surface();
        let dims: Vec<&str> = sig.dimensions.keys().map(String::as_str).collect();
        let blind = dims[0];
        let obs = observer(&[blind], &dims, &[blind]);

        let contact = obs.contact(&sig).unwrap();
        assert!(contact.achieved.is_empty());
        assert_eq!(contact.gaps.len(), 1);
        assert_eq!(contact.gaps[0].reason, ContactGapReason::Blindspot);

        let residues = contact.to_residues(TraceId::new("t"));
        let r = &residues[0];
        assert_eq!(r.status, ResidueStatus::Deferred);
        assert_eq!(r.next_action, NextAction::Accept);
        assert!(
            !r.open_obligation(),
            "an honest blindspot is not a blocking obligation"
        );
    }

    // Fully-met emphasis yields no gaps and no residues.
    #[test]
    fn complete_contact_emits_no_residue() {
        let sig = surface();
        let dims: Vec<&str> = sig.dimensions.keys().map(String::as_str).collect();
        let obs = observer(&dims, &dims, &[]);
        let contact = obs.contact(&sig).unwrap();
        assert!(contact.is_complete());
        assert!(contact.to_residues(TraceId::new("t")).is_empty());
    }
}
